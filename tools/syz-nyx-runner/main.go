// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"golang.org/x/sys/unix"
)

var reNyxModuleRangeSubmitted = regexp.MustCompile(`nyx module range submitted slot=(\d+) target=([^ ]+) name=([^ ]+) base=0x([0-9a-fA-F]+) end=0x([0-9a-fA-F]+)`)

const (
	nyxInterfacePing        = byte('x')
	nyxAuxMagic             = 0x54502d554d4551
	nyxAuxVersion           = 0x3
	nyxAuxHash              = 0x54
	nyxStateOffset          = 128 + 256 + 512
	nyxMiscOffset           = nyxStateOffset + 512
	nyxResultExecDoneOffset = nyxStateOffset + 1
	nyxResultExecCodeOffset = nyxStateOffset + 2
	nyxResultReloadedOffset = nyxStateOffset + 3
	nyxResultPtOverflowOff  = nyxStateOffset + 4
	nyxResultPageFaultOff   = nyxStateOffset + 5
	nyxResultPageAddrOff    = nyxStateOffset + 8

	nyxRCSuccess   = 0
	nyxRCCrash     = 1
	nyxRCHprintf   = 2
	nyxRCTimeout   = 3
	nyxRCInputBuf  = 4
	nyxRCAbort     = 5
	nyxRCSanitizer = 6
	nyxRCStarved   = 7

	nyxMsgMagic      = 0x3158594e
	nyxMsgVersion    = 1
	nyxKindHandshake = 1
	nyxKindExec      = 2
	nyxKindIdle      = 3
	nyxExecKeepState = 1 << 0

	nyxHandshakeAck = "syz_nyx_handshake.ok"
	nyxExecResult   = "syz_nyx_result.bin"
	nyxPageSize     = 0x1000

	nyxModuleRangeConfigMagic   = 0x4d52594e
	nyxModuleRangeConfigVersion = 1
	nyxModuleRangePatternSize   = 64
	nyxMaxModuleRangeTargets    = 16
	nyxModuleRangeConfigFile    = "syz_nyx_module_ranges.bin"
	nyxInitMinTimeout           = 2 * time.Minute
	nyxManagerReconnectBackoff  = time.Second
)

type multiFlag []string

type moduleRangeSpec struct {
	Pattern  string
	Required bool
}

type traceEvent struct {
	Seq          uint64         `json:"seq"`
	Time         time.Time      `json:"time"`
	SinceStartMS int64          `json:"since_start_ms"`
	Source       string         `json:"source"`
	Stage        string         `json:"stage"`
	RequestID    int64          `json:"request_id,omitempty"`
	Fields       map[string]any `json:"fields,omitempty"`
}

type traceRecorder struct {
	start  time.Time
	max    int
	next   int
	total  uint64
	events []traceEvent
}

func newTraceRecorder(maxEvents int) *traceRecorder {
	if maxEvents <= 0 {
		maxEvents = 1
	}
	return &traceRecorder{
		start:  time.Now(),
		max:    maxEvents,
		events: make([]traceEvent, 0, maxEvents),
	}
}

func (tr *traceRecorder) Add(source, stage string, requestID int64, fields map[string]any) {
	if tr == nil {
		return
	}
	now := time.Now()
	event := traceEvent{
		Seq:          tr.total + 1,
		Time:         now.UTC(),
		SinceStartMS: now.Sub(tr.start).Milliseconds(),
		Source:       source,
		Stage:        stage,
		RequestID:    requestID,
		Fields:       fields,
	}
	tr.total++
	if len(tr.events) < tr.max {
		tr.events = append(tr.events, event)
		return
	}
	tr.events[tr.next] = event
	tr.next = (tr.next + 1) % tr.max
}

func (tr *traceRecorder) Tail(source string, maxEvents int) []traceEvent {
	if tr == nil || len(tr.events) == 0 {
		return nil
	}
	ordered := make([]traceEvent, 0, len(tr.events))
	if len(tr.events) < tr.max {
		ordered = append(ordered, tr.events...)
	} else {
		ordered = append(ordered, tr.events[tr.next:]...)
		ordered = append(ordered, tr.events[:tr.next]...)
	}
	if source != "" {
		filtered := ordered[:0]
		for _, event := range ordered {
			if event.Source == source {
				filtered = append(filtered, event)
			}
		}
		ordered = filtered
	}
	if maxEvents > 0 && len(ordered) > maxEvents {
		ordered = ordered[len(ordered)-maxEvents:]
	}
	return append([]traceEvent(nil), ordered...)
}

func traceFields(kv ...any) map[string]any {
	if len(kv) == 0 {
		return nil
	}
	fields := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok || key == "" {
			continue
		}
		fields[key] = kv[i+1]
	}
	return fields
}

func (m *multiFlag) String() string {
	return strings.Join(*m, " ")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func reorderArgsForFlags(args []string) []string {
	takesValue := map[string]bool{
		"-qemu-path":                       true,
		"-image":                           true,
		"-workdir":                         true,
		"-payload-size":                    true,
		"-bitmap-size":                     true,
		"-memory":                          true,
		"-hard-timeout":                    true,
		"-windows-minidump-timeout":        true,
		"-standalone-syscall":              true,
		"-standalone-seed":                 true,
		"-standalone-program":              true,
		"-standalone-target-profile":       true,
		"-standalone-exec-program":         true,
		"-standalone-staged-program":       true,
		"-standalone-staged-exec-program":  true,
		"-standalone-rounds":               true,
		"-standalone-stage-delay-ms":       true,
		"-standalone-stage-idle-ms":        true,
		"-standalone-syscall-timeout-ms":   true,
		"-standalone-program-timeout-ms":   true,
		"-standalone-keep-state":           true,
		"-module-ranges":                   true,
		"-coverage-debug-stream":           true,
		"-slow-trace-dir":                  true,
		"-slow-trace-threshold-ms":         true,
		"-slow-trace-max-events":           true,
		"-vv":                              true,
		"-qemu-arg":                        true,
		"--qemu-path":                      true,
		"--image":                          true,
		"--workdir":                        true,
		"--payload-size":                   true,
		"--bitmap-size":                    true,
		"--memory":                         true,
		"--hard-timeout":                   true,
		"--windows-minidump-timeout":       true,
		"--standalone-syscall":             true,
		"--standalone-seed":                true,
		"--standalone-program":             true,
		"--standalone-target-profile":      true,
		"--standalone-exec-program":        true,
		"--standalone-staged-program":      true,
		"--standalone-staged-exec-program": true,
		"--standalone-rounds":              true,
		"--standalone-stage-delay-ms":      true,
		"--standalone-stage-idle-ms":       true,
		"--standalone-syscall-timeout-ms":  true,
		"--standalone-program-timeout-ms":  true,
		"--standalone-keep-state":          true,
		"--module-ranges":                  true,
		"--coverage-debug-stream":          true,
		"--slow-trace-dir":                 true,
		"--slow-trace-threshold-ms":        true,
		"--slow-trace-max-events":          true,
		"--vv":                             true,
		"--qemu-arg":                       true,
	}
	var flags []string
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if strings.Contains(arg, "=") {
				continue
			}
			if takesValue[arg] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, arg)
	}
	return append(flags, pos...)
}

func defaultModuleRangeList() string {
	return "ntoskrnl.exe:required,ntfs.sys,afd.sys,win32k*.sys"
}

func parseModuleRanges(raw string) ([]moduleRangeSpec, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("module range list is empty")
	}
	parts := strings.Split(raw, ",")
	ranges := make([]moduleRangeSpec, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty module range entry in %q", raw)
		}
		required := false
		if strings.HasSuffix(part, ":required") {
			required = true
			part = strings.TrimSuffix(part, ":required")
		}
		if part == "" {
			return nil, fmt.Errorf("empty required module range entry in %q", raw)
		}
		if strings.Contains(part, "\x00") {
			return nil, fmt.Errorf("module range %q contains NUL", part)
		}
		if len(part) >= nyxModuleRangePatternSize {
			return nil, fmt.Errorf("module range %q exceeds %d bytes", part, nyxModuleRangePatternSize-1)
		}
		ranges = append(ranges, moduleRangeSpec{Pattern: part, Required: required})
	}
	if len(ranges) > nyxMaxModuleRangeTargets {
		return nil, fmt.Errorf("module range list has %d entries, max %d", len(ranges), nyxMaxModuleRangeTargets)
	}
	return ranges, nil
}

func formatModuleRanges(ranges []moduleRangeSpec) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		part := r.Pattern
		if r.Required {
			part += ":required"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ",")
}

func packModuleRangeConfig(ranges []moduleRangeSpec) []byte {
	const headerSize = 8
	const entrySize = 1 + nyxModuleRangePatternSize
	payload := make([]byte, headerSize+entrySize*len(ranges))
	binary.LittleEndian.PutUint32(payload[0:4], nyxModuleRangeConfigMagic)
	binary.LittleEndian.PutUint16(payload[4:6], nyxModuleRangeConfigVersion)
	binary.LittleEndian.PutUint16(payload[6:8], uint16(len(ranges)))
	for i, r := range ranges {
		off := headerSize + i*entrySize
		if r.Required {
			payload[off] = 1
		}
		copy(payload[off+1:off+1+nyxModuleRangePatternSize], r.Pattern)
	}
	return payload
}

func bootstrapWSA() string {
	return "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"
}

func bootstrapClose(ref string) string {
	return fmt.Sprintf("closesocket$any(%s)\n", ref)
}

func bootstrapTCPServer(addrRef string) string {
	return bootstrapWSA() +
		"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n" +
		fmt.Sprintf("bind$inet_tcp(r0, %s, 0x10)\n", addrRef) +
		"listen$inet_tcp(r0, 0x1)\n"
}

func bootstrapTCPClient(addrRef string) string {
	return "r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
		fmt.Sprintf("connect$inet_tcp(r1, %s, 0x10)\n", addrRef)
}

func bootstrapUDPClient(addrRef string) string {
	return "r1 = socket$inet_udp(0x2, 0x2, 0x11)\n" +
		fmt.Sprintf("connect$inet_udp(r1, %s, 0x10)\n", addrRef)
}

func bootstrapUDPConnectedSession(addrRef string) string {
	return bootstrapWSA() +
		"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n" +
		fmt.Sprintf("connect$inet_udp(r0, %s, 0x10)\n", addrRef)
}

func bootstrapUDPBoundReceiverWithPeerSend(bindAddrRef, peerAddrRef string) string {
	return bootstrapWSA() +
		"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n" +
		fmt.Sprintf("bind$inet_udp(r0, %s, 0x10)\n", bindAddrRef) +
		bootstrapUDPClient(peerAddrRef) +
		"send$inet_udp(r1, 'abcd', 0x4, 0x0)\n"
}

func bootstrapAcceptSocket() string {
	return "r2 = socket$accept_tcp(0x2, 0x1, 0x6)\n"
}

func bootstrapTCPAcceptedSession() string {
	return "r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"
}

func bootstrapAcceptPeerSend() string {
	return "send$inet_accept(r2, 'abcd', 0x4, 0x0)\n"
}

func bootstrapConnectedPeerSend() string {
	return "send$inet_tcp(r1, 'abcd', 0x4, 0x0)\n"
}

func bootstrapFilePayload() string {
	return "r3 = CreateFileA(&(0x7f0000000200)='./nyx-txfile\\x00', 0xffffffff, 0x7, 0x0, 0x2, 0x80, 0xffffffffffffffff)\n" +
		"WriteFile(r3, &(0x7f0000000240)='abcd', 0x4, &(0x7f0000000280)=0x0, 0x0)\n"
}

func bootstrapTCPAcceptedSessionWithClient(listenerAddrRef, clientAddrRef string) string {
	return bootstrapTCPServer(listenerAddrRef) +
		bootstrapTCPClient(clientAddrRef) +
		bootstrapTCPAcceptedSession()
}

func bootstrapTCPAcceptExSessionWithClient(listenerAddrRef, clientAddrRef string) string {
	return bootstrapTCPServer(listenerAddrRef) +
		bootstrapTCPClient(clientAddrRef) +
		bootstrapAcceptSocket()
}

func bootstrapTCPAcceptExPendingSessionWithClient(listenerAddrRef, clientAddrRef string) string {
	return bootstrapTCPServer(listenerAddrRef) +
		bootstrapAcceptSocket() +
		"r3 = AcceptEx$inet_tcp_pending(r0, r2, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
		bootstrapTCPClient(clientAddrRef)
}

func bootstrapTCPAcceptExUpdatedSessionWithClient(listenerAddrRef, clientAddrRef string) string {
	return bootstrapTCPAcceptExPendingSessionWithClient(listenerAddrRef, clientAddrRef) +
		"r4 = setsockopt$update_accept_context(r3, 0xffff, 0x700b, &(0x7f0000000380)=r0, 0x8)\n"
}

func bootstrapTCPAcceptedSessionWithClientConnectedPeerSend(listenerAddrRef, clientAddrRef string) string {
	return bootstrapTCPAcceptedSessionWithClient(listenerAddrRef, clientAddrRef) +
		bootstrapConnectedPeerSend()
}

func bootstrapTCPAcceptedSessionWithClientAcceptPeerSend(listenerAddrRef, clientAddrRef string) string {
	return bootstrapTCPAcceptedSessionWithClient(listenerAddrRef, clientAddrRef) +
		bootstrapAcceptPeerSend()
}

func bootstrapCloseAcceptSessionSockets() string {
	return bootstrapClose("r2") +
		bootstrapClose("r1") +
		bootstrapClose("r0")
}

func bootstrapTCPListenerNonblocking() string {
	return "ioctlsocket$fionbio_tcp(r0, 0x8004667e, &(0x7f0000000080)=0x1)\n"
}

type nyxMsgHeader struct {
	Magic    uint32
	Version  uint16
	Kind     uint16
	BodySize uint32
}

type nyxExecMeta struct {
	RequestID int64
	ProcID    int32
	Flags     int32
}

type nyxIdleMeta struct {
	SleepMS  uint32
	Reserved uint32
}

type nyxCovHeader struct {
	Magic       uint32
	Version     uint16
	Reserved    uint16
	RecordCount uint32
}

type nyxCovRecord struct {
	CallIndex uint32
	SlotID    uint32
	Flags     uint64
	PCCount   uint32
	Reserved  uint32
}

type nyxCovDumpRecord struct {
	CallIndex uint32
	SlotID    uint32
	Flags     uint64
	PCs       []uint64
}

type moduleCoverageSlotSummary struct {
	SlotID  uint32
	Records int
	PCs     int
}

type moduleCoverageCallSummary struct {
	CallIndex uint32
	SlotID    uint32
	CallName  string
	Records   int
	PCs       int
}

type callFeedbackSummary struct {
	CallIndex uint32
	CallName  string
	Signal    int
	Cover     int
	Comps     int
	Error     int32
}

type coverageDebugStreamEvent struct {
	RequestID   int64                     `json:"request_id"`
	GeneratedAt time.Time                 `json:"generated_at"`
	Calls       []coverageDebugStreamCall `json:"calls,omitempty"`
}

type coverageDebugStreamCall struct {
	CallIndex uint32   `json:"call_index"`
	CallName  string   `json:"call_name,omitempty"`
	SlotID    uint32   `json:"slot_id"`
	Module    string   `json:"module,omitempty"`
	PCs       []string `json:"pcs"`
	Offsets   []string `json:"offsets,omitempty"`
}

type moduleRuntimeRange struct {
	SlotID uint32
	Target string
	Name   string
	Base   uint64
	End    uint64
}

type moduleRangeCanonicalizer struct {
	canonical map[string]moduleRuntimeRange
	current   []moduleRuntimeRange
}

type nyxCompEntry struct {
	Pc    uint64
	Op1   uint64
	Op2   uint64
	Size  uint8
	Kind  uint8
	IsImm uint8
}

type nyxCovCompRecord struct {
	CallIndex uint32
	SlotID    uint32
	Flags     uint64
	Comps     []nyxCompEntry
}

const (
	nyxCovMagic        = 0x564f4353
	nyxCovVersion      = 2
	nyxCovVersionMinV1 = 1
)

type qemuAux struct {
	data []byte
}

func openAux(path string) (*qemuAux, error) {
	fd, err := unix.Open(path, unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	data, err := unix.Mmap(fd, 0, 0x1000, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	aux := &qemuAux{data: data}
	if binary.LittleEndian.Uint64(aux.data[:8]) != nyxAuxMagic {
		return nil, fmt.Errorf("bad aux magic")
	}
	if binary.LittleEndian.Uint16(aux.data[8:10]) != nyxAuxVersion ||
		binary.LittleEndian.Uint16(aux.data[10:12]) != nyxAuxHash {
		return nil, fmt.Errorf("bad aux header version/hash")
	}
	return aux, nil
}

func (a *qemuAux) close() {
	_ = unix.Munmap(a.data)
}

func (a *qemuAux) state() uint8 {
	return a.data[nyxStateOffset]
}

func (a *qemuAux) execDone() bool {
	return a.data[nyxResultExecDoneOffset] != 0
}

func (a *qemuAux) execCode() uint8 {
	return a.data[nyxResultExecCodeOffset]
}

// reloaded reports whether nyx restored the root snapshot during the last
// execution (set by qemu-nyx perform_reload on timeout/crash/asan). When true
// the VM is already back at the primed root snapshot, so no full VM restart is
// needed to recover from a hanged request.
func (a *qemuAux) reloaded() bool {
	return a.data[nyxResultReloadedOffset] != 0
}

func (a *qemuAux) ptOverflow() bool {
	return a.data[nyxResultPtOverflowOff] != 0
}

func (a *qemuAux) pageFault() bool {
	return a.data[nyxResultPageFaultOff] != 0
}

func (a *qemuAux) pageAddr() uint64 {
	return binary.LittleEndian.Uint64(a.data[nyxResultPageAddrOff : nyxResultPageAddrOff+8])
}

func (a *qemuAux) misc() []byte {
	mlen := binary.LittleEndian.Uint16(a.data[nyxMiscOffset : nyxMiscOffset+2])
	if nyxMiscOffset+2+int(mlen) > len(a.data) {
		mlen = uint16(len(a.data) - nyxMiscOffset - 2)
	}
	return append([]byte{}, a.data[nyxMiscOffset+2:nyxMiscOffset+2+int(mlen)]...)
}

func (a *qemuAux) clearTransientResult() {
	a.data[nyxResultExecDoneOffset] = 0
	a.data[nyxResultExecCodeOffset] = 0
	a.data[nyxResultReloadedOffset] = 0
	a.data[nyxResultPtOverflowOff] = 0
	a.data[nyxResultPageFaultOff] = 0
	for i := 0; i < 8; i++ {
		a.data[nyxResultPageAddrOff+i] = 0
	}
	binary.LittleEndian.PutUint16(a.data[nyxMiscOffset:nyxMiscOffset+2], 0)
}

func (a *qemuAux) setTimeout(timeout time.Duration) {
	secs := byte(timeout / time.Second)
	usec := uint32((timeout % time.Second) / time.Microsecond)
	a.data[128+256] = 1
	a.data[128+256+1] = secs
	binary.LittleEndian.PutUint32(a.data[128+256+2:128+256+6], usec)
}

func (a *qemuAux) dumpPage(addr uint64) {
	a.data[128+256] = 1
	a.data[128+256+10] = 1
	binary.LittleEndian.PutUint64(a.data[128+256+11:128+256+19], addr)
}

func deriveHardTimeout(programTimeoutMs int32, fallback time.Duration) time.Duration {
	if fallback <= 0 {
		fallback = 3 * time.Minute
	}
	if programTimeoutMs <= 0 {
		return fallback
	}
	programTimeout := time.Duration(programTimeoutMs) * time.Millisecond
	slack := programTimeout
	if slack < 10*time.Second {
		slack = 10 * time.Second
	}
	hardTimeout := programTimeout + slack
	if hardTimeout > fallback {
		return fallback
	}
	return hardTimeout
}

func applyStandaloneHardTimeout(vm *nyxVM, programTimeoutMs int) time.Duration {
	derivedTimeout := deriveHardTimeout(int32(programTimeoutMs), vm.hardTimeout)
	if derivedTimeout != vm.hardTimeout {
		log.Logf(0, "standalone using derived hard timeout %s (fallback=%s program_timeout_ms=%d)",
			derivedTimeout, vm.hardTimeout, programTimeoutMs)
		vm.hardTimeout = derivedTimeout
	}
	return vm.hardTimeout
}

type nyxVM struct {
	index       int
	workdir     string
	dumpDir     string
	controlPath string
	auxPath     string
	sharedDir   string
	bitmapPath  string
	payloadPath string
	ijonPath    string
	coverPath   string
	snapshotDir string

	payloadSize int
	bitmapSize  int

	qemuPath               string
	qemuArgs               []string
	image                  string
	memoryMB               int
	debug                  bool
	hardTimeout            time.Duration
	moduleRanges           []moduleRangeSpec
	windowsMinidump        bool
	windowsMinidumpTimeout int
	runtimeModuleRanges    []moduleRuntimeRange
	moduleCanonicalizer    moduleRangeCanonicalizer

	ctx         context.Context
	payloadFile *os.File
	payloadMM   []byte
	auxFile     *os.File
	auxMM       []byte
	control     net.Conn
	aux         *qemuAux
	process     *exec.Cmd
	trace       *traceRecorder
	traceReqID  int64
}

func (vm *nyxVM) debugLogf(msg string, args ...any) {
	if vm.debug {
		log.Logf(0, msg, args...)
	}
}

func (vm *nyxVM) recordTrace(source, stage string, requestID int64, fields map[string]any) {
	if vm == nil || vm.trace == nil {
		return
	}
	vm.trace.Add(source, stage, requestID, fields)
}

func (vm *nyxVM) recordAuxTrace(stage string, requestID int64) {
	if vm == nil || vm.aux == nil || vm.trace == nil {
		return
	}
	fields := traceFields(
		"state", vm.aux.state(),
		"exec_done", vm.aux.execDone(),
		"exec_code", vm.aux.execCode(),
		"exec_code_name", nyxExitReason(vm.aux.execCode()),
		"reloaded", vm.aux.reloaded(),
		"pt_overflow", vm.aux.ptOverflow(),
		"page_fault", vm.aux.pageFault(),
	)
	if vm.aux.pageFault() {
		fields["page_addr"] = fmt.Sprintf("0x%x", vm.aux.pageAddr())
	}
	if misc := cleanAuxMessage(vm.aux.misc()); misc != "" {
		fields["misc"] = misc
	}
	vm.recordTrace("qemu", stage, requestID, fields)
}

func (vm *nyxVM) recordHprintfTrace(requestID int64) {
	if vm == nil || vm.aux == nil || vm.trace == nil {
		return
	}
	msg := cleanAuxMessage(vm.aux.misc())
	if msg == "" {
		return
	}
	fields := traceFields("message", msg)
	for key, value := range traceKeyValueFields(msg) {
		fields[key] = value
	}
	vm.recordTrace("executor", hprintfStage(msg), requestID, fields)
}

func cleanAuxMessage(data []byte) string {
	return strings.TrimSpace(strings.TrimRight(string(data), "\x00"))
}

func traceKeyValueFields(msg string) map[string]any {
	fields := map[string]any{}
	for _, part := range strings.Fields(msg) {
		key, value, ok := strings.Cut(part, "=")
		if !ok || key == "" || value == "" {
			continue
		}
		fields[key] = traceScalar(value)
	}
	return fields
}

func traceScalar(value string) any {
	value = strings.TrimRight(value, ",")
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		return value
	}
	if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
		return parsed
	}
	return value
}

func hprintfStage(msg string) string {
	if index := strings.Index(msg, "stage="); index >= 0 {
		value := msg[index+len("stage="):]
		if end := strings.IndexAny(value, " \n\r\t"); end >= 0 {
			value = value[:end]
		}
		if value != "" {
			return value
		}
	}
	switch {
	case strings.HasPrefix(msg, "nyx exec preview"):
		return "exec_preview"
	case strings.HasPrefix(msg, "nyx exec req="):
		return "exec_request"
	case strings.HasPrefix(msg, "nyx cov dumped"):
		return "coverage_dump"
	case strings.HasPrefix(msg, "nyx result dumped"):
		return "result_dump"
	case strings.HasPrefix(msg, "nyx result requesting reload"):
		return "request_reload"
	case strings.HasPrefix(msg, "nyx handshake"):
		return "handshake"
	case strings.HasPrefix(msg, "nyx module range"):
		return "module_range"
	default:
		return "hprintf"
	}
}

func newNyxVM(index int, workdir, qemuPath string, qemuArgs []string, image string, memoryMB int, payloadSize, bitmapSize int, debug bool, hardTimeout time.Duration, moduleRanges []moduleRangeSpec, windowsMinidump bool, windowsMinidumpTimeout int) *nyxVM {
	payloadSize = alignUp(payloadSize, nyxPageSize)
	return &nyxVM{
		index:                  index,
		workdir:                workdir,
		dumpDir:                filepath.Join(workdir, "dump"),
		controlPath:            filepath.Join(workdir, fmt.Sprintf("interface_%d", index)),
		auxPath:                filepath.Join(workdir, fmt.Sprintf("aux_buffer_%d", index)),
		sharedDir:              filepath.Join(workdir, "sharedir"),
		bitmapPath:             filepath.Join(workdir, fmt.Sprintf("bitmap_%d", index)),
		payloadPath:            filepath.Join(workdir, fmt.Sprintf("payload_%d", index)),
		ijonPath:               filepath.Join(workdir, fmt.Sprintf("ijon_%d", index)),
		coverPath:              filepath.Join(workdir, fmt.Sprintf("syz_cov_%d.bin", index)),
		snapshotDir:            filepath.Join(workdir, "snapshot"),
		payloadSize:            payloadSize,
		bitmapSize:             bitmapSize,
		qemuPath:               qemuPath,
		qemuArgs:               qemuArgs,
		image:                  image,
		memoryMB:               memoryMB,
		debug:                  debug,
		hardTimeout:            hardTimeout,
		moduleRanges:           append([]moduleRangeSpec(nil), moduleRanges...),
		windowsMinidump:        windowsMinidump,
		windowsMinidumpTimeout: windowsMinidumpTimeout,
	}
}

func alignUp(v, align int) int {
	if align <= 0 {
		return v
	}
	rem := v % align
	if rem == 0 {
		return v
	}
	return v + align - rem
}

func (vm *nyxVM) start(ctx context.Context) error {
	vm.ctx = ctx
	vm.recordTrace("runner", "vm_start", 0, traceFields(
		"workdir", vm.workdir,
		"qemu_path", vm.qemuPath,
		"hard_timeout_ms", vm.hardTimeout.Milliseconds(),
	))
	if err := os.MkdirAll(vm.workdir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(vm.dumpDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(vm.sharedDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(vm.workdir, fmt.Sprintf("redqueen_workdir_%d", vm.index)), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(vm.snapshotDir, 0o755); err != nil {
		return err
	}
	for _, path := range []string{
		filepath.Join(vm.workdir, "page_cache.lock"),
		filepath.Join(vm.workdir, "page_cache.addr"),
		filepath.Join(vm.workdir, "page_cache.dump"),
	} {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
		if err != nil {
			return err
		}
		_ = f.Close()
	}
	for _, path := range []string{
		vm.controlPath,
		vm.auxPath,
		vm.coverPath,
		filepath.Join(vm.dumpDir, nyxHandshakeAck),
		filepath.Join(vm.dumpDir, nyxExecResult),
	} {
		_ = os.Remove(path)
	}
	for _, file := range []struct {
		path string
		size int64
	}{
		{vm.bitmapPath, int64(vm.bitmapSize)},
		{vm.payloadPath, int64(vm.payloadSize)},
		{vm.ijonPath, 0x1000},
	} {
		f, err := os.OpenFile(file.path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		if err := f.Truncate(file.size); err != nil {
			f.Close()
			return err
		}
		if file.path == vm.payloadPath {
			vm.payloadFile = f
		} else {
			f.Close()
		}
	}
	payloadMM, err := unix.Mmap(int(vm.payloadFile.Fd()), 0, vm.payloadSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return err
	}
	vm.payloadMM = payloadMM
	if len(vm.moduleRanges) != 0 {
		log.Logf(0, "runner module range config: %s", formatModuleRanges(vm.moduleRanges))
		path := filepath.Join(vm.sharedDir, nyxModuleRangeConfigFile)
		if err := os.WriteFile(path, packModuleRangeConfig(vm.moduleRanges), 0o644); err != nil {
			return fmt.Errorf("write module range config %s: %w", path, err)
		}
	}

	args := append([]string{}, vm.qemuArgs...)
	if vm.image != "" {
		args = append(args, "-drive", qemuImageDriveArg(vm.image))
	}
	if vm.memoryMB > 0 {
		args = append(args, "-m", fmt.Sprint(vm.memoryMB))
	}
	nyxDevice := fmt.Sprintf("nyx,chardev=nyx_socket,workdir=%s,sharedir=%s,worker_id=%d,bitmap_size=%d,input_buffer_size=%d",
		vm.workdir, vm.sharedDir, vm.index, vm.bitmapSize, vm.payloadSize)
	if vm.windowsMinidump {
		nyxDevice += ",windows_minidump"
		if vm.windowsMinidumpTimeout > 0 {
			nyxDevice += fmt.Sprintf(",windows_minidump_timeout=%d", vm.windowsMinidumpTimeout)
		}
	}
	args = append(args,
		"-chardev", fmt.Sprintf("socket,server,id=nyx_socket,path=%s", vm.controlPath),
		"-device", nyxDevice,
		"-fast_vm_reload", fmt.Sprintf("path=%s,load=off", vm.snapshotDir),
	)
	vm.process = osutil.CommandContext(ctx, vm.qemuPath, args...)
	if vm.debug {
		vm.process.Stdout = os.Stdout
		vm.process.Stderr = os.Stderr
	}
	if err := vm.process.Start(); err != nil {
		return err
	}
	vm.recordTrace("runner", "qemu_started", 0, traceFields("pid", vm.process.Process.Pid))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", vm.controlPath)
		if err == nil {
			vm.control = conn
			break
		}
		if vm.process.ProcessState != nil && vm.process.ProcessState.Exited() {
			return errors.New("qemu exited before nyx socket appeared")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if vm.control == nil {
		return errors.New("timed out waiting for qemu nyx socket")
	}
	auxDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(auxDeadline) {
		if _, err := os.Stat(vm.auxPath); err == nil {
			break
		}
		if vm.process.ProcessState != nil && vm.process.ProcessState.Exited() {
			return errors.New("qemu exited before aux buffer appeared")
		}
		time.Sleep(100 * time.Millisecond)
	}
	vm.aux, err = openAux(vm.auxPath)
	if err != nil {
		return fmt.Errorf("open aux buffer: %w", err)
	}
	vm.recordAuxTrace("aux_opened", 0)
	initTimeout := vm.initWaitTimeout()
	initDeadline := time.Now().Add(initTimeout)
	initTimedOut := make(chan struct{}, 1)
	initDone := make(chan struct{})
	go func(process *os.Process) {
		timer := time.NewTimer(initTimeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			if process != nil {
				_ = process.Kill()
			}
			initTimedOut <- struct{}{}
		case <-initDone:
		}
	}(vm.process.Process)
	defer close(initDone)
	lastState := vm.aux.state()
	lastReport := time.Now()
	for vm.aux.state() != 3 {
		select {
		case <-initTimedOut:
			return fmt.Errorf("timed out waiting for nyx init state=3: state=%d exec_code=%d misc=%q",
				vm.aux.state(), vm.aux.execCode(), strings.TrimSpace(string(vm.aux.misc())))
		default:
		}
		if time.Now().After(initDeadline) {
			return fmt.Errorf("timed out waiting for nyx init state=3: state=%d exec_code=%d misc=%q",
				vm.aux.state(), vm.aux.execCode(), strings.TrimSpace(string(vm.aux.misc())))
		}
		remaining := time.Until(initDeadline)
		if err := vm.stepUntilReady(remaining); err != nil {
			select {
			case <-initTimedOut:
				return fmt.Errorf("timed out waiting for nyx init state=3: state=%d exec_code=%d misc=%q",
					vm.aux.state(), vm.aux.execCode(), strings.TrimSpace(string(vm.aux.misc())))
			default:
			}
			if isTimeoutError(err) {
				return fmt.Errorf("timed out stepping qemu during nyx init: state=%d exec_code=%d misc=%q",
					vm.aux.state(), vm.aux.execCode(), strings.TrimSpace(string(vm.aux.misc())))
			}
			return err
		}
		if vm.aux.state() != lastState || time.Since(lastReport) > 10*time.Second {
			log.Logf(0, "nyx init state=%d exec_code=%d misc=%q",
				vm.aux.state(), vm.aux.execCode(), strings.TrimSpace(string(vm.aux.misc())))
			vm.recordAuxTrace("init_wait", 0)
			lastState = vm.aux.state()
			lastReport = time.Now()
		}
	}
	vm.recordAuxTrace("init_ready", 0)
	vm.applyHardTimeout()
	return nil
}

// ensureAuxMmap opens and mmaps the aux buffer file, which is created
// by QEMU at startup (not by the runner).  Called lazily on first use.
func (vm *nyxVM) ensureAuxMmap() error {
	if vm.auxMM != nil {
		return nil
	}
	f, err := os.OpenFile(vm.auxPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	mm, err := unix.Mmap(int(f.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		f.Close()
		return err
	}
	vm.auxFile = f
	vm.auxMM = mm
	return nil
}

func (vm *nyxVM) applyHardTimeout() {
	t := vm.hardTimeout
	if t <= 0 {
		t = 3 * time.Minute
	}
	if t > 255*time.Second {
		log.Logf(0, "runner hard timeout %s exceeds aux limit; clamping to 255s", t)
		t = 255 * time.Second
	}
	vm.aux.setTimeout(t)
}

func qemuImageDriveArg(image string) string {
	opts := []string{"file=" + image, "if=ide"}
	switch strings.ToLower(filepath.Ext(image)) {
	case ".qcow2":
		opts = append(opts, "format=qcow2")
	case ".raw", ".img":
		opts = append(opts, "format=raw")
	}
	return strings.Join(opts, ",")
}

func (vm *nyxVM) stepUntilReady(timeout time.Duration) error {
	if err := vm.runQemuWithTimeout(timeout); err != nil {
		return err
	}
	switch vm.aux.execCode() {
	case nyxRCHprintf:
		vm.recordModuleRangesFromAux()
		log.Logf(0, "nyx hprintf: %s", string(vm.aux.misc()))
	case nyxRCAbort:
		return fmt.Errorf("guest abort during init: %s", string(vm.aux.misc()))
	}
	return nil
}

func (vm *nyxVM) recordModuleRangesFromAux() {
	vm.moduleCanonicalizer.Record(parseModuleRangesFromAux(string(vm.aux.misc())))
	vm.runtimeModuleRanges = vm.moduleCanonicalizer.Current()
}

func (can *moduleRangeCanonicalizer) Record(rows []moduleRuntimeRange) {
	for _, row := range rows {
		if can.canonical == nil {
			can.canonical = make(map[string]moduleRuntimeRange)
		}
		if _, ok := can.canonical[moduleRangeKey(row)]; !ok {
			can.canonical[moduleRangeKey(row)] = row
		}
		replaced := false
		for i := range can.current {
			if can.current[i].SlotID == row.SlotID {
				can.current[i] = row
				replaced = true
				break
			}
		}
		if !replaced {
			can.current = append(can.current, row)
		}
	}
}

func (can moduleRangeCanonicalizer) Current() []moduleRuntimeRange {
	return slicesCloneModuleRanges(can.current)
}

func (can moduleRangeCanonicalizer) CanonicalRanges() []moduleRuntimeRange {
	ret := make([]moduleRuntimeRange, 0, len(can.canonical))
	for _, rng := range can.canonical {
		ret = append(ret, rng)
	}
	sort.Slice(ret, func(i, j int) bool {
		if ret[i].SlotID != ret[j].SlotID {
			return ret[i].SlotID < ret[j].SlotID
		}
		return moduleRangeKey(ret[i]) < moduleRangeKey(ret[j])
	})
	return ret
}

func (can moduleRangeCanonicalizer) CanonicalizePCs(pcs []uint64) []uint64 {
	if len(pcs) == 0 || len(can.current) == 0 || len(can.canonical) == 0 {
		return pcs
	}
	ret := pcs[:0]
	for _, pc := range pcs {
		ret = append(ret, can.CanonicalizePC(pc))
	}
	return ret
}

func (can moduleRangeCanonicalizer) CanonicalizePC(pc uint64) uint64 {
	for _, current := range can.current {
		if pc < current.Base || pc >= current.End {
			continue
		}
		canonical, ok := can.canonical[moduleRangeKey(current)]
		if !ok || canonical.End <= canonical.Base {
			return pc
		}
		off := pc - current.Base
		if off >= canonical.End-canonical.Base {
			return pc
		}
		return canonical.Base + off
	}
	return pc
}

func moduleRangeKey(rng moduleRuntimeRange) string {
	return strings.ToLower(rng.Target) + "\x00" + strings.ToLower(rng.Name)
}

func slicesCloneModuleRanges(ranges []moduleRuntimeRange) []moduleRuntimeRange {
	if len(ranges) == 0 {
		return nil
	}
	ret := make([]moduleRuntimeRange, len(ranges))
	copy(ret, ranges)
	return ret
}

func parseModuleRangesFromAux(text string) []moduleRuntimeRange {
	var ranges []moduleRuntimeRange
	for _, line := range strings.Split(text, "\n") {
		match := reNyxModuleRangeSubmitted.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		slotID, err := strconv.ParseUint(match[1], 10, 32)
		if err != nil {
			continue
		}
		base, err := strconv.ParseUint(match[4], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(match[5], 16, 64)
		if err != nil || end <= base {
			continue
		}
		ranges = append(ranges, moduleRuntimeRange{
			SlotID: uint32(slotID),
			Target: match[2],
			Name:   match[3],
			Base:   base,
			End:    end,
		})
	}
	return ranges
}

func nyxModuleInfoFiles(ranges []moduleRuntimeRange) []*flatrpc.FileInfo {
	if len(ranges) == 0 {
		return nil
	}
	modules := make([]*vminfo.KernelModule, 0, len(ranges))
	for _, rng := range ranges {
		if rng.End <= rng.Base || rng.Name == "" {
			continue
		}
		modules = append(modules, &vminfo.KernelModule{
			Name: rng.Name,
			Addr: rng.Base,
			Size: rng.End - rng.Base,
			Path: rng.Name,
		})
	}
	if len(modules) == 0 {
		return nil
	}
	data, err := json.Marshal(modules)
	if err != nil {
		return nil
	}
	return []*flatrpc.FileInfo{{
		Name:   vminfo.NyxModulesFile,
		Exists: true,
		Data:   data,
	}}
}

func (vm *nyxVM) close() {
	if vm.aux != nil {
		vm.aux.close()
		vm.aux = nil
	}
	if vm.control != nil {
		_ = vm.control.Close()
		vm.control = nil
	}
	if vm.payloadMM != nil {
		_ = unix.Munmap(vm.payloadMM)
		vm.payloadMM = nil
	}
	if vm.payloadFile != nil {
		_ = vm.payloadFile.Close()
		vm.payloadFile = nil
	}
	if vm.auxMM != nil {
		_ = unix.Munmap(vm.auxMM)
		vm.auxMM = nil
	}
	if vm.auxFile != nil {
		_ = vm.auxFile.Close()
		vm.auxFile = nil
	}
	if vm.process != nil && vm.process.Process != nil {
		_ = osutil.KillAndWait(vm.process, 10*time.Second)
	}
	vm.process = nil
	_ = os.Remove(vm.controlPath)
	_ = os.Remove(vm.auxPath)
}

func (vm *nyxVM) restart() error {
	ctx := vm.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	vm.close()
	return vm.start(ctx)
}

func (vm *nyxVM) runQemu() error {
	return vm.runQemuWithTimeout(0)
}

func (vm *nyxVM) runQemuWithTimeout(timeout time.Duration) error {
	requestID := vm.traceReqID
	vm.recordTrace("qemu", "kvm_run_begin", requestID, traceFields("timeout_ms", timeout.Milliseconds()))
	started := time.Now()
	if timeout > 0 {
		if err := vm.control.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		defer vm.control.SetDeadline(time.Time{})
	}
	if _, err := vm.control.Write([]byte{nyxInterfacePing}); err != nil {
		return err
	}
	var ack [1]byte
	_, err := vm.control.Read(ack[:])
	fields := traceFields("duration_ms", time.Since(started).Milliseconds())
	if err != nil {
		fields["error"] = err.Error()
	}
	vm.recordTrace("qemu", "kvm_run_end", requestID, fields)
	return err
}

func (vm *nyxVM) setPayload(payload []byte) error {
	if len(payload)+4 > len(vm.payloadMM) {
		return fmt.Errorf("payload too large: %d > %d", len(payload)+4, len(vm.payloadMM))
	}
	binary.LittleEndian.PutUint32(vm.payloadMM[:4], uint32(len(payload)))
	copy(vm.payloadMM[4:], payload)
	for i := 4 + len(payload); i < len(vm.payloadMM); i++ {
		vm.payloadMM[i] = 0
	}
	return nil
}

func (vm *nyxVM) executeHandshake(payload []byte, requestID int64) error {
	prevReqID := vm.traceReqID
	vm.traceReqID = requestID
	defer func() {
		vm.traceReqID = prevReqID
	}()
	vm.recordTrace("runner", "handshake_begin", requestID, traceFields("payload_bytes", len(payload)))
	_ = os.Remove(filepath.Join(vm.dumpDir, nyxHandshakeAck))
	vm.aux.clearTransientResult()
	if err := vm.setPayload(payload); err != nil {
		return err
	}
	deadline := time.Now().Add(vm.execWaitTimeout())
	for i := 0; i < 16; i++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			vm.recordAuxTrace("handshake_deadline_expired", requestID)
			return errors.New("timed out waiting for nyx handshake ack")
		}
		vm.debugLogf("runner handshake step=%d state=%d exec_done=%v exec_code=%d misc=%q",
			i, vm.aux.state(), vm.aux.execDone(), vm.aux.execCode(),
			strings.TrimSpace(string(vm.aux.misc())))
		if err := vm.runQemuWithTimeout(remaining); err != nil {
			if isTimeoutError(err) {
				vm.recordAuxTrace("handshake_step_timeout", requestID)
				return fmt.Errorf("timed out waiting for nyx handshake ack at step=%d: %w", i, err)
			}
			return err
		}
		if data, err := os.ReadFile(filepath.Join(vm.dumpDir, nyxHandshakeAck)); err == nil && bytes.Equal(data, []byte("ok")) {
			vm.debugLogf("runner handshake ack observed at step=%d", i)
			vm.recordTrace("runner", "handshake_ack", requestID, traceFields("step", i))
			return nil
		}
		vm.recordAuxTrace("handshake_step", requestID)
		vm.debugLogf("runner handshake post-step=%d state=%d exec_done=%v exec_code=%d misc=%q",
			i, vm.aux.state(), vm.aux.execDone(), vm.aux.execCode(),
			strings.TrimSpace(string(vm.aux.misc())))
		switch vm.aux.execCode() {
		case nyxRCHprintf:
			vm.recordHprintfTrace(requestID)
			vm.recordModuleRangesFromAux()
			vm.debugLogf("nyx hprintf: %s", string(vm.aux.misc()))
		case nyxRCAbort:
			return fmt.Errorf("guest abort during handshake: %s", string(vm.aux.misc()))
		}
	}
	return errors.New("timed out waiting for nyx handshake ack")
}

func (vm *nyxVM) executeRequest(payload []byte, req *flatrpc.ExecRequest) (*flatrpc.ExecutorMessage, error) {
	requestID := reqID(req)
	vm.traceReqID = requestID
	defer func() {
		vm.traceReqID = 0
	}()
	vm.recordTrace("runner", "exec_payload_begin", requestID, traceFields(
		"payload_bytes", len(payload),
	))
	_ = os.Remove(filepath.Join(vm.dumpDir, nyxExecResult))
	_ = os.Remove(vm.coverPath)
	vm.aux.clearTransientResult()
	if err := vm.setPayload(payload); err != nil {
		return nil, err
	}
	steps := 0
	deadline := time.Now().Add(vm.execWaitTimeout())
	resultPath := filepath.Join(vm.dumpDir, nyxExecResult)
	for {
		if data, err := os.ReadFile(resultPath); err == nil {
			vm.debugLogf("runner exec result observed before step=%d", steps)
			vm.recordTrace("runner", "exec_result_file", requestID, traceFields("step", steps, "bytes", len(data)))
			msg, err := parseExecResult(data)
			if err != nil {
				return nil, err
			}
			return msg, nil
		}
		if time.Now().After(deadline) {
			log.Logf(0, "runner exec wait deadline expired after %d steps; synthesizing hanged result", steps)
			vm.recordAuxTrace("exec_deadline_expired", requestID)
			return synthesizeHangedResult(req), nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			log.Logf(0, "runner exec wait deadline expired before step=%d; synthesizing hanged result", steps)
			return synthesizeHangedResult(req), nil
		}
		vm.debugLogf("runner exec step=%d state=%d exec_done=%v exec_code=%d misc=%q",
			steps, vm.aux.state(), vm.aux.execDone(), vm.aux.execCode(),
			strings.TrimSpace(string(vm.aux.misc())))
		if err := vm.runQemuWithTimeout(remaining); err != nil {
			if isTimeoutError(err) {
				log.Logf(0, "runner exec qemu step timeout at step=%d; synthesizing hanged result", steps)
				vm.recordAuxTrace("exec_step_timeout", requestID)
				return synthesizeHangedResult(req), nil
			}
			return nil, err
		}
		steps++
		vm.recordAuxTrace("exec_step", requestID)
		vm.debugLogf("runner exec post-step=%d state=%d exec_done=%v exec_code=%d misc=%q",
			steps, vm.aux.state(), vm.aux.execDone(), vm.aux.execCode(),
			strings.TrimSpace(string(vm.aux.misc())))
		if vm.aux.pageFault() {
			vm.recordAuxTrace("page_fault", requestID)
			vm.aux.dumpPage(vm.aux.pageAddr())
			continue
		}
		switch vm.aux.execCode() {
		case nyxRCCrash, nyxRCSanitizer:
			vm.recordAuxTrace("exec_crash", requestID)
			return nil, vm.makeCrashError(vm.aux.execCode(), req)
		case nyxRCHprintf:
			vm.recordHprintfTrace(requestID)
			vm.recordModuleRangesFromAux()
			vm.debugLogf("nyx hprintf: %s", string(vm.aux.misc()))
			continue
		case nyxRCTimeout:
			log.Logf(0, "runner exec timeout at step=%d; synthesizing hanged result", steps)
			vm.recordAuxTrace("exec_timeout", requestID)
			return synthesizeHangedResult(req), nil
		case nyxRCAbort:
			vm.recordAuxTrace("exec_abort", requestID)
			return nil, fmt.Errorf("guest abort: %s", string(vm.aux.misc()))
		}
		if vm.aux.execDone() {
			vm.debugLogf("runner exec observed exec_done at step=%d but result file is not present yet", steps)
			vm.recordAuxTrace("exec_done_without_result", requestID)
		}
	}
}

func (vm *nyxVM) executeIdle(sleepMs int) (*flatrpc.ExecutorMessage, error) {
	if sleepMs < 0 {
		return nil, fmt.Errorf("bad idle sleep: %d", sleepMs)
	}
	if sleepMs > 10000 {
		return nil, fmt.Errorf("idle sleep too large: %d", sleepMs)
	}
	body := new(bytes.Buffer)
	_ = binary.Write(body, binary.LittleEndian, &nyxIdleMeta{SleepMS: uint32(sleepMs)})
	req := &flatrpc.ExecRequest{
		Id:   0,
		Type: flatrpc.RequestTypeProgram,
		ExecOpts: &flatrpc.ExecOpts{
			ExecFlags: 0,
		},
	}
	return vm.executeRequest(packNyxPayload(nyxKindIdle, nil, body.Bytes()), req)
}

func reqID(req *flatrpc.ExecRequest) int64 {
	if req == nil {
		return 0
	}
	return req.Id
}

func (vm *nyxVM) execWaitTimeout() time.Duration {
	return timeoutWithSlack(vm.hardTimeout)
}

func (vm *nyxVM) initWaitTimeout() time.Duration {
	timeout := hardTimeoutWithSlack(vm.hardTimeout)
	if timeout < nyxInitMinTimeout+5*time.Second {
		return nyxInitMinTimeout + 5*time.Second
	}
	return timeout
}

func hardTimeoutWithSlack(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	return timeout + 5*time.Second
}

func timeoutWithSlack(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return timeout + 5*time.Second
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func parseExecResult(data []byte) (*flatrpc.ExecutorMessage, error) {
	if len(data) < 4 {
		return nil, errors.New("short nyx exec result")
	}
	raw, err := flatrpc.Parse[*flatrpc.ExecutorMessageRaw](data[4:])
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func synthesizeHangedResult(req *flatrpc.ExecRequest) *flatrpc.ExecutorMessage {
	callCount := 0
	var id int64
	if req != nil {
		id = req.Id
		callCount = progExecCallCountOrPanic(req.Data)
	}
	return &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type: flatrpc.ExecutorMessagesRawExecResult,
			Value: &flatrpc.ExecResult{
				Id:     id,
				Proc:   0,
				Info:   flatrpc.EmptyProgInfo(callCount),
				Hanged: true,
			},
		},
	}
}

func synthesizeErrorResult(req *flatrpc.ExecRequest, err error) *flatrpc.ExecutorMessage {
	callCount := 0
	var id int64
	if req != nil {
		id = req.Id
		callCount = progExecCallCountOrPanic(req.Data)
	}
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	return &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type: flatrpc.ExecutorMessagesRawExecResult,
			Value: &flatrpc.ExecResult{
				Id:    id,
				Proc:  0,
				Error: errText,
				Info:  flatrpc.EmptyProgInfo(callCount),
			},
		},
	}
}

type nyxCrashError struct {
	title  string
	report []byte
}

func (err *nyxCrashError) Error() string {
	return "nyx crash: " + err.title
}

func logStandaloneFatal(format string, err error) {
	var crashErr *nyxCrashError
	if errors.As(err, &crashErr) {
		_, _ = os.Stderr.Write(crashErr.report)
	}
	log.Fatalf(format, err)
}

func (vm *nyxVM) makeCrashError(code byte, req *flatrpc.ExecRequest) *nyxCrashError {
	title := nyxCrashTitle(code, string(vm.aux.misc()))
	dump := vm.preserveWindowsDump(title)
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "SYZ-NYX-WINDOWS-CRASH: %s\n", title)
	fmt.Fprintf(&buf, "nyx exit reason: %s\n", nyxExitReason(code))
	if misc := strings.TrimSpace(string(vm.aux.misc())); misc != "" {
		fmt.Fprintf(&buf, "nyx misc: %s\n", misc)
	}
	if dump.storedPath != "" {
		fmt.Fprintf(&buf, "dump file: %s\n", dump.storedPath)
		fmt.Fprintf(&buf, "dump source: %s\n", dump.sourcePath)
		fmt.Fprintf(&buf, "dump size: %d\n", dump.size)
		fmt.Fprintf(&buf, "dump sha256: %s\n", dump.sha256)
		if dump.tracePath != "" {
			fmt.Fprintf(&buf, "dump trace: %s\n", dump.tracePath)
		}
	} else if dump.err != "" {
		fmt.Fprintf(&buf, "dump error: %s\n", dump.err)
	}
	if req != nil {
		fmt.Fprintf(&buf, "last executing request: id=%d\n", req.Id)
		fmt.Fprintf(&buf, "last executing program:\n%s\n", formatLastExecutingProgram(req.Data))
	}
	fmt.Fprintf(&buf, "END SYZ-NYX-WINDOWS-CRASH\n")
	return &nyxCrashError{title: title, report: buf.Bytes()}
}

func nyxCrashTitle(code byte, misc string) string {
	misc = strings.TrimSpace(misc)
	switch {
	case strings.Contains(misc, "WINDOWS BUGCHECK DIRECT DUMP IO"):
		return "WINDOWS BUGCHECK DIRECT DUMP IO"
	case strings.Contains(misc, "WINDOWS BUGCHECK"):
		return "WINDOWS BUGCHECK"
	case code == nyxRCSanitizer:
		return "NYX SANITIZER"
	default:
		return "NYX CRASH"
	}
}

func nyxExitReason(code byte) string {
	switch code {
	case nyxRCCrash:
		return "crash"
	case nyxRCSanitizer:
		return "sanitizer"
	default:
		return fmt.Sprintf("code_%d", code)
	}
}

type preservedDump struct {
	sourcePath string
	storedPath string
	tracePath  string
	size       int64
	sha256     string
	err        string
}

type stableDumpInfo struct {
	size    int64
	modTime time.Time
}

var (
	windowsDumpSettlePoll          = 50 * time.Millisecond
	windowsDumpSettleStableFor     = 6 * time.Second
	windowsDumpSettleTimeout       = 20 * time.Second
	windowsDumpSettleStableSamples = 3
	windowsDumpCopyAttempts        = 3
)

func (vm *nyxVM) preserveWindowsDump(title string) preservedDump {
	src := filepath.Join(vm.dumpDir, fmt.Sprintf("worker_%d_pending.dmp", vm.index))
	if err := os.MkdirAll(filepath.Join(vm.workdir, "dumps"), 0o755); err != nil {
		return preservedDump{sourcePath: src, err: err.Error()}
	}
	var lastErr error
	for attempt := 0; attempt < windowsDumpCopyAttempts; attempt++ {
		stable, err := waitForStableWindowsDump(src)
		if err != nil {
			return preservedDump{sourcePath: src, err: err.Error()}
		}
		dump, err := vm.copyStableWindowsDump(title, src, stable)
		if err == nil {
			return dump
		}
		lastErr = err
		time.Sleep(windowsDumpSettlePoll)
	}
	return preservedDump{sourcePath: src, err: lastErr.Error()}
}

func waitForStableWindowsDump(path string) (stableDumpInfo, error) {
	if windowsDumpSettleStableSamples < 1 {
		windowsDumpSettleStableSamples = 1
	}
	deadline := time.Now().Add(windowsDumpSettleTimeout)
	var last stableDumpInfo
	var stableSamples int
	var stableSince time.Time
	for {
		info, err := os.Stat(path)
		if err != nil {
			return stableDumpInfo{}, err
		}
		if info.IsDir() {
			return stableDumpInfo{}, errors.New("pending dump path is a directory")
		}
		cur := stableDumpInfo{size: info.Size(), modTime: info.ModTime()}
		if cur.size > 0 && cur == last {
			stableSamples++
		} else {
			last = cur
			stableSamples = 1
			stableSince = time.Now()
		}
		if cur.size > 0 && stableSamples >= windowsDumpSettleStableSamples &&
			time.Since(stableSince) >= windowsDumpSettleStableFor {
			return cur, nil
		}
		if time.Now().After(deadline) {
			return stableDumpInfo{}, fmt.Errorf("pending dump did not stabilize within %s", windowsDumpSettleTimeout)
		}
		time.Sleep(windowsDumpSettlePoll)
	}
}

func (vm *nyxVM) copyStableWindowsDump(title, src string, stable stableDumpInfo) (preservedDump, error) {
	in, err := os.Open(src)
	if err != nil {
		return preservedDump{}, err
	}
	defer in.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, in); err != nil {
		return preservedDump{}, err
	}
	hash := fmt.Sprintf("%x", sum.Sum(nil))
	dst := filepath.Join(vm.workdir, "dumps", fmt.Sprintf("%s_%06d_%s.dmp",
		sanitizeDumpName(title), time.Now().UnixNano()%1000000, hash[:12]))
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return preservedDump{}, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		return preservedDump{}, err
	}
	copied, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(dst)
		return preservedDump{}, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(dst)
		return preservedDump{}, closeErr
	}
	info, err := os.Stat(src)
	if err != nil {
		_ = os.Remove(dst)
		return preservedDump{}, err
	}
	if copied != stable.size || info.Size() != stable.size || !info.ModTime().Equal(stable.modTime) {
		_ = os.Remove(dst)
		return preservedDump{}, fmt.Errorf("pending dump changed while copying: stable_size=%d copied=%d current_size=%d",
			stable.size, copied, info.Size())
	}
	dump := preservedDump{
		sourcePath: src,
		storedPath: dst,
		size:       stable.size,
		sha256:     hash,
	}
	traceSrc := filepath.Join(vm.dumpDir, fmt.Sprintf("worker_%d_dumpio_trace.log", vm.index))
	traceDst := strings.TrimSuffix(dst, ".dmp") + ".dumpio_trace.log"
	if err := copyFileIfExists(traceSrc, traceDst); err == nil {
		dump.tracePath = traceDst
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Logf(0, "failed to preserve Windows dump trace %s: %v", traceSrc, err)
	}
	return dump, nil
}

func copyFileIfExists(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(dst)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(dst)
		return closeErr
	}
	return nil
}

func sanitizeDumpName(title string) string {
	title = strings.ToLower(title)
	var sb strings.Builder
	lastUnderscore := false
	for _, ch := range title {
		if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' {
			sb.WriteRune(ch)
			lastUnderscore = false
		} else if sb.Len() != 0 && !lastUnderscore {
			sb.WriteByte('_')
			lastUnderscore = true
		}
	}
	ret := strings.Trim(sb.String(), "_")
	if ret == "" {
		return "crash"
	}
	return ret
}

func formatLastExecutingProgram(data []byte) string {
	return describeExecProgram(data)
}

func packFlatbuffer(msg interface {
	Pack(*flatbuffers.Builder) flatbuffers.UOffsetT
}) []byte {
	builder := flatbuffers.NewBuilder(0)
	off := msg.Pack(builder)
	builder.Finish(off)
	return append([]byte{}, builder.FinishedBytes()...)
}

func packNyxPayload(kind uint16, meta *nyxExecMeta, body []byte) []byte {
	header := nyxMsgHeader{
		Magic:    nyxMsgMagic,
		Version:  nyxMsgVersion,
		Kind:     kind,
		BodySize: uint32(len(body)),
	}
	if meta != nil {
		header.BodySize += uint32(binary.Size(*meta))
	}
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, &header)
	if meta != nil {
		_ = binary.Write(buf, binary.LittleEndian, meta)
	}
	buf.Write(body)
	return buf.Bytes()
}

func authHash(value uint64) uint64 {
	return (value * 73856093) ^ 83492791
}

func normalizeWindowsNyxEnvFlags(env flatrpc.ExecEnv) flatrpc.ExecEnv {
	/* The Windows Nyx executor gets per-request coverage from explicit PT
	 * hypercalls, while executor-side nocover stubs make KCOV feature knobs
	 * inert. Keep only the handshake bits that are meaningful on Windows and
	 * pin the sandbox/coverage mode so manager-side Linux feature probing does
	 * not keep reconfiguring the guest between otherwise identical requests. */
	const keep = flatrpc.ExecEnvDebug |
		flatrpc.ExecEnvReadOnlyCoverage |
		flatrpc.ExecEnvResetState
	return (env & keep) | flatrpc.ExecEnvSignal | flatrpc.ExecEnvSandboxNone
}

func injectCoverage(msg *flatrpc.ExecRequest, execMsg *flatrpc.ExecutorMessage,
	coverEdges, kernel64Bit bool,
	canonicalizer moduleRangeCanonicalizer,
	covRecords []nyxCovDumpRecord, compRecords []nyxCovCompRecord) error {
	res, ok := execMsg.Msg.Value.(*flatrpc.ExecResult)
	if !ok || res.Info == nil || len(res.Info.Calls) == 0 {
		return nil
	}
	callCover := make(map[uint32][]uint64)
	for _, rec := range covRecords {
		if int(rec.CallIndex) >= len(res.Info.Calls) {
			return fmt.Errorf("coverage record for call %d out of range (%d calls)",
				rec.CallIndex, len(res.Info.Calls))
		}
		pcs := filterCoveragePCs(canonicalizer.CanonicalizePCs(rec.PCs), kernel64Bit)
		if len(pcs) == 0 {
			continue
		}
		callCover[rec.CallIndex] = append(callCover[rec.CallIndex], pcs...)
	}
	for callIndex, pcs := range callCover {
		call := res.Info.Calls[callIndex]
		if msg.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover != 0 {
			call.Cover = append(call.Cover[:0], pcs...)
		}
		if msg.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal != 0 {
			call.Signal = append(call.Signal[:0], pcsToSignal(pcs, coverEdges)...)
		}
	}
	if msg.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps != 0 {
		total := 0
		for _, crec := range compRecords {
			if int(crec.CallIndex) >= len(res.Info.Calls) {
				return fmt.Errorf("comparison record for call %d out of range (%d calls)",
					crec.CallIndex, len(res.Info.Calls))
			}
			call := res.Info.Calls[crec.CallIndex]
			for _, comp := range crec.Comps {
				call.Comps = append(call.Comps, &flatrpc.ComparisonRawT{
					Pc:      canonicalizer.CanonicalizePC(comp.Pc),
					Op1:     comp.Op2,
					Op2:     comp.Op1,
					IsConst: comp.IsImm != 0,
				})
			}
			total += len(crec.Comps)
		}
		if total > 0 {
			log.Logf(0, "runner injected comps: id=%d total=%d records=%d",
				msg.Id, total, len(compRecords))
		}
	}
	return nil
}

func filterCoveragePCs(pcs []uint64, kernel64Bit bool) []uint64 {
	if len(pcs) == 0 {
		return nil
	}
	ret := pcs[:0]
	for _, pc := range pcs {
		if pc == 0 {
			continue
		}
		if kernel64Bit && !isLikelyKernelPC64(pc) {
			continue
		}
		ret = append(ret, pc)
	}
	return ret
}

func isLikelyKernelPC64(pc uint64) bool {
	const canonicalKernelBase = 0xffff800000000000
	return pc >= canonicalKernelBase
}

func readCompEntry(data []byte) (nyxCompEntry, error) {
	if len(data) < 28 {
		return nyxCompEntry{}, errors.New("short comp entry")
	}
	return nyxCompEntry{
		Pc:    binary.LittleEndian.Uint64(data[0:8]),
		Op1:   binary.LittleEndian.Uint64(data[8:16]),
		Op2:   binary.LittleEndian.Uint64(data[16:24]),
		Size:  data[24],
		Kind:  data[25],
		IsImm: data[26],
	}, nil
}

func parseCoverageDump(path string) ([]nyxCovDumpRecord, []nyxCovCompRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if len(data) < binary.Size(nyxCovHeader{}) {
		return nil, nil, errors.New("short coverage dump")
	}
	var hdr nyxCovHeader
	if err := binary.Read(bytes.NewReader(data[:binary.Size(hdr)]), binary.LittleEndian, &hdr); err != nil {
		return nil, nil, err
	}
	if hdr.Magic != nyxCovMagic {
		return nil, nil, fmt.Errorf("unexpected syz_cov magic 0x%x", hdr.Magic)
	}
	if hdr.Version < nyxCovVersionMinV1 || hdr.Version > nyxCovVersion {
		return nil, nil, fmt.Errorf("unsupported syz_cov version %d", hdr.Version)
	}
	if hdr.RecordCount == 0 && hdr.Version < 2 {
		return nil, nil, nil
	}
	off := binary.Size(hdr)
	records := make([]nyxCovDumpRecord, 0, hdr.RecordCount)
	for range hdr.RecordCount {
		if off+binary.Size(nyxCovRecord{}) > len(data) {
			return nil, nil, errors.New("coverage record truncated")
		}
		var rec nyxCovRecord
		if err := binary.Read(bytes.NewReader(data[off:off+binary.Size(rec)]), binary.LittleEndian, &rec); err != nil {
			return nil, nil, err
		}
		off += binary.Size(rec)
		pcs := make([]uint64, rec.PCCount)
		for i := range pcs {
			if off+8 > len(data) {
				return nil, nil, errors.New("coverage body truncated")
			}
			pcs[i] = binary.LittleEndian.Uint64(data[off : off+8])
			off += 8
		}
		records = append(records, nyxCovDumpRecord{
			CallIndex: rec.CallIndex,
			SlotID:    rec.SlotID,
			Flags:     rec.Flags,
			PCs:       pcs,
		})
	}
	var compRecords []nyxCovCompRecord
	if hdr.Version >= 2 && off < len(data) {
		if off+4 > len(data) {
			return nil, nil, errors.New("comp record count truncated")
		}
		compRecordCount := binary.LittleEndian.Uint32(data[off : off+4])
		off += 4
		compRecords = make([]nyxCovCompRecord, 0, compRecordCount)
		for i := uint32(0); i < compRecordCount; i++ {
			if off+binary.Size(nyxCovRecord{}) > len(data) {
				return nil, nil, errors.New("comp record header truncated")
			}
			var rec nyxCovRecord
			if err := binary.Read(bytes.NewReader(data[off:off+binary.Size(rec)]), binary.LittleEndian, &rec); err != nil {
				return nil, nil, err
			}
			off += binary.Size(rec)
			comps := make([]nyxCompEntry, rec.PCCount)
			for j := range comps {
				ce, err := readCompEntry(data[off : off+28])
				if err != nil {
					return nil, nil, err
				}
				comps[j] = ce
				off += 28
			}
			compRecords = append(compRecords, nyxCovCompRecord{
				CallIndex: rec.CallIndex,
				SlotID:    rec.SlotID,
				Flags:     rec.Flags,
				Comps:     comps,
			})
		}
	}
	if off != len(data) {
		return nil, nil, fmt.Errorf("unexpected trailing syz_cov data: %d bytes", len(data)-off)
	}
	return records, compRecords, nil
}

func pcsToSignal(pcs []uint64, coverEdges bool) []uint64 {
	seen := make(map[uint64]struct{})
	var ret []uint64
	var prev uint32
	for _, pc := range pcs {
		sig := pc
		if coverEdges {
			const mask = (1 << 12) - 1
			sig ^= uint64(hash32(prev&mask) & mask)
			prev = uint32(pc)
		}
		if _, ok := seen[sig]; ok {
			continue
		}
		seen[sig] = struct{}{}
		ret = append(ret, sig)
	}
	return ret
}

func hash32(a uint32) uint32 {
	a = (a ^ 61) ^ (a >> 16)
	a = a + (a << 3)
	a = a ^ (a >> 4)
	a = a * 0x27d4eb2d
	a = a ^ (a >> 15)
	return a
}

func describeExecProgram(data []byte) string {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		return fmt.Sprintf("decode_target_err=%v", err)
	}
	decoded, err := target.DeserializeExec(data, nil)
	if err != nil {
		return fmt.Sprintf("decode_err=%v", err)
	}
	sum := sha1.Sum(data)
	if len(decoded.Calls) == 0 {
		return fmt.Sprintf("sha1=%x calls=0", sum[:6])
	}
	call := decoded.Calls[0]
	if call.Meta == nil {
		return fmt.Sprintf("sha1=%x calls=%d call0=<nil>", sum[:6], len(decoded.Calls))
	}
	parts := []string{
		fmt.Sprintf("sha1=%x", sum[:6]),
		fmt.Sprintf("calls=%d", len(decoded.Calls)),
		fmt.Sprintf("call0=%s", call.Meta.Name),
	}
	if deep := firstDeepAFDCallName(decoded.Calls); deep != "" {
		parts = append(parts, fmt.Sprintf("deep0=%s", deep))
	}
	if programUsesWindowsVNet(decoded.Calls) {
		parts = append(parts, "vnet=1")
	}
	for i, arg := range call.Args {
		if i >= 4 {
			break
		}
		switch a := arg.(type) {
		case prog.ExecArgConst:
			parts = append(parts, fmt.Sprintf("arg%d=0x%x", i, a.Value))
		case prog.ExecArgResult:
			parts = append(parts, fmt.Sprintf("arg%d=result(index=%d,default=0x%x)", i, a.Index, a.Default))
		default:
			parts = append(parts, fmt.Sprintf("arg%d=%T", i, arg))
		}
	}
	return strings.Join(parts, " ")
}

func execProgramIsMultiCallWindowsVNet(data []byte) bool {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		return false
	}
	decoded, err := target.DeserializeExec(data, nil)
	if err != nil {
		return false
	}
	return len(decoded.Calls) > 1 && programUsesWindowsVNet(decoded.Calls)
}

func programUsesWindowsVNet(calls []prog.ExecCall) bool {
	for _, call := range calls {
		if call.Meta == nil {
			continue
		}
		switch call.Meta.Name {
		case "syz_emit_ethernet$windows", "syz_extract_tcp_res$windows", "syz_extract_tcp_res$windows_synack":
			return true
		}
	}
	return false
}

func firstDeepAFDCallName(calls []prog.ExecCall) string {
	for _, call := range calls {
		if call.Meta != nil && isDeepAFDCallName(call.Meta.Name) {
			return call.Meta.Name
		}
	}
	return ""
}

func isDeepAFDCallName(name string) bool {
	switch {
	case name == "WSAGetOverlappedResult$socket" ||
		name == "CancelIoEx$socket" ||
		name == "CancelIo$socket" ||
		name == "CreateIoCompletionPort$socket" ||
		name == "GetQueuedCompletionStatus$socket" ||
		name == "AcceptEx$inet_tcp_pending" ||
		name == "ConnectEx$inet_tcp_pending" ||
		strings.Contains(name, "_pending") ||
		strings.HasPrefix(name, "WSAEventSelect$") ||
		strings.HasPrefix(name, "WSAEnumNetworkEvents$") ||
		strings.HasPrefix(name, "WSAIoctl$") ||
		strings.HasPrefix(name, "WSARecv") ||
		strings.HasPrefix(name, "WSASend") ||
		strings.HasPrefix(name, "send$inet_") ||
		strings.HasPrefix(name, "recv$inet_") ||
		strings.HasPrefix(name, "sendto$") ||
		strings.HasPrefix(name, "recvfrom$") ||
		strings.HasPrefix(name, "ConnectEx$") ||
		strings.HasPrefix(name, "DisconnectEx$") ||
		strings.HasPrefix(name, "TransmitFile$") ||
		strings.HasPrefix(name, "TransmitPackets$") ||
		strings.HasPrefix(name, "WSARecvMsg$") ||
		strings.HasPrefix(name, "GetAcceptExSockaddrs$") ||
		strings.HasPrefix(name, "setsockopt$update_accept_context") ||
		strings.HasPrefix(name, "setsockopt$update_connect_context") ||
		strings.HasPrefix(name, "setsockopt$int_") ||
		strings.HasPrefix(name, "getsockopt$int_") ||
		strings.HasPrefix(name, "ioctlsocket$fionbio_") ||
		strings.HasPrefix(name, "shutdown$") ||
		strings.HasPrefix(name, "getsockname$") ||
		strings.HasPrefix(name, "getpeername$") ||
		strings.HasPrefix(name, "select$afd_"):
		return true
	default:
		return false
	}
}

func execCallNames(data []byte) []string {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		return nil
	}
	decoded, err := target.DeserializeExec(data, nil)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(decoded.Calls))
	for _, call := range decoded.Calls {
		if call.Meta == nil {
			names = append(names, "<nil>")
			continue
		}
		names = append(names, call.Meta.Name)
	}
	return names
}

type runner struct {
	id                int
	addr              string
	port              string
	vm                *nyxVM
	conn              *flatrpc.Conn
	connectReply      *flatrpc.ConnectReply
	handshakeReady    bool
	coveragePrimed    bool
	lastEnvFlags      flatrpc.ExecEnv
	lastSandboxArg    int64
	needRestart       bool
	keepState         bool
	coverageDebugPath string
	slowTrace         *slowTraceConfig
	lastCompletedReq  *flatrpc.ExecRequest
}

func newRunner(id int, addr, port string, vm *nyxVM) *runner {
	return &runner{id: id, addr: addr, port: port, vm: vm}
}

type slowTraceConfig struct {
	dir       string
	threshold time.Duration
	maxEvents int
}

type slowTraceMetadata struct {
	GeneratedAt     time.Time                `json:"generated_at"`
	Reason          string                   `json:"reason"`
	Label           string                   `json:"label"`
	RunnerID        int                      `json:"runner_id"`
	RequestID       int64                    `json:"request_id"`
	DurationMS      int64                    `json:"duration_ms"`
	ThresholdMS     int64                    `json:"threshold_ms"`
	KeepState       bool                     `json:"keep_state"`
	QEMUPID         int                      `json:"qemu_pid,omitempty"`
	Workdir         string                   `json:"workdir"`
	ProgramSHA1     string                   `json:"program_sha1"`
	ProgramSHA256   string                   `json:"program_sha256"`
	ProgramSummary  string                   `json:"program_summary"`
	CallCount       int                      `json:"call_count"`
	CallNames       []string                 `json:"call_names,omitempty"`
	Request         map[string]any           `json:"request"`
	PreviousRequest *slowTraceProgramContext `json:"previous_request,omitempty"`
	Result          map[string]any           `json:"result,omitempty"`
	Aux             map[string]any           `json:"aux,omitempty"`
	Diagnosis       map[string]any           `json:"diagnosis,omitempty"`
	ArtifactFiles   map[string]string        `json:"artifact_files"`
}

type slowTraceProgramContext struct {
	RequestID      int64          `json:"request_id"`
	ProgramSHA1    string         `json:"program_sha1"`
	ProgramSHA256  string         `json:"program_sha256"`
	ProgramSummary string         `json:"program_summary"`
	CallCount      int            `json:"call_count"`
	CallNames      []string       `json:"call_names,omitempty"`
	Request        map[string]any `json:"request"`
}

func slowTraceProgramContextForRequest(req *flatrpc.ExecRequest) *slowTraceProgramContext {
	if req == nil {
		return nil
	}
	sum1 := sha1.Sum(req.Data)
	sum256 := sha256.Sum256(req.Data)
	return &slowTraceProgramContext{
		RequestID:      req.Id,
		ProgramSHA1:    fmt.Sprintf("%x", sum1),
		ProgramSHA256:  fmt.Sprintf("%x", sum256),
		ProgramSummary: describeExecProgram(req.Data),
		CallCount:      progExecCallCountOrPanic(req.Data),
		CallNames:      execCallNames(req.Data),
		Request:        slowTraceRequestSummary(req, nil),
	}
}

func slowTraceRequestSummary(req *flatrpc.ExecRequest, started *time.Time) map[string]any {
	if req == nil {
		return nil
	}
	ret := map[string]any{
		"type":        req.Type.String(),
		"flags":       uint64(req.Flags),
		"exec_flags":  uint64(req.ExecOpts.ExecFlags),
		"env_flags":   uint64(req.ExecOpts.EnvFlags),
		"sandbox_arg": req.ExecOpts.SandboxArg,
		"all_signal":  req.AllSignal,
	}
	if started != nil {
		ret["started_at"] = started.UTC()
	}
	return ret
}

func cloneExecRequestForArtifact(req *flatrpc.ExecRequest) *flatrpc.ExecRequest {
	if req == nil {
		return nil
	}
	cp := *req
	cp.Data = append([]byte(nil), req.Data...)
	cp.AllSignal = append([]int32(nil), req.AllSignal...)
	return &cp
}

func (r *runner) maybeDumpSlowTrace(req *flatrpc.ExecRequest, label string, started time.Time,
	duration time.Duration, execMsg *flatrpc.ExecutorMessage, execErr error) {
	if r.slowTrace == nil || r.slowTrace.dir == "" {
		return
	}
	reason := ""
	switch {
	case execResultHanged(execMsg):
		reason = "hang"
	case r.slowTrace.threshold > 0 && duration >= r.slowTrace.threshold:
		if execErr != nil {
			reason = "slow-error"
		} else {
			reason = "slow"
		}
	default:
		return
	}
	path, err := r.writeSlowTraceArtifact(req, label, reason, started, duration, execMsg, execErr)
	if err != nil {
		log.Logf(0, "runner slow trace dump failed: id=%d reason=%s duration_ms=%d err=%v",
			reqID(req), reason, duration.Milliseconds(), err)
		return
	}
	log.Logf(0, "runner slow trace saved: id=%d reason=%s duration_ms=%d path=%s",
		reqID(req), reason, duration.Milliseconds(), path)
}

func (r *runner) writeSlowTraceArtifact(req *flatrpc.ExecRequest, label, reason string, started time.Time,
	duration time.Duration, execMsg *flatrpc.ExecutorMessage, execErr error) (string, error) {
	if req == nil {
		return "", errors.New("nil exec request")
	}
	if err := os.MkdirAll(r.slowTrace.dir, 0o755); err != nil {
		return "", err
	}
	sum1 := sha1.Sum(req.Data)
	sum256 := sha256.Sum256(req.Data)
	dir := filepath.Join(r.slowTrace.dir, fmt.Sprintf("%s-vm%d-id%d-%s-%x",
		time.Now().UTC().Format("20060102-150405.000000000"), r.id, req.Id,
		sanitizeArtifactName(reason), sum1[:6]))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	files := map[string]string{}
	writeFile := func(name string, data []byte) error {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return err
		}
		files[name] = path
		return nil
	}
	if err := writeFile("program.exec.bin", req.Data); err != nil {
		return "", err
	}
	if err := writeFile("program.txt", []byte(formatExecProgramForArtifact(req.Data))); err != nil {
		return "", err
	}
	var previous *slowTraceProgramContext
	if strings.Contains(label, "handshake") && r.lastCompletedReq != nil {
		previous = slowTraceProgramContextForRequest(r.lastCompletedReq)
		if err := writeFile("previous-program.exec.bin", r.lastCompletedReq.Data); err != nil {
			return "", err
		}
		if err := writeFile("previous-program.txt", []byte(formatExecProgramForArtifact(r.lastCompletedReq.Data))); err != nil {
			return "", err
		}
	}
	if execMsg != nil {
		if data, err := json.MarshalIndent(execMsg, "", "\t"); err == nil {
			if err := writeFile("result.json", data); err != nil {
				return "", err
			}
		}
	}
	if execErr != nil {
		if err := writeFile("error.txt", []byte(execErr.Error()+"\n")); err != nil {
			return "", err
		}
	}
	trace := r.vm.trace
	if trace == nil {
		trace = newTraceRecorder(1)
	}
	events := trace.Tail("", r.slowTrace.maxEvents)
	if err := writeTraceJSONL(filepath.Join(dir, "trace.jsonl"), events); err != nil {
		return "", err
	}
	files["trace.jsonl"] = filepath.Join(dir, "trace.jsonl")
	for _, source := range []string{"runner", "qemu", "executor"} {
		name := source + "-trace.jsonl"
		events := trace.Tail(source, r.slowTrace.maxEvents)
		if err := writeTraceJSONL(filepath.Join(dir, name), events); err != nil {
			return "", err
		}
		files[name] = filepath.Join(dir, name)
	}
	if data, err := tailFile(r.vm.qemuFlightPath(), r.slowTrace.maxEvents, 4<<20); err == nil && len(data) != 0 {
		if err := writeFile("qemu-flight-tail.jsonl", data); err != nil {
			return "", err
		}
	}
	diagnosis := slowTraceDiagnosis(events, r.keepState)
	if previous != nil {
		if diagnosis == nil {
			diagnosis = map[string]any{}
		}
		diagnosis["phase"] = "pre_request_handshake"
		diagnosis["previous_request_id"] = previous.RequestID
		diagnosis["previous_program_summary"] = previous.ProgramSummary
		diagnosis["previous_call_names"] = previous.CallNames
	}
	meta := slowTraceMetadata{
		GeneratedAt:     time.Now().UTC(),
		Reason:          reason,
		Label:           label,
		RunnerID:        r.id,
		RequestID:       req.Id,
		DurationMS:      duration.Milliseconds(),
		ThresholdMS:     r.slowTrace.threshold.Milliseconds(),
		KeepState:       r.keepState,
		Workdir:         r.vm.workdir,
		ProgramSHA1:     fmt.Sprintf("%x", sum1),
		ProgramSHA256:   fmt.Sprintf("%x", sum256),
		ProgramSummary:  describeExecProgram(req.Data),
		CallCount:       progExecCallCountOrPanic(req.Data),
		CallNames:       execCallNames(req.Data),
		Request:         slowTraceRequestSummary(req, &started),
		PreviousRequest: previous,
		Result:          execResultArtifactSummary(execMsg, execErr),
		Aux:             r.vm.auxArtifactSummary(),
		Diagnosis:       diagnosis,
		ArtifactFiles:   files,
	}
	if r.vm.process != nil && r.vm.process.Process != nil {
		meta.QEMUPID = r.vm.process.Process.Pid
	}
	data, err := json.MarshalIndent(meta, "", "\t")
	if err != nil {
		return "", err
	}
	if err := writeFile("metadata.json", append(data, '\n')); err != nil {
		return "", err
	}
	return dir, nil
}

func slowTraceDiagnosis(events []traceEvent, keepState bool) map[string]any {
	if len(events) == 0 {
		return nil
	}
	last := events[len(events)-1]
	ret := map[string]any{
		"category":       classifySlowTrace(events),
		"last_component": last.Source,
		"last_stage":     last.Stage,
		"last_seq":       last.Seq,
		"keep_state":     keepState,
	}
	if last.RequestID != 0 {
		ret["last_request_id"] = last.RequestID
	}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Source != "executor" || len(event.Fields) == 0 {
			continue
		}
		for _, key := range []string{"call_index", "call_num", "call_name", "stage", "tid", "guest_ms"} {
			if value, ok := event.Fields[key]; ok {
				ret["executor_"+key] = value
			}
		}
		break
	}
	return ret
}

func classifySlowTrace(events []traceEvent) string {
	lastPreAcquire := -1
	lastPostRelease := -1
	lastStage := strings.ToLower(events[len(events)-1].Stage)
	for i, event := range events {
		stage := strings.ToLower(event.Stage)
		switch {
		case strings.Contains(stage, "pre_acquire"):
			lastPreAcquire = i
		case strings.Contains(stage, "post_release") || stage == "release":
			lastPostRelease = i
		}
	}
	switch {
	case strings.Contains(lastStage, "reload"):
		return "reload"
	case strings.Contains(lastStage, "handshake") || strings.Contains(lastStage, "vm_start"):
		return "restart/handshake"
	case strings.Contains(lastStage, "coverage") || strings.Contains(lastStage, "cov") ||
		strings.Contains(lastStage, "pt_"):
		return "coverage"
	case lastPreAcquire > lastPostRelease:
		return "syscall"
	default:
		return "runner/qemu"
	}
}

func sanitizeArtifactName(name string) string {
	var b strings.Builder
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			b.WriteRune(ch)
		}
	}
	if b.Len() == 0 {
		return "trace"
	}
	return b.String()
}

func writeTraceJSONL(path string, events []traceEvent) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	for _, event := range events {
		if err := enc.Encode(event); err != nil {
			return err
		}
	}
	return nil
}

func tailFile(path string, maxLines int, maxBytes int64) ([]byte, error) {
	if path == "" {
		return nil, os.ErrNotExist
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	start := int64(0)
	if maxBytes > 0 && info.Size() > maxBytes {
		start = info.Size() - maxBytes
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if start != 0 {
		if _, err := file.Seek(start, io.SeekStart); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	if start != 0 {
		if index := bytes.IndexByte(data, '\n'); index >= 0 {
			data = data[index+1:]
		}
	}
	if maxLines <= 0 {
		return data, nil
	}
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) != 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	if len(lines) == 0 {
		return nil, nil
	}
	return append(bytes.Join(lines, []byte{'\n'}), '\n'), nil
}

func execResultArtifactSummary(msg *flatrpc.ExecutorMessage, execErr error) map[string]any {
	ret := map[string]any{}
	if execErr != nil {
		ret["runner_error"] = execErr.Error()
	}
	if msg == nil || msg.Msg == nil {
		return ret
	}
	res, ok := msg.Msg.Value.(*flatrpc.ExecResult)
	if !ok || res == nil {
		ret["message_type"] = fmt.Sprintf("%T", msg.Msg.Value)
		return ret
	}
	ret["hanged"] = res.Hanged
	ret["error"] = res.Error
	ret["proc"] = res.Proc
	ret["output_bytes"] = len(res.Output)
	if res.Info != nil {
		ret["calls"] = len(res.Info.Calls)
		ret["covered_calls"] = countNonEmptyCover(res.Info.Calls)
		ret["extra_signal"] = callInfoSignalLen(res.Info.Extra)
		ret["extra_cover"] = callInfoCoverLen(res.Info.Extra)
	}
	return ret
}

func callInfoSignalLen(info *flatrpc.CallInfo) int {
	if info == nil {
		return 0
	}
	return len(info.Signal)
}

func callInfoCoverLen(info *flatrpc.CallInfo) int {
	if info == nil {
		return 0
	}
	return len(info.Cover)
}

func (vm *nyxVM) auxArtifactSummary() map[string]any {
	if vm == nil || vm.aux == nil {
		return nil
	}
	ret := map[string]any{
		"state":          vm.aux.state(),
		"exec_done":      vm.aux.execDone(),
		"exec_code":      vm.aux.execCode(),
		"exec_code_name": nyxExitReason(vm.aux.execCode()),
		"reloaded":       vm.aux.reloaded(),
		"pt_overflow":    vm.aux.ptOverflow(),
		"page_fault":     vm.aux.pageFault(),
	}
	if vm.aux.pageFault() {
		ret["page_addr"] = fmt.Sprintf("0x%x", vm.aux.pageAddr())
	}
	if misc := cleanAuxMessage(vm.aux.misc()); misc != "" {
		ret["misc"] = misc
	}
	return ret
}

func (vm *nyxVM) qemuFlightPath() string {
	if vm == nil || vm.workdir == "" {
		return ""
	}
	return filepath.Join(vm.workdir, fmt.Sprintf("nyx_flight_%d.jsonl", vm.index))
}

func formatExecProgramForArtifact(data []byte) string {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		return fmt.Sprintf("decode_target_err=%v\n", err)
	}
	decoded, err := target.DeserializeExec(data, nil)
	if err != nil {
		return fmt.Sprintf("decode_err=%v\nsummary: %s\n", err, describeExecProgram(data))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "summary: %s\n", describeExecProgram(data))
	for index, call := range decoded.Calls {
		name := "<nil>"
		if call.Meta != nil {
			name = call.Meta.Name
		}
		fmt.Fprintf(&b, "#%d %s args=%d copyin=%d copyout=%d\n",
			index, name, len(call.Args), len(call.Copyin), len(call.Copyout))
	}
	return b.String()
}

func (r *runner) resetForReconnect() {
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
	}
	r.connectReply = nil
	r.handshakeReady = false
	r.coveragePrimed = false
	r.lastEnvFlags = 0
	r.lastSandboxArg = 0
	r.lastCompletedReq = nil
}

func (r *runner) connect() error {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		return err
	}
	conn, err := net.Dial("tcp", net.JoinHostPort(r.addr, r.port))
	if err != nil {
		return err
	}
	r.conn = flatrpc.NewConn(conn)
	log.Logf(0, "runner connecting to manager %s:%s", r.addr, r.port)
	hello, err := flatrpc.Recv[*flatrpc.ConnectHelloRaw](r.conn)
	if err != nil {
		return err
	}
	req := &flatrpc.ConnectRequest{
		Cookie:      authHash(hello.Cookie),
		Id:          int64(r.id),
		Arch:        "amd64",
		GitRevision: prog.GitRevision,
		SyzRevision: target.Revision,
	}
	if err := flatrpc.Send(r.conn, req); err != nil {
		return err
	}
	r.connectReply, err = flatrpc.Recv[*flatrpc.ConnectReplyRaw](r.conn)
	if err != nil {
		return err
	}
	log.Logf(0, "runner connected: cover_edges=%v kernel64=%v slowdown=%d syscall_timeout_ms=%d program_timeout_ms=%d",
		r.connectReply.CoverEdges, r.connectReply.Kernel64Bit, r.connectReply.Slowdown,
		r.connectReply.SyscallTimeoutMs, r.connectReply.ProgramTimeoutMs)
	derivedTimeout := deriveHardTimeout(r.connectReply.ProgramTimeoutMs, r.vm.hardTimeout)
	if derivedTimeout != r.vm.hardTimeout {
		log.Logf(0, "runner using derived hard timeout %s (fallback=%s program_timeout_ms=%d)",
			derivedTimeout, r.vm.hardTimeout, r.connectReply.ProgramTimeoutMs)
		r.vm.hardTimeout = derivedTimeout
	}
	if err := flatrpc.Send(r.conn, &flatrpc.InfoRequest{
		Files: nyxModuleInfoFiles(r.vm.moduleCanonicalizer.CanonicalRanges()),
	}); err != nil {
		return err
	}
	_, err = flatrpc.Recv[*flatrpc.InfoReplyRaw](r.conn)
	return err
}

func (r *runner) ensureHandshake(req *flatrpc.ExecRequest) error {
	envFlags := normalizeWindowsNyxEnvFlags(req.ExecOpts.EnvFlags)
	if r.handshakeReady && r.lastEnvFlags == envFlags && r.lastSandboxArg == req.ExecOpts.SandboxArg {
		return nil
	}
	r.vm.debugLogf("runner sending handshake: raw_env=0x%x normalized_env=0x%x sandbox_arg=%d",
		uint64(req.ExecOpts.EnvFlags), uint64(envFlags), req.ExecOpts.SandboxArg)
	msg := &flatrpc.SnapshotHandshakeT{
		CoverEdges:       r.connectReply.CoverEdges,
		Kernel64Bit:      r.connectReply.Kernel64Bit,
		Slowdown:         r.connectReply.Slowdown,
		SyscallTimeoutMs: r.connectReply.SyscallTimeoutMs,
		ProgramTimeoutMs: r.connectReply.ProgramTimeoutMs,
		Features:         r.connectReply.Features,
		EnvFlags:         envFlags,
		SandboxArg:       req.ExecOpts.SandboxArg,
	}
	started := time.Now()
	r.vm.recordTrace("runner", "handshake_request_begin", req.Id, traceFields(
		"env_flags", uint64(envFlags),
		"sandbox_arg", req.ExecOpts.SandboxArg,
	))
	err := r.vm.executeHandshake(packNyxPayload(nyxKindHandshake, nil, packFlatbuffer(msg)), req.Id)
	duration := time.Since(started)
	if err != nil {
		r.vm.recordTrace("runner", "handshake_error", req.Id, traceFields(
			"duration_ms", duration.Milliseconds(),
			"error", err.Error(),
		))
		r.maybeDumpSlowTrace(req, "runner handshake", started, duration, nil, err)
		return err
	}
	r.vm.recordTrace("runner", "handshake_end", req.Id, traceFields(
		"duration_ms", duration.Milliseconds(),
	))
	r.maybeDumpSlowTrace(req, "runner handshake", started, duration, nil, nil)
	r.vm.debugLogf("runner handshake complete")
	r.handshakeReady = true
	r.coveragePrimed = false
	r.lastEnvFlags = envFlags
	r.lastSandboxArg = req.ExecOpts.SandboxArg
	return nil
}

func (r *runner) markForRestart(reason string) {
	if r.needRestart {
		return
	}
	log.Logf(0, "runner scheduling VM restart: %s", reason)
	r.needRestart = true
}

func (r *runner) handleHangedRequest(reqID int64) {
	// qemu-nyx restores the root snapshot itself when its watchdog fires
	// (nyxRCTimeout -> perform_reload). In that case the VM is already
	// clean, so a full QEMU reboot (~tens of seconds) is wasted work and
	// just burns the fuzzing budget. Only force a restart when nyx did NOT
	// reload (genuine wedge: runner deadline / qemu ping timeout).
	if r.vm.aux.reloaded() {
		log.Logf(0, "request %d hanged but nyx already restored root snapshot; skipping VM restart", reqID)
		return
	}
	r.markForRestart(fmt.Sprintf("request %d hanged without nyx reload", reqID))
}

func (r *runner) restartVM(reason string) error {
	log.Logf(0, "runner restarting VM: %s", reason)
	if err := r.vm.restart(); err != nil {
		return err
	}
	r.handshakeReady = false
	r.coveragePrimed = false
	r.lastEnvFlags = 0
	r.lastSandboxArg = 0
	r.lastCompletedReq = nil
	r.needRestart = false
	return nil
}

func requestNeedsCoveragePriming(req *flatrpc.ExecRequest) bool {
	if req == nil || req.ExecOpts == nil {
		return false
	}
	return req.ExecOpts.ExecFlags&(flatrpc.ExecFlagCollectCover|flatrpc.ExecFlagCollectSignal) != 0
}

func execResultHasCoverage(msg *flatrpc.ExecutorMessage) bool {
	if msg == nil || msg.Msg == nil {
		return false
	}
	res, ok := msg.Msg.Value.(*flatrpc.ExecResult)
	if !ok || res == nil || res.Info == nil || res.Hanged || res.Error != "" {
		return false
	}
	return countNonEmptyCover(res.Info.Calls) != 0
}

func (r *runner) executeRequestOnce(req *flatrpc.ExecRequest, prime bool) (*flatrpc.ExecutorMessage, error) {
	if req.Type != flatrpc.RequestTypeProgram {
		return nil, fmt.Errorf("unsupported request type %v", req.Type)
	}
	execFlags := req.ExecOpts.ExecFlags
	requestLabel := "runner exec"
	if prime {
		requestLabel = "runner prime"
	}
	r.vm.debugLogf("%s request: id=%d prog_calls=%d flags=0x%x effective_flags=0x%x all_signal=%v",
		requestLabel, req.Id, progExecCallCountOrPanic(req.Data), req.ExecOpts.ExecFlags, execFlags, req.AllSignal)
	r.vm.debugLogf("%s program: id=%d %s", requestLabel, req.Id, describeExecProgram(req.Data))

	// Control redqueen via aux buffer, mirroring kAFL's set_redqueen_mode().
	// hintsJob sends CollectComps → enable redqueen before execution.
	// Normal fuzz sends CollectCover/Signal → disable after execution.
	// We write redqueen_mode directly WITHOUT the changed flag, so the
	// aux buffer poll loop does NOT process it (avoids pt_pre_kvm_run).
	// syz_cov_dump() reads the byte directly to insert/remove hooks.
	needComps := execFlags&flatrpc.ExecFlagCollectComps != 0
	if needComps {
		if err := r.vm.ensureAuxMmap(); err != nil {
			log.Logf(0, "runner aux mmap failed: %v", err)
		}
	}
	if len(r.vm.auxMM) >= 391 {
		if needComps {
			r.vm.auxMM[390] = 1 // redqueen_mode = 1 (enable)
			defer func() {
				r.vm.auxMM[390] = 0 // redqueen_mode = 0 (disable)
			}()
		}
	}
	r.vm.applyHardTimeout()
	meta := &nyxExecMeta{RequestID: req.Id, ProcID: 0}
	if r.keepState {
		meta.Flags |= nyxExecKeepState
	}
	body := &flatrpc.SnapshotRequestT{
		ExecFlags:      execFlags,
		NumCalls:       int32(progExecCallCountOrPanic(req.Data)),
		AllCallSignal:  allCallSignal(req.AllSignal),
		AllExtraSignal: hasExtraSignal(req.AllSignal),
		ProgData:       req.Data,
	}
	started := time.Now()
	r.vm.recordTrace("runner", "request_begin", req.Id, traceFields(
		"label", requestLabel,
		"exec_flags", uint64(req.ExecOpts.ExecFlags),
		"effective_flags", uint64(execFlags),
		"keep_state", r.keepState,
		"calls", progExecCallCountOrPanic(req.Data),
	))
	execMsg, err := r.vm.executeRequest(packNyxPayload(nyxKindExec, meta, packFlatbuffer(body)), req)
	duration := time.Since(started)
	if err != nil {
		r.vm.recordTrace("runner", "request_error", req.Id, traceFields(
			"label", requestLabel,
			"duration_ms", duration.Milliseconds(),
			"error", err.Error(),
		))
		r.maybeDumpSlowTrace(req, requestLabel, started, duration, nil, err)
		r.markForRestart(fmt.Sprintf("request %d failed: %v", req.Id, err))
		return nil, err
	}
	if !r.keepState {
		// The pending root reload is consumed by the next payload release. The
		// root snapshot is taken before the executor receives the syzkaller
		// handshake, so the next payload must be a handshake.
		r.handshakeReady = false
		r.coveragePrimed = false
		r.lastEnvFlags = 0
		r.lastSandboxArg = 0
	}
	covRecords, compRecords, covErr := parseCoverageDump(r.vm.coverPath)
	if covErr == nil {
		covErr = injectCoverage(req, execMsg, r.connectReply.CoverEdges,
			r.connectReply.Kernel64Bit, r.vm.moduleCanonicalizer, covRecords, compRecords)
		if covErr == nil {
			if r.vm.debug {
				logModuleCoverage(req.Id, req.Data, covRecords, r.connectReply.Kernel64Bit,
					r.vm.moduleCanonicalizer.CanonicalRanges())
			}
			if r.coverageDebugPath != "" {
				if err := appendCoverageDebugStream(r.coverageDebugPath,
					buildCoverageDebugStreamEvent(req.Id, req.Data, covRecords,
						r.connectReply.Kernel64Bit, r.vm.moduleCanonicalizer)); err != nil {
					log.Logf(0, "runner coverage debug stream failed: %v", err)
				}
			}
		}
	}
	if covErr != nil {
		res, ok := execMsg.Msg.Value.(*flatrpc.ExecResult)
		if ok && res.Hanged && errors.Is(covErr, os.ErrNotExist) {
			log.Logf(0, "runner exec hanged and coverage dump is absent; continuing without coverage")
		} else {
			return nil, covErr
		}
	}
	if execResultHanged(execMsg) {
		r.handleHangedRequest(req.Id)
	}
	r.vm.recordTrace("runner", "request_end", req.Id, traceFields(
		"label", requestLabel,
		"duration_ms", duration.Milliseconds(),
		"hanged", execResultHanged(execMsg),
	))
	r.maybeDumpSlowTrace(req, requestLabel, started, duration, execMsg, nil)
	r.lastCompletedReq = cloneExecRequestForArtifact(req)
	if res, ok := execMsg.Msg.Value.(*flatrpc.ExecResult); ok && res.Info != nil {
		if r.vm.debug {
			logCallFeedback(req.Id, req.Data, res.Info.Calls)
		}
		if res.Hanged || res.Error != "" {
			log.Logf(0, "%s complete: id=%d calls=%d cover_records=%d duration_ms=%d hanged=%v error=%q",
				requestLabel, req.Id, len(res.Info.Calls), countNonEmptyCover(res.Info.Calls),
				duration.Milliseconds(), res.Hanged, res.Error)
		} else {
			r.vm.debugLogf("%s complete: id=%d calls=%d cover_records=%d duration_ms=%d hanged=%v error=%q",
				requestLabel, req.Id, len(res.Info.Calls), countNonEmptyCover(res.Info.Calls),
				duration.Milliseconds(), res.Hanged, res.Error)
		}
	}
	return execMsg, nil
}

func logCallFeedback(requestID int64, execData []byte, calls []*flatrpc.CallInfo) {
	for _, row := range summarizeCallFeedback(calls, execCallNames(execData)) {
		log.Logf(0, "runner call feedback: id=%d call=%d name=%s signal=%d cover=%d comps=%d errno=%d",
			requestID, row.CallIndex, row.CallName, row.Signal, row.Cover, row.Comps, row.Error)
	}
}

func summarizeCallFeedback(calls []*flatrpc.CallInfo, callNames []string) []callFeedbackSummary {
	rows := make([]callFeedbackSummary, 0, len(calls))
	for index, call := range calls {
		if call == nil || (len(call.Signal) == 0 && len(call.Cover) == 0 && len(call.Comps) == 0) {
			continue
		}
		rows = append(rows, callFeedbackSummary{
			CallIndex: uint32(index),
			CallName:  callNameForIndex(callNames, uint32(index)),
			Signal:    len(call.Signal),
			Cover:     len(call.Cover),
			Comps:     len(call.Comps),
			Error:     call.Error,
		})
	}
	return rows
}

func logModuleCoverage(requestID int64, execData []byte, covRecords []nyxCovDumpRecord, kernel64Bit bool, ranges []moduleRuntimeRange) {
	for _, row := range summarizeModuleCoverageBySlot(covRecords, kernel64Bit, ranges) {
		log.Logf(0, "runner module coverage: id=%d slot=%d records=%d pcs=%d",
			requestID, row.SlotID, row.Records, row.PCs)
	}
	for _, row := range summarizeModuleCoverageByCall(covRecords, kernel64Bit, ranges, execCallNames(execData)) {
		log.Logf(0, "runner call module coverage: id=%d call=%d name=%s slot=%d records=%d pcs=%d",
			requestID, row.CallIndex, row.CallName, row.SlotID, row.Records, row.PCs)
	}
}

func buildCoverageDebugStreamEvent(requestID int64, execData []byte, covRecords []nyxCovDumpRecord,
	kernel64Bit bool, canonicalizer moduleRangeCanonicalizer) coverageDebugStreamEvent {
	event := coverageDebugStreamEvent{
		RequestID:   requestID,
		GeneratedAt: time.Now().UTC(),
	}
	callNames := execCallNames(execData)
	ranges := canonicalizer.CanonicalRanges()
	for _, rec := range covRecords {
		pcs := filterCoveragePCs(canonicalizer.CanonicalizePCs(rec.PCs), kernel64Bit)
		if len(pcs) == 0 {
			continue
		}
		if len(ranges) == 0 {
			event.Calls = append(event.Calls, coverageDebugStreamCall{
				CallIndex: rec.CallIndex,
				CallName:  callNameForIndex(callNames, rec.CallIndex),
				SlotID:    rec.SlotID,
				PCs:       hexUint64List(pcs),
			})
			continue
		}
		byModule := make(map[string]*coverageDebugStreamCall)
		for _, pc := range pcs {
			for _, rng := range ranges {
				if pc < rng.Base || pc >= rng.End {
					continue
				}
				key := fmt.Sprintf("%d/%s", rng.SlotID, moduleRangeKey(rng))
				row := byModule[key]
				if row == nil {
					row = &coverageDebugStreamCall{
						CallIndex: rec.CallIndex,
						CallName:  callNameForIndex(callNames, rec.CallIndex),
						SlotID:    rng.SlotID,
						Module:    rng.Name,
					}
					byModule[key] = row
				}
				row.PCs = append(row.PCs, fmt.Sprintf("0x%x", pc))
				row.Offsets = append(row.Offsets, fmt.Sprintf("0x%x", pc-rng.Base))
			}
		}
		keys := make([]string, 0, len(byModule))
		for key := range byModule {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			event.Calls = append(event.Calls, *byModule[key])
		}
	}
	return event
}

func appendCoverageDebugStream(path string, event coverageDebugStreamEvent) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	return enc.Encode(event)
}

func hexUint64List(values []uint64) []string {
	ret := make([]string, 0, len(values))
	for _, value := range values {
		ret = append(ret, fmt.Sprintf("0x%x", value))
	}
	return ret
}

func summarizeModuleCoverageBySlot(covRecords []nyxCovDumpRecord, kernel64Bit bool, ranges []moduleRuntimeRange) []moduleCoverageSlotSummary {
	bySlot := make(map[uint32]*moduleCoverageSlotSummary)
	for _, rec := range covRecords {
		pcs := filterCoveragePCs(rec.PCs, kernel64Bit)
		if len(pcs) == 0 {
			continue
		}
		if len(ranges) == 0 {
			row := moduleCoverageRow(bySlot, rec.SlotID)
			row.Records++
			row.PCs += len(pcs)
			continue
		}
		recordSlots := map[uint32]bool{}
		for _, pc := range pcs {
			for _, rng := range ranges {
				if pc >= rng.Base && pc < rng.End {
					recordSlots[rng.SlotID] = true
					row := moduleCoverageRow(bySlot, rng.SlotID)
					row.PCs++
				}
			}
		}
		for slotID := range recordSlots {
			moduleCoverageRow(bySlot, slotID).Records++
		}
	}
	rows := make([]moduleCoverageSlotSummary, 0, len(bySlot))
	for _, row := range bySlot {
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].SlotID < rows[j].SlotID
	})
	return rows
}

func summarizeModuleCoverageByCall(covRecords []nyxCovDumpRecord, kernel64Bit bool, ranges []moduleRuntimeRange, callNames []string) []moduleCoverageCallSummary {
	byKey := make(map[uint64]*moduleCoverageCallSummary)
	for _, rec := range covRecords {
		pcs := filterCoveragePCs(rec.PCs, kernel64Bit)
		if len(pcs) == 0 {
			continue
		}
		if len(ranges) == 0 {
			row := moduleCoverageCallRow(byKey, rec.CallIndex, rec.SlotID, callNameForIndex(callNames, rec.CallIndex))
			row.Records++
			row.PCs += len(pcs)
			continue
		}
		recordSlots := map[uint32]bool{}
		for _, pc := range pcs {
			for _, rng := range ranges {
				if pc >= rng.Base && pc < rng.End {
					recordSlots[rng.SlotID] = true
					row := moduleCoverageCallRow(byKey, rec.CallIndex, rng.SlotID, callNameForIndex(callNames, rec.CallIndex))
					row.PCs++
				}
			}
		}
		for slotID := range recordSlots {
			moduleCoverageCallRow(byKey, rec.CallIndex, slotID, callNameForIndex(callNames, rec.CallIndex)).Records++
		}
	}
	rows := make([]moduleCoverageCallSummary, 0, len(byKey))
	for _, row := range byKey {
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CallIndex != rows[j].CallIndex {
			return rows[i].CallIndex < rows[j].CallIndex
		}
		return rows[i].SlotID < rows[j].SlotID
	})
	return rows
}

func moduleCoverageRow(bySlot map[uint32]*moduleCoverageSlotSummary, slotID uint32) *moduleCoverageSlotSummary {
	row := bySlot[slotID]
	if row == nil {
		row = &moduleCoverageSlotSummary{SlotID: slotID}
		bySlot[slotID] = row
	}
	return row
}

func moduleCoverageCallRow(byKey map[uint64]*moduleCoverageCallSummary, callIndex, slotID uint32, callName string) *moduleCoverageCallSummary {
	key := uint64(callIndex)<<32 | uint64(slotID)
	row := byKey[key]
	if row == nil {
		row = &moduleCoverageCallSummary{CallIndex: callIndex, SlotID: slotID, CallName: callName}
		byKey[key] = row
	}
	return row
}

func callNameForIndex(callNames []string, index uint32) string {
	if int(index) < len(callNames) && callNames[index] != "" {
		return callNames[index]
	}
	return "<unknown>"
}

func (r *runner) runRequest(req *flatrpc.ExecRequest) (*flatrpc.ExecutorMessage, error) {
	if req.Type != flatrpc.RequestTypeProgram {
		return nil, fmt.Errorf("unsupported request type %v", req.Type)
	}
	if r.needRestart {
		if err := r.restartVM("recovering from previous hanged request"); err != nil {
			return nil, err
		}
	}
	if err := r.ensureHandshake(req); err != nil {
		return nil, err
	}
	if !r.coveragePrimed && requestNeedsCoveragePriming(req) {
		primeMsg, err := r.executeRequestOnce(req, true)
		if err != nil {
			return nil, err
		}
		r.coveragePrimed = true
		if primeResultCanReturn(primeMsg) {
			return primeMsg, nil
		}
		log.Logf(0, "runner replaying first traced request after handshake to prime PT coverage: id=%d", req.Id)
		return r.executeRequestOnce(req, false)
	}
	if requestNeedsCoveragePriming(req) {
		r.coveragePrimed = true
	}
	return r.executeRequestOnce(req, false)
}

func primeResultCanReturn(msg *flatrpc.ExecutorMessage) bool {
	if execResultHanged(msg) {
		return true
	}
	if msg == nil || msg.Msg == nil {
		return false
	}
	res, ok := msg.Msg.Value.(*flatrpc.ExecResult)
	if !ok || res == nil || res.Error != "" {
		return false
	}
	return execResultHasCoverage(msg)
}

func execResultHanged(msg *flatrpc.ExecutorMessage) bool {
	if msg == nil || msg.Msg == nil {
		return false
	}
	res, ok := msg.Msg.Value.(*flatrpc.ExecResult)
	return ok && res.Hanged
}

func countNonEmptyCover(calls []*flatrpc.CallInfo) int {
	n := 0
	for _, call := range calls {
		if call != nil && (len(call.Cover) != 0 || len(call.Signal) != 0) {
			n++
		}
	}
	return n
}

func progExecCallCountOrPanic(data []byte) int {
	n, err := prog.ExecCallCount(data)
	if err != nil {
		panic(err)
	}
	return n
}

func allCallSignal(all []int32) uint64 {
	var mask uint64
	for _, call := range all {
		if call >= 0 && call < 64 {
			mask |= 1 << call
		}
	}
	return mask
}

func hasExtraSignal(all []int32) bool {
	for _, call := range all {
		if call < 0 {
			return true
		}
	}
	return false
}

func countNewSignal(calls []*flatrpc.CallInfo, seen map[uint64]struct{}) int {
	n := 0
	for _, call := range calls {
		if call == nil {
			continue
		}
		for _, sig := range call.Signal {
			if _, ok := seen[sig]; ok {
				continue
			}
			seen[sig] = struct{}{}
			n++
		}
	}
	return n
}

func (r *runner) loop() error {
	for {
		msg, err := flatrpc.Recv[*flatrpc.HostMessageRaw](r.conn)
		if err != nil {
			if isExpectedManagerDisconnect(err) {
				log.Logf(0, "runner stopping after manager disconnect: %v", err)
				return nil
			}
			return err
		}
		switch req := msg.Msg.Value.(type) {
		case *flatrpc.ExecRequest:
			r.vm.debugLogf("runner received ExecRequest id=%d type=%v", req.Id, req.Type)
			executing := &flatrpc.ExecutorMessage{
				Msg: &flatrpc.ExecutorMessages{
					Type:  flatrpc.ExecutorMessagesRawExecuting,
					Value: &flatrpc.ExecutingMessage{Id: req.Id, ProcId: 0, Try: 0},
				},
			}
			if err := flatrpc.Send(r.conn, executing); err != nil {
				if isExpectedManagerDisconnect(err) {
					log.Logf(0, "runner stopping after manager disconnect during Executing reply: %v", err)
					return nil
				}
				return err
			}
			execMsg, err := r.runRequest(req)
			if err != nil {
				var crashErr *nyxCrashError
				if errors.As(err, &crashErr) {
					_, _ = os.Stderr.Write(crashErr.report)
				}
				execMsg = synthesizeErrorResult(req, err)
			}
			if err := flatrpc.Send(r.conn, execMsg); err != nil {
				if isExpectedManagerDisconnect(err) {
					log.Logf(0, "runner stopping after manager disconnect during ExecResult reply: %v", err)
					return nil
				}
				return err
			}
		case *flatrpc.StateRequest:
			r.vm.debugLogf("runner received StateRequest")
			state := &flatrpc.ExecutorMessage{
				Msg: &flatrpc.ExecutorMessages{
					Type:  flatrpc.ExecutorMessagesRawState,
					Value: &flatrpc.StateResult{Data: []byte("syz-nyx-runner alive\n")},
				},
			}
			if err := flatrpc.Send(r.conn, state); err != nil {
				if isExpectedManagerDisconnect(err) {
					log.Logf(0, "runner stopping after manager disconnect during State reply: %v", err)
					return nil
				}
				return err
			}
		case *flatrpc.SignalUpdate:
			r.vm.debugLogf("runner received SignalUpdate")
		case *flatrpc.CorpusTriaged:
			r.vm.debugLogf("runner received CorpusTriaged")
		default:
			return fmt.Errorf("unhandled host message %T", req)
		}
	}
}

func isExpectedManagerDisconnect(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED)
}

func connectWithRetry(r *runner, retryFor time.Duration) error {
	deadline := time.Now().Add(retryFor)
	var lastErr error
	for {
		if err := r.connect(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		log.Logf(0, "runner connect failed: %v; retrying", lastErr)
		time.Sleep(time.Second)
	}
}

func runStandalone(index int, vm *nyxVM, syscallName string, seed int64, programPath, targetProfile string, threaded, keepState bool,
	collectCover, fixedRepeat bool, syscallTimeoutMs, programTimeoutMs, rounds int, coverageDebugPath string) error {
	target, err := standaloneTarget(targetProfile)
	if err != nil {
		return err
	}
	p, bootstrap, label, err := standaloneBaseProgram(target, syscallName, seed, programPath)
	if err != nil {
		return err
	}
	connectReply := &flatrpc.ConnectReply{
		Cover:            collectCover,
		CoverEdges:       collectCover,
		Kernel64Bit:      true,
		Procs:            1,
		Slowdown:         1,
		SyscallTimeoutMs: int32(syscallTimeoutMs),
		ProgramTimeoutMs: int32(programTimeoutMs),
	}
	execFlags := standaloneExecFlags(threaded, collectCover)
	req := &flatrpc.ExecRequest{
		Id:   1,
		Type: flatrpc.RequestTypeProgram,
		ExecOpts: &flatrpc.ExecOpts{
			EnvFlags:   flatrpc.ExecEnvSignal | flatrpc.ExecEnvSandboxNone,
			ExecFlags:  execFlags,
			SandboxArg: 0,
		},
	}
	r := &runner{
		id:                index,
		vm:                vm,
		connectReply:      connectReply,
		keepState:         keepState,
		coverageDebugPath: coverageDebugPath,
	}
	if rounds < 0 {
		rounds = 1
	}
	var ct *prog.ChoiceTable
	if (rounds == 0 || rounds > 1) && !fixedRepeat {
		enabled := standaloneEnabledCallsForProgram(target, p)
		ct = target.BuildChoiceTable(nil, enabled)
	}
	corpus := []*prog.Prog{p.Clone()}
	seenSignal := make(map[uint64]struct{})
	for round := 0; rounds == 0 || round < rounds; round++ {
		var cur *prog.Prog
		roundSeed := seed + int64(round)
		if round == 0 {
			cur = p.Clone()
			if bootstrap {
				log.Logf(0, "standalone bootstrap program for %s:\n%s", label, string(cur.Serialize()))
			} else if programPath != "" {
				log.Logf(0, "standalone file program for %s:\n%s", label, string(cur.Serialize()))
			} else {
				log.Logf(0, "standalone seed program for %s (seed=%d):\n%s", label, seed, string(cur.Serialize()))
			}
		} else if fixedRepeat {
			cur = p.Clone()
			log.Logf(0, "standalone fixed-repeat program round=%d:\n%s",
				round+1, string(cur.Serialize()))
		} else {
			base := corpus[mrand.New(mrand.NewSource(roundSeed)).Intn(len(corpus))].Clone()
			base.Mutate(mrand.NewSource(roundSeed), 1, ct, nil, corpus)
			cur = base
			log.Logf(0, "standalone mutated program round=%d seed=%d corpus=%d:\n%s",
				round+1, roundSeed, len(corpus), string(cur.Serialize()))
		}
		execData, err := cur.SerializeForExec()
		if err != nil {
			return fmt.Errorf("serialize standalone program for exec: %w", err)
		}
		execCalls, err := prog.ExecCallCount(execData)
		if err != nil {
			return fmt.Errorf("count standalone exec calls: %w", err)
		}
		log.Logf(0, "standalone exec encoding round=%d: bytes=%d calls=%d collect_cover=%v", round+1, len(execData), execCalls, collectCover)
		log.Logf(0, "standalone exec program round=%d: %s", round+1, describeExecProgram(execData))
		req.Data = execData
		req.Id = int64(round + 1)
		execMsg, err := r.runRequest(req)
		if err != nil {
			return err
		}
		res, ok := execMsg.Msg.Value.(*flatrpc.ExecResult)
		if !ok || res.Info == nil {
			return fmt.Errorf("unexpected executor message type %T", execMsg.Msg.Value)
		}
		newSignal := countNewSignal(res.Info.Calls, seenSignal)
		log.Logf(0, "standalone exec finished round=%d: calls=%d cover_records=%d new_signal=%d corpus=%d",
			round+1, len(res.Info.Calls), countNonEmptyCover(res.Info.Calls), newSignal, len(corpus))
		for i, call := range res.Info.Calls {
			if call == nil {
				log.Logf(0, "call[%d]: <nil>", i)
				continue
			}
			log.Logf(0, "call[%d]: errno=%d flags=0x%x cover=%d signal=%d comps=%d",
				i, call.Error, call.Flags, len(call.Cover), len(call.Signal), len(call.Comps))
		}
		if newSignal > 0 {
			corpus = append(corpus, cur.Clone())
			log.Logf(0, "standalone corpus accepted round=%d new_size=%d", round+1, len(corpus))
		}
	}
	return nil
}

func runStandaloneExec(index int, vm *nyxVM, programPath string, threaded, keepState bool,
	collectCover bool, syscallTimeoutMs, programTimeoutMs, rounds int, coverageDebugPath string) error {
	execData, label, err := standaloneExecProgram(programPath)
	if err != nil {
		return err
	}
	connectReply := standaloneConnectReply(syscallTimeoutMs, programTimeoutMs, collectCover)
	execFlags := standaloneExecFlags(threaded, collectCover)
	req := &flatrpc.ExecRequest{
		Type: flatrpc.RequestTypeProgram,
		ExecOpts: &flatrpc.ExecOpts{
			EnvFlags:   flatrpc.ExecEnvSignal | flatrpc.ExecEnvSandboxNone,
			ExecFlags:  execFlags,
			SandboxArg: 0,
		},
		Data: execData,
	}
	r := &runner{
		id:                index,
		vm:                vm,
		connectReply:      connectReply,
		keepState:         keepState,
		coverageDebugPath: coverageDebugPath,
	}
	if rounds < 0 {
		rounds = 1
	}
	seenSignal := make(map[uint64]struct{})
	for round := 0; rounds == 0 || round < rounds; round++ {
		req.Id = int64(round + 1)
		log.Logf(0, "standalone exec file program round=%d for %s collect_cover=%v: %s",
			round+1, label, collectCover, describeExecProgram(execData))
		execMsg, err := r.runRequest(req)
		if err != nil {
			return err
		}
		res, ok := execMsg.Msg.Value.(*flatrpc.ExecResult)
		if !ok || res.Info == nil {
			return fmt.Errorf("unexpected executor message type %T", execMsg.Msg.Value)
		}
		newSignal := countNewSignal(res.Info.Calls, seenSignal)
		log.Logf(0, "standalone exec file finished round=%d: calls=%d cover_records=%d new_signal=%d",
			round+1, len(res.Info.Calls), countNonEmptyCover(res.Info.Calls), newSignal)
		for i, call := range res.Info.Calls {
			if call == nil {
				log.Logf(0, "exec-file call[%d]: <nil>", i)
				continue
			}
			log.Logf(0, "exec-file call[%d]: errno=%d flags=0x%x cover=%d signal=%d comps=%d",
				i, call.Error, call.Flags, len(call.Cover), len(call.Signal), len(call.Comps))
		}
	}
	return nil
}

func runStandaloneStaged(index int, vm *nyxVM, firstProgramPath, secondProgramPath, targetProfile string, threaded, keepState bool,
	collectCover bool, syscallTimeoutMs, programTimeoutMs, stageDelayMs, stageIdleMs int, coverageDebugPath string) error {
	target, err := standaloneTarget(targetProfile)
	if err != nil {
		return err
	}
	first, _, firstLabel, err := standaloneBaseProgram(target, "", 0, firstProgramPath)
	if err != nil {
		return fmt.Errorf("load standalone stage1 program: %w", err)
	}
	second, _, secondLabel, err := standaloneBaseProgram(target, "", 0, secondProgramPath)
	if err != nil {
		return fmt.Errorf("load standalone stage2 program: %w", err)
	}
	connectReply := standaloneConnectReply(syscallTimeoutMs, programTimeoutMs, collectCover)
	execFlags := standaloneExecFlags(threaded, collectCover)
	r := &runner{
		id:                index,
		vm:                vm,
		connectReply:      connectReply,
		keepState:         keepState,
		coverageDebugPath: coverageDebugPath,
	}
	stages := []struct {
		id    int64
		name  string
		label string
		prog  *prog.Prog
	}{
		{id: 1, name: "stage1", label: firstLabel, prog: first},
		{id: 2, name: "stage2", label: secondLabel, prog: second},
	}
	for i, stage := range stages {
		log.Logf(0, "standalone staged %s file program for %s:\n%s", stage.name, stage.label, string(stage.prog.Serialize()))
		execData, err := stage.prog.SerializeForExec()
		if err != nil {
			return fmt.Errorf("serialize standalone staged %s program for exec: %w", stage.name, err)
		}
		execCalls, err := prog.ExecCallCount(execData)
		if err != nil {
			return fmt.Errorf("count standalone staged %s exec calls: %w", stage.name, err)
		}
		log.Logf(0, "standalone staged exec encoding %s: bytes=%d calls=%d collect_cover=%v", stage.name, len(execData), execCalls, collectCover)
		log.Logf(0, "standalone staged exec program %s: %s", stage.name, describeExecProgram(execData))
		req := &flatrpc.ExecRequest{
			Id:   stage.id,
			Type: flatrpc.RequestTypeProgram,
			ExecOpts: &flatrpc.ExecOpts{
				EnvFlags:   flatrpc.ExecEnvSignal | flatrpc.ExecEnvSandboxNone,
				ExecFlags:  execFlags,
				SandboxArg: 0,
			},
			Data: execData,
		}
		execMsg, err := r.runRequest(req)
		if err != nil {
			return err
		}
		res, ok := execMsg.Msg.Value.(*flatrpc.ExecResult)
		if !ok || res.Info == nil {
			return fmt.Errorf("unexpected executor message type %T", execMsg.Msg.Value)
		}
		log.Logf(0, "standalone staged exec finished %s: calls=%d cover_records=%d",
			stage.name, len(res.Info.Calls), countNonEmptyCover(res.Info.Calls))
		for callIndex, call := range res.Info.Calls {
			if call == nil {
				log.Logf(0, "staged %s call[%d]: <nil>", stage.name, callIndex)
				continue
			}
			log.Logf(0, "staged %s call[%d]: errno=%d flags=0x%x cover=%d signal=%d comps=%d",
				stage.name, callIndex, call.Error, call.Flags, len(call.Cover), len(call.Signal), len(call.Comps))
		}
		if i == 0 && stageDelayMs > 0 {
			log.Logf(0, "standalone staged host sleep before stage2: %dms (guest is not stepped)", stageDelayMs)
			time.Sleep(time.Duration(stageDelayMs) * time.Millisecond)
		}
		if i == 0 && stageIdleMs > 0 {
			log.Logf(0, "standalone staged guest idle before stage2: %d yield payloads", stageIdleMs)
			for idle := 0; idle < stageIdleMs; idle++ {
				idleMsg, err := vm.executeIdle(0)
				if err != nil {
					return fmt.Errorf("standalone staged guest idle %d failed: %w", idle+1, err)
				}
				res, ok := idleMsg.Msg.Value.(*flatrpc.ExecResult)
				if !ok || res.Info == nil {
					return fmt.Errorf("unexpected idle executor message type %T", idleMsg.Msg.Value)
				}
				if idle == 0 || idle+1 == stageIdleMs || (idle+1)%100 == 0 {
					log.Logf(0, "standalone staged guest idle progress: %d/%d calls=%d hanged=%v error=%q",
						idle+1, stageIdleMs, len(res.Info.Calls), res.Hanged, res.Error)
				}
			}
			log.Logf(0, "standalone staged guest idle finished: yields=%d", stageIdleMs)
		}
	}
	return nil
}

func runStandaloneExecStaged(index int, vm *nyxVM, firstProgramPath, secondProgramPath string, threaded, keepState bool,
	collectCover bool, syscallTimeoutMs, programTimeoutMs, stageDelayMs, stageIdleMs int, coverageDebugPath string) error {
	first, firstLabel, err := standaloneExecProgram(firstProgramPath)
	if err != nil {
		return fmt.Errorf("load standalone stage1 exec program: %w", err)
	}
	second, secondLabel, err := standaloneExecProgram(secondProgramPath)
	if err != nil {
		return fmt.Errorf("load standalone stage2 exec program: %w", err)
	}
	connectReply := standaloneConnectReply(syscallTimeoutMs, programTimeoutMs, collectCover)
	execFlags := standaloneExecFlags(threaded, collectCover)
	r := &runner{
		id:                index,
		vm:                vm,
		connectReply:      connectReply,
		keepState:         keepState,
		coverageDebugPath: coverageDebugPath,
	}
	stages := []struct {
		id    int64
		name  string
		label string
		data  []byte
	}{
		{id: 1, name: "stage1", label: firstLabel, data: first},
		{id: 2, name: "stage2", label: secondLabel, data: second},
	}
	for i, stage := range stages {
		log.Logf(0, "standalone staged exec-file %s for %s collect_cover=%v: %s",
			stage.name, stage.label, collectCover, describeExecProgram(stage.data))
		req := &flatrpc.ExecRequest{
			Id:   stage.id,
			Type: flatrpc.RequestTypeProgram,
			ExecOpts: &flatrpc.ExecOpts{
				EnvFlags:   flatrpc.ExecEnvSignal | flatrpc.ExecEnvSandboxNone,
				ExecFlags:  execFlags,
				SandboxArg: 0,
			},
			Data: stage.data,
		}
		execMsg, err := r.runRequest(req)
		if err != nil {
			return err
		}
		res, ok := execMsg.Msg.Value.(*flatrpc.ExecResult)
		if !ok || res.Info == nil {
			return fmt.Errorf("unexpected executor message type %T", execMsg.Msg.Value)
		}
		log.Logf(0, "standalone staged exec-file finished %s: calls=%d cover_records=%d",
			stage.name, len(res.Info.Calls), countNonEmptyCover(res.Info.Calls))
		for callIndex, call := range res.Info.Calls {
			if call == nil {
				log.Logf(0, "staged exec-file %s call[%d]: <nil>", stage.name, callIndex)
				continue
			}
			log.Logf(0, "staged exec-file %s call[%d]: errno=%d flags=0x%x cover=%d signal=%d comps=%d",
				stage.name, callIndex, call.Error, call.Flags, len(call.Cover), len(call.Signal), len(call.Comps))
		}
		if i == 0 && stageDelayMs > 0 {
			log.Logf(0, "standalone staged host sleep before stage2: %dms (guest is not stepped)", stageDelayMs)
			time.Sleep(time.Duration(stageDelayMs) * time.Millisecond)
		}
		if i == 0 && stageIdleMs > 0 {
			log.Logf(0, "standalone staged guest idle before stage2: %d yield payloads", stageIdleMs)
			for idle := 0; idle < stageIdleMs; idle++ {
				idleMsg, err := vm.executeIdle(0)
				if err != nil {
					return fmt.Errorf("standalone staged guest idle %d failed: %w", idle+1, err)
				}
				res, ok := idleMsg.Msg.Value.(*flatrpc.ExecResult)
				if !ok || res.Info == nil {
					return fmt.Errorf("unexpected idle executor message type %T", idleMsg.Msg.Value)
				}
				if idle == 0 || idle+1 == stageIdleMs || (idle+1)%100 == 0 {
					log.Logf(0, "standalone staged guest idle progress: %d/%d calls=%d hanged=%v error=%q",
						idle+1, stageIdleMs, len(res.Info.Calls), res.Hanged, res.Error)
				}
			}
			log.Logf(0, "standalone staged guest idle finished: yields=%d", stageIdleMs)
		}
	}
	return nil
}

func standaloneBaseProgram(target *prog.Target, syscallName string, seed int64, programPath string) (*prog.Prog, bool, string, error) {
	if programPath != "" {
		data, err := os.ReadFile(programPath)
		if err != nil {
			return nil, false, "", fmt.Errorf("read standalone program %q: %w", programPath, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			return nil, false, "", fmt.Errorf("deserialize standalone program %q: %w", programPath, err)
		}
		return p, false, programPath, nil
	}
	meta := target.SyscallMap[syscallName]
	if meta == nil {
		return nil, false, "", fmt.Errorf("unknown syscall %q", syscallName)
	}
	p, bootstrap, err := standaloneProgram(target, meta, seed)
	if err != nil {
		return nil, false, "", err
	}
	return p, bootstrap, syscallName, nil
}

func standaloneTarget(profile string) (*prog.Target, error) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		return nil, fmt.Errorf("get target: %w", err)
	}
	if profile == "" {
		return target, nil
	}
	if target.ApplyTargetProfile == nil {
		return nil, fmt.Errorf("windows/amd64 target does not support standalone target profile %q", profile)
	}
	target, err = target.ApplyTargetProfile(target, profile)
	if err != nil {
		return nil, fmt.Errorf("apply standalone target profile %q: %w", profile, err)
	}
	return target, nil
}

func standaloneExecProgram(path string) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read standalone exec program %q: %w", path, err)
	}
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		return nil, "", fmt.Errorf("get target: %w", err)
	}
	if _, err := target.DeserializeExec(data, nil); err != nil {
		return nil, "", fmt.Errorf("deserialize standalone exec program %q: %w", path, err)
	}
	return data, path, nil
}

func standaloneConnectReply(syscallTimeoutMs, programTimeoutMs int, collectCover bool) *flatrpc.ConnectReply {
	return &flatrpc.ConnectReply{
		Cover:            collectCover,
		CoverEdges:       collectCover,
		Kernel64Bit:      true,
		Procs:            1,
		Slowdown:         1,
		SyscallTimeoutMs: int32(syscallTimeoutMs),
		ProgramTimeoutMs: int32(programTimeoutMs),
	}
}

func standaloneExecFlags(threaded, collectCover bool) flatrpc.ExecFlag {
	execFlags := flatrpc.ExecFlagCollectSignal
	if collectCover {
		execFlags |= flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagDedupCover
	}
	if threaded {
		execFlags |= flatrpc.ExecFlagThreaded
	}
	return execFlags
}

func standaloneEnabledCallsForProgram(target *prog.Target, p *prog.Prog) map[*prog.Syscall]bool {
	enabled := make(map[*prog.Syscall]bool)
	for _, call := range p.Calls {
		if call != nil && call.Meta != nil {
			enabled[call.Meta] = true
		}
	}
	enabled, _ = target.TransitivelyEnabledCalls(enabled)
	return enabled
}

func standaloneProgram(target *prog.Target, meta *prog.Syscall, seed int64) (*prog.Prog, bool, error) {
	if meta.Name == "NtQuerySystemInformation" {
		// Keep one async worker blocked long enough to encourage a real
		// scheduler handoff and exercise the per-thread PT path.
		src := []byte(
			"VirtualAlloc(0x0, 0x1000, 0x3000, 0x40)\n" +
				"NtQuerySystemInformation(0x0, &(0x7f0000000000)=\"\"/4096, 0x1000, &(0x7f0000001000)=0x0)\n" +
				"NtQueryTimerResolution(&(0x7f0000002000)=0x0, &(0x7f0000002004)=0x0, &(0x7f0000002008)=0x0)\n" +
				"NtQuerySystemTime(&(0x7f0000002010)=0x0)\n" +
				"NtQueryPerformanceCounter(&(0x7f0000002020)=0x0, &(0x7f0000002030)=0x0)\n" +
				"NtDelayExecution(0x0, &(0x7f0000002040)=@QuadPart=0xfffffffffff85ee0) (async)\n" +
				"CloseHandle(0xffffffffffffffff) (async)\n" +
				"NtYieldExecution() (async)\n" +
				"NtFlushWriteBuffer() (async)\n")
		p, err := target.Deserialize(src, prog.NonStrict)
		if err != nil {
			return nil, false, fmt.Errorf("build standalone 9-call bootstrap program: %w", err)
		}
		return p, true, nil
	}
	if standaloneNeedsFileHandleProgram(meta) {
		src, err := standaloneFileHandleProgram(meta.Name)
		if err != nil {
			return nil, false, err
		}
		p, err := target.Deserialize(src, prog.NonStrict)
		if err != nil {
			return nil, false, fmt.Errorf("build standalone %s file-handle program: %w", meta.Name, err)
		}
		return p, true, nil
	}
	if meta.Name == "getsockopt$int_accept" {
		src := bootstrapTCPAcceptedSessionWithClient(
			"&(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}",
			"&(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}") +
			"getsockopt$int_accept(r2, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n" +
			bootstrapCloseAcceptSessionSockets()
		p, err := target.Deserialize([]byte(src), prog.NonStrict)
		if err != nil {
			return nil, false, fmt.Errorf("build standalone getsockopt$int_accept program: %w", err)
		}
		return p, true, nil
	}
	ct := target.BuildChoiceTable(nil, standaloneEnabledCalls(target, meta))
	for attempts := 0; attempts < 128; attempts++ {
		p := target.Generate(mrand.NewSource(seed+int64(attempts)), 6, ct)
		if standaloneProgramContainsCall(p, meta.Name) {
			return p, false, nil
		}
	}
	return nil, false, fmt.Errorf("failed to generate standalone program containing %s", meta.Name)
}

func standaloneEnabledCalls(target *prog.Target, meta *prog.Syscall) map[*prog.Syscall]bool {
	enabled := map[*prog.Syscall]bool{meta: true}
	for _, name := range []string{
		"VirtualAlloc",
		"CloseHandle",
		"CreateFileA",
		"CreateFile2",
		"ReadFile",
		"WriteFile",
		"FlushFileBuffers",
		"DeleteFileA",
		"SetFileInformationByHandle",
		"NtFsControlFile",
		"NtReadFile",
		"NtWriteFile",
		"NtDelayExecution",
		"NtYieldExecution",
		"NtQueryTimerResolution",
		"NtSetTimerResolution",
		"NtQuerySystemTime",
		"NtQueryPerformanceCounter",
		"NtPowerInformation",
		"NtFlushInstructionCache",
		"NtFlushWriteBuffer",
		"NtQueryDefaultLocale",
		"NtQueryDefaultUILanguage",
		"NtDeviceIoControlFile",
		"NtFsControlFile$ntfs_get_compression",
		"NtFsControlFile$ntfs_set_compression",
		"NtFsControlFile$ntfs_set_sparse",
		"NtFsControlFile$ntfs_set_zero_data",
		"NtFsControlFile$ntfs_query_allocated_ranges",
	} {
		if s, ok := target.SyscallMap[name]; ok {
			enabled[s] = true
		}
	}
	enabled, _ = target.TransitivelyEnabledCalls(enabled)
	return enabled
}

func standaloneProgramContainsCall(p *prog.Prog, name string) bool {
	if p == nil {
		return false
	}
	for _, call := range p.Calls {
		if call != nil && call.Meta != nil && call.Meta.Name == name {
			return true
		}
	}
	return false
}

func standaloneNeedsFileHandleProgram(meta *prog.Syscall) bool {
	if meta == nil {
		return false
	}
	switch meta.Name {
	case "NtDeviceIoControlFile", "NtFsControlFile", "NtFsControlFile$ntfs_get_compression",
		"NtFsControlFile$ntfs_set_compression", "NtFsControlFile$ntfs_set_sparse",
		"NtFsControlFile$ntfs_set_zero_data", "NtFsControlFile$ntfs_query_allocated_ranges",
		"NtQueryInformationFile$basic", "NtQueryInformationFile$standard",
		"NtQueryInformationFile$network_open", "NtReadFile", "NtSetInformationFile$basic",
		"NtWriteFile", "TransmitFile$inet_accept",
		"ConnectEx$inet_tcp", "DisconnectEx$inet_tcp", "GetAcceptExSockaddrs$inet_tcp",
		"ConnectEx$inet_tcp_pending", "CreateIoCompletionPort$connect_pending",
		"WSAGetOverlappedResult$connect_pending", "CancelIoEx$connect_pending",
		"CancelIo$connect_pending", "setsockopt$update_connect_context",
		"closesocket$connect_pending",
		"DisconnectEx$inet_tcp_reuse", "ConnectEx$inet_tcp_reuse",
		"TransmitPackets$inet_accept", "WSARecvMsg$udp",
		"WSAEventSelect$tcp", "WSAEnumNetworkEvents$tcp",
		"WSAEventSelect$accept", "WSAEnumNetworkEvents$accept",
		"WSAGetOverlappedResult$socket", "CancelIoEx$socket", "CancelIo$socket",
		"CreateIoCompletionPort$socket", "GetQueuedCompletionStatus$socket",
		"AcceptEx$inet_tcp_pending", "setsockopt$update_accept_context",
		"CreateIoCompletionPort$accept_pending", "WSAGetOverlappedResult$accept_pending",
		"CancelIoEx$accept_pending", "CancelIo$accept_pending",
		"closesocket$accept_pending",
		"WSARecv$accept_pending", "WSASend$accept_pending",
		"CreateIoCompletionPort$accept_recv_pending", "CreateIoCompletionPort$accept_send_pending",
		"WSAGetOverlappedResult$accept_recv_pending", "WSAGetOverlappedResult$accept_send_pending",
		"CancelIoEx$accept_recv_pending", "CancelIoEx$accept_send_pending",
		"CancelIo$accept_recv_pending", "CancelIo$accept_send_pending",
		"closesocket$accept_recv_pending", "closesocket$accept_send_pending",
		"WSARecv$tcp_pending", "WSASend$tcp_pending",
		"CreateIoCompletionPort$tcp_recv_pending", "CreateIoCompletionPort$tcp_send_pending",
		"WSAGetOverlappedResult$tcp_recv_pending", "WSAGetOverlappedResult$tcp_send_pending",
		"CancelIoEx$tcp_recv_pending", "CancelIoEx$tcp_send_pending",
		"CancelIo$tcp_recv_pending", "CancelIo$tcp_send_pending",
		"closesocket$tcp_recv_pending", "closesocket$tcp_send_pending",
		"send$inet_accept_updated", "recv$inet_accept_updated",
		"setsockopt$int_accept_updated", "getsockopt$int_accept_updated":
		return true
	}
	return false
}

func standaloneFileHandleProgram(name string) ([]byte, error) {
	switch name {
	case "NtFsControlFile":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtFsControlFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)={@Status=0x0, 0x0}, 0x9003c, 0x0, 0x0, &(0x7f0000000200)='\\x00'/2, 0x2)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtFsControlFile$ntfs_get_compression":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl-get-compression\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtFsControlFile$ntfs_get_compression(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)={@Status=0x0, 0x0}, 0x9003c, 0x0, 0x0, &(0x7f0000000200), 0x2)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtFsControlFile$ntfs_set_compression":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl-set-compression\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtFsControlFile$ntfs_set_compression(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)={@Status=0x0, 0x0}, 0x9c040, &(0x7f0000000200)={0x0}, 0x2, 0x0, 0x0)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtFsControlFile$ntfs_set_sparse":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl-set-sparse\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtFsControlFile$ntfs_set_sparse(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)={@Status=0x0, 0x0}, 0x900c4, &(0x7f0000000200)={0x1}, 0x1, 0x0, 0x0)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtFsControlFile$ntfs_set_zero_data":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl-set-zero\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"WriteFile(r0, &(0x7f0000000100)='abcd', 0x4, &(0x7f0000000140)=0x0, 0x0)\n" +
				"NtFsControlFile$ntfs_set_zero_data(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000200)={@Status=0x0, 0x0}, 0x980c8, &(0x7f0000000300)={@QuadPart=0x0, @QuadPart=0x4}, 0x10, 0x0, 0x0)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtFsControlFile$ntfs_query_allocated_ranges":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl-query-ranges\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"WriteFile(r0, &(0x7f0000000100)='abcd', 0x4, &(0x7f0000000140)=0x0, 0x0)\n" +
				"NtFsControlFile$ntfs_query_allocated_ranges(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000200)={@Status=0x0, 0x0}, 0x940cf, &(0x7f0000000300)={@QuadPart=0x0, @QuadPart=0x1000}, 0x10, &(0x7f0000000400)=[{{@QuadPart=0x0, @QuadPart=0x0}}, {{@QuadPart=0x0, @QuadPart=0x0}}], 0x20)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtDeviceIoControlFile":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-device-ioctl\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtDeviceIoControlFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)={@Status=0x0, 0x0}, 0x70000, 0x0, 0x0, &(0x7f0000000200)='\\x00'/256, 0x100)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtQueryInformationFile$basic":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-qinfo-basic\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtQueryInformationFile$basic(r0, &(0x7f0000000100)={@Status=0x0, 0x0}, &(0x7f0000000200), 0x28, 0x4)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtQueryInformationFile$standard":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-qinfo-standard\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtQueryInformationFile$standard(r0, &(0x7f0000000100)={@Status=0x0, 0x0}, &(0x7f0000000200), 0x18, 0x5)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtQueryInformationFile$network_open":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-qinfo-netopen\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtQueryInformationFile$network_open(r0, &(0x7f0000000100)={@Status=0x0, 0x0}, &(0x7f0000000200), 0x38, 0x22)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtReadFile":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-read\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtReadFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)={@Status=0x0, 0x0}, &(0x7f0000000200)='\\x00'/256, 0x100, 0x0, 0x0)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtSetInformationFile$basic":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-setinfo-basic\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtSetInformationFile$basic(r0, &(0x7f0000000100)={@Status=0x0, 0x0}, &(0x7f0000000200)={@QuadPart=0x0, @QuadPart=0x0, @QuadPart=0x0, @QuadPart=0x0, 0x80}, 0x28, 0x4)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtWriteFile":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-write\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtWriteFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)={@Status=0x0, 0x0}, &(0x7f0000000200)=\"abcd\", 0x4, 0x0, 0x0)\n" +
				"CloseHandle(r0)\n"), nil
	case "TransmitFile$inet_accept":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n" +
				"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r0, 0x1)\n" +
				"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
				"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n" +
				"r3 = CreateFileA(&(0x7f0000000200)='./nyx-txfile\\x00', 0xffffffff, 0x7, 0x0, 0x2, 0x80, 0xffffffffffffffff)\n" +
				"WriteFile(r3, &(0x7f0000000240)='abcd', 0x4, &(0x7f0000000280)=0x0, 0x0)\n" +
				"TransmitFile$inet_accept(r2, r3, 0x4, 0x0, 0x0, 0x0, 0x0)\n" +
				"CloseHandle(r3)\n" +
				"closesocket$any(r2)\n" +
				"closesocket$any(r1)\n" +
				"closesocket$any(r0)\n"), nil
	case "ConnectEx$inet_tcp":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n" +
				"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r0, 0x1)\n" +
				"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
				"bind$connectex_tcp(r1, &(0x7f0000000120)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"ConnectEx$inet_tcp(r1, &(0x7f0000000140)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000180)='cx', 0x2, &(0x7f00000001c0), 0x0)\n" +
				"closesocket$any(r1)\n" +
				"closesocket$any(r0)\n"), nil
	case "ConnectEx$inet_tcp_pending", "CreateIoCompletionPort$connect_pending",
		"WSAGetOverlappedResult$connect_pending":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n" +
				"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r0, 0x1)\n" +
				"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
				"bind$connectex_tcp(r1, &(0x7f0000000120)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000140)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000180)='cx', 0x2, &(0x7f00000001c0), &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r3 = CreateIoCompletionPort$connect_pending(r2, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r2, &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r3, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n" +
				"closesocket$connect_pending(r2)\n" +
				"closesocket$any(r0)\n"), nil
	case "CancelIoEx$connect_pending", "CancelIo$connect_pending", "closesocket$connect_pending":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n" +
				"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r0, 0x1)\n" +
				"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
				"bind$connectex_tcp(r1, &(0x7f0000000120)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000140)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000180)='cx', 0x2, &(0x7f00000001c0), &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CreateIoCompletionPort$connect_pending(r2, 0x0, 0xafd, 0x0)\n" +
				"CancelIoEx$connect_pending(r2, &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CancelIo$connect_pending(r2)\n" +
				"closesocket$connect_pending(r2)\n" +
				"closesocket$any(r0)\n"), nil
	case "setsockopt$update_connect_context":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000120)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000140)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000180)='cx', 0x2, &(0x7f00000001c0), &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r5 = CreateIoCompletionPort$connect_pending(r4, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r4, &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r5, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n" +
				"setsockopt$update_connect_context(r4, 0xffff, 0x7010, 0x0, 0x0)\n" +
				"closesocket$any(r1)\n"), nil
	case "DisconnectEx$inet_tcp":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n" +
				"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r0, 0x1)\n" +
				"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
				"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n" +
				"DisconnectEx$inet_tcp(r1, 0x0, 0x0, 0x0)\n" +
				"closesocket$any(r2)\n" +
				"closesocket$any(r1)\n" +
				"closesocket$any(r0)\n"), nil
	case "DisconnectEx$inet_tcp_reuse":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = connect$inet_tcp(r3, &(0x7f0000000140)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = accept$inet_tcp(r2, 0x0, 0x0)\n" +
				"closesocket$any(r5)\n" +
				"r6 = DisconnectEx$inet_tcp_reuse(r4, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x2, 0x0)\n" +
				"r7 = CreateIoCompletionPort$disconnect_reuse_pending(r6, 0x0, 0xafd, 0x0)\n" +
				"GetQueuedCompletionStatus$socket(r7, &(0x7f0000000280), &(0x7f00000002c0), &(0x7f0000000300), 0x0)\n" +
				"r8 = WSAGetOverlappedResult$disconnect_reuse_pending(r6, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000340), 0x0, &(0x7f0000000380)=0x0)\n" +
				"closesocket$any(r2)\n" +
				"closesocket$any(r8)\n"), nil
	case "ConnectEx$inet_tcp_reuse":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = connect$inet_tcp(r3, &(0x7f0000000140)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = accept$inet_tcp(r2, 0x0, 0x0)\n" +
				"closesocket$any(r5)\n" +
				"r6 = DisconnectEx$inet_tcp_reuse(r4, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x2, 0x0)\n" +
				"r7 = CreateIoCompletionPort$disconnect_reuse_pending(r6, 0x0, 0xafd, 0x0)\n" +
				"GetQueuedCompletionStatus$socket(r7, &(0x7f0000000280), &(0x7f00000002c0), &(0x7f0000000300), 0x0)\n" +
				"r8 = WSAGetOverlappedResult$disconnect_reuse_pending(r6, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000340), 0x0, &(0x7f0000000380)=0x0)\n" +
				"r9 = ConnectEx$inet_tcp_reuse(r8, &(0x7f00000003c0)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000400)='cx', 0x2, &(0x7f0000000440), &(0x7f0000000480)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r10 = CreateIoCompletionPort$connect_pending(r9, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r9, &(0x7f0000000480)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000580), 0x0, &(0x7f00000005c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r10, &(0x7f0000000600), &(0x7f0000000640), &(0x7f0000000680), 0x0)\n" +
				"setsockopt$update_connect_context(r9, 0xffff, 0x7010, 0x0, 0x0)\n" +
				"closesocket$any(r2)\n"), nil
	case "GetAcceptExSockaddrs$inet_tcp":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"GetAcceptExSockaddrs$inet_tcp(&(0x7f0000000100), 0x0, 0x20, 0x20, &(0x7f0000000200), &(0x7f0000000240), &(0x7f0000000280), &(0x7f00000002c0))\n"), nil
	case "TransmitPackets$inet_accept":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n" +
				"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r0, 0x1)\n" +
				"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
				"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n" +
				"TransmitPackets$inet_accept(r2, &(0x7f0000000200)=[{0x5, 0x4, &(0x7f0000000280)='abcd', 0x0}], 0x1, 0x0, 0x0, 0x0)\n" +
				"closesocket$any(r2)\n" +
				"closesocket$any(r1)\n" +
				"closesocket$any(r0)\n"), nil
	case "WSARecvMsg$udp":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$bound_udp(0x2, 0x2, 0x11)\n" +
				"bind$inet_udp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r1 = socket$connected_udp(0x2, 0x2, 0x11)\n" +
				"connect$inet_udp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"send$inet_udp(r1, &(0x7f0000000180)='msg', 0x3, 0x0)\n" +
				"WSARecvMsg$udp(r0, &(0x7f0000000200)={&(0x7f0000000280), 0x10, 0x0, &(0x7f0000000300)=[{0x40, &(0x7f0000000380)='\\x00'/64}], 0x1, 0x0, {0x20, &(0x7f0000000400)='\\x00'/32}, 0x0, 0x0}, &(0x7f0000000480), 0x0, 0x0)\n" +
				"closesocket$any(r1)\n" +
				"closesocket$any(r0)\n"), nil
	case "WSAEventSelect$tcp", "WSAEnumNetworkEvents$tcp":
		return []byte(bootstrapTCPAcceptedSessionWithClient(
			"&(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}",
			"&(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}") +
			"r3 = WSACreateEvent()\n" +
			"WSAEventSelect$tcp(r1, r3, 0x3f)\n" +
			"send$inet_accept(r2, &(0x7f0000000200)='evt', 0x3, 0x0)\n" +
			"WSAEnumNetworkEvents$tcp(r1, r3, &(0x7f0000000280))\n" +
			"WSACloseEvent(r3)\n" +
			"closesocket$any(r2)\n" +
			"closesocket$any(r1)\n" +
			"closesocket$any(r0)\n"), nil
	case "WSAEventSelect$accept", "WSAEnumNetworkEvents$accept":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n" +
				"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r0, 0x1)\n" +
				"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
				"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n" +
				"r3 = WSACreateEvent()\n" +
				"WSAEventSelect$accept(r2, r3, 0x3f)\n" +
				"send$inet_tcp(r1, &(0x7f0000000200)='evt', 0x3, 0x0)\n" +
				"WSAEnumNetworkEvents$accept(r2, r3, &(0x7f0000000280))\n" +
				"WSACloseEvent(r3)\n" +
				"closesocket$any(r2)\n" +
				"closesocket$any(r1)\n" +
				"closesocket$any(r0)\n"), nil
	case "WSAGetOverlappedResult$socket", "CancelIoEx$socket", "CancelIo$socket",
		"CreateIoCompletionPort$socket", "GetQueuedCompletionStatus$socket":
		return []byte(
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n" +
				"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r0, 0x1)\n" +
				"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
				"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n" +
				"r3 = CreateIoCompletionPort$socket(r2, 0x0, 0xafd, 0x0)\n" +
				"WSARecv$accept(r2, &(0x7f0000000200)=[{0x40, &(0x7f0000000280)='\\x00'/64}], 0x1, &(0x7f0000000300), &(0x7f0000000340)=0x0, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
				"CancelIoEx$socket(r2, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"WSAGetOverlappedResult$socket(r2, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000400), 0x0, &(0x7f0000000440)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r3, &(0x7f0000000480), &(0x7f00000004c0), &(0x7f0000000500), 0x0)\n" +
				"CancelIo$socket(r2)\n" +
				"closesocket$any(r2)\n" +
				"closesocket$any(r1)\n" +
				"closesocket$any(r0)\n"), nil
	case "AcceptEx$inet_tcp_pending", "CreateIoCompletionPort$accept_pending",
		"WSAGetOverlappedResult$accept_pending", "CancelIoEx$accept_pending",
		"CancelIo$accept_pending", "closesocket$accept_pending":
		return []byte(bootstrapTCPAcceptExPendingSessionWithClient(
			"&(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}",
			"&(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}") +
			"r4 = CreateIoCompletionPort$accept_pending(r3, 0x0, 0xafd, 0x0)\n" +
			"CancelIoEx$accept_pending(r3, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
			"WSAGetOverlappedResult$accept_pending(r3, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000400), 0x0, &(0x7f0000000440)=0x0)\n" +
			"CancelIo$accept_pending(r3)\n" +
			"GetQueuedCompletionStatus$socket(r4, &(0x7f0000000480), &(0x7f00000004c0), &(0x7f0000000500), 0x0)\n" +
			"closesocket$accept_pending(r3)\n" +
			"closesocket$any(r1)\n" +
			"closesocket$any(r0)\n"), nil
	case "WSARecv$accept_pending", "CreateIoCompletionPort$accept_recv_pending",
		"WSAGetOverlappedResult$accept_recv_pending", "CancelIoEx$accept_recv_pending",
		"CancelIo$accept_recv_pending", "closesocket$accept_recv_pending":
		return []byte(bootstrapTCPAcceptedSessionWithClient(
			"&(0x7f0000000100)={0x2, 0x4e22, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}",
			"&(0x7f0000000120)={0x2, 0x4e22, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}") +
			"r3 = WSARecv$accept_pending(r2, &(0x7f0000000200)=[{0x40, &(0x7f0000000280)='\\x00'/64}], 0x1, &(0x7f0000000300), &(0x7f0000000340)=0x0, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
			"r4 = CreateIoCompletionPort$accept_recv_pending(r3, 0x0, 0xafd, 0x0)\n" +
			"CancelIoEx$accept_recv_pending(r3, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
			"WSAGetOverlappedResult$accept_recv_pending(r3, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000400), 0x0, &(0x7f0000000440)=0x0)\n" +
			"CancelIo$accept_recv_pending(r3)\n" +
			"GetQueuedCompletionStatus$socket(r4, &(0x7f0000000480), &(0x7f00000004c0), &(0x7f0000000500), 0x0)\n" +
			"closesocket$accept_recv_pending(r3)\n" +
			"closesocket$any(r1)\n" +
			"closesocket$any(r0)\n"), nil
	case "WSASend$accept_pending", "CreateIoCompletionPort$accept_send_pending",
		"WSAGetOverlappedResult$accept_send_pending", "CancelIoEx$accept_send_pending",
		"CancelIo$accept_send_pending", "closesocket$accept_send_pending":
		return []byte(bootstrapTCPAcceptedSessionWithClient(
			"&(0x7f0000000100)={0x2, 0x4e23, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}",
			"&(0x7f0000000120)={0x2, 0x4e23, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}") +
			"r3 = WSASend$accept_pending(r2, &(0x7f0000000200)=[{0x4, &(0x7f0000000280)='send'}], 0x1, &(0x7f0000000300), 0x0, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
			"r4 = CreateIoCompletionPort$accept_send_pending(r3, 0x0, 0xafd, 0x0)\n" +
			"CancelIoEx$accept_send_pending(r3, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
			"WSAGetOverlappedResult$accept_send_pending(r3, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000400), 0x0, &(0x7f0000000440)=0x0)\n" +
			"CancelIo$accept_send_pending(r3)\n" +
			"GetQueuedCompletionStatus$socket(r4, &(0x7f0000000480), &(0x7f00000004c0), &(0x7f0000000500), 0x0)\n" +
			"closesocket$accept_send_pending(r3)\n" +
			"closesocket$any(r1)\n" +
			"closesocket$any(r0)\n"), nil
	case "WSARecv$tcp_pending", "CreateIoCompletionPort$tcp_recv_pending",
		"WSAGetOverlappedResult$tcp_recv_pending", "CancelIoEx$tcp_recv_pending",
		"CancelIo$tcp_recv_pending", "closesocket$tcp_recv_pending":
		return []byte(bootstrapTCPAcceptedSessionWithClient(
			"&(0x7f0000000100)={0x2, 0x4e24, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}",
			"&(0x7f0000000120)={0x2, 0x4e24, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}") +
			"send$inet_accept(r2, &(0x7f0000000200)='recv', 0x4, 0x0)\n" +
			"r3 = WSARecv$tcp_pending(r1, &(0x7f0000000280)=[{0x40, &(0x7f0000000300)='\\x00'/64}], 0x1, &(0x7f0000000380), &(0x7f00000003c0)=0x0, &(0x7f0000000400)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
			"r4 = CreateIoCompletionPort$tcp_recv_pending(r3, 0x0, 0xafd, 0x0)\n" +
			"CancelIoEx$tcp_recv_pending(r3, &(0x7f0000000400)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
			"WSAGetOverlappedResult$tcp_recv_pending(r3, &(0x7f0000000400)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000480), 0x0, &(0x7f00000004c0)=0x0)\n" +
			"CancelIo$tcp_recv_pending(r3)\n" +
			"GetQueuedCompletionStatus$socket(r4, &(0x7f0000000500), &(0x7f0000000540), &(0x7f0000000580), 0x0)\n" +
			"closesocket$tcp_recv_pending(r3)\n" +
			"closesocket$any(r2)\n" +
			"closesocket$any(r0)\n"), nil
	case "WSASend$tcp_pending", "CreateIoCompletionPort$tcp_send_pending",
		"WSAGetOverlappedResult$tcp_send_pending", "CancelIoEx$tcp_send_pending",
		"CancelIo$tcp_send_pending", "closesocket$tcp_send_pending":
		return []byte(bootstrapTCPAcceptedSessionWithClient(
			"&(0x7f0000000100)={0x2, 0x4e25, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}",
			"&(0x7f0000000120)={0x2, 0x4e25, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}") +
			"r3 = WSASend$tcp_pending(r1, &(0x7f0000000200)=[{0x4, &(0x7f0000000280)='send'}], 0x1, &(0x7f0000000300), 0x0, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
			"r4 = CreateIoCompletionPort$tcp_send_pending(r3, 0x0, 0xafd, 0x0)\n" +
			"CancelIoEx$tcp_send_pending(r3, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
			"WSAGetOverlappedResult$tcp_send_pending(r3, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000400), 0x0, &(0x7f0000000440)=0x0)\n" +
			"CancelIo$tcp_send_pending(r3)\n" +
			"GetQueuedCompletionStatus$socket(r4, &(0x7f0000000480), &(0x7f00000004c0), &(0x7f0000000500), 0x0)\n" +
			"closesocket$tcp_send_pending(r3)\n" +
			"closesocket$any(r2)\n" +
			"closesocket$any(r0)\n"), nil
	case "setsockopt$update_accept_context", "send$inet_accept_updated", "recv$inet_accept_updated",
		"setsockopt$int_accept_updated", "getsockopt$int_accept_updated":
		return []byte(bootstrapTCPAcceptExUpdatedSessionWithClient(
			"&(0x7f0000000100)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}",
			"&(0x7f0000000120)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}") +
			"send$inet_tcp(r1, &(0x7f0000000400)='upd', 0x3, 0x0)\n" +
			"recv$inet_accept_updated(r4, &(0x7f0000000480)='\\x00'/64, 0x40, 0x0)\n" +
			"send$inet_accept_updated(r4, &(0x7f0000000500)='reply', 0x5, 0x0)\n" +
			"setsockopt$int_accept_updated(r4, 0x1, 0x8, &(0x7f0000000580)=0x1, 0x4)\n" +
			"getsockopt$int_accept_updated(r4, 0x1, 0x8, &(0x7f00000005c0)=0x0, &(0x7f0000000600)=0x4)\n" +
			"closesocket$any(r4)\n" +
			"closesocket$any(r1)\n" +
			"closesocket$any(r0)\n"), nil
	default:
		return nil, fmt.Errorf("unsupported file-handle standalone syscall %q", name)
	}
}

func main() {
	os.Args = append([]string{os.Args[0]}, reorderArgsForFlags(os.Args[1:])...)

	var qemuArgs multiFlag
	var (
		qemuPath                    = flag.String("qemu-path", "", "qemu binary path")
		image                       = flag.String("image", "", "boot image path")
		workdir                     = flag.String("workdir", "", "nyx runner workdir")
		purge                       = flag.Bool("purge", false, "remove the existing workdir before starting")
		hardTimeout                 = flag.Duration("hard-timeout", 3*time.Minute, "Nyx/KVM hard timeout fallback (max 255s)")
		payloadSize                 = flag.Int("payload-size", int(flatrpc.ConstMaxInputSize)+4, "nyx payload buffer size")
		bitmapSize                  = flag.Int("bitmap-size", 0x10000, "nyx bitmap size")
		memoryMB                    = flag.Int("memory", 2048, "guest memory size in MB")
		windowsMinidump             = flag.Bool("windows-minidump", false, "preserve Windows minidumps through qemu-nyx")
		windowsMinidumpTimeout      = flag.Int("windows-minidump-timeout", 120, "Windows minidump completion timeout in seconds")
		keepState                   = flag.Bool("keep-state", false, "preserve guest state across manager-driven exec requests")
		debug                       = flag.Bool("debug", false, "inherit qemu stdout/stderr")
		standalone                  = flag.Bool("standalone", false, "run a local Nyx executor request without syz-manager")
		standaloneSyscall           = flag.String("standalone-syscall", "NtQuerySystemInformation", "Windows syscall name for standalone mode")
		standaloneSeed              = flag.Int64("standalone-seed", 1, "program generation seed for standalone mode")
		standaloneProgramPath       = flag.String("standalone-program", "", "path to a serialized syzkaller program to execute in standalone mode")
		standaloneTargetProfile     = flag.String("standalone-target-profile", "", "optional target profile applied before parsing/generating standalone syzkaller programs")
		standaloneExecProgramPath   = flag.String("standalone-exec-program", "", "path to a serialized executor program to execute in standalone mode")
		standaloneStagedProgram     = flag.String("standalone-staged-program", "", "optional second serialized syzkaller program for staged standalone mode")
		standaloneStagedExecProgram = flag.String("standalone-staged-exec-program", "", "optional second serialized executor program for staged standalone mode")
		standaloneRounds            = flag.Int("standalone-rounds", 1, "number of standalone exec rounds; 0 repeats until externally stopped; rounds>1 mutate accepted syzkaller programs")
		standaloneStageDelayMs      = flag.Int("standalone-stage-delay-ms", 0, "host-side delay between standalone staged programs")
		standaloneStageIdleMs       = flag.Int("standalone-stage-idle-ms", 0, "guest-side Nyx yield payload count between standalone staged programs")
		standaloneSyscallTimeoutMs  = flag.Int("standalone-syscall-timeout-ms", 20000, "standalone executor syscall timeout in ms")
		standaloneProgramTimeoutMs  = flag.Int("standalone-program-timeout-ms", 60000, "standalone executor program timeout in ms")
		standaloneThreaded          = flag.Bool("standalone-threaded", true, "set ExecFlagThreaded in standalone mode")
		standaloneKeepState         = flag.Bool("standalone-keep-state", true, "preserve guest state between standalone exec requests")
		standaloneNoCover           = flag.Bool("standalone-no-cover", false, "disable standalone coverage collection while keeping signal collection")
		standaloneFixedRepeat       = flag.Bool("standalone-fixed-repeat", false, "repeat the initial standalone syzkaller program for all rounds instead of mutating")
		moduleRangesRaw             = flag.String("module-ranges", defaultModuleRangeList(), "comma-separated kernel module PT range targets; suffix :required for mandatory matches")
		coverageDebugStream         = flag.String("coverage-debug-stream", "", "optional JSONL path for per-exec raw module coverage diagnostics")
		slowTraceDir                = flag.String("slow-trace-dir", "", "slow/hang artifact directory (default: workdir/slow-traces; '-' disables)")
		slowTraceThresholdMs        = flag.Int("slow-trace-threshold-ms", 2000, "dump a slow trace when execution duration is at least this many ms")
		slowTraceMaxEvents          = flag.Int("slow-trace-max-events", 4096, "maximum flight-recorder events retained and copied per slow trace")
	)
	flag.Var(&qemuArgs, "qemu-arg", "extra qemu argument (repeatable)")
	flag.Parse()
	if *qemuPath == "" || *workdir == "" || (!*standalone && flag.NArg() != 3) || (*standalone && flag.NArg() != 1) {
		fmt.Fprintf(os.Stderr, "usage: syz-nyx-runner <index> <manager-addr> <manager-port> --qemu-path ... --workdir ... [--image ...] [--qemu-arg ...]\n")
		fmt.Fprintf(os.Stderr, "   or: syz-nyx-runner <index> --standalone --qemu-path ... --workdir ... [--standalone-syscall ...]\n")
		os.Exit(2)
	}
	index, err := strconv.Atoi(flag.Arg(0))
	if err != nil {
		log.Fatalf("bad index: %v", err)
	}
	if *purge {
		log.Logf(0, "purging nyx workdir %s", *workdir)
		if err := os.RemoveAll(*workdir); err != nil {
			log.Fatalf("failed to purge workdir %s: %v", *workdir, err)
		}
	}
	if *standaloneSyscallTimeoutMs <= 0 || *standaloneProgramTimeoutMs <= *standaloneSyscallTimeoutMs {
		log.Fatalf("bad standalone timeouts: syscall=%d program=%d", *standaloneSyscallTimeoutMs, *standaloneProgramTimeoutMs)
	}
	if *standaloneStageDelayMs < 0 {
		log.Fatalf("bad standalone stage delay: %d", *standaloneStageDelayMs)
	}
	if *standaloneStageIdleMs < 0 {
		log.Fatalf("bad standalone stage idle: %d", *standaloneStageIdleMs)
	}
	if *standaloneStagedProgram != "" && *standaloneProgramPath == "" {
		log.Fatalf("--standalone-staged-program requires --standalone-program")
	}
	if *standaloneExecProgramPath != "" && *standaloneProgramPath != "" {
		log.Fatalf("--standalone-exec-program cannot be combined with --standalone-program")
	}
	if *standaloneStagedExecProgram != "" && *standaloneExecProgramPath == "" {
		log.Fatalf("--standalone-staged-exec-program requires --standalone-exec-program")
	}
	if *standaloneStagedExecProgram != "" && *standaloneStagedProgram != "" {
		log.Fatalf("--standalone-staged-exec-program cannot be combined with --standalone-staged-program")
	}
	if *slowTraceThresholdMs < 0 {
		log.Fatalf("bad slow trace threshold: %d", *slowTraceThresholdMs)
	}
	if *slowTraceMaxEvents <= 0 {
		log.Fatalf("bad slow trace max events: %d", *slowTraceMaxEvents)
	}
	moduleRanges, err := parseModuleRanges(*moduleRangesRaw)
	if err != nil {
		log.Fatalf("bad module range config: %v", err)
	}
	vm := newNyxVM(index, *workdir, *qemuPath, qemuArgs, *image, *memoryMB, *payloadSize, *bitmapSize, *debug, *hardTimeout, moduleRanges, *windowsMinidump, *windowsMinidumpTimeout)
	vm.trace = newTraceRecorder(*slowTraceMaxEvents)
	resolvedSlowTraceDir := *slowTraceDir
	if resolvedSlowTraceDir == "" {
		resolvedSlowTraceDir = filepath.Join(*workdir, "slow-traces")
	}
	if resolvedSlowTraceDir == "-" {
		resolvedSlowTraceDir = ""
	}
	defer vm.close()
	if *standalone {
		applyStandaloneHardTimeout(vm, *standaloneProgramTimeoutMs)
	}
	standaloneCollectCover := !*standaloneNoCover
	ctx := context.Background()
	if err := vm.start(ctx); err != nil {
		vm.close()
		log.Fatalf("failed to start Nyx VM: %v", err)
	}
	if *standalone {
		if *standaloneStagedExecProgram != "" {
			if err := runStandaloneExecStaged(index, vm, *standaloneExecProgramPath, *standaloneStagedExecProgram, *standaloneThreaded,
				*standaloneKeepState, standaloneCollectCover, *standaloneSyscallTimeoutMs, *standaloneProgramTimeoutMs, *standaloneStageDelayMs, *standaloneStageIdleMs, *coverageDebugStream); err != nil {
				logStandaloneFatal("standalone staged Nyx exec request failed: %v", err)
			}
			return
		}
		if *standaloneStagedProgram != "" {
			if err := runStandaloneStaged(index, vm, *standaloneProgramPath, *standaloneStagedProgram, *standaloneTargetProfile, *standaloneThreaded,
				*standaloneKeepState, standaloneCollectCover, *standaloneSyscallTimeoutMs, *standaloneProgramTimeoutMs, *standaloneStageDelayMs, *standaloneStageIdleMs, *coverageDebugStream); err != nil {
				logStandaloneFatal("standalone staged Nyx request failed: %v", err)
			}
			return
		}
		if *standaloneExecProgramPath != "" {
			if err := runStandaloneExec(index, vm, *standaloneExecProgramPath, *standaloneThreaded,
				*standaloneKeepState, standaloneCollectCover, *standaloneSyscallTimeoutMs, *standaloneProgramTimeoutMs, *standaloneRounds, *coverageDebugStream); err != nil {
				logStandaloneFatal("standalone Nyx exec request failed: %v", err)
			}
			return
		}
		if err := runStandalone(index, vm, *standaloneSyscall, *standaloneSeed, *standaloneProgramPath, *standaloneTargetProfile, *standaloneThreaded,
			*standaloneKeepState, standaloneCollectCover, *standaloneFixedRepeat, *standaloneSyscallTimeoutMs, *standaloneProgramTimeoutMs, *standaloneRounds, *coverageDebugStream); err != nil {
			logStandaloneFatal("standalone Nyx request failed: %v", err)
		}
		return
	}
	r := newRunner(index, flag.Arg(1), flag.Arg(2), vm)
	r.keepState = *keepState
	r.coverageDebugPath = *coverageDebugStream
	r.slowTrace = &slowTraceConfig{
		dir:       resolvedSlowTraceDir,
		threshold: time.Duration(*slowTraceThresholdMs) * time.Millisecond,
		maxEvents: *slowTraceMaxEvents,
	}
	if err := connectWithRetry(r, 30*time.Second); err != nil {
		vm.close()
		log.Fatalf("failed to connect to manager: %v", err)
	}
	for {
		if err := r.loop(); err != nil {
			vm.close()
			log.Fatalf("runner loop failed: %v", err)
		}
		log.Logf(0, "runner manager connection closed; reconnecting after %s", nyxManagerReconnectBackoff)
		r.resetForReconnect()
		time.Sleep(nyxManagerReconnectBackoff)
		if err := connectWithRetry(r, 30*time.Second); err != nil {
			log.Logf(0, "runner reconnect window expired, exiting: %v", err)
			return
		}
	}
}

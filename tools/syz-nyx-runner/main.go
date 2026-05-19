// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"golang.org/x/sys/unix"
)

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

	nyxHandshakeAck = "syz_nyx_handshake.ok"
	nyxExecResult   = "syz_nyx_result.bin"
	nyxPageSize     = 0x1000
)

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, " ")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func reorderArgsForFlags(args []string) []string {
	takesValue := map[string]bool{
		"-qemu-path":                      true,
		"-image":                          true,
		"-workdir":                        true,
		"-payload-size":                   true,
		"-bitmap-size":                    true,
		"-memory":                         true,
		"-hard-timeout":                   true,
		"-standalone-syscall":             true,
		"-standalone-seed":                true,
		"-standalone-rounds":              true,
		"-standalone-syscall-timeout-ms":  true,
		"-standalone-program-timeout-ms":  true,
		"-vv":                             true,
		"-qemu-arg":                       true,
		"--qemu-path":                     true,
		"--image":                         true,
		"--workdir":                       true,
		"--payload-size":                  true,
		"--bitmap-size":                   true,
		"--memory":                        true,
		"--hard-timeout":                  true,
		"--standalone-syscall":            true,
		"--standalone-seed":               true,
		"--standalone-rounds":             true,
		"--standalone-syscall-timeout-ms": true,
		"--standalone-program-timeout-ms": true,
		"--vv":                            true,
		"--qemu-arg":                      true,
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
	Reserved  int32
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

func (a *qemuAux) pageFault() bool {
	return a.data[nyxResultPageFaultOff] != 0
}

func (a *qemuAux) pageAddr() uint64 {
	return binary.LittleEndian.Uint64(a.data[nyxResultPageAddrOff : nyxResultPageAddrOff+8])
}

func (a *qemuAux) misc() []byte {
	mlen := binary.LittleEndian.Uint16(a.data[nyxMiscOffset : nyxMiscOffset+2])
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

type nyxVM struct {
	index       int
	workdir     string
	dumpDir     string
	controlPath string
	auxPath     string
	bitmapPath  string
	payloadPath string
	ijonPath    string
	coverPath   string
	snapshotDir string

	payloadSize int
	bitmapSize  int

	qemuPath    string
	qemuArgs    []string
	image       string
	memoryMB    int
	debug       bool
	hardTimeout time.Duration

	ctx         context.Context
	payloadFile *os.File
	payloadMM   []byte
	auxFile     *os.File
	auxMM       []byte
	control     net.Conn
	aux         *qemuAux
	process     *exec.Cmd
}

func newNyxVM(index int, workdir, qemuPath string, qemuArgs []string, image string, memoryMB int, payloadSize, bitmapSize int, debug bool, hardTimeout time.Duration) *nyxVM {
	payloadSize = alignUp(payloadSize, nyxPageSize)
	return &nyxVM{
		index:       index,
		workdir:     workdir,
		dumpDir:     filepath.Join(workdir, "dump"),
		controlPath: filepath.Join(workdir, fmt.Sprintf("interface_%d", index)),
		auxPath:     filepath.Join(workdir, fmt.Sprintf("aux_buffer_%d", index)),
		bitmapPath:  filepath.Join(workdir, fmt.Sprintf("bitmap_%d", index)),
		payloadPath: filepath.Join(workdir, fmt.Sprintf("payload_%d", index)),
		ijonPath:    filepath.Join(workdir, fmt.Sprintf("ijon_%d", index)),
		coverPath:   filepath.Join(workdir, fmt.Sprintf("syz_cov_%d.bin", index)),
		snapshotDir: filepath.Join(workdir, "snapshot"),
		payloadSize: payloadSize,
		bitmapSize:  bitmapSize,
		qemuPath:    qemuPath,
		qemuArgs:    qemuArgs,
		image:       image,
		memoryMB:    memoryMB,
		debug:       debug,
		hardTimeout: hardTimeout,
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
	if err := os.MkdirAll(vm.workdir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(vm.dumpDir, 0o755); err != nil {
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

	args := append([]string{}, vm.qemuArgs...)
	if vm.image != "" {
		args = append(args, "-drive", qemuImageDriveArg(vm.image))
	}
	if vm.memoryMB > 0 {
		args = append(args, "-m", fmt.Sprint(vm.memoryMB))
	}
	args = append(args,
		"-chardev", fmt.Sprintf("socket,server,id=nyx_socket,path=%s", vm.controlPath),
		"-device", fmt.Sprintf("nyx,chardev=nyx_socket,workdir=%s,worker_id=%d,bitmap_size=%d,input_buffer_size=%d",
			vm.workdir, vm.index, vm.bitmapSize, vm.payloadSize),
		"-fast_vm_reload", fmt.Sprintf("path=%s,load=off", vm.snapshotDir),
	)
	vm.process = exec.CommandContext(ctx, vm.qemuPath, args...)
	if vm.debug {
		vm.process.Stdout = os.Stdout
		vm.process.Stderr = os.Stderr
	}
	if err := vm.process.Start(); err != nil {
		return err
	}
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
	lastState := vm.aux.state()
	lastReport := time.Now()
	for vm.aux.state() != 3 {
		if err := vm.stepUntilReady(); err != nil {
			return err
		}
		if vm.aux.state() != lastState || time.Since(lastReport) > 10*time.Second {
			log.Logf(0, "nyx init state=%d exec_code=%d misc=%q",
				vm.aux.state(), vm.aux.execCode(), strings.TrimSpace(string(vm.aux.misc())))
			lastState = vm.aux.state()
			lastReport = time.Now()
		}
	}
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

func (vm *nyxVM) stepUntilReady() error {
	if err := vm.runQemu(); err != nil {
		return err
	}
	switch vm.aux.execCode() {
	case nyxRCHprintf:
		log.Logf(0, "nyx hprintf: %s", string(vm.aux.misc()))
	case nyxRCAbort:
		return fmt.Errorf("guest abort during init: %s", string(vm.aux.misc()))
	}
	return nil
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
		_ = vm.process.Process.Kill()
		_ = vm.process.Wait()
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
	if _, err := vm.control.Write([]byte{nyxInterfacePing}); err != nil {
		return err
	}
	var ack [1]byte
	_, err := vm.control.Read(ack[:])
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

func (vm *nyxVM) executeHandshake(payload []byte) error {
	_ = os.Remove(filepath.Join(vm.dumpDir, nyxHandshakeAck))
	vm.aux.clearTransientResult()
	if err := vm.setPayload(payload); err != nil {
		return err
	}
	for i := 0; i < 16; i++ {
		log.Logf(0, "runner handshake step=%d state=%d exec_done=%v exec_code=%d misc=%q",
			i, vm.aux.state(), vm.aux.execDone(), vm.aux.execCode(),
			strings.TrimSpace(string(vm.aux.misc())))
		if err := vm.runQemu(); err != nil {
			return err
		}
		if data, err := os.ReadFile(filepath.Join(vm.dumpDir, nyxHandshakeAck)); err == nil && bytes.Equal(data, []byte("ok")) {
			log.Logf(0, "runner handshake ack observed at step=%d", i)
			return nil
		}
		log.Logf(0, "runner handshake post-step=%d state=%d exec_done=%v exec_code=%d misc=%q",
			i, vm.aux.state(), vm.aux.execDone(), vm.aux.execCode(),
			strings.TrimSpace(string(vm.aux.misc())))
		switch vm.aux.execCode() {
		case nyxRCHprintf:
			log.Logf(0, "nyx hprintf: %s", string(vm.aux.misc()))
		case nyxRCAbort:
			return fmt.Errorf("guest abort during handshake: %s", string(vm.aux.misc()))
		}
	}
	return errors.New("timed out waiting for nyx handshake ack")
}

func (vm *nyxVM) executeRequest(payload []byte, req *flatrpc.ExecRequest) (*flatrpc.ExecutorMessage, error) {
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
			log.Logf(0, "runner exec result observed before step=%d", steps)
			return parseExecResult(data)
		}
		if time.Now().After(deadline) {
			log.Logf(0, "runner exec wait deadline expired after %d steps; synthesizing hanged result", steps)
			return synthesizeHangedResult(req), nil
		}
		log.Logf(0, "runner exec step=%d state=%d exec_done=%v exec_code=%d misc=%q",
			steps, vm.aux.state(), vm.aux.execDone(), vm.aux.execCode(),
			strings.TrimSpace(string(vm.aux.misc())))
		if err := vm.runQemu(); err != nil {
			return nil, err
		}
		steps++
		log.Logf(0, "runner exec post-step=%d state=%d exec_done=%v exec_code=%d misc=%q",
			steps, vm.aux.state(), vm.aux.execDone(), vm.aux.execCode(),
			strings.TrimSpace(string(vm.aux.misc())))
		if vm.aux.pageFault() {
			vm.aux.dumpPage(vm.aux.pageAddr())
			continue
		}
		switch vm.aux.execCode() {
		case nyxRCHprintf:
			log.Logf(0, "nyx hprintf: %s", string(vm.aux.misc()))
			continue
		case nyxRCTimeout:
			log.Logf(0, "runner exec timeout at step=%d; synthesizing hanged result", steps)
			return synthesizeHangedResult(req), nil
		case nyxRCAbort:
			return nil, fmt.Errorf("guest abort: %s", string(vm.aux.misc()))
		}
		if vm.aux.execDone() {
			log.Logf(0, "runner exec observed exec_done at step=%d but result file is not present yet", steps)
		}
	}
}

func (vm *nyxVM) execWaitTimeout() time.Duration {
	timeout := vm.hardTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	return timeout + 5*time.Second
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
		pcs := filterCoveragePCs(rec.PCs, kernel64Bit)
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
					Pc:      comp.Pc,
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

type runner struct {
	id             int
	addr           string
	port           string
	vm             *nyxVM
	conn           *flatrpc.Conn
	connectReply   *flatrpc.ConnectReply
	handshakeReady bool
	coveragePrimed bool
	lastEnvFlags   flatrpc.ExecEnv
	lastSandboxArg int64
	needRestart    bool
}

func newRunner(id int, addr, port string, vm *nyxVM) *runner {
	return &runner{id: id, addr: addr, port: port, vm: vm}
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
}

func (r *runner) connect() error {
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
		Cookie: authHash(hello.Cookie),
		Id:     int64(r.id),
		Arch:   "windows/amd64",
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
	if err := flatrpc.Send(r.conn, &flatrpc.InfoRequest{}); err != nil {
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
	log.Logf(0, "runner sending handshake: raw_env=0x%x normalized_env=0x%x sandbox_arg=%d",
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
	if err := r.vm.executeHandshake(packNyxPayload(nyxKindHandshake, nil, packFlatbuffer(msg))); err != nil {
		return err
	}
	log.Logf(0, "runner handshake complete")
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

func (r *runner) restartVM(reason string) error {
	log.Logf(0, "runner restarting VM: %s", reason)
	if err := r.vm.restart(); err != nil {
		return err
	}
	r.handshakeReady = false
	r.coveragePrimed = false
	r.lastEnvFlags = 0
	r.lastSandboxArg = 0
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
	log.Logf(0, "%s request: id=%d prog_calls=%d flags=0x%x effective_flags=0x%x all_signal=%v",
		requestLabel, req.Id, progExecCallCountOrPanic(req.Data), req.ExecOpts.ExecFlags, execFlags, req.AllSignal)
	log.Logf(0, "%s program: id=%d %s", requestLabel, req.Id, describeExecProgram(req.Data))

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
	body := &flatrpc.SnapshotRequestT{
		ExecFlags:      execFlags,
		NumCalls:       int32(progExecCallCountOrPanic(req.Data)),
		AllCallSignal:  allCallSignal(req.AllSignal),
		AllExtraSignal: hasExtraSignal(req.AllSignal),
		ProgData:       req.Data,
	}
	execMsg, err := r.vm.executeRequest(packNyxPayload(nyxKindExec, meta, packFlatbuffer(body)), req)
	if err != nil {
		r.markForRestart(fmt.Sprintf("request %d failed: %v", req.Id, err))
		return nil, err
	}
	covRecords, compRecords, covErr := parseCoverageDump(r.vm.coverPath)
	if covErr == nil {
		covErr = injectCoverage(req, execMsg, r.connectReply.CoverEdges,
			r.connectReply.Kernel64Bit, covRecords, compRecords)
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
		r.markForRestart(fmt.Sprintf("request %d hanged", req.Id))
	}
	if res, ok := execMsg.Msg.Value.(*flatrpc.ExecResult); ok && res.Info != nil {
		log.Logf(0, "%s complete: id=%d calls=%d cover_records=%d",
			requestLabel, req.Id, len(res.Info.Calls), countNonEmptyCover(res.Info.Calls))
	}
	return execMsg, nil
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
		if execResultHasCoverage(primeMsg) {
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
			log.Logf(0, "runner received ExecRequest id=%d type=%v", req.Id, req.Type)
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
				execMsg = &flatrpc.ExecutorMessage{
					Msg: &flatrpc.ExecutorMessages{
						Type: flatrpc.ExecutorMessagesRawExecResult,
						Value: &flatrpc.ExecResult{
							Id:    req.Id,
							Proc:  0,
							Error: err.Error(),
							Info:  flatrpc.EmptyProgInfo(progExecCallCountOrPanic(req.Data)),
						},
					},
				}
			}
			if err := flatrpc.Send(r.conn, execMsg); err != nil {
				if isExpectedManagerDisconnect(err) {
					log.Logf(0, "runner stopping after manager disconnect during ExecResult reply: %v", err)
					return nil
				}
				return err
			}
		case *flatrpc.StateRequest:
			log.Logf(0, "runner received StateRequest")
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
			log.Logf(0, "runner received SignalUpdate")
		case *flatrpc.CorpusTriaged:
			log.Logf(0, "runner received CorpusTriaged")
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

func runStandalone(index int, vm *nyxVM, syscallName string, seed int64, threaded bool,
	syscallTimeoutMs, programTimeoutMs, rounds int) error {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		return fmt.Errorf("get target: %w", err)
	}
	meta := target.SyscallMap[syscallName]
	if meta == nil {
		return fmt.Errorf("unknown syscall %q", syscallName)
	}
	p, bootstrap, err := standaloneProgram(target, meta, seed)
	if err != nil {
		return err
	}
	enabled := standaloneEnabledCalls(target, meta)
	ct := target.BuildChoiceTable(nil, enabled)
	connectReply := &flatrpc.ConnectReply{
		Cover:            true,
		CoverEdges:       true,
		Kernel64Bit:      true,
		Procs:            1,
		Slowdown:         1,
		SyscallTimeoutMs: int32(syscallTimeoutMs),
		ProgramTimeoutMs: int32(programTimeoutMs),
	}
	execFlags := flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagDedupCover
	if threaded {
		execFlags |= flatrpc.ExecFlagThreaded
	}
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
		id:           index,
		vm:           vm,
		connectReply: connectReply,
	}
	if rounds <= 0 {
		rounds = 1
	}
	corpus := []*prog.Prog{p.Clone()}
	seenSignal := make(map[uint64]struct{})
	for round := 0; round < rounds; round++ {
		var cur *prog.Prog
		roundSeed := seed + int64(round)
		if round == 0 {
			cur = p.Clone()
			if bootstrap {
				log.Logf(0, "standalone bootstrap program for %s:\n%s", syscallName, string(cur.Serialize()))
			} else {
				log.Logf(0, "standalone seed program for %s (seed=%d):\n%s", syscallName, seed, string(cur.Serialize()))
			}
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
		log.Logf(0, "standalone exec encoding round=%d: bytes=%d calls=%d", round+1, len(execData), execCalls)
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
				"NtDelayExecution(0x0, &(0x7f0000002040)=0xfffffffffff85ee0) (async)\n" +
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
	for attempts := 0; attempts < 32; attempts++ {
		p := target.Generate(mrand.NewSource(seed+int64(attempts)), 1, ct)
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
	case "NtFsControlFile", "NtReadFile", "NtWriteFile", "TransmitFile$inet_accept":
		return true
	}
	return false
}

func standaloneFileHandleProgram(name string) ([]byte, error) {
	switch name {
	case "NtFsControlFile":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtFsControlFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)='\\x00'/128, 0x9c040, &(0x7f0000000200)='\\x00'/512, 0x200)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtReadFile":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-read\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtReadFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)='\\x00'/128, &(0x7f0000000200)='\\x00'/256, 0x100, 0x0, 0x0)\n" +
				"CloseHandle(r0)\n"), nil
	case "NtWriteFile":
		return []byte(
			"r0 = CreateFileA(&(0x7f0000000000)='./nyx-write\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
				"NtWriteFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)='\\x00'/128, &(0x7f0000000200)=\"abcd\", 0x4, 0x0, 0x0)\n" +
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
	default:
		return nil, fmt.Errorf("unsupported file-handle standalone syscall %q", name)
	}
}

func main() {
	os.Args = append([]string{os.Args[0]}, reorderArgsForFlags(os.Args[1:])...)

	var qemuArgs multiFlag
	var (
		qemuPath                   = flag.String("qemu-path", "", "qemu binary path")
		image                      = flag.String("image", "", "boot image path")
		workdir                    = flag.String("workdir", "", "nyx runner workdir")
		purge                      = flag.Bool("purge", false, "remove the existing workdir before starting")
		hardTimeout                = flag.Duration("hard-timeout", 3*time.Minute, "Nyx/KVM hard timeout fallback (max 255s)")
		payloadSize                = flag.Int("payload-size", int(flatrpc.ConstMaxInputSize)+4, "nyx payload buffer size")
		bitmapSize                 = flag.Int("bitmap-size", 0x10000, "nyx bitmap size")
		memoryMB                   = flag.Int("memory", 2048, "guest memory size in MB")
		debug                      = flag.Bool("debug", false, "inherit qemu stdout/stderr")
		standalone                 = flag.Bool("standalone", false, "run a local Nyx executor request without syz-manager")
		standaloneSyscall          = flag.String("standalone-syscall", "NtQuerySystemInformation", "Windows syscall name for standalone mode")
		standaloneSeed             = flag.Int64("standalone-seed", 1, "program generation seed for standalone mode")
		standaloneRounds           = flag.Int("standalone-rounds", 1, "number of standalone exec rounds; rounds>1 mutate accepted programs with syzkaller's mutator")
		standaloneSyscallTimeoutMs = flag.Int("standalone-syscall-timeout-ms", 20000, "standalone executor syscall timeout in ms")
		standaloneProgramTimeoutMs = flag.Int("standalone-program-timeout-ms", 60000, "standalone executor program timeout in ms")
		standaloneThreaded         = flag.Bool("standalone-threaded", true, "set ExecFlagThreaded in standalone mode")
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
	vm := newNyxVM(index, *workdir, *qemuPath, qemuArgs, *image, *memoryMB, *payloadSize, *bitmapSize, *debug, *hardTimeout)
	defer vm.close()
	ctx := context.Background()
	if err := vm.start(ctx); err != nil {
		log.Fatalf("failed to start Nyx VM: %v", err)
	}
	if *standalone {
		if err := runStandalone(index, vm, *standaloneSyscall, *standaloneSeed, *standaloneThreaded,
			*standaloneSyscallTimeoutMs, *standaloneProgramTimeoutMs, *standaloneRounds); err != nil {
			log.Fatalf("standalone Nyx request failed: %v", err)
		}
		return
	}
	r := newRunner(index, flag.Arg(1), flag.Arg(2), vm)
	if err := connectWithRetry(r, 30*time.Second); err != nil {
		log.Fatalf("failed to connect to manager: %v", err)
	}
	for {
		if err := r.loop(); err != nil {
			log.Fatalf("runner loop failed: %v", err)
		}
		log.Logf(0, "runner manager connection closed; attempting reconnect")
		r.resetForReconnect()
		if err := connectWithRetry(r, 30*time.Second); err != nil {
			log.Logf(0, "runner reconnect window expired, exiting: %v", err)
			return
		}
	}
}

// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
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
)

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, " ")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
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

	qemuPath string
	qemuArgs []string
	image    string
	memoryMB int
	debug    bool

	payloadFile *os.File
	payloadMM   []byte
	control     net.Conn
	aux         *qemuAux
	process     *exec.Cmd
}

func newNyxVM(index int, workdir, qemuPath string, qemuArgs []string, image string, memoryMB int, payloadSize, bitmapSize int, debug bool) *nyxVM {
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
	}
}

func (vm *nyxVM) start(ctx context.Context) error {
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
		args = append(args, "-drive", "file="+vm.image)
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
	vm.aux, err = openAux(vm.auxPath)
	if err != nil {
		return err
	}
	for vm.aux.state() != 3 {
		if err := vm.stepUntilReady(); err != nil {
			return err
		}
	}
	vm.aux.setTimeout(30 * time.Second)
	return nil
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
	}
	if vm.control != nil {
		_ = vm.control.Close()
	}
	if vm.payloadMM != nil {
		_ = unix.Munmap(vm.payloadMM)
	}
	if vm.payloadFile != nil {
		_ = vm.payloadFile.Close()
	}
	if vm.process != nil && vm.process.Process != nil {
		_ = vm.process.Process.Kill()
		_ = vm.process.Wait()
	}
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
	if err := vm.setPayload(payload); err != nil {
		return err
	}
	for i := 0; i < 16; i++ {
		if err := vm.runQemu(); err != nil {
			return err
		}
		if data, err := os.ReadFile(filepath.Join(vm.dumpDir, nyxHandshakeAck)); err == nil && bytes.Equal(data, []byte("ok")) {
			return nil
		}
		switch vm.aux.execCode() {
		case nyxRCHprintf:
			log.Logf(0, "nyx hprintf: %s", string(vm.aux.misc()))
		case nyxRCAbort:
			return fmt.Errorf("guest abort during handshake: %s", string(vm.aux.misc()))
		}
	}
	return errors.New("timed out waiting for nyx handshake ack")
}

func (vm *nyxVM) executeRequest(payload []byte) (*flatrpc.ExecutorMessage, error) {
	_ = os.Remove(filepath.Join(vm.dumpDir, nyxExecResult))
	_ = os.Remove(vm.coverPath)
	if err := vm.setPayload(payload); err != nil {
		return nil, err
	}
	for {
		if err := vm.runQemu(); err != nil {
			return nil, err
		}
		if vm.aux.pageFault() {
			vm.aux.dumpPage(vm.aux.pageAddr())
			continue
		}
		switch vm.aux.execCode() {
		case nyxRCHprintf:
			log.Logf(0, "nyx hprintf: %s", string(vm.aux.misc()))
			continue
		case nyxRCAbort:
			return nil, fmt.Errorf("guest abort: %s", string(vm.aux.misc()))
		}
		if vm.aux.execDone() {
			break
		}
	}
	data, err := os.ReadFile(filepath.Join(vm.dumpDir, nyxExecResult))
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, errors.New("short nyx exec result")
	}
	raw, err := flatrpc.Parse[*flatrpc.ExecutorMessageRaw](data[4:])
	if err != nil {
		return nil, err
	}
	return raw, nil
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

func injectCoverage(msg *flatrpc.ExecRequest, execMsg *flatrpc.ExecutorMessage, coverEdges bool, coverPath string) error {
	res, ok := execMsg.Msg.Value.(*flatrpc.ExecResult)
	if !ok || res.Info == nil || len(res.Info.Calls) == 0 {
		return nil
	}
	pcs, err := parseCoverageDump(coverPath)
	if err != nil {
		return err
	}
	call := res.Info.Calls[0]
	if msg.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover != 0 {
		call.Cover = append(call.Cover[:0], pcs...)
	}
	if msg.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal != 0 {
		call.Signal = append(call.Signal[:0], pcsToSignal(pcs, coverEdges)...)
	}
	return nil
}

func parseCoverageDump(path string) ([]uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < binary.Size(nyxCovHeader{}) {
		return nil, errors.New("short coverage dump")
	}
	var hdr nyxCovHeader
	if err := binary.Read(bytes.NewReader(data[:binary.Size(hdr)]), binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	if hdr.RecordCount == 0 {
		return nil, nil
	}
	off := binary.Size(hdr)
	var rec nyxCovRecord
	if err := binary.Read(bytes.NewReader(data[off:off+binary.Size(rec)]), binary.LittleEndian, &rec); err != nil {
		return nil, err
	}
	off += binary.Size(rec)
	pcs := make([]uint64, rec.PCCount)
	for i := range pcs {
		if off+8 > len(data) {
			return nil, errors.New("coverage body truncated")
		}
		pcs[i] = binary.LittleEndian.Uint64(data[off : off+8])
		off += 8
	}
	return pcs, nil
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

type runner struct {
	id             int
	addr           string
	port           string
	vm             *nyxVM
	conn           *flatrpc.Conn
	connectReply   *flatrpc.ConnectReply
	handshakeReady bool
	lastEnvFlags   flatrpc.ExecEnv
	lastSandboxArg int64
}

func newRunner(id int, addr, port string, vm *nyxVM) *runner {
	return &runner{id: id, addr: addr, port: port, vm: vm}
}

func (r *runner) connect() error {
	conn, err := net.Dial("tcp", net.JoinHostPort(r.addr, r.port))
	if err != nil {
		return err
	}
	r.conn = flatrpc.NewConn(conn)
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
	if err := flatrpc.Send(r.conn, &flatrpc.InfoRequest{}); err != nil {
		return err
	}
	_, err = flatrpc.Recv[*flatrpc.InfoReplyRaw](r.conn)
	return err
}

func (r *runner) ensureHandshake(req *flatrpc.ExecRequest) error {
	if r.handshakeReady && r.lastEnvFlags == req.ExecOpts.EnvFlags && r.lastSandboxArg == req.ExecOpts.SandboxArg {
		return nil
	}
	msg := &flatrpc.SnapshotHandshakeT{
		CoverEdges:       r.connectReply.CoverEdges,
		Kernel64Bit:      r.connectReply.Kernel64Bit,
		Slowdown:         r.connectReply.Slowdown,
		SyscallTimeoutMs: r.connectReply.SyscallTimeoutMs,
		ProgramTimeoutMs: r.connectReply.ProgramTimeoutMs,
		Features:         r.connectReply.Features,
		EnvFlags:         req.ExecOpts.EnvFlags,
		SandboxArg:       req.ExecOpts.SandboxArg,
	}
	if err := r.vm.executeHandshake(packNyxPayload(nyxKindHandshake, nil, packFlatbuffer(msg))); err != nil {
		return err
	}
	r.handshakeReady = true
	r.lastEnvFlags = req.ExecOpts.EnvFlags
	r.lastSandboxArg = req.ExecOpts.SandboxArg
	return nil
}

func (r *runner) runRequest(req *flatrpc.ExecRequest) (*flatrpc.ExecutorMessage, error) {
	if req.Type != flatrpc.RequestTypeProgram {
		return nil, fmt.Errorf("unsupported request type %v", req.Type)
	}
	if err := r.ensureHandshake(req); err != nil {
		return nil, err
	}
	meta := &nyxExecMeta{RequestID: req.Id, ProcID: 0}
	body := &flatrpc.SnapshotRequestT{
		ExecFlags:      req.ExecOpts.ExecFlags,
		NumCalls:       int32(progExecCallCountOrPanic(req.Data)),
		AllCallSignal:  allCallSignal(req.AllSignal),
		AllExtraSignal: hasExtraSignal(req.AllSignal),
		ProgData:       req.Data,
	}
	execMsg, err := r.vm.executeRequest(packNyxPayload(nyxKindExec, meta, packFlatbuffer(body)))
	if err != nil {
		return nil, err
	}
	if err := injectCoverage(req, execMsg, r.connectReply.CoverEdges, r.vm.coverPath); err != nil {
		return nil, err
	}
	return execMsg, nil
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

func (r *runner) loop() error {
	for {
		msg, err := flatrpc.Recv[*flatrpc.HostMessageRaw](r.conn)
		if err != nil {
			return err
		}
		switch req := msg.Msg.Value.(type) {
		case *flatrpc.ExecRequest:
			executing := &flatrpc.ExecutorMessage{
				Msg: &flatrpc.ExecutorMessages{
					Type:  flatrpc.ExecutorMessagesRawExecuting,
					Value: &flatrpc.ExecutingMessage{Id: req.Id, ProcId: 0, Try: 0},
				},
			}
			if err := flatrpc.Send(r.conn, executing); err != nil {
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
				return err
			}
		case *flatrpc.StateRequest:
			state := &flatrpc.ExecutorMessage{
				Msg: &flatrpc.ExecutorMessages{
					Type:  flatrpc.ExecutorMessagesRawState,
					Value: &flatrpc.StateResult{Data: []byte("syz-nyx-runner alive\n")},
				},
			}
			if err := flatrpc.Send(r.conn, state); err != nil {
				return err
			}
		case *flatrpc.SignalUpdate:
		case *flatrpc.CorpusTriaged:
		default:
			return fmt.Errorf("unhandled host message %T", req)
		}
	}
}

func main() {
	var qemuArgs multiFlag
	var (
		qemuPath    = flag.String("qemu-path", "", "qemu binary path")
		image       = flag.String("image", "", "boot image path")
		workdir     = flag.String("workdir", "", "nyx runner workdir")
		payloadSize = flag.Int("payload-size", int(flatrpc.ConstMaxInputSize)+4, "nyx payload buffer size")
		bitmapSize  = flag.Int("bitmap-size", 0x10000, "nyx bitmap size")
		memoryMB    = flag.Int("memory", 2048, "guest memory size in MB")
		debug       = flag.Bool("debug", false, "inherit qemu stdout/stderr")
	)
	flag.Var(&qemuArgs, "qemu-arg", "extra qemu argument (repeatable)")
	flag.Parse()
	if *qemuPath == "" || *workdir == "" || flag.NArg() != 3 {
		fmt.Fprintf(os.Stderr, "usage: syz-nyx-runner <index> <manager-addr> <manager-port> --qemu-path ... --workdir ... [--image ...] [--qemu-arg ...]\n")
		os.Exit(2)
	}
	index, err := strconv.Atoi(flag.Arg(0))
	if err != nil {
		log.Fatalf("bad index: %v", err)
	}
	vm := newNyxVM(index, *workdir, *qemuPath, qemuArgs, *image, *memoryMB, *payloadSize, *bitmapSize, *debug)
	defer vm.close()
	ctx := context.Background()
	if err := vm.start(ctx); err != nil {
		log.Fatalf("failed to start Nyx VM: %v", err)
	}
	r := newRunner(index, flag.Arg(1), flag.Arg(2), vm)
	if err := r.connect(); err != nil {
		log.Fatalf("failed to connect to manager: %v", err)
	}
	if err := r.loop(); err != nil {
		log.Fatalf("runner loop failed: %v", err)
	}
}

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
)

func writeCoverageDump(t *testing.T, path string, records []nyxCovDumpRecord) {
	t.Helper()
	buf := new(bytes.Buffer)
	hdr := nyxCovHeader{
		Magic:       nyxCovMagic,
		Version:     nyxCovVersion,
		RecordCount: uint32(len(records)),
	}
	if err := binary.Write(buf, binary.LittleEndian, &hdr); err != nil {
		t.Fatal(err)
	}
	for _, rec := range records {
		raw := nyxCovRecordV3{
			CallIndex:        rec.CallIndex,
			SlotID:           rec.SlotID,
			Flags:            rec.Flags,
			PCCount:          uint32(len(rec.PCs)),
			SessionID:        rec.SessionID,
			Tid:              rec.Tid,
			Teb:              rec.Teb,
			SourceID:         rec.SourceID,
			ChunkIndex:       rec.ChunkIndex,
			CPUMask:          rec.CPUMask,
			SourceGeneration: rec.SourceGeneration,
		}
		if err := binary.Write(buf, binary.LittleEndian, &raw); err != nil {
			t.Fatal(err)
		}
		for _, pc := range rec.PCs {
			if err := binary.Write(buf, binary.LittleEndian, pc); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func uint64SlicesEqual(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func TestTraceRecorderTail(t *testing.T) {
	rec := newTraceRecorder(3)
	rec.Add("runner", "begin", 1, nil)
	rec.Add("qemu", "kvm_run_begin", 1, nil)
	rec.Add("executor", "call_begin", 1, nil)
	rec.Add("qemu", "kvm_run_end", 1, nil)

	tail := rec.Tail("", 0)
	if len(tail) != 3 {
		t.Fatalf("tail len=%d want 3", len(tail))
	}
	if tail[0].Stage != "kvm_run_begin" || tail[1].Stage != "call_begin" || tail[2].Stage != "kvm_run_end" {
		t.Fatalf("bad ordered tail: %#v", tail)
	}
	qemuTail := rec.Tail("qemu", 0)
	if len(qemuTail) != 2 || qemuTail[0].Stage != "kvm_run_begin" || qemuTail[1].Stage != "kvm_run_end" {
		t.Fatalf("bad qemu tail: %#v", qemuTail)
	}
	limited := rec.Tail("", 2)
	if len(limited) != 2 || limited[0].Stage != "call_begin" || limited[1].Stage != "kvm_run_end" {
		t.Fatalf("bad limited tail: %#v", limited)
	}
}

func TestWriteSlowTraceArtifact(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	execData := serializeWindowsTestProgramForExec(t,
		filepath.Join("..", "..", "sys", "windows", "test", "nyx_afd_private_query_readonly.txt"))
	auxData := make([]byte, 4096)
	auxData[nyxStateOffset] = 3
	auxData[nyxResultExecCodeOffset] = nyxRCTimeout
	auxData[nyxResultReloadedOffset] = 1
	misc := []byte("nyx exec execute_one stage=execute_call_pre_acquire call_index=0 call_num=1 call_name=<none> a0=0x1\x00")
	binary.LittleEndian.PutUint16(auxData[nyxMiscOffset:nyxMiscOffset+2], uint16(len(misc)))
	copy(auxData[nyxMiscOffset+2:], misc)

	workdir := t.TempDir()
	vm := &nyxVM{
		workdir: workdir,
		aux:     &qemuAux{data: auxData},
		trace:   newTraceRecorder(8),
	}
	vm.recordTrace("runner", "request_begin", 42, nil)
	vm.recordTrace("qemu", "exec_timeout", 42, traceFields("exec_code", nyxRCTimeout))
	vm.recordHprintfTrace(42)
	if err := os.WriteFile(vm.qemuFlightPath(), []byte("{\"event\":\"pt_enable\"}\n{\"event\":\"reload_begin\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &runner{
		id:        3,
		vm:        vm,
		keepState: true,
		slowTrace: &slowTraceConfig{
			dir:       filepath.Join(workdir, "slow"),
			threshold: time.Millisecond,
			maxEvents: 8,
		},
	}
	req := &flatrpc.ExecRequest{
		Id:   42,
		Type: flatrpc.RequestTypeProgram,
		Data: execData,
		ExecOpts: &flatrpc.ExecOpts{
			ExecFlags:  flatrpc.ExecFlagThreaded | flatrpc.ExecFlagCollectCover,
			SandboxArg: 7,
		},
		AllSignal: []int32{0, -1},
	}
	artifactDir, err := r.writeSlowTraceArtifact(req, "runner exec", "hang",
		time.Now().Add(-2*time.Second), 2*time.Second, synthesizeHangedResult(req), nil)
	if err != nil {
		t.Fatalf("writeSlowTraceArtifact: %v", err)
	}
	for _, name := range []string{
		"metadata.json",
		"program.exec.bin",
		"program.txt",
		"result.json",
		"trace.jsonl",
		"qemu-trace.jsonl",
		"qemu-flight-tail.jsonl",
		"executor-trace.jsonl",
	} {
		if _, err := os.Stat(filepath.Join(artifactDir, name)); err != nil {
			t.Fatalf("missing artifact %s: %v", name, err)
		}
	}
	programData, err := os.ReadFile(filepath.Join(artifactDir, "program.exec.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(programData, execData) {
		t.Fatal("program.exec.bin does not match request data")
	}
	metaData, err := os.ReadFile(filepath.Join(artifactDir, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta slowTraceMetadata
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("metadata json: %v", err)
	}
	if meta.Reason != "hang" || meta.RequestID != 42 || !meta.KeepState || meta.DurationMS != 2000 {
		t.Fatalf("bad metadata: %#v", meta)
	}
	if meta.PreviousRequest != nil {
		t.Fatalf("exec artifact unexpectedly has previous request context: %#v", meta.PreviousRequest)
	}
	if meta.Aux["exec_code_name"] != nyxExitReason(nyxRCTimeout) {
		t.Fatalf("bad aux metadata: %#v", meta.Aux)
	}
	if meta.Diagnosis["category"] != "syscall" ||
		meta.Diagnosis["executor_stage"] != "execute_call_pre_acquire" ||
		meta.Diagnosis["executor_call_name"] != "<none>" {
		t.Fatalf("bad diagnosis: %#v", meta.Diagnosis)
	}
	executorTrace, err := os.ReadFile(filepath.Join(artifactDir, "executor-trace.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(executorTrace), "execute_call_pre_acquire") {
		t.Fatalf("executor trace missing stage: %s", executorTrace)
	}

	prevReq := cloneExecRequestForArtifact(req)
	prevReq.Id = 41
	r.lastCompletedReq = prevReq
	handshakeReq := cloneExecRequestForArtifact(req)
	handshakeReq.Id = 43
	handshakeDir, err := r.writeSlowTraceArtifact(handshakeReq, "runner handshake", "slow",
		time.Now().Add(-3*time.Second), 3*time.Second, nil, nil)
	if err != nil {
		t.Fatalf("write handshake slow trace artifact: %v", err)
	}
	for _, name := range []string{"previous-program.exec.bin", "previous-program.txt"} {
		if _, err := os.Stat(filepath.Join(handshakeDir, name)); err != nil {
			t.Fatalf("missing handshake related artifact %s: %v", name, err)
		}
	}
	metaData, err = os.ReadFile(filepath.Join(handshakeDir, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("handshake metadata json: %v", err)
	}
	if meta.PreviousRequest == nil || meta.PreviousRequest.RequestID != 41 {
		t.Fatalf("handshake artifact missing previous request context: %#v", meta.PreviousRequest)
	}
	if meta.Diagnosis["phase"] != "pre_request_handshake" ||
		meta.Diagnosis["previous_request_id"] != float64(41) {
		t.Fatalf("handshake diagnosis missing previous request attribution: %#v", meta.Diagnosis)
	}
}

func serializeWindowsTestProgramForExec(t *testing.T, path string) []byte {
	t.Helper()
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize %s: %v", path, err)
	}
	execData, err := p.SerializeForExec()
	if err != nil {
		t.Fatalf("SerializeForExec %s: %v", path, err)
	}
	return execData
}

func TestStandaloneExecProgramLoadsSerializedExec(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	execData := serializeWindowsTestProgramForExec(t,
		filepath.Join("..", "..", "sys", "windows", "test", "nyx_afd_private_query_readonly.txt"))
	path := filepath.Join(t.TempDir(), "program.exec.bin")
	if err := os.WriteFile(path, execData, 0o644); err != nil {
		t.Fatal(err)
	}
	got, label, err := standaloneExecProgram(path)
	if err != nil {
		t.Fatalf("standaloneExecProgram: %v", err)
	}
	if label != path {
		t.Fatalf("label=%q want %q", label, path)
	}
	if !bytes.Equal(got, execData) {
		t.Fatal("standaloneExecProgram changed exec data")
	}

	textPath := filepath.Join(t.TempDir(), "program.txt")
	if err := os.WriteFile(textPath, []byte("NtYieldExecution()\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := standaloneExecProgram(textPath); err == nil ||
		!strings.Contains(err.Error(), "deserialize standalone exec program") {
		t.Fatalf("standaloneExecProgram accepted text program: %v", err)
	}
}

func TestParseCoverageDumpMultipleRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syz_cov.bin")
	want := []nyxCovDumpRecord{
		{CallIndex: 0, SlotID: 0, Flags: 1, PCs: []uint64{0x11, 0x22}},
		{CallIndex: 2, SlotID: 1, Flags: 0, PCs: []uint64{0x33}},
	}
	writeCoverageDump(t, path, want)

	got, _, _, err := parseCoverageDump(path)
	if err != nil {
		t.Fatalf("parseCoverageDump failed: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].CallIndex != want[i].CallIndex || got[i].SlotID != want[i].SlotID || got[i].Flags != want[i].Flags {
			t.Fatalf("record %d metadata mismatch: got %+v want %+v", i, got[i], want[i])
		}
		if len(got[i].PCs) != len(want[i].PCs) {
			t.Fatalf("record %d pc count mismatch: got %d want %d", i, len(got[i].PCs), len(want[i].PCs))
		}
		for j := range want[i].PCs {
			if got[i].PCs[j] != want[i].PCs[j] {
				t.Fatalf("record %d pc %d mismatch: got 0x%x want 0x%x", i, j, got[i].PCs[j], want[i].PCs[j])
			}
		}
	}
}

func TestParseCoverageDumpV3Metadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syz_cov.bin")
	want := []nyxCovDumpRecord{
		{
			CallIndex:        1,
			SlotID:           2,
			Flags:            3,
			SessionID:        0x1234,
			Tid:              0x55,
			Teb:              0x6677,
			SourceID:         4,
			ChunkIndex:       5,
			CPUMask:          1 << 3,
			SourceGeneration: 9,
			PCs:              []uint64{0xaa, 0xbb},
		},
	}
	writeCoverageDump(t, path, want)

	got, _, _, err := parseCoverageDump(path)
	if err != nil {
		t.Fatalf("parseCoverageDump failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].CallIndex != want[0].CallIndex ||
		got[0].SlotID != want[0].SlotID ||
		got[0].Flags != want[0].Flags ||
		got[0].SessionID != want[0].SessionID ||
		got[0].Tid != want[0].Tid ||
		got[0].Teb != want[0].Teb ||
		got[0].SourceID != want[0].SourceID ||
		got[0].ChunkIndex != want[0].ChunkIndex ||
		got[0].CPUMask != want[0].CPUMask ||
		got[0].SourceGeneration != want[0].SourceGeneration {
		t.Fatalf("metadata mismatch: got %+v want %+v", got[0], want[0])
	}
	if !uint64SlicesEqual(got[0].PCs, want[0].PCs) {
		t.Fatalf("pcs mismatch: got %#v want %#v", got[0].PCs, want[0].PCs)
	}
}

func TestParseCoverageDumpV2Compatibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syz_cov_v2.bin")
	buf := new(bytes.Buffer)
	hdr := nyxCovHeader{
		Magic:       nyxCovMagic,
		Version:     2,
		RecordCount: 1,
	}
	rec := nyxCovRecord{
		CallIndex: 7,
		SlotID:    8,
		Flags:     9,
		PCCount:   1,
	}
	if err := binary.Write(buf, binary.LittleEndian, &hdr); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(buf, binary.LittleEndian, &rec); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(buf, binary.LittleEndian, uint64(0xdead)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(0)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	got, comps, _, err := parseCoverageDump(path)
	if err != nil {
		t.Fatalf("parseCoverageDump failed: %v", err)
	}
	if len(got) != 1 || len(comps) != 0 {
		t.Fatalf("got records=%d comps=%d, want records=1 comps=0", len(got), len(comps))
	}
	if got[0].CallIndex != rec.CallIndex || got[0].SlotID != rec.SlotID ||
		got[0].Flags != rec.Flags || !uint64SlicesEqual(got[0].PCs, []uint64{0xdead}) {
		t.Fatalf("v2 record mismatch: got %+v", got[0])
	}
	if got[0].SessionID != 0 || got[0].SourceID != 0 || got[0].CPUMask != 0 {
		t.Fatalf("v2 metadata should be zero: got %+v", got[0])
	}
}

func TestParseCoverageDumpRejectsBadMagic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syz_cov.bin")
	buf := new(bytes.Buffer)
	hdr := nyxCovHeader{Magic: 0x12345678, Version: nyxCovVersion, RecordCount: 0}
	if err := binary.Write(buf, binary.LittleEndian, &hdr); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := parseCoverageDump(path); err == nil {
		t.Fatal("parseCoverageDump unexpectedly succeeded on bad magic")
	}
}

func TestSynthesizeHangedResultPreservesRequest(t *testing.T) {
	var data [binary.MaxVarintLen64]byte
	n := binary.PutVarint(data[:], 2)
	req := &flatrpc.ExecRequest{
		Id:   42,
		Data: data[:n],
	}
	msg := synthesizeHangedResult(req)
	if msg.Msg.Type != flatrpc.ExecutorMessagesRawExecResult {
		t.Fatalf("message type=%v, want ExecResult", msg.Msg.Type)
	}
	res, ok := msg.Msg.Value.(*flatrpc.ExecResult)
	if !ok {
		t.Fatalf("message value has type %T", msg.Msg.Value)
	}
	if res.Id != req.Id || res.Proc != 0 || !res.Hanged {
		t.Fatalf("bad hanged result metadata: id=%d proc=%d hanged=%v", res.Id, res.Proc, res.Hanged)
	}
	if res.Info == nil || len(res.Info.Calls) != 2 {
		t.Fatalf("hanged result call info len=%d, want 2", len(res.Info.Calls))
	}
}

func TestSynthesizeErrorResultPreservesRequest(t *testing.T) {
	var data [binary.MaxVarintLen64]byte
	n := binary.PutVarint(data[:], 3)
	req := &flatrpc.ExecRequest{
		Id:   43,
		Data: data[:n],
	}
	msg := synthesizeErrorResult(req, errors.New("nyx crash: bugcheck"))
	if msg.Msg.Type != flatrpc.ExecutorMessagesRawExecResult {
		t.Fatalf("message type=%v, want ExecResult", msg.Msg.Type)
	}
	res, ok := msg.Msg.Value.(*flatrpc.ExecResult)
	if !ok {
		t.Fatalf("message value has type %T", msg.Msg.Value)
	}
	if res.Id != req.Id || res.Proc != 0 || res.Error != "nyx crash: bugcheck" || res.Hanged {
		t.Fatalf("bad error result metadata: id=%d proc=%d error=%q hanged=%v",
			res.Id, res.Proc, res.Error, res.Hanged)
	}
	if res.Info == nil || len(res.Info.Calls) != 3 {
		t.Fatalf("error result call info len=%d, want 3", len(res.Info.Calls))
	}
}

func TestPreserveWindowsDumpWaitsForStableFile(t *testing.T) {
	oldPoll := windowsDumpSettlePoll
	oldStableFor := windowsDumpSettleStableFor
	oldTimeout := windowsDumpSettleTimeout
	oldSamples := windowsDumpSettleStableSamples
	oldAttempts := windowsDumpCopyAttempts
	windowsDumpSettlePoll = 10 * time.Millisecond
	windowsDumpSettleStableFor = 120 * time.Millisecond
	windowsDumpSettleTimeout = time.Second
	windowsDumpSettleStableSamples = 3
	windowsDumpCopyAttempts = 1
	t.Cleanup(func() {
		windowsDumpSettlePoll = oldPoll
		windowsDumpSettleStableFor = oldStableFor
		windowsDumpSettleTimeout = oldTimeout
		windowsDumpSettleStableSamples = oldSamples
		windowsDumpCopyAttempts = oldAttempts
	})

	workdir := t.TempDir()
	vm := &nyxVM{
		index:   0,
		workdir: workdir,
		dumpDir: filepath.Join(workdir, "dump"),
	}
	if err := os.MkdirAll(vm.dumpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(vm.dumpDir, "worker_0_pending.dmp")
	first := bytes.Repeat([]byte("A"), 64)
	second := bytes.Repeat([]byte("B"), 64)
	if err := os.WriteFile(src, first, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(80 * time.Millisecond)
		f, err := os.OpenFile(src, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Errorf("open pending dump for append: %v", err)
			return
		}
		if _, err := f.Write(second); err != nil {
			t.Errorf("append pending dump: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Errorf("close pending dump: %v", err)
		}
	}()

	dump := vm.preserveWindowsDump("WINDOWS BUGCHECK DIRECT DUMP IO")
	<-done
	if dump.err != "" {
		t.Fatalf("preserveWindowsDump failed: %s", dump.err)
	}
	if dump.size != int64(len(first)+len(second)) {
		t.Fatalf("dump size=%d, want %d", dump.size, len(first)+len(second))
	}
	got, err := os.ReadFile(dump.storedPath)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{}, first...), second...)
	if !bytes.Equal(got, want) {
		t.Fatalf("stored dump mismatch: got %d bytes want %d", len(got), len(want))
	}
}

func TestInjectCoverageByCallIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syz_cov.bin")
	writeCoverageDump(t, path, []nyxCovDumpRecord{
		{CallIndex: 0, PCs: []uint64{0x10, 0x20}},
		{CallIndex: 2, PCs: []uint64{0x30, 0x40}},
	})

	req := &flatrpc.ExecRequest{
		ExecOpts: &flatrpc.ExecOpts{
			ExecFlags: flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal,
		},
	}
	res := &flatrpc.ExecResult{
		Info: flatrpc.EmptyProgInfo(3),
	}
	execMsg := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type:  flatrpc.ExecutorMessagesRawExecResult,
			Value: res,
		},
	}

	covRecords, _, _, err := parseCoverageDump(path)
	if err != nil {
		t.Fatalf("parseCoverageDump failed: %v", err)
	}
	if err := injectCoverage(req, execMsg, false, false, moduleRangeCanonicalizer{}, covRecords, nil); err != nil {
		t.Fatalf("injectCoverage failed: %v", err)
	}
	if got := res.Info.Calls[0].Cover; len(got) != 2 || got[0] != 0x10 || got[1] != 0x20 {
		t.Fatalf("call 0 cover mismatch: %#v", got)
	}
	if got := res.Info.Calls[2].Cover; len(got) != 2 || got[0] != 0x30 || got[1] != 0x40 {
		t.Fatalf("call 2 cover mismatch: %#v", got)
	}
	if got := res.Info.Calls[1].Cover; len(got) != 0 {
		t.Fatalf("call 1 unexpectedly has cover: %#v", got)
	}
	if got := res.Info.Calls[0].Signal; len(got) != 2 || got[0] != 0x10 || got[1] != 0x20 {
		t.Fatalf("call 0 signal mismatch: %#v", got)
	}
	if got := res.Info.Calls[2].Signal; len(got) != 2 || got[0] != 0x30 || got[1] != 0x40 {
		t.Fatalf("call 2 signal mismatch: %#v", got)
	}
}

func TestInjectCoverageInterleavedConcurrentRecords(t *testing.T) {
	req := &flatrpc.ExecRequest{
		ExecOpts: &flatrpc.ExecOpts{
			ExecFlags: flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal,
		},
	}
	res := &flatrpc.ExecResult{
		Info: flatrpc.EmptyProgInfo(3),
	}
	execMsg := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type:  flatrpc.ExecutorMessagesRawExecResult,
			Value: res,
		},
	}
	covRecords := []nyxCovDumpRecord{
		{CallIndex: 1, PCs: []uint64{0x101, 0x102}},
		{CallIndex: 0, PCs: []uint64{0x201}},
		{CallIndex: 1, PCs: []uint64{0x103}},
		{CallIndex: 2, PCs: []uint64{0x301, 0x302}},
	}

	if err := injectCoverage(req, execMsg, false, false, moduleRangeCanonicalizer{}, covRecords, nil); err != nil {
		t.Fatalf("injectCoverage failed: %v", err)
	}
	if want := []uint64{0x101, 0x102, 0x103}; !uint64SlicesEqual(res.Info.Calls[1].Cover, want) {
		t.Fatalf("call 1 cover mismatch: got %#v want %#v", res.Info.Calls[1].Cover, want)
	}
	if want := []uint64{0x201}; !uint64SlicesEqual(res.Info.Calls[0].Cover, want) {
		t.Fatalf("call 0 cover mismatch: got %#v want %#v", res.Info.Calls[0].Cover, want)
	}
	if want := []uint64{0x301, 0x302}; !uint64SlicesEqual(res.Info.Calls[2].Cover, want) {
		t.Fatalf("call 2 cover mismatch: got %#v want %#v", res.Info.Calls[2].Cover, want)
	}
}

func TestInjectCoverageDoesNotCreateCrossRecordEdges(t *testing.T) {
	req := &flatrpc.ExecRequest{
		ExecOpts: &flatrpc.ExecOpts{
			ExecFlags: flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal,
		},
	}
	res := &flatrpc.ExecResult{
		Info: flatrpc.EmptyProgInfo(1),
	}
	execMsg := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type:  flatrpc.ExecutorMessagesRawExecResult,
			Value: res,
		},
	}
	covRecords := []nyxCovDumpRecord{
		{CallIndex: 0, PCs: []uint64{0x1001, 0x2017}},
		{CallIndex: 0, PCs: []uint64{0x3033}},
	}
	if err := injectCoverage(req, execMsg, true, false, moduleRangeCanonicalizer{}, covRecords, nil); err != nil {
		t.Fatalf("injectCoverage failed: %v", err)
	}
	wantSignal := append(pcsToSignal(covRecords[0].PCs, true),
		pcsToSignal(covRecords[1].PCs, true)...)
	if !uint64SlicesEqual(res.Info.Calls[0].Signal, wantSignal) {
		t.Fatalf("signal mismatch: got %#v want %#v", res.Info.Calls[0].Signal, wantSignal)
	}
	crossRecordSignal := pcsToSignal([]uint64{0x1001, 0x2017, 0x3033}, true)
	if uint64SlicesEqual(res.Info.Calls[0].Signal, crossRecordSignal) {
		t.Fatalf("signal unexpectedly contains cross-record edge: %#v", res.Info.Calls[0].Signal)
	}
}

func TestInjectCoverageCanonicalizesRestartedModuleRanges(t *testing.T) {
	var canonicalizer moduleRangeCanonicalizer
	canonicalizer.Record([]moduleRuntimeRange{
		{SlotID: 2, Target: "afd.sys", Name: "afd.sys", Base: 0xfffff80600000000, End: 0xfffff80600002000},
	})
	canonicalizer.Record([]moduleRuntimeRange{
		{SlotID: 2, Target: "afd.sys", Name: "afd.sys", Base: 0xfffff80f10000000, End: 0xfffff80f10002000},
	})
	req := &flatrpc.ExecRequest{
		ExecOpts: &flatrpc.ExecOpts{
			ExecFlags: flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal,
		},
	}
	res := &flatrpc.ExecResult{
		Info: flatrpc.EmptyProgInfo(1),
	}
	execMsg := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type:  flatrpc.ExecutorMessagesRawExecResult,
			Value: res,
		},
	}
	covRecords := []nyxCovDumpRecord{
		{CallIndex: 0, SlotID: 2, PCs: []uint64{0xfffff80f10000100, 0xfffff80f10000120}},
	}
	if err := injectCoverage(req, execMsg, false, true, canonicalizer, covRecords, nil); err != nil {
		t.Fatalf("injectCoverage failed: %v", err)
	}
	want := []uint64{0xfffff80600000100, 0xfffff80600000120}
	if got := res.Info.Calls[0].Cover; !uint64SlicesEqual(got, want) {
		t.Fatalf("cover mismatch: got %#v want %#v", got, want)
	}
	if got := res.Info.Calls[0].Signal; !uint64SlicesEqual(got, want) {
		t.Fatalf("signal mismatch: got %#v want %#v", got, want)
	}
}

func TestSummarizeModuleCoverageBySlot(t *testing.T) {
	records := []nyxCovDumpRecord{
		{CallIndex: 0, SlotID: 2, PCs: []uint64{0xfffff80000001000, 0x7ff600001000}},
		{CallIndex: 1, SlotID: 1, PCs: []uint64{0xfffff80000002000}},
		{CallIndex: 2, SlotID: 2, PCs: []uint64{0xfffff80000003000, 0xfffff80000004000}},
		{CallIndex: 3, SlotID: 3, PCs: []uint64{0}},
	}
	got := summarizeModuleCoverageBySlot(records, true, nil)
	want := []moduleCoverageSlotSummary{
		{SlotID: 1, Records: 1, PCs: 1},
		{SlotID: 2, Records: 2, PCs: 3},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d mismatch: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestSummarizeModuleCoverageByRuntimeRanges(t *testing.T) {
	ranges := []moduleRuntimeRange{
		{SlotID: 0, Target: "ntoskrnl.exe", Name: "ntoskrnl.exe", Base: 0xfffff80000000000, End: 0xfffff80000002000},
		{SlotID: 2, Target: "afd.sys", Name: "afd.sys", Base: 0xfffff80600000000, End: 0xfffff80600002000},
	}
	records := []nyxCovDumpRecord{
		{CallIndex: 0, SlotID: 0, PCs: []uint64{0xfffff80000001000, 0xfffff80600001000, 0x7ff600001000}},
		{CallIndex: 1, SlotID: 0, PCs: []uint64{0xfffff80600001100, 0xfffff80600001200}},
	}
	got := summarizeModuleCoverageBySlot(records, true, ranges)
	want := []moduleCoverageSlotSummary{
		{SlotID: 0, Records: 1, PCs: 1},
		{SlotID: 2, Records: 2, PCs: 3},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d mismatch: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestSummarizeModuleCoverageByCall(t *testing.T) {
	ranges := []moduleRuntimeRange{
		{SlotID: 0, Target: "ntoskrnl.exe", Name: "ntoskrnl.exe", Base: 0xfffff80000000000, End: 0xfffff80000002000},
		{SlotID: 2, Target: "afd.sys", Name: "afd.sys", Base: 0xfffff80600000000, End: 0xfffff80600002000},
	}
	records := []nyxCovDumpRecord{
		{CallIndex: 0, SlotID: 0, PCs: []uint64{0xfffff80000001000, 0xfffff80600001000}},
		{CallIndex: 1, SlotID: 0, PCs: []uint64{0xfffff80600001100, 0xfffff80600001200}},
	}
	got := summarizeModuleCoverageByCall(records, true, ranges, []string{"accept$inet_tcp", "WSARecv$accept"})
	want := []moduleCoverageCallSummary{
		{CallIndex: 0, SlotID: 0, CallName: "accept$inet_tcp", Records: 1, PCs: 1},
		{CallIndex: 0, SlotID: 2, CallName: "accept$inet_tcp", Records: 1, PCs: 1},
		{CallIndex: 1, SlotID: 2, CallName: "WSARecv$accept", Records: 1, PCs: 2},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d mismatch: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestCoverageDebugStreamUsesCanonicalModuleOffsets(t *testing.T) {
	var canonicalizer moduleRangeCanonicalizer
	canonicalizer.Record([]moduleRuntimeRange{
		{SlotID: 2, Target: "afd.sys", Name: "afd.sys", Base: 0xfffff80600000000, End: 0xfffff80600002000},
	})
	canonicalizer.Record([]moduleRuntimeRange{
		{SlotID: 2, Target: "afd.sys", Name: "afd.sys", Base: 0xfffff80f10000000, End: 0xfffff80f10002000},
	})
	event := buildCoverageDebugStreamEvent(7, nil, []nyxCovDumpRecord{{
		CallIndex: 0,
		SlotID:    2,
		PCs:       []uint64{0xfffff80f10000100},
	}}, true, canonicalizer)
	if len(event.Calls) != 1 {
		t.Fatalf("debug calls=%d want 1: %+v", len(event.Calls), event.Calls)
	}
	call := event.Calls[0]
	if call.Module != "afd.sys" || call.SlotID != 2 {
		t.Fatalf("bad debug module row: %+v", call)
	}
	if got, want := strings.Join(call.PCs, ","), "0xfffff80600000100"; got != want {
		t.Fatalf("debug pcs=%s want %s", got, want)
	}
	if got, want := strings.Join(call.Offsets, ","), "0x100"; got != want {
		t.Fatalf("debug offsets=%s want %s", got, want)
	}

	path := filepath.Join(t.TempDir(), "coverage.jsonl")
	if err := appendCoverageDebugStream(path, event); err != nil {
		t.Fatalf("appendCoverageDebugStream: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded coverageDebugStreamEvent
	if err := json.Unmarshal(bytes.TrimSpace(data), &decoded); err != nil {
		t.Fatalf("decode JSONL: %v", err)
	}
	if decoded.RequestID != 7 || len(decoded.Calls) != 1 {
		t.Fatalf("bad decoded event: %+v", decoded)
	}
}

func TestSummarizeCallFeedback(t *testing.T) {
	calls := []*flatrpc.CallInfo{
		{Signal: []uint64{1, 2}, Cover: []uint64{3, 4, 5}, Error: 0},
		nil,
		{Comps: []*flatrpc.Comparison{{Pc: 1}}, Error: 22},
	}
	got := summarizeCallFeedback(calls, []string{"accept$inet_tcp", "recv$inet_accept", "WSARecv$accept"})
	want := []callFeedbackSummary{
		{CallIndex: 0, CallName: "accept$inet_tcp", Signal: 2, Cover: 3},
		{CallIndex: 2, CallName: "WSARecv$accept", Comps: 1, Error: 22},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d mismatch: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestParseModuleRangesFromAux(t *testing.T) {
	got := parseModuleRangesFromAux(strings.Join([]string{
		"nyx module range submitted slot=0 target=ntoskrnl.exe name=ntoskrnl.exe base=0xfffff80000000000 end=0xfffff80000002000 size=0x2000",
		"nyx module range submitted slot=2 target=afd.sys name=afd.sys base=0xfffff80600000000 end=0xfffff80600001000 size=0x1000",
	}, "\n"))
	if len(got) != 2 {
		t.Fatalf("got %d ranges, want 2: %+v", len(got), got)
	}
	if got[1].SlotID != 2 || got[1].Target != "afd.sys" ||
		got[1].Base != 0xfffff80600000000 || got[1].End != 0xfffff80600001000 {
		t.Fatalf("unexpected afd range: %+v", got[1])
	}
}

func TestNyxModuleInfoFiles(t *testing.T) {
	files := nyxModuleInfoFiles([]moduleRuntimeRange{
		{SlotID: 2, Target: "afd.sys", Name: "afd.sys", Base: 0xfffff80600000000, End: 0xfffff80600001000},
	})
	if len(files) != 1 {
		t.Fatalf("files=%d want 1", len(files))
	}
	if files[0].Name != vminfo.NyxModulesFile || !files[0].Exists {
		t.Fatalf("bad module info file metadata: %+v", files[0])
	}
	var modules []*vminfo.KernelModule
	if err := json.Unmarshal(files[0].Data, &modules); err != nil {
		t.Fatalf("unmarshal module info: %v", err)
	}
	if len(modules) != 1 || modules[0].Name != "afd.sys" ||
		modules[0].Addr != 0xfffff80600000000 || modules[0].Size != 0x1000 ||
		modules[0].Path != "afd.sys" {
		t.Fatalf("bad modules: %+v", modules)
	}
}

func TestNormalizeWindowsNyxEnvFlags(t *testing.T) {
	raw := flatrpc.ExecEnvSandboxAndroid |
		flatrpc.ExecEnvEnableNetReset |
		flatrpc.ExecEnvEnableCgroups |
		flatrpc.ExecEnvEnableCloseFds |
		flatrpc.ExecEnvEnableWifi |
		flatrpc.ExecEnvDelayKcovMmap |
		flatrpc.ExecEnvExtraCover |
		flatrpc.ExecEnvDebug
	got := normalizeWindowsNyxEnvFlags(raw)
	want := flatrpc.ExecEnvDebug |
		flatrpc.ExecEnvSignal |
		flatrpc.ExecEnvSandboxNone
	if got != want {
		t.Fatalf("normalized env mismatch: got 0x%x want 0x%x", uint64(got), uint64(want))
	}
}

func TestRequestNeedsCoveragePriming(t *testing.T) {
	tests := []struct {
		name string
		req  *flatrpc.ExecRequest
		want bool
	}{
		{
			name: "nil",
			req:  nil,
			want: false,
		},
		{
			name: "no opts",
			req:  &flatrpc.ExecRequest{},
			want: false,
		},
		{
			name: "threaded only",
			req: &flatrpc.ExecRequest{ExecOpts: &flatrpc.ExecOpts{
				ExecFlags: flatrpc.ExecFlagThreaded,
			}},
			want: false,
		},
		{
			name: "collect cover",
			req: &flatrpc.ExecRequest{ExecOpts: &flatrpc.ExecOpts{
				ExecFlags: flatrpc.ExecFlagThreaded | flatrpc.ExecFlagCollectCover,
			}},
			want: true,
		},
		{
			name: "collect signal",
			req: &flatrpc.ExecRequest{ExecOpts: &flatrpc.ExecOpts{
				ExecFlags: flatrpc.ExecFlagCollectSignal,
			}},
			want: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := requestNeedsCoveragePriming(test.req); got != test.want {
				t.Fatalf("requestNeedsCoveragePriming()=%v want %v", got, test.want)
			}
		})
	}
}

func TestExecProgramIsMultiCallWindowsVNet(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	vnet := serializeWindowsTestProgramForExec(t,
		filepath.Join("..", "..", "sys", "windows", "test", "nyx_afd_accept_vnet_recv.txt"))
	if !execProgramIsMultiCallWindowsVNet(vnet) {
		t.Fatal("AFD vnet receive seed should be classified as a multi-call Windows vnet program")
	}

	nonVNet := serializeWindowsTestProgramForExec(t,
		filepath.Join("..", "..", "sys", "windows", "test", "nyx_afd_private_query_readonly.txt"))
	if execProgramIsMultiCallWindowsVNet(nonVNet) {
		t.Fatal("non-vnet AFD seed must not be classified as a Windows vnet program")
	}
}

func TestPrimeResultCanReturn(t *testing.T) {
	tests := []struct {
		name string
		msg  *flatrpc.ExecutorMessage
		want bool
	}{
		{
			name: "coverage",
			msg: execResultMessage(&flatrpc.ExecResult{
				Info: &flatrpc.ProgInfo{
					Calls: []*flatrpc.CallInfo{
						{Cover: []uint64{0x10}},
					},
				},
			}),
			want: true,
		},
		{
			name: "signal only",
			msg: execResultMessage(&flatrpc.ExecResult{
				Info: &flatrpc.ProgInfo{
					Calls: []*flatrpc.CallInfo{
						{Signal: []uint64{0x10}},
					},
				},
			}),
			want: true,
		},
		{
			name: "hanged",
			msg: execResultMessage(&flatrpc.ExecResult{
				Hanged: true,
				Info:   flatrpc.EmptyProgInfo(1),
			}),
			want: true,
		},
		{
			name: "no coverage",
			msg: execResultMessage(&flatrpc.ExecResult{
				Info: flatrpc.EmptyProgInfo(1),
			}),
			want: false,
		},
		{
			name: "executor error",
			msg: execResultMessage(&flatrpc.ExecResult{
				Error: "executor failed",
				Info:  flatrpc.EmptyProgInfo(1),
			}),
			want: false,
		},
	}
	for _, test := range tests {
		if got := primeResultCanReturn(test.msg); got != test.want {
			t.Fatalf("%s: got %v, want %v", test.name, got, test.want)
		}
	}
}

func execResultMessage(res *flatrpc.ExecResult) *flatrpc.ExecutorMessage {
	return &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type:  flatrpc.ExecutorMessagesRawExecResult,
			Value: res,
		},
	}
}

func TestExecResultHasCoverage(t *testing.T) {
	withCoverage := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type: flatrpc.ExecutorMessagesRawExecResult,
			Value: &flatrpc.ExecResult{
				Info: &flatrpc.ProgInfo{
					Calls: []*flatrpc.CallInfo{{Cover: []uint64{0x10}}},
				},
			},
		},
	}
	withoutCoverage := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type: flatrpc.ExecutorMessagesRawExecResult,
			Value: &flatrpc.ExecResult{
				Info: flatrpc.EmptyProgInfo(1),
			},
		},
	}
	if !execResultHasCoverage(withCoverage) {
		t.Fatal("execResultHasCoverage returned false for non-empty cover")
	}
	if execResultHasCoverage(withoutCoverage) {
		t.Fatal("execResultHasCoverage returned true for empty cover")
	}
}

func TestReorderArgsForFlags(t *testing.T) {
	in := []string{
		"0",
		"127.0.0.1",
		"56555",
		"--workdir", "/dev/shm/nyx-fullchain",
		"--qemu-path", "/tmp/qemu",
		"--qemu-arg=-display",
		"--qemu-arg", "none",
		"--module-ranges", "ntoskrnl.exe:required,ntfs.sys",
		"--coverage-debug-stream", "/tmp/coverage.jsonl",
	}
	got := reorderArgsForFlags(in)
	want := []string{
		"--workdir", "/dev/shm/nyx-fullchain",
		"--qemu-path", "/tmp/qemu",
		"--qemu-arg=-display",
		"--qemu-arg", "none",
		"--module-ranges", "ntoskrnl.exe:required,ntfs.sys",
		"--coverage-debug-stream", "/tmp/coverage.jsonl",
		"0",
		"127.0.0.1",
		"56555",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d args, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d mismatch: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestParseModuleRanges(t *testing.T) {
	ranges, err := parseModuleRanges("ntoskrnl.exe:required, ntfs.sys, win32k*.sys")
	if err != nil {
		t.Fatalf("parseModuleRanges: %v", err)
	}
	want := []moduleRangeSpec{
		{Pattern: "ntoskrnl.exe", Required: true},
		{Pattern: "ntfs.sys"},
		{Pattern: "win32k*.sys"},
	}
	if len(ranges) != len(want) {
		t.Fatalf("got %d ranges, want %d", len(ranges), len(want))
	}
	for i := range want {
		if ranges[i] != want[i] {
			t.Fatalf("range %d got %+v want %+v", i, ranges[i], want[i])
		}
	}
}

func TestPackModuleRangeConfig(t *testing.T) {
	ranges := []moduleRangeSpec{
		{Pattern: "ntoskrnl.exe", Required: true},
		{Pattern: "ntfs.sys"},
	}
	payload := packModuleRangeConfig(ranges)
	if got := binary.LittleEndian.Uint32(payload[0:4]); got != nyxModuleRangeConfigMagic {
		t.Fatalf("magic=%#x want %#x", got, nyxModuleRangeConfigMagic)
	}
	if got := binary.LittleEndian.Uint16(payload[4:6]); got != nyxModuleRangeConfigVersion {
		t.Fatalf("version=%d want %d", got, nyxModuleRangeConfigVersion)
	}
	if got := binary.LittleEndian.Uint16(payload[6:8]); got != uint16(len(ranges)) {
		t.Fatalf("count=%d want %d", got, len(ranges))
	}
	entrySize := 1 + nyxModuleRangePatternSize
	if payload[8] != 1 {
		t.Fatalf("first entry required=%d want 1", payload[8])
	}
	if got := string(bytes.TrimRight(payload[9:9+nyxModuleRangePatternSize], "\x00")); got != "ntoskrnl.exe" {
		t.Fatalf("first pattern=%q", got)
	}
	second := 8 + entrySize
	if payload[second] != 0 {
		t.Fatalf("second entry required=%d want 0", payload[second])
	}
	if got := string(bytes.TrimRight(payload[second+1:second+1+nyxModuleRangePatternSize], "\x00")); got != "ntfs.sys" {
		t.Fatalf("second pattern=%q", got)
	}
}

func TestDeriveHardTimeoutUsesProgramTimeout(t *testing.T) {
	got := deriveHardTimeout(5000, 3*time.Minute)
	want := 15 * time.Second
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestIsExpectedManagerDisconnect(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "eof", err: io.EOF, want: true},
		{name: "closed", err: net.ErrClosed, want: true},
		{name: "epipe", err: fmt.Errorf("wrapped: %w", syscall.EPIPE), want: true},
		{name: "econnreset", err: fmt.Errorf("wrapped: %w", syscall.ECONNRESET), want: true},
		{name: "econnaborted", err: fmt.Errorf("wrapped: %w", syscall.ECONNABORTED), want: true},
		{name: "other", err: errors.New("guest abort"), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isExpectedManagerDisconnect(tc.err); got != tc.want {
				t.Fatalf("got %v, want %v for %v", got, tc.want, tc.err)
			}
		})
	}
}

func TestRunnerLoopGracefulOnManagerEOF(t *testing.T) {
	runnerConn, managerConn := net.Pipe()
	defer runnerConn.Close()
	r := &runner{conn: flatrpc.NewConn(runnerConn)}
	done := make(chan error, 1)
	go func() {
		done <- r.loop()
	}()
	_ = managerConn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loop returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for loop to exit after manager EOF")
	}
}

func TestRunnerResetForReconnect(t *testing.T) {
	runnerConn, managerConn := net.Pipe()
	defer managerConn.Close()
	r := &runner{
		conn:           flatrpc.NewConn(runnerConn),
		connectReply:   &flatrpc.ConnectReply{},
		handshakeReady: true,
		lastEnvFlags:   123,
		lastSandboxArg: 456,
		needRestart:    true,
	}
	r.resetForReconnect()
	if r.conn != nil {
		t.Fatal("connection should be cleared")
	}
	if r.connectReply != nil {
		t.Fatal("connectReply should be cleared")
	}
	if r.handshakeReady {
		t.Fatal("handshakeReady should be reset")
	}
	if r.lastEnvFlags != 0 || r.lastSandboxArg != 0 {
		t.Fatalf("handshake cache not reset: env=%v sandbox=%v", r.lastEnvFlags, r.lastSandboxArg)
	}
	if !r.needRestart {
		t.Fatal("needRestart should be preserved across reconnect reset")
	}
}

func TestDeriveHardTimeoutHonorsFallbackUpperBound(t *testing.T) {
	got := deriveHardTimeout(120000, 1*time.Minute)
	want := 1 * time.Minute
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestDeriveHardTimeoutFallsBackWithoutProgramTimeout(t *testing.T) {
	got := deriveHardTimeout(0, 45*time.Second)
	want := 45 * time.Second
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestApplyStandaloneHardTimeoutUsesProgramTimeout(t *testing.T) {
	vm := &nyxVM{hardTimeout: 3 * time.Minute}
	got := applyStandaloneHardTimeout(vm, 60000)
	want := 2 * time.Minute
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if vm.hardTimeout != want {
		t.Fatalf("vm hard timeout = %s, want %s", vm.hardTimeout, want)
	}
}

func TestApplyStandaloneHardTimeoutHonorsSmallerFallback(t *testing.T) {
	vm := &nyxVM{hardTimeout: 45 * time.Second}
	got := applyStandaloneHardTimeout(vm, 60000)
	want := 45 * time.Second
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if vm.hardTimeout != want {
		t.Fatalf("vm hard timeout = %s, want %s", vm.hardTimeout, want)
	}
}

func TestHardTimeoutWithSlackUsesMinimum(t *testing.T) {
	got := hardTimeoutWithSlack(5 * time.Second)
	want := 35 * time.Second
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestExecWaitTimeoutHonorsDerivedShortProgramTimeout(t *testing.T) {
	vm := &nyxVM{hardTimeout: 15 * time.Second}
	got := vm.execWaitTimeout()
	want := 20 * time.Second
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestInitWaitTimeoutKeepsSlowNyxShadowInitBudget(t *testing.T) {
	vm := &nyxVM{hardTimeout: 45 * time.Second}
	got := vm.initWaitTimeout()
	want := 125 * time.Second
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestInitWaitTimeoutHonorsLongerHardTimeout(t *testing.T) {
	vm := &nyxVM{hardTimeout: 3 * time.Minute}
	got := vm.initWaitTimeout()
	want := 185 * time.Second
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestExecResultHanged(t *testing.T) {
	hanged := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type: flatrpc.ExecutorMessagesRawExecResult,
			Value: &flatrpc.ExecResult{
				Hanged: true,
			},
		},
	}
	if !execResultHanged(hanged) {
		t.Fatal("expected hanged exec result to be detected")
	}
	ok := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type: flatrpc.ExecutorMessagesRawExecResult,
			Value: &flatrpc.ExecResult{
				Hanged: false,
			},
		},
	}
	if execResultHanged(ok) {
		t.Fatal("unexpected hanged detection for successful exec result")
	}
	if execResultHanged(nil) {
		t.Fatal("nil message must not be treated as hanged")
	}
}

func TestHandleHangedRequestSkipsRestartAfterNyxReload(t *testing.T) {
	auxData := make([]byte, nyxResultReloadedOffset+1)
	auxData[nyxResultReloadedOffset] = 1
	r := &runner{vm: &nyxVM{aux: &qemuAux{data: auxData}}}

	r.handleHangedRequest(123)

	if r.needRestart {
		t.Fatal("hanged request after nyx reload must not schedule full VM restart")
	}
}

func TestHandleHangedRequestRestartsWithoutNyxReload(t *testing.T) {
	auxData := make([]byte, nyxResultReloadedOffset+1)
	r := &runner{vm: &nyxVM{aux: &qemuAux{data: auxData}}}

	r.handleHangedRequest(123)

	if !r.needRestart {
		t.Fatal("hanged request without nyx reload must schedule full VM restart")
	}
}

func writeRaceSection(buf *bytes.Buffer, stats RaceStats) {
	binary.Write(buf, binary.LittleEndian, uint32(raceSectionMagic))
	binary.Write(buf, binary.LittleEndian, uint16(raceSectionVersion))
	binary.Write(buf, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(buf, binary.LittleEndian, stats.WatchpointsArmed)
	binary.Write(buf, binary.LittleEndian, stats.WatchpointsHit)
	binary.Write(buf, binary.LittleEndian, stats.RacesDetected)
	binary.Write(buf, binary.LittleEndian, stats.DoubleFetchesDetected)
	binary.Write(buf, binary.LittleEndian, stats.RacesKnownOrigin)
	binary.Write(buf, binary.LittleEndian, stats.RacesUnknownOrigin)
	binary.Write(buf, binary.LittleEndian, stats.TotalStallNs)
	binary.Write(buf, binary.LittleEndian, stats.RaceFingerprintsNew)
}

func TestParseRaceSection(t *testing.T) {
	want := RaceStats{
		WatchpointsArmed:      42,
		WatchpointsHit:        17,
		RacesDetected:         3,
		DoubleFetchesDetected: 1,
		RacesKnownOrigin:      2,
		RacesUnknownOrigin:    1,
		TotalStallNs:          1234567,
		RaceFingerprintsNew:   5,
	}
	buf := new(bytes.Buffer)
	writeRaceSection(buf, want)
	got, err := parseRaceSection(buf.Bytes())
	if err != nil {
		t.Fatalf("parseRaceSection failed: %v", err)
	}
	if got == nil {
		t.Fatal("parseRaceSection returned nil")
	}
	if *got != want {
		t.Fatalf("race stats mismatch:\n got  %+v\n want %+v", *got, want)
	}
}

func TestParseRaceSectionAbsent(t *testing.T) {
	// An empty data slice means no race section was appended.
	_, err := parseRaceSection(nil)
	if err == nil {
		t.Fatal("expected error for empty race section")
	}
}

func TestParseRaceSectionBadMagic(t *testing.T) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0xDEADBEEF))
	binary.Write(buf, binary.LittleEndian, uint16(raceSectionVersion))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	buf.Write(make([]byte, raceStatsSize))
	_, err := parseRaceSection(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for bad race section magic")
	}
}

func TestParseCoverageDumpWithRaceSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "syz_cov_race.bin")
	// Write a minimal coverage dump (0 records) + race section.
	buf := new(bytes.Buffer)
	hdr := nyxCovHeader{Magic: nyxCovMagic, Version: nyxCovVersion, RecordCount: 0}
	binary.Write(buf, binary.LittleEndian, &hdr)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // comp record count
	wantStats := RaceStats{
		WatchpointsArmed: 10, WatchpointsHit: 5, RacesDetected: 2,
		DoubleFetchesDetected: 1, RacesKnownOrigin: 1, RacesUnknownOrigin: 1,
		TotalStallNs: 999, RaceFingerprintsNew: 3,
	}
	writeRaceSection(buf, wantStats)
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, raceStats, err := parseCoverageDump(path)
	if err != nil {
		t.Fatalf("parseCoverageDump failed: %v", err)
	}
	if raceStats == nil {
		t.Fatal("expected race stats, got nil")
	}
	if *raceStats != wantStats {
		t.Fatalf("race stats mismatch:\n got  %+v\n want %+v", *raceStats, wantStats)
	}
}

func TestParseCoverageDumpWithoutRaceSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "syz_cov_norace.bin")
	// Write a minimal coverage dump (0 records) without a race section.
	writeCoverageDump(t, path, nil)
	_, _, raceStats, err := parseCoverageDump(path)
	if err != nil {
		t.Fatalf("parseCoverageDump failed: %v", err)
	}
	if raceStats != nil {
		t.Fatalf("expected nil race stats, got %+v", *raceStats)
	}
}

func TestRaceFingerprintDeterministic(t *testing.T) {
	ev := RaceEvent{
		Gpa:           0x1000,
		ArmerRip:      0xFFFF80001000,
		HitterRip:     0xFFFF80002000,
		ArmerIsWrite:  true,
		HitterIsWrite: false,
		RaceType:      0,
	}
	fp1 := raceFingerprint(ev)
	fp2 := raceFingerprint(ev)
	if fp1 != fp2 {
		t.Fatalf("fingerprint not deterministic: 0x%x vs 0x%x", fp1, fp2)
	}
}

func TestRaceFingerprintDistinct(t *testing.T) {
	base := RaceEvent{
		Gpa: 0x2000, ArmerRip: 0x1000, HitterRip: 0x2000,
		ArmerIsWrite: true, HitterIsWrite: false, RaceType: 0,
	}
	fpBase := raceFingerprint(base)

	// Different armer RIP → different fingerprint.
	diff := base
	diff.ArmerRip = 0x9999
	if fp := raceFingerprint(diff); fp == fpBase {
		t.Fatalf("expected different fingerprint for different armer_rip")
	}

	// Different hitter RIP → different fingerprint.
	diff = base
	diff.HitterRip = 0x8888
	if fp := raceFingerprint(diff); fp == fpBase {
		t.Fatalf("expected different fingerprint for different hitter_rip")
	}

	// Different page → different fingerprint.
	diff = base
	diff.Gpa = 0x5000
	if fp := raceFingerprint(diff); fp == fpBase {
		t.Fatalf("expected different fingerprint for different gpa page")
	}

	// Same page, different sub-page offset → same fingerprint (page alignment).
	diff = base
	diff.Gpa = base.Gpa + 0xFF // still within the same 4K page
	if fp := raceFingerprint(diff); fp != fpBase {
		t.Fatalf("expected same fingerprint for same page, got 0x%x vs 0x%x", fp, fpBase)
	}

	// Different access types → different fingerprint.
	diff = base
	diff.HitterIsWrite = true
	if fp := raceFingerprint(diff); fp == fpBase {
		t.Fatalf("expected different fingerprint for different access types")
	}
}

func TestInjectRaceSignals(t *testing.T) {
	execMsg := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type: flatrpc.ExecutorMessagesRawExecResult,
			Value: &flatrpc.ExecResult{
				Info: &flatrpc.ProgInfo{},
			},
		},
	}
	events := []RaceEvent{
		{Gpa: 0x1000, ArmerRip: 0xA, HitterRip: 0xB, ArmerIsWrite: true, RaceType: 0},
		{Gpa: 0x2000, ArmerRip: 0xC, HitterRip: 0xD, ArmerIsWrite: false, RaceType: 1},
		// Duplicate of the first event → should be deduplicated.
		{Gpa: 0x1000, ArmerRip: 0xA, HitterRip: 0xB, ArmerIsWrite: true, RaceType: 0},
	}
	injectRaceSignals(execMsg, events)
	res := execMsg.Msg.Value.(*flatrpc.ExecResult)
	if res.Info.Extra == nil {
		t.Fatal("Expected Extra CallInfo to be created")
	}
	if len(res.Info.Extra.Signal) != 2 {
		t.Fatalf("Expected 2 unique signals, got %d", len(res.Info.Extra.Signal))
	}
	// Verify the two signals are distinct.
	if res.Info.Extra.Signal[0] == res.Info.Extra.Signal[1] {
		t.Fatal("Expected distinct signal values")
	}
}

func TestInjectRaceSignalsEmpty(t *testing.T) {
	execMsg := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type: flatrpc.ExecutorMessagesRawExecResult,
			Value: &flatrpc.ExecResult{
				Info: &flatrpc.ProgInfo{},
			},
		},
	}
	// No events → no signals, no Extra created.
	injectRaceSignals(execMsg, nil)
	res := execMsg.Msg.Value.(*flatrpc.ExecResult)
	if res.Info.Extra != nil {
		t.Fatal("Expected Extra to remain nil for empty events")
	}
}

func TestParseRaceReportDumpMissing(t *testing.T) {
	// A non-existent file should return an error (os.ErrNotExist).
	_, err := parseRaceReportDump("/nonexistent/race_report.bin")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

package main

import (
	"bytes"
	"encoding/binary"
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
		raw := nyxCovRecord{
			CallIndex: rec.CallIndex,
			SlotID:    rec.SlotID,
			Flags:     rec.Flags,
			PCCount:   uint32(len(rec.PCs)),
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

func TestParseCoverageDumpMultipleRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syz_cov.bin")
	want := []nyxCovDumpRecord{
		{CallIndex: 0, SlotID: 0, Flags: 1, PCs: []uint64{0x11, 0x22}},
		{CallIndex: 2, SlotID: 1, Flags: 0, PCs: []uint64{0x33}},
	}
	writeCoverageDump(t, path, want)

	got, _, err := parseCoverageDump(path)
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
	if _, _, err := parseCoverageDump(path); err == nil {
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

	covRecords, _, err := parseCoverageDump(path)
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
	}
	got := reorderArgsForFlags(in)
	want := []string{
		"--workdir", "/dev/shm/nyx-fullchain",
		"--qemu-path", "/tmp/qemu",
		"--qemu-arg=-display",
		"--qemu-arg", "none",
		"--module-ranges", "ntoskrnl.exe:required,ntfs.sys",
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

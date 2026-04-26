package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

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

func TestParseCoverageDumpMultipleRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syz_cov.bin")
	want := []nyxCovDumpRecord{
		{CallIndex: 0, SlotID: 0, Flags: 1, PCs: []uint64{0x11, 0x22}},
		{CallIndex: 2, SlotID: 1, Flags: 0, PCs: []uint64{0x33}},
	}
	writeCoverageDump(t, path, want)

	got, err := parseCoverageDump(path)
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
	if _, err := parseCoverageDump(path); err == nil {
		t.Fatal("parseCoverageDump unexpectedly succeeded on bad magic")
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

	if err := injectCoverage(req, execMsg, false, path); err != nil {
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

func TestReorderArgsForFlags(t *testing.T) {
	in := []string{
		"0",
		"127.0.0.1",
		"56555",
		"--workdir", "/dev/shm/nyx-fullchain",
		"--qemu-path", "/tmp/qemu",
		"--qemu-arg=-display",
		"--qemu-arg", "none",
	}
	got := reorderArgsForFlags(in)
	want := []string{
		"--workdir", "/dev/shm/nyx-fullchain",
		"--qemu-path", "/tmp/qemu",
		"--qemu-arg=-display",
		"--qemu-arg", "none",
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

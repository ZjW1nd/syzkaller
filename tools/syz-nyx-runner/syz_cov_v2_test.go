package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
)

func buildMockSyzCovV2(t *testing.T) []byte {
	t.Helper()
	buf := new(bytes.Buffer)

	// syz_cov_header_t: magic(4) + version(2) + reserved(2) + record_count(4)
	header := struct {
		Magic       uint32
		Version     uint16
		Reserved    uint16
		RecordCount uint32
	}{
		Magic:       0x564f4353, // "SCOV"
		Version:     2,
		Reserved:    0,
		RecordCount: 1,
	}
	binary.Write(buf, binary.LittleEndian, &header)

	// Coverage record: call_index(4) + slot_id(4) + flags(8) + pc_count(4) + reserved(4)
	covRec := struct {
		CallIndex uint32
		SlotID    uint32
		Flags     uint64
		PCCount   uint32
		Reserved  uint32
	}{
		CallIndex: 0,
		SlotID:    0,
		Flags:     0,
		PCCount:   2,
		Reserved:  0,
	}
	binary.Write(buf, binary.LittleEndian, &covRec)

	// 2 coverage PCs
	pcs := []uint64{0xfffff80001020304, 0xfffff80005060708}
	for _, pc := range pcs {
		binary.Write(buf, binary.LittleEndian, pc)
	}

	// comp_record_count (uint32): 1
	compRecCount := uint32(1)
	binary.Write(buf, binary.LittleEndian, compRecCount)

	// One comp record: reuse syz_cov_record_t header, pc_count = comp_count
	compRecHeader := struct {
		CallIndex uint32
		SlotID    uint32
		Flags     uint64
		PCCount   uint32 // overloaded as comp_count
		Reserved  uint32
	}{
		CallIndex: 0,
		SlotID:    0,
		Flags:     0,
		PCCount:   2, // 2 comparison entries
		Reserved:  0,
	}
	binary.Write(buf, binary.LittleEndian, &compRecHeader)

	// Two comp entries (28 bytes each)
	type compEntry struct {
		Pc    uint64
		Op1   uint64
		Op2   uint64
		Size  uint8
		Kind  uint8
		IsImm uint8
		_pad  uint8
	}
	comp1 := compEntry{
		Pc:    0xfffff8000a000000,
		Op1:   0x000000000000000A, // dst (register, dynamic) = 0xA
		Op2:   0x000000000000000F, // src (immediate) = 0xF (const)
		Size:  32,
		Kind:  0, // RQ_COMP_KIND_CMP
		IsImm: 1,
	}
	comp2 := compEntry{
		Pc:    0xfffff8000b000000,
		Op1:   0x0000000000123456, // reg = 0x123456
		Op2:   0x00000000007890AB, // reg = 0x7890AB (both dynamic, not const)
		Size:  64,
		Kind:  0,
		IsImm: 0,
	}
	binary.Write(buf, binary.LittleEndian, comp1)
	binary.Write(buf, binary.LittleEndian, comp2)

	return buf.Bytes()
}

func TestParseCoverageDumpV2(t *testing.T) {
	data := buildMockSyzCovV2(t)
	tmp := t.TempDir()
	path := tmp + "/syz_cov_0.bin"
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	covRecords, compRecords, err := parseCoverageDump(path)
	if err != nil {
		t.Fatalf("parseCoverageDump: %v", err)
	}

	// Verify coverage
	if len(covRecords) != 1 {
		t.Fatalf("expected 1 coverage record, got %d", len(covRecords))
	}
	if len(covRecords[0].PCs) != 2 {
		t.Fatalf("expected 2 coverage PCs, got %d", len(covRecords[0].PCs))
	}

	// Verify comparisons
	if len(compRecords) != 1 {
		t.Fatalf("expected 1 comp record, got %d", len(compRecords))
	}
	comps := compRecords[0].Comps
	if len(comps) != 2 {
		t.Fatalf("expected 2 comp entries, got %d", len(comps))
	}

	// Entry 0: CMP 32-bit with immediate
	if comps[0].Pc != 0xfffff8000a000000 {
		t.Errorf("comp[0].Pc = 0x%x, want 0xfffff8000a000000", comps[0].Pc)
	}
	if comps[0].Op1 != 0xA {
		t.Errorf("comp[0].Op1 = 0x%x, want 0xA", comps[0].Op1)
	}
	if comps[0].Op2 != 0xF {
		t.Errorf("comp[0].Op2 = 0x%x, want 0xF", comps[0].Op2)
	}
	if comps[0].Kind != 0 {
		t.Errorf("comp[0].Kind = %d, want 0 (CMP)", comps[0].Kind)
	}
	if comps[0].IsImm != 1 {
		t.Errorf("comp[0].IsImm = %d, want 1", comps[0].IsImm)
	}

	// Entry 1: CMP 64-bit non-const
	if comps[1].IsImm != 0 {
		t.Errorf("comp[1].IsImm = %d, want 0", comps[1].IsImm)
	}
}

func TestInjectCompsFromRecords(t *testing.T) {
	compRecords := []nyxCovCompRecord{
		{
			CallIndex: 0,
			Comps: []nyxCompEntry{
				{Pc: 0x100, Op1: 0xA, Op2: 0xF, Size: 32, Kind: 0, IsImm: 1},
			},
		},
	}

	req := &flatrpc.ExecRequest{
		ExecOpts: &flatrpc.ExecOpts{
			ExecFlags: flatrpc.ExecFlagCollectComps,
		},
	}
	execMsg := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Value: &flatrpc.ExecResult{
				Info: &flatrpc.ProgInfoRawT{
					Calls: []*flatrpc.CallInfoRawT{
						{},
					},
				},
			},
		},
	}

	err := injectCoverage(req, execMsg, false, true, moduleRangeCanonicalizer{}, nil, compRecords)
	if err != nil {
		t.Fatalf("injectCoverage: %v", err)
	}

	res := execMsg.Msg.Value.(*flatrpc.ExecResult)
	call := res.Info.Calls[0]
	if len(call.Comps) != 1 {
		t.Fatalf("expected 1 injected comp, got %d", len(call.Comps))
	}

	// Verify operand swap: Redqueen val1=dst, val2=src.
	// KCOV convention: Op1=src(compared-against), Op2=dst(dynamic).
	// So injected comp should have Op1=val2, Op2=val1.
	cmp := call.Comps[0]
	if cmp.Pc != 0x100 {
		t.Errorf("Pc = 0x%x, want 0x100", cmp.Pc)
	}
	if cmp.Op1 != 0xF {
		t.Errorf("Op1 = 0x%x, want 0xF (swapped val2=src)", cmp.Op1)
	}
	if cmp.Op2 != 0xA {
		t.Errorf("Op2 = 0x%x, want 0xA (swapped val1=dst)", cmp.Op2)
	}
	if !cmp.IsConst {
		t.Errorf("IsConst = false, want true (IsImm=1)")
	}
}

func TestInjectCompsRejectsOutOfRangeCall(t *testing.T) {
	req := &flatrpc.ExecRequest{
		ExecOpts: &flatrpc.ExecOpts{
			ExecFlags: flatrpc.ExecFlagCollectComps,
		},
	}
	execMsg := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Value: &flatrpc.ExecResult{
				Info: flatrpc.EmptyProgInfo(1),
			},
		},
	}

	err := injectCoverage(req, execMsg, false, true, moduleRangeCanonicalizer{}, nil, []nyxCovCompRecord{
		{CallIndex: 1, Comps: []nyxCompEntry{{Pc: 0x100}}},
	})
	if err == nil {
		t.Fatal("injectCoverage unexpectedly accepted an out-of-range comparison record")
	}
}

func TestParseCoverageDumpV1BackwardCompat(t *testing.T) {
	// Build a v1 dump (no comp section)
	buf := new(bytes.Buffer)
	header := struct {
		Magic       uint32
		Version     uint16
		Reserved    uint16
		RecordCount uint32
	}{
		Magic:       0x564f4353,
		Version:     1,
		Reserved:    0,
		RecordCount: 1,
	}
	binary.Write(buf, binary.LittleEndian, &header)

	covRec := struct {
		CallIndex uint32
		SlotID    uint32
		Flags     uint64
		PCCount   uint32
		Reserved  uint32
	}{
		PCCount: 1,
	}
	binary.Write(buf, binary.LittleEndian, &covRec)
	binary.Write(buf, binary.LittleEndian, uint64(0xfffff8000c000000))

	tmp := t.TempDir()
	path := tmp + "/syz_cov_v1.bin"
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	covRecords, compRecords, err := parseCoverageDump(path)
	if err != nil {
		t.Fatalf("parseCoverageDump v1: %v", err)
	}
	if len(covRecords) != 1 {
		t.Errorf("v1: expected 1 cov record, got %d", len(covRecords))
	}
	if len(compRecords) != 0 {
		t.Errorf("v1: expected 0 comp records, got %d", len(compRecords))
	}
}

func TestParseCoverageDumpEmpty(t *testing.T) {
	tmp := t.TempDir()
	path := tmp + "/nonexistent.bin"

	_, _, err := parseCoverageDump(path)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected ErrNotExist, got %v", err)
	}
}

package main

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectorSampleWritesCSV(t *testing.T) {
	dir := t.TempDir()
	managerLog := filepath.Join(dir, "manager.log")
	runnerLog := filepath.Join(dir, "runner.log")
	out := filepath.Join(dir, "stats.csv")

	managerLines := []string{
		"2026/05/07 13:19:18 rpcserver exec result: id=1420 calls=3 raw_nonempty=3 raw_signal=10037 raw_cover=21009 post_nonempty=3 post_signal=10037 post_cover=21009 hanged=false",
		"2026/05/07 13:19:18 windows triage: call=2 name=NtFsControlFile signal=251 cover=254 prio=3 new=24 errno=0 flags=0x0",
		"2026/05/07 13:19:18 windows corpus save: call=0 name=NtFsControlFile stable_signal=231 new_stable=76 cover=151 raw_cover=0",
		"2026/05/07 13:30:27 candidates=16 corpus=54 coverage=9913 exec total=604 (362/min) ",
	}
	runnerLines := []string{
		"2026/05/07 12:49:10 runner handshake complete",
		"2026/05/07 12:49:10 nyx hprintf: nyx handshake submit_cr3=0xae1ff000",
		"2026/05/07 12:49:20 runner exec complete: id=2 calls=9 cover_records=6",
		"[+00079.807896] [QEMU-NYX] Warning: CrashFlow[PT_DECODE] bytes=144 decode_bytes=144 trimmed=0 terminator_before=0x55 result=2 bb_before=0 bb_after=60 trace_size=144",
		"[+00079.807917] [QEMU-NYX] Warning: CrashFlow[SYZ_COV_DUMP] active=1 records=6 last_call=6 last_slot=0 last_pcs=190 ip_callbacks=9 ip_recorded=9 first_pc=0xfffff8009727c200 last_pc=0x7ffeb5703414",
	}
	if err := os.WriteFile(managerLog, []byte(strings.Join(managerLines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runnerLog, []byte(strings.Join(runnerLines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(csvHeader()); err != nil {
		t.Fatal(err)
	}
	c := &collector{
		manager: fileTracker{path: managerLog},
		runner:  fileTracker{path: runnerLog},
		state:   statsState{start: time.Now()},
	}
	if err := c.sample(w); err != nil {
		t.Fatalf("sample failed: %v", err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatal(err)
	}

	rows, err := readCSV(out)
	if err != nil {
		t.Fatalf("readCSV failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	row := rows[0]
	if row.ExecTotal != 604 || row.Coverage != 9913 || row.Corpus != 54 {
		t.Fatalf("bad manager stats row: %#v", row)
	}
	if row.RawSignal != 10037 || row.RawCover != 21009 || row.NonZeroExec != 1 {
		t.Fatalf("bad exec result row: %#v", row)
	}
	if row.NTFSTriage != 1 || row.CorpusSaves != 1 {
		t.Fatalf("bad triage/corpus counts: %#v", row)
	}
	if row.SubmitCR3Count != 1 || row.LastSubmitCR3 != "0xae1ff000" {
		t.Fatalf("bad cr3 fields: %#v", row)
	}
	if row.RunnerLastCoverRecs != 6 || row.PTLastTraceSize != 144 || row.SYZCovLastRecords != 6 {
		t.Fatalf("bad runner/PT fields: %#v", row)
	}
}

func TestRunPlotProducesArtifacts(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "stats.csv")
	outdir := filepath.Join(dir, "out")

	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	w := csv.NewWriter(f)
	if err := w.Write(csvHeader()); err != nil {
		t.Fatal(err)
	}
	rows := []csvRow{
		{TimestampUnix: 1, ElapsedSec: 0, ExecTotal: 1, ExecPerMin: 60, Coverage: 10, Corpus: 1, Candidates: 5, RawSignal: 10, RawCover: 20, PostSignal: 10, PostCover: 20, RunnerLastCoverRecs: 1, PTLastTraceSize: 100, PTLastBBAfter: 5, SYZCovLastRecords: 1},
		{TimestampUnix: 2, ElapsedSec: 5, ExecTotal: 10, ExecPerMin: 120, Coverage: 50, Corpus: 3, Candidates: 4, RawSignal: 30, RawCover: 40, PostSignal: 30, PostCover: 40, RunnerLastCoverRecs: 2, PTLastTraceSize: 150, PTLastBBAfter: 10, SYZCovLastRecords: 2},
	}
	for _, row := range rows {
		if err := w.Write(row.toCSV()); err != nil {
			t.Fatal(err)
		}
	}
	w.Flush()
	_ = f.Close()
	if err := w.Error(); err != nil {
		t.Fatal(err)
	}

	if err := runPlot([]string{"--input", input, "--outdir", outdir, "--title", "test"}); err != nil {
		t.Fatalf("runPlot failed: %v", err)
	}
	for _, name := range []string{
		"coverage_corpus.svg",
		"throughput.svg",
		"signal_cover.svg",
		"pt_trace.svg",
		"summary.json",
		"index.html",
	} {
		data, err := os.ReadFile(filepath.Join(outdir, name))
		if err != nil {
			t.Fatalf("missing artifact %s: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("artifact %s is empty", name)
		}
	}
}

func TestTrimPlotRowsDropsLeadingZeroPrefix(t *testing.T) {
	rows := []csvRow{
		{TimestampUnix: 1, ElapsedSec: 0},
		{TimestampUnix: 2, ElapsedSec: 5},
		{TimestampUnix: 3, ElapsedSec: 10, ExecTotal: 7, Coverage: 20},
		{TimestampUnix: 4, ElapsedSec: 15, ExecTotal: 12, Coverage: 25},
	}

	trimmed, offset := trimPlotRows(rows)
	if offset != 10 {
		t.Fatalf("got offset %.3f, want 10", offset)
	}
	if len(trimmed) != 2 {
		t.Fatalf("got %d rows, want 2", len(trimmed))
	}
	if trimmed[0].ElapsedSec != 0 || trimmed[1].ElapsedSec != 5 {
		t.Fatalf("unexpected elapsed values after trim: %#v", trimmed)
	}
	if trimmed[0].ExecTotal != 7 || trimmed[1].ExecTotal != 12 {
		t.Fatalf("unexpected trimmed rows: %#v", trimmed)
	}
}

func TestRunCompareProducesAggregateArtifacts(t *testing.T) {
	dir := t.TempDir()
	input1 := filepath.Join(dir, "run1.csv")
	input2 := filepath.Join(dir, "run2.csv")
	outdir := filepath.Join(dir, "aggregate")

	writeCSV := func(path string, rows []csvRow) {
		t.Helper()
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		w := csv.NewWriter(f)
		if err := w.Write(csvHeader()); err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if err := w.Write(row.toCSV()); err != nil {
				t.Fatal(err)
			}
		}
		w.Flush()
		_ = f.Close()
		if err := w.Error(); err != nil {
			t.Fatal(err)
		}
	}

	writeCSV(input1, []csvRow{
		{TimestampUnix: 1, ElapsedSec: 0, ExecTotal: 10, ExecPerMin: 120, Coverage: 100, Corpus: 5, RawSignal: 10, RawCover: 20, PostSignal: 10, PostCover: 20, RunnerLastCoverRecs: 2, PTLastTraceSize: 64, PTLastBBAfter: 10, SYZCovLastRecords: 2, NTFSTriage: 1},
		{TimestampUnix: 2, ElapsedSec: 5, ExecTotal: 20, ExecPerMin: 140, Coverage: 150, Corpus: 6, RawSignal: 12, RawCover: 24, PostSignal: 12, PostCover: 24, RunnerLastCoverRecs: 3, PTLastTraceSize: 80, PTLastBBAfter: 12, SYZCovLastRecords: 3, NTFSTriage: 2},
	})
	writeCSV(input2, []csvRow{
		{TimestampUnix: 1, ElapsedSec: 0, ExecTotal: 8, ExecPerMin: 100, Coverage: 90, Corpus: 4, RawSignal: 9, RawCover: 18, PostSignal: 9, PostCover: 18, RunnerLastCoverRecs: 1, PTLastTraceSize: 60, PTLastBBAfter: 9, SYZCovLastRecords: 1, NTFSTriage: 1},
		{TimestampUnix: 2, ElapsedSec: 5, ExecTotal: 18, ExecPerMin: 130, Coverage: 140, Corpus: 5, RawSignal: 11, RawCover: 22, PostSignal: 11, PostCover: 22, RunnerLastCoverRecs: 2, PTLastTraceSize: 70, PTLastBBAfter: 11, SYZCovLastRecords: 2, NTFSTriage: 3},
	})

	if err := runCompare([]string{
		"--inputs", input1 + "," + input2,
		"--outdir", outdir,
		"--title", "aggregate-test",
		"--step-sec", "5",
	}); err != nil {
		t.Fatalf("runCompare failed: %v", err)
	}
	for _, name := range []string{
		"aggregate_coverage_corpus.svg",
		"aggregate_throughput.svg",
		"aggregate_signal_cover.svg",
		"aggregate_pt_trace.svg",
		"aggregate_summary.json",
		"final_metrics.csv",
		"index.html",
	} {
		data, err := os.ReadFile(filepath.Join(outdir, name))
		if err != nil {
			t.Fatalf("missing artifact %s: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("artifact %s is empty", name)
		}
	}
	metricsCSV, err := os.ReadFile(filepath.Join(outdir, "final_metrics.csv"))
	if err != nil {
		t.Fatalf("failed to read final_metrics.csv: %v", err)
	}
	if !strings.Contains(string(metricsCSV), "exec_total") {
		t.Fatalf("final_metrics.csv missing exec_total row: %s", metricsCSV)
	}
}

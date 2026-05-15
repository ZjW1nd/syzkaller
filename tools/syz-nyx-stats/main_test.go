package main

import (
	"encoding/csv"
	"encoding/json"
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
		"2026/05/07 13:30:27 exec gen=12 exec fuzz=34 exec candidate=5 exec triage=8 exec collide=2 ",
		"2026/05/07 13:30:27 win_tmpl_gen=5 win_tmpl_corpus=3 win_tmpl_collide=2 ",
		"2026/05/07 13:30:27 win_rc_try=7 win_rc_hit=4 win_rc_no_candidates=2 win_rc_zero_score=1 ",
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
	if row.ExecGen != 12 || row.ExecFuzz != 34 || row.ExecCandidate != 5 ||
		row.ExecTriage != 8 || row.ExecCollide != 2 {
		t.Fatalf("bad exec mode counts: %#v", row)
	}
	if row.NTFSTriage != 1 || row.CorpusSaves != 1 {
		t.Fatalf("bad triage/corpus counts: %#v", row)
	}
	if row.WinTemplateGen != 5 || row.WinTemplateCorpus != 3 || row.WinTemplateCollide != 2 {
		t.Fatalf("bad template counts: %#v", row)
	}
	if row.WinResourceCentricTry != 7 || row.WinResourceCentricHit != 4 ||
		row.WinResourceCentricNoCandidates != 2 || row.WinResourceCentricZeroScore != 1 {
		t.Fatalf("bad resource-centric counts: %#v", row)
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
		"exec_mix.svg",
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
		"aggregate_exec_mix.svg",
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

func TestRunCollideSummaryProducesJSON(t *testing.T) {
	dir := t.TempDir()
	managerLog := filepath.Join(dir, "manager.log")
	output := filepath.Join(dir, "collide_summary.json")
	lines := []string{
		"2026/05/12 09:32:01 windows collide result: origin=collide:gen active=[3:send$inet_tcp(sig=2824 cover=3381 err=0) 4:recv$inet_tcp(sig=1152 cover=1252 err=0)]",
		"2026/05/12 09:32:03 windows collide result: origin=collide:gen active=[3:send$inet_tcp(sig=2824 cover=3381 err=0) 4:recv$inet_tcp(sig=1152 cover=1252 err=0)]",
		"2026/05/12 10:07:16 windows collide result: origin=collide:fuzz active=[5:getsockopt$int_accept(sig=2398 cover=2694 err=0)]",
	}
	if err := os.WriteFile(managerLog, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runCollideSummary([]string{"--manager-log", managerLog, "--output", output}); err != nil {
		t.Fatalf("runCollideSummary failed: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read collide summary: %v", err)
	}
	var rows []collideSummaryEntry
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("unmarshal collide summary: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Origin != "collide:gen" || rows[0].Count != 2 {
		t.Fatalf("unexpected first row: %+v", rows[0])
	}
}

func TestRunCollideQualityProducesJSON(t *testing.T) {
	dir := t.TempDir()
	managerLog := filepath.Join(dir, "manager.log")
	output := filepath.Join(dir, "collide_quality.json")
	lines := []string{
		"2026/05/12 09:32:01 windows triage job queued: origin=collide:gen calls=[send$inet_tcp] flags=0x0 attempt=0 status=Success",
		"2026/05/12 09:32:01 windows collide result: origin=collide:gen active=[3:send$inet_tcp(sig=2824 cover=3381 err=0) 4:recv$inet_tcp(sig=1152 cover=1252 err=0)]",
		"2026/05/12 09:32:02 windows corpus save: origin=collide:gen call=3 name=send$inet_tcp stable_signal=100 new_stable=10 cover=20 raw_cover=0",
	}
	if err := os.WriteFile(managerLog, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runCollideQuality([]string{"--manager-log", managerLog, "--output", output}); err != nil {
		t.Fatalf("runCollideQuality failed: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read collide quality: %v", err)
	}
	var rows []collideQualityEntry
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("unmarshal collide quality: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].Origin != "collide:gen" || rows[0].Count != 1 {
		t.Fatalf("unexpected row: %+v", rows[0])
	}
	if len(rows[0].TriageCalls) != 1 || rows[0].TriageCalls[0] != "send$inet_tcp" {
		t.Fatalf("unexpected triage calls: %+v", rows[0].TriageCalls)
	}
	if len(rows[0].CorpusSaves) != 1 || rows[0].CorpusSaves[0] != "send$inet_tcp" {
		t.Fatalf("unexpected corpus saves: %+v", rows[0].CorpusSaves)
	}
}

func TestRunCollideQualityKeepsSameOriginEventsSeparated(t *testing.T) {
	dir := t.TempDir()
	managerLog := filepath.Join(dir, "manager.log")
	output := filepath.Join(dir, "collide_quality.json")
	lines := []string{
		"2026/05/12 09:32:01 windows triage job queued: origin=collide:gen calls=[bind$inet_tcp listen$inet_tcp] flags=0x0 attempt=0 status=Success",
		"2026/05/12 09:32:01 windows collide result: origin=collide:gen active=[1:bind$inet_tcp(sig=10 cover=20 err=0) 2:listen$inet_tcp(sig=30 cover=40 err=0)]",
		"2026/05/12 09:32:02 windows triage job queued: origin=collide:gen calls=[send$inet_accept] flags=0x0 attempt=0 status=Success",
		"2026/05/12 09:32:02 windows collide result: origin=collide:gen active=[5:WSARecvEx$inet_accept(sig=100 cover=200 err=0) 6:send$inet_accept(sig=300 cover=400 err=0)]",
		"2026/05/12 09:32:03 windows corpus save: origin=collide:gen call=6 name=send$inet_accept stable_signal=10 new_stable=5 cover=8 raw_cover=0",
	}
	if err := os.WriteFile(managerLog, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runCollideQuality([]string{"--manager-log", managerLog, "--output", output}); err != nil {
		t.Fatalf("runCollideQuality failed: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read collide quality: %v", err)
	}
	var rows []collideQualityEntry
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("unmarshal collide quality: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	var shallow, deep *collideQualityEntry
	for i := range rows {
		row := &rows[i]
		switch {
		case strings.Contains(row.ActiveCalls, "WSARecvEx$inet_accept"):
			deep = row
		case strings.Contains(row.ActiveCalls, "bind$inet_tcp"):
			shallow = row
		}
	}
	if shallow == nil || deep == nil {
		t.Fatalf("failed to classify collide quality rows: %+v", rows)
	}
	if got := strings.Join(shallow.TriageCalls, ","); got != "bind$inet_tcp,listen$inet_tcp" {
		t.Fatalf("shallow triage calls=%q", got)
	}
	if len(shallow.CorpusSaves) != 0 {
		t.Fatalf("shallow corpus saves should stay empty, got %+v", shallow.CorpusSaves)
	}
	if got := strings.Join(deep.TriageCalls, ","); got != "send$inet_accept" {
		t.Fatalf("deep triage calls=%q", got)
	}
	if got := strings.Join(deep.CorpusSaves, ","); got != "send$inet_accept" {
		t.Fatalf("deep corpus saves=%q", got)
	}
}

func TestRunCollideOwnersAggregatesAcrossInputs(t *testing.T) {
	dir := t.TempDir()
	in1 := filepath.Join(dir, "one.json")
	in2 := filepath.Join(dir, "two.json")
	out := filepath.Join(dir, "owners.json")
	rows1 := []collideQualityEntry{
		{Origin: "collide:gen", ActiveCalls: "shape1", Count: 1, TriageCalls: []string{"getsockopt$int_accept"}},
		{Origin: "collide:triage", ActiveCalls: "shape2", Count: 1, TriageCalls: []string{"getsockopt$int_accept"}},
	}
	rows2 := []collideQualityEntry{
		{Origin: "collide:gen", ActiveCalls: "shape3", Count: 1, TriageCalls: []string{"WSARecvEx$inet_accept"}},
		{Origin: "collide:triage", ActiveCalls: "shape4", Count: 1, TriageCalls: []string{"getsockopt$int_accept"}},
	}
	for path, rows := range map[string][]collideQualityEntry{in1: rows1, in2: rows2} {
		data, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := runCollideOwners([]string{"--inputs", in1 + "," + in2, "--output", out}); err != nil {
		t.Fatalf("runCollideOwners failed: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read owners: %v", err)
	}
	var rows []collideOwnerEntry
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("unmarshal owners: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	if rows[0].Origin != "collide:triage" || rows[0].Owner != "getsockopt$int_accept" || rows[0].Count != 2 {
		t.Fatalf("unexpected first row: %+v", rows[0])
	}
}

func TestRunCollideQualityUsesTraceIDForPreciseAttribution(t *testing.T) {
	dir := t.TempDir()
	managerLog := filepath.Join(dir, "manager.log")
	output := filepath.Join(dir, "collide_quality.json")
	lines := []string{
		"2026/05/12 09:32:01 windows triage job queued: origin=collide:gen trace=collide-1 calls=[bind$inet_tcp listen$inet_tcp] flags=0x0 attempt=0 status=Success",
		"2026/05/12 09:32:01 windows collide result: origin=collide:gen trace=collide-1 active=[1:bind$inet_tcp(sig=10 cover=20 err=0) 2:listen$inet_tcp(sig=30 cover=40 err=0)]",
		"2026/05/12 09:32:02 windows triage job queued: origin=collide:gen trace=collide-2 calls=[send$inet_accept] flags=0x0 attempt=0 status=Success",
		"2026/05/12 09:32:02 windows collide result: origin=collide:gen trace=collide-2 active=[5:WSARecvEx$inet_accept(sig=100 cover=200 err=0) 6:send$inet_accept(sig=300 cover=400 err=0)]",
		"2026/05/12 09:32:03 windows corpus save: origin=collide:gen trace=collide-2 call=6 name=send$inet_accept stable_signal=10 new_stable=5 cover=8 raw_cover=0",
	}
	if err := os.WriteFile(managerLog, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runCollideQuality([]string{"--manager-log", managerLog, "--output", output}); err != nil {
		t.Fatalf("runCollideQuality failed: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read collide quality: %v", err)
	}
	var rows []collideQualityEntry
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("unmarshal collide quality: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	var shallow, deep *collideQualityEntry
	for i := range rows {
		row := &rows[i]
		switch {
		case strings.Contains(row.ActiveCalls, "WSARecvEx$inet_accept"):
			deep = row
		case strings.Contains(row.ActiveCalls, "bind$inet_tcp"):
			shallow = row
		}
	}
	if shallow == nil || deep == nil {
		t.Fatalf("failed to classify collide quality rows: %+v", rows)
	}
	if got := strings.Join(shallow.TriageCalls, ","); got != "bind$inet_tcp,listen$inet_tcp" {
		t.Fatalf("shallow triage calls=%q", got)
	}
	if len(shallow.CorpusSaves) != 0 {
		t.Fatalf("shallow corpus saves should stay empty, got %+v", shallow.CorpusSaves)
	}
	if got := strings.Join(deep.TriageCalls, ","); got != "send$inet_accept" {
		t.Fatalf("deep triage calls=%q", got)
	}
	if got := strings.Join(deep.CorpusSaves, ","); got != "send$inet_accept" {
		t.Fatalf("deep corpus saves=%q", got)
	}
}

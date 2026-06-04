package main

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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
		"2026/05/07 13:30:27 candidates=16 corpus=54 coverage=9913 exec candidate=5 (3/min) exec collide=2 (1/min) exec fuzz=34 (20/min) exec gen=12 (7/min) exec total=604 (362/min) exec triage=8 (4/min) ",
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

func TestHandleManagerLineAcceptsHourlyExecRate(t *testing.T) {
	c := &collector{}
	c.handleManagerLine("2026/05/31 00:45:06 candidates=0 corpus=5 coverage=11284 exec candidate=16 (77/hour) exec collide=4 (19/hour) exec fuzz=0 (0/hour) exec gen=0 (0/hour) exec total=91 (442/hour) exec triage=46 (223/hour)")
	if c.state.execTotal != 91 || c.state.execPerMin != 8 ||
		c.state.coverage != 11284 || c.state.corpus != 5 {
		t.Fatalf("bad hourly manager stats: %+v", c.state)
	}
}

func TestAFDCallCategoryClassifiesAcceptRecvSendPending(t *testing.T) {
	for _, name := range []string{
		"WSARecv$accept_pending",
		"WSASend$accept_pending",
		"CreateIoCompletionPort$accept_recv_pending",
		"CreateIoCompletionPort$accept_send_pending",
		"WSAGetOverlappedResult$accept_recv_pending",
		"WSAGetOverlappedResult$accept_send_pending",
		"CancelIoEx$accept_recv_pending",
		"CancelIoEx$accept_send_pending",
		"CancelIo$accept_recv_pending",
		"CancelIo$accept_send_pending",
		"closesocket$accept_pending",
		"closesocket$accept_recv_pending",
		"closesocket$accept_send_pending",
		"WSARecv$tcp_pending",
		"WSASend$tcp_pending",
		"CreateIoCompletionPort$tcp_recv_pending",
		"CreateIoCompletionPort$tcp_send_pending",
		"WSAGetOverlappedResult$tcp_recv_pending",
		"WSAGetOverlappedResult$tcp_send_pending",
		"CancelIoEx$tcp_recv_pending",
		"CancelIoEx$tcp_send_pending",
		"CancelIo$tcp_recv_pending",
		"CancelIo$tcp_send_pending",
		"closesocket$tcp_recv_pending",
		"closesocket$tcp_send_pending",
		"ConnectEx$inet_tcp_pending",
		"CreateIoCompletionPort$connect_pending",
		"WSAGetOverlappedResult$connect_pending",
		"CancelIoEx$connect_pending",
		"CancelIo$connect_pending",
		"closesocket$connect_pending",
		"WSAEventSelect$tcp",
		"WSAEnumNetworkEvents$tcp",
		"WSAEventSelect$accept",
		"WSAEnumNetworkEvents$accept",
	} {
		if got := afdCallCategory(name); got != "async_completion" {
			t.Fatalf("%s category=%q, want async_completion", name, got)
		}
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

func TestRunAFDCompareAggregatesSummaries(t *testing.T) {
	dir := t.TempDir()
	input1 := filepath.Join(dir, "afd1.json")
	input2 := filepath.Join(dir, "afd2.json")
	output := filepath.Join(dir, "afd_aggregate.json")
	writeSummary := func(path string, summary afdSummary) {
		t.Helper()
		data, err := json.Marshal(summary)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeSummary(input1, afdSummary{
		AFDModuleHitRatio:      0.75,
		DeepTriageEvents:       3,
		DeepCorpusSaves:        2,
		DeepCollideActiveCalls: 4,
		SetupTriageEvents:      1,
		SetupCorpusSaves:       1,
		ModuleCoverClasses:     []afdModuleCoverSummary{{Class: "afd", Requests: 3, RequestRatio: 0.75, ModuleRecords: 3, ModuleRecordRatio: 0.75, PCs: 30, PCRatio: 0.75}, {Class: "ntos_only", Requests: 1, RequestRatio: 0.25, ModuleRecords: 1, ModuleRecordRatio: 0.25, PCs: 4, PCRatio: 0.25}},
		CallStats:              []afdCallSummary{{Name: "WSARecv$accept", Category: "accepted_data", TriageEvents: 2, CorpusSaves: 1, ExecResults: 2, ExecRawSignal: 9, ExecRawCover: 11}, {Name: "CancelIoEx$socket", Category: "async_completion", TriageEvents: 1, CollideActive: 3}},
		CategoryStats:          []afdCategorySummary{{Category: "accepted_data", TriageEvents: 2, CorpusSaves: 1, ExecResults: 2, ExecRawSignal: 9, ExecRawCover: 11}, {Category: "async_completion", TriageEvents: 1, CollideActive: 3}},
		Runner:                 afdRunnerSummary{HangedResults: 1, RestartScheduled: 1, RestartCompleted: 1},
		RestartReasons:         []afdRestartReason{{Reason: "request 7 hanged", Scheduled: 1}},
		CollideQuality: []collideQualityEntry{{
			Origin:           "collide:gen",
			ActiveCalls:      "5:WSARecv$accept(sig=1 cover=2 err=0) 6:CancelIoEx$socket(sig=3 cover=4 err=995)",
			Count:            1,
			ActiveCallNames:  []string{"CancelIoEx$socket", "WSARecv$accept"},
			ActiveCategories: []string{"accepted_data", "async_completion"},
			HasDeepActive:    true,
			TriageCalls:      []string{"WSARecv$accept"},
			CorpusSaves:      []string{"WSARecv$accept"},
			DeepTriageCalls:  []string{"WSARecv$accept"},
			DeepCorpusSaves:  []string{"WSARecv$accept"},
		}},
		FailureEvents: []afdFailureEvent{{
			Kind:       "hang",
			Reason:     "request hanged",
			Count:      1,
			RequestIDs: []int{7},
			Programs:   []afdFailureProgram{{SHA1: "run1", Calls: 8, Call0: "WSARecv$accept", Category: "accepted_data", Count: 1, RequestIDs: []int{7}}},
		}},
	})
	writeSummary(input2, afdSummary{
		AFDModuleHitRatio:      0.25,
		DeepTriageEvents:       1,
		DeepCorpusSaves:        1,
		DeepCollideActiveCalls: 2,
		SetupTriageEvents:      3,
		ModuleCoverClasses:     []afdModuleCoverSummary{{Class: "afd", Requests: 1, RequestRatio: 1.0 / 3.0, ModuleRecords: 1, ModuleRecordRatio: 1, PCs: 10, PCRatio: 1}, {Class: "unknown_or_user", Requests: 2, RequestRatio: 2.0 / 3.0}},
		CallStats:              []afdCallSummary{{Name: "WSARecv$accept", Category: "accepted_data", TriageEvents: 1, CorpusSaves: 1, ExecResults: 1, ExecRawSignal: 5, ExecRawCover: 6, ExecComps: 2}, {Name: "bind$inet_tcp", Category: "setup", TriageEvents: 3}},
		CategoryStats:          []afdCategorySummary{{Category: "accepted_data", TriageEvents: 1, CorpusSaves: 1, ExecResults: 1, ExecRawSignal: 5, ExecRawCover: 6, ExecComps: 2}, {Category: "setup", TriageEvents: 3}},
		Runner:                 afdRunnerSummary{RestartScheduled: 2},
		RestartReasons:         []afdRestartReason{{Reason: "request 7 hanged", Scheduled: 1}, {Reason: "manual", Scheduled: 1}},
		CollideQuality: []collideQualityEntry{
			{
				Origin:           "collide:gen",
				ActiveCalls:      "5:WSARecv$accept(sig=1 cover=2 err=0) 6:CancelIoEx$socket(sig=3 cover=4 err=995)",
				Count:            2,
				ActiveCallNames:  []string{"CancelIoEx$socket", "WSARecv$accept"},
				ActiveCategories: []string{"accepted_data", "async_completion"},
				HasDeepActive:    true,
				TriageCalls:      []string{"CancelIoEx$socket"},
				DeepTriageCalls:  []string{"CancelIoEx$socket"},
			},
			{
				Origin:           "collide:gen",
				ActiveCalls:      "1:bind$inet_tcp(sig=1 cover=2 err=0)",
				Count:            1,
				ActiveCallNames:  []string{"bind$inet_tcp"},
				ActiveCategories: []string{"setup"},
				HasSetupActive:   true,
				TriageCalls:      []string{"bind$inet_tcp"},
				SetupTriageCalls: []string{"bind$inet_tcp"},
			},
		},
		FailureEvents: []afdFailureEvent{
			{
				Kind:       "hang",
				Reason:     "request hanged",
				Count:      1,
				RequestIDs: []int{7},
				Programs:   []afdFailureProgram{{SHA1: "run2", Calls: 8, Call0: "CancelIoEx$socket", Category: "async_completion", Count: 1, RequestIDs: []int{7}}},
			},
			{
				Kind:       "request_failed",
				Reason:     "EOF",
				Count:      1,
				RequestIDs: []int{8},
				Programs:   []afdFailureProgram{{SHA1: "eof", Calls: 16, Call0: "WSAStartup", Category: "helper", Count: 1, RequestIDs: []int{8}}},
			},
		},
	})

	if err := runAFDCompare([]string{"--inputs", input1 + "," + input2, "--output", output, "--title", "afd-agg"}); err != nil {
		t.Fatalf("runAFDCompare failed: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read aggregate: %v", err)
	}
	var summary afdAggregateSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("unmarshal aggregate: %v", err)
	}
	if summary.Title != "afd-agg" || summary.RunCount != 2 || len(summary.Runs) != 2 {
		t.Fatalf("unexpected aggregate header: %+v", summary)
	}
	if summary.AFDModuleHitRatio.Mean != 0.5 || summary.AFDModuleHitRatio.Min != 0.25 ||
		summary.AFDModuleHitRatio.Max != 0.75 {
		t.Fatalf("unexpected AFD hit ratio summary: %+v", summary.AFDModuleHitRatio)
	}
	if summary.DeepTriageEvents.Mean != 2 || summary.SetupTriageEvents.Mean != 2 {
		t.Fatalf("unexpected owner metric summaries: deep=%+v setup=%+v", summary.DeepTriageEvents, summary.SetupTriageEvents)
	}
	if got := aggregateCoverClass(summary.ModuleCoverClasses, "afd"); got == nil ||
		got.RequestsSum != 4 || got.RequestsMean != 2 || got.PCsSum != 40 ||
		!floatClose(got.RequestRatioMean, (0.75+1.0/3.0)/2) ||
		!floatClose(got.ModuleRecordRatioMean, 0.875) ||
		!floatClose(got.PCRatioMean, 0.875) {
		t.Fatalf("unexpected aggregate afd class: %+v classes=%+v", got, summary.ModuleCoverClasses)
	}
	if got := aggregateCoverClass(summary.ModuleCoverClasses, "unknown_or_user"); got == nil ||
		got.RequestsSum != 2 || got.RequestsMean != 1 ||
		!floatClose(got.RequestRatioMean, 1.0/3.0) {
		t.Fatalf("unexpected aggregate unknown class: %+v classes=%+v", got, summary.ModuleCoverClasses)
	}
	if len(summary.TopCalls) == 0 || summary.TopCalls[0].Name != "WSARecv$accept" ||
		summary.TopCalls[0].CorpusSaves != 2 || summary.TopCalls[0].TriageEvents != 3 ||
		summary.TopCalls[0].ExecRawSignal != 14 || summary.TopCalls[0].ExecComps != 2 {
		t.Fatalf("unexpected top calls: %+v", summary.TopCalls)
	}
	if len(summary.TopCategories) == 0 || summary.TopCategories[0].Category != "accepted_data" ||
		summary.TopCategories[0].CorpusSaves != 2 || summary.TopCategories[0].ExecRawCover != 17 {
		t.Fatalf("unexpected top categories: %+v", summary.TopCategories)
	}
	if got := ownerSummary(summary.OwnerStats, "deep"); got == nil ||
		!slices.Equal(got.Categories, []string{"accepted_data", "async_completion"}) ||
		got.TriageEvents != 4 ||
		got.CorpusSaves != 2 ||
		got.CollideActive != 3 ||
		got.ExecResults != 3 ||
		got.ExecRawSignal != 14 ||
		got.ExecRawCover != 17 ||
		got.ExecComps != 2 {
		t.Fatalf("unexpected aggregate deep owner stats: %+v owners=%+v", got, summary.OwnerStats)
	}
	if got := ownerSummary(summary.OwnerStats, "setup_or_helper"); got == nil ||
		!slices.Equal(got.Categories, []string{"setup"}) ||
		got.TriageEvents != 3 {
		t.Fatalf("unexpected aggregate setup owner stats: %+v owners=%+v", got, summary.OwnerStats)
	}
	if len(summary.CollideQualitySummary) != 2 ||
		summary.CollideQualitySummary[0].Origin != "collide:gen" ||
		summary.CollideQualitySummary[0].RunCount != 2 ||
		summary.CollideQualitySummary[0].Count != 3 ||
		!summary.CollideQualitySummary[0].HasDeepActive ||
		summary.CollideQualitySummary[0].HasSetupActive ||
		!slices.Equal(summary.CollideQualitySummary[0].ActiveCategories, []string{"accepted_data", "async_completion"}) ||
		!slices.Equal(summary.CollideQualitySummary[0].TriageCalls, []string{"CancelIoEx$socket", "WSARecv$accept"}) ||
		!slices.Equal(summary.CollideQualitySummary[0].CorpusSaves, []string{"WSARecv$accept"}) ||
		!slices.Equal(summary.CollideQualitySummary[0].DeepTriageCalls, []string{"CancelIoEx$socket", "WSARecv$accept"}) ||
		!slices.Equal(summary.CollideQualitySummary[0].DeepCorpusSaves, []string{"WSARecv$accept"}) {
		t.Fatalf("unexpected aggregate collide quality row 0: %+v", summary.CollideQualitySummary)
	}
	if summary.CollideQualitySummary[1].Count != 1 ||
		!summary.CollideQualitySummary[1].HasSetupActive ||
		summary.CollideQualitySummary[1].HasDeepActive ||
		!slices.Equal(summary.CollideQualitySummary[1].SetupTriageCalls, []string{"bind$inet_tcp"}) {
		t.Fatalf("unexpected aggregate collide quality row 1: %+v", summary.CollideQualitySummary)
	}
	if len(summary.RestartReasons) != 2 || summary.RestartReasons[0].Reason != "request 7 hanged" ||
		summary.RestartReasons[0].Scheduled != 2 {
		t.Fatalf("unexpected restart reasons: %+v", summary.RestartReasons)
	}
	if len(summary.FailureEvents) != 2 ||
		summary.FailureEvents[0].Kind != "hang" ||
		summary.FailureEvents[0].Count != 2 ||
		!slices.Equal(summary.FailureEvents[0].RequestIDs, []int{7}) ||
		len(summary.FailureEvents[0].Programs) != 2 ||
		summary.FailureEvents[0].Programs[0].Call0 != "WSARecv$accept" ||
		summary.FailureEvents[0].Programs[1].Call0 != "CancelIoEx$socket" ||
		summary.FailureEvents[1].Kind != "request_failed" ||
		!slices.Equal(summary.FailureEvents[1].RequestIDs, []int{8}) ||
		len(summary.FailureEvents[1].Programs) != 1 ||
		summary.FailureEvents[1].Programs[0].Call0 != "WSAStartup" {
		t.Fatalf("unexpected failure events: %+v", summary.FailureEvents)
	}
	if len(summary.FailureCategoryStats) != 3 ||
		summary.FailureCategoryStats[0].Category != "accepted_data" ||
		summary.FailureCategoryStats[0].Count != 1 ||
		summary.FailureCategoryStats[0].RequestCount != 1 ||
		summary.FailureCategoryStats[0].Hangs != 1 ||
		!summary.FailureCategoryStats[0].Deep ||
		summary.FailureCategoryStats[1].Category != "async_completion" ||
		summary.FailureCategoryStats[1].Count != 1 ||
		summary.FailureCategoryStats[1].Hangs != 1 ||
		!summary.FailureCategoryStats[1].Deep ||
		summary.FailureCategoryStats[2].Category != "helper" ||
		summary.FailureCategoryStats[2].RequestFailures != 1 ||
		!summary.FailureCategoryStats[2].SetupOrHelper {
		t.Fatalf("unexpected failure category stats: %+v", summary.FailureCategoryStats)
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
	if !slices.Equal(rows[0].ActiveCallNames, []string{"recv$inet_tcp", "send$inet_tcp"}) ||
		!slices.Equal(rows[0].ActiveCategories, []string{"connected_data"}) ||
		!rows[0].HasDeepActive ||
		len(rows[0].DeepTriageCalls) != 1 || rows[0].DeepTriageCalls[0] != "send$inet_tcp" ||
		len(rows[0].DeepCorpusSaves) != 1 || rows[0].DeepCorpusSaves[0] != "send$inet_tcp" {
		t.Fatalf("unexpected collide quality deep attribution: %+v", rows[0])
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
	if !deep.HasDeepActive || deep.HasSetupActive ||
		!slices.Equal(deep.ActiveCategories, []string{"accepted_data"}) ||
		!slices.Equal(deep.DeepTriageCalls, []string{"send$inet_accept"}) ||
		!slices.Equal(deep.DeepCorpusSaves, []string{"send$inet_accept"}) {
		t.Fatalf("unexpected deep collide attribution: %+v", deep)
	}
	if !shallow.HasSetupActive || shallow.HasDeepActive ||
		!slices.Equal(shallow.ActiveCategories, []string{"setup"}) ||
		!slices.Equal(shallow.SetupTriageCalls, []string{"bind$inet_tcp", "listen$inet_tcp"}) {
		t.Fatalf("unexpected shallow collide attribution: %+v", shallow)
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

func TestRunAFDSummaryClassifiesDeepAndSetupOwners(t *testing.T) {
	dir := t.TempDir()
	managerLog := filepath.Join(dir, "manager.log")
	runnerLog := filepath.Join(dir, "runner.log")
	output := filepath.Join(dir, "afd_summary.json")
	managerLines := []string{
		"2026/05/12 09:31:59 candidates=0 corpus=6 coverage=15193 exec candidate=14 (2/min) exec collide=0 (0/min) exec fuzz=0 (0/min) exec gen=0 (0/min) exec total=66 (10/min) exec triage=36 (5/min)",
		"2026/05/12 09:32:00 win_tmpl_gen=11 win_tmpl_corpus=7 win_tmpl_collide=3 win_rc_try=5 win_rc_hit=2 win_rc_no_candidates=1 win_rc_zero_score=4",
		"2026/05/12 09:32:01 windows triage job queued: origin=collide:gen calls=[bind$inet_tcp send$inet_accept] flags=0x0 attempt=0 status=Success",
		"2026/05/12 09:32:02 windows triage: call=5 name=send$inet_accept signal=10 cover=20 prio=3 new=4 errno=0 flags=0x0",
		"2026/05/12 09:32:03 windows triage: call=2 name=listen$inet_tcp signal=1 cover=2 prio=1 new=1 errno=0 flags=0x0",
		"2026/05/12 09:32:03 windows triage: call=8 name=CancelIoEx$socket signal=7 cover=9 prio=5 new=3 errno=0 flags=0x0",
		"2026/05/12 09:32:05 windows corpus save: call=2 name=listen$inet_tcp stable_signal=2 new_stable=1 cover=3 raw_cover=0",
		"2026/05/12 09:32:06 windows collide result: origin=collide:gen active=[2:listen$inet_tcp(sig=1 cover=2 err=0) 5:send$inet_accept(sig=10 cover=20 err=0) 6:TransmitPackets$inet_accept(sig=5 cover=6 err=0)]",
		"2026/05/12 09:32:06 windows corpus save: origin=collide:gen call=5 name=send$inet_accept stable_signal=10 new_stable=5 cover=8 raw_cover=3",
		"2026/05/12 09:32:07 rpcserver exec result: id=44 calls=7 raw_nonempty=0 raw_signal=0 raw_cover=0 post_nonempty=0 post_signal=0 post_cover=0 hanged=true",
	}
	runnerLines := []string{
		"2026/05/12 09:32:01 runner exec complete: id=1 calls=5 cover_records=0",
		"2026/05/12 09:32:02 runner exec complete: id=2 calls=6 cover_records=4",
		"2026/05/12 09:32:02 runner exec complete: id=3 calls=7 cover_records=3",
		"2026/05/12 09:32:02 runner exec complete: id=4 calls=4 cover_records=2",
		"2026/05/12 09:32:02 runner prime complete: id=6 calls=2 cover_records=1",
		"[+00001.000000] [QEMU-NYX] Warning: nyx module range submitted slot=0 target=afd.sys name=afd.sys base=0xfffff80600000000 end=0xfffff80600100000 size=0x100000",
		"[+00001.000001] [QEMU-NYX] Warning: nyx module range submitted slot=1 target=ntoskrnl.exe name=ntoskrnl.exe base=0xfffff80000000000 end=0xfffff80000100000 size=0x100000",
		"[+00001.000002] [QEMU-NYX] Warning: nyx module range submitted slot=2 target=ntfs.sys name=ntfs.sys base=0xfffff80700000000 end=0xfffff80700100000 size=0x100000",
		"2026/05/12 09:32:02 runner module coverage: id=2 slot=0 records=2 pcs=6",
		"2026/05/12 09:32:02 runner module coverage: id=2 slot=1 records=1 pcs=4",
		"2026/05/12 09:32:02 runner call module coverage: id=2 call=5 name=WSARecv$accept slot=0 records=2 pcs=6",
		"2026/05/12 09:32:02 runner call module coverage: id=2 call=1 name=accept$inet_tcp slot=1 records=1 pcs=4",
		"2026/05/12 09:32:02 runner call feedback: id=2 call=5 name=WSARecv$accept signal=12 cover=13 comps=1 errno=0",
		"2026/05/12 09:32:03 runner module coverage: id=3 slot=0 records=1 pcs=2",
		"2026/05/12 09:32:03 runner call module coverage: id=3 call=4 name=CancelIoEx$socket slot=0 records=1 pcs=2",
		"2026/05/12 09:32:03 runner call feedback: id=3 call=4 name=CancelIoEx$socket signal=7 cover=9 comps=0 errno=995",
		"2026/05/12 09:32:03 runner module coverage: id=4 slot=2 records=1 pcs=5",
		"2026/05/12 09:32:03 runner call module coverage: id=4 call=3 name=NtReadFile slot=2 records=1 pcs=5",
		"2026/05/12 09:32:03 runner exec complete: id=5 calls=3 cover_records=1",
		"2026/05/12 09:32:03 runner exec program: id=6 sha1=cafe01 calls=5 call0=socket$listener_tcp deep0=WSARecv$accept vnet=1 arg0=0x2",
		"2026/05/12 09:32:03 runner module coverage: id=6 slot=0 records=1 pcs=1",
		"2026/05/12 09:32:03 runner exec program: id=7 sha1=cafe02 calls=3 call0=socket$inet_tcp arg0=0x2",
		"2026/05/12 09:32:03 runner exec complete: id=7 calls=3 cover_records=0",
		"2026/05/12 09:32:03 runner exec program: id=44 sha1=feed44 calls=8 call0=WSARecv$accept arg0=0xffffffffffffffff",
		"2026/05/12 09:32:03 runner scheduling VM restart: request 44 hanged",
		"2026/05/12 09:32:04 runner restarting VM: recovering from previous hanged request",
		"2026/05/12 09:32:05 runner exec program: id=45 sha1=badc0de calls=8 call0=socket$listener_tcp deep0=CancelIoEx$socket arg0=0x2",
		"2026/05/12 09:32:05 runner scheduling VM restart: request 45 failed: nyx crash: WINDOWS BUGCHECK DIRECT DUMP IO",
		"SYZ-NYX-WINDOWS-CRASH: WINDOWS BUGCHECK DIRECT DUMP IO",
		"last executing request: id=45",
		"last executing program:",
		"sha1=deadbeef calls=8 call0=socket$listener_tcp deep0=CancelIoEx$socket",
		"END SYZ-NYX-WINDOWS-CRASH",
		"2026/05/12 09:32:06 [FATAL] runner loop failed: nyx crash: WINDOWS BUGCHECK DIRECT DUMP IO",
		"2026/05/12 09:32:07 [FATAL] failed to start Nyx VM: guest abort during init: ToPA allocation failure. Check kernel logs.",
	}
	if err := os.WriteFile(managerLog, []byte(strings.Join(managerLines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runnerLog, []byte(strings.Join(runnerLines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runAFDSummary([]string{"--manager-log", managerLog, "--runner-log", runnerLog, "--output", output}); err != nil {
		t.Fatalf("runAFDSummary failed: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read afd summary: %v", err)
	}
	var summary afdSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("unmarshal afd summary: %v", err)
	}
	if summary.Manager.Coverage != 15193 || summary.Manager.Corpus != 6 ||
		summary.Manager.ExecTotal != 66 || summary.Manager.ExecCandidate != 14 ||
		summary.Manager.ExecTriage != 36 || summary.Manager.ExecPerMin != 10 {
		t.Fatalf("unexpected manager summary: %+v", summary.Manager)
	}
	if summary.Manager.WinTemplateGen != 11 || summary.Manager.WinResourceCentricZeroScore != 4 {
		t.Fatalf("unexpected manager policy counters: %+v", summary.Manager)
	}
	if summary.DeepTriageJobs != 1 || summary.SetupTriageJobs != 1 {
		t.Fatalf("unexpected triage jobs: %+v", summary)
	}
	if summary.DeepTriageEvents != 2 || summary.SetupTriageEvents != 1 {
		t.Fatalf("unexpected triage events: %+v", summary)
	}
	if summary.DeepCorpusSaves != 1 || summary.SetupCorpusSaves != 1 {
		t.Fatalf("unexpected corpus saves: %+v", summary)
	}
	if summary.DeepCollideActiveCalls != 2 || summary.SetupCollideActiveCalls != 1 {
		t.Fatalf("unexpected collide active counts: %+v", summary)
	}
	if len(summary.CollideQuality) != 1 ||
		!summary.CollideQuality[0].HasDeepActive ||
		!summary.CollideQuality[0].HasSetupActive ||
		!slices.Equal(summary.CollideQuality[0].ActiveCallNames, []string{"TransmitPackets$inet_accept", "listen$inet_tcp", "send$inet_accept"}) ||
		!slices.Equal(summary.CollideQuality[0].ActiveCategories, []string{"accepted_data", "setup", "transmit"}) ||
		!slices.Equal(summary.CollideQuality[0].TriageCalls, []string{"bind$inet_tcp", "send$inet_accept"}) ||
		!slices.Equal(summary.CollideQuality[0].CorpusSaves, []string{"send$inet_accept"}) ||
		!slices.Equal(summary.CollideQuality[0].DeepTriageCalls, []string{"send$inet_accept"}) ||
		!slices.Equal(summary.CollideQuality[0].DeepCorpusSaves, []string{"send$inet_accept"}) ||
		!slices.Equal(summary.CollideQuality[0].SetupTriageCalls, []string{"bind$inet_tcp"}) {
		t.Fatalf("unexpected embedded collide quality: %+v", summary.CollideQuality)
	}
	if summary.Runner.ExecResults != 7 || summary.Runner.NonZeroCover != 5 ||
		summary.Runner.HangedResults != 1 || summary.Runner.RestartCompleted != 1 {
		t.Fatalf("unexpected runner summary: %+v", summary.Runner)
	}
	if got := summary.HangedRequestIDs; len(got) != 1 || got[0] != 44 {
		t.Fatalf("unexpected hanged request ids: %+v", got)
	}
	if len(summary.RestartReasons) != 3 ||
		summary.RestartReasons[0].Reason != "recovering from previous hanged request" ||
		summary.RestartReasons[1].Reason != "request 44 hanged" ||
		summary.RestartReasons[2].Reason != "request 45 failed: nyx crash: WINDOWS BUGCHECK DIRECT DUMP IO" {
		t.Fatalf("unexpected restart reasons: %+v", summary.RestartReasons)
	}
	if len(summary.FailureEvents) != 5 {
		t.Fatalf("unexpected failure events: %+v", summary.FailureEvents)
	}
	wantFailure := map[string]struct {
		count int
		reqs  []int
	}{
		"hang\x00request hanged": {count: 1, reqs: []int{44}},
		"request_failed\x00nyx crash: WINDOWS BUGCHECK DIRECT DUMP IO":                                          {count: 1, reqs: []int{45}},
		"windows_crash\x00WINDOWS BUGCHECK DIRECT DUMP IO":                                                      {count: 1},
		"fatal\x00runner loop failed: nyx crash: WINDOWS BUGCHECK DIRECT DUMP IO":                               {count: 1},
		"fatal\x00failed to start Nyx VM: guest abort during init: ToPA allocation failure. Check kernel logs.": {count: 1},
	}
	for _, event := range summary.FailureEvents {
		want, ok := wantFailure[event.Kind+"\x00"+event.Reason]
		if !ok {
			t.Fatalf("unexpected failure event: %+v", event)
		}
		if event.Count != want.count || !slices.Equal(event.RequestIDs, want.reqs) {
			t.Fatalf("failure event %+v, want count=%d reqs=%+v", event, want.count, want.reqs)
		}
		delete(wantFailure, event.Kind+"\x00"+event.Reason)
	}
	if len(wantFailure) != 0 {
		t.Fatalf("missing failure events: %+v", wantFailure)
	}
	if event := failureEventByKey(summary.FailureEvents, "hang", "request hanged"); event == nil ||
		len(event.Programs) != 1 ||
		event.Programs[0].Call0 != "WSARecv$accept" ||
		event.Programs[0].Category != "accepted_data" ||
		event.Programs[0].Count != 1 ||
		!slices.Equal(event.Programs[0].RequestIDs, []int{44}) {
		t.Fatalf("unexpected hang program attribution: %+v", event)
	}
	if event := failureEventByKey(summary.FailureEvents, "request_failed", "nyx crash: WINDOWS BUGCHECK DIRECT DUMP IO"); event == nil ||
		len(event.Programs) != 1 ||
		event.Programs[0].SHA1 != "deadbeef" ||
		event.Programs[0].Call0 != "socket$listener_tcp" ||
		event.Programs[0].Deep0 != "CancelIoEx$socket" ||
		event.Programs[0].Category != "async_completion" ||
		!slices.Equal(event.Programs[0].RequestIDs, []int{45}) {
		t.Fatalf("unexpected crash program attribution: %+v", event)
	}
	if len(summary.FailureCategoryStats) != 2 ||
		summary.FailureCategoryStats[0].Category != "accepted_data" ||
		summary.FailureCategoryStats[0].Count != 1 ||
		summary.FailureCategoryStats[0].RequestCount != 1 ||
		summary.FailureCategoryStats[0].Hangs != 1 ||
		!summary.FailureCategoryStats[0].Deep ||
		summary.FailureCategoryStats[1].Category != "async_completion" ||
		summary.FailureCategoryStats[1].Count != 1 ||
		summary.FailureCategoryStats[1].RequestCount != 1 ||
		summary.FailureCategoryStats[1].RequestFailures != 1 ||
		!summary.FailureCategoryStats[1].Deep {
		t.Fatalf("unexpected failure category stats: %+v", summary.FailureCategoryStats)
	}
	if len(summary.ModuleRanges) != 3 || summary.ModuleRanges[0].Name != "afd.sys" {
		t.Fatalf("unexpected module ranges: %+v", summary.ModuleRanges)
	}
	if len(summary.ModuleHits) != 3 || summary.ModuleHits[0].Name != "afd.sys" ||
		summary.ModuleHits[0].PCs != 9 || !floatClose(summary.AFDModuleHitRatio, 0.5) {
		t.Fatalf("unexpected module hits: ratio=%v hits=%+v", summary.AFDModuleHitRatio, summary.ModuleHits)
	}
	if got := summary.ModuleHits[0].RequestIDs; !slices.Equal(got, []int{2, 3, 6}) {
		t.Fatalf("unexpected AFD request ids: %+v", got)
	}
	if got := moduleCoverClass(summary.ModuleCoverClasses, "afd"); got == nil ||
		got.Requests != 3 || got.CoverRecords != 8 || got.PCs != 13 ||
		!floatClose(got.RequestRatio, 3.0/7.0) ||
		!floatClose(got.ModuleRecordRatio, 5.0/6.0) ||
		!floatClose(got.PCRatio, 13.0/18.0) {
		t.Fatalf("unexpected afd cover class: %+v classes=%+v", got, summary.ModuleCoverClasses)
	}
	if got := moduleCoverClass(summary.ModuleCoverClasses, "other_module"); got == nil ||
		got.Requests != 1 || got.CoverRecords != 2 || got.PCs != 5 ||
		!floatClose(got.RequestRatio, 1.0/7.0) ||
		!floatClose(got.ModuleRecordRatio, 1.0/6.0) ||
		!floatClose(got.PCRatio, 5.0/18.0) {
		t.Fatalf("unexpected other-module cover class: %+v classes=%+v", got, summary.ModuleCoverClasses)
	}
	if got := moduleCoverClass(summary.ModuleCoverClasses, "unknown_or_user"); got == nil ||
		got.Requests != 1 || got.CoverRecords != 1 ||
		!floatClose(got.RequestRatio, 1.0/7.0) {
		t.Fatalf("unexpected unknown cover class: %+v classes=%+v", got, summary.ModuleCoverClasses)
	}
	if got := moduleCoverClass(summary.ModuleCoverClasses, "no_cover"); got == nil ||
		got.Requests != 2 || got.CoverRecords != 0 ||
		!floatClose(got.RequestRatio, 2.0/7.0) {
		t.Fatalf("unexpected no-cover class: %+v classes=%+v", got, summary.ModuleCoverClasses)
	}
	if summary.Throughput.ExecPerMin != 10 ||
		summary.Throughput.RunnerExecResults != 7 ||
		summary.Throughput.HangedResults != 1 ||
		!floatClose(summary.Throughput.HangedRatio, 1.0/7.0) ||
		summary.Throughput.NoCoverRequests != 2 ||
		!floatClose(summary.Throughput.NoCoverRatio, 2.0/7.0) ||
		summary.Throughput.TopFailureCategory != "accepted_data" ||
		summary.Throughput.TopFailureCount != 1 ||
		summary.Throughput.TopFailureHangs != 1 ||
		summary.Throughput.TopFailureRequestCount != 1 {
		t.Fatalf("unexpected throughput summary: %+v", summary.Throughput)
	}
	if summary.Injection.VNetRequests != 1 ||
		summary.Injection.NonVNetRequests != 3 ||
		summary.Injection.VNetNoCoverRequests != 0 ||
		summary.Injection.NonVNetNoCoverRequests != 1 ||
		summary.Injection.VNetHangedRequests != 0 ||
		summary.Injection.NonVNetHangedRequests != 1 ||
		summary.Injection.VNetAFDModuleRequests != 1 ||
		summary.Injection.NonVNetAFDModuleRequests != 0 ||
		!floatClose(summary.Injection.NonVNetNoCoverRatio, 1.0/3.0) ||
		!floatClose(summary.Injection.NonVNetHangedRatio, 1.0/3.0) ||
		!floatClose(summary.Injection.VNetAFDModuleHitRatio, 1.0) ||
		!slices.Equal(summary.Injection.VNetRequestIDs, []int{6}) ||
		!slices.Equal(summary.Injection.NonVNetRequestIDs, []int{7, 44, 45}) {
		t.Fatalf("unexpected injection summary: %+v", summary.Injection)
	}
	var sendAccept *afdCallSummary
	var cancel *afdCallSummary
	for i := range summary.CallStats {
		if summary.CallStats[i].Name == "send$inet_accept" {
			sendAccept = &summary.CallStats[i]
		}
		if summary.CallStats[i].Name == "CancelIoEx$socket" {
			cancel = &summary.CallStats[i]
		}
	}
	if sendAccept == nil {
		t.Fatalf("missing send$inet_accept stats: %+v", summary.CallStats)
	}
	var wsaRecv *afdCallSummary
	var acceptSetup *afdCallSummary
	if sendAccept.Category != "accepted_data" || sendAccept.TriageSignal != 10 ||
		sendAccept.CorpusRawCover != 3 || sendAccept.CollideCover != 20 {
		t.Fatalf("unexpected send$inet_accept stats: %+v", sendAccept)
	}
	if cancel == nil || cancel.Category != "async_completion" || cancel.TriageSignal != 7 {
		t.Fatalf("unexpected CancelIoEx$socket stats: %+v", cancel)
	}
	for i := range summary.CallStats {
		if summary.CallStats[i].Name == "WSARecv$accept" {
			wsaRecv = &summary.CallStats[i]
		}
		if summary.CallStats[i].Name == "accept$inet_tcp" {
			acceptSetup = &summary.CallStats[i]
		}
	}
	if wsaRecv == nil || wsaRecv.AFDModuleRecords != 2 || wsaRecv.AFDModulePCs != 6 ||
		wsaRecv.ModuleRecords != 2 || wsaRecv.ModulePCs != 6 ||
		wsaRecv.ExecResults != 1 || wsaRecv.ExecRawSignal != 12 ||
		wsaRecv.ExecRawCover != 13 || wsaRecv.ExecComps != 1 {
		t.Fatalf("unexpected WSARecv module stats: %+v", wsaRecv)
	}
	if cancel.ExecResults != 1 || cancel.ExecRawSignal != 7 || cancel.ExecRawCover != 9 {
		t.Fatalf("unexpected CancelIoEx exec feedback stats: %+v", cancel)
	}
	if acceptSetup == nil || acceptSetup.NtosModuleRecords != 1 || acceptSetup.NtosModulePCs != 4 ||
		acceptSetup.ModuleRecords != 1 || acceptSetup.ModulePCs != 4 {
		t.Fatalf("unexpected accept setup module stats: %+v", acceptSetup)
	}
	var acceptedData *afdCategorySummary
	for i := range summary.CategoryStats {
		if summary.CategoryStats[i].Category == "accepted_data" {
			acceptedData = &summary.CategoryStats[i]
		}
	}
	if acceptedData == nil || acceptedData.ExecResults != 1 ||
		acceptedData.ExecRawSignal != 12 || acceptedData.ExecRawCover != 13 {
		t.Fatalf("unexpected accepted_data exec feedback stats: %+v", acceptedData)
	}
	if got := ownerSummary(summary.OwnerStats, "deep"); got == nil ||
		!slices.Equal(got.Categories, []string{"accepted_data", "async_completion", "transmit"}) ||
		got.TriageJobs != 1 ||
		got.TriageEvents != 2 ||
		got.CorpusSaves != 1 ||
		got.CollideActive != 2 ||
		got.ExecResults != 2 ||
		got.ExecRawSignal != 19 ||
		got.ExecRawCover != 22 ||
		got.AFDModuleRecords != 3 ||
		got.AFDModulePCs != 8 {
		t.Fatalf("unexpected deep owner stats: %+v owners=%+v", got, summary.OwnerStats)
	}
	if got := ownerSummary(summary.OwnerStats, "setup_or_helper"); got == nil ||
		!slices.Equal(got.Categories, []string{"setup"}) ||
		got.TriageJobs != 1 ||
		got.TriageEvents != 1 ||
		got.CorpusSaves != 1 ||
		got.CollideActive != 1 ||
		got.NtosModuleRecords != 1 ||
		got.NtosModulePCs != 4 {
		t.Fatalf("unexpected setup owner stats: %+v owners=%+v", got, summary.OwnerStats)
	}
}

func moduleCoverClass(rows []afdModuleCoverSummary, class string) *afdModuleCoverSummary {
	for i := range rows {
		if rows[i].Class == class {
			return &rows[i]
		}
	}
	return nil
}

func failureEventByKey(rows []afdFailureEvent, kind, reason string) *afdFailureEvent {
	for i := range rows {
		if rows[i].Kind == kind && rows[i].Reason == reason {
			return &rows[i]
		}
	}
	return nil
}

func ownerSummary(rows []afdOwnerSummary, owner string) *afdOwnerSummary {
	for i := range rows {
		if rows[i].Owner == owner {
			return &rows[i]
		}
	}
	return nil
}

func floatClose(got, want float64) bool {
	const epsilon = 0.000001
	if got > want {
		return got-want < epsilon
	}
	return want-got < epsilon
}

func aggregateCoverClass(rows []afdAggregateClassSummary, class string) *afdAggregateClassSummary {
	for i := range rows {
		if rows[i].Class == class {
			return &rows[i]
		}
	}
	return nil
}

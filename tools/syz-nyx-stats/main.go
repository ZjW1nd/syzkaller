// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type statsState struct {
	start time.Time

	execTotal    int
	coverage     int
	corpus       int
	candidates   int
	execPerMin   int
	rpcResults   int
	rawNonEmpty  int
	rawSignal    int
	rawCover     int
	postNonEmpty int
	postSignal   int
	postCover    int
	hangedCount  int
	nonZeroExec  int

	corpusSaves  int
	triageEvents int
	ntfsTriage   int

	runnerExecResults   int
	runnerNonZeroCover  int
	runnerLastExecID    int
	runnerLastExecCalls int
	runnerLastCoverRecs int
	handshakeCount      int
	restartScheduled    int
	restartCompleted    int
	brokenPipeCount     int
	submitCR3Count      int
	lastSubmitCR3       string

	ptDecodeCount     int
	ptLastBytes       int
	ptLastDecodeBytes int
	ptLastResult      int
	ptLastBBAfter     int
	ptLastTraceSize   int

	syzCovDumpCount       int
	syzCovLastRecords     int
	syzCovLastCall        int
	syzCovLastPCs         int
	syzCovLastIPCallbacks int
	syzCovLastIPRecorded  int
}

type fileTracker struct {
	path    string
	offset  int64
	partial string
}

type collector struct {
	manager fileTracker
	runner  fileTracker
	state   statsState
}

type csvRow struct {
	TimestampUnix int64
	ElapsedSec    float64

	ExecTotal  int
	ExecPerMin int
	Coverage   int
	Corpus     int
	Candidates int

	RPCResults   int
	NonZeroExec  int
	HangedCount  int
	RawNonEmpty  int
	RawSignal    int
	RawCover     int
	PostNonEmpty int
	PostSignal   int
	PostCover    int

	CorpusSaves  int
	TriageEvents int
	NTFSTriage   int

	RunnerExecResults   int
	RunnerNonZeroCover  int
	RunnerLastExecID    int
	RunnerLastExecCalls int
	RunnerLastCoverRecs int
	HandshakeCount      int
	RestartScheduled    int
	RestartCompleted    int
	BrokenPipeCount     int
	SubmitCR3Count      int
	LastSubmitCR3       string

	PTDecodeCount     int
	PTLastBytes       int
	PTLastDecodeBytes int
	PTLastResult      int
	PTLastBBAfter     int
	PTLastTraceSize   int

	SYZCovDumpCount       int
	SYZCovLastRecords     int
	SYZCovLastCall        int
	SYZCovLastPCs         int
	SYZCovLastIPCallbacks int
	SYZCovLastIPRecorded  int
}

type plotSeries struct {
	Name   string
	Values []float64
	Color  string
}

type plotPanel struct {
	Title  string
	Series []plotSeries
}

type plotChart struct {
	File   string
	Title  string
	Panels []plotPanel
}

var (
	reManagerStats = regexp.MustCompile(`candidates=(\d+)\s+corpus=(\d+)\s+coverage=(\d+)\s+exec total=(\d+)\s+\((\d+)/min\)`)
	reRPCResult    = regexp.MustCompile(`rpcserver exec result: id=(\d+) calls=(\d+) raw_nonempty=(\d+) raw_signal=(\d+) raw_cover=(\d+) post_nonempty=(\d+) post_signal=(\d+) post_cover=(\d+) hanged=(\w+)`)
	reRunnerExec   = regexp.MustCompile(`runner exec complete: id=(\d+) calls=(\d+) cover_records=(\d+)`)
	reSubmitCR3    = regexp.MustCompile(`submit_cr3=0x([0-9a-fA-F]+)`)
	rePTDecode     = regexp.MustCompile(`PT_DECODE\] bytes=(\d+) decode_bytes=(\d+) trimmed=(\d+) terminator_before=0x[0-9a-fA-F]+ result=(\d+) bb_before=\d+ bb_after=(\d+) trace_size=(\d+)`)
	reSYZCovDump   = regexp.MustCompile(`SYZ_COV_DUMP\] active=\d+ records=(\d+) last_call=(\d+) last_slot=\d+ last_pcs=(\d+) ip_callbacks=(\d+) ip_recorded=(\d+)`)
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "collect":
		if err := runCollect(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "syz-nyx-stats collect: %v\n", err)
			os.Exit(1)
		}
	case "plot":
		if err := runPlot(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "syz-nyx-stats plot: %v\n", err)
			os.Exit(1)
		}
	case "compare":
		if err := runCompare(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "syz-nyx-stats compare: %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: syz-nyx-stats <collect|plot|compare> ...\n")
}

func runCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	managerLog := fs.String("manager-log", "", "path to syz-manager log")
	runnerLog := fs.String("runner-log", "", "path to syz-nyx-runner log")
	output := fs.String("output", "", "CSV output path")
	interval := fs.Duration("interval", 5*time.Second, "sampling interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *output == "" {
		return errors.New("missing --output")
	}
	if *managerLog == "" && *runnerLog == "" {
		return errors.New("need at least one of --manager-log or --runner-log")
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		return err
	}

	f, err := os.Create(*output)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write(csvHeader()); err != nil {
		return err
	}

	c := &collector{
		manager: fileTracker{path: *managerLog},
		runner:  fileTracker{path: *runnerLog},
		state:   statsState{start: time.Now()},
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	if err := c.sample(w); err != nil {
		return err
	}

	for {
		select {
		case <-ticker.C:
			if err := c.sample(w); err != nil {
				return err
			}
		case <-sigCh:
			return c.sample(w)
		}
	}
}

func csvHeader() []string {
	return []string{
		"timestamp_unix", "elapsed_sec",
		"exec_total", "exec_per_min", "coverage", "corpus", "candidates",
		"rpc_results", "nonzero_exec_results", "hanged_count",
		"raw_nonempty", "raw_signal", "raw_cover", "post_nonempty", "post_signal", "post_cover",
		"corpus_saves", "triage_events", "ntfs_triage_events",
		"runner_exec_results", "runner_nonzero_cover_records", "runner_last_exec_id", "runner_last_exec_calls", "runner_last_cover_records",
		"handshake_count", "restart_scheduled", "restart_completed", "broken_pipe_count",
		"submit_cr3_count", "last_submit_cr3",
		"pt_decode_count", "pt_last_bytes", "pt_last_decode_bytes", "pt_last_result", "pt_last_bb_after", "pt_last_trace_size",
		"syz_cov_dump_count", "syz_cov_last_records", "syz_cov_last_call", "syz_cov_last_pcs", "syz_cov_last_ip_callbacks", "syz_cov_last_ip_recorded",
	}
}

func (c *collector) sample(w *csv.Writer) error {
	if err := c.readNewLines(&c.manager, c.handleManagerLine); err != nil {
		return err
	}
	if err := c.readNewLines(&c.runner, c.handleRunnerLine); err != nil {
		return err
	}
	row := c.makeRow()
	if err := w.Write(row.toCSV()); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

func (c *collector) readNewLines(ft *fileTracker, handle func(string)) error {
	if ft.path == "" {
		return nil
	}
	st, err := os.Stat(ft.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Size() < ft.offset {
		ft.offset = 0
		ft.partial = ""
	}
	f, err := os.Open(ft.path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(ft.offset, 0); err != nil {
		return err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	ft.offset += int64(len(data))
	if len(data) == 0 {
		return nil
	}
	text := ft.partial + string(data)
	lines := strings.Split(text, "\n")
	ft.partial = lines[len(lines)-1]
	for _, line := range lines[:len(lines)-1] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		handle(line)
	}
	return nil
}

func (c *collector) handleManagerLine(line string) {
	if m := reManagerStats.FindStringSubmatch(line); m != nil {
		c.state.candidates = mustAtoi(m[1])
		c.state.corpus = mustAtoi(m[2])
		c.state.coverage = mustAtoi(m[3])
		c.state.execTotal = mustAtoi(m[4])
		c.state.execPerMin = mustAtoi(m[5])
	}
	if m := reRPCResult.FindStringSubmatch(line); m != nil {
		c.state.rpcResults++
		c.state.rawNonEmpty = mustAtoi(m[3])
		c.state.rawSignal = mustAtoi(m[4])
		c.state.rawCover = mustAtoi(m[5])
		c.state.postNonEmpty = mustAtoi(m[6])
		c.state.postSignal = mustAtoi(m[7])
		c.state.postCover = mustAtoi(m[8])
		if strings.EqualFold(m[9], "true") {
			c.state.hangedCount++
		}
		if c.state.rawSignal > 0 || c.state.rawCover > 0 {
			c.state.nonZeroExec++
		}
	}
	if strings.Contains(line, "windows corpus save:") {
		c.state.corpusSaves++
	}
	if strings.Contains(line, "windows triage:") {
		c.state.triageEvents++
		if strings.Contains(line, "NtFsControlFile") {
			c.state.ntfsTriage++
		}
	}
}

func (c *collector) handleRunnerLine(line string) {
	if strings.Contains(line, "runner handshake complete") {
		c.state.handshakeCount++
	}
	if m := reSubmitCR3.FindStringSubmatch(line); m != nil {
		c.state.submitCR3Count++
		c.state.lastSubmitCR3 = "0x" + strings.ToLower(m[1])
	}
	if m := reRunnerExec.FindStringSubmatch(line); m != nil {
		c.state.runnerExecResults++
		c.state.runnerLastExecID = mustAtoi(m[1])
		c.state.runnerLastExecCalls = mustAtoi(m[2])
		c.state.runnerLastCoverRecs = mustAtoi(m[3])
		if c.state.runnerLastCoverRecs > 0 {
			c.state.runnerNonZeroCover++
		}
	}
	if strings.Contains(line, "runner scheduling VM restart:") {
		c.state.restartScheduled++
	}
	if strings.Contains(line, "runner restarting VM:") {
		c.state.restartCompleted++
	}
	if strings.Contains(line, "broken pipe") {
		c.state.brokenPipeCount++
	}
	if m := rePTDecode.FindStringSubmatch(line); m != nil {
		c.state.ptDecodeCount++
		c.state.ptLastBytes = mustAtoi(m[1])
		c.state.ptLastDecodeBytes = mustAtoi(m[2])
		c.state.ptLastResult = mustAtoi(m[4])
		c.state.ptLastBBAfter = mustAtoi(m[5])
		c.state.ptLastTraceSize = mustAtoi(m[6])
	}
	if m := reSYZCovDump.FindStringSubmatch(line); m != nil {
		c.state.syzCovDumpCount++
		c.state.syzCovLastRecords = mustAtoi(m[1])
		c.state.syzCovLastCall = mustAtoi(m[2])
		c.state.syzCovLastPCs = mustAtoi(m[3])
		c.state.syzCovLastIPCallbacks = mustAtoi(m[4])
		c.state.syzCovLastIPRecorded = mustAtoi(m[5])
	}
}

func (c *collector) makeRow() csvRow {
	now := time.Now()
	return csvRow{
		TimestampUnix:         now.Unix(),
		ElapsedSec:            now.Sub(c.state.start).Seconds(),
		ExecTotal:             c.state.execTotal,
		ExecPerMin:            c.state.execPerMin,
		Coverage:              c.state.coverage,
		Corpus:                c.state.corpus,
		Candidates:            c.state.candidates,
		RPCResults:            c.state.rpcResults,
		NonZeroExec:           c.state.nonZeroExec,
		HangedCount:           c.state.hangedCount,
		RawNonEmpty:           c.state.rawNonEmpty,
		RawSignal:             c.state.rawSignal,
		RawCover:              c.state.rawCover,
		PostNonEmpty:          c.state.postNonEmpty,
		PostSignal:            c.state.postSignal,
		PostCover:             c.state.postCover,
		CorpusSaves:           c.state.corpusSaves,
		TriageEvents:          c.state.triageEvents,
		NTFSTriage:            c.state.ntfsTriage,
		RunnerExecResults:     c.state.runnerExecResults,
		RunnerNonZeroCover:    c.state.runnerNonZeroCover,
		RunnerLastExecID:      c.state.runnerLastExecID,
		RunnerLastExecCalls:   c.state.runnerLastExecCalls,
		RunnerLastCoverRecs:   c.state.runnerLastCoverRecs,
		HandshakeCount:        c.state.handshakeCount,
		RestartScheduled:      c.state.restartScheduled,
		RestartCompleted:      c.state.restartCompleted,
		BrokenPipeCount:       c.state.brokenPipeCount,
		SubmitCR3Count:        c.state.submitCR3Count,
		LastSubmitCR3:         c.state.lastSubmitCR3,
		PTDecodeCount:         c.state.ptDecodeCount,
		PTLastBytes:           c.state.ptLastBytes,
		PTLastDecodeBytes:     c.state.ptLastDecodeBytes,
		PTLastResult:          c.state.ptLastResult,
		PTLastBBAfter:         c.state.ptLastBBAfter,
		PTLastTraceSize:       c.state.ptLastTraceSize,
		SYZCovDumpCount:       c.state.syzCovDumpCount,
		SYZCovLastRecords:     c.state.syzCovLastRecords,
		SYZCovLastCall:        c.state.syzCovLastCall,
		SYZCovLastPCs:         c.state.syzCovLastPCs,
		SYZCovLastIPCallbacks: c.state.syzCovLastIPCallbacks,
		SYZCovLastIPRecorded:  c.state.syzCovLastIPRecorded,
	}
}

func (r csvRow) toCSV() []string {
	return []string{
		strconv.FormatInt(r.TimestampUnix, 10),
		fmt.Sprintf("%.3f", r.ElapsedSec),
		itoa(r.ExecTotal), itoa(r.ExecPerMin), itoa(r.Coverage), itoa(r.Corpus), itoa(r.Candidates),
		itoa(r.RPCResults), itoa(r.NonZeroExec), itoa(r.HangedCount),
		itoa(r.RawNonEmpty), itoa(r.RawSignal), itoa(r.RawCover), itoa(r.PostNonEmpty), itoa(r.PostSignal), itoa(r.PostCover),
		itoa(r.CorpusSaves), itoa(r.TriageEvents), itoa(r.NTFSTriage),
		itoa(r.RunnerExecResults), itoa(r.RunnerNonZeroCover), itoa(r.RunnerLastExecID), itoa(r.RunnerLastExecCalls), itoa(r.RunnerLastCoverRecs),
		itoa(r.HandshakeCount), itoa(r.RestartScheduled), itoa(r.RestartCompleted), itoa(r.BrokenPipeCount),
		itoa(r.SubmitCR3Count), r.LastSubmitCR3,
		itoa(r.PTDecodeCount), itoa(r.PTLastBytes), itoa(r.PTLastDecodeBytes), itoa(r.PTLastResult), itoa(r.PTLastBBAfter), itoa(r.PTLastTraceSize),
		itoa(r.SYZCovDumpCount), itoa(r.SYZCovLastRecords), itoa(r.SYZCovLastCall), itoa(r.SYZCovLastPCs), itoa(r.SYZCovLastIPCallbacks), itoa(r.SYZCovLastIPRecorded),
	}
}

func runPlot(args []string) error {
	fs := flag.NewFlagSet("plot", flag.ContinueOnError)
	input := fs.String("input", "", "CSV input path")
	outdir := fs.String("outdir", "", "output directory")
	title := fs.String("title", "Windows Nyx Stats", "plot title")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" || *outdir == "" {
		return errors.New("need --input and --outdir")
	}
	rows, err := readCSV(*input)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errors.New("no data rows in CSV")
	}
	rows, plotStartOffset := trimPlotRows(rows)
	if err := os.MkdirAll(*outdir, 0o755); err != nil {
		return err
	}
	elapsed := make([]float64, len(rows))
	execTotal := make([]float64, len(rows))
	coverage := make([]float64, len(rows))
	corpus := make([]float64, len(rows))
	execPerMin := make([]float64, len(rows))
	rawSignal := make([]float64, len(rows))
	rawCover := make([]float64, len(rows))
	postSignal := make([]float64, len(rows))
	postCover := make([]float64, len(rows))
	coverRecords := make([]float64, len(rows))
	restarts := make([]float64, len(rows))
	ptTrace := make([]float64, len(rows))
	ptBB := make([]float64, len(rows))
	syzCovRecords := make([]float64, len(rows))
	ntfsTriage := make([]float64, len(rows))
	for i, row := range rows {
		elapsed[i] = row.ElapsedSec
		execTotal[i] = float64(row.ExecTotal)
		coverage[i] = float64(row.Coverage)
		corpus[i] = float64(row.Corpus)
		execPerMin[i] = float64(row.ExecPerMin)
		rawSignal[i] = float64(row.RawSignal)
		rawCover[i] = float64(row.RawCover)
		postSignal[i] = float64(row.PostSignal)
		postCover[i] = float64(row.PostCover)
		coverRecords[i] = float64(row.RunnerLastCoverRecs)
		restarts[i] = float64(row.RestartScheduled)
		ptTrace[i] = float64(row.PTLastTraceSize)
		ptBB[i] = float64(row.PTLastBBAfter)
		syzCovRecords[i] = float64(row.SYZCovLastRecords)
		ntfsTriage[i] = float64(row.NTFSTriage)
	}
	charts := []plotChart{
		{
			File:  "coverage_corpus.svg",
			Title: "Coverage / Corpus Growth",
			Panels: []plotPanel{
				{Title: "coverage", Series: []plotSeries{{Name: "coverage", Values: coverage, Color: "#1f77b4"}}},
				{Title: "corpus", Series: []plotSeries{{Name: "corpus", Values: corpus, Color: "#ff7f0e"}}},
				{Title: "exec_total", Series: []plotSeries{{Name: "exec_total", Values: execTotal, Color: "#2ca02c"}}},
			},
		},
		{
			File:  "throughput.svg",
			Title: "Execution Throughput",
			Panels: []plotPanel{
				{Title: "exec_per_min", Series: []plotSeries{{Name: "exec_per_min", Values: execPerMin, Color: "#1f77b4"}}},
				{Title: "runner_cover_records", Series: []plotSeries{{Name: "runner_cover_records", Values: coverRecords, Color: "#d62728"}}},
				{Title: "restart_scheduled", Series: []plotSeries{{Name: "restart_scheduled", Values: restarts, Color: "#9467bd"}}},
			},
		},
		{
			File:  "signal_cover.svg",
			Title: "Signal / Cover per Latest Exec",
			Panels: []plotPanel{
				{
					Title: "signal",
					Series: []plotSeries{
						{Name: "raw_signal", Values: rawSignal, Color: "#1f77b4"},
						{Name: "post_signal", Values: postSignal, Color: "#2ca02c"},
					},
				},
				{
					Title: "cover",
					Series: []plotSeries{
						{Name: "raw_cover", Values: rawCover, Color: "#ff7f0e"},
						{Name: "post_cover", Values: postCover, Color: "#d62728"},
					},
				},
			},
		},
		{
			File:  "pt_trace.svg",
			Title: "PT / SYZ_COV Internals",
			Panels: []plotPanel{
				{Title: "pt_trace_size", Series: []plotSeries{{Name: "pt_trace_size", Values: ptTrace, Color: "#1f77b4"}}},
				{Title: "pt_bb_after", Series: []plotSeries{{Name: "pt_bb_after", Values: ptBB, Color: "#ff7f0e"}}},
				{Title: "syz_cov_records", Series: []plotSeries{{Name: "syz_cov_records", Values: syzCovRecords, Color: "#2ca02c"}}},
				{Title: "ntfs_triage", Series: []plotSeries{{Name: "ntfs_triage", Values: ntfsTriage, Color: "#d62728"}}},
			},
		},
	}
	for _, chart := range charts {
		if err := os.WriteFile(filepath.Join(*outdir, chart.File),
			[]byte(renderSVG(chart.Title, elapsed, chart.Panels)), 0o644); err != nil {
			return err
		}
	}
	summary := map[string]any{
		"title":                 *title,
		"rows":                  len(rows),
		"plot_start_offset_sec": plotStartOffset,
		"last":                  rows[len(rows)-1],
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*outdir, "summary.json"), data, 0o644); err != nil {
		return err
	}
	index := renderIndex(*title, rows[len(rows)-1], charts)
	return os.WriteFile(filepath.Join(*outdir, "index.html"), []byte(index), 0o644)
}

type aggregateSeries struct {
	X    []float64
	Mean []float64
	Min  []float64
	Max  []float64
}

type aggregateSummary struct {
	Title               string             `json:"title"`
	RunCount            int                `json:"run_count"`
	SampleStepSec       float64            `json:"sample_step_sec"`
	PlotStartOffsetsSec []float64          `json:"plot_start_offsets_sec"`
	Inputs              []string           `json:"inputs"`
	FinalMean           csvRow             `json:"final_mean"`
	FinalMin            csvRow             `json:"final_min"`
	FinalMax            csvRow             `json:"final_max"`
	FinalMetricTable    []metricSummaryRow `json:"final_metric_table"`
	Finals              []csvRow           `json:"finals"`
}

type metricSummaryRow struct {
	Name   string  `json:"name"`
	Mean   float64 `json:"mean"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Stddev float64 `json:"stddev"`
}

func runCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	inputsArg := fs.String("inputs", "", "comma-separated CSV input paths")
	outdir := fs.String("outdir", "", "output directory")
	title := fs.String("title", "Windows Nyx Aggregate", "plot title")
	stepSec := fs.Float64("step-sec", 5, "resample step size in seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputsArg == "" || *outdir == "" {
		return errors.New("need --inputs and --outdir")
	}
	inputs := splitInputs(*inputsArg)
	if len(inputs) == 0 {
		return errors.New("no input csv paths after parsing --inputs")
	}
	var runs [][]csvRow
	var offsets []float64
	for _, input := range inputs {
		rows, err := readCSV(input)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return fmt.Errorf("no data rows in CSV: %s", input)
		}
		rows, offset := trimPlotRows(rows)
		runs = append(runs, rows)
		offsets = append(offsets, offset)
	}
	if err := os.MkdirAll(*outdir, 0o755); err != nil {
		return err
	}
	x := makeAggregateXAxis(runs, *stepSec)
	coverage := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.Coverage) })
	corpus := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.Corpus) })
	execTotal := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.ExecTotal) })
	execPerMin := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.ExecPerMin) })
	coverRecords := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.RunnerLastCoverRecs) })
	restarts := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.RestartScheduled) })
	rawSignal := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.RawSignal) })
	rawCover := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.RawCover) })
	postSignal := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.PostSignal) })
	postCover := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.PostCover) })
	ptTrace := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.PTLastTraceSize) })
	ptBB := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.PTLastBBAfter) })
	syzCov := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.SYZCovLastRecords) })
	ntfsTriage := aggregateMetric(runs, x, func(row csvRow) float64 { return float64(row.NTFSTriage) })

	charts := []plotChart{
		{
			File:  "aggregate_coverage_corpus.svg",
			Title: "Coverage / Corpus Growth (mean)",
			Panels: []plotPanel{
				{Title: "coverage_mean", Series: []plotSeries{{Name: "coverage_mean", Values: coverage.Mean, Color: "#1f77b4"}}},
				{Title: "corpus_mean", Series: []plotSeries{{Name: "corpus_mean", Values: corpus.Mean, Color: "#ff7f0e"}}},
				{Title: "exec_total_mean", Series: []plotSeries{{Name: "exec_total_mean", Values: execTotal.Mean, Color: "#2ca02c"}}},
			},
		},
		{
			File:  "aggregate_throughput.svg",
			Title: "Execution Throughput (mean)",
			Panels: []plotPanel{
				{Title: "exec_per_min_mean", Series: []plotSeries{{Name: "exec_per_min_mean", Values: execPerMin.Mean, Color: "#1f77b4"}}},
				{Title: "runner_cover_records_mean", Series: []plotSeries{{Name: "runner_cover_records_mean", Values: coverRecords.Mean, Color: "#d62728"}}},
				{Title: "restart_scheduled_mean", Series: []plotSeries{{Name: "restart_scheduled_mean", Values: restarts.Mean, Color: "#9467bd"}}},
			},
		},
		{
			File:  "aggregate_signal_cover.svg",
			Title: "Signal / Cover per Latest Exec (mean)",
			Panels: []plotPanel{
				{
					Title: "signal_mean",
					Series: []plotSeries{
						{Name: "raw_signal_mean", Values: rawSignal.Mean, Color: "#1f77b4"},
						{Name: "post_signal_mean", Values: postSignal.Mean, Color: "#2ca02c"},
					},
				},
				{
					Title: "cover_mean",
					Series: []plotSeries{
						{Name: "raw_cover_mean", Values: rawCover.Mean, Color: "#ff7f0e"},
						{Name: "post_cover_mean", Values: postCover.Mean, Color: "#d62728"},
					},
				},
			},
		},
		{
			File:  "aggregate_pt_trace.svg",
			Title: "PT / SYZ_COV Internals (mean)",
			Panels: []plotPanel{
				{Title: "pt_trace_size_mean", Series: []plotSeries{{Name: "pt_trace_size_mean", Values: ptTrace.Mean, Color: "#1f77b4"}}},
				{Title: "pt_bb_after_mean", Series: []plotSeries{{Name: "pt_bb_after_mean", Values: ptBB.Mean, Color: "#ff7f0e"}}},
				{Title: "syz_cov_records_mean", Series: []plotSeries{{Name: "syz_cov_records_mean", Values: syzCov.Mean, Color: "#2ca02c"}}},
				{Title: "ntfs_triage_mean", Series: []plotSeries{{Name: "ntfs_triage_mean", Values: ntfsTriage.Mean, Color: "#d62728"}}},
			},
		},
	}
	for _, chart := range charts {
		if err := os.WriteFile(filepath.Join(*outdir, chart.File),
			[]byte(renderSVG(chart.Title, x, chart.Panels)), 0o644); err != nil {
			return err
		}
	}
	finals := make([]csvRow, 0, len(runs))
	for _, rows := range runs {
		finals = append(finals, rows[len(rows)-1])
	}
	metricTable := summarizeFinalMetrics(finals)
	summary := aggregateSummary{
		Title:               *title,
		RunCount:            len(runs),
		SampleStepSec:       *stepSec,
		PlotStartOffsetsSec: offsets,
		Inputs:              inputs,
		FinalMean:           aggregateFinalRows(finals, meanReducer),
		FinalMin:            aggregateFinalRows(finals, minReducer),
		FinalMax:            aggregateFinalRows(finals, maxReducer),
		FinalMetricTable:    metricTable,
		Finals:              finals,
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*outdir, "aggregate_summary.json"), data, 0o644); err != nil {
		return err
	}
	if err := writeMetricTableCSV(filepath.Join(*outdir, "final_metrics.csv"), metricTable); err != nil {
		return err
	}
	index := renderAggregateIndex(*title, summary, charts)
	return os.WriteFile(filepath.Join(*outdir, "index.html"), []byte(index), 0o644)
}

func splitInputs(arg string) []string {
	var inputs []string
	for _, item := range strings.Split(arg, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		inputs = append(inputs, item)
	}
	return inputs
}

func makeAggregateXAxis(runs [][]csvRow, stepSec float64) []float64 {
	if stepSec <= 0 {
		stepSec = 5
	}
	maxElapsed := 0.0
	for _, rows := range runs {
		if n := len(rows); n != 0 && rows[n-1].ElapsedSec > maxElapsed {
			maxElapsed = rows[n-1].ElapsedSec
		}
	}
	if maxElapsed <= 0 {
		return []float64{0}
	}
	var x []float64
	for cur := 0.0; cur < maxElapsed; cur += stepSec {
		x = append(x, cur)
	}
	if len(x) == 0 || x[len(x)-1] < maxElapsed {
		x = append(x, maxElapsed)
	}
	return x
}

func aggregateMetric(runs [][]csvRow, x []float64, value func(csvRow) float64) aggregateSeries {
	series := aggregateSeries{
		X:    append([]float64(nil), x...),
		Mean: make([]float64, len(x)),
		Min:  make([]float64, len(x)),
		Max:  make([]float64, len(x)),
	}
	for i, xi := range x {
		vals := make([]float64, 0, len(runs))
		for _, rows := range runs {
			if row, ok := rowAtOrBefore(rows, xi); ok {
				vals = append(vals, value(row))
			}
		}
		if len(vals) == 0 {
			continue
		}
		series.Mean[i] = reduceFloat64(vals, meanReducer)
		series.Min[i] = reduceFloat64(vals, minReducer)
		series.Max[i] = reduceFloat64(vals, maxReducer)
	}
	return series
}

func rowAtOrBefore(rows []csvRow, elapsed float64) (csvRow, bool) {
	if len(rows) == 0 {
		return csvRow{}, false
	}
	if elapsed < rows[0].ElapsedSec {
		return csvRow{}, false
	}
	idx := 0
	for idx+1 < len(rows) && rows[idx+1].ElapsedSec <= elapsed {
		idx++
	}
	return rows[idx], true
}

type floatReducer func([]float64) float64

func meanReducer(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func stddevReducer(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	mean := meanReducer(vals)
	sumSquares := 0.0
	for _, v := range vals {
		delta := v - mean
		sumSquares += delta * delta
	}
	return math.Sqrt(sumSquares / float64(len(vals)))
}

func minReducer(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	min := vals[0]
	for _, v := range vals[1:] {
		if v < min {
			min = v
		}
	}
	return min
}

func maxReducer(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	max := vals[0]
	for _, v := range vals[1:] {
		if v > max {
			max = v
		}
	}
	return max
}

func reduceFloat64(vals []float64, fn floatReducer) float64 {
	return fn(vals)
}

func aggregateFinalRows(rows []csvRow, reducer floatReducer) csvRow {
	pickInt := func(fn func(csvRow) float64) int {
		vals := make([]float64, 0, len(rows))
		for _, row := range rows {
			vals = append(vals, fn(row))
		}
		return int(reducer(vals))
	}
	pickFloat := func(fn func(csvRow) float64) float64 {
		vals := make([]float64, 0, len(rows))
		for _, row := range rows {
			vals = append(vals, fn(row))
		}
		return reducer(vals)
	}
	return csvRow{
		ElapsedSec:            pickFloat(func(r csvRow) float64 { return r.ElapsedSec }),
		ExecTotal:             pickInt(func(r csvRow) float64 { return float64(r.ExecTotal) }),
		ExecPerMin:            pickInt(func(r csvRow) float64 { return float64(r.ExecPerMin) }),
		Coverage:              pickInt(func(r csvRow) float64 { return float64(r.Coverage) }),
		Corpus:                pickInt(func(r csvRow) float64 { return float64(r.Corpus) }),
		Candidates:            pickInt(func(r csvRow) float64 { return float64(r.Candidates) }),
		RPCResults:            pickInt(func(r csvRow) float64 { return float64(r.RPCResults) }),
		NonZeroExec:           pickInt(func(r csvRow) float64 { return float64(r.NonZeroExec) }),
		HangedCount:           pickInt(func(r csvRow) float64 { return float64(r.HangedCount) }),
		RawNonEmpty:           pickInt(func(r csvRow) float64 { return float64(r.RawNonEmpty) }),
		RawSignal:             pickInt(func(r csvRow) float64 { return float64(r.RawSignal) }),
		RawCover:              pickInt(func(r csvRow) float64 { return float64(r.RawCover) }),
		PostNonEmpty:          pickInt(func(r csvRow) float64 { return float64(r.PostNonEmpty) }),
		PostSignal:            pickInt(func(r csvRow) float64 { return float64(r.PostSignal) }),
		PostCover:             pickInt(func(r csvRow) float64 { return float64(r.PostCover) }),
		CorpusSaves:           pickInt(func(r csvRow) float64 { return float64(r.CorpusSaves) }),
		TriageEvents:          pickInt(func(r csvRow) float64 { return float64(r.TriageEvents) }),
		NTFSTriage:            pickInt(func(r csvRow) float64 { return float64(r.NTFSTriage) }),
		RunnerExecResults:     pickInt(func(r csvRow) float64 { return float64(r.RunnerExecResults) }),
		RunnerNonZeroCover:    pickInt(func(r csvRow) float64 { return float64(r.RunnerNonZeroCover) }),
		RunnerLastExecID:      pickInt(func(r csvRow) float64 { return float64(r.RunnerLastExecID) }),
		RunnerLastExecCalls:   pickInt(func(r csvRow) float64 { return float64(r.RunnerLastExecCalls) }),
		RunnerLastCoverRecs:   pickInt(func(r csvRow) float64 { return float64(r.RunnerLastCoverRecs) }),
		HandshakeCount:        pickInt(func(r csvRow) float64 { return float64(r.HandshakeCount) }),
		RestartScheduled:      pickInt(func(r csvRow) float64 { return float64(r.RestartScheduled) }),
		RestartCompleted:      pickInt(func(r csvRow) float64 { return float64(r.RestartCompleted) }),
		BrokenPipeCount:       pickInt(func(r csvRow) float64 { return float64(r.BrokenPipeCount) }),
		SubmitCR3Count:        pickInt(func(r csvRow) float64 { return float64(r.SubmitCR3Count) }),
		PTDecodeCount:         pickInt(func(r csvRow) float64 { return float64(r.PTDecodeCount) }),
		PTLastBytes:           pickInt(func(r csvRow) float64 { return float64(r.PTLastBytes) }),
		PTLastDecodeBytes:     pickInt(func(r csvRow) float64 { return float64(r.PTLastDecodeBytes) }),
		PTLastResult:          pickInt(func(r csvRow) float64 { return float64(r.PTLastResult) }),
		PTLastBBAfter:         pickInt(func(r csvRow) float64 { return float64(r.PTLastBBAfter) }),
		PTLastTraceSize:       pickInt(func(r csvRow) float64 { return float64(r.PTLastTraceSize) }),
		SYZCovDumpCount:       pickInt(func(r csvRow) float64 { return float64(r.SYZCovDumpCount) }),
		SYZCovLastRecords:     pickInt(func(r csvRow) float64 { return float64(r.SYZCovLastRecords) }),
		SYZCovLastCall:        pickInt(func(r csvRow) float64 { return float64(r.SYZCovLastCall) }),
		SYZCovLastPCs:         pickInt(func(r csvRow) float64 { return float64(r.SYZCovLastPCs) }),
		SYZCovLastIPCallbacks: pickInt(func(r csvRow) float64 { return float64(r.SYZCovLastIPCallbacks) }),
		SYZCovLastIPRecorded:  pickInt(func(r csvRow) float64 { return float64(r.SYZCovLastIPRecorded) }),
	}
}

func summarizeFinalMetrics(rows []csvRow) []metricSummaryRow {
	type metricDef struct {
		name  string
		value func(csvRow) float64
	}
	metrics := []metricDef{
		{name: "elapsed_sec", value: func(r csvRow) float64 { return r.ElapsedSec }},
		{name: "exec_total", value: func(r csvRow) float64 { return float64(r.ExecTotal) }},
		{name: "exec_per_min", value: func(r csvRow) float64 { return float64(r.ExecPerMin) }},
		{name: "coverage", value: func(r csvRow) float64 { return float64(r.Coverage) }},
		{name: "corpus", value: func(r csvRow) float64 { return float64(r.Corpus) }},
		{name: "rpc_results", value: func(r csvRow) float64 { return float64(r.RPCResults) }},
		{name: "nonzero_exec", value: func(r csvRow) float64 { return float64(r.NonZeroExec) }},
		{name: "corpus_saves", value: func(r csvRow) float64 { return float64(r.CorpusSaves) }},
		{name: "triage_events", value: func(r csvRow) float64 { return float64(r.TriageEvents) }},
		{name: "ntfs_triage", value: func(r csvRow) float64 { return float64(r.NTFSTriage) }},
		{name: "runner_exec_results", value: func(r csvRow) float64 { return float64(r.RunnerExecResults) }},
		{name: "runner_nonzero_cover", value: func(r csvRow) float64 { return float64(r.RunnerNonZeroCover) }},
		{name: "restart_completed", value: func(r csvRow) float64 { return float64(r.RestartCompleted) }},
		{name: "broken_pipe_count", value: func(r csvRow) float64 { return float64(r.BrokenPipeCount) }},
		{name: "submit_cr3_count", value: func(r csvRow) float64 { return float64(r.SubmitCR3Count) }},
		{name: "pt_decode_count", value: func(r csvRow) float64 { return float64(r.PTDecodeCount) }},
		{name: "syz_cov_dump_count", value: func(r csvRow) float64 { return float64(r.SYZCovDumpCount) }},
	}
	table := make([]metricSummaryRow, 0, len(metrics))
	for _, metric := range metrics {
		vals := make([]float64, 0, len(rows))
		for _, row := range rows {
			vals = append(vals, metric.value(row))
		}
		table = append(table, metricSummaryRow{
			Name:   metric.name,
			Mean:   meanReducer(vals),
			Min:    minReducer(vals),
			Max:    maxReducer(vals),
			Stddev: stddevReducer(vals),
		})
	}
	return table
}

func writeMetricTableCSV(path string, rows []metricSummaryRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"metric", "mean", "min", "max", "stddev"}); err != nil {
		return err
	}
	for _, row := range rows {
		record := []string{
			row.Name,
			fmt.Sprintf("%.3f", row.Mean),
			fmt.Sprintf("%.3f", row.Min),
			fmt.Sprintf("%.3f", row.Max),
			fmt.Sprintf("%.3f", row.Stddev),
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}
	return w.Error()
}

func renderAggregateIndex(title string, summary aggregateSummary, charts []plotChart) string {
	type chartInfo struct {
		File  string
		Title string
	}
	var list []chartInfo
	for _, ch := range charts {
		list = append(list, chartInfo{File: ch.File, Title: ch.Title})
	}
	tpl := template.Must(template.New("agg_index").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>{{.Title}}</title>
<style>
body { font-family: monospace; margin: 24px; }
.cards { display: grid; grid-template-columns: repeat(4, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }
.card { border: 1px solid #ddd; padding: 12px; border-radius: 6px; }
img { max-width: 100%; border: 1px solid #ddd; margin-bottom: 16px; }
table { border-collapse: collapse; margin-top: 24px; }
th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: right; }
th:first-child, td:first-child { text-align: left; }
</style></head><body>
<h1>{{.Title}}</h1>
<div class="cards">
<div class="card"><b>run_count</b><br>{{.Summary.RunCount}}</div>
<div class="card"><b>final_exec_total_mean</b><br>{{.Summary.FinalMean.ExecTotal}}</div>
<div class="card"><b>final_coverage_mean</b><br>{{.Summary.FinalMean.Coverage}}</div>
<div class="card"><b>final_ntfs_triage_mean</b><br>{{.Summary.FinalMean.NTFSTriage}}</div>
</div>
{{range .Charts}}
<h2>{{.Title}}</h2>
<img src="{{.File}}" alt="{{.Title}}">
{{end}}
<h2>Final Metrics</h2>
<table>
<tr><th>metric</th><th>mean</th><th>min</th><th>max</th><th>stddev</th></tr>
{{range .Summary.FinalMetricTable}}
<tr><td>{{.Name}}</td><td>{{printf "%.3f" .Mean}}</td><td>{{printf "%.3f" .Min}}</td><td>{{printf "%.3f" .Max}}</td><td>{{printf "%.3f" .Stddev}}</td></tr>
{{end}}
</table>
</body></html>`))
	var buf bytes.Buffer
	_ = tpl.Execute(&buf, map[string]any{
		"Title":   title,
		"Summary": summary,
		"Charts":  list,
	})
	return buf.String()
}

func trimPlotRows(rows []csvRow) ([]csvRow, float64) {
	start := -1
	for i, row := range rows {
		if rowHasPlotActivity(row) {
			start = i
			break
		}
	}
	if start <= 0 {
		return rows, 0
	}
	trimmed := append([]csvRow(nil), rows[start:]...)
	base := trimmed[0].ElapsedSec
	for i := range trimmed {
		trimmed[i].ElapsedSec -= base
		if trimmed[i].ElapsedSec < 0 {
			trimmed[i].ElapsedSec = 0
		}
	}
	return trimmed, base
}

func rowHasPlotActivity(row csvRow) bool {
	return row.ExecTotal > 0 ||
		row.Coverage > 0 ||
		row.Corpus > 0 ||
		row.RPCResults > 0 ||
		row.NonZeroExec > 0 ||
		row.RawSignal > 0 ||
		row.RawCover > 0 ||
		row.PostSignal > 0 ||
		row.PostCover > 0 ||
		row.CorpusSaves > 0 ||
		row.TriageEvents > 0 ||
		row.RunnerExecResults > 0 ||
		row.RunnerNonZeroCover > 0 ||
		row.RunnerLastCoverRecs > 0 ||
		row.PTDecodeCount > 0 ||
		row.PTLastTraceSize > 0 ||
		row.SYZCovDumpCount > 0 ||
		row.SYZCovLastRecords > 0
}

func readCSV(path string) ([]csvRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) <= 1 {
		return nil, nil
	}
	var rows []csvRow
	for _, rec := range records[1:] {
		if len(rec) < len(csvHeader()) {
			continue
		}
		rows = append(rows, csvRow{
			TimestampUnix:         mustAtoi64(rec[0]),
			ElapsedSec:            mustAtof(rec[1]),
			ExecTotal:             mustAtoi(rec[2]),
			ExecPerMin:            mustAtoi(rec[3]),
			Coverage:              mustAtoi(rec[4]),
			Corpus:                mustAtoi(rec[5]),
			Candidates:            mustAtoi(rec[6]),
			RPCResults:            mustAtoi(rec[7]),
			NonZeroExec:           mustAtoi(rec[8]),
			HangedCount:           mustAtoi(rec[9]),
			RawNonEmpty:           mustAtoi(rec[10]),
			RawSignal:             mustAtoi(rec[11]),
			RawCover:              mustAtoi(rec[12]),
			PostNonEmpty:          mustAtoi(rec[13]),
			PostSignal:            mustAtoi(rec[14]),
			PostCover:             mustAtoi(rec[15]),
			CorpusSaves:           mustAtoi(rec[16]),
			TriageEvents:          mustAtoi(rec[17]),
			NTFSTriage:            mustAtoi(rec[18]),
			RunnerExecResults:     mustAtoi(rec[19]),
			RunnerNonZeroCover:    mustAtoi(rec[20]),
			RunnerLastExecID:      mustAtoi(rec[21]),
			RunnerLastExecCalls:   mustAtoi(rec[22]),
			RunnerLastCoverRecs:   mustAtoi(rec[23]),
			HandshakeCount:        mustAtoi(rec[24]),
			RestartScheduled:      mustAtoi(rec[25]),
			RestartCompleted:      mustAtoi(rec[26]),
			BrokenPipeCount:       mustAtoi(rec[27]),
			SubmitCR3Count:        mustAtoi(rec[28]),
			LastSubmitCR3:         rec[29],
			PTDecodeCount:         mustAtoi(rec[30]),
			PTLastBytes:           mustAtoi(rec[31]),
			PTLastDecodeBytes:     mustAtoi(rec[32]),
			PTLastResult:          mustAtoi(rec[33]),
			PTLastBBAfter:         mustAtoi(rec[34]),
			PTLastTraceSize:       mustAtoi(rec[35]),
			SYZCovDumpCount:       mustAtoi(rec[36]),
			SYZCovLastRecords:     mustAtoi(rec[37]),
			SYZCovLastCall:        mustAtoi(rec[38]),
			SYZCovLastPCs:         mustAtoi(rec[39]),
			SYZCovLastIPCallbacks: mustAtoi(rec[40]),
			SYZCovLastIPRecorded:  mustAtoi(rec[41]),
		})
	}
	return rows, nil
}

func renderSVG(title string, x []float64, panels []plotPanel) string {
	const (
		width        = 1200
		marginLeft   = 84
		marginRight  = 20
		titleTop     = 28
		panelTop     = 52
		panelHeight  = 130
		panelGap     = 28
		marginBottom = 44
	)
	if len(panels) == 0 {
		panels = []plotPanel{{Title: title}}
	}
	height := panelTop + len(panels)*panelHeight + (len(panels)-1)*panelGap + marginBottom
	plotW := width - marginLeft - marginRight
	maxX := 1.0
	if len(x) > 0 && x[len(x)-1] > 0 {
		maxX = x[len(x)-1]
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`, width, height, width, height)
	fmt.Fprintf(&buf, `<rect width="100%%" height="100%%" fill="white"/>`)
	fmt.Fprintf(&buf, `<text x="%d" y="%d" font-family="monospace" font-size="18">%s</text>`, marginLeft, titleTop, template.HTMLEscapeString(title))

	for panelIdx, panel := range panels {
		top := panelTop + panelIdx*(panelHeight+panelGap)
		maxY := 0.0
		for _, s := range panel.Series {
			for _, v := range s.Values {
				if v > maxY {
					maxY = v
				}
			}
		}
		maxY = niceAxisMax(maxY)
		for i := 0; i <= 4; i++ {
			yv := maxY * float64(i) / 4.0
			y := top + panelHeight - int(float64(panelHeight)*float64(i)/4.0)
			fmt.Fprintf(&buf, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#e3e3e3" stroke-width="1"/>`, marginLeft, y, marginLeft+plotW, y)
			fmt.Fprintf(&buf, `<text x="%d" y="%d" font-family="monospace" font-size="11">%s</text>`, 8, y+4, template.HTMLEscapeString(formatAxisValue(yv)))
		}
		for i := 0; i <= 5; i++ {
			xv := maxX * float64(i) / 5.0
			xp := marginLeft + int(float64(plotW)*float64(i)/5.0)
			fmt.Fprintf(&buf, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#e3e3e3" stroke-width="1"/>`, xp, top, xp, top+panelHeight)
			if panelIdx == len(panels)-1 {
				fmt.Fprintf(&buf, `<text x="%d" y="%d" text-anchor="middle" font-family="monospace" font-size="11">%s</text>`, xp, height-10, template.HTMLEscapeString(formatSeconds(xv)))
			}
		}
		fmt.Fprintf(&buf, `<rect x="%d" y="%d" width="%d" height="%d" fill="none" stroke="#333333" stroke-width="1.2"/>`, marginLeft, top, plotW, panelHeight)
		fmt.Fprintf(&buf, `<text x="%d" y="%d" font-family="monospace" font-size="13">%s</text>`, marginLeft+8, top+16, template.HTMLEscapeString(panel.Title))
		legendY := top + 16
		for _, s := range panel.Series {
			path := buildPath(x, s.Values, marginLeft, top, plotW, panelHeight, maxX, maxY)
			if path == "" {
				continue
			}
			fmt.Fprintf(&buf, `<path d="%s" fill="none" stroke="%s" stroke-width="2"/>`, path, s.Color)
			if len(panel.Series) > 1 {
				fmt.Fprintf(&buf, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="3"/>`, width-210, legendY-4, width-182, legendY-4, s.Color)
				fmt.Fprintf(&buf, `<text x="%d" y="%d" font-family="monospace" font-size="11">%s</text>`, width-176, legendY, template.HTMLEscapeString(s.Name))
				legendY += 16
			}
		}
	}
	fmt.Fprintf(&buf, `<text x="%d" y="%d" text-anchor="middle" font-family="monospace" font-size="11">elapsed fuzzing time</text>`, marginLeft+plotW/2, height-24)
	buf.WriteString(`</svg>`)
	return buf.String()
}

func niceAxisMax(maxY float64) float64 {
	if maxY <= 0 {
		return 1
	}
	padded := maxY * 1.05
	if padded <= 1 {
		return 1
	}
	magnitude := math.Pow(10, math.Floor(math.Log10(padded)))
	normalized := padded / magnitude
	for _, candidate := range []float64{1, 2, 2.5, 5, 10} {
		if normalized <= candidate {
			return candidate * magnitude
		}
	}
	return 10 * magnitude
}

func formatSeconds(v float64) string {
	if v >= 60 {
		return fmt.Sprintf("%.0fs", v)
	}
	if v >= 10 {
		return fmt.Sprintf("%.1fs", v)
	}
	return fmt.Sprintf("%.2fs", v)
}

func formatAxisValue(v float64) string {
	abs := math.Abs(v)
	switch {
	case abs >= 1e9:
		return formatScaled(v, 1e9, "G")
	case abs >= 1e6:
		return formatScaled(v, 1e6, "M")
	case abs >= 1e3:
		return formatScaled(v, 1e3, "k")
	case abs >= 100:
		return fmt.Sprintf("%.0f", v)
	case abs >= 10:
		return trimFloat(fmt.Sprintf("%.1f", v))
	case abs >= 1:
		return trimFloat(fmt.Sprintf("%.2f", v))
	default:
		return trimFloat(fmt.Sprintf("%.3f", v))
	}
}

func formatScaled(v, scale float64, suffix string) string {
	return trimFloat(fmt.Sprintf("%.1f", v/scale)) + suffix
}

func trimFloat(s string) string {
	if !strings.Contains(s, ".") {
		return s
	}
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	return s
}

func buildPath(x, y []float64, left, top, width, height int, maxX, maxY float64) string {
	if len(x) == 0 || len(y) == 0 {
		return ""
	}
	n := len(x)
	if len(y) < n {
		n = len(y)
	}
	var parts []string
	for i := 0; i < n; i++ {
		px := float64(left)
		if maxX > 0 {
			px += (x[i] / maxX) * float64(width)
		}
		py := float64(top + height)
		if maxY > 0 {
			py -= (y[i] / maxY) * float64(height)
		}
		cmd := "L"
		if i == 0 {
			cmd = "M"
		}
		parts = append(parts, fmt.Sprintf("%s %.2f %.2f", cmd, px, py))
	}
	return strings.Join(parts, " ")
}

func renderIndex(title string, last csvRow, charts []plotChart) string {
	type chartInfo struct {
		File  string
		Title string
	}
	var list []chartInfo
	for _, ch := range charts {
		list = append(list, chartInfo{File: ch.File, Title: ch.Title})
	}
	tpl := template.Must(template.New("index").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>{{.Title}}</title>
<style>
body { font-family: monospace; margin: 24px; }
.cards { display: grid; grid-template-columns: repeat(4, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }
.card { border: 1px solid #ddd; padding: 12px; border-radius: 6px; }
img { max-width: 100%; border: 1px solid #ddd; margin-bottom: 16px; }
</style></head><body>
<h1>{{.Title}}</h1>
<div class="cards">
<div class="card"><b>exec_total</b><br>{{.Last.ExecTotal}}</div>
<div class="card"><b>coverage</b><br>{{.Last.Coverage}}</div>
<div class="card"><b>corpus</b><br>{{.Last.Corpus}}</div>
<div class="card"><b>ntfs_triage</b><br>{{.Last.NTFSTriage}}</div>
</div>
{{range .Charts}}
<h2>{{.Title}}</h2>
<img src="{{.File}}" alt="{{.Title}}">
{{end}}
</body></html>`))
	var buf bytes.Buffer
	_ = tpl.Execute(&buf, map[string]any{
		"Title":  title,
		"Last":   last,
		"Charts": list,
	})
	return buf.String()
}

func mustAtoi(v string) int {
	i, _ := strconv.Atoi(strings.TrimSpace(v))
	return i
}

func mustAtoi64(v string) int64 {
	i, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	return i
}

func mustAtof(v string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
	return f
}

func itoa(v int) string {
	return strconv.Itoa(v)
}

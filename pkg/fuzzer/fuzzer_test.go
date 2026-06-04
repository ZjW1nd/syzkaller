// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"bytes"
	"context"
	"fmt"
	"hash/crc32"
	"math/rand"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestFuzz(t *testing.T) {
	defer checkGoroutineLeaks()

	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	sysTarget := targets.Get(target.OS, target.Arch)
	if sysTarget.BrokenCompiler != "" {
		t.Skipf("skipping, broken cross-compiler: %v", sysTarget.BrokenCompiler)
	}
	executor := csource.BuildExecutor(t, target, "../..", "-fsanitize-coverage=trace-pc", "-g")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	corpusUpdates := make(chan corpus.NewItemEvent)
	fuzzer := NewFuzzer(ctx, &Config{
		Debug:  true,
		Corpus: corpus.NewMonitoredCorpus(ctx, corpusUpdates),
		Logf: func(level int, msg string, args ...any) {
			if level > 1 {
				return
			}
			t.Logf(msg, args...)
		},
		Coverage: true,
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["syz_test_fuzzer1"]: true,
		},
	}, rand.New(testutil.RandSource(t)), target)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case u := <-corpusUpdates:
				t.Logf("new prog:\n%s", u.ProgData)
			}
		}
	}()

	tf := &testFuzzer{
		t:         t,
		target:    target,
		fuzzer:    fuzzer,
		executor:  executor,
		iterLimit: 10000,
		expectedCrashes: map[string]bool{
			"first bug":  true,
			"second bug": true,
		},
	}
	tf.run()

	t.Logf("resulting corpus:")
	for _, p := range fuzzer.Config.Corpus.Programs() {
		t.Logf("-----")
		t.Logf("%s", p.Serialize())
	}
}

func TestDefaultExecOptsWindowsVMLessDoesNotForceFeedback(t *testing.T) {
	cfg := &mgrconfig.Config{
		Cover:   true,
		Sandbox: "none",
		Derived: mgrconfig.Derived{
			TargetOS: "windows",
			VMLess:   true,
		},
	}
	opts := DefaultExecOpts(cfg, flatrpc.FeatureCoverage, false)
	want := flatrpc.ExecFlagThreaded |
		flatrpc.ExecFlagDedupCover
	if opts.ExecFlags != want {
		t.Fatalf("unexpected exec flags: got=%v want=%v", opts.ExecFlags, want)
	}
	if opts.EnvFlags&flatrpc.ExecEnvSignal == 0 {
		t.Fatal("coverage-enabled config should still negotiate signal support in env flags")
	}
}

func TestWindowsSkipsHintsForAutomaticHelpers(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !target.Helpers.SkipHintsForAutomaticHelpers {
		t.Fatal("windows target did not enable helper hints skipping")
	}
	helper := target.SyscallMap["CreateFileA"]
	if helper == nil || !target.CallIsAutomaticHelper(helper) {
		t.Fatal("CreateFileA is not classified as AutomaticHelper")
	}
	nonHelper := target.SyscallMap["NtFsControlFile"]
	if nonHelper == nil {
		t.Fatal("NtFsControlFile is missing from windows target")
	}
	fuzzer := &Fuzzer{
		Config: &Config{
			Comparisons:    true,
			NewInputFilter: func(string) bool { return true },
		},
		target: target,
		Cover:  newCover(),
	}
	job := &triageJob{fuzzer: fuzzer}
	helperProg := &prog.Prog{Target: target, Calls: []*prog.Call{{Meta: helper}}}
	if job.shouldStartHints(helperProg, 0) {
		t.Fatal("hints should be skipped for AutomaticHelper syscalls on windows")
	}
	targetProg := &prog.Prog{Target: target, Calls: []*prog.Call{{Meta: nonHelper}}}
	if !job.shouldStartHints(targetProg, 0) {
		t.Fatal("hints should still run for non-helper target syscalls")
	}
	unscored := target.SyscallMap["NtQuerySystemInformation"]
	if unscored == nil {
		t.Fatal("NtQuerySystemInformation is missing from windows target")
	}
	unscoredProg := &prog.Prog{Target: target, Calls: []*prog.Call{{Meta: unscored}}}
	if !job.shouldStartHints(unscoredProg, 0) {
		t.Fatal("unscored windows calls should not be blocked by stage-aware hints threshold")
	}
	var triage map[int]*triageCall
	fuzzer.triageProgCall("", helperProg, &flatrpc.CallInfo{Signal: []uint64{1, 2, 3}, Cover: []uint64{1, 2, 3}}, 0, &triage)
	if len(triage) != 0 {
		t.Fatal("helper call should not produce a triage entry on windows")
	}
	fuzzer.triageProgCall("", targetProg, &flatrpc.CallInfo{Signal: []uint64{4, 5, 6}, Cover: []uint64{4, 5, 6}}, 0, &triage)
	if len(triage) != 1 {
		t.Fatal("deep non-helper call should still produce triage entry on windows")
	}
	var triageUnscored map[int]*triageCall
	fuzzer.triageProgCall("", unscoredProg, &flatrpc.CallInfo{Signal: []uint64{7, 8, 9}, Cover: []uint64{7, 8, 9}}, 0, &triageUnscored)
	if len(triageUnscored) != 1 {
		t.Fatal("unscored windows calls should not be blocked by stage-aware triage threshold")
	}
}

func TestForceGenerateEveryNInterleavesFreshGeneration(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	corp := corpus.NewCorpus(ctx)
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:              corp,
		EnabledCalls:        map[*prog.Syscall]bool{target.SyscallMap["test$length11"]: true},
		ForceGenerateEveryN: 2,
	}, rand.New(rand.NewSource(0)), target)

	candidateProg, err := target.Deserialize([]byte("test$manual(0x1)"), prog.Strict)
	if err != nil {
		t.Fatal(err)
	}
	fuzzer.statCandidates.Add(1)
	fuzzer.candidateQueue.Submit(&queue.Request{
		Prog: candidateProg,
		Stat: fuzzer.statExecCandidate,
	})

	first := fuzzer.source.Next()
	if first == nil || first.Stat != fuzzer.statExecCandidate {
		t.Fatalf("first request = %#v, want candidate", first)
	}
	second := fuzzer.source.Next()
	if second == nil || second.Stat != fuzzer.statExecGenerate {
		t.Fatalf("second request = %#v, want generated request", second)
	}
}

func TestForceGenerateEveryNDoesNotPreemptTriageCandidateQueue(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	corp := corpus.NewCorpus(ctx)
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:              corp,
		EnabledCalls:        map[*prog.Syscall]bool{target.SyscallMap["test$length11"]: true},
		ForceGenerateEveryN: 2,
	}, rand.New(rand.NewSource(0)), target)

	triageCandidate := &queue.Request{Origin: "triage-candidate"}
	candidate := &queue.Request{Origin: "candidate"}
	fuzzer.triageCandidateQueue.Append().Submit(triageCandidate)
	fuzzer.candidateQueue.Submit(candidate)

	first := fuzzer.source.Next()
	if first != triageCandidate {
		t.Fatalf("first request origin=%q, want triage-candidate", first.Origin)
	}
	second := fuzzer.source.Next()
	if second != candidate {
		t.Fatalf("second request origin=%q, want candidate", second.Origin)
	}
	third := fuzzer.source.Next()
	if third == nil || third.Stat != fuzzer.statExecGenerate {
		t.Fatalf("third request = %#v, want generated request", third)
	}
}

func TestFuzzerNextFallsBackToFreshGenerationWhenSourceIsEmpty(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus: corpus.NewCorpus(ctx),
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["test$length11"]: true,
		},
	}, rand.New(rand.NewSource(0)), target)
	fuzzer.source = queue.Callback(func() *queue.Request { return nil })
	req := fuzzer.Next()
	if req == nil || req.Prog == nil {
		t.Fatal("Next did not fall back to a fresh generated program")
	}
	if req.Stat != fuzzer.statExecGenerate {
		t.Fatalf("fallback request stat=%v, want generate stat", req.Stat)
	}
}

func TestWindowsSkipsCorpusForAutomaticHelpers(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !target.Helpers.SkipCorpusForAutomaticHelpers {
		t.Fatal("windows target did not enable helper corpus skipping")
	}
	helper := target.SyscallMap["CreateFileA"]
	if helper == nil || !target.CallIsAutomaticHelper(helper) {
		t.Fatal("CreateFileA is not classified as AutomaticHelper")
	}
	nonHelper := target.SyscallMap["NtFsControlFile"]
	if nonHelper == nil {
		t.Fatal("NtFsControlFile is missing from windows target")
	}
	fuzzer := &Fuzzer{Config: &Config{}, target: target}
	job := &triageJob{fuzzer: fuzzer}
	helperProg := &prog.Prog{Target: target, Calls: []*prog.Call{{Meta: helper}}}
	if job.shouldPersistCall(helperProg, 0) {
		t.Fatal("helper call should not be persisted as owning corpus entry on windows")
	}
	targetProg := &prog.Prog{Target: target, Calls: []*prog.Call{{Meta: nonHelper}}}
	if !job.shouldPersistCall(targetProg, 0) {
		t.Fatal("non-helper target call should still be persisted")
	}
}

func TestWindowsAFDSkipsCorpusForSeedOnlyPrograms(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	seedOnly := profiled.SyscallMap["WSAEventSelect$tcp"]
	if seedOnly == nil || !seedOnly.Attrs.NoGenerate {
		t.Fatal("WSAEventSelect$tcp should be seed-only in the windows target")
	}
	creator := profiled.SyscallMap["ConnectEx$inet_tcp"]
	if creator == nil || creator.Attrs.NoGenerate {
		t.Fatal("ConnectEx$inet_tcp should remain generatable")
	}
	fuzzer := &Fuzzer{Config: &Config{}, target: profiled}
	job := &triageJob{fuzzer: fuzzer, origin: "candidate"}
	seedOnlyProg := &prog.Prog{Target: profiled, Calls: []*prog.Call{{Meta: seedOnly}}}
	if job.shouldPersistCall(seedOnlyProg, 0) {
		t.Fatal("seed-only AFD programs should not be persisted as corpus entries")
	}
	creatorProg := &prog.Prog{Target: profiled, Calls: []*prog.Call{{Meta: creator}}}
	if !job.shouldPersistCall(creatorProg, 0) {
		t.Fatal("regular public AFD calls should still be persisted")
	}
}

func TestWindowsSkipsTriageForAutomaticHelpers(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !target.Helpers.SkipTriageForAutomaticHelpers {
		t.Fatal("windows target did not enable helper triage skipping")
	}
	helper := target.SyscallMap["CreateFileA"]
	if helper == nil || !target.CallIsAutomaticHelper(helper) {
		t.Fatal("CreateFileA is not classified as AutomaticHelper")
	}
	nonHelper := target.SyscallMap["NtFsControlFile"]
	if nonHelper == nil {
		t.Fatal("NtFsControlFile is missing from windows target")
	}
	fuzzer := &Fuzzer{
		Config: &Config{
			NewInputFilter: func(string) bool { return true },
		},
		target: target,
		Cover:  newCover(),
	}
	helperProg := &prog.Prog{Target: target, Calls: []*prog.Call{{Meta: helper}}}
	var triage map[int]*triageCall
	fuzzer.triageProgCall("", helperProg, &flatrpc.CallInfo{
		Signal: []uint64{1, 2, 3},
		Cover:  []uint64{1, 2, 3},
	}, 0, &triage)
	if len(triage) != 0 {
		t.Fatal("helper call should not produce a triage entry on windows")
	}
	targetProg := &prog.Prog{Target: target, Calls: []*prog.Call{{Meta: nonHelper}}}
	fuzzer.triageProgCall("", targetProg, &flatrpc.CallInfo{
		Signal: []uint64{4, 5, 6},
		Cover:  []uint64{4, 5, 6},
	}, 0, &triage)
	if len(triage) != 1 {
		t.Fatalf("non-helper call should still produce triage entry, got %d", len(triage))
	}
}

func TestWindowsAFDSkipsTriageForSeedOnlyPrograms(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	seedOnly := profiled.SyscallMap["WSAEventSelect$tcp"]
	if seedOnly == nil || !seedOnly.Attrs.NoGenerate {
		t.Fatal("WSAEventSelect$tcp should be seed-only in the windows target")
	}
	creator := profiled.SyscallMap["ConnectEx$inet_tcp"]
	if creator == nil || creator.Attrs.NoGenerate {
		t.Fatal("ConnectEx$inet_tcp should remain generatable")
	}
	fuzzer := &Fuzzer{
		Config: &Config{
			NewInputFilter: func(string) bool { return true },
		},
		target: profiled,
		Cover:  newCover(),
	}
	seedOnlyProg := &prog.Prog{Target: profiled, Calls: []*prog.Call{{Meta: seedOnly}}}
	var triage map[int]*triageCall
	fuzzer.triageProgCall("candidate", seedOnlyProg, &flatrpc.CallInfo{
		Signal: []uint64{1, 2, 3},
		Cover:  []uint64{1, 2, 3},
	}, 0, &triage)
	if len(triage) != 0 {
		t.Fatal("seed-only AFD program should update max signal without entering triage")
	}
	if got := fuzzer.Cover.CopyMaxSignal().Len(); got != 3 {
		t.Fatalf("seed-only AFD program max signal=%d, want 3", got)
	}
	creatorProg := &prog.Prog{Target: profiled, Calls: []*prog.Call{{Meta: creator}}}
	fuzzer.triageProgCall("candidate", creatorProg, &flatrpc.CallInfo{
		Signal: []uint64{4, 5, 6},
		Cover:  []uint64{4, 5, 6},
	}, 0, &triage)
	if len(triage) != 1 {
		t.Fatalf("pure async state creator should still produce triage, got %d", len(triage))
	}
}

func TestWindowsAFDTriageKeepsDeepOwnerOverScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p, err := profiled.Deserialize([]byte(
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = bind$inet_tcp(r0, &(0x7f0000000000)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = listen$inet_tcp(r1, 0x1)\n"+
			"r3 = accept$inet_tcp(r2, 0x0, 0x0)\n"+
			"WSARecv$accept(r3, &(0x7f0000000100)=[{0x40, &(0x7f0000000180)='\\x00'/64}], 0x1, &(0x7f0000000200), &(0x7f0000000240)=0x0, 0x0, 0x0)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	listenCall := windowsFuzzerTestCallIndex(t, p, "listen$inet_tcp")
	deepCall := windowsFuzzerTestCallIndex(t, p, "WSARecv$accept")
	fuzzer := &Fuzzer{
		Config: &Config{
			NewInputFilter: func(string) bool { return true },
		},
		target: profiled,
		Cover:  newCover(),
	}
	var triage map[int]*triageCall
	fuzzer.triageProgCall("candidate", p, &flatrpc.CallInfo{
		Signal: []uint64{1},
		Cover:  []uint64{1},
	}, listenCall, &triage)
	fuzzer.triageProgCall("candidate", p, &flatrpc.CallInfo{
		Signal: []uint64{2},
		Cover:  []uint64{2},
	}, deepCall, &triage)
	if len(triage) != 1 {
		t.Fatalf("triage owners=%v, want only deep AFD call", triage)
	}
	if _, ok := triage[deepCall]; !ok {
		t.Fatalf("triage owner is %v, want %s", triage, p.CallName(deepCall))
	}
}

func windowsFuzzerTestCallIndex(t *testing.T, p *prog.Prog, name string) int {
	t.Helper()
	for i, call := range p.Calls {
		if call.Meta != nil && call.Meta.Name == name {
			return i
		}
	}
	t.Fatalf("program is missing %s", name)
	return -1
}

func BenchmarkFuzzer(b *testing.B) {
	b.ReportAllocs()
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := map[*prog.Syscall]bool{}
	for _, c := range target.Syscalls {
		calls[c] = true
	}
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:       corpus.NewCorpus(ctx),
		Coverage:     true,
		EnabledCalls: calls,
	}, rand.New(rand.NewSource(time.Now().UnixNano())), target)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := fuzzer.Next()
			res, _, _ := emulateExec(req)
			req.Done(res)
		}
	})
}

// Based on the example from Go documentation.
var crc32q = crc32.MakeTable(0xD5828281)

func emulateExec(req *queue.Request) (*queue.Result, string, error) {
	serializedLines := bytes.Split(req.Prog.Serialize(), []byte("\n"))
	var info flatrpc.ProgInfo
	for i, call := range req.Prog.Calls {
		cover := []uint64{uint64(call.Meta.ID*1024) +
			uint64(crc32.Checksum(serializedLines[i], crc32q)%4)}
		callInfo := &flatrpc.CallInfo{}
		if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover > 0 {
			callInfo.Cover = cover
		}
		if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0 {
			callInfo.Signal = cover
		}
		info.Calls = append(info.Calls, callInfo)
	}
	return &queue.Result{Info: &info}, "", nil
}

type testFuzzer struct {
	t               testing.TB
	target          *prog.Target
	fuzzer          *Fuzzer
	executor        string
	mu              sync.Mutex
	crashes         map[string]int
	expectedCrashes map[string]bool
	iter            int
	iterLimit       int
	done            func()
	finished        atomic.Bool
}

func (f *testFuzzer) run() {
	f.crashes = make(map[string]int)
	ctx, done := context.WithCancel(context.Background())
	f.done = done
	var output bytes.Buffer
	cfg := &rpcserver.LocalConfig{
		Config: rpcserver.Config{
			Config: vminfo.Config{
				Debug:    true,
				Cover:    true,
				Target:   f.target,
				Features: flatrpc.FeatureSandboxNone | flatrpc.FeatureCoverage,
				Sandbox:  flatrpc.ExecEnvSandboxNone,
			},
			Procs:    4,
			Slowdown: 1,
		},
		Executor:     f.executor,
		Dir:          f.t.TempDir(),
		OutputWriter: &output,
	}
	cfg.MachineChecked = func(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source {
		return f
	}
	if err := rpcserver.RunLocal(ctx, cfg); err != nil {
		f.t.Logf("executor output:\n%s", output.String())
		f.t.Fatal(err)
	}
	assert.Equal(f.t, len(f.expectedCrashes), len(f.crashes), "not all expected crashes were found")
	assert.NotEmpty(f.t, f.fuzzer.Config.Corpus.StatProgs.Val(), "must have non-empty corpus")
	assert.NotEmpty(f.t, f.fuzzer.Config.Corpus.StatSignal.Val(), "must have non-empty signal")
}

func (f *testFuzzer) Next() *queue.Request {
	if f.finished.Load() {
		return nil
	}
	req := f.fuzzer.Next()
	req.ExecOpts.EnvFlags |= flatrpc.ExecEnvSignal | flatrpc.ExecEnvSandboxNone
	req.ReturnOutput = true
	req.ReturnError = true
	req.OnDone(f.OnDone)
	return req
}

func (f *testFuzzer) OnDone(req *queue.Request, res *queue.Result) bool {
	// TODO: support hints emulation.
	match := crashRe.FindSubmatch(res.Output)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.finished.Load() {
		// Don't touch f.crashes in this case b/c it can cause races with the main goroutine,
		// and logging can cause "Log in goroutine after TestFuzz has completed" panic.
		return true
	}
	if match != nil {
		crash := string(match[1])
		f.t.Logf("CRASH: %s", crash)
		res.Status = queue.Crashed
		if !f.expectedCrashes[crash] {
			f.t.Errorf("unexpected crash: %q", crash)
		}
		f.crashes[crash]++
	}
	f.iter++
	corpusProgs := f.fuzzer.Config.Corpus.StatProgs.Val()
	signal := f.fuzzer.Config.Corpus.StatSignal.Val()
	if f.iter%100 == 0 {
		f.t.Logf("<iter %d>: corpus %d, signal %d, max signal %d, crash types %d, running jobs %d",
			f.iter, corpusProgs, signal, len(f.fuzzer.Cover.maxSignal),
			len(f.crashes), f.fuzzer.statJobs.Val())
	}
	criteriaMet := len(f.crashes) == len(f.expectedCrashes) &&
		corpusProgs > 0 && signal > 0
	if f.iter > f.iterLimit || criteriaMet {
		f.done()
		f.finished.Store(true)
	}
	return true
}

var crashRe = regexp.MustCompile(`{{CRASH: (.*?)}}`)

func checkGoroutineLeaks() {
	// Inspired by src/net/http/main_test.go.
	buf := make([]byte, 2<<20)
	err := ""
	for range 3 {
		buf = buf[:runtime.Stack(buf, true)]
		err = ""
		for _, g := range strings.Split(string(buf), "\n\n") {
			if !strings.Contains(g, "pkg/fuzzer/fuzzer.go") {
				continue
			}
			err = fmt.Sprintf("%sLeaked goroutine:\n%s", err, g)
		}
		if err == "" {
			return
		}
		// Give ctx.Done() a chance to propagate to all goroutines.
		time.Sleep(100 * time.Millisecond)
	}
	if err != "" {
		panic(err)
	}
}

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
	"github.com/google/syzkaller/pkg/signal"
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

func TestDefaultExecOptsWindowsVMLessCollectsFeedback(t *testing.T) {
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
		flatrpc.ExecFlagDedupCover |
		flatrpc.ExecFlagCollectSignal |
		flatrpc.ExecFlagCollectCover
	if opts.ExecFlags != want {
		t.Fatalf("unexpected exec flags: got=%v want=%v", opts.ExecFlags, want)
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
	shallow := target.SyscallMap["connect$inet_tcp"]
	if shallow == nil {
		t.Fatal("connect$inet_tcp is missing from windows target")
	}
	shallowProg := &prog.Prog{Target: target, Calls: []*prog.Call{{Meta: shallow}}}
	if job.shouldStartHints(shallowProg, 0) {
		t.Fatal("hints should be skipped for shallow scaffold calls on windows")
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
	fuzzer.triageProgCall("", shallowProg, &flatrpc.CallInfo{Signal: []uint64{2, 3, 4}, Cover: []uint64{2, 3, 4}}, 0, &triage)
	if len(triage) != 0 {
		t.Fatal("shallow scaffold call should not produce triage entry on windows")
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

func TestWindowsPreferCollideProgramForTemplatePaths(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if target.RuntimePolicy.PreferCollideProgram == nil {
		t.Fatal("windows target did not install PreferCollideProgram hook")
	}
	templateProg, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_tcp(r0, 'abcd', 0x4, 0x0)\n"+
			"recv$inet_tcp(r0, &(0x7f00000001a0)='\\x00'/64, 0x40, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize template program: %v", err)
	}
	if !target.RuntimePolicy.PreferCollideProgram(templateProg) {
		t.Fatal("windows target did not prefer collide for local continuation template")
	}
	shallowProg, err := target.Deserialize([]byte(
		"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"listen$inet_tcp(r0, 0x1)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize shallow program: %v", err)
	}
	if target.RuntimePolicy.PreferCollideProgram(shallowProg) {
		t.Fatal("windows target unexpectedly preferred collide for shallow scaffold program")
	}
	fuzzer := &Fuzzer{target: target}
	if got := fuzzer.collideChanceForProg(templateProg); got != 1 {
		t.Fatalf("template collide chance=%d, want 1", got)
	}
	if got := fuzzer.collideChanceForProg(shallowProg); got != 3 {
		t.Fatalf("shallow collide chance=%d, want 3", got)
	}
}

func TestWindowsAutoAddsHelpersToNoMutate(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:       corpus.NewCorpus(ctx),
		EnabledCalls: map[*prog.Syscall]bool{target.SyscallMap["NtFsControlFile"]: true},
	}, rand.New(rand.NewSource(0)), target)
	for _, name := range []string{
		"CloseHandle", "CreateFileA", "CreateFile2", "VirtualAlloc",
		"WSAStartup", "WSACleanup", "socket$inet_tcp", "socket$inet_udp", "closesocket$any",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !fuzzer.Config.NoMutateCalls[call.ID] {
			t.Fatalf("automatic helper %q was not auto-added to NoMutateCalls", name)
		}
	}
}

func TestWindowsTemplateObserverStatsHooked(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus: corpus.NewCorpus(ctx),
	}, rand.New(rand.NewSource(0)), target.Clone())
	if fuzzer.target.ObserveTemplateHook == nil {
		t.Fatal("windows target does not expose template observer hook")
	}
	fuzzer.target.ObserveTemplateHook("gen:windows")
	fuzzer.target.ObserveTemplateHook("corpus:windows")
	fuzzer.target.ObserveTemplateHook("collide:windows")
	fuzzer.target.ObserveTemplateHook("rc_try:windows")
	fuzzer.target.ObserveTemplateHook("rc_hit:windows")
	fuzzer.target.ObserveTemplateHook("rc_no_candidates:windows")
	fuzzer.target.ObserveTemplateHook("rc_zero_score:windows")
	if got := fuzzer.statWindowsTemplateGen.Val(); got != 1 {
		t.Fatalf("gen template stat=%d, want 1", got)
	}
	if got := fuzzer.statWindowsTemplateCorpus.Val(); got != 1 {
		t.Fatalf("corpus template stat=%d, want 1", got)
	}
	if got := fuzzer.statWindowsTemplateCollide.Val(); got != 1 {
		t.Fatalf("collide template stat=%d, want 1", got)
	}
	if got := fuzzer.statWindowsResourceCentricTry.Val(); got != 1 {
		t.Fatalf("resourceCentric try stat=%d, want 1", got)
	}
	if got := fuzzer.statWindowsResourceCentricHit.Val(); got != 1 {
		t.Fatalf("resourceCentric hit stat=%d, want 1", got)
	}
	if got := fuzzer.statWindowsResourceCentricNoCandidates.Val(); got != 1 {
		t.Fatalf("resourceCentric no-candidates stat=%d, want 1", got)
	}
	if got := fuzzer.statWindowsResourceCentricZeroScore.Val(); got != 1 {
		t.Fatalf("resourceCentric zero-score stat=%d, want 1", got)
	}
}

func TestWindowsTemplateStatsIncrementOnRealStrategyHooks(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus: corpus.NewCorpus(ctx),
	}, rand.New(rand.NewSource(0)), target.Clone())

	enabled := map[*prog.Syscall]bool{
		fuzzer.target.SyscallMap["recv$inet_accept"]:      true,
		fuzzer.target.SyscallMap["getsockopt$int_accept"]: true,
	}
	ct := fuzzer.target.BuildChoiceTable(nil, enabled)
	genProg, err := fuzzer.target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'main', 0x4, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize generation program: %v", err)
	}
	if idx := fuzzer.target.Bias.SelectGeneratedCall(genProg, len(genProg.Calls), genProg.Calls[len(genProg.Calls)-1].Meta.ID, ct); idx < 0 {
		t.Fatal("windows target did not select generated call")
	}
	if got := fuzzer.statWindowsTemplateGen.Val(); got == 0 {
		t.Fatal("windows generation template stat did not increment")
	}

	corpusProg, err := fuzzer.target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'abcd', 0x4, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize corpus program: %v", err)
	}
	var candidate *prog.ResultArg
	prog.ForeachArg(corpusProg.Calls[len(corpusProg.Calls)-1], func(arg prog.Arg, _ *prog.ArgCtx) {
		if res, ok := arg.(*prog.ResultArg); ok && res.Res != nil && res.Res.Type().Name() == "SOCKET_ACCEPT" {
			candidate = res.Res
		}
	})
	if candidate == nil {
		t.Fatal("failed to capture corpus candidate root")
	}
	current := fuzzer.target.SyscallMap["recv$inet_accept"]
	if current == nil {
		t.Fatal("missing recv$inet_accept")
	}
	if score := fuzzer.target.CorpusResourceScore(current, candidate, genProg, len(genProg.Calls), corpusProg); score == 0 {
		t.Fatal("windows target did not score corpus resource")
	}
	if got := fuzzer.statWindowsTemplateCorpus.Val(); got == 0 {
		t.Fatal("windows corpus template stat did not increment")
	}

	collideProg, err := fuzzer.target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_tcp(r0, 'abcd', 0x4, 0x0)\n"+
			"recv$inet_tcp(r0, &(0x7f00000001a0)='\\x00'/64, 0x40, 0x0)\n"+
			"getsockopt$int_tcp(r0, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize collide program: %v", err)
	}
	if indices, blocked := fuzzer.target.SelectCollideCallIndices(collideProg.Calls); blocked || len(indices) == 0 {
		t.Fatalf("windows collide selector failed: blocked=%v indices=%v", blocked, indices)
	}
	if got := fuzzer.statWindowsTemplateCollide.Val(); got == 0 {
		t.Fatal("windows collide template stat did not increment")
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

func TestBorrowingCorpusFeedsFreshGeneration(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	corp := corpus.NewCorpus(ctx)
	borrowProg, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e34, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_tcp(r0, 'ping', 0x4, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus: corp,
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["recv$inet_tcp"]: true,
		},
		BorrowingCorpus: []*prog.Prog{borrowProg},
	}, rand.New(rand.NewSource(0)), target)
	req := genProgRequest(fuzzer, rand.New(rand.NewSource(0)))
	if req == nil || req.Prog == nil {
		t.Fatal("genProgRequest returned nil")
	}
	serialized := string(req.Prog.Serialize())
	if !strings.Contains(serialized, "send$inet_tcp") {
		t.Fatalf("fresh generation did not borrow the expected tcp slice:\n%s", serialized)
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

func TestWindowsPrefersDeeperTriageOwner(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if target.CallRelevanceScore == nil {
		t.Fatal("windows target did not set CallRelevanceScore")
	}
	connect := target.SyscallMap["connect$inet_tcp"]
	send := target.SyscallMap["send$inet_tcp"]
	if connect == nil || send == nil {
		t.Fatal("connect$inet_tcp/send$inet_tcp syscalls missing from windows target")
	}
	if target.CallRelevanceScore(send) <= target.CallRelevanceScore(connect) {
		t.Fatalf("expected send to be deeper than connect: send=%d connect=%d",
			target.CallRelevanceScore(send), target.CallRelevanceScore(connect))
	}
	fuzzer := &Fuzzer{
		Config: &Config{
			NewInputFilter: func(string) bool { return true },
		},
		target: target,
		Cover:  newCover(),
	}
	p := &prog.Prog{Target: target, Calls: []*prog.Call{{Meta: connect}, {Meta: send}}}
	var triage map[int]*triageCall
	fuzzer.triageProgCall("", p, &flatrpc.CallInfo{Signal: []uint64{11}, Cover: []uint64{11}}, 0, &triage)
	if len(triage) != 0 {
		t.Fatalf("expected shallow connect to be skipped by triage threshold, got %+v", triage)
	}
	fuzzer.triageProgCall("", p, &flatrpc.CallInfo{Signal: []uint64{22}, Cover: []uint64{22}}, 1, &triage)
	if len(triage) != 1 || triage[1] == nil {
		t.Fatalf("expected deeper send to be triaged, got %+v", triage)
	}
}

func TestWindowsPrefersVeryDeepTriageOwner(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	send := target.SyscallMap["send$inet_accept"]
	transmit := target.SyscallMap["TransmitFile$inet_accept"]
	if send == nil || transmit == nil {
		t.Fatal("send/transmit syscalls missing from windows target")
	}
	fuzzer := &Fuzzer{
		Config: &Config{
			NewInputFilter: func(string) bool { return true },
		},
		target: target,
		Cover:  newCover(),
	}
	p := &prog.Prog{Target: target, Calls: []*prog.Call{{Meta: send}, {Meta: transmit}}}
	var triage map[int]*triageCall
	fuzzer.triageProgCall("", p, &flatrpc.CallInfo{Signal: []uint64{11}, Cover: []uint64{11}}, 0, &triage)
	if len(triage) != 1 || triage[0] == nil {
		t.Fatalf("expected send to be triaged first, got %+v", triage)
	}
	fuzzer.triageProgCall("", p, &flatrpc.CallInfo{Signal: []uint64{22}, Cover: []uint64{22}}, 1, &triage)
	if len(triage) != 1 || triage[0] == nil {
		t.Fatalf("expected stable send path to remain triage owner over transmit, got %+v", triage)
	}
}

func TestWindowsPrefersStableDataPathTriageOwnerOverVeryDeepTemplateCall(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	send := target.SyscallMap["send$inet_accept"]
	wsaRecv := target.SyscallMap["WSARecvEx$inet_accept"]
	if send == nil || wsaRecv == nil {
		t.Fatal("send/WSARecvEx syscalls missing from windows target")
	}
	fuzzer := &Fuzzer{
		Config: &Config{
			NewInputFilter: func(string) bool { return true },
		},
		target: target,
		Cover:  newCover(),
	}
	p := &prog.Prog{Target: target, Calls: []*prog.Call{{Meta: send}, {Meta: wsaRecv}}}
	var triage map[int]*triageCall
	fuzzer.triageProgCall("", p, &flatrpc.CallInfo{Signal: []uint64{11}, Cover: []uint64{11}}, 0, &triage)
	if len(triage) != 1 || triage[0] == nil {
		t.Fatalf("expected send to be triaged first, got %+v", triage)
	}
	fuzzer.triageProgCall("", p, &flatrpc.CallInfo{Signal: []uint64{22}, Cover: []uint64{22}}, 1, &triage)
	if len(triage) != 1 || triage[0] == nil {
		t.Fatalf("expected send to remain triage owner over WSARecvEx, got %+v", triage)
	}
}

func TestWindowsAcceptRaceProfilePrefersDeepAcceptOwnerOverSend(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	send := acceptRace.SyscallMap["send$inet_accept"]
	wsaRecv := acceptRace.SyscallMap["WSARecvEx$inet_accept"]
	getsockopt := acceptRace.SyscallMap["getsockopt$int_accept"]
	if send == nil || wsaRecv == nil || getsockopt == nil {
		t.Fatal("missing send/accept-side deep syscalls")
	}
	fuzzer := &Fuzzer{
		Config: &Config{
			NewInputFilter: func(string) bool { return true },
		},
		target: acceptRace,
		Cover:  newCover(),
	}
	p := &prog.Prog{Target: acceptRace, Calls: []*prog.Call{{Meta: send}, {Meta: wsaRecv}, {Meta: getsockopt}}}

	var triage map[int]*triageCall
	fuzzer.triageProgCall("", p, &flatrpc.CallInfo{Signal: []uint64{11}, Cover: []uint64{11}}, 0, &triage)
	if len(triage) != 1 || triage[0] == nil {
		t.Fatalf("expected send to be triaged first, got %+v", triage)
	}
	fuzzer.triageProgCall("", p, &flatrpc.CallInfo{Signal: []uint64{22}, Cover: []uint64{22}}, 1, &triage)
	if len(triage) != 1 || triage[1] == nil {
		t.Fatalf("expected accept-race profile to prefer WSARecvEx owner over send, got %+v", triage)
	}
	fuzzer.triageProgCall("", p, &flatrpc.CallInfo{Signal: []uint64{33}, Cover: []uint64{33}}, 2, &triage)
	if len(triage) != 1 || (triage[1] == nil && triage[2] == nil) {
		t.Fatalf("expected accept-race profile to retain a deep accept-side owner over earlier send/recv, got %+v", triage)
	}
}

func TestWindowsAcceptRaceImmediateCollideQueuedAfterCorpusSave(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	if acceptRace.RuntimePolicy.ShouldScheduleImmediateCollide == nil {
		t.Fatal("accept-race target missing immediate collide hook")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:  corpus.NewCorpus(ctx),
		Collide: true,
	}, rand.New(rand.NewSource(0)), acceptRace)
	job := &triageJob{
		fuzzer:  fuzzer,
		origin:  "gen",
		queue:   queue.Plain(),
		flags:   ProgMinimized,
		traceID: "triage-1",
	}
	p, err := acceptRace.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'main', 0x4, 0x0)\n"+
			"getsockopt$int_accept(r2, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	job.p = p
	info := &triageCall{
		newStableSignal: signal.FromRaw([]uint64{1, 2, 3}, 0),
		stableSignal:    signal.FromRaw([]uint64{1, 2, 3}, 0),
	}
	collided := job.immediateCollideProg(p)
	if collided == nil || string(collided.Serialize()) == string(p.Serialize()) {
		t.Fatalf("expected immediate collide helper to produce a distinct program:\norig:\n%s\ncollided:\n%s",
			p.Serialize(), collided.Serialize())
	}
	job.handleCall(8, info)
	req := fuzzer.immediateCollideQueue.Next()
	if req == nil {
		t.Fatal("expected immediate collide request to be queued")
	}
	if req.Origin != "collide:triage" {
		t.Fatalf("immediate collide origin=%q", req.Origin)
	}
	if req.TraceID == "" {
		t.Fatal("immediate collide trace id is empty")
	}
	if req.Stat != fuzzer.statExecCollide {
		t.Fatal("immediate collide request did not use collide stat")
	}
}

func TestWindowsAcceptRaceImmediateCollideQueuedAfterTransmitCorpusSave(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	if acceptRace.RuntimePolicy.ShouldScheduleImmediateCollide == nil {
		t.Fatal("accept-race target missing immediate collide hook")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:  corpus.NewCorpus(ctx),
		Collide: true,
	}, rand.New(rand.NewSource(0)), acceptRace)
	job := &triageJob{
		fuzzer:  fuzzer,
		origin:  "candidate",
		queue:   queue.Plain(),
		flags:   ProgMinimized | progCandidate,
		traceID: "triage-tx-1",
	}
	p, err := acceptRace.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"r3 = CreateFileA(&(0x7f0000000200)='./nyx-txfile\\x00', 0xffffffff, 0x7, 0x0, 0x2, 0x80, 0xffffffffffffffff)\n"+
			"WriteFile(r3, &(0x7f0000000240)='abcd', 0x4, &(0x7f0000000280)=0x0, 0x0)\n"+
			"TransmitFile$inet_accept(r2, r3, 0x4, 0x0, 0x0, 0x0, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	job.p = p
	info := &triageCall{
		newStableSignal: signal.FromRaw([]uint64{1, 2, 3}, 0),
		stableSignal:    signal.FromRaw([]uint64{1, 2, 3}, 0),
	}
	job.handleCall(9, info)
	req := fuzzer.immediateCollideQueue.Next()
	if req == nil {
		t.Fatal("expected transmit immediate collide request to be queued")
	}
	if req.Origin != "collide:triage" {
		t.Fatalf("transmit immediate collide origin=%q", req.Origin)
	}
}

func TestImmediateCollideQueuePrecedesCandidateAndRegularTriageQueue(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus: corpus.NewCorpus(ctx),
	}, rand.New(rand.NewSource(0)), target)
	immediate := &queue.Request{Origin: "collide:triage"}
	triageCandidate := &queue.Request{Origin: "triage-candidate"}
	candidate := &queue.Request{Origin: "candidate"}
	regular := &queue.Request{Origin: "triage"}
	fuzzer.immediateCollideQueue.Submit(immediate)
	fuzzer.triageCandidateQueue.Append().Submit(triageCandidate)
	fuzzer.candidateQueue.Submit(candidate)
	fuzzer.triageQueue.Append().Submit(regular)
	first := fuzzer.source.Next()
	if first != immediate {
		t.Fatalf("first request origin=%q, want immediate collide", first.Origin)
	}
	second := fuzzer.source.Next()
	if second != triageCandidate {
		t.Fatalf("second request origin=%q, want triage-candidate", second.Origin)
	}
	third := fuzzer.source.Next()
	if third != candidate {
		t.Fatalf("third request origin=%q, want candidate", third.Origin)
	}
	fourth := fuzzer.source.Next()
	if fourth != regular {
		t.Fatalf("fourth request origin=%q, want regular triage", fourth.Origin)
	}
}

func TestWindowsAcceptRaceForceTriageForIoctlCollideTriageOrigin(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	fuzzer := &Fuzzer{
		Config: &Config{
			NewInputFilter: func(string) bool { return true },
		},
		target: acceptRace,
		Cover:  newCover(),
	}
	ioctl := acceptRace.SyscallMap["ioctlsocket$fionbio_accept"]
	if ioctl == nil {
		t.Fatal("missing ioctlsocket$fionbio_accept")
	}
	p := &prog.Prog{Target: acceptRace, Calls: []*prog.Call{{Meta: ioctl}}}
	info := &flatrpc.CallInfo{
		Signal: []uint64{1, 2, 3},
		Cover:  []uint64{10, 11, 12},
	}
	// Prime max-signal so the second call contributes no global novelty.
	var triage map[int]*triageCall
	fuzzer.triageProgCall("candidate", p, info, 0, &triage)
	triage = nil
	fuzzer.triageProgCall("candidate", p, info, 0, &triage)
	if len(triage) != 0 {
		t.Fatalf("unexpected triage for non-collide origin: %+v", triage)
	}
	fuzzer.triageProgCall("collide:triage", p, info, 0, &triage)
	if len(triage) != 1 || triage[0] == nil {
		t.Fatalf("expected forced triage for collide:triage ioctl path, got %+v", triage)
	}
}

func TestWindowsAcceptRaceForceTriageForTransmitCollideTriageOrigin(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	fuzzer := &Fuzzer{
		Config: &Config{
			NewInputFilter: func(string) bool { return true },
		},
		target: acceptRace,
		Cover:  newCover(),
	}
	transmit := acceptRace.SyscallMap["TransmitFile$inet_accept"]
	if transmit == nil {
		t.Fatal("missing TransmitFile$inet_accept")
	}
	p := &prog.Prog{Target: acceptRace, Calls: []*prog.Call{{Meta: transmit}}}
	info := &flatrpc.CallInfo{
		Signal: []uint64{1, 2, 3},
		Cover:  []uint64{10, 11, 12},
	}
	var triage map[int]*triageCall
	fuzzer.triageProgCall("candidate", p, info, 0, &triage)
	triage = nil
	fuzzer.triageProgCall("candidate", p, info, 0, &triage)
	if len(triage) != 0 {
		t.Fatalf("unexpected triage for non-collide origin: %+v", triage)
	}
	fuzzer.triageProgCall("collide:triage", p, info, 0, &triage)
	if len(triage) != 1 || triage[0] == nil {
		t.Fatalf("expected forced triage for collide:triage transmit path, got %+v", triage)
	}
}

func TestWindowsTransmitProfileRetainsStableTransmitWithoutNewSignal(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	transmitProfile := target.Clone()
	if err := transmitProfile.ConfigureProfile(transmitProfile, "afd_transmit"); err != nil {
		t.Fatalf("ConfigureProfile(afd_transmit): %v", err)
	}
	if transmitProfile.RuntimePolicy.ShouldPersistStableTriageCall == nil {
		t.Fatal("transmit profile missing stable-triage persistence hook")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:         corpus.NewCorpus(ctx),
		Collide:        true,
		NewInputFilter: func(string) bool { return true },
	}, rand.New(rand.NewSource(0)), transmitProfile)
	job := &triageJob{
		fuzzer:  fuzzer,
		origin:  "candidate",
		queue:   queue.Plain(),
		flags:   ProgMinimized | progCandidate,
		traceID: "triage-tx-keep",
	}
	transmit := transmitProfile.SyscallMap["TransmitFile$inet_accept"]
	if transmit == nil {
		t.Fatal("missing TransmitFile$inet_accept")
	}
	p, err := transmitProfile.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"r3 = CreateFileA(&(0x7f0000000200)='./nyx-txfile\\x00', 0xffffffff, 0x7, 0x0, 0x2, 0x80, 0xffffffffffffffff)\n"+
			"WriteFile(r3, &(0x7f0000000240)='abcd', 0x4, &(0x7f0000000280)=0x0, 0x0)\n"+
			"TransmitFile$inet_accept(r2, r3, 0x4, 0x0, 0x0, 0x0, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	job.p = p
	info := &triageCall{
		stableSignal: signal.FromRaw([]uint64{1, 2, 3}, 0),
	}
	job.handleCall(9, info)
	if fuzzer.Config.Corpus.StatProgs.Val() != 1 {
		t.Fatalf("expected transmit owner to be retained in corpus, corpus size=%d", fuzzer.Config.Corpus.StatProgs.Val())
	}
}

func TestWindowsRandomCollideSkipsShallowPrograms(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"listen$inet_tcp(r0, 0x1)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize shallow program: %v", err)
	}
	rnd := rand.New(rand.NewSource(0))
	for range 50 {
		collided := randomCollide(p, rnd)
		if string(collided.Serialize()) != string(p.Serialize()) {
			t.Fatalf("expected randomCollide to leave shallow program unchanged:\norig:\n%s\ncollided:\n%s",
				p.Serialize(), collided.Serialize())
		}
	}
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

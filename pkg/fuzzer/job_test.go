// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestDeflake(t *testing.T) {
	type Test struct {
		Info triageCall
		Exec func(run uint64) (errno int32, signal []uint64, cover []uint64)
		Runs uint64
	}
	tests := []Test{
		{
			Info: triageCall{
				newSignal: signal.FromRaw([]uint64{0, 1, 2, 3, 4}, 0),
				cover:     cover.FromRaw([]uint64{10, 20}),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				// For first, we return 1. For second, 2. And so on.
				return 0, []uint64{run}, []uint64{10, 20}
			},
			Runs: 3,
		},
		{
			Info: triageCall{
				newSignal: signal.FromRaw([]uint64{0, 1, 2}, 0),
				// Cover is a union of all coverages.
				cover: cover.FromRaw([]uint64{10, 20, 30, 40, 100}),
				// 0, 2, 6 were in three resuls.
				stableSignal: signal.FromRaw([]uint64{0, 2, 6}, 0),
				// 0, 2 were also in newSignal.
				newStableSignal: signal.FromRaw([]uint64{0, 2, 6}, 0),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				switch run {
				case 1:
					return 0, []uint64{0, 2, 4, 6, 8}, []uint64{10, 20}
				case 2:
					// This one should be ignored -- it has a different errno.
					return 1, []uint64{0, 1, 2}, []uint64{100}
				case 3:
					return 0, []uint64{0, 2, 4, 6, 8}, []uint64{20, 30}
				case 4:
					return 0, []uint64{0, 2, 6}, []uint64{30, 40}
				}
				panic("unrechable")
			},
			Runs: 4,
		},
		{
			Info: triageCall{
				newSignal:       signal.FromRaw([]uint64{0, 1, 2, 3, 4}, 3),
				cover:           cover.FromRaw([]uint64{10, 20}),
				stableSignal:    signal.FromRaw([]uint64{2}, 0),
				newStableSignal: signal.FromRaw([]uint64{2}, 0),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				// For first, we return 0 and 1. For second, 1 and 2. And so on.
				return 0, []uint64{run, run + 1}, []uint64{10, 20}
			},
			Runs: 2,
		},
	}

	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	assert.NoError(t, err)
	const anyTestProg = `syz_compare(&AUTO="00000000", 0x4, &AUTO=@conditional={0x0, @void, @void, @void}, AUTO)`
	prog, err := target.Deserialize([]byte(anyTestProg), prog.NonStrict)
	assert.NoError(t, err)

	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			info := test.Info
			info.signals[0] = test.Info.newSignal.Copy()
			info.cover = nil
			info.stableSignal = nil
			info.newStableSignal = nil
			testJob := &triageJob{
				p:     prog,
				calls: map[int]*triageCall{0: &info},
				fuzzer: &Fuzzer{
					Cover:  newCover(),
					Config: &Config{},
				},
				info: &JobInfo{},
			}

			var run uint64
			stop := testJob.deflake(func(_ *queue.Request, _ ProgFlags) *queue.Result {
				run++
				errno, signal, cover := test.Exec(run)
				return &queue.Result{
					Info: &flatrpc.ProgInfo{
						Calls: []*flatrpc.CallInfo{{
							Error:  errno,
							Signal: signal,
							Cover:  cover,
						}},
					},
				}
			})

			assert.False(t, stop)
			assert.Equal(t, run, test.Runs)
			assert.ElementsMatch(t, info.cover.Serialize(), test.Info.cover.Serialize())
			assert.ElementsMatch(t, info.stableSignal.ToRaw(), test.Info.stableSignal.ToRaw())
			assert.ElementsMatch(t, info.newStableSignal.ToRaw(), test.Info.newStableSignal.ToRaw())
		})
	}
}

func TestDeflakeUsesHangedResultWithInfo(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	assert.NoError(t, err)
	const anyTestProg = `syz_compare(&AUTO="00000000", 0x4, &AUTO=@conditional={0x0, @void, @void, @void}, AUTO)`
	p, err := target.Deserialize([]byte(anyTestProg), prog.NonStrict)
	assert.NoError(t, err)
	prio := signalPrio(p, &flatrpc.CallInfo{}, 0)
	info := triageCall{
		newSignal: signal.FromRaw([]uint64{1}, prio),
		signals:   [deflakeNeedRuns]signal.Signal{signal.FromRaw([]uint64{1}, prio)},
	}
	job := &triageJob{
		p:     p,
		calls: map[int]*triageCall{0: &info},
		fuzzer: &Fuzzer{
			Cover:  newCover(),
			Config: &Config{},
		},
		info: &JobInfo{},
	}
	run := 0
	stop := job.deflake(func(_ *queue.Request, _ ProgFlags) *queue.Result {
		run++
		status := queue.Success
		if run == 2 {
			status = queue.Hanged
		}
		return &queue.Result{
			Status: status,
			Info: &flatrpc.ProgInfo{
				Calls: []*flatrpc.CallInfo{{
					Signal: []uint64{1},
					Cover:  []uint64{10},
				}},
			},
		}
	})
	assert.False(t, stop)
	assert.Equal(t, 2, run)
	assert.ElementsMatch(t, []uint64{1}, info.stableSignal.ToRaw())
	assert.ElementsMatch(t, []uint64{1}, info.newStableSignal.ToRaw())
}

type recordingExecutor struct {
	submitted chan *queue.Request
	result    *queue.Result
}

func (e *recordingExecutor) Submit(req *queue.Request) {
	e.submitted <- req
	req.Done(e.result)
}

type minimizeSignalExecutor struct {
	signal []uint64
	errno  int32
}

func (e *minimizeSignalExecutor) Submit(req *queue.Request) {
	calls := make([]*flatrpc.CallInfo, len(req.Prog.Calls))
	for _, call := range req.ReturnAllSignal {
		if call < 0 || call >= len(calls) {
			continue
		}
		calls[call] = &flatrpc.CallInfo{
			Error:  e.errno,
			Signal: e.signal,
			Cover:  e.signal,
		}
	}
	req.Done(&queue.Result{
		Status: queue.Success,
		Info:   &flatrpc.ProgInfo{Calls: calls},
	})
}

type hangedMinimizeExecutor struct{}

func (e *hangedMinimizeExecutor) Submit(req *queue.Request) {
	req.Done(&queue.Result{Status: queue.Hanged})
}

type failSubmitExecutor struct {
	t *testing.T
}

func (e *failSubmitExecutor) Submit(req *queue.Request) {
	e.t.Fatalf("unexpected executor submit during no_minimize triage: %s", req.Prog)
}

func TestTriageExecuteSignalsReadyAfterSubmit(t *testing.T) {
	exec := &recordingExecutor{
		submitted: make(chan *queue.Request, 1),
		result:    &queue.Result{Status: queue.Hanged},
	}
	job := &triageJob{
		fuzzer: &Fuzzer{
			ctx:    context.Background(),
			Config: &Config{},
			Cover:  newCover(),
		},
		queue: exec,
		ready: make(chan struct{}),
		info:  &JobInfo{},
	}
	req := &queue.Request{}
	done := make(chan struct{})
	go func() {
		job.execute(req, progInTriage)
		close(done)
	}()

	<-job.ready
	select {
	case got := <-exec.submitted:
		assert.Same(t, req, got)
	default:
		t.Fatal("triage request was not submitted before ready was signaled")
	}
	<-done
}

func TestFuzzerExecuteHonorsRuntimePolicy(t *testing.T) {
	target := testRuntimePolicyTarget(t)
	p := testRuntimePolicyProg(t, target)
	exec := &recordingExecutor{
		submitted: make(chan *queue.Request, 1),
		result:    &queue.Result{Status: queue.Success},
	}
	fuzzer := &Fuzzer{
		ctx:    context.Background(),
		Config: &Config{},
		target: target,
	}
	res := fuzzer.execute(exec, &queue.Request{
		Prog:   p,
		Origin: "smash",
	})
	assert.Equal(t, queue.ExecFailure, res.Status)
	if res.Err == nil || !strings.Contains(res.Err.Error(), "runtime policy rejected program") {
		t.Fatalf("bad rejection error: %v", res.Err)
	}
	select {
	case req := <-exec.submitted:
		t.Fatalf("runtime-rejected request reached executor: %#v", req)
	default:
	}
}

func TestTriageExecuteHonorsRuntimePolicy(t *testing.T) {
	target := testRuntimePolicyTarget(t)
	p := testRuntimePolicyProg(t, target)
	exec := &recordingExecutor{
		submitted: make(chan *queue.Request, 1),
		result:    &queue.Result{Status: queue.Success},
	}
	job := &triageJob{
		fuzzer: &Fuzzer{
			ctx:    context.Background(),
			Config: &Config{},
			target: target,
		},
		queue: exec,
		ready: make(chan struct{}),
		info:  &JobInfo{},
	}
	res := job.execute(&queue.Request{
		Prog:   p,
		Origin: "triage",
	}, progInTriage)
	assert.Equal(t, queue.Success, res.Status)
	if res.Info != nil {
		t.Fatalf("runtime-rejected triage execution returned info: %#v", res.Info)
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "runtime policy rejected program") {
		t.Fatalf("bad rejection error: %v", res.Err)
	}
	select {
	case <-job.ready:
	default:
		t.Fatal("runtime-rejected triage execution did not signal readiness")
	}
	select {
	case req := <-exec.submitted:
		t.Fatalf("runtime-rejected triage request reached executor: %#v", req)
	default:
	}
}

func testRuntimePolicyTarget(t *testing.T) *prog.Target {
	t.Helper()
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	assert.NoError(t, err)
	target = target.Clone()
	target.RuntimePolicy.ShouldScheduleProgram = func(string, *prog.Prog) bool {
		return false
	}
	return target
}

func testRuntimePolicyProg(t *testing.T, target *prog.Target) *prog.Prog {
	t.Helper()
	p, err := target.Deserialize([]byte(
		`syz_compare(&AUTO="00000000", 0x4, &AUTO=@conditional={0x0, @void, @void, @void}, AUTO)`),
		prog.NonStrict)
	assert.NoError(t, err)
	return p
}

func TestWindowsAFDMinimizePreservesFocusedResourceLineage(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p := windowsFuzzerTestDirectAcceptReceiveProgram(t, profiled)
	call := windowsFuzzerTestCallIndex(t, p, "NtDeviceIoControlFile$afd_receive_accept_nonblock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:       corpus.NewCorpus(ctx),
		EnabledCalls: map[*prog.Syscall]bool{profiled.SyscallMap["NtDeviceIoControlFile$afd_receive_accept_nonblock"]: true},
		Logf:         func(int, string, ...any) {},
	}, rand.New(rand.NewSource(0)), profiled)
	job := &triageJob{
		p:      p,
		fuzzer: fuzzer,
		queue:  &minimizeSignalExecutor{signal: []uint64{0x10}},
		ready:  make(chan struct{}),
		info:   &JobInfo{},
		origin: "candidate",
	}
	minimized, minCall := job.minimize(call, &triageCall{
		errno:           0,
		newStableSignal: signal.FromRaw([]uint64{0x10}, 3),
	})
	if minimized == nil {
		t.Fatal("minimize returned nil")
	}
	if minimized.CallName(minCall) != "NtDeviceIoControlFile$afd_receive_accept_nonblock" {
		t.Fatalf("minimized call=%s, want NtDeviceIoControlFile$afd_receive_accept_nonblock", minimized.CallName(minCall))
	}
	if len(minimized.Calls) < 5 {
		t.Fatalf("minimization dropped focused resource lineage:\n%s", minimized.Serialize())
	}
	if !job.shouldPersistCall(minimized, minCall) {
		t.Fatalf("minimized focused program is not persistable:\n%s", minimized.Serialize())
	}
}

func TestTriageMinimizeDoesNotSpawnRecursiveTriageJobs(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p := windowsFuzzerTestDirectAcceptReceiveProgram(t, profiled)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:       corpus.NewCorpus(ctx),
		EnabledCalls: map[*prog.Syscall]bool{profiled.SyscallMap["NtDeviceIoControlFile$afd_receive_accept_nonblock"]: true},
		Logf:         func(int, string, ...any) {},
	}, rand.New(rand.NewSource(0)), profiled)
	call := windowsFuzzerTestCallIndex(t, p, "NtDeviceIoControlFile$afd_receive_accept_nonblock")
	job := &triageJob{
		p:       p,
		fuzzer:  fuzzer,
		queue:   &minimizeSignalExecutor{signal: []uint64{0x10}},
		ready:   make(chan struct{}),
		info:    &JobInfo{},
		origin:  "candidate",
		traceID: "candidate-1",
	}
	minimized, _ := job.minimize(call, &triageCall{
		errno:           0,
		newStableSignal: signal.FromRaw([]uint64{0x10}, 3),
	})
	if minimized == nil {
		t.Fatal("minimize returned nil")
	}
	if req := fuzzer.triageQueue.Next(); req != nil {
		t.Fatalf("minimize execution spawned recursive triage request: %s", req.Prog)
	}
}

func TestFocusedResourceTriageDeflakeLogsProgress(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p := windowsFuzzerTestDirectAcceptReceiveProgram(t, profiled)
	call := windowsFuzzerTestCallIndex(t, p, "NtDeviceIoControlFile$afd_receive_accept_nonblock")
	var logs []string
	fuzzer := &Fuzzer{
		Config: &Config{
			Logf: func(level int, msg string, args ...any) {
				logs = append(logs, fmt.Sprintf(msg, args...))
			},
		},
		target: profiled,
		Cover:  newCover(),
	}
	fuzzer.Cover.addRawMaxSignal([]uint64{0x10}, 3)
	job := &triageJob{
		p:       p,
		flags:   ProgMinimized | ProgSmashed,
		origin:  "candidate",
		traceID: "candidate-1",
		fuzzer:  fuzzer,
		calls: map[int]*triageCall{call: {
			newSignal:       signal.FromRaw([]uint64{0x10}, 3),
			candidateSignal: signal.FromRaw([]uint64{0x10}, 3),
			signals:         [deflakeNeedRuns]signal.Signal{signal.FromRaw([]uint64{0x10}, 3)},
		}},
		info: &JobInfo{},
	}
	var run int
	stop := job.deflake(func(_ *queue.Request, _ ProgFlags) *queue.Result {
		run++
		calls := make([]*flatrpc.CallInfo, len(p.Calls))
		calls[call] = &flatrpc.CallInfo{
			Signal: []uint64{0x10},
			Cover:  []uint64{0x20 + uint64(run)},
		}
		return &queue.Result{
			Status: queue.Success,
			Info:   &flatrpc.ProgInfo{Calls: calls},
		}
	})
	if stop {
		t.Fatal("deflake unexpectedly stopped")
	}
	got := strings.Join(logs, "\n")
	for _, want := range []string{
		"triage deflake start: origin=candidate trace=candidate-1 calls=[NtDeviceIoControlFile$afd_receive_accept_nonblock] need_runs=3",
		"triage deflake run: origin=candidate trace=candidate-1 run=1 need_runs=3 calls=[NtDeviceIoControlFile$afd_receive_accept_nonblock] status=Success",
		"triage deflake signal: origin=candidate trace=candidate-1 run=1 need_runs=3 call=",
		"name=NtDeviceIoControlFile$afd_receive_accept_nonblock signal=1 cover=1 prio=3 new_max=0 candidate_overlap=1 new_overlap=1 buckets=[1 1 0]",
		"triage deflake complete: origin=candidate trace=candidate-1 call=",
		"name=NtDeviceIoControlFile$afd_receive_accept_nonblock stable_signal=1 new_stable=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing log %q in:\n%s", want, got)
		}
	}
}

func TestWindowsAFDTriageDeflakeStopsForPersistableStableOwner(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p := windowsFuzzerTestDirectAcceptReceiveProgram(t, profiled)
	acceptCall := windowsFuzzerTestCallIndex(t, p, "NtDeviceIoControlFile$afd_accept_tcp")
	recvCall := windowsFuzzerTestCallIndex(t, p, "NtDeviceIoControlFile$afd_receive_accept_nonblock")
	fuzzer := &Fuzzer{
		Config: &Config{},
		target: profiled,
		Cover:  newCover(),
	}
	job := &triageJob{
		p:      p,
		flags:  ProgMinimized | ProgSmashed,
		origin: "candidate",
		fuzzer: fuzzer,
		calls: map[int]*triageCall{
			acceptCall: {
				newSignal:       signal.FromRaw([]uint64{0x30}, 1),
				candidateSignal: signal.FromRaw([]uint64{0x30, 0x31}, 1),
				signals:         [deflakeNeedRuns]signal.Signal{signal.FromRaw([]uint64{0x30, 0x31}, 1)},
			},
			recvCall: {
				newSignal:       signal.FromRaw([]uint64{0x10}, 3),
				candidateSignal: signal.FromRaw([]uint64{0x10, 0x20}, 3),
				signals:         [deflakeNeedRuns]signal.Signal{signal.FromRaw([]uint64{0x10, 0x20}, 3)},
			},
		},
		info: &JobInfo{},
	}
	var runs int
	stop := job.deflake(func(_ *queue.Request, _ ProgFlags) *queue.Result {
		runs++
		calls := make([]*flatrpc.CallInfo, len(p.Calls))
		calls[acceptCall] = &flatrpc.CallInfo{
			Signal: []uint64{0x30 + uint64(runs-1)},
			Cover:  []uint64{0x100 + uint64(runs)},
		}
		calls[recvCall] = &flatrpc.CallInfo{
			Signal: []uint64{0x20},
			Cover:  []uint64{0x200 + uint64(runs)},
		}
		return &queue.Result{
			Status: queue.Success,
			Info:   &flatrpc.ProgInfo{Calls: calls},
		}
	})
	if stop {
		t.Fatal("deflake unexpectedly stopped")
	}
	if runs != 2 {
		t.Fatalf("deflake runs=%d, want 2 once stable AFD owner can be persisted", runs)
	}
	info := job.calls[recvCall]
	if info.stableSignal.Empty() {
		t.Fatal("NtDeviceIoControlFile$afd_receive_accept_nonblock should have stable signal")
	}
	if !job.calls[acceptCall].stableSignal.Empty() {
		t.Fatalf("NtDeviceIoControlFile$afd_accept_tcp stable signal=%d, want only deep persistable owner to stop deflake",
			job.calls[acceptCall].stableSignal.Len())
	}
}

func TestFocusedResourceTriageSkipLogsEmptyNewStableSignal(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p := windowsFuzzerTestDirectAcceptReceiveProgram(t, profiled)
	call := windowsFuzzerTestCallIndex(t, p, "NtDeviceIoControlFile$afd_receive_accept_nonblock")
	var logs []string
	fuzzer := &Fuzzer{
		Config: &Config{
			NewInputFilter: func(string) bool { return true },
			Logf: func(level int, msg string, args ...any) {
				logs = append(logs, fmt.Sprintf(msg, args...))
			},
		},
		target: profiled,
	}
	job := &triageJob{
		p:       p,
		flags:   ProgMinimized | ProgSmashed,
		origin:  "fuzz",
		traceID: "candidate-1",
		fuzzer:  fuzzer,
	}
	job.handleCall(call, &triageCall{
		newSignal:    signal.FromRaw([]uint64{0x10, 0x20}, 3),
		stableSignal: signal.FromRaw([]uint64{0x30}, 3),
		cover:        cover.FromRaw([]uint64{0x40}),
	})
	got := strings.Join(logs, "\n")
	for _, want := range []string{
		"triage skip: origin=fuzz trace=candidate-1 call=",
		"name=NtDeviceIoControlFile$afd_receive_accept_nonblock reason=no_new_stable_signal",
		"stable_signal=1 new_stable=0 new_signal=2 cover=1 raw_cover=0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing log %q in:\n%s", want, got)
		}
	}
}

func TestWindowsAFDPersistsStableCandidateOwner(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p := windowsFuzzerTestDirectAcceptReceiveProgram(t, profiled)
	corp := corpus.NewCorpus(context.Background())
	fuzzer := &Fuzzer{
		ctx: context.Background(),
		Config: &Config{
			Corpus:         corp,
			NewInputFilter: func(string) bool { return true },
		},
		target: profiled,
	}
	call := windowsFuzzerTestCallIndex(t, p, "NtDeviceIoControlFile$afd_receive_accept_nonblock")
	job := &triageJob{
		p:      p,
		flags:  ProgMinimized | ProgSmashed,
		origin: "candidate",
		fuzzer: fuzzer,
	}
	job.handleCall(call, &triageCall{
		stableSignal: signal.FromRaw([]uint64{1}, 0),
		cover:        cover.FromRaw([]uint64{1}),
	})
	items := corp.Items()
	if len(items) != 1 {
		t.Fatalf("corpus items=%d, want one deep candidate owner", len(items))
	}
	if got := items[0].StringCall(); got != "NtDeviceIoControlFile$afd_receive_accept_nonblock" {
		t.Fatalf("corpus owner=%q, want NtDeviceIoControlFile$afd_receive_accept_nonblock", got)
	}
}

func TestWindowsAFDKeepsOriginalStableOwnerWhenMinimizeHangs(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p := windowsFuzzerTestDirectAcceptReceiveProgram(t, profiled)
	corp := corpus.NewCorpus(context.Background())
	fuzzer := &Fuzzer{
		ctx: context.Background(),
		Config: &Config{
			Corpus:         corp,
			NewInputFilter: func(string) bool { return true },
		},
		target: profiled,
	}
	call := windowsFuzzerTestCallIndex(t, p, "NtDeviceIoControlFile$afd_receive_accept_nonblock")
	job := &triageJob{
		p:      p,
		flags:  ProgSmashed,
		origin: "candidate",
		fuzzer: fuzzer,
		queue:  &hangedMinimizeExecutor{},
		ready:  make(chan struct{}),
		info:   &JobInfo{},
	}
	job.handleCall(call, &triageCall{
		errno:           0,
		stableSignal:    signal.FromRaw([]uint64{1, 2}, 3),
		newStableSignal: signal.FromRaw([]uint64{2}, 3),
		cover:           cover.FromRaw([]uint64{3, 4}),
		rawCover:        []uint64{5},
	})
	items := corp.Items()
	if len(items) != 1 {
		t.Fatalf("corpus items=%d, want original stable AFD vnet owner", len(items))
	}
	if got := items[0].StringCall(); got != "NtDeviceIoControlFile$afd_receive_accept_nonblock" {
		t.Fatalf("corpus owner=%q, want NtDeviceIoControlFile$afd_receive_accept_nonblock", got)
	}
	if got := string(items[0].Prog.Serialize()); got != string(p.Serialize()) {
		t.Fatalf("persisted program was minimized despite hanged minimization:\n%s", items[0].Prog.Serialize())
	}
}

func TestWindowsAFDKeepsOriginalStableNoMinimizeOwner(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	noMinimize := profiled.SyscallMap["NtReadFile$afd_accept_nonblock"]
	if noMinimize == nil {
		t.Fatal("NtReadFile$afd_accept_nonblock is missing")
	}
	if profiled.GenerateNoGenerateCalls == nil {
		profiled.GenerateNoGenerateCalls = make(map[int]bool)
	}
	profiled.GenerateNoGenerateCalls[noMinimize.ID] = true
	p := windowsFuzzerTestSeedProgram(t, profiled,
		"../../sys/windows/test/nyx_afd_private_full_010_NtReadFile_afd_accept_nonblock.txt")
	corp := corpus.NewCorpus(context.Background())
	fuzzer := &Fuzzer{
		ctx: context.Background(),
		Config: &Config{
			Corpus:         corp,
			NewInputFilter: func(string) bool { return true },
		},
		target: profiled,
	}
	call := windowsFuzzerTestCallIndex(t, p, "NtReadFile$afd_accept_nonblock")
	if !p.Calls[call].Meta.Attrs.NoMinimize {
		t.Fatal("NtReadFile$afd_accept_nonblock must stay no_minimize for this test")
	}
	job := &triageJob{
		p:      p,
		flags:  ProgSmashed,
		origin: "candidate",
		fuzzer: fuzzer,
		queue:  &failSubmitExecutor{t: t},
		ready:  make(chan struct{}),
		info:   &JobInfo{},
	}
	job.handleCall(call, &triageCall{
		errno:           0,
		stableSignal:    signal.FromRaw([]uint64{1, 2}, 3),
		newStableSignal: signal.FromRaw([]uint64{2}, 3),
		cover:           cover.FromRaw([]uint64{3, 4}),
		rawCover:        []uint64{5},
	})
	items := corp.Items()
	if len(items) != 1 {
		t.Fatalf("corpus items=%d, want original stable no_minimize owner", len(items))
	}
	if got := items[0].StringCall(); got != "NtReadFile$afd_accept_nonblock" {
		t.Fatalf("corpus owner=%q, want NtReadFile$afd_accept_nonblock", got)
	}
	if got := string(items[0].Prog.Serialize()); got != string(p.Serialize()) {
		t.Fatalf("persisted program was modified despite no_minimize owner:\n%s", items[0].Prog.Serialize())
	}
}

func TestWindowsAFDCorpusSaveCallbackIncludesCandidateTrace(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p := windowsFuzzerTestDirectAcceptReceiveProgram(t, profiled)
	var events []CorpusSaveEvent
	fuzzer := &Fuzzer{
		Config: &Config{
			Corpus:         corpus.NewCorpus(context.Background()),
			NewInputFilter: func(string) bool { return true },
			CorpusSaveCallback: func(event CorpusSaveEvent) {
				events = append(events, event)
			},
		},
		target: profiled,
	}
	call := windowsFuzzerTestCallIndex(t, p, "NtDeviceIoControlFile$afd_receive_accept_nonblock")
	job := &triageJob{
		p:       p,
		flags:   ProgMinimized | ProgSmashed,
		origin:  "candidate",
		traceID: "candidate-7",
		fuzzer:  fuzzer,
	}
	job.handleCall(call, &triageCall{
		stableSignal:    signal.FromRaw([]uint64{1, 2}, 0),
		newStableSignal: signal.FromRaw([]uint64{2}, 0),
		cover:           cover.FromRaw([]uint64{3, 4, 5}),
		rawCover:        []uint64{6},
	})
	if len(events) != 1 {
		t.Fatalf("corpus save events=%d, want one", len(events))
	}
	event := events[0]
	if event.Origin != "candidate" || event.TraceID != "candidate-7" ||
		event.Call != call || event.CallName != "NtDeviceIoControlFile$afd_receive_accept_nonblock" {
		t.Fatalf("bad corpus save event: %+v", event)
	}
	if event.StableSignal != 2 || event.NewStableSignal != 1 ||
		event.Cover != 3 || event.RawCover != 1 {
		t.Fatalf("bad corpus save event counts: %+v", event)
	}
}

func windowsAFDDirectAcceptReceiveProgram() string {
	return `NtCreateFile$afd_tcp_endpoint(&(0x7f0000030000)=<r0=>0x0, 0xc0100000, &(0x7f0000030040)={0x30, 0x0, 0x0, &(0x7f0000030080)={0x16, 0x18, 0x0, &(0x7f00000300c0)={0x5c, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x5c, 0x41, 0x66, 0x64, 0x0}}, 0x40, 0x0, 0x0, 0x0}, &(0x7f0000030140)={@Status=0x0, 0x0}, 0x0, 0x0, 0x3, 0x3, 0x0, &(0x7f0000030180)={0x0, 0x0, 0xf, 0x1c, {0x41, 0x66, 0x64, 0x4f, 0x70, 0x65, 0x6e, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x58, 0x58, 0x0}, {0x0, 0x0, 0x2, 0x1, 0x6, 0x0, 0x0}}, 0x34)
r1 = NtDeviceIoControlFile$afd_bind_tcp_listener(r0, 0x0, 0x0, 0x0, &(0x7f0000030200)={@Status=0x0, 0x0}, 0x12003, &(0x7f0000030240)={0x3, {0x2, 0x4e22, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}}, 0x14, &(0x7f0000030280), 0x10)
r2 = NtDeviceIoControlFile$afd_start_listen_tcp(r1, 0x0, 0x0, 0x0, &(0x7f00000302c0)={@Status=0x0, 0x0}, 0x1200b, &(0x7f0000030300)={0x0, [0, 0, 0], 0x1, 0x0, [0, 0, 0]}, 0xc, 0x0, 0x0)
NtCreateFile$afd_tcp_endpoint(&(0x7f0000030340)=<r3=>0x0, 0xc0100000, &(0x7f0000030380)={0x30, 0x0, 0x0, &(0x7f00000303c0)={0x16, 0x18, 0x0, &(0x7f0000030400)={0x5c, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x5c, 0x41, 0x66, 0x64, 0x0}}, 0x40, 0x0, 0x0, 0x0}, &(0x7f0000030480)={@Status=0x0, 0x0}, 0x0, 0x0, 0x3, 0x3, 0x0, &(0x7f00000304c0)={0x0, 0x0, 0xf, 0x1c, {0x41, 0x66, 0x64, 0x4f, 0x70, 0x65, 0x6e, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x58, 0x58, 0x0}, {0x0, 0x0, 0x2, 0x1, 0x6, 0x0, 0x0}}, 0x34)
r4 = NtDeviceIoControlFile$afd_bind_tcp(r3, 0x0, 0x0, 0x0, &(0x7f0000030540)={@Status=0x0, 0x0}, 0x12003, &(0x7f0000030580)={0x3, {0x2, 0x0, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}}, 0x14, &(0x7f00000305c0), 0x10)
r5 = NtDeviceIoControlFile$afd_connect_tcp_to_listener(r4, 0x0, 0x0, 0x0, &(0x7f0000030600)={@Status=0x0, 0x0}, 0x12007, &(0x7f0000030640)={0x0, [0, 0, 0, 0, 0, 0, 0], 0x0, r2, {0x2, 0x4e22, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}}, 0x28, &(0x7f0000030680)={@Status=0x0, 0x0}, 0x10)
r6 = NtDeviceIoControlFile$afd_wait_for_listen_tcp(r5, 0x0, 0x0, 0x0, &(0x7f00000306c0)={@Status=0x0, 0x0}, 0x1200c, 0x0, 0x0, &(0x7f0000030700)={<r7=>0x0, {0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}}, 0x14)
NtCreateFile$afd_tcp_accept_slot(&(0x7f0000030800)=<r8=>0x0, 0xc0100000, &(0x7f0000030840)={0x30, 0x0, 0x0, &(0x7f0000030880)={0x16, 0x18, 0x0, &(0x7f00000308c0)={0x5c, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x5c, 0x41, 0x66, 0x64, 0x0}}, 0x40, 0x0, 0x0, 0x0}, &(0x7f0000030940)={@Status=0x0, 0x0}, 0x0, 0x0, 0x3, 0x3, 0x0, &(0x7f0000030980)={0x0, 0x0, 0xf, 0x1c, {0x41, 0x66, 0x64, 0x4f, 0x70, 0x65, 0x6e, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x58, 0x58, 0x0}, {0x0, 0x0, 0x2, 0x1, 0x6, 0x0, 0x0}}, 0x34)
r9 = NtDeviceIoControlFile$afd_accept_tcp(r6, 0x0, 0x0, 0x0, &(0x7f0000030a00)={@Status=0x0, 0x0}, 0x12010, &(0x7f0000030a40)={0x0, [0, 0, 0], r7, r8}, 0x10, 0x0, 0x0)
r10 = NtDeviceIoControlFile$afd_set_information_nonblock_tcp_accepted(r9, 0x0, 0x0, 0x0, &(0x7f0000030a80)={@Status=0x0, 0x0}, 0x1203b, &(0x7f0000030ac0)={0x2, 0x0, 0x1, [0, 0, 0, 0, 0, 0, 0]}, 0x10, 0x0, 0x0)
NtDeviceIoControlFile$afd_receive_accept_nonblock(r10, 0x0, 0x0, 0x0, &(0x7f0000030b00)={@Status=0x0, 0x0}, 0x12017, &(0x7f0000030b40)={&(0x7f0000030b80)=[{0x40, &(0x7f0000030bc0)=""/64}], 0x1, 0x0, 0x20, 0x0}, 0x18, 0x0, 0x0)
`
}

func TestWindowsAFDPersistsStableCollideOwner(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p, err := profiled.Deserialize([]byte(windowsAFDDirectAcceptReceiveProgram()), prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	corp := corpus.NewCorpus(context.Background())
	fuzzer := &Fuzzer{
		Config: &Config{
			Corpus:         corp,
			NewInputFilter: func(string) bool { return true },
		},
		target: profiled,
	}
	call := windowsFuzzerTestCallIndex(t, p, "NtDeviceIoControlFile$afd_receive_accept_nonblock")
	job := &triageJob{
		p:      p,
		flags:  ProgMinimized | ProgSmashed,
		origin: "collide:triage",
		fuzzer: fuzzer,
	}
	job.handleCall(call, &triageCall{
		stableSignal: signal.FromRaw([]uint64{1}, 0),
		cover:        cover.FromRaw([]uint64{1}),
	})
	items := corp.Items()
	if len(items) != 1 {
		t.Fatalf("corpus items=%d, want one deep collide owner", len(items))
	}
	if got := items[0].StringCall(); got != "NtDeviceIoControlFile$afd_receive_accept_nonblock" {
		t.Fatalf("corpus owner=%q, want NtDeviceIoControlFile$afd_receive_accept_nonblock", got)
	}
}

func TestWindowsAFDSchedulesImmediateCollideForDirectOwner(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p, err := profiled.Deserialize([]byte(windowsAFDDirectAcceptReceiveProgram()), prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	enabledCalls := windowsFuzzerTestEnabledCalls(t, profiled, []string{
		"NtDeviceIoControlFile$afd_start_listen_tcp",
		"NtDeviceIoControlFile$afd_receive_accept_nonblock",
	}, nil)
	newTestFuzzer := func(seed int64) *Fuzzer {
		return NewFuzzer(context.Background(), &Config{
			Collide:      true,
			Corpus:       corpus.NewCorpus(context.Background()),
			EnabledCalls: enabledCalls,
		}, rand.New(rand.NewSource(seed)), profiled)
	}
	fuzzer := newTestFuzzer(0)
	job := &triageJob{fuzzer: fuzzer}
	job.maybeScheduleImmediateCollide(p, windowsFuzzerTestCallIndex(t, p, "NtDeviceIoControlFile$afd_start_listen_tcp"))
	if got := fuzzer.immediateCollideQueue.Len(); got == 0 {
		t.Fatal("foundational AFD listen owner did not schedule immediate collide")
	}

	var req *queue.Request
	for seed := int64(0); seed < 64 && req == nil; seed++ {
		fuzzer = newTestFuzzer(seed)
		job = &triageJob{fuzzer: fuzzer}
		job.maybeScheduleImmediateCollide(p, windowsFuzzerTestCallIndex(t, p, "NtDeviceIoControlFile$afd_receive_accept_nonblock"))
		req = fuzzer.immediateCollideQueue.Next()
	}
	if req == nil {
		t.Fatal("direct AFD owner did not schedule immediate collide")
	}
	if req.Origin != "collide:triage" || req.Stat != fuzzer.statExecCollide || !req.Important {
		t.Fatalf("bad collide request: origin=%q stat=%v important=%v", req.Origin, req.Stat, req.Important)
	}
	if string(req.Prog.Serialize()) == string(p.Serialize()) {
		t.Fatalf("immediate collide request did not transform program:\n%s", req.Prog.Serialize())
	}
	if got := fuzzer.immediateCollideQueue.Len(); got != 0 {
		t.Fatalf("unexpected extra immediate collide requests: %d", got)
	}
}

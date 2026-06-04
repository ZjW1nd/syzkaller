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

type recordingExecutor struct {
	submitted chan *queue.Request
	result    *queue.Result
}

func (e *recordingExecutor) Submit(req *queue.Request) {
	e.submitted <- req
	req.Done(e.result)
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

func TestFocusedResourceTriageDeflakeLogsProgress(t *testing.T) {
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
	call := windowsFuzzerTestCallIndex(t, p, "WSARecv$accept")
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
		"triage deflake start: origin=candidate trace=candidate-1 calls=[WSARecv$accept] need_runs=3",
		"triage deflake run: origin=candidate trace=candidate-1 run=1 need_runs=3 calls=[WSARecv$accept] status=Success",
		"triage deflake signal: origin=candidate trace=candidate-1 run=1 need_runs=3 call=",
		"name=WSARecv$accept signal=1 cover=1 prio=3 new_max=0 candidate_overlap=1 new_overlap=1 buckets=[1 1 0]",
		"triage deflake complete: origin=candidate trace=candidate-1 call=",
		"name=WSARecv$accept stable_signal=1 new_stable=1",
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
	p, err := profiled.Deserialize([]byte(
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = bind$inet_tcp(r0, &(0x7f0000000000)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = listen$inet_tcp(r1, 0x1)\n"+
			"r3 = accept$inet_tcp(r2, 0x0, 0x0)\n"+
			"recv$inet_accept(r3, &(0x7f0000000100)=\"\"/64, 0x40, 0x0)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	acceptCall := windowsFuzzerTestCallIndex(t, p, "accept$inet_tcp")
	recvCall := windowsFuzzerTestCallIndex(t, p, "recv$inet_accept")
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
		t.Fatal("recv$inet_accept should have stable signal")
	}
	if !job.calls[acceptCall].stableSignal.Empty() {
		t.Fatalf("accept$inet_tcp stable signal=%d, want only deep persistable owner to stop deflake",
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
	p, err := profiled.Deserialize([]byte(
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = bind$inet_tcp(r0, &(0x7f0000000000)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = listen$inet_tcp(r1, 0x1)\n"+
			"r3 = accept$inet_tcp(r2, 0x0, 0x0)\n"+
			"recv$inet_accept(r3, &(0x7f0000000100)=\"\"/64, 0x40, 0x0)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	call := windowsFuzzerTestCallIndex(t, p, "recv$inet_accept")
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
		"name=recv$inet_accept reason=no_new_stable_signal",
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
	corp := corpus.NewCorpus(context.Background())
	fuzzer := &Fuzzer{
		Config: &Config{
			Corpus:         corp,
			NewInputFilter: func(string) bool { return true },
		},
		target: profiled,
	}
	call := windowsFuzzerTestCallIndex(t, p, "WSARecv$accept")
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
	if got := items[0].StringCall(); got != "WSARecv$accept" {
		t.Fatalf("corpus owner=%q, want WSARecv$accept", got)
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
	call := windowsFuzzerTestCallIndex(t, p, "WSARecv$accept")
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
		event.Call != call || event.CallName != "WSARecv$accept" {
		t.Fatalf("bad corpus save event: %+v", event)
	}
	if event.StableSignal != 2 || event.NewStableSignal != 1 ||
		event.Cover != 3 || event.RawCover != 1 {
		t.Fatalf("bad corpus save event counts: %+v", event)
	}
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
	corp := corpus.NewCorpus(context.Background())
	fuzzer := &Fuzzer{
		Config: &Config{
			Corpus:         corp,
			NewInputFilter: func(string) bool { return true },
		},
		target: profiled,
	}
	call := windowsFuzzerTestCallIndex(t, p, "WSARecv$accept")
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
	if got := items[0].StringCall(); got != "WSARecv$accept" {
		t.Fatalf("corpus owner=%q, want WSARecv$accept", got)
	}
}

func TestWindowsAFDSchedulesImmediateCollideForDeepOwner(t *testing.T) {
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
	fuzzer := NewFuzzer(context.Background(), &Config{
		Collide:      true,
		Corpus:       corpus.NewCorpus(context.Background()),
		EnabledCalls: map[*prog.Syscall]bool{profiled.SyscallMap["WSARecv$accept"]: true},
	}, rand.New(rand.NewSource(0)), profiled)
	job := &triageJob{fuzzer: fuzzer}
	job.maybeScheduleImmediateCollide(p, windowsFuzzerTestCallIndex(t, p, "listen$inet_tcp"))
	if got := fuzzer.immediateCollideQueue.Len(); got != 0 {
		t.Fatalf("shallow scaffold scheduled %d immediate collide requests", got)
	}
	job.maybeScheduleImmediateCollide(p, windowsFuzzerTestCallIndex(t, p, "WSARecv$accept"))
	req := fuzzer.immediateCollideQueue.Next()
	if req == nil {
		t.Fatal("deep AFD owner did not schedule immediate collide")
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

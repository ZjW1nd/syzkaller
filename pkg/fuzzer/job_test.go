// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
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

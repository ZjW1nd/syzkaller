// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"bytes"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type job interface {
	run(fuzzer *Fuzzer)
}

type jobIntrospector interface {
	getInfo() *JobInfo
}

type JobInfo struct {
	Name  string
	Calls []string
	Type  string
	Execs atomic.Int32

	syncBuffer
}

func (ji *JobInfo) ID() string {
	return fmt.Sprintf("%p", ji)
}

func genProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	var p *prog.Prog
	if len(fuzzer.Config.BorrowingCorpus) != 0 {
		p = fuzzer.target.GenerateWithCorpus(rnd, fuzzer.RecommendedCalls(),
			fuzzer.ChoiceTable(), fuzzer.Config.BorrowingCorpus)
	} else {
		p = fuzzer.target.Generate(rnd,
			fuzzer.RecommendedCalls(),
			fuzzer.ChoiceTable())
	}
	return &queue.Request{
		Prog:     p,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecGenerate,
		Origin:   "gen",
		TraceID:  fuzzer.nextTraceID("gen"),
	}
}

func mutateProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	p := fuzzer.Config.Corpus.ChooseProgram(rnd)
	if p == nil {
		return nil
	}
	newP := p.Clone()
	newP.Mutate(rnd,
		fuzzer.RecommendedCalls(),
		fuzzer.ChoiceTable(),
		fuzzer.Config.NoMutateCalls,
		fuzzer.Config.Corpus.Programs(),
	)
	return &queue.Request{
		Prog:     newP,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecFuzz,
		Origin:   "fuzz",
		TraceID:  fuzzer.nextTraceID("fuzz"),
	}
}

// triageJob are programs for which we noticed potential new coverage during
// first execution. But we are not sure yet if the coverage is real or not.
// During triage we understand if these programs in fact give new coverage,
// and if yes, minimize them and add to corpus.
type triageJob struct {
	p        *prog.Prog
	executor queue.ExecutorID
	flags    ProgFlags
	origin   string
	traceID  string
	fuzzer   *Fuzzer
	queue    queue.Executor
	// Set of calls that gave potential new coverage.
	calls     map[int]*triageCall
	ready     chan struct{}
	readyOnce sync.Once

	info *JobInfo
}

type triageCall struct {
	errno           int32
	newSignal       signal.Signal
	candidateSignal signal.Signal
	origin          string

	// Filled after deflake:
	signals         [deflakeNeedRuns]signal.Signal
	stableSignal    signal.Signal
	newStableSignal signal.Signal
	cover           cover.Cover
	rawCover        []uint64
}

// As demonstrated in #4639, programs reproduce with a very high, but not 100% probability.
// The triage algorithm must tolerate this, so let's pick the signal that is common
// to 3 out of 5 runs.
// By binomial distribution, a program that reproduces 80% of time will pass deflake()
// with a 94% probability. If it reproduces 90% of time, it passes in 99% of cases.
//
// During corpus triage we are more permissive and require only 2/6 to produce new stable signal.
// Such parameters make 80% flakiness to pass 99% of time, and even 60% flakiness passes 96% of time.
// First, we don't need to be strict during corpus triage since the program has already passed
// the stricter check when it was added to the corpus. So we can do fewer runs during triage,
// and finish it sooner. If the program does not produce any stable signal any more, just flakes,
// (if the kernel code was changed, or configs disabled), then it still should be phased out
// of the corpus eventually.
// Second, even if small percent of programs are dropped from the corpus due to flaky signal,
// later after several restarts we will add them to the corpus again, and it will create lots
// of duplicate work for minimization/hints/smash/fault injection. For example, a program with
// 60% flakiness has 68% chance to pass 3/5 criteria, but it's also likely to be dropped from
// the corpus if we use the same 3/5 criteria during triage. With a large corpus this effect
// can cause re-addition of thousands of programs to the corpus, and hundreds of thousands
// of runs for the additional work. With 2/6 criteria, a program with 60% flakiness has
// 96% chance to be kept in the corpus after retriage.
const (
	deflakeNeedRuns         = 3
	deflakeMaxRuns          = 5
	deflakeNeedCorpusRuns   = 2
	deflakeMinCorpusRuns    = 4
	deflakeMaxCorpusRuns    = 6
	deflakeTotalCorpusRuns  = 20
	deflakeNeedSnapshotRuns = 2
)

func (job *triageJob) execute(req *queue.Request, flags ProgFlags) *queue.Result {
	defer job.info.Execs.Add(1)
	req.Important = true // All triage executions are important.
	if req.Origin == "" {
		req.Origin = job.origin
	}
	if req.TraceID == "" {
		req.TraceID = job.traceID
	}
	if job.fuzzer.target != nil && job.fuzzer.target.RuntimePolicy.ShouldScheduleProgram != nil &&
		!job.fuzzer.shouldScheduleProgram(req) {
		job.readyOnce.Do(func() {
			close(job.ready)
		})
		return runtimePolicySkippedResult(req)
	}
	// Make the request visible to the shared executor queue before unblocking
	// the request-completion path that is waiting for the first deflake rerun.
	job.fuzzer.prepare(req, flags, 0)
	job.queue.Submit(req)
	job.readyOnce.Do(func() {
		close(job.ready)
	})
	return req.Wait(job.fuzzer.ctx)
}

func (job *triageJob) run(fuzzer *Fuzzer) {
	fuzzer.statNewInputs.Add(1)
	job.fuzzer = fuzzer
	job.info.Logf("\n%s", job.p.Serialize())
	for call, info := range job.calls {
		job.info.Logf("call #%d [%s]: |new signal|=%d%s",
			call, job.p.CallName(call), info.newSignal.Len(), signalPreview(info.newSignal))
	}

	// Compute input coverage and non-flaky signal for minimization.
	stop := job.deflake(job.execute)
	if stop {
		job.logTriageSkip(-1, ".all", nil, "deflake_stopped")
		return
	}
	var wg sync.WaitGroup
	for call, info := range job.calls {
		wg.Add(1)
		go func() {
			job.handleCall(call, info)
			wg.Done()
		}()
	}
	wg.Wait()
}

func (job *triageJob) handleCall(call int, info *triageCall) {
	origCall := call
	origCallName := job.p.CallName(call)
	if info.newStableSignal.Empty() {
		if job != nil && job.fuzzer != nil && job.fuzzer.target != nil &&
			job.fuzzer.target.RuntimePolicy.ShouldPersistStableTriageCall != nil &&
			!info.stableSignal.Empty() &&
			job.fuzzer.target.RuntimePolicy.ShouldPersistStableTriageCall(job.origin, job.p, call) {
		} else {
			job.logTriageSkip(call, origCallName, info, "no_new_stable_signal")
			return
		}
	}

	p := job.p
	if job.flags&ProgMinimized == 0 {
		if job.shouldKeepOriginalWithoutMinimization(call, info) {
			job.info.Logf("[call #%d] no_minimize stable owner; keeping original input", call)
		} else {
			p, call = job.minimize(call, info)
			if p == nil {
				if job.shouldPersistOriginalAfterMinimizeFailure(origCall, info) {
					p = job.p
					call = origCall
					job.info.Logf("[call #%d] minimization failed; keeping original stable focused input", call)
				} else {
					job.logTriageSkip(origCall, origCallName, info, "minimize_failed")
					return
				}
			}
		}
	}
	callName := p.CallName(call)
	if !job.shouldPersistCall(p, call) {
		job.logTriageSkip(call, callName, info, "should_persist_call")
		return
	}
	if !job.fuzzer.Config.NewInputFilter(callName) {
		job.logTriageSkip(call, callName, info, "new_input_filter")
		return
	}
	if job.flags&ProgSmashed == 0 {
		job.fuzzer.startJob(job.fuzzer.statJobsSmash, &smashJob{
			exec: job.fuzzer.smashQueue,
			p:    p.Clone(),
			info: &JobInfo{
				Name:  p.String(),
				Type:  "smash",
				Calls: []string{p.CallName(call)},
			},
		})
		if job.shouldStartHints(p, call) {
			job.fuzzer.startJob(job.fuzzer.statJobsHints, &hintsJob{
				exec: job.fuzzer.smashQueue,
				p:    p.Clone(),
				call: call,
				info: &JobInfo{
					Name:  p.String(),
					Type:  "hints",
					Calls: []string{p.CallName(call)},
				},
			})
		}
		if job.fuzzer.Config.FaultInjection && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsFaultInjection, &faultInjectionJob{
				exec: job.fuzzer.smashQueue,
				p:    p.Clone(),
				call: call,
			})
		}
	}
	job.fuzzer.Logf(2, "added new input for %v to the corpus: %s", callName, p)
	coverData := info.cover.Serialize()
	job.notifyCorpusSave(call, callName, info, coverData)
	job.logCorpusSave(call, callName, info, coverData)
	input := corpus.NewInput{
		Prog:     p,
		Call:     call,
		Signal:   info.stableSignal,
		Cover:    coverData,
		RawCover: info.rawCover,
	}
	job.fuzzer.Config.Corpus.Save(input)
	job.maybeScheduleImmediateCollide(p, call)
}

func (job *triageJob) notifyCorpusSave(call int, callName string, info *triageCall, coverData []uint64) {
	if job == nil || job.fuzzer == nil || job.fuzzer.Config.CorpusSaveCallback == nil ||
		info == nil {
		return
	}
	job.fuzzer.Config.CorpusSaveCallback(CorpusSaveEvent{
		Origin:          job.origin,
		TraceID:         job.traceID,
		Call:            call,
		CallName:        callName,
		StableSignal:    info.stableSignal.Len(),
		NewStableSignal: info.newStableSignal.Len(),
		Cover:           len(coverData),
		RawCover:        len(info.rawCover),
	})
}

func (job *triageJob) logCorpusSave(call int, callName string, info *triageCall, coverData []uint64) {
	if !job.triageDiagnosticsEnabled() || info == nil {
		return
	}
	trace := ""
	if job.traceID != "" {
		trace = fmt.Sprintf(" trace=%s", job.traceID)
	}
	job.fuzzer.Logf(0, "corpus save: origin=%s%s call=%d name=%s stable_signal=%d new_stable=%d cover=%d raw_cover=%d",
		job.origin, trace, call, callName, info.stableSignal.Len(), info.newStableSignal.Len(), len(coverData), len(info.rawCover))
}

func (job *triageJob) logTriageSkip(call int, callName string, info *triageCall, reason string) {
	if !job.triageDiagnosticsEnabled() {
		return
	}
	stableSignal, newStableSignal, newSignal, cover, rawCover := 0, 0, 0, 0, 0
	if info != nil {
		stableSignal = info.stableSignal.Len()
		newStableSignal = info.newStableSignal.Len()
		newSignal = info.newSignal.Len()
		cover = len(info.cover.Serialize())
		rawCover = len(info.rawCover)
	}
	trace := ""
	if job.traceID != "" {
		trace = fmt.Sprintf(" trace=%s", job.traceID)
	}
	job.fuzzer.Logf(0, "triage skip: origin=%s%s call=%d name=%s reason=%s stable_signal=%d new_stable=%d new_signal=%d cover=%d raw_cover=%d",
		job.origin, trace, call, callName, reason, stableSignal, newStableSignal, newSignal, cover, rawCover)
}

func (job *triageJob) shouldStartHints(p *prog.Prog, call int) bool {
	if !job.fuzzer.Config.Comparisons || call < 0 {
		return false
	}
	if !job.fuzzer.target.CallEligibleForHints(p.Calls[call].Meta) {
		return false
	}
	return true
}

func (job *triageJob) shouldPersistCall(p *prog.Prog, call int) bool {
	if call < 0 {
		return true
	}
	if job.fuzzer.target.RuntimePolicy.ShouldSkipTriageProgram != nil &&
		job.fuzzer.target.RuntimePolicy.ShouldSkipTriageProgram(job.origin, p) {
		return false
	}
	if job.fuzzer.target.Helpers.SkipCorpusForAutomaticHelpers && job.fuzzer.target.CallIsAutomaticHelper(p.Calls[call].Meta) {
		return false
	}
	return true
}

func (job *triageJob) shouldPersistOriginalAfterMinimizeFailure(call int, info *triageCall) bool {
	if call < 0 || info == nil || info.stableSignal.Empty() {
		return false
	}
	if job.shouldKeepOriginalWithoutMinimization(call, info) {
		return true
	}
	if job.fuzzer == nil || job.fuzzer.target == nil ||
		job.fuzzer.target.RuntimePolicy.ShouldPersistStableTriageCall == nil {
		return false
	}
	return job.fuzzer.target.RuntimePolicy.ShouldPersistStableTriageCall(job.origin, job.p, call)
}

func (job *triageJob) shouldKeepOriginalWithoutMinimization(call int, info *triageCall) bool {
	if call < 0 || info == nil || info.stableSignal.Empty() || job == nil || job.p == nil ||
		call >= len(job.p.Calls) || job.p.Calls[call] == nil || job.p.Calls[call].Meta == nil {
		return false
	}
	if !job.p.Calls[call].Meta.Attrs.NoMinimize {
		return false
	}
	return job.shouldPersistCall(job.p, call)
}

func (job *triageJob) maybeScheduleImmediateCollide(p *prog.Prog, call int) {
	if job == nil || job.fuzzer == nil || !job.fuzzer.Config.Collide || p == nil || call < 0 {
		return
	}
	if job.flags&ProgSmashed != 0 {
		return
	}
	if job.fuzzer.target == nil || job.fuzzer.target.RuntimePolicy.ShouldScheduleImmediateCollide == nil {
		return
	}
	if !job.fuzzer.target.RuntimePolicy.ShouldScheduleImmediateCollide(p, call) {
		return
	}
	collidedProg := job.immediateCollideProg(p)
	if collidedProg == nil || string(collidedProg.Serialize()) == string(p.Serialize()) {
		return
	}
	req := &queue.Request{
		Prog:      collidedProg,
		ExecOpts:  setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:      job.fuzzer.statExecCollide,
		Origin:    "collide:triage",
		TraceID:   job.fuzzer.nextTraceID("collide"),
		Important: true,
	}
	if !job.fuzzer.shouldScheduleProgram(req) {
		return
	}
	job.fuzzer.enqueue(job.fuzzer.immediateCollideQueue, req, ProgSmashed, 0)
}

func (job *triageJob) immediateCollideProg(p *prog.Prog) *prog.Prog {
	if job == nil || job.fuzzer == nil || p == nil {
		return nil
	}
	orig := p.Serialize()
	for range 8 {
		collided := randomCollide(p.Clone(), job.fuzzer.rand())
		if collided != nil && !bytes.Equal(collided.Serialize(), orig) {
			return collided
		}
	}
	return nil
}

func (job *triageJob) deflake(exec func(*queue.Request, ProgFlags) *queue.Result) (stop bool) {
	job.info.Logf("deflake started")

	avoid := []queue.ExecutorID{job.executor}
	needRuns := deflakeNeedCorpusRuns
	if job.fuzzer.Config.Snapshot {
		needRuns = deflakeNeedSnapshotRuns
	} else if job.flags&ProgFromCorpus == 0 {
		needRuns = deflakeNeedRuns
	}
	job.logTriageDeflakeStart(needRuns)
	prevTotalNewSignal := 0
	for run := 1; ; run++ {
		totalNewSignal := 0
		indices := make([]int, 0, len(job.calls))
		for call, info := range job.calls {
			indices = append(indices, call)
			totalNewSignal += len(info.newSignal)
		}
		if job.stopDeflake(run, needRuns, prevTotalNewSignal == totalNewSignal) {
			break
		}
		prevTotalNewSignal = totalNewSignal
		result := exec(&queue.Request{
			Prog:            job.p,
			ExecOpts:        setFlags(flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal),
			ReturnAllSignal: indices,
			Avoid:           avoid,
			Stat:            job.fuzzer.statExecTriage,
		}, progInTriage)
		job.logTriageDeflakeRun(run, needRuns, indices, result)
		if result.Stop() && (result.Status != queue.Hanged || result.Info == nil) {
			job.logTriageDeflakeStop(run, needRuns, result.Status)
			return true
		}
		avoid = append(avoid, result.Executor)
		if result.Info == nil {
			continue // the program has failed
		}
		deflakeCall := func(call int, res *flatrpc.CallInfo) {
			info := job.calls[call]
			if info == nil {
				job.fuzzer.triageProgCall(job.origin, job.p, res, call, &job.calls)
				info = job.calls[call]
			}
			if info == nil || res == nil {
				return
			}
			if len(info.rawCover) == 0 && job.fuzzer.Config.FetchRawCover {
				info.rawCover = res.Cover
			}
			// Since the signal is frequently flaky, we may get some new new max signal.
			// Merge it into the new signal we are chasing.
			// Most likely we won't conclude it's stable signal b/c we already have at least one
			// initial run w/o this signal, so if we exit after needRuns runs,
			// it won't be stable. However, it's still possible if we do more than needRuns runs.
			// But also we already observed it and we know it's flaky, so at least doing
			// cover.addRawMaxSignal for it looks useful.
			prio := signalPrio(job.p, res, call)
			thisSignal := signal.FromRaw(res.Signal, prio)
			candidateOverlap := info.candidateSignal.Intersection(thisSignal).Len()
			newOverlap := info.newSignal.Intersection(thisSignal).Len()
			newMaxSignal := job.fuzzer.Cover.addRawMaxSignal(res.Signal, prio)
			info.newSignal.Merge(newMaxSignal)
			info.cover.Merge(res.Cover)
			for j := needRuns - 1; j > 0; j-- {
				intersect := info.signals[j-1].Intersection(thisSignal)
				info.signals[j].Merge(intersect)
			}
			info.signals[0].Merge(thisSignal)
			job.logTriageDeflakeSignalRun(run, needRuns, call, res, newMaxSignal.Len(),
				candidateOverlap, newOverlap, info)
		}
		for i, callInfo := range result.Info.Calls {
			deflakeCall(i, callInfo)
		}
		deflakeCall(-1, result.Info.Extra)
	}
	job.info.Logf("deflake complete")
	for call, info := range job.calls {
		info.stableSignal = info.signals[needRuns-1]
		info.newStableSignal = info.newSignal.Intersection(info.stableSignal)
		job.info.Logf("call #%d [%s]: |stable signal|=%d, |new stable signal|=%d%s",
			call, job.p.CallName(call), info.stableSignal.Len(), info.newStableSignal.Len(),
			signalPreview(info.newStableSignal))
		job.logTriageDeflakeComplete(call, info)
	}
	return false
}

func (job *triageJob) logTriageDeflakeStart(needRuns int) {
	if !job.triageDiagnosticsEnabled() {
		return
	}
	job.fuzzer.Logf(0, "triage deflake start: origin=%s%s calls=[%s] need_runs=%d flags=0x%x",
		job.origin, job.traceLogSuffix(), job.callNamesForLog(job.callIndices()), needRuns, job.flags)
}

func (job *triageJob) logTriageDeflakeRun(run, needRuns int, calls []int, result *queue.Result) {
	if !job.triageDiagnosticsEnabled() || result == nil {
		return
	}
	infoCalls := 0
	if result.Info != nil {
		infoCalls = len(result.Info.Calls)
	}
	job.fuzzer.Logf(0, "triage deflake run: origin=%s%s run=%d need_runs=%d calls=[%s] status=%s info_calls=%d",
		job.origin, job.traceLogSuffix(), run, needRuns, job.callNamesForLog(calls), result.Status, infoCalls)
}

func (job *triageJob) logTriageDeflakeStop(run, needRuns int, status queue.Status) {
	if !job.triageDiagnosticsEnabled() {
		return
	}
	job.fuzzer.Logf(0, "triage deflake stop: origin=%s%s run=%d need_runs=%d status=%s",
		job.origin, job.traceLogSuffix(), run, needRuns, status)
}

func (job *triageJob) logTriageDeflakeComplete(call int, info *triageCall) {
	if !job.triageDiagnosticsEnabled() || info == nil {
		return
	}
	job.fuzzer.Logf(0, "triage deflake complete: origin=%s%s call=%d name=%s stable_signal=%d new_stable=%d new_signal=%d cover=%d raw_cover=%d",
		job.origin, job.traceLogSuffix(), call, job.p.CallName(call), info.stableSignal.Len(), info.newStableSignal.Len(),
		info.newSignal.Len(), len(info.cover.Serialize()), len(info.rawCover))
}

func (job *triageJob) logTriageDeflakeSignalRun(run, needRuns, call int, res *flatrpc.CallInfo,
	newMaxSignal, candidateOverlap, newOverlap int, info *triageCall) {
	if !job.triageDiagnosticsEnabled() || res == nil || info == nil {
		return
	}
	buckets := make([]int, needRuns)
	for i := 0; i < needRuns; i++ {
		buckets[i] = info.signals[i].Len()
	}
	job.fuzzer.Logf(0, "triage deflake signal: origin=%s%s run=%d need_runs=%d call=%d name=%s signal=%d cover=%d prio=%d new_max=%d candidate_overlap=%d new_overlap=%d buckets=[%s] errno=%d flags=0x%x",
		job.origin, job.traceLogSuffix(), run, needRuns, call, job.p.CallName(call), len(res.Signal),
		len(res.Cover), signalPrio(job.p, res, call), newMaxSignal, candidateOverlap, newOverlap,
		intsForLog(buckets), res.Error, uint8(res.Flags))
}

func (job *triageJob) triageDiagnosticsEnabled() bool {
	return job != nil && job.fuzzer != nil && job.fuzzer.triageDiagnosticsEnabled()
}

func (job *triageJob) traceLogSuffix() string {
	if job.traceID == "" {
		return ""
	}
	return fmt.Sprintf(" trace=%s", job.traceID)
}

func (job *triageJob) callIndices() []int {
	calls := make([]int, 0, len(job.calls))
	for call := range job.calls {
		calls = append(calls, call)
	}
	return calls
}

func (job *triageJob) callNamesForLog(calls []int) string {
	names := make([]string, 0, len(calls))
	for _, call := range calls {
		names = append(names, job.p.CallName(call))
	}
	slices.Sort(names)
	return strings.Join(names, " ")
}

func intsForLog(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprint(value))
	}
	return strings.Join(parts, " ")
}

func (job *triageJob) stopDeflake(run, needRuns int, noNewSignal bool) bool {
	if job.fuzzer.Config.Snapshot {
		return run >= needRuns+1
	}
	haveSignal := true
	havePersistableStableSignal := false
	for call, info := range job.calls {
		if !info.newSignal.IntersectsWith(info.signals[needRuns-1]) {
			haveSignal = false
		}
		if job.shouldStopDeflakeForStableTriageCall(call, info, needRuns) {
			havePersistableStableSignal = true
		}
	}
	if job.flags&ProgFromCorpus == 0 {
		// For fuzzing programs we stop if we already have the right deflaked signal for all calls,
		// or there's no chance to get coverage common to needRuns for all calls.
		if run >= deflakeMaxRuns {
			return true
		}
		noChance := true
		for _, call := range job.calls {
			if left := deflakeMaxRuns - run; left >= needRuns ||
				call.newSignal.IntersectsWith(call.signals[needRuns-left-1]) {
				noChance = false
			}
		}
		if haveSignal || havePersistableStableSignal || noChance {
			return true
		}
	} else if run >= deflakeTotalCorpusRuns ||
		noNewSignal && (run >= deflakeMaxCorpusRuns || run >= deflakeMinCorpusRuns && haveSignal) {
		// For programs from the corpus we use a different condition b/c we want to extract
		// as much flaky signal from them as possible. They have large coverage and run
		// in the beginning, gathering flaky signal on them allows to grow max signal quickly
		// and avoid lots of useless executions later. Any bit of flaky coverage discovered
		// later will lead to triage, and if we are unlucky to conclude it's stable also
		// to minimization+smash+hints (potentially thousands of runs).
		// So we run them at least 5 times, or while we are still getting any new signal.
		return true
	}
	return false
}

func (job *triageJob) shouldStopDeflakeForStableTriageCall(call int, info *triageCall, needRuns int) bool {
	if call < 0 || info == nil || info.signals[needRuns-1].Empty() {
		return false
	}
	if job.fuzzer == nil || job.fuzzer.target == nil ||
		job.fuzzer.target.RuntimePolicy.ShouldPersistStableTriageCall == nil {
		return false
	}
	return job.fuzzer.target.RuntimePolicy.ShouldPersistStableTriageCall(job.origin, job.p, call)
}

func (job *triageJob) minimize(call int, info *triageCall) (*prog.Prog, int) {
	job.info.Logf("[call #%d] minimize started", call)
	minimizeAttempts := 3
	if job.fuzzer.Config.Snapshot {
		minimizeAttempts = 2
	}
	stop := false
	mode := prog.MinimizeCorpus
	if job.fuzzer.Config.PatchTest {
		mode = prog.MinimizeCallsOnly
	}
	p, call := prog.Minimize(job.p, call, mode, func(p1 *prog.Prog, call1 int) bool {
		if stop {
			return false
		}
		var mergedSignal signal.Signal
		for range minimizeAttempts {
			result := job.execute(&queue.Request{
				Prog:            p1,
				ExecOpts:        setFlags(flatrpc.ExecFlagCollectSignal),
				ReturnAllSignal: []int{call1},
				Stat:            job.fuzzer.statExecMinimize,
			}, progInTriage)
			if result.Stop() {
				stop = true
				return false
			}
			if !reexecutionSuccess(result.Info, info.errno, call1) {
				// The call was not executed or failed.
				continue
			}
			thisSignal := getSignalAndCover(p1, result.Info, call1)
			if mergedSignal.Len() == 0 {
				mergedSignal = thisSignal
			} else {
				mergedSignal.Merge(thisSignal)
			}
			if info.newStableSignal.Intersection(mergedSignal).Len() == info.newStableSignal.Len() {
				if !job.shouldPersistCall(p1, call1) {
					job.info.Logf("[call #%d] minimization step rejected by persist policy (|calls| = %d)",
						call, len(p1.Calls))
					return false
				}
				job.info.Logf("[call #%d] minimization step success (|calls| = %d)",
					call, len(p1.Calls))
				return true
			}
		}
		job.info.Logf("[call #%d] minimization step failure", call)
		return false
	})
	if stop {
		return nil, 0
	}
	return p, call
}

func reexecutionSuccess(info *flatrpc.ProgInfo, oldErrno int32, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldErrno == 0 && info.Calls[call].Error != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return info.Extra != nil && len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *flatrpc.ProgInfo, call int) signal.Signal {
	inf := info.Extra
	if call != -1 {
		inf = info.Calls[call]
	}
	if inf == nil {
		return nil
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call))
}

func signalPreview(s signal.Signal) string {
	if s.Len() > 0 && s.Len() <= 3 {
		var sb strings.Builder
		sb.WriteString(" (")
		for i, x := range s.ToRaw() {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "0x%x", x)
		}
		sb.WriteByte(')')
		return sb.String()
	}
	return ""
}

func (job *triageJob) getInfo() *JobInfo {
	return job.info
}

type smashJob struct {
	exec queue.Executor
	p    *prog.Prog
	info *JobInfo
}

func (job *smashJob) run(fuzzer *Fuzzer) {
	fuzzer.Logf(2, "smashing the program %s:", job.p)
	job.info.Logf("\n%s", job.p.Serialize())

	const iters = 25
	rnd := fuzzer.rand()
	for range iters {
		p := job.p.Clone()
		p.Mutate(rnd, fuzzer.RecommendedCalls(),
			fuzzer.ChoiceTable(),
			fuzzer.Config.NoMutateCalls,
			fuzzer.Config.Corpus.Programs())
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:     fuzzer.statExecSmash,
		})
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
	}
}

func (job *smashJob) getInfo() *JobInfo {
	return job.info
}

func randomCollide(origP *prog.Prog, rnd *rand.Rand) *prog.Prog {
	if rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	if rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, rnd)
	if rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, rnd)
	}
	return p
}

type faultInjectionJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
}

func (job *faultInjectionJob) run(fuzzer *Fuzzer) {
	for nth := 1; nth <= 100; nth++ {
		fuzzer.Logf(2, "injecting fault into call %v, step %v",
			job.call, nth)
		newProg := job.p.Clone()
		newProg.Calls[job.call].Props.FailNth = nth
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog: newProg,
			Stat: fuzzer.statExecFaultInject,
		})
		if result.Stop() {
			return
		}
		info := result.Info
		if info != nil && len(info.Calls) > job.call &&
			info.Calls[job.call].Flags&flatrpc.CallFlagFaultInjected == 0 {
			break
		}
	}
}

type hintsJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
	info *JobInfo
}

func (job *hintsJob) run(fuzzer *Fuzzer) {
	// First execute the original program several times to get comparisons from KCOV.
	// Additional executions lets us filter out flaky values, which seem to constitute ~30-40%.
	p := job.p
	job.info.Logf("\n%s", p.Serialize())

	var comps prog.CompMap
	for i := range 3 {
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectComps),
			Stat:     fuzzer.statExecSeed,
		})
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
		if result.Info == nil || len(result.Info.Calls[job.call].Comps) == 0 {
			continue
		}
		got := make(prog.CompMap)
		for _, cmp := range result.Info.Calls[job.call].Comps {
			got.Add(cmp.Pc, cmp.Op1, cmp.Op2, cmp.IsConst)
		}
		if i == 0 {
			comps = got
		} else {
			comps.InplaceIntersect(got)
		}
	}

	job.info.Logf("stable comps: %d", comps.Len())
	fuzzer.hintsLimiter.Limit(comps)
	job.info.Logf("stable comps (after the hints limiter): %d", comps.Len())

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(job.call, comps,
		func(p *prog.Prog) bool {
			defer job.info.Execs.Add(1)
			result := fuzzer.execute(job.exec, &queue.Request{
				Prog:     p,
				ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
				Stat:     fuzzer.statExecHint,
			})
			return !result.Stop()
		})
}

func (job *hintsJob) getInfo() *JobInfo {
	return job.info
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *syncBuffer) Logf(logFmt string, args ...any) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	fmt.Fprintf(&sb.buf, "%s: ", time.Now().Format(time.DateTime))
	fmt.Fprintf(&sb.buf, logFmt, args...)
	sb.buf.WriteByte('\n')
}

func (sb *syncBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Bytes()
}

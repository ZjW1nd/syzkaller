// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Stats
	Config *Config
	Cover  *Cover

	ctx          context.Context
	mu           sync.Mutex
	rnd          *rand.Rand
	target       *prog.Target
	hintsLimiter prog.HintsLimiter
	runningJobs  map[jobIntrospector]struct{}

	ct           *prog.ChoiceTable
	ctProgs      int
	ctMu         sync.Mutex // TODO: use RWLock.
	ctRegenerate chan struct{}
	traceSeq     atomic.Uint64

	execQueues
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	if cfg.NewInputFilter == nil {
		cfg.NewInputFilter = func(call string) bool {
			return true
		}
	}
	if target != nil && target.RuntimePolicy.TriageDiagnostics {
		cfg.TriageDiagnostics = true
	}
	cfg.NoMutateCalls = mergeTargetNoMutateCalls(target, cfg.NoMutateCalls)
	f := &Fuzzer{
		Stats:  newStats(target),
		Config: cfg,
		Cover:  newCover(),

		ctx:         ctx,
		rnd:         rnd,
		target:      target,
		runningJobs: map[jobIntrospector]struct{}{},

		// We're okay to lose some of the messages -- if we are already
		// regenerating the table, we don't want to repeat it right away.
		ctRegenerate: make(chan struct{}),
	}
	if target != nil {
		target.ObserveTemplateHook = func(name string) {
			switch {
			case strings.HasPrefix(name, "gen:"):
				f.statTemplateGen.Add(1)
			case strings.HasPrefix(name, "corpus:"):
				f.statTemplateCorpus.Add(1)
			case strings.HasPrefix(name, "collide:"):
				f.statTemplateCollide.Add(1)
			case strings.HasPrefix(name, "rc_try:"):
				f.statResourceCentricTry.Add(1)
			case strings.HasPrefix(name, "rc_hit:"):
				f.statResourceCentricHit.Add(1)
			case strings.HasPrefix(name, "rc_no_candidates:"):
				f.statResourceCentricNoCandidates.Add(1)
			case strings.HasPrefix(name, "rc_zero_score:"):
				f.statResourceCentricZeroScore.Add(1)
			}
		}
	}
	f.execQueues = newExecQueues(f)
	f.updateChoiceTable(nil)
	go f.choiceTableUpdater()
	if cfg.Debug {
		go f.logCurrentStats()
	}
	return f
}

func mergeTargetNoMutateCalls(target *prog.Target, noMutate map[int]bool) map[int]bool {
	if target == nil || !target.Helpers.NoMutateAutomaticHelpers {
		return noMutate
	}
	var merged map[int]bool
	if noMutate != nil {
		merged = make(map[int]bool, len(noMutate))
		for id, v := range noMutate {
			merged[id] = v
		}
	} else {
		merged = make(map[int]bool)
	}
	for _, call := range target.Syscalls {
		if target.CallIsAutomaticHelper(call) {
			merged[call.ID] = true
		}
	}
	return merged
}

func (fuzzer *Fuzzer) RecommendedCalls() int {
	if fuzzer.Config.MaxCallsPerProg > 0 {
		if fuzzer.Config.ModeKFuzzTest {
			return min(fuzzer.Config.MaxCallsPerProg, prog.RecommendedCallsKFuzzTest)
		}
		return min(fuzzer.Config.MaxCallsPerProg, prog.RecommendedCalls)
	}
	if fuzzer.Config.ModeKFuzzTest {
		return prog.RecommendedCallsKFuzzTest
	}
	return prog.RecommendedCalls
}

type execQueues struct {
	triageCandidateQueue  *queue.DynamicOrderer
	candidateQueue        *queue.PlainQueue
	immediateCollideQueue *queue.PlainQueue
	triageQueue           *queue.DynamicOrderer
	smashQueue            *queue.PlainQueue
	source                queue.Source
}

func newExecQueues(fuzzer *Fuzzer) execQueues {
	ret := execQueues{
		triageCandidateQueue:  queue.DynamicOrder(),
		candidateQueue:        queue.Plain(),
		immediateCollideQueue: queue.Plain(),
		triageQueue:           queue.DynamicOrder(),
		smashQueue:            queue.Plain(),
	}
	// Alternate smash jobs with exec/fuzz to spread attention to the wider area.
	skipQueue := 3
	if fuzzer.Config.PatchTest {
		// When we do patch fuzzing, we do not focus on finding and persisting
		// new coverage that much, so it's reasonable to spend more time just
		// mutating various corpus programs.
		skipQueue = 2
	}
	// Sources are listed in the order, in which they will be polled.
	highPriority := queue.Order(
		ret.immediateCollideQueue,
		ret.triageCandidateQueue,
	)
	regularPriority := queue.Order(
		ret.candidateQueue,
		ret.triageQueue,
		queue.Alternate(ret.smashQueue, skipQueue),
	)
	generate := queue.Callback(fuzzer.genFuzz)
	regularWithGenerate := queue.Order(regularPriority, generate)
	if fuzzer.Config.ForceGenerateEveryN > 0 {
		regularWithGenerate = queue.Interleave(regularPriority, generate, fuzzer.Config.ForceGenerateEveryN)
	}
	ret.source = queue.Order(highPriority, queue.Callback(func() *queue.Request {
		if fuzzer.statJobsTriageCandidate.Val() > 0 {
			return nil
		}
		return regularWithGenerate.Next()
	}))
	return ret
}

func (fuzzer *Fuzzer) CandidatesToTriage() int {
	return fuzzer.statCandidates.Val() + fuzzer.statJobsTriageCandidate.Val()
}

func (fuzzer *Fuzzer) CandidateTriageFinished() bool {
	return fuzzer.CandidatesToTriage() == 0
}

func (fuzzer *Fuzzer) execute(executor queue.Executor, req *queue.Request) *queue.Result {
	return fuzzer.executeWithFlags(executor, req, 0)
}

func (fuzzer *Fuzzer) executeWithFlags(executor queue.Executor, req *queue.Request, flags ProgFlags) *queue.Result {
	if !fuzzer.shouldScheduleProgram(req) {
		return runtimePolicyRejectedResult(req)
	}
	fuzzer.enqueue(executor, req, flags, 0)
	return req.Wait(fuzzer.ctx)
}

func (fuzzer *Fuzzer) prepare(req *queue.Request, flags ProgFlags, attempt int) {
	if req != nil && req.Prog != nil {
		req.Prog, _ = prog.SanitizeCollidePropsForTarget(req.Prog)
	}
	req.OnDone(func(req *queue.Request, res *queue.Result) bool {
		return fuzzer.processResult(req, res, flags, attempt)
	})
}

func (fuzzer *Fuzzer) enqueue(executor queue.Executor, req *queue.Request, flags ProgFlags, attempt int) {
	fuzzer.prepare(req, flags, attempt)
	executor.Submit(req)
}

func (fuzzer *Fuzzer) processResult(req *queue.Request, res *queue.Result, flags ProgFlags, attempt int) bool {
	// If we are already triaging this exact prog, this is flaky coverage.
	// Hanged programs are harmful as they consume executor procs.
	dontTriage := flags&progInTriage > 0 || res.Status == queue.Hanged
	// Triage the program.
	// We do it before unblocking the waiting threads because
	// it may result it concurrent modification of req.Prog.
	var triage map[int]*triageCall
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0 && res.Info != nil && !dontTriage {
		for call, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Origin, req.Prog, info, call, &triage)
		}
		fuzzer.triageProgCall(req.Origin, req.Prog, res.Info.Extra, -1, &triage)

		if len(triage) != 0 {
			queue, stat := fuzzer.triageQueue, fuzzer.statJobsTriage
			if flags&progCandidate > 0 {
				queue, stat = fuzzer.triageCandidateQueue, fuzzer.statJobsTriageCandidate
			}
			job := &triageJob{
				p:        req.Prog.Clone(),
				executor: res.Executor,
				flags:    flags,
				origin:   req.Origin,
				traceID:  req.TraceID,
				queue:    queue.Append(),
				calls:    triage,
				ready:    make(chan struct{}),
				info: &JobInfo{
					Name: req.Prog.String(),
					Type: "triage",
				},
			}
			for id := range triage {
				job.info.Calls = append(job.info.Calls, job.p.CallName(id))
			}
			slices.Sort(job.info.Calls)
			fuzzer.logTriageJobQueued(req.Origin, req.TraceID, job.info.Calls, flags, attempt, res.Status)
			fuzzer.startJob(stat, job)
			<-job.ready
		}
	}

	if res.Info != nil {
		fuzzer.statExecTime.Add(int(res.Info.Elapsed / 1e6))
		for call, info := range res.Info.Calls {
			fuzzer.handleCallInfo(req, info, call)
		}
		fuzzer.handleCallInfo(req, res.Info.Extra, -1)
	}

	// Corpus candidates may have flaky coverage, so we give them a second chance.
	maxCandidateAttempts := 3
	if req.Risky() {
		// In non-snapshot mode usually we are not sure which exactly input caused the crash,
		// so give it one more chance. In snapshot mode we know for sure, so don't retry.
		maxCandidateAttempts = 2
		if fuzzer.Config.Snapshot || res.Status == queue.Hanged {
			maxCandidateAttempts = 0
		}
	}
	if len(triage) == 0 && flags&ProgFromCorpus != 0 && attempt < maxCandidateAttempts {
		fuzzer.enqueue(fuzzer.candidateQueue, req, flags, attempt+1)
		return false
	}
	if flags&progCandidate != 0 {
		fuzzer.statCandidates.Add(-1)
	}
	return true
}

type Config struct {
	Debug               bool
	Corpus              *corpus.Corpus
	Logf                func(level int, msg string, args ...any)
	TriageDiagnostics   bool
	CorpusSaveCallback  func(CorpusSaveEvent)
	Snapshot            bool
	Coverage            bool
	FaultInjection      bool
	Comparisons         bool
	Collide             bool
	EnabledCalls        map[*prog.Syscall]bool
	NoMutateCalls       map[int]bool
	NoGenerateCalls     map[int]bool
	BorrowingCorpus     []*prog.Prog
	CorpusProgramWeight corpus.ProgramWeightFunc
	FetchRawCover       bool
	NewInputFilter      func(call string) bool
	PatchTest           bool
	ModeKFuzzTest       bool
	MaxCallsPerProg     int
	ForceGenerateEveryN int
}

func (fuzzer *Fuzzer) triageProgCall(origin string, p *prog.Prog, info *flatrpc.CallInfo, call int, triage *map[int]*triageCall) {
	if info == nil {
		return
	}
	prio := signalPrio(p, info, call)
	if fuzzer.target != nil && fuzzer.target.RuntimePolicy.ShouldSkipTriageProgram != nil &&
		fuzzer.target.RuntimePolicy.ShouldSkipTriageProgram(origin, p) {
		fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
		return
	}
	if call >= 0 && !fuzzer.target.CallEligibleForTriage(p.Calls[call].Meta) {
		return
	}
	if !fuzzer.Config.NewInputFilter(p.CallName(call)) {
		return
	}
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if newMaxSignal.Empty() {
		if len(info.Signal) == 0 {
			return
		}
		if fuzzer.target == nil || fuzzer.target.RuntimePolicy.ShouldForceTriageCall == nil ||
			!fuzzer.target.RuntimePolicy.ShouldForceTriageCall(origin, p, call) {
			return
		}
		newMaxSignal = signal.FromRaw([]uint64{1}, 0)
	}
	if fuzzer.pruneLessRelevantTriage(origin, p, call, triage) {
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s", call, p)
	fuzzer.logTriageCall(p, call, info, prio, newMaxSignal.Len())
	if *triage == nil {
		*triage = make(map[int]*triageCall)
	}
	(*triage)[call] = &triageCall{
		errno:           info.Error,
		newSignal:       newMaxSignal,
		candidateSignal: signal.FromRaw(info.Signal, prio),
		origin:          origin,
		signals:         [deflakeNeedRuns]signal.Signal{signal.FromRaw(info.Signal, prio)},
	}
}

func (fuzzer *Fuzzer) pruneLessRelevantTriage(origin string, p *prog.Prog, call int, triage *map[int]*triageCall) bool {
	if call < 0 || *triage == nil {
		return false
	}
	keepCandidateOwner := fuzzer.shouldKeepCandidateTriageOwner(origin, p, call)
	score := fuzzer.target.TriageRelevance(p.Calls[call].Meta)
	skipCurrent := false
	for id := range *triage {
		if id < 0 {
			continue
		}
		if keepCandidateOwner && fuzzer.shouldKeepCandidateTriageOwner(origin, p, id) {
			continue
		}
		otherScore := fuzzer.target.TriageRelevance(p.Calls[id].Meta)
		if otherScore > score {
			skipCurrent = true
			continue
		}
		if otherScore < score {
			delete(*triage, id)
		}
	}
	return skipCurrent
}

func (fuzzer *Fuzzer) shouldKeepCandidateTriageOwner(origin string, p *prog.Prog, call int) bool {
	if origin != "candidate" || fuzzer == nil || fuzzer.target == nil || p == nil || call < 0 || call >= len(p.Calls) {
		return false
	}
	meta := p.Calls[call].Meta
	if !fuzzer.target.CallEligibleForTriage(meta) {
		return false
	}
	if fuzzer.target.Helpers.SkipCorpusForAutomaticHelpers && fuzzer.target.CallIsAutomaticHelper(meta) {
		return false
	}
	if fuzzer.target.RuntimePolicy.ShouldSkipTriageProgram != nil &&
		fuzzer.target.RuntimePolicy.ShouldSkipTriageProgram(origin, p) {
		return false
	}
	return fuzzer.target.RuntimePolicy.ShouldPersistStableTriageCall != nil &&
		fuzzer.target.RuntimePolicy.ShouldPersistStableTriageCall(origin, p, call)
}

func (fuzzer *Fuzzer) handleCallInfo(req *queue.Request, info *flatrpc.CallInfo, call int) {
	if info == nil || info.Flags&flatrpc.CallFlagCoverageOverflow == 0 {
		return
	}
	syscallIdx := len(fuzzer.Syscalls) - 1
	if call != -1 {
		syscallIdx = req.Prog.Calls[call].Meta.ID
	}
	stat := &fuzzer.Syscalls[syscallIdx]
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps != 0 {
		stat.CompsOverflows.Add(1)
		fuzzer.statCompsOverflows.Add(1)
	} else {
		stat.CoverOverflows.Add(1)
		fuzzer.statCoverOverflows.Add(1)
	}
}

func signalPrio(p *prog.Prog, info *flatrpc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Error == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func (fuzzer *Fuzzer) genFuzz() *queue.Request {
	// Either generate a new input or mutate an existing one.
	mutateRate := 0.95
	if !fuzzer.Config.Coverage {
		// If we don't have real coverage signal, generate programs
		// more frequently because fallback signal is weak.
		mutateRate = 0.5
	}
	var req *queue.Request
	rnd := fuzzer.rand()
	for range 16 {
		if rnd.Float64() < mutateRate {
			req = mutateProgRequest(fuzzer, rnd)
		}
		if req == nil {
			req = genProgRequest(fuzzer, rnd)
		}
		if fuzzer.shouldScheduleProgram(req) {
			break
		}
		req = nil
	}
	if req == nil && len(fuzzer.Config.BorrowingCorpus) != 0 {
		for range 16 {
			req = genFreshProgRequest(fuzzer, rnd)
			if fuzzer.shouldScheduleProgram(req) {
				break
			}
			req = nil
		}
	}
	if req == nil {
		return nil
	}
	collideChance := fuzzer.collideChanceForProg(req.Prog)
	if fuzzer.Config.Collide && (fuzzer.Config.MaxCallsPerProg == 0 || fuzzer.Config.MaxCallsPerProg > 1) &&
		rnd.Intn(collideChance) == 0 {
		collidedProg := randomCollide(req.Prog, rnd)
		collideReq := &queue.Request{
			Prog:       collidedProg,
			Stat:       fuzzer.statExecCollide,
			ExtraStats: []*stat.Val{req.Stat},
			Origin:     "collide:" + req.Origin,
			TraceID:    fuzzer.nextTraceID("collide"),
		}
		if fuzzer.shouldScheduleProgram(collideReq) {
			req = collideReq
		}
	}
	fuzzer.prepare(req, 0, 0)
	return req
}

func (fuzzer *Fuzzer) shouldScheduleProgram(req *queue.Request) bool {
	if req == nil {
		return false
	}
	if req.Type != flatrpc.RequestTypeProgram {
		return true
	}
	if req.Prog == nil {
		return false
	}
	if fuzzer.target == nil || fuzzer.target.RuntimePolicy.ShouldScheduleProgram == nil {
		return true
	}
	if !fuzzer.programUsesEnabledCalls(req.Prog) {
		return false
	}
	return fuzzer.target.RuntimePolicy.ShouldScheduleProgram(req.Origin, req.Prog)
}

func (fuzzer *Fuzzer) programUsesEnabledCalls(p *prog.Prog) bool {
	if p == nil || fuzzer == nil || fuzzer.Config == nil || len(fuzzer.Config.EnabledCalls) == 0 {
		return true
	}
	for _, call := range p.Calls {
		if call == nil || call.Meta == nil || fuzzer.Config.EnabledCalls[call.Meta] {
			continue
		}
		if fuzzer.target.CallNoGenerate(call.Meta) ||
			fuzzer.target != nil && fuzzer.target.CallIsAutomaticHelper(call.Meta) {
			continue
		}
		return false
	}
	return true
}

func runtimePolicyRejectedResult(req *queue.Request) *queue.Result {
	origin := ""
	if req != nil {
		origin = req.Origin
	}
	return &queue.Result{
		Status: queue.ExecFailure,
		Err:    fmt.Errorf("runtime policy rejected program origin=%q", origin),
	}
}

func runtimePolicySkippedResult(req *queue.Request) *queue.Result {
	res := runtimePolicyRejectedResult(req)
	res.Status = queue.Success
	return res
}

func (fuzzer *Fuzzer) collideChanceForProg(p *prog.Prog) int {
	if p != nil && fuzzer.target != nil && fuzzer.target.RuntimePolicy.PreferCollideProgram != nil &&
		fuzzer.target.RuntimePolicy.PreferCollideProgram(p) {
		return 1
	}
	return 3
}

func (fuzzer *Fuzzer) nextTraceID(prefix string) string {
	if prefix == "" {
		prefix = "req"
	}
	return fmt.Sprintf("%s-%d", prefix, fuzzer.traceSeq.Add(1))
}

func (fuzzer *Fuzzer) startJob(stat *stat.Val, newJob job) {
	fuzzer.Logf(2, "started %T", newJob)
	go func() {
		stat.Add(1)
		defer stat.Add(-1)

		fuzzer.statJobs.Add(1)
		defer fuzzer.statJobs.Add(-1)

		if obj, ok := newJob.(jobIntrospector); ok {
			fuzzer.mu.Lock()
			fuzzer.runningJobs[obj] = struct{}{}
			fuzzer.mu.Unlock()

			defer func() {
				fuzzer.mu.Lock()
				delete(fuzzer.runningJobs, obj)
				fuzzer.mu.Unlock()
			}()
		}

		newJob.run(fuzzer)
	}()
}

func (fuzzer *Fuzzer) Next() *queue.Request {
	for tries := 0; ; tries++ {
		req := fuzzer.source.Next()
		if req != nil {
			return req
		}
		if fuzzer.statJobsTriageCandidate.Val() > 0 {
			return nil
		}
		// Some focused modes can temporarily exhaust candidate/corpus-driven sources,
		// especially when mutation has no available base program. Fall back to a fresh
		// generation request instead of panicking the whole manager.
		if req = genProgRequest(fuzzer, fuzzer.rand()); fuzzer.shouldScheduleProgram(req) {
			fuzzer.prepare(req, 0, 0)
			return req
		}
		if tries >= 16 {
			return nil
		}
	}
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...any) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

func (fuzzer *Fuzzer) logTriageCall(p *prog.Prog, call int, info *flatrpc.CallInfo, prio uint8, newSignal int) {
	if !fuzzer.triageDiagnosticsEnabled() || info == nil {
		return
	}
	fuzzer.Logf(0, "triage: call=%d name=%s signal=%d cover=%d prio=%d new=%d errno=%d flags=0x%x",
		call, p.CallName(call), len(info.Signal), len(info.Cover), prio, newSignal, info.Error, uint8(info.Flags))
}

func (fuzzer *Fuzzer) logTriageJobQueued(origin, traceID string, calls []string, flags ProgFlags, attempt int, status queue.Status) {
	if !fuzzer.triageDiagnosticsEnabled() {
		return
	}
	trace := ""
	if traceID != "" {
		trace = fmt.Sprintf(" trace=%s", traceID)
	}
	fuzzer.Logf(0, "triage job queued: origin=%s%s calls=[%s] flags=0x%x attempt=%d status=%s",
		origin, trace, strings.Join(calls, " "), flags, attempt, status)
}

func (fuzzer *Fuzzer) triageDiagnosticsEnabled() bool {
	if fuzzer == nil {
		return false
	}
	if fuzzer.Config != nil && fuzzer.Config.TriageDiagnostics {
		return true
	}
	return fuzzer.target != nil && fuzzer.target.RuntimePolicy.TriageDiagnostics
}

type ProgFlags int

const (
	// The candidate was loaded from our local corpus rather than come from hub.
	ProgFromCorpus ProgFlags = 1 << iota
	ProgMinimized
	ProgSmashed
	ProgFromSeed

	progCandidate
	progInTriage
)

type Candidate struct {
	Prog  *prog.Prog
	Flags ProgFlags
}

type CorpusSaveEvent struct {
	Origin          string
	TraceID         string
	Call            int
	CallName        string
	StableSignal    int
	NewStableSignal int
	Cover           int
	RawCover        int
}

func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	accepted := 0
	for _, candidate := range candidates {
		origin := "candidate"
		if candidate.Flags&ProgFromSeed != 0 {
			origin = "seed"
		}
		req := &queue.Request{
			Prog:       candidate.Prog,
			ExecOpts:   setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:       fuzzer.statExecCandidate,
			Origin:     origin,
			TraceID:    fuzzer.nextTraceID(origin),
			Important:  true,
			NoPrefetch: true,
		}
		if !fuzzer.shouldScheduleProgram(req) {
			continue
		}
		accepted++
		fuzzer.enqueue(fuzzer.candidateQueue, req, candidate.Flags|progCandidate, 0)
	}
	fuzzer.statCandidates.Add(accepted)
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return rand.New(rand.NewSource(fuzzer.rnd.Int63()))
}

func (fuzzer *Fuzzer) updateChoiceTable(programs []*prog.Prog) {
	newCt := fuzzer.target.BuildChoiceTableWithNoDirectCalls(programs,
		fuzzer.Config.EnabledCalls, fuzzer.Config.NoGenerateCalls)

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	if len(programs) >= fuzzer.ctProgs {
		fuzzer.ctProgs = len(programs)
		fuzzer.ct = newCt
	}
}

func (fuzzer *Fuzzer) choiceTableUpdater() {
	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case <-fuzzer.ctRegenerate:
		}
		fuzzer.updateChoiceTable(fuzzer.Config.Corpus.AllPrograms())
	}
}

func (fuzzer *Fuzzer) ChoiceTable() *prog.ChoiceTable {
	progs := fuzzer.Config.Corpus.AllPrograms()

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()

	// There were no deep ideas nor any calculations behind these numbers.
	regenerateEveryProgs := 333
	if len(progs) < 100 {
		regenerateEveryProgs = 33
	}
	if fuzzer.ctProgs+regenerateEveryProgs < len(progs) {
		select {
		case fuzzer.ctRegenerate <- struct{}{}:
		default:
			// We're okay to lose the message.
			// It means that we're already regenerating the table.
		}
	}
	return fuzzer.ct
}

func (fuzzer *Fuzzer) RunningJobs() []*JobInfo {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()

	var ret []*JobInfo
	for item := range fuzzer.runningJobs {
		ret = append(ret, item.getInfo())
	}
	return ret
}

func (fuzzer *Fuzzer) logCurrentStats() {
	for {
		select {
		case <-time.After(time.Minute):
		case <-fuzzer.ctx.Done():
			return
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		str := fmt.Sprintf("running jobs: %d, heap (MB): %d",
			fuzzer.statJobs.Val(), m.Alloc/1000/1000)
		fuzzer.Logf(0, "%s", str)
	}
}

func setFlags(execFlags flatrpc.ExecFlag) flatrpc.ExecOpts {
	/* Always include ExecFlagThreaded so the executor uses per-syscall
	 * timeout (event_timedwait) even for blocking syscalls.  Without
	 * Threaded, a blocking syscall hangs the whole program and only the
	 * QEMU watchdog (hard timeout) can break it. */
	return flatrpc.ExecOpts{
		ExecFlags: execFlags | flatrpc.ExecFlagThreaded,
	}
}

// TODO: This method belongs better to pkg/flatrpc, but we currently end up
// having a cyclic dependency error.
func DefaultExecOpts(cfg *mgrconfig.Config, features flatrpc.Feature, debug bool) flatrpc.ExecOpts {
	env := csource.FeaturesToFlags(features, nil)
	if debug {
		env |= flatrpc.ExecEnvDebug
	}
	if cfg.Experimental.ResetAccState {
		env |= flatrpc.ExecEnvResetState
	}
	if cfg.Cover {
		env |= flatrpc.ExecEnvSignal
	}
	sandbox, err := flatrpc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := flatrpc.ExecFlagThreaded
	if !cfg.RawCover {
		exec |= flatrpc.ExecFlagDedupCover
	}
	return flatrpc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: cfg.SandboxArg,
	}
}

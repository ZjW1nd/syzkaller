// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Contains prog transformations that intend to trigger more races.

package prog

import (
	"fmt"
	"math/rand"
)

// The executor has no more than 32 threads that are used both for async calls and for calls
// that timed out. If we just ignore that limit, we could end up generating programs that
// would force the executor to fail and thus stall the fuzzing process.
// As an educated guess, let's use no more than 24 async calls to let executor handle everything.
const maxAsyncPerProg = 24

// Ensures that if an async call produces a resource, then
// it is distanced from a call consuming the resource at least
// by one non-async call.
// This does not give 100% guarantee that the async call finishes
// by that time, but hopefully this is enough for most cases.
func AssignRandomAsync(origProg *Prog, rand *rand.Rand) *Prog {
	var unassigned map[*ResultArg]bool
	leftAsync := maxAsyncPerProg
	prog := origProg.Clone()
	preferred := make(map[int]bool)
	preferredIdx, thresholdBlocked := preferredCollideIndices(prog.Calls, prog.Target)
	if thresholdBlocked {
		return prog
	}
	for _, idx := range preferredIdx {
		preferred[idx] = true
	}
	usePreferred := len(preferred) != 0
	for i := len(prog.Calls) - 1; i >= 0; i-- {
		call := prog.Calls[i]
		producesUnassigned := false
		consumes := make(map[*ResultArg]bool)
		ForeachArg(call, func(arg Arg, ctx *ArgCtx) {
			res, ok := arg.(*ResultArg)
			if !ok {
				return
			}
			if res.Dir() != DirIn && unassigned[res] {
				// If this call is made async, at least one of the resources
				// will be empty when it's needed.
				producesUnassigned = true
			}
			if res.Dir() != DirOut {
				consumes[res.Res] = true
			}
		})
		if callRequiresAsync(prog.Calls, prog.Target, i) {
			call.Props.Async = true
			for res := range consumes {
				unassigned[res] = true
			}
			if leftAsync > 0 {
				leftAsync--
			}
			continue
		}
		forceSync := prog.Target.Helpers.AvoidCollidingAutomaticHelpers && prog.Target.CallIsAutomaticHelper(call.Meta)
		if usePreferred && !preferred[i] {
			forceSync = true
		}
		if !canAsyncCollideCall(prog.Calls, prog.Target, i) {
			forceSync = true
		}
		// Make async with a 66% chance (but never the last call).
		if leftAsync > 0 && !forceSync && !producesUnassigned && i+1 != len(prog.Calls) && rand.Intn(3) != 0 {
			call.Props.Async = true
			for res := range consumes {
				unassigned[res] = true
			}
			leftAsync--
		} else {
			call.Props.Async = false
			unassigned = consumes
		}
	}
	if usePreferred {
		anyAsync := false
		for _, call := range prog.Calls {
			if call.Props.Async {
				anyAsync = true
				break
			}
		}
		if !anyAsync {
			for i := len(prog.Calls) - 1; i >= 0; i-- {
				if !preferred[i] || i+1 == len(prog.Calls) ||
					!canAsyncCollideCall(prog.Calls, prog.Target, i) {
					continue
				}
				prog.Calls[i].Props.Async = true
				break
			}
		}
	}

	return prog
}

var rerunSteps = []int{32, 64}

func preferredCollideIndices(calls []*Call, target *Target) ([]int, bool) {
	if target != nil && target.SelectCollideCallIndices != nil {
		return target.SelectCollideCallIndices(calls)
	}
	if target != nil {
		return SelectResourceLineageCollideCallIndices(target, calls)
	}
	return nil, false
}

func canAsyncCollideCall(calls []*Call, target *Target, idx int) bool {
	if idx < 0 || idx >= len(calls) {
		return false
	}
	if calls[idx] == nil || calls[idx].Meta == nil {
		return false
	}
	if target == nil || target.AllowAsyncCollideCall == nil {
		return true
	}
	return target.AllowAsyncCollideCall(calls, idx)
}

func callRequiresAsync(calls []*Call, target *Target, idx int) bool {
	if idx < 0 || idx >= len(calls) {
		return false
	}
	if calls[idx] == nil || calls[idx].Meta == nil {
		return false
	}
	if target == nil || target.CallRequiresAsync == nil {
		return false
	}
	return target.CallRequiresAsync(calls, idx)
}

// SanitizeCollidePropsForTarget clears async/rerun properties that the target
// no longer allows. It returns the original program when no changes are needed.
func SanitizeCollidePropsForTarget(p *Prog) (*Prog, bool) {
	if p == nil || p.Target == nil ||
		p.Target.AllowAsyncCollideCall == nil && p.Target.CallRequiresAsync == nil {
		return p, false
	}
	needsSanitize := false
	for i, call := range p.Calls {
		if call == nil {
			continue
		}
		requiresAsync := callRequiresAsync(p.Calls, p.Target, i)
		if requiresAsync && !call.Props.Async {
			needsSanitize = true
			break
		}
		if call.Props.Async && !requiresAsync && !canAsyncCollideCall(p.Calls, p.Target, i) {
			needsSanitize = true
			break
		}
		if call.Props.Rerun != 0 && !canAsyncCollideCall(p.Calls, p.Target, i) {
			needsSanitize = true
			break
		}
	}
	if !needsSanitize {
		return p, false
	}
	clone := p.Clone()
	allowedRerun := make(map[int]bool)
	for i, call := range clone.Calls {
		if call == nil {
			continue
		}
		if callRequiresAsync(clone.Calls, clone.Target, i) {
			call.Props.Async = true
			continue
		}
		if !call.Props.Async || canAsyncCollideCall(clone.Calls, clone.Target, i) {
			continue
		}
		call.Props.Async = false
		call.Props.Rerun = 0
	}
	for i := 0; i+1 < len(clone.Calls); i++ {
		call := clone.Calls[i]
		if call == nil || !call.Props.Async || call.Props.Rerun == 0 ||
			!canAsyncCollideCall(clone.Calls, clone.Target, i) {
			continue
		}
		if next := clone.Calls[i+1]; next != nil && next.Props.Rerun == call.Props.Rerun {
			allowedRerun[i] = true
			allowedRerun[i+1] = true
		}
	}
	for i, call := range clone.Calls {
		if call != nil && call.Props.Rerun != 0 && !allowedRerun[i] {
			call.Props.Rerun = 0
		}
	}
	return clone, true
}

func AssignRandomRerun(prog *Prog, rand *rand.Rand) {
	preferred := make(map[int]bool)
	preferredIdx, thresholdBlocked := preferredCollideIndices(prog.Calls, prog.Target)
	if thresholdBlocked {
		return
	}
	for _, idx := range preferredIdx {
		preferred[idx] = true
	}
	usePreferred := len(preferred) != 0
	for i := 0; i+1 < len(prog.Calls); i++ {
		if !prog.Calls[i].Props.Async {
			continue
		}
		if usePreferred && !preferred[i] {
			continue
		}
		if !canAsyncCollideCall(prog.Calls, prog.Target, i) {
			continue
		}
		if rand.Intn(4) != 0 {
			continue
		}
		// We assign rerun to consecutive pairs of calls, where the first call is async.
		// TODO: consider assigning rerun also to non-collided progs.
		rerun := rerunSteps[rand.Intn(len(rerunSteps))]
		prog.Calls[i].Props.Rerun = rerun
		prog.Calls[i+1].Props.Rerun = rerun
		i++
	}
}

// We append prog to itself, but let the second part only reference resource from the first one.
// Then we execute all the duplicated calls simultaneously.
// This somehow resembles the way the previous collide mode was implemented - a program was executed
// normally and then one more time again, while keeping resource values from the first execution and
// not waiting until every other call finishes.
func DoubleExecCollide(origProg *Prog, rand *rand.Rand) (*Prog, error) {
	if len(origProg.Calls)*2 > MaxCalls {
		return nil, fmt.Errorf("the prog is too big for the DoubleExecCollide transformation")
	}
	prog := origProg.Clone()
	dupCalls := cloneCalls(prog.Calls, nil)
	leftAsync := maxAsyncPerProg
	preferred, thresholdBlocked := preferredCollideIndices(dupCalls, prog.Target)
	if thresholdBlocked {
		return nil, fmt.Errorf("no sufficiently relevant calls for double-exec collide")
	}
	for _, idx := range preferred {
		if leftAsync == 0 {
			break
		}
		if !canAsyncCollideCall(dupCalls, prog.Target, idx) {
			continue
		}
		dupCalls[idx].Props.Async = true
		leftAsync--
	}
	if len(preferred) != 0 && leftAsync == maxAsyncPerProg {
		return nil, fmt.Errorf("no target-allowed calls for double-exec collide")
	}
	if leftAsync == maxAsyncPerProg {
		for idx, c := range dupCalls {
			if leftAsync == 0 {
				break
			}
			if prog.Target.Helpers.AvoidCollidingAutomaticHelpers && prog.Target.CallIsAutomaticHelper(c.Meta) {
				continue
			}
			if !canAsyncCollideCall(dupCalls, prog.Target, idx) {
				continue
			}
			c.Props.Async = true
			leftAsync--
		}
	}
	if leftAsync == maxAsyncPerProg {
		return nil, fmt.Errorf("no target-allowed calls for double-exec collide")
	}
	prog.Calls = append(prog.Calls, dupCalls...)
	return prog, nil
}

// DupCallCollide duplicates some of the calls in the program and marks them async.
// This should hopefully trigger races in a more granular way than DoubleExecCollide.
func DupCallCollide(origProg *Prog, rand *rand.Rand) (*Prog, error) {
	if len(origProg.Calls) < 2 {
		// For 1-call programs the behavior is similar to DoubleExecCollide.
		return nil, fmt.Errorf("the prog is too small for the transformation")
	}
	// By default let's duplicate 1/3 calls in the original program (but at least one).
	insert := max(len(origProg.Calls)/3, 1)
	insert = min(insert, maxAsyncPerProg)
	insert = min(insert, MaxCalls-len(origProg.Calls))
	if insert == 0 {
		return nil, fmt.Errorf("no calls could be duplicated")
	}
	candidates := make([]int, 0, len(origProg.Calls))
	for i, c := range origProg.Calls {
		if origProg.Target.Helpers.AvoidCollidingAutomaticHelpers && origProg.Target.CallIsAutomaticHelper(c.Meta) {
			continue
		}
		candidates = append(candidates, i)
	}
	if len(candidates) == 0 {
		for i := range origProg.Calls {
			candidates = append(candidates, i)
		}
	}
	if preferred, thresholdBlocked := preferredCollideIndices(origProg.Calls, origProg.Target); len(preferred) != 0 {
		candidates = preferred
	} else if thresholdBlocked {
		return nil, fmt.Errorf("no sufficiently relevant calls for duplicate-collide")
	}
	filtered := candidates[:0]
	for _, idx := range candidates {
		if canAsyncCollideCall(origProg.Calls, origProg.Target, idx) {
			filtered = append(filtered, idx)
		}
	}
	candidates = filtered
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no target-allowed calls for duplicate-collide")
	}
	insert = min(insert, len(candidates))
	duplicate := map[int]bool{}
	for _, idx := range rand.Perm(len(candidates))[:insert] {
		pos := candidates[idx]
		duplicate[pos] = true
	}
	prog := origProg.Clone()
	var retCalls []*Call
	for i, c := range prog.Calls {
		if duplicate[i] {
			dupCall := cloneCall(c, nil)
			dupCall.Props.Async = true
			retCalls = append(retCalls, dupCall)
		}
		retCalls = append(retCalls, c)
	}
	prog.Calls = retCalls
	return prog, nil
}

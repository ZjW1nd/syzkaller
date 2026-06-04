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
	for i := len(prog.Calls) - 1; i >= 0 && leftAsync > 0; i-- {
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
		forceSync := prog.Target.Helpers.AvoidCollidingAutomaticHelpers && prog.Target.CallIsAutomaticHelper(call.Meta)
		if usePreferred && !preferred[i] {
			forceSync = true
		}
		// Make async with a 66% chance (but never the last call).
		if !forceSync && !producesUnassigned && i+1 != len(prog.Calls) && rand.Intn(3) != 0 {
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
				if !preferred[i] || i+1 == len(prog.Calls) {
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
		dupCalls[idx].Props.Async = true
		leftAsync--
	}
	if leftAsync == maxAsyncPerProg {
		for _, c := range dupCalls {
			if leftAsync == 0 {
				break
			}
			if prog.Target.Helpers.AvoidCollidingAutomaticHelpers && prog.Target.CallIsAutomaticHelper(c.Meta) {
				continue
			}
			c.Props.Async = true
			leftAsync--
		}
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

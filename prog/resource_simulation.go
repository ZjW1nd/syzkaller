// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
)

type ResourceSimulationFailure struct {
	Call     int
	Syscall  string
	Resource string
	Reason   string
}

func (f ResourceSimulationFailure) String() string {
	if f.Resource != "" {
		return fmt.Sprintf("call %d %s resource %s: %s", f.Call, f.Syscall, f.Resource, f.Reason)
	}
	return fmt.Sprintf("call %d %s: %s", f.Call, f.Syscall, f.Reason)
}

type CallResourceSimulation struct {
	Constructed        *Prog
	Reused             *Prog
	ConstructFailures  []ResourceSimulationFailure
	ReuseFailures      []ResourceSimulationFailure
	ConstructedCallCnt int
	ReusedCallCnt      int
}

func (sim *CallResourceSimulation) Valid() bool {
	return sim != nil && len(sim.ConstructFailures) == 0 && len(sim.ReuseFailures) == 0
}

func (sim *CallResourceSimulation) Failures() []ResourceSimulationFailure {
	if sim == nil {
		return nil
	}
	failures := append([]ResourceSimulationFailure{}, sim.ConstructFailures...)
	failures = append(failures, sim.ReuseFailures...)
	return failures
}

func (target *Target) SimulateCallResourceUse(meta *Syscall, enabled map[*Syscall]bool) (*CallResourceSimulation, error) {
	if target == nil {
		return nil, fmt.Errorf("nil target")
	}
	if meta == nil {
		return nil, fmt.Errorf("nil syscall")
	}
	ct := target.simulationChoiceTable(meta, enabled)
	sim := &CallResourceSimulation{}

	constructed, constructedCallCnt, err := target.generateSimulatedResourceCall(nil, 0, meta, ct,
		resourceGenerationConstruct)
	if err != nil {
		return nil, err
	}
	sim.Constructed = constructed
	sim.ConstructedCallCnt = constructedCallCnt
	sim.ConstructFailures = validateResourceSimulation(constructed, 0, len(constructed.Calls))
	if len(constructed.Calls) == 0 {
		return sim, nil
	}

	prefix := &Prog{
		Target: target,
		Calls:  append([]*Call{}, constructed.Calls[:len(constructed.Calls)-1]...),
	}
	reused, reusedCallCnt, err := target.generateSimulatedResourceCall(prefix, len(prefix.Calls), meta, ct,
		resourceGenerationReuse)
	if err != nil {
		return nil, err
	}
	sim.Reused = reused
	sim.ReusedCallCnt = reusedCallCnt
	if reusedCallCnt != 1 {
		sim.ReuseFailures = append(sim.ReuseFailures, ResourceSimulationFailure{
			Call:    len(prefix.Calls),
			Syscall: meta.Name,
			Reason:  fmt.Sprintf("reuse generated %d setup calls", reusedCallCnt-1),
		})
	}
	sim.ReuseFailures = append(sim.ReuseFailures,
		validateResourceSimulation(reused, len(reused.Calls)-1, len(reused.Calls))...)
	return sim, nil
}

func (target *Target) simulationChoiceTable(meta *Syscall, enabled map[*Syscall]bool) *ChoiceTable {
	if enabled == nil {
		enabled = make(map[*Syscall]bool, len(target.Syscalls))
		for _, call := range target.Syscalls {
			if call != nil && !call.Attrs.Disabled {
				enabled[call] = true
			}
		}
	} else {
		clone := make(map[*Syscall]bool, len(enabled)+1)
		for call, on := range enabled {
			clone[call] = on
		}
		enabled = clone
	}
	enabled[meta] = true
	if target.ExpandEnabledCalls != nil {
		enabled = target.ExpandEnabledCalls(target, enabled)
	}
	return target.BuildChoiceTable(nil, enabled)
}

func (target *Target) generateSimulatedResourceCall(prefix *Prog, insertionPoint int, meta *Syscall,
	ct *ChoiceTable, mode resourceGenerationMode) (p *Prog, insertedCalls int, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("simulate %v resources for %s: %v", mode, meta.Name, r)
		}
	}()
	if prefix == nil {
		prefix = &Prog{Target: target}
	}
	if prefix.Target == nil {
		prefix = &Prog{Target: target, Calls: prefix.Calls, Comments: prefix.Comments}
	}
	if insertionPoint < 0 || insertionPoint > len(prefix.Calls) {
		insertionPoint = len(prefix.Calls)
	}
	state := newState(target, ct, nil)
	for _, call := range prefix.Calls[:insertionPoint] {
		state.analyze(call)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentProg = prefix
	r.currentInsertionPoint = insertionPoint
	r.resourceMode = mode
	calls := r.generateParticularCallUnsafe(state, meta)
	p = &Prog{Target: target}
	p.Calls = append(p.Calls, prefix.Calls[:insertionPoint]...)
	p.Calls = append(p.Calls, calls...)
	p.Calls = append(p.Calls, prefix.Calls[insertionPoint:]...)
	return p, len(calls), nil
}

func validateResourceSimulation(p *Prog, from, to int) []ResourceSimulationFailure {
	if p == nil {
		return []ResourceSimulationFailure{{
			Call:   -1,
			Reason: "nil program",
		}}
	}
	if from < 0 {
		from = 0
	}
	if to > len(p.Calls) {
		to = len(p.Calls)
	}
	producers := make(map[*ResultArg]int)
	var failures []ResourceSimulationFailure
	for idx, call := range p.Calls[:to] {
		if call == nil || call.Meta == nil {
			continue
		}
		if idx >= from {
			ForeachArg(call, func(arg Arg, _ *ArgCtx) {
				typ, ok := arg.Type().(*ResourceType)
				if !ok {
					return
				}
				res := arg.(*ResultArg)
				if res.Dir() == DirOut {
					return
				}
				if res.Res == nil {
					if !typ.Optional() {
						failures = append(failures, ResourceSimulationFailure{
							Call:     idx,
							Syscall:  call.Meta.Name,
							Resource: typ.Desc.Name,
							Reason:   "default resource",
						})
					}
					return
				}
				if producer, ok := producers[res.Res]; !ok || producer >= idx {
					failures = append(failures, ResourceSimulationFailure{
						Call:     idx,
						Syscall:  call.Meta.Name,
						Resource: typ.Desc.Name,
						Reason:   "resource has no prior producer",
					})
				}
			})
		}
		ForeachArg(call, func(arg Arg, _ *ArgCtx) {
			if _, ok := arg.Type().(*ResourceType); !ok {
				return
			}
			res := arg.(*ResultArg)
			if res.Dir() != DirIn {
				producers[res] = idx
			}
		})
	}
	return failures
}

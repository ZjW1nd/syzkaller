// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package windows

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
)

const windowsTargetProfileAFD = "afd"

func applyWindowsTargetProfile(target *prog.Target, profile string) (*prog.Target, error) {
	if target == nil {
		return nil, fmt.Errorf("windows target profile %q requires a target", profile)
	}
	switch profile {
	case "", "default":
		return target, nil
	case windowsTargetProfileAFD:
		clone := target.Clone()
		clone.MinimumHintsCallRelevance = 4
		clone.MinimumTriageCallRelevance = 4
		clone.MinimumCollideCallRelevance = 4
		clone.MinimumMutationCallRelevance = 4
		clone.Bias.MinimumGenerationBiasCallRelevance = 3
		clone.SelectCollideCallIndices = func(calls []*prog.Call) ([]int, bool) {
			return prog.SelectResourceLineageCollideCallIndices(clone, calls)
		}
		clone.RuntimePolicy = windowsRuntimePolicy(
			prog.FocusedResourceRuntimePolicy(clone, clone.MinimumCollideCallRelevance))
		return clone, nil
	default:
		return nil, fmt.Errorf("unknown windows target profile %q", profile)
	}
}

func configureWindowsHelpers(target *prog.Target) {
	target.Helpers.DeprioritizeAutomaticHelpers = true
	target.Helpers.NoGenerateAutomaticHelpers = true
	target.Helpers.AvoidCollidingAutomaticHelpers = true
	target.Helpers.SkipHintsForAutomaticHelpers = true
	target.Helpers.NoMutateAutomaticHelpers = true
	target.Helpers.SkipCorpusForAutomaticHelpers = true
	target.Helpers.SkipTriageForAutomaticHelpers = true
	target.Helpers.AvoidAutomaticHelperBias = true
}

func windowsCallRelevanceScore(call *prog.Syscall) int {
	return prog.ResourceDepthCallScore(nil, call)
}

func expandWindowsEnabledCalls(target *prog.Target, enabled map[*prog.Syscall]bool) map[*prog.Syscall]bool {
	expanded := prog.ExpandEnabledResourceCtors(target, enabled)
	if windowsProgramNeedsWSAStartup(expanded) {
		if startup := target.SyscallMap["WSAStartup"]; startup != nil {
			expanded[startup] = true
		}
	}
	return expanded
}

func windowsSelectGeneratedCall(p *prog.Prog, insertionPoint int, biasCall int, ct *prog.ChoiceTable) int {
	if p == nil || p.Target == nil || insertionPoint != 0 {
		return -1
	}
	startup := p.Target.SyscallMap["WSAStartup"]
	if startup == nil || !ct.Generatable(startup.ID) {
		return -1
	}
	return startup.ID
}

func windowsRuntimePolicy(base prog.RuntimePolicy) prog.RuntimePolicy {
	prev := base.ShouldScheduleProgram
	base.ShouldScheduleProgram = func(origin string, p *prog.Prog) bool {
		if !windowsHasValidWinsockStartupOrder(p) {
			return false
		}
		if prev != nil {
			return prev(origin, p)
		}
		return true
	}
	return base
}

func windowsProgramNeedsWSAStartup(calls map[*prog.Syscall]bool) bool {
	for call := range calls {
		if windowsCallNeedsWSAStartup(call) {
			return true
		}
	}
	return false
}

func windowsHasValidWinsockStartupOrder(p *prog.Prog) bool {
	if p == nil {
		return true
	}
	started := false
	for _, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		if call.Meta.Name == "WSAStartup" {
			started = true
			continue
		}
		if windowsCallNeedsWSAStartup(call.Meta) && !started {
			return false
		}
	}
	return true
}

func windowsCallNeedsWSAStartup(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	switch call.Name {
	case "WSAStartup", "WSACleanup":
		return false
	}
	if strings.HasPrefix(call.Name, "WSA") || strings.HasPrefix(call.Name, "socket$") {
		return true
	}
	needsStartup := false
	prog.ForeachCallType(call, func(typ prog.Type, ctx *prog.TypeCtx) {
		res, ok := typ.(*prog.ResourceType)
		if !ok {
			return
		}
		if strings.Contains(res.Desc.Name, "SOCKET") || strings.HasPrefix(res.Desc.Name, "WSA") {
			needsStartup = true
			ctx.Stop = true
		}
	})
	return needsStartup
}

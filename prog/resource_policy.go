// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"slices"
	"strings"
)

const (
	resourceUseDepthScale        = 10
	resourceReuseProducerBonus   = 20
	resourceReuseConsumerBonus   = 5
	resourceReuseExactBonus      = 40
	resourceCtorInputPenalty     = 4
	resourceCtorImprecisePenalty = 8
	resourceCtorSubtypePenalty   = 16
	resourceCtorTransitionBonus  = 16
	resourceCtorHelperBonus      = 4
	resourceCtorStateDepth       = 3
)

// ExpandEnabledResourceCtors closes an enabled syscall set over precise resource
// constructors. This is intentionally target-agnostic: the syzlang resource graph
// is the source of truth for which helpers/constructors are needed.
func ExpandEnabledResourceCtors(target *Target, enabled map[*Syscall]bool) map[*Syscall]bool {
	if target == nil || len(enabled) == 0 {
		return enabled
	}
	expanded := cloneCallSet(enabled)
	for {
		changed := false
		for call := range cloneCallSet(expanded) {
			for _, res := range call.inputResources {
				ctors := target.resourceCtorsForExpansion(res)
				if best := selectResourceCtorByDepth(call, res.Name, ctors, true); best != nil &&
					!best.Attrs.Disabled && !expanded[best] {
					expanded[best] = true
					changed = true
				}
				for _, ctor := range ctors {
					if !resourceCtorAddsStateTransition(res.Name, ctors, ctor) ||
						ctor.Call.Attrs.Disabled || expanded[ctor.Call] {
						continue
					}
					expanded[ctor.Call] = true
					changed = true
				}
			}
		}
		if !changed {
			return expanded
		}
	}
}

func (target *Target) resourceCtorsForExpansion(res *ResourceDesc) []ResourceCtor {
	ctors := target.calcResourceCtors(res, false)
	ctors = append(ctors, res.seedCtors...)
	return ctors
}

func cloneCallSet(calls map[*Syscall]bool) map[*Syscall]bool {
	clone := make(map[*Syscall]bool, len(calls))
	for call, on := range calls {
		if on {
			clone[call] = true
		}
	}
	return clone
}

// ResourceDepthCallScore scores calls by the depth of required resource states
// in their input resource kinds. Helper calls are negative when the target marks
// them as automatic helpers.
func ResourceDepthCallScore(target *Target, call *Syscall) int {
	if call == nil {
		return 0
	}
	if call.Attrs.AutomaticHelper || target != nil && target.CallIsAutomaticHelper(call) {
		return -1
	}
	depth := callInputResourceDepth(call)
	if depth == 0 {
		return 1
	}
	if len(call.createsResources) != 0 || len(call.seedCreatesResources) != 0 {
		return max(depth, 1)
	}
	if len(call.createsResources) == 0 && len(call.seedCreatesResources) == 0 {
		return depth + 1
	}
	return depth
}

// ResourceDepthUseScore gives deeper resource consumers more weight in analysis
// and corpus borrowing. Constructors without input resources naturally score 0.
func ResourceDepthUseScore(call *Syscall) int {
	if call == nil {
		return 0
	}
	return callInputResourceDepth(call) * resourceUseDepthScale
}

func callInputResourceDepth(call *Syscall) int {
	depth := 0
	for _, res := range call.inputResources {
		depth = max(depth, resourceKindDepth(res))
	}
	return depth
}

func resourceKindDepth(res *ResourceDesc) int {
	if res == nil {
		return 0
	}
	return len(res.Kind)
}

// SelectResourceCtorByDepth chooses the most precise constructor whose own input
// chain is shortest. This favors syzlang's state-transition constructors over
// broad compatibility helpers without naming any target-specific calls.
func SelectResourceCtorByDepth(current *Syscall, resourceType string, ctors []ResourceCtor) *Syscall {
	return selectResourceCtorByDepth(current, resourceType, ctors, false)
}

func selectResourceCtorByDepth(current *Syscall, resourceType string, ctors []ResourceCtor, allowNoGenerate bool) *Syscall {
	var best *Syscall
	bestScore := 0
	for _, ctor := range ctors {
		if ctor.Call == nil {
			continue
		}
		if ctor.Call.Attrs.NoGenerate && !allowNoGenerate {
			continue
		}
		if resourceCtorNeedsResource(ctor.Call, resourceType) {
			continue
		}
		score := callInputResourceDepth(ctor.Call) + len(ctor.Call.inputResources)*resourceCtorInputPenalty
		if !ctor.Precise {
			score += resourceCtorImprecisePenalty
		}
		if !resourceCtorCreatesExact(ctor.Call, resourceType) {
			score += resourceCtorSubtypePenalty
		}
		if resourceCtorIsExactStateTransition(resourceType, ctors, ctor) {
			score -= resourceCtorTransitionBonus
		}
		if ctor.Call.Attrs.AutomaticHelper {
			score -= resourceCtorHelperBonus
		}
		if best == nil || score < bestScore {
			best = ctor.Call
			bestScore = score
		}
	}
	return best
}

func resourceCtorAddsStateTransition(resourceType string, ctors []ResourceCtor, ctor ResourceCtor) bool {
	if ctor.Call == nil || ctor.Call.Attrs.AutomaticHelper ||
		resourceKindDepthFromCtors(resourceType, ctors) < resourceCtorStateDepth ||
		callInputResourceDepth(ctor.Call) == 0 ||
		resourceCtorNeedsResource(ctor.Call, resourceType) {
		return false
	}
	return resourceCtorCreatesExact(ctor.Call, resourceType) ||
		resourceCtorCreatesParent(ctor.Call, resourceType, ctors)
}

func resourceCtorIsExactStateTransition(resourceType string, ctors []ResourceCtor, ctor ResourceCtor) bool {
	return resourceCtorAddsStateTransition(resourceType, ctors, ctor) &&
		resourceCtorCreatesExact(ctor.Call, resourceType)
}

func resourceKindDepthFromCtors(resourceType string, ctors []ResourceCtor) int {
	for _, ctor := range ctors {
		if res := resourceCtorExactResource(ctor.Call, resourceType); res != nil {
			return resourceKindDepth(res)
		}
	}
	return 0
}

func resourceCtorCreatesExact(call *Syscall, resourceType string) bool {
	return resourceCtorExactResource(call, resourceType) != nil
}

func resourceCtorExactResource(call *Syscall, resourceType string) *ResourceDesc {
	if call == nil {
		return nil
	}
	for _, res := range call.createsResources {
		if res.Name == resourceType {
			return res
		}
	}
	for _, res := range call.seedCreatesResources {
		if res.Name == resourceType {
			return res
		}
	}
	return nil
}

func resourceCtorCreatesParent(call *Syscall, resourceType string, ctors []ResourceCtor) bool {
	requested := resourceKindFromCtors(resourceType, ctors)
	if call == nil || len(requested) == 0 {
		return false
	}
	for _, res := range append(call.createsResources, call.seedCreatesResources...) {
		if len(res.Kind) >= len(requested) {
			continue
		}
		if resourceKindHasPrefix(requested, res.Kind) {
			return true
		}
	}
	return false
}

func resourceKindFromCtors(resourceType string, ctors []ResourceCtor) []string {
	for _, ctor := range ctors {
		if res := resourceCtorExactResource(ctor.Call, resourceType); res != nil {
			return res.Kind
		}
	}
	return nil
}

func resourceKindHasPrefix(kind, prefix []string) bool {
	if len(prefix) > len(kind) {
		return false
	}
	for i, part := range prefix {
		if kind[i] != part {
			return false
		}
	}
	return true
}

func resourceCtorNeedsResource(call *Syscall, resourceType string) bool {
	if call == nil {
		return false
	}
	for _, input := range call.inputResources {
		if input.Name == resourceType {
			return true
		}
	}
	return false
}

// ResourceLineageReuseScore prefers resources produced by deeper state-transition
// calls when they are compatible with the current call's resource inputs.
func ResourceLineageReuseScore(current *Syscall, candidate *ResultArg, p *Prog, insertionPoint int) int {
	if current == nil || candidate == nil {
		return 0
	}
	if !callAcceptsResultResource(current, candidate) {
		return 0
	}
	candidateDepth := resourceKindDepth(resultArgResourceDesc(candidate))
	currentUse := ResourceDepthUseScore(current)
	score := candidateDepth*resourceReuseProducerBonus + currentUse/resourceReuseConsumerBonus
	if producer := ResourceReturnProducer(candidate, p, insertionPoint); producer != nil {
		score += ResourceDepthUseScore(producer)
	}
	if callAcceptsExactResultResource(current, candidate) {
		score += resourceReuseExactBonus
	}
	return score
}

// CorpusResourceLineageScore is the corpus-borrowing equivalent of
// ResourceLineageReuseScore, with a small bonus for corpus resources whose
// producer has already been consumed by deeper calls in that corpus program.
func CorpusResourceLineageScore(current *Syscall, candidate *ResultArg, p *Prog, insertionPoint int, corpusProg *Prog) int {
	if corpusProg == nil {
		return ResourceLineageReuseScore(current, candidate, p, insertionPoint)
	}
	score := ResourceLineageReuseScore(current, candidate, corpusProg, len(corpusProg.Calls))
	if score == 0 {
		return 0
	}
	return score + corpusResourceUseScore(candidate, corpusProg)
}

func corpusResourceUseScore(candidate *ResultArg, p *Prog) int {
	best := 0
	if candidate == nil || p == nil {
		return best
	}
	for _, call := range p.Calls {
		ForeachArg(call, func(arg Arg, _ *ArgCtx) {
			res, ok := arg.(*ResultArg)
			if !ok || res.Dir() == DirOut || res.Res != candidate {
				return
			}
			best = max(best, ResourceDepthUseScore(call.Meta))
		})
	}
	return best
}

func PreferResourceCentricByDepth(current *Syscall) bool {
	return ResourceDepthUseScore(current) >= resourceUseDepthScale*3
}

// SelectResourceLineageCollideCallIndices selects the most relevant call(s),
// preferring adjacent calls that consume the same resource root when available.
func SelectResourceLineageCollideCallIndices(target *Target, calls []*Call) ([]int, bool) {
	if target == nil {
		return nil, false
	}
	minScore := 0
	minScore = target.MinimumCollideCallRelevance
	bestScore := 0
	hasScored := false
	var indices []int
	for i, call := range calls {
		if call == nil || call.Meta == nil || !callCanOwnResourcePolicy(target, call.Meta) {
			continue
		}
		if !callHasFocusedResourceLineage(calls, i, nil) {
			continue
		}
		score := target.CallRelevance(call.Meta)
		if score > 0 {
			hasScored = true
		}
		if score > bestScore {
			bestScore = score
			indices = indices[:0]
		}
		if score == bestScore {
			indices = append(indices, i)
		}
	}
	blocked := hasScored && minScore > 0 && bestScore < minScore
	if blocked {
		return nil, true
	}
	if len(indices) == 0 && minScore > 0 {
		return nil, true
	}
	if len(indices) > 1 {
		if lineage := SameResourceLineageCallIndices(calls, indices); len(lineage) != 0 {
			return lineage, false
		}
	}
	return indices, false
}

func SameResourceLineageCallIndices(calls []*Call, indices []int) []int {
	preferred := make(map[int]bool, len(indices))
	for _, idx := range indices {
		preferred[idx] = true
	}
	for _, idx := range indices {
		if idx+1 >= len(calls) || !preferred[idx+1] {
			continue
		}
		if CallsShareResourceLineage(calls[idx], calls[idx+1]) {
			return []int{idx}
		}
	}
	return nil
}

func CallsShareResourceLineage(first, second *Call) bool {
	firstResources := inputResourceRoots(first)
	if len(firstResources) == 0 {
		return false
	}
	for resource := range inputResourceRoots(second) {
		if firstResources[resource] {
			return true
		}
	}
	return false
}

func inputResourceRoots(call *Call) map[*ResultArg]bool {
	resources := map[*ResultArg]bool{}
	if call == nil {
		return resources
	}
	ForeachArg(call, func(arg Arg, _ *ArgCtx) {
		res, ok := arg.(*ResultArg)
		if !ok || res.Dir() == DirOut || res.Res == nil {
			return
		}
		resources[res.Res] = true
	})
	return resources
}

func ResourceProducer(candidate *ResultArg, p *Prog, insertionPoint int) *Syscall {
	if producer := ResourceReturnProducer(candidate, p, insertionPoint); producer != nil {
		return producer
	}
	return ResourceOutputProducer(candidate, p, insertionPoint)
}

func ResourceReturnProducer(candidate *ResultArg, p *Prog, insertionPoint int) *Syscall {
	if candidate == nil || p == nil {
		return nil
	}
	limit := len(p.Calls)
	if insertionPoint >= 0 && insertionPoint < limit {
		limit = insertionPoint
	}
	for i := 0; i < limit; i++ {
		call := p.Calls[i]
		if call != nil && call.Ret == candidate {
			return call.Meta
		}
	}
	return nil
}

func resourceProducerCall(candidate *ResultArg, calls []*Call, insertionPoint int) *Call {
	if candidate == nil {
		return nil
	}
	limit := len(calls)
	if insertionPoint >= 0 && insertionPoint < limit {
		limit = insertionPoint
	}
	for i := 0; i < limit; i++ {
		call := calls[i]
		if call != nil && call.Ret == candidate {
			return call
		}
	}
	for i := 0; i < limit; i++ {
		call := calls[i]
		if call == nil || call.Ret == candidate {
			continue
		}
		found := false
		ForeachArg(call, func(arg Arg, ctx *ArgCtx) {
			if found || arg.Dir() != DirOut {
				return
			}
			if arg == candidate {
				found = true
				ctx.Stop = true
			}
		})
		if found {
			return call
		}
	}
	return nil
}

func ResourceOutputProducer(candidate *ResultArg, p *Prog, insertionPoint int) *Syscall {
	if candidate == nil || p == nil {
		return nil
	}
	limit := len(p.Calls)
	if insertionPoint >= 0 && insertionPoint < limit {
		limit = insertionPoint
	}
	for i := 0; i < limit; i++ {
		call := p.Calls[i]
		if call == nil || call.Ret == candidate {
			continue
		}
		found := false
		ForeachArg(call, func(arg Arg, ctx *ArgCtx) {
			if found || arg.Dir() != DirOut {
				return
			}
			if arg == candidate {
				found = true
				ctx.Stop = true
			}
		})
		if found {
			return call.Meta
		}
	}
	return nil
}

func callAcceptsResultResource(call *Syscall, candidate *ResultArg) bool {
	candidateDesc := resultArgResourceDesc(candidate)
	if call == nil || candidateDesc == nil {
		return false
	}
	for _, input := range call.inputResources {
		if isCompatibleResourceImpl(input.Kind, candidateDesc.Kind, false) {
			return true
		}
	}
	return false
}

func callAcceptsExactResultResource(call *Syscall, candidate *ResultArg) bool {
	candidateDesc := resultArgResourceDesc(candidate)
	if call == nil || candidateDesc == nil {
		return false
	}
	for _, input := range call.inputResources {
		if input.Name == candidateDesc.Name {
			return true
		}
	}
	return false
}

func resultArgResourceDesc(arg *ResultArg) *ResourceDesc {
	if arg == nil {
		return nil
	}
	typ, ok := arg.Type().(*ResourceType)
	if !ok {
		return nil
	}
	return typ.Desc
}

// FocusedResourceRuntimePolicy returns generic focused-target runtime gates:
// helper-only/seed-only programs do not own corpus, while deep resource owners
// may be triaged, persisted, and scheduled for collide attempts.
func FocusedResourceRuntimePolicy(target *Target, minOwnerScore int) RuntimePolicy {
	return RuntimePolicy{
		TriageDiagnostics: true,
		PreferCollideProgram: func(p *Prog) bool {
			return ProgramHasResourceOwner(target, p, minOwnerScore)
		},
		ShouldScheduleProgram: func(origin string, p *Prog) bool {
			return ProgramHasResourceOwner(target, p, minOwnerScore) && ProgramHasValidResourceLineage(target, p)
		},
		ShouldScheduleImmediateCollide: func(p *Prog, call int) bool {
			return CallIndexHasResourceOwner(target, p, call, minOwnerScore)
		},
		ShouldForceTriageCall: func(origin string, p *Prog, call int) bool {
			return shouldKeepFocusedResourceOwner(target, origin, p, call, minOwnerScore)
		},
		ShouldSkipTriageProgram: func(origin string, p *Prog) bool {
			return ShouldSkipFocusedResourceProgram(target, p, minOwnerScore)
		},
		ShouldPersistStableTriageCall: func(origin string, p *Prog, call int) bool {
			return shouldKeepFocusedResourceOwner(target, origin, p, call, minOwnerScore)
		},
	}
}

func ProgramHasResourceOwner(target *Target, p *Prog, minOwnerScore int) bool {
	if p == nil {
		return false
	}
	for idx := range p.Calls {
		if CallIndexHasResourceOwner(target, p, idx, minOwnerScore) {
			return true
		}
	}
	return false
}

func ProgramHasValidResourceLineage(target *Target, p *Prog) bool {
	if p == nil {
		return false
	}
	for idx, call := range p.Calls {
		if call == nil || call.Meta == nil || len(call.Meta.inputResources) == 0 {
			continue
		}
		if call.Meta.Attrs.NoGenerate || target != nil && target.CallIsAutomaticHelper(call.Meta) {
			continue
		}
		if !callHasFocusedResourceLineage(p.Calls, idx, nil) {
			return false
		}
	}
	return true
}

func CallIndexHasResourceOwner(target *Target, p *Prog, call int, minOwnerScore int) bool {
	if p == nil || call < 0 || call >= len(p.Calls) || p.Calls[call] == nil {
		return false
	}
	meta := p.Calls[call].Meta
	if meta == nil || !callCanOwnResourcePolicy(target, meta) {
		return false
	}
	if !callHasFocusedResourceLineage(p.Calls, call, nil) {
		return false
	}
	return focusedResourceOwnerScore(target, meta) >= minOwnerScore
}

func focusedResourceOwnerScore(target *Target, call *Syscall) int {
	if target != nil {
		score := target.CallRelevance(call)
		if len(call.createsResources) != 0 || len(call.seedCreatesResources) != 0 {
			score = max(score, callInputResourceDepth(call))
		}
		return score
	}
	return ResourceDepthCallScore(nil, call)
}

func callCanOwnResourcePolicy(target *Target, call *Syscall) bool {
	if call == nil || call.Attrs.NoGenerate {
		return false
	}
	if target != nil && target.CallIsAutomaticHelper(call) {
		return false
	}
	if len(call.createsResources) == 0 && len(call.seedCreatesResources) == 0 {
		return true
	}
	return callInputResourceDepth(call) >= resourceCtorStateDepth
}

func ShouldSkipFocusedResourceProgram(target *Target, p *Prog, minOwnerScore int) bool {
	if p == nil {
		return false
	}
	containsNoGenerate := false
	containsUnownedFocusedCall := false
	for idx, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		if CallIndexHasResourceOwner(target, p, idx, minOwnerScore) {
			return false
		}
		if call.Meta.Attrs.NoGenerate {
			containsNoGenerate = true
		}
		if callCanOwnResourcePolicy(target, call.Meta) &&
			focusedResourceOwnerScore(target, call.Meta) >= minOwnerScore {
			containsUnownedFocusedCall = true
		}
	}
	return containsNoGenerate || containsUnownedFocusedCall
}

func shouldKeepFocusedResourceOwner(target *Target, origin string, p *Prog, call int, minOwnerScore int) bool {
	if origin != "candidate" && !strings.HasPrefix(origin, "collide:") {
		return false
	}
	return CallIndexHasResourceOwner(target, p, call, minOwnerScore)
}

func callHasFocusedResourceLineage(calls []*Call, callIndex int, seen map[*Call]bool) bool {
	if callIndex < 0 || callIndex >= len(calls) {
		return false
	}
	call := calls[callIndex]
	if call == nil || call.Meta == nil || len(call.Meta.inputResources) == 0 {
		return true
	}
	if seen == nil {
		seen = make(map[*Call]bool)
	}
	if seen[call] {
		return true
	}
	seen[call] = true
	foundRequiredResource := false
	validRequiredResources := true
	ForeachArg(call, func(arg Arg, ctx *ArgCtx) {
		res, ok := arg.(*ResultArg)
		if !ok || res.Dir() == DirOut || res.Type().Optional() {
			return
		}
		foundRequiredResource = true
		if res.Res == nil {
			validRequiredResources = false
			ctx.Stop = true
			return
		}
		producer := resourceProducerCall(res.Res, calls, callIndex)
		if producer == nil {
			validRequiredResources = false
			ctx.Stop = true
			return
		}
		producerIndex := -1
		for i := callIndex - 1; i >= 0; i-- {
			if calls[i] == producer {
				producerIndex = i
				break
			}
		}
		if producerIndex == -1 || !callHasFocusedResourceLineage(calls, producerIndex, seen) {
			validRequiredResources = false
			ctx.Stop = true
			return
		}
	})
	return foundRequiredResource && validRequiredResources
}

// NoTargetProfile keeps ApplyTargetProfile implementations compact when a target
// supports compatibility aliases but has no changes for the default profile.
func NoTargetProfile(target *Target, profile string) (*Target, error) {
	return target, nil
}

func sortedCallNames(calls []*Syscall) []string {
	names := make([]string, 0, len(calls))
	for _, call := range calls {
		if call != nil {
			names = append(names, call.Name)
		}
	}
	slices.Sort(names)
	return names
}

// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package windows

import (
	"fmt"
	"slices"
	"strings"

	"github.com/google/syzkaller/prog"
)

type windowsStatePolicy struct {
	name      windowsProfileName
	helpers   windowsHelperPolicy
	relevance windowsRelevancePolicy
	bias      windowsBiasPolicy
	closure   windowsClosurePolicy
}

type windowsProfileName string

const (
	windowsProfileDefault       windowsProfileName = "default"
	windowsProfileAFD           windowsProfileName = "afd"
	windowsProfileAFDAcceptRace windowsProfileName = "afd_accept_race"
	windowsProfileAFDTransmit   windowsProfileName = "afd_transmit"
	windowsProfileFSCTL         windowsProfileName = "fsctl"
)

type windowsHelperPolicy struct {
	syscalls []string
}

type windowsRelevancePolicy struct {
	minimumHintsCallRelevance          int
	minimumTriageCallRelevance         int
	minimumCollideCallRelevance        int
	minimumMutationCallRelevance       int
	minimumGenerationBiasCallRelevance int
	disabledCallPrefixes               []string
	disabledCalls                      map[string]bool
}

type windowsBiasPolicy struct{}

type windowsClosurePolicy struct{}

var defaultWindowsStatePolicy = windowsStatePolicy{
	name: windowsProfileDefault,
	helpers: windowsHelperPolicy{
		syscalls: []string{
			"CloseHandle", "CreateFileA", "CreateFile2", "VirtualAlloc",
			"WSAStartup", "WSACleanup",
			"socket$inet_tcp", "socket$inet_udp", "socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp",
			"closesocket$any",
		},
	},
	relevance: windowsRelevancePolicy{
		minimumHintsCallRelevance:          3,
		minimumTriageCallRelevance:         3,
		minimumCollideCallRelevance:        3,
		minimumMutationCallRelevance:       3,
		minimumGenerationBiasCallRelevance: 3,
	},
}

var afdWindowsStatePolicy = windowsStatePolicy{
	name:    windowsProfileAFD,
	helpers: defaultWindowsStatePolicy.helpers,
	relevance: windowsRelevancePolicy{
		minimumHintsCallRelevance:          2,
		minimumTriageCallRelevance:         2,
		minimumCollideCallRelevance:        2,
		minimumMutationCallRelevance:       2,
		minimumGenerationBiasCallRelevance: 2,
		disabledCalls: map[string]bool{
			"NtFsControlFile":            true,
			"NtReadFile":                 true,
			"NtWriteFile":                true,
			"ReadFile":                   true,
			"WriteFile":                  true,
			"FlushFileBuffers":           true,
			"SetFileInformationByHandle": true,
			"DeleteFileA":                true,
		},
	},
}

var afdAcceptRaceWindowsStatePolicy = windowsStatePolicy{
	name:    windowsProfileAFDAcceptRace,
	helpers: defaultWindowsStatePolicy.helpers,
	relevance: windowsRelevancePolicy{
		minimumHintsCallRelevance:          3,
		minimumTriageCallRelevance:         3,
		minimumCollideCallRelevance:        3,
		minimumMutationCallRelevance:       3,
		minimumGenerationBiasCallRelevance: 3,
		disabledCalls: map[string]bool{
			"NtFsControlFile":            true,
			"NtReadFile":                 true,
			"NtWriteFile":                true,
			"ReadFile":                   true,
			"WriteFile":                  true,
			"FlushFileBuffers":           true,
			"SetFileInformationByHandle": true,
			"DeleteFileA":                true,
		},
	},
}

var afdTransmitWindowsStatePolicy = windowsStatePolicy{
	name:    windowsProfileAFDTransmit,
	helpers: defaultWindowsStatePolicy.helpers,
	relevance: windowsRelevancePolicy{
		minimumHintsCallRelevance:          3,
		minimumTriageCallRelevance:         3,
		minimumCollideCallRelevance:        3,
		minimumMutationCallRelevance:       3,
		minimumGenerationBiasCallRelevance: 3,
		disabledCalls: map[string]bool{
			"NtFsControlFile":            true,
			"NtReadFile":                 true,
			"NtWriteFile":                true,
			"ReadFile":                   true,
			"WriteFile":                  true,
			"FlushFileBuffers":           true,
			"SetFileInformationByHandle": true,
			"DeleteFileA":                true,
		},
	},
}

var fsctlWindowsStatePolicy = windowsStatePolicy{
	name:    windowsProfileFSCTL,
	helpers: defaultWindowsStatePolicy.helpers,
	relevance: windowsRelevancePolicy{
		minimumHintsCallRelevance:          2,
		minimumTriageCallRelevance:         2,
		minimumCollideCallRelevance:        3,
		minimumMutationCallRelevance:       2,
		minimumGenerationBiasCallRelevance: 2,
		disabledCallPrefixes: []string{"socket$", "bind$", "listen$", "connect$", "accept$", "send$", "recv$",
			"ioctlsocket$", "setsockopt$", "getsockopt$", "AcceptEx$", "WSARecvEx$", "TransmitFile$"},
		disabledCalls: map[string]bool{
			"WSAStartup":      true,
			"WSACleanup":      true,
			"closesocket$any": true,
		},
	},
}

func configureWindowsStatePolicy(target *prog.Target) {
	policy := selectWindowsStatePolicy(windowsProfileDefault)
	policy.apply(target)
}

func ConfigureTargetProfile(target *prog.Target, profile string) error {
	if target == nil {
		return fmt.Errorf("nil target")
	}
	if profile == "" {
		return nil
	}
	policyName, err := parseWindowsProfile(profile)
	if err != nil {
		return err
	}
	policy := selectWindowsStatePolicy(policyName)
	policy.apply(target)
	return nil
}

func parseWindowsProfile(profile string) (windowsProfileName, error) {
	switch windowsProfileName(strings.ToLower(profile)) {
	case windowsProfileDefault:
		return windowsProfileDefault, nil
	case windowsProfileAFD:
		return windowsProfileAFD, nil
	case windowsProfileAFDAcceptRace:
		return windowsProfileAFDAcceptRace, nil
	case windowsProfileAFDTransmit:
		return windowsProfileAFDTransmit, nil
	case windowsProfileFSCTL:
		return windowsProfileFSCTL, nil
	default:
		return "", fmt.Errorf("unknown windows target profile %q", profile)
	}
}

func selectWindowsStatePolicy(profile windowsProfileName) windowsStatePolicy {
	switch profile {
	case windowsProfileDefault:
		return defaultWindowsStatePolicy
	case windowsProfileAFD:
		return afdWindowsStatePolicy
	case windowsProfileAFDAcceptRace:
		return afdAcceptRaceWindowsStatePolicy
	case windowsProfileAFDTransmit:
		return afdTransmitWindowsStatePolicy
	case windowsProfileFSCTL:
		return fsctlWindowsStatePolicy
	default:
		panic("unknown windows state policy profile")
	}
}

func (policy windowsStatePolicy) apply(target *prog.Target) {
	target.ConfiguredProfile = string(policy.name)
	policy.helpers.apply(target)
	target.Helpers.DeprioritizeAutomaticHelpers = true
	target.Helpers.AvoidCollidingAutomaticHelpers = true
	target.Helpers.SkipHintsForAutomaticHelpers = true
	target.Helpers.NoMutateAutomaticHelpers = true
	target.Helpers.SkipCorpusForAutomaticHelpers = true
	target.Helpers.SkipTriageForAutomaticHelpers = true
	target.Helpers.AvoidAutomaticHelperBias = true
	target.Bias.SelectGenerationBiasCall = func(p *prog.Prog, insertionPoint int) int {
		return policy.bias.selectGenerationBiasCall(policy, p, insertionPoint)
	}
	target.Bias.SelectGeneratedCall = func(p *prog.Prog, insertionPoint int, biasCall int, ct *prog.ChoiceTable) int {
		return policy.bias.selectGeneratedCall(policy, p, insertionPoint, biasCall, ct)
	}
	target.Bias.GenerationTemplateScore = func(p *prog.Prog, insertionPoint int, call *prog.Syscall) int {
		return policy.bias.generationTemplateScore(target, p, insertionPoint, call)
	}
	target.Bias.FilterBiasCalls = func(calls []*prog.Syscall) []*prog.Syscall {
		return policy.bias.filterBiasCalls(policy, calls)
	}
	target.SelectCollideCallIndices = func(calls []*prog.Call) ([]int, bool) {
		return policy.relevance.selectCollideCallIndices(policy, target, calls)
	}
	target.RuntimePolicy.PreferCollideProgram = policy.relevance.preferCollideProgram
	target.RuntimePolicy.ShouldScheduleImmediateCollide = func(p *prog.Prog, call int) bool {
		return policy.relevance.shouldScheduleImmediateCollide(policy, p, call)
	}
	target.RuntimePolicy.ShouldForceTriageCall = func(origin string, p *prog.Prog, call int) bool {
		return policy.relevance.shouldForceTriageCall(policy, origin, p, call)
	}
	target.RuntimePolicy.ShouldPersistStableTriageCall = func(origin string, p *prog.Prog, call int) bool {
		return policy.relevance.shouldPersistStableTriageCall(policy, origin, p, call)
	}
	target.Bias.AdjustCallPriority = func(src, dst *prog.Syscall, weight int32) int32 {
		return policy.bias.adjustCallPriority(policy, src, dst, weight)
	}
	target.ResourceUseScore = policy.relevance.callStageScore
	target.ResourceReuseScore = policy.relevance.resourceReuseScore
	target.CorpusResourceScore = policy.relevance.corpusResourceScore
	target.PreferResourceCentricBorrowing = policy.relevance.preferResourceCentricBorrowing
	target.SelectResourceCtor = policy.relevance.selectResourceCtor
	target.CallRelevanceScore = policy.relevance.callStageScore
	target.TriageCallScore = func(call *prog.Syscall) int {
		score := policy.relevance.triageCallScore(call)
		if (policy.name != windowsProfileAFDAcceptRace && policy.name != windowsProfileAFDTransmit) ||
			call == nil || score < 0 {
			return score
		}
		switch call.Name {
		case "WSARecvEx$inet_accept":
			if policy.name == windowsProfileAFDTransmit {
				return score + 190
			}
			return score + 200
		case "TransmitFile$inet_accept":
			if policy.name == windowsProfileAFDTransmit {
				return score + 220
			}
			return score + 170
		case "ioctlsocket$fionbio_accept":
			return score + 195
		case "getsockopt$int_accept":
			return score + 180
		case "send$inet_accept", "recv$inet_accept",
			"send$inet_tcp", "recv$inet_tcp", "getsockopt$int_tcp", "ioctlsocket$fionbio_tcp":
			return score + 100
		case "accept$inet_tcp":
			return score + 50
		case "bind$inet_tcp", "listen$inet_tcp", "connect$inet_tcp",
			"socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp":
			return max(score-100, 0)
		default:
			return score
		}
	}
	target.ExpandEnabledCalls = func(target *prog.Target, enabled map[*prog.Syscall]bool) map[*prog.Syscall]bool {
		return policy.closure.expandEnabledCalls(target, enabled)
	}
	target.MinimumHintsCallRelevance = policy.relevance.minimumHintsCallRelevance
	target.MinimumTriageCallRelevance = policy.relevance.minimumTriageCallRelevance
	target.MinimumCollideCallRelevance = policy.relevance.minimumCollideCallRelevance
	target.MinimumMutationCallRelevance = policy.relevance.minimumMutationCallRelevance
	target.Bias.MinimumGenerationBiasCallRelevance = policy.relevance.minimumGenerationBiasCallRelevance
}

func (helpers windowsHelperPolicy) apply(target *prog.Target) {
	helperSet := make(map[string]bool, len(helpers.syscalls))
	for _, name := range helpers.syscalls {
		helperSet[name] = true
	}
	target.Helpers.AutomaticHelperPredicate = func(call *prog.Syscall) bool {
		if call == nil {
			return false
		}
		return helperSet[call.Name] || call.Attrs.AutomaticHelper
	}
}

func (bias windowsBiasPolicy) adjustCallPriority(policy windowsStatePolicy, src, dst *prog.Syscall, weight int32) int32 {
	boost := func(minWeight, factor int32) int32 {
		if weight < minWeight {
			weight = minWeight
		}
		return weight * factor
	}
	srcStage := policy.relevance.resourceStageScore(src)
	dstStage := policy.relevance.resourceStageScore(dst)
	switch {
	case srcStage == 2 && dstStage == 3:
		return boost(14, 3)
	case srcStage == 2 && dstStage == 4:
		return boost(16, 4)
	case srcStage == 3 && dstStage == 4:
		return boost(14, 3)
	}
	switch src.Name {
	case "socket$inet_tcp":
		if dst.Name == "bind$inet_tcp" || dst.Name == "listen$inet_tcp" ||
			dst.Name == "connect$inet_tcp" || dst.Name == "ioctlsocket$fionbio_tcp" ||
			dst.Name == "setsockopt$int_tcp" || dst.Name == "getsockopt$int_tcp" {
			return boost(12, 3)
		}
	case "socket$inet_udp":
		if dst.Name == "bind$inet_udp" || dst.Name == "connect$inet_udp" ||
			dst.Name == "send$inet_udp" || dst.Name == "recv$inet_udp" ||
			dst.Name == "ioctlsocket$fionbio_udp" || dst.Name == "setsockopt$int_udp" ||
			dst.Name == "getsockopt$int_udp" {
			return boost(12, 3)
		}
	case "connect$inet_udp":
		if dst.Name == "send$inet_udp" || dst.Name == "recv$inet_udp" ||
			dst.Name == "setsockopt$int_udp" || dst.Name == "getsockopt$int_udp" ||
			dst.Name == "ioctlsocket$fionbio_udp" {
			return boost(14, 3)
		}
	}
	return weight
}

func (bias windowsBiasPolicy) selectGenerationBiasCall(policy windowsStatePolicy, p *prog.Prog, insertionPoint int) int {
	if p == nil || insertionPoint <= 0 || insertionPoint > len(p.Calls) {
		return -1
	}
	target := p.Target
	if target == nil || target.CallRelevanceScore == nil {
		return -1
	}
	minScore := 1
	if target.Bias.MinimumGenerationBiasCallRelevance > 0 {
		minScore = target.Bias.MinimumGenerationBiasCallRelevance
	}
	filtered := make([]*prog.Call, 0, insertionPoint)
	indices := make([]int, 0, insertionPoint)
	for i, call := range p.Calls[:insertionPoint] {
		if call == nil || call.Meta == nil || !target.CallEligibleForGenerationBias(call.Meta) {
			continue
		}
		filtered = append(filtered, call)
		indices = append(indices, i)
	}
	bestFiltered, _ := target.SelectBestRelevanceCallIndex(filtered, minScore, true)
	if bestFiltered >= 0 {
		return indices[bestFiltered]
	}
	bestIdx, _ := target.SelectBestRelevanceCallIndex(p.Calls[:insertionPoint], minScore, true)
	if bestIdx < 0 {
		return prog.NoGenerationBiasCall
	}
	return bestIdx
}

func (bias windowsBiasPolicy) filterBiasCalls(policy windowsStatePolicy, calls []*prog.Syscall) []*prog.Syscall {
	if len(calls) == 0 {
		return nil
	}
	bestScore := 0
	filtered := make([]*prog.Syscall, 0, len(calls))
	for _, call := range calls {
		if call == nil || policy.helpers.contains(call.Name) {
			continue
		}
		score := policy.relevance.callStageScore(call)
		if score > bestScore {
			bestScore = score
			filtered = filtered[:0]
		}
		if score > 0 && score == bestScore {
			filtered = append(filtered, call)
		}
	}
	return filtered
}

func (bias windowsBiasPolicy) selectGeneratedCall(policy windowsStatePolicy, p *prog.Prog,
	insertionPoint int, biasCall int, ct *prog.ChoiceTable) int {
	if p == nil || ct == nil || insertionPoint <= 0 || insertionPoint > len(p.Calls) {
		return -1
	}
	sessionFamily := windowsSessionGenerationFamily(p.Calls[:insertionPoint])
	if sessionFamily == "" {
		return -1
	}
	target := p.Target
	if target == nil {
		return -1
	}
	if next := windowsSessionTemplateContinuation(policy, target, p.Calls[:insertionPoint], ct); next >= 0 {
		if target.ObserveTemplateHook != nil {
			target.ObserveTemplateHook("gen:" + windowsGenerationContextTag(p) + ":template")
		}
		return next
	}
	candidates := windowsFamilyGenerationCandidates(sessionFamily)
	var preferred []*prog.Syscall
	for _, name := range candidates {
		call := target.SyscallMap[name]
		if call == nil {
			continue
		}
		if !ct.Generatable(call.ID) || !target.CallEligibleForMutation(call) {
			continue
		}
		preferred = append(preferred, call)
	}
	if len(preferred) == 0 {
		return -1
	}
	best := preferred[0]
	bestScore := bias.generationCallScore(policy, best)
	for _, call := range preferred[1:] {
		score := bias.generationCallScore(policy, call)
		if score > bestScore || score == bestScore && best.ID < call.ID {
			best = call
			bestScore = score
		}
	}
	if target.ObserveTemplateHook != nil {
		target.ObserveTemplateHook("gen:" + windowsGenerationContextTag(p) + ":family")
	}
	return best.ID
}

func windowsGenerationContextTag(p *prog.Prog) string {
	if p == nil {
		return "unknown"
	}
	if rg := p.GenerationContext(); rg != "" {
		return rg
	}
	return "unknown"
}

func windowsSessionTemplateContinuation(policy windowsStatePolicy, target *prog.Target, calls []*prog.Call,
	ct *prog.ChoiceTable) int {
	if target == nil || ct == nil || len(calls) == 0 {
		return -1
	}
	relevant := windowsRecentGenerationCalls(calls, 2)
	if len(relevant) >= 2 {
		prev := relevant[len(relevant)-2]
		last := relevant[len(relevant)-1]
		if call := windowsBestContinuationCandidate(policy, target, ct,
			windowsContinuationCandidates2(prev.Meta.Name, last.Meta.Name)); call != nil {
			return call.ID
		}
	}
	if len(relevant) == 0 {
		return -1
	}
	last := relevant[len(relevant)-1]
	if call := windowsBestContinuationCandidate(policy, target, ct,
		windowsContinuationCandidates(last.Meta.Name)); call != nil {
		return call.ID
	}
	return -1
}

func windowsBestContinuationCandidate(policy windowsStatePolicy, target *prog.Target, ct *prog.ChoiceTable,
	names []string) *prog.Syscall {
	if target == nil || ct == nil || len(names) == 0 {
		return nil
	}
	var best *prog.Syscall
	bestScore := -1
	bias := windowsBiasPolicy{}
	for _, name := range names {
		call := target.SyscallMap[name]
		if call == nil || !ct.Generatable(call.ID) || !target.CallEligibleForMutation(call) {
			continue
		}
		score := bias.generationCallScore(policy, call)
		if best == nil || score > bestScore || score == bestScore && best.ID < call.ID {
			best = call
			bestScore = score
		}
	}
	return best
}

func windowsContinuationCandidates(name string) []string {
	switch name {
	case "accept$inet_tcp":
		return []string{"send$inet_accept", "recv$inet_accept", "WSARecvEx$inet_accept", "getsockopt$int_accept", "ioctlsocket$fionbio_accept", "TransmitFile$inet_accept"}
	case "send$inet_accept":
		return []string{"recv$inet_accept", "WSARecvEx$inet_accept", "getsockopt$int_accept", "ioctlsocket$fionbio_accept", "TransmitFile$inet_accept"}
	case "recv$inet_accept":
		return []string{"send$inet_accept", "WSARecvEx$inet_accept", "getsockopt$int_accept", "ioctlsocket$fionbio_accept", "TransmitFile$inet_accept"}
	case "WSARecvEx$inet_accept":
		return []string{"send$inet_accept", "getsockopt$int_accept", "ioctlsocket$fionbio_accept", "TransmitFile$inet_accept"}
	case "TransmitFile$inet_accept":
		return []string{"getsockopt$int_accept", "ioctlsocket$fionbio_accept", "send$inet_accept"}
	case "connect$inet_tcp":
		return []string{"send$inet_tcp", "recv$inet_tcp", "getsockopt$int_tcp"}
	case "send$inet_tcp":
		return []string{"recv$inet_tcp", "getsockopt$int_tcp", "ioctlsocket$fionbio_tcp"}
	case "recv$inet_tcp":
		return []string{"send$inet_tcp", "getsockopt$int_tcp", "ioctlsocket$fionbio_tcp"}
	case "connect$inet_udp":
		return []string{"send$inet_udp", "recv$inet_udp", "getsockopt$int_udp"}
	case "send$inet_udp":
		return []string{"recv$inet_udp", "getsockopt$int_udp", "ioctlsocket$fionbio_udp"}
	case "recv$inet_udp":
		return []string{"send$inet_udp", "getsockopt$int_udp", "ioctlsocket$fionbio_udp"}
	case "NtFsControlFile":
		return []string{"NtWriteFile", "NtReadFile", "FlushFileBuffers"}
	case "NtWriteFile":
		return []string{"NtFsControlFile", "NtReadFile", "FlushFileBuffers"}
	case "NtReadFile":
		return []string{"NtWriteFile", "NtFsControlFile", "FlushFileBuffers"}
	default:
		return nil
	}
}

func windowsContinuationCandidates2(prev, last string) []string {
	switch {
	case prev == "accept$inet_tcp" && last == "send$inet_accept":
		return []string{"recv$inet_accept", "WSARecvEx$inet_accept", "getsockopt$int_accept", "ioctlsocket$fionbio_accept", "TransmitFile$inet_accept"}
	case prev == "accept$inet_tcp" && last == "recv$inet_accept":
		return []string{"send$inet_accept", "WSARecvEx$inet_accept", "getsockopt$int_accept", "ioctlsocket$fionbio_accept", "TransmitFile$inet_accept"}
	case prev == "accept$inet_tcp" && last == "WSARecvEx$inet_accept":
		return []string{"getsockopt$int_accept", "ioctlsocket$fionbio_accept", "TransmitFile$inet_accept", "send$inet_accept"}
	case prev == "accept$inet_tcp" && last == "TransmitFile$inet_accept":
		return []string{"getsockopt$int_accept", "ioctlsocket$fionbio_accept", "send$inet_accept"}
	case prev == "send$inet_accept" && last == "recv$inet_accept":
		return []string{"WSARecvEx$inet_accept", "getsockopt$int_accept", "ioctlsocket$fionbio_accept", "TransmitFile$inet_accept"}
	case prev == "recv$inet_accept" && last == "send$inet_accept":
		return []string{"WSARecvEx$inet_accept", "getsockopt$int_accept", "ioctlsocket$fionbio_accept", "TransmitFile$inet_accept"}
	case prev == "send$inet_accept" && last == "WSARecvEx$inet_accept":
		return []string{"getsockopt$int_accept", "ioctlsocket$fionbio_accept", "TransmitFile$inet_accept"}
	case prev == "recv$inet_accept" && last == "WSARecvEx$inet_accept":
		return []string{"getsockopt$int_accept", "ioctlsocket$fionbio_accept", "TransmitFile$inet_accept"}
	case prev == "send$inet_accept" && last == "getsockopt$int_accept":
		return []string{"WSARecvEx$inet_accept", "ioctlsocket$fionbio_accept", "recv$inet_accept"}
	case prev == "recv$inet_accept" && last == "getsockopt$int_accept":
		return []string{"WSARecvEx$inet_accept", "ioctlsocket$fionbio_accept", "send$inet_accept"}
	case prev == "send$inet_accept" && last == "ioctlsocket$fionbio_accept":
		return []string{"WSARecvEx$inet_accept", "getsockopt$int_accept", "recv$inet_accept"}
	case prev == "recv$inet_accept" && last == "ioctlsocket$fionbio_accept":
		return []string{"WSARecvEx$inet_accept", "getsockopt$int_accept", "send$inet_accept"}
	case prev == "WSARecvEx$inet_accept" && last == "getsockopt$int_accept":
		return []string{"ioctlsocket$fionbio_accept", "send$inet_accept"}
	case prev == "WSARecvEx$inet_accept" && last == "ioctlsocket$fionbio_accept":
		return []string{"getsockopt$int_accept", "send$inet_accept"}
	case prev == "TransmitFile$inet_accept" && last == "getsockopt$int_accept":
		return []string{"ioctlsocket$fionbio_accept", "send$inet_accept"}
	case prev == "TransmitFile$inet_accept" && last == "ioctlsocket$fionbio_accept":
		return []string{"getsockopt$int_accept", "send$inet_accept"}
	case prev == "connect$inet_tcp" && last == "send$inet_tcp":
		return []string{"recv$inet_tcp", "getsockopt$int_tcp"}
	case prev == "connect$inet_tcp" && last == "recv$inet_tcp":
		return []string{"send$inet_tcp", "getsockopt$int_tcp"}
	case prev == "connect$inet_udp" && last == "send$inet_udp":
		return []string{"recv$inet_udp", "getsockopt$int_udp"}
	case prev == "connect$inet_udp" && last == "recv$inet_udp":
		return []string{"send$inet_udp", "getsockopt$int_udp"}
	case prev == "NtFsControlFile" && last == "NtWriteFile":
		return []string{"NtFsControlFile", "FlushFileBuffers"}
	case prev == "NtFsControlFile" && last == "NtReadFile":
		return []string{"NtWriteFile", "NtFsControlFile"}
	case prev == "NtWriteFile" && last == "NtReadFile":
		return []string{"NtFsControlFile", "FlushFileBuffers"}
	default:
		return nil
	}
}

func (bias windowsBiasPolicy) generationCallScore(policy windowsStatePolicy, call *prog.Syscall) int {
	if call == nil {
		return 0
	}
	score := policy.relevance.callStageScore(call)
	if score < 0 {
		return score
	}
	if policy.name == windowsProfileAFDAcceptRace || policy.name == windowsProfileAFDTransmit {
		switch call.Name {
		case "WSARecvEx$inet_accept":
			return 190
		case "TransmitFile$inet_accept":
			if policy.name == windowsProfileAFDTransmit {
				return 195
			}
			return 175
		case "ioctlsocket$fionbio_accept":
			return 185
		case "getsockopt$int_accept":
			return 180
		case "send$inet_accept", "recv$inet_accept":
			return 140
		}
	}
	switch call.Name {
	case "send$inet_accept", "recv$inet_accept", "send$inet_tcp", "recv$inet_tcp",
		"send$inet_udp", "recv$inet_udp":
		return 130
	case "WSARecvEx$inet_accept":
		return 120
	case "TransmitFile$inet_accept":
		return 115
	case "getsockopt$int_accept", "setsockopt$int_accept", "ioctlsocket$fionbio_accept",
		"getsockopt$int_tcp", "setsockopt$int_tcp", "ioctlsocket$fionbio_tcp",
		"getsockopt$int_udp", "setsockopt$int_udp", "ioctlsocket$fionbio_udp":
		return 110
	case "NtFsControlFile":
		return 130
	case "NtWriteFile", "NtReadFile":
		return 120
	case "WriteFile", "ReadFile":
		return 110
	case "FlushFileBuffers", "SetFileInformationByHandle", "DeleteFileA":
		return 100
	default:
		return score * 10
	}
}

func (bias windowsBiasPolicy) generationTemplateScore(target *prog.Target, p *prog.Prog,
	insertionPoint int, call *prog.Syscall) int {
	if target == nil || p == nil || call == nil || insertionPoint <= 0 || insertionPoint > len(p.Calls) {
		return 0
	}
	if len(p.Calls[:insertionPoint]) >= 2 {
		prev := p.Calls[insertionPoint-2]
		last := p.Calls[insertionPoint-1]
		if prev != nil && prev.Meta != nil && last != nil && last.Meta != nil {
			for _, name := range windowsContinuationCandidates2(prev.Meta.Name, last.Meta.Name) {
				if name == call.Name {
					return 20
				}
			}
		}
	}
	last := p.Calls[insertionPoint-1]
	if last != nil && last.Meta != nil {
		for _, name := range windowsContinuationCandidates(last.Meta.Name) {
			if name == call.Name {
				return 10
			}
		}
	}
	return 0
}

func (relevance windowsRelevancePolicy) callStageScore(call *prog.Syscall) int {
	if call == nil {
		return 0
	}
	if relevance.disabledCalls != nil && relevance.disabledCalls[call.Name] {
		return -1
	}
	for _, prefix := range relevance.disabledCallPrefixes {
		if strings.HasPrefix(call.Name, prefix) {
			return -1
		}
	}
	if defaultWindowsStatePolicy.helpers.contains(call.Name) {
		return 0
	}
	score := relevance.resourceStageScore(call)
	switch call.Name {
	case "bind$inet_tcp", "bind$inet_udp", "connect$inet_udp",
		"ioctlsocket$fionbio_tcp", "ioctlsocket$fionbio_udp", "ioctlsocket$fionbio_accept",
		"setsockopt$int_tcp", "setsockopt$int_udp", "setsockopt$int_accept",
		"getsockopt$int_tcp", "getsockopt$int_udp", "getsockopt$int_accept":
		if score < 2 {
			score = 2
		}
	case "send$inet_tcp", "send$inet_udp", "send$inet_accept",
		"recv$inet_tcp", "recv$inet_udp", "recv$inet_accept",
		"NtReadFile", "NtWriteFile",
		"ReadFile", "WriteFile", "FlushFileBuffers", "SetFileInformationByHandle", "DeleteFileA":
		if score < 3 {
			score = 3
		}
	case "WSARecvEx$inet_accept", "TransmitFile$inet_accept", "NtFsControlFile":
		if score < 4 {
			score = 4
		}
	default:
		if strings.HasPrefix(call.Name, "send$inet_") || strings.HasPrefix(call.Name, "recv$inet_") {
			if score < 3 {
				score = 3
			}
		}
	}
	return score
}

func (relevance windowsRelevancePolicy) triageCallScore(call *prog.Syscall) int {
	score := relevance.callStageScore(call)
	if score < 0 {
		return score
	}
	switch call.Name {
	case "send$inet_accept", "recv$inet_accept", "send$inet_tcp", "recv$inet_tcp",
		"send$inet_udp", "recv$inet_udp", "NtFsControlFile", "NtWriteFile", "NtReadFile":
		return 200
	case "getsockopt$int_accept", "setsockopt$int_accept", "ioctlsocket$fionbio_accept",
		"getsockopt$int_tcp", "setsockopt$int_tcp", "ioctlsocket$fionbio_tcp",
		"getsockopt$int_udp", "setsockopt$int_udp", "ioctlsocket$fionbio_udp":
		return 170
	case "WSARecvEx$inet_accept", "TransmitFile$inet_accept":
		return 160
	case "WriteFile", "ReadFile", "FlushFileBuffers", "SetFileInformationByHandle", "DeleteFileA":
		return 150
	default:
		return score * 10
	}
}

func (relevance windowsRelevancePolicy) preferResourceCentricBorrowing(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	switch call.Name {
	case "recv$inet_accept", "send$inet_accept", "WSARecvEx$inet_accept",
		"getsockopt$int_accept", "ioctlsocket$fionbio_accept",
		"recv$inet_tcp", "send$inet_tcp", "getsockopt$int_tcp", "ioctlsocket$fionbio_tcp",
		"recv$inet_udp", "send$inet_udp", "getsockopt$int_udp", "ioctlsocket$fionbio_udp",
		"NtFsControlFile", "NtReadFile", "NtWriteFile":
		return true
	default:
		return false
	}
}

func (relevance windowsRelevancePolicy) preferCollideProgram(p *prog.Prog) bool {
	if p == nil || len(p.Calls) < 2 {
		return false
	}
	for i := 1; i < len(p.Calls); i++ {
		prev := p.Calls[i-1]
		cur := p.Calls[i]
		if prev == nil || prev.Meta == nil || cur == nil || cur.Meta == nil {
			continue
		}
		if len(windowsContinuationCandidates2(prev.Meta.Name, cur.Meta.Name)) != 0 {
			return true
		}
	}
	return false
}

func (relevance windowsRelevancePolicy) shouldScheduleImmediateCollide(policy windowsStatePolicy,
	p *prog.Prog, call int) bool {
	if (policy.name != windowsProfileAFDAcceptRace && policy.name != windowsProfileAFDTransmit) ||
		p == nil || call < 0 || call >= len(p.Calls) {
		return false
	}
	meta := p.Calls[call].Meta
	if meta == nil {
		return false
	}
	switch meta.Name {
	case "WSARecvEx$inet_accept", "getsockopt$int_accept", "ioctlsocket$fionbio_accept",
		"TransmitFile$inet_accept", "recv$inet_accept":
		return true
	default:
		return false
	}
}

func (relevance windowsRelevancePolicy) shouldForceTriageCall(policy windowsStatePolicy,
	origin string, p *prog.Prog, call int) bool {
	if (policy.name != windowsProfileAFDAcceptRace && policy.name != windowsProfileAFDTransmit) ||
		origin != "collide:triage" ||
		p == nil || call < 0 || call >= len(p.Calls) {
		return false
	}
	meta := p.Calls[call].Meta
	return meta != nil && (meta.Name == "ioctlsocket$fionbio_accept" ||
		meta.Name == "TransmitFile$inet_accept")
}

func (relevance windowsRelevancePolicy) shouldPersistStableTriageCall(policy windowsStatePolicy,
	origin string, p *prog.Prog, call int) bool {
	if policy.name != windowsProfileAFDTransmit || origin != "candidate" ||
		p == nil || call < 0 || call >= len(p.Calls) {
		return false
	}
	meta := p.Calls[call].Meta
	return meta != nil && meta.Name == "TransmitFile$inet_accept"
}

func (relevance windowsRelevancePolicy) selectResourceCtor(current *prog.Syscall, resourceType string, ctors []prog.ResourceCtor) *prog.Syscall {
	prefer := func(names ...string) *prog.Syscall {
		for _, name := range names {
			for _, info := range ctors {
				if info.Call != nil && info.Call.Name == name {
					return info.Call
				}
			}
		}
		return nil
	}
	switch resourceType {
	case "SOCKET_ACCEPT":
		return prefer("accept$inet_tcp")
	case "SOCKET_CONNECTED":
		return prefer("connect$inet_tcp", "connect$inet_udp")
	case "SOCKET_LISTENER":
		return prefer("listen$inet_tcp", "bind$inet_tcp")
	case "FILE_HANDLE":
		return prefer("CreateFileA", "CreateFile2")
	default:
		return nil
	}
}

func (relevance windowsRelevancePolicy) resourceStageScore(call *prog.Syscall) int {
	score := 0
	bump := func(v int) {
		if v > score {
			score = v
		}
	}
	for _, res := range call.InputResources() {
		switch res.Name {
		case "SOCKET_LISTENER":
			bump(2)
		case "SOCKET_CONNECTED":
			bump(2)
		case "SOCKET_ACCEPT":
			bump(3)
		case "FILE_HANDLE":
			bump(3)
		}
	}
	for _, res := range call.CreatesResources() {
		switch res.Name {
		case "SOCKET_LISTENER":
			bump(2)
		case "SOCKET_CONNECTED":
			bump(2)
		case "SOCKET_ACCEPT":
			bump(3)
		case "FILE_HANDLE":
			bump(2)
		}
	}
	return score
}

func (relevance windowsRelevancePolicy) resourceReuseScore(current *prog.Syscall, candidate *prog.ResultArg,
	p *prog.Prog, insertionPoint int) int {
	if current == nil || candidate == nil {
		return 0
	}
	root := windowsRootResultArg(candidate)
	if root == nil {
		return 0
	}
	currentFamily := windowsCallRaceFamily(current)
	if currentFamily == "" {
		return 0
	}
	candidateFamily := windowsResultArgFamily(root)
	if candidateFamily != currentFamily {
		return 0
	}
	score := windowsBaseResourceReuseScore(currentFamily)
	score += windowsRootUseScore(currentFamily, current, root, p, insertionPoint, p, insertionPoint)
	if recent := windowsRecentSessionRoot(p, insertionPoint, currentFamily); recent != nil && recent == root {
		score += 10
	}
	return score
}

func (relevance windowsRelevancePolicy) corpusResourceScore(current *prog.Syscall, candidate *prog.ResultArg,
	p *prog.Prog, insertionPoint int, corpusProg *prog.Prog) int {
	score := relevance.resourceReuseScore(current, candidate, p, insertionPoint)
	if current == nil || candidate == nil {
		return score
	}
	root := windowsRootResultArg(candidate)
	if root == nil {
		return score
	}
	rootFamily := windowsResultArgFamily(root)
	useScore := windowsRootUseScore(rootFamily, current, root, p, insertionPoint, corpusProg, len(corpusProg.Calls))
	score += useScore
	if p != nil && p.Target != nil && p.Target.Bias.GenerationTemplateScore != nil {
		bonus := p.Target.Bias.GenerationTemplateScore(p, insertionPoint, current)
		score += bonus
		if (bonus != 0 || useScore >= windowsTemplateCorpusObserveThreshold(rootFamily, current)) &&
			p.Target.ObserveTemplateHook != nil {
			p.Target.ObserveTemplateHook("corpus:windows")
		}
	}
	return score
}

func (relevance windowsRelevancePolicy) selectCollideCallIndices(policy windowsStatePolicy,
	target *prog.Target, calls []*prog.Call) ([]int, bool) {
	if len(calls) == 0 {
		return nil, false
	}
	bestIdx, bestScore, thresholdBlocked := relevance.selectBestCollideCall(policy, target, calls)
	if bestIdx < 0 {
		return nil, thresholdBlocked
	}
	bestCall := calls[bestIdx]
	bestMeta := bestCall.Meta
	bestFamily := windowsCallRaceFamily(bestMeta)
	bestStage := relevance.resourceStageScore(bestMeta)
	bestRoots := windowsCallResourceRoots(bestCall)
	templateMatch := windowsTemplateCollideMatches(calls, bestIdx)
	preferred := make([]int, 0, len(calls))
	seen := make(map[int]bool)
	sharedRoots := make([]int, 0, len(calls))
	templatePreferred := make([]int, 0, len(calls))
	for i, call := range calls {
		if call == nil || call.Meta == nil {
			continue
		}
		if len(templateMatch) != 0 && templateMatch[i] {
			templatePreferred = append(templatePreferred, i)
			continue
		}
		if !target.CallEligibleForCollide(call.Meta) {
			continue
		}
		score := relevance.collideCallScore(policy, call.Meta)
		if score < bestScore {
			continue
		}
		if bestFamily != "" && windowsCallRaceFamily(call.Meta) != bestFamily {
			continue
		}
		if relevance.resourceStageScore(call.Meta) != bestStage {
			continue
		}
		preferred = append(preferred, i)
		seen[i] = true
		if len(bestRoots) != 0 && windowsCallsShareResourceRoot(bestRoots, call) {
			sharedRoots = append(sharedRoots, i)
		}
	}
	if len(templatePreferred) != 0 {
		if target.ObserveTemplateHook != nil {
			family := bestFamily
			if family == "" {
				family = "unknown"
			}
			summary := windowsCollideTemplateSummary(calls, templatePreferred)
			target.ObserveTemplateHook("collide:" + family + ":" + summary)
		}
		return templatePreferred, thresholdBlocked
	}
	if len(sharedRoots) != 0 {
		return sharedRoots, thresholdBlocked
	}
	if !seen[bestIdx] {
		preferred = append(preferred, bestIdx)
	}
	if len(preferred) == 0 {
		return []int{bestIdx}, thresholdBlocked
	}
	return preferred, thresholdBlocked
}

func windowsTemplateCollideMatches(calls []*prog.Call, bestIdx int) map[int]bool {
	if bestIdx < 0 || bestIdx >= len(calls) {
		return nil
	}
	for i := max(1, bestIdx-2); i <= min(bestIdx+1, len(calls)-1); i++ {
		prev := calls[i-1]
		best := calls[i]
		if prev == nil || prev.Meta == nil || best == nil || best.Meta == nil {
			continue
		}
		match := make(map[int]bool)
		switch {
		case prev.Meta.Name == "send$inet_accept" && best.Meta.Name == "recv$inet_accept":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "recv$inet_accept" && best.Meta.Name == "send$inet_accept":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "send$inet_accept" && best.Meta.Name == "WSARecvEx$inet_accept":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "recv$inet_accept" && best.Meta.Name == "WSARecvEx$inet_accept":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "getsockopt$int_accept" && best.Meta.Name == "send$inet_accept":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "getsockopt$int_accept" && best.Meta.Name == "recv$inet_accept":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "getsockopt$int_accept" && best.Meta.Name == "WSARecvEx$inet_accept":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "WSARecvEx$inet_accept" && best.Meta.Name == "getsockopt$int_accept":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "ioctlsocket$fionbio_accept" && best.Meta.Name == "send$inet_accept":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "ioctlsocket$fionbio_accept" && best.Meta.Name == "recv$inet_accept":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "ioctlsocket$fionbio_accept" && best.Meta.Name == "WSARecvEx$inet_accept":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "WSARecvEx$inet_accept" && best.Meta.Name == "ioctlsocket$fionbio_accept":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "send$inet_tcp" && best.Meta.Name == "recv$inet_tcp":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "recv$inet_tcp" && best.Meta.Name == "send$inet_tcp":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "getsockopt$int_tcp" && best.Meta.Name == "send$inet_tcp":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "getsockopt$int_tcp" && best.Meta.Name == "recv$inet_tcp":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "ioctlsocket$fionbio_tcp" && best.Meta.Name == "send$inet_tcp":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "ioctlsocket$fionbio_tcp" && best.Meta.Name == "recv$inet_tcp":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "send$inet_udp" && best.Meta.Name == "recv$inet_udp":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "recv$inet_udp" && best.Meta.Name == "send$inet_udp":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "NtFsControlFile" && best.Meta.Name == "NtWriteFile":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "NtWriteFile" && best.Meta.Name == "NtFsControlFile":
			match[i-1] = true
			match[i] = true
		case prev.Meta.Name == "NtFsControlFile" && best.Meta.Name == "NtReadFile":
			match[i-1] = true
			match[i] = true
		}
		if len(match) != 0 {
			return match
		}
	}
	return nil
}

func windowsCollideTemplateSummary(calls []*prog.Call, indices []int) string {
	if len(indices) == 0 {
		return "none"
	}
	names := make([]string, 0, len(indices))
	seen := make(map[string]bool)
	for _, idx := range indices {
		if idx < 0 || idx >= len(calls) {
			continue
		}
		call := calls[idx]
		if call == nil || call.Meta == nil || seen[call.Meta.Name] {
			continue
		}
		seen[call.Meta.Name] = true
		names = append(names, call.Meta.Name)
	}
	if len(names) == 0 {
		return "none"
	}
	slices.Sort(names)
	return strings.Join(names, "|")
}

func (relevance windowsRelevancePolicy) selectBestCollideCall(policy windowsStatePolicy,
	target *prog.Target, calls []*prog.Call) (bestIdx, bestScore int, thresholdBlocked bool) {
	bestIdx = -1
	hasEligible := false
	for i, call := range calls {
		if call == nil || call.Meta == nil || !target.CallEligibleForCollide(call.Meta) {
			continue
		}
		hasEligible = true
		score := relevance.collideCallScore(policy, call.Meta)
		if score > bestScore || score == bestScore && bestIdx < i {
			bestScore = score
			bestIdx = i
		}
	}
	if bestIdx >= 0 {
		return bestIdx, bestScore, false
	}
	if !hasEligible && target.MinimumCollideCallRelevance > 0 {
		if _, blocked := target.SelectBestRelevanceCallIndex(calls, target.MinimumCollideCallRelevance, true); blocked {
			return -1, 0, true
		}
	}
	// Fall back to the generic deepest call so selector keeps working even if a call does not
	// have a family-specific collide priority yet.
	bestIdx, thresholdBlocked = target.SelectBestRelevanceCallIndex(calls, target.MinimumCollideCallRelevance, true)
	if bestIdx >= 0 {
		bestScore = relevance.collideCallScore(policy, calls[bestIdx].Meta)
	}
	return bestIdx, bestScore, thresholdBlocked
}

func (relevance windowsRelevancePolicy) collideCallScore(policy windowsStatePolicy, call *prog.Syscall) int {
	stage := relevance.callStageScore(call)
	if stage < 0 {
		return stage
	}
	if policy.name == windowsProfileAFDAcceptRace {
		switch call.Name {
		case "TransmitFile$inet_accept":
			if policy.name == windowsProfileAFDTransmit {
				return 230
			}
			return 100
		case "WSARecvEx$inet_accept":
			if policy.name == windowsProfileAFDTransmit {
				return 205
			}
			return 210
		case "ioctlsocket$fionbio_accept":
			if policy.name == windowsProfileAFDTransmit {
				return 200
			}
			return 200
		case "getsockopt$int_accept":
			if policy.name == windowsProfileAFDTransmit {
				return 190
			}
			return 190
		case "send$inet_accept", "recv$inet_accept":
			return 150
		case "accept$inet_tcp":
			return 120
		}
	}
	switch call.Name {
	case "send$inet_accept", "recv$inet_accept", "send$inet_tcp", "recv$inet_tcp",
		"send$inet_udp", "recv$inet_udp":
		return 130
	case "WSARecvEx$inet_accept":
		return 120
	case "getsockopt$int_accept", "setsockopt$int_accept", "ioctlsocket$fionbio_accept",
		"getsockopt$int_tcp", "setsockopt$int_tcp", "ioctlsocket$fionbio_tcp",
		"getsockopt$int_udp", "setsockopt$int_udp", "ioctlsocket$fionbio_udp":
		return 110
	case "TransmitFile$inet_accept":
		return 100
	case "AcceptEx$inet_tcp", "accept$inet_tcp", "connect$inet_tcp", "connect$inet_udp":
		return 90
	case "NtFsControlFile":
		return 130
	case "NtWriteFile", "NtReadFile":
		return 120
	case "WriteFile", "ReadFile":
		return 110
	case "FlushFileBuffers", "SetFileInformationByHandle", "DeleteFileA":
		return 100
	default:
		return stage * 10
	}
}

func (closure windowsClosurePolicy) expandEnabledCalls(target *prog.Target, enabled map[*prog.Syscall]bool) map[*prog.Syscall]bool {
	expanded := make(map[*prog.Syscall]bool, len(enabled))
	for call, v := range enabled {
		expanded[call] = v
	}
	add := func(names ...string) {
		for _, name := range names {
			if meta := target.SyscallMap[name]; meta != nil {
				expanded[meta] = true
			}
		}
	}
	add("VirtualAlloc")
	for {
		sizeBefore := len(expanded)
		current := make([]*prog.Syscall, 0, len(expanded))
		for call := range expanded {
			current = append(current, call)
		}
		for _, call := range current {
			switch {
			case closure.callNeedsTCPClosure(call):
				add("WSAStartup", "WSACleanup", "closesocket$any")
				add(closure.networkStageClosure(call)...)
			case closure.callNeedsUDPClosure(call):
				add("WSAStartup", "WSACleanup", "closesocket$any")
				add(closure.udpStageClosure(call.Name)...)
			case closure.callNeedsFileClosure(call):
				add(closure.fileStageClosure(target, call.Name)...)
			}
		}
		if len(expanded) == sizeBefore {
			break
		}
	}
	return expanded
}

func (closure windowsClosurePolicy) callTouchesResourceFamily(call *prog.Syscall, prefix string) bool {
	for _, res := range call.InputResources() {
		if strings.HasPrefix(res.Name, prefix) {
			return true
		}
	}
	for _, res := range call.CreatesResources() {
		if strings.HasPrefix(res.Name, prefix) {
			return true
		}
	}
	return false
}

func (closure windowsClosurePolicy) callNeedsTCPClosure(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	if call.Name == "closesocket$any" || call.Name == "WSAStartup" || call.Name == "WSACleanup" {
		return false
	}
	return closure.callTouchesResourceFamily(call, "SOCKET_") &&
		!closure.callTouchesResourceFamily(call, "SOCKET_UDP")
}

func (closure windowsClosurePolicy) callNeedsUDPClosure(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	if call.Name == "closesocket$any" || call.Name == "WSAStartup" || call.Name == "WSACleanup" {
		return false
	}
	return closure.callTouchesResourceFamily(call, "SOCKET_UDP")
}

func (closure windowsClosurePolicy) callNeedsFileClosure(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	if closure.callTouchesResourceFamily(call, "FILE_HANDLE") {
		return true
	}
	return call.Name == "DeleteFileA"
}

func (closure windowsClosurePolicy) callUsesInputResource(call *prog.Syscall, resName string) bool {
	for _, res := range call.InputResources() {
		if res.Name == resName {
			return true
		}
	}
	return false
}

func (closure windowsClosurePolicy) callCreatesResource(call *prog.Syscall, resName string) bool {
	for _, res := range call.CreatesResources() {
		if res.Name == resName {
			return true
		}
	}
	return false
}

func (closure windowsClosurePolicy) networkStageClosure(call *prog.Syscall) []string {
	scaffold := []string{}
	add := func(names ...string) {
		scaffold = append(scaffold, names...)
	}

	switch call.Name {
	case "socket$inet_tcp":
		add("socket$inet_tcp")
	}
	if closure.callNeedsListenerScaffold(call) {
		add("socket$listener_tcp", "bind$inet_tcp")
	}
	if closure.callNeedsListenScaffold(call) {
		add("listen$inet_tcp")
	}
	if closure.callNeedsConnectedScaffold(call) {
		add("socket$connected_tcp", "connect$inet_tcp")
	}
	if closure.callNeedsAcceptScaffold(call) {
		add("socket$accept_tcp", "accept$inet_tcp")
	}
	if peerSend := closure.peerTrafficScaffoldCall(call); peerSend != "" {
		add(peerSend)
	}
	if closure.callNeedsFilePayloadScaffold(call) {
		add("CreateFileA", "CreateFile2", "CloseHandle", "WriteFile")
	}
	return scaffold
}

func (closure windowsClosurePolicy) callNeedsListenerScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	return call.Name == "bind$inet_tcp" || call.Name == "listen$inet_tcp" ||
		call.Name == "connect$inet_tcp" || call.Name == "send$inet_tcp" || call.Name == "recv$inet_tcp" ||
		closure.callUsesInputResource(call, "SOCKET_LISTENER") ||
		closure.callUsesInputResource(call, "SOCKET_ACCEPT")
}

func (closure windowsClosurePolicy) callNeedsListenScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	return call.Name == "listen$inet_tcp" || call.Name == "accept$inet_tcp" ||
		closure.callUsesInputResource(call, "SOCKET_ACCEPT")
}

func (closure windowsClosurePolicy) callNeedsConnectedScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	return call.Name == "connect$inet_tcp" ||
		closure.callUsesInputResource(call, "SOCKET_CONNECTED") ||
		closure.callUsesInputResource(call, "SOCKET_ACCEPT")
}

func (closure windowsClosurePolicy) callNeedsAcceptScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	return call.Name == "AcceptEx$inet_tcp" ||
		call.Name == "recv$inet_tcp" ||
		closure.callUsesInputResource(call, "SOCKET_ACCEPT") ||
		closure.callCreatesResource(call, "SOCKET_ACCEPT")
}

func (closure windowsClosurePolicy) peerTrafficScaffoldCall(call *prog.Syscall) string {
	if call == nil {
		return ""
	}
	switch call.Name {
	case "recv$inet_tcp":
		return "send$inet_accept"
	case "recv$inet_accept", "WSARecvEx$inet_accept":
		return "send$inet_tcp"
	case "recv$inet_udp":
		return "send$inet_udp"
	default:
		return ""
	}
}

func (closure windowsClosurePolicy) callNeedsFilePayloadScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	return call.Name == "TransmitFile$inet_accept"
}

func (closure windowsClosurePolicy) udpStageClosure(name string) []string {
	scaffold := []string{"socket$inet_udp"}
	switch name {
	case "send$inet_udp", "recv$inet_udp", "ioctlsocket$fionbio_udp",
		"setsockopt$int_udp", "getsockopt$int_udp":
		scaffold = append(scaffold, "connect$inet_udp")
	}
	if name == "recv$inet_udp" {
		scaffold = append(scaffold, "send$inet_udp")
	}
	return scaffold
}

func (closure windowsClosurePolicy) fileStageClosure(target *prog.Target, name string) []string {
	scaffold := []string{"CreateFileA", "CreateFile2", "CloseHandle"}
	if target != nil && (target.ConfiguredProfile == string(windowsProfileAFD) ||
		target.ConfiguredProfile == string(windowsProfileAFDAcceptRace)) {
		switch name {
		case "WriteFile", "ReadFile", "FlushFileBuffers", "SetFileInformationByHandle", "DeleteFileA":
			return scaffold
		}
	}
	switch name {
	case "ReadFile", "WriteFile", "FlushFileBuffers", "SetFileInformationByHandle", "DeleteFileA":
		scaffold = append(scaffold, "NtReadFile", "NtWriteFile", "NtFsControlFile")
	}
	return scaffold
}

func windowsCallRaceFamily(call *prog.Syscall) string {
	if call == nil {
		return ""
	}
	switch {
	case strings.Contains(call.Name, "$inet_accept"):
		return "accept"
	case strings.Contains(call.Name, "$inet_tcp"):
		return "tcp"
	case strings.Contains(call.Name, "$inet_udp"):
		return "udp"
	case strings.Contains(call.Name, "File") || strings.HasPrefix(call.Name, "Nt") && strings.Contains(call.Name, "File"):
		return "file"
	default:
		return ""
	}
}

func windowsSessionGenerationFamily(calls []*prog.Call) string {
	for i := len(calls) - 1; i >= 0; i-- {
		call := calls[i]
		if call == nil || call.Meta == nil {
			continue
		}
		switch family := windowsCallRaceFamily(call.Meta); family {
		case "accept", "tcp", "udp", "file":
			if strings.HasPrefix(call.Meta.Name, "socket$") || strings.HasPrefix(call.Meta.Name, "bind$") ||
				strings.HasPrefix(call.Meta.Name, "listen$") || strings.HasPrefix(call.Meta.Name, "connect$") ||
				call.Meta.Name == "CreateFileA" || call.Meta.Name == "CreateFile2" || call.Meta.Name == "CloseHandle" {
				continue
			}
			return family
		}
	}
	return ""
}

func windowsRecentGenerationCalls(calls []*prog.Call, want int) []*prog.Call {
	if want <= 0 || len(calls) == 0 {
		return nil
	}
	ret := make([]*prog.Call, 0, want)
	for i := len(calls) - 1; i >= 0 && len(ret) < want; i-- {
		call := calls[i]
		if call == nil || call.Meta == nil {
			continue
		}
		if strings.HasPrefix(call.Meta.Name, "socket$") || strings.HasPrefix(call.Meta.Name, "bind$") ||
			strings.HasPrefix(call.Meta.Name, "listen$") || strings.HasPrefix(call.Meta.Name, "connect$") ||
			call.Meta.Name == "CreateFileA" || call.Meta.Name == "CreateFile2" || call.Meta.Name == "CloseHandle" ||
			call.Meta.Name == "closesocket$any" || call.Meta.Name == "WSAStartup" || call.Meta.Name == "WSACleanup" {
			continue
		}
		ret = append(ret, call)
	}
	slices.Reverse(ret)
	return ret
}

func windowsFamilyGenerationCandidates(family string) []string {
	switch family {
	case "accept":
		return []string{"send$inet_accept", "recv$inet_accept", "WSARecvEx$inet_accept",
			"getsockopt$int_accept", "setsockopt$int_accept", "ioctlsocket$fionbio_accept",
			"TransmitFile$inet_accept"}
	case "tcp":
		return []string{"send$inet_tcp", "recv$inet_tcp", "getsockopt$int_tcp",
			"setsockopt$int_tcp", "ioctlsocket$fionbio_tcp"}
	case "udp":
		return []string{"send$inet_udp", "recv$inet_udp", "getsockopt$int_udp",
			"setsockopt$int_udp", "ioctlsocket$fionbio_udp"}
	case "file":
		return []string{"NtFsControlFile", "NtWriteFile", "NtReadFile",
			"WriteFile", "ReadFile", "FlushFileBuffers", "SetFileInformationByHandle"}
	default:
		return nil
	}
}

func windowsCallResourceRoots(call *prog.Call) map[*prog.ResultArg]bool {
	roots := make(map[*prog.ResultArg]bool)
	if call == nil {
		return roots
	}
	prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
		res, ok := arg.(*prog.ResultArg)
		if !ok || res.Dir() == prog.DirOut || res.Res == nil {
			return
		}
		roots[windowsRootResultArg(res.Res)] = true
	})
	return roots
}

func windowsCallsShareResourceRoot(roots map[*prog.ResultArg]bool, call *prog.Call) bool {
	if len(roots) == 0 || call == nil {
		return false
	}
	shared := false
	prog.ForeachArg(call, func(arg prog.Arg, ctx *prog.ArgCtx) {
		res, ok := arg.(*prog.ResultArg)
		if !ok || res.Dir() == prog.DirOut || res.Res == nil {
			return
		}
		if roots[windowsRootResultArg(res.Res)] {
			shared = true
			ctx.Stop = true
		}
	})
	return shared
}

func windowsRootResultArg(res *prog.ResultArg) *prog.ResultArg {
	for res != nil && res.Res != nil {
		res = res.Res
	}
	return res
}

func windowsResultArgFamily(arg *prog.ResultArg) string {
	if arg == nil {
		return ""
	}
	switch arg.Type().Name() {
	case "SOCKET_ACCEPT":
		return "accept"
	case "SOCKET_CONNECTED", "SOCKET_LISTENER", "SOCKET_TCP":
		return "tcp"
	case "SOCKET_UDP":
		return "udp"
	case "FILE_HANDLE":
		return "file"
	default:
		return ""
	}
}

func windowsRecentSessionRoot(p *prog.Prog, insertionPoint int, family string) *prog.ResultArg {
	if p == nil || insertionPoint <= 0 {
		return nil
	}
	if insertionPoint > len(p.Calls) {
		insertionPoint = len(p.Calls)
	}
	for i := insertionPoint - 1; i >= 0; i-- {
		call := p.Calls[i]
		if call == nil || call.Meta == nil || windowsCallRaceFamily(call.Meta) != family {
			continue
		}
		roots := windowsCallResourceRoots(call)
		for root := range roots {
			return root
		}
	}
	return nil
}

func windowsRootUseScore(family string, current *prog.Syscall, root *prog.ResultArg,
	p *prog.Prog, insertionPoint int, corpusProg *prog.Prog, limit int) int {
	if root == nil || corpusProg == nil {
		return 0
	}
	if limit <= 0 || limit > len(corpusProg.Calls) {
		limit = len(corpusProg.Calls)
	}
	best := 0
	prog.ForeachUseResultArg(root, func(use *prog.ResultArg) {
		score := windowsUseResultArgScore(family, current, use, p, insertionPoint, corpusProg, limit)
		if score > best {
			best = score
		}
	})
	return best
}

func windowsUseResultArgScore(family string, current *prog.Syscall, arg *prog.ResultArg,
	p *prog.Prog, insertionPoint int, corpusProg *prog.Prog, limit int) int {
	if arg == nil || corpusProg == nil {
		return 0
	}
	useCall := prog.FindUseCall(corpusProg, arg, limit)
	callName := ""
	if useCall != nil && useCall.Meta != nil {
		callName = useCall.Meta.Name
	}
	score := 0
	switch family {
	case "accept":
		switch current.Name {
		case "recv$inet_accept", "WSARecvEx$inet_accept":
			switch callName {
			case "send$inet_accept":
				score = 30
			case "WSARecvEx$inet_accept", "TransmitFile$inet_accept":
				score = 24
			case "getsockopt$int_accept", "setsockopt$int_accept", "ioctlsocket$fionbio_accept":
				score = 18
			}
		case "send$inet_accept":
			switch callName {
			case "recv$inet_accept", "WSARecvEx$inet_accept":
				score = 30
			case "TransmitFile$inet_accept":
				score = 24
			case "getsockopt$int_accept", "setsockopt$int_accept", "ioctlsocket$fionbio_accept":
				score = 18
			}
		case "getsockopt$int_accept", "setsockopt$int_accept", "ioctlsocket$fionbio_accept":
			switch callName {
			case "getsockopt$int_accept", "setsockopt$int_accept", "ioctlsocket$fionbio_accept":
				score = 28
			case "send$inet_accept", "recv$inet_accept", "WSARecvEx$inet_accept":
				score = 18
			}
		case "TransmitFile$inet_accept":
			switch callName {
			case "TransmitFile$inet_accept":
				score = 30
			case "send$inet_accept", "recv$inet_accept", "WSARecvEx$inet_accept":
				score = 24
			case "getsockopt$int_accept", "setsockopt$int_accept", "ioctlsocket$fionbio_accept":
				score = 16
			}
		default:
			switch callName {
			case "send$inet_accept", "recv$inet_accept":
				score = 20
			case "WSARecvEx$inet_accept":
				score = 18
			case "TransmitFile$inet_accept":
				score = 16
			case "getsockopt$int_accept", "setsockopt$int_accept", "ioctlsocket$fionbio_accept":
				score = 12
			}
		}
	case "tcp":
		switch current.Name {
		case "recv$inet_tcp":
			switch callName {
			case "send$inet_tcp":
				score = 28
			case "getsockopt$int_tcp", "setsockopt$int_tcp", "ioctlsocket$fionbio_tcp":
				score = 16
			}
		case "send$inet_tcp":
			switch callName {
			case "recv$inet_tcp":
				score = 28
			case "getsockopt$int_tcp", "setsockopt$int_tcp", "ioctlsocket$fionbio_tcp":
				score = 16
			}
		case "getsockopt$int_tcp", "setsockopt$int_tcp", "ioctlsocket$fionbio_tcp":
			switch callName {
			case "getsockopt$int_tcp", "setsockopt$int_tcp", "ioctlsocket$fionbio_tcp":
				score = 26
			case "send$inet_tcp", "recv$inet_tcp":
				score = 16
			}
		default:
			switch callName {
			case "send$inet_tcp", "recv$inet_tcp":
				score = 18
			case "getsockopt$int_tcp", "setsockopt$int_tcp", "ioctlsocket$fionbio_tcp":
				score = 12
			}
		}
	case "udp":
		switch current.Name {
		case "recv$inet_udp":
			switch callName {
			case "send$inet_udp":
				score = 28
			case "getsockopt$int_udp", "setsockopt$int_udp", "ioctlsocket$fionbio_udp":
				score = 16
			}
		case "send$inet_udp":
			switch callName {
			case "recv$inet_udp":
				score = 28
			case "getsockopt$int_udp", "setsockopt$int_udp", "ioctlsocket$fionbio_udp":
				score = 16
			}
		case "getsockopt$int_udp", "setsockopt$int_udp", "ioctlsocket$fionbio_udp":
			switch callName {
			case "getsockopt$int_udp", "setsockopt$int_udp", "ioctlsocket$fionbio_udp":
				score = 26
			case "send$inet_udp", "recv$inet_udp":
				score = 16
			}
		default:
			switch callName {
			case "send$inet_udp", "recv$inet_udp":
				score = 18
			case "getsockopt$int_udp", "setsockopt$int_udp", "ioctlsocket$fionbio_udp":
				score = 12
			}
		}
	case "file":
		switch current.Name {
		case "NtFsControlFile":
			switch callName {
			case "NtFsControlFile":
				score = 30
			case "NtWriteFile", "NtReadFile":
				score = 24
			case "WriteFile", "ReadFile":
				score = 16
			case "FlushFileBuffers", "SetFileInformationByHandle", "DeleteFileA":
				score = 12
			}
		case "NtWriteFile", "NtReadFile":
			switch callName {
			case "NtFsControlFile":
				score = 28
			case "NtWriteFile", "NtReadFile":
				score = 24
			case "WriteFile", "ReadFile":
				score = 16
			case "FlushFileBuffers", "SetFileInformationByHandle", "DeleteFileA":
				score = 12
			}
		default:
			switch callName {
			case "NtFsControlFile":
				score = 20
			case "NtWriteFile", "NtReadFile":
				score = 18
			case "WriteFile", "ReadFile":
				score = 14
			case "FlushFileBuffers", "SetFileInformationByHandle", "DeleteFileA":
				score = 10
			}
		}
	default:
		switch callName {
		case "send$inet_accept", "recv$inet_accept":
			score = 20
		}
	}
	score += windowsTemplateContinuationBonus(p, insertionPoint, current, callName)
	return score
}

func windowsTemplateContinuationBonus(p *prog.Prog, insertionPoint int, current *prog.Syscall, candidateUseCall string) int {
	if p == nil || current == nil || candidateUseCall == "" || insertionPoint < 2 || insertionPoint > len(p.Calls) {
		return 0
	}
	prev := p.Calls[insertionPoint-2]
	last := p.Calls[insertionPoint-1]
	if prev == nil || prev.Meta == nil || last == nil || last.Meta == nil {
		return 0
	}
	for _, name := range windowsContinuationCandidates2(prev.Meta.Name, last.Meta.Name) {
		if name == current.Name && last.Meta.Name == candidateUseCall {
			return 6
		}
	}
	return 0
}

func windowsBaseResourceReuseScore(family string) int {
	switch family {
	case "accept":
		return 20
	case "file":
		return 20
	case "tcp", "udp":
		return 15
	default:
		return 0
	}
}

func windowsTemplateCorpusObserveThreshold(family string, current *prog.Syscall) int {
	if current == nil {
		return 0
	}
	switch family {
	case "accept":
		switch current.Name {
		case "recv$inet_accept", "send$inet_accept", "WSARecvEx$inet_accept",
			"getsockopt$int_accept", "setsockopt$int_accept", "ioctlsocket$fionbio_accept",
			"TransmitFile$inet_accept":
			return 18
		}
	case "tcp":
		switch current.Name {
		case "recv$inet_tcp", "send$inet_tcp", "getsockopt$int_tcp",
			"setsockopt$int_tcp", "ioctlsocket$fionbio_tcp":
			return 16
		}
	case "udp":
		switch current.Name {
		case "recv$inet_udp", "send$inet_udp", "getsockopt$int_udp",
			"setsockopt$int_udp", "ioctlsocket$fionbio_udp":
			return 16
		}
	case "file":
		switch current.Name {
		case "NtFsControlFile", "NtReadFile", "NtWriteFile", "ReadFile", "WriteFile":
			return 16
		}
	}
	return 0
}

func (helpers windowsHelperPolicy) contains(name string) bool {
	for _, helper := range helpers.syscalls {
		if helper == name {
			return true
		}
	}
	return false
}

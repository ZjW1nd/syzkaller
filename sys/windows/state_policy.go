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
		clone.Helpers.StrictResourceCtors = true
		clone.CallRelevanceScore = windowsAFDCallRelevanceScore
		clone.TriageCallScore = windowsAFDTriageCallScore
		windowsAFDAllowProfileGenerationPrefix(clone, "NtCreateFile$afd_")
		windowsAFDAllowProfileGenerationPrefix(clone, "NtDeviceIoControlFile$afd_")
		windowsAFDAllowProfileGenerationPrefix(clone, "NtReadFile$afd_")
		windowsAFDAllowProfileGenerationPrefix(clone, "NtWriteFile$afd_")
		windowsAFDAllowProfileGenerationPrefix(clone, "NtCancelIoFileEx$afd_")
		windowsAFDAllowProfileGenerationPrefix(clone, "CloseHandle$afd_")
		windowsAFDAllowProfileGenerationPrefix(clone, "GetKernelObjectSecurity$afd_")
		windowsAFDAllowProfileGenerationPrefix(clone, "SetKernelObjectSecurity$afd_")
		windowsAFDAllowProfileGeneration(clone,
			"syz_emit_ethernet$windows",
			"syz_extract_tcp_res$windows",
			"syz_extract_tcp_res$windows_synack",
			"AcceptEx$inet_tcp_pending",
			"CreateIoCompletionPort$accept_pending",
			"CancelIoEx$accept_pending",
			"CancelIo$accept_pending",
			"closesocket$accept_pending",
		)
		clone.MinimumHintsCallRelevance = 4
		clone.MinimumTriageCallRelevance = 4
		clone.MinimumCollideCallRelevance = 4
		clone.MinimumMutationCallRelevance = 4
		clone.Bias.MinimumGenerationBiasCallRelevance = 3
		clone.SelectCollideCallIndices = func(calls []*prog.Call) ([]int, bool) {
			return windowsAFDSelectCollideCallIndices(clone, calls)
		}
		clone.AllowAsyncCollideCall = func(calls []*prog.Call, idx int) bool {
			allowed, reason := windowsAFDAllowAsyncCollideCall(calls, idx)
			if !allowed && clone.ObserveTemplateHook != nil {
				clone.ObserveTemplateHook("collide:block:" + reason)
			}
			return allowed
		}
		clone.CallRequiresAsync = windowsAFDCallRequiresAsync
		clone.SemanticStateModel = windowsAFDSemanticStateModel
		clone.RuntimePolicy = windowsRuntimePolicy(
			prog.FocusedResourceRuntimePolicy(clone, clone.MinimumCollideCallRelevance))
		return clone, nil
	default:
		return nil, fmt.Errorf("unknown windows target profile %q", profile)
	}
}

func windowsAFDAllowProfileGenerationPrefix(target *prog.Target, prefix string) {
	for _, call := range target.Syscalls {
		if call != nil && strings.HasPrefix(call.Name, prefix) &&
			!windowsAFDSyscallRequiresAsync(call) {
			windowsAFDAllowProfileGeneration(target, call.Name)
		}
	}
}

func windowsAFDAllowProfileGeneration(target *prog.Target, names ...string) {
	for _, name := range names {
		if call := target.SyscallMap[name]; call != nil {
			if target.GenerateNoGenerateCalls == nil {
				target.GenerateNoGenerateCalls = make(map[int]bool)
			}
			target.GenerateNoGenerateCalls[call.ID] = true
		}
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

func windowsAFDCallRelevanceScore(call *prog.Syscall) int {
	score := windowsCallRelevanceScore(call)
	if score < 0 || !windowsIsAFDProfileSurfaceCall(call) {
		return score
	}
	return max(score, 4)
}

func windowsAFDTriageCallScore(call *prog.Syscall) int {
	score := windowsAFDCallRelevanceScore(call)
	if score < 0 || !windowsIsAFDProfileSurfaceCall(call) {
		return score
	}
	// Linux network fuzzing lets shallow socket state edges own corpus entries.
	// Keep AFD public surface calls flat for triage so deeper follow-up calls do
	// not prune foundational transitions such as AfdBind/AfdConnect.
	return 4
}

func windowsIsAFDProfileSurfaceCall(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	name := call.Name
	switch {
	case strings.HasPrefix(name, "NtCreateFile$afd_"):
		return true
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_"):
		return true
	case strings.HasPrefix(name, "NtReadFile$afd_"):
		return true
	case strings.HasPrefix(name, "NtWriteFile$afd_"):
		return true
	case strings.HasPrefix(name, "NtCancelIoFileEx$afd_"):
		return true
	case strings.HasPrefix(name, "CancelIoEx$afd_"):
		return true
	case strings.HasPrefix(name, "CancelIo$afd_"):
		return true
	case strings.HasPrefix(name, "CloseHandle$afd_"):
		return true
	case strings.HasPrefix(name, "GetKernelObjectSecurity$afd_"):
		return true
	case strings.HasPrefix(name, "SetKernelObjectSecurity$afd_"):
		return true
	}
	switch name {
	case "syz_emit_ethernet$windows",
		"syz_extract_tcp_res$windows",
		"syz_extract_tcp_res$windows_synack":
		return true
	}
	return false
}

func windowsAFDAllowAsyncCollideCall(calls []*prog.Call, idx int) (bool, string) {
	if idx < 0 || idx >= len(calls) || calls[idx] == nil || calls[idx].Meta == nil {
		return false, "invalid"
	}
	call := calls[idx]
	name := call.Meta.Name
	if !windowsIsAFDProfileSurfaceCall(call.Meta) {
		return true, ""
	}
	if windowsAFDSyscallRequiresAsync(call.Meta) {
		return false, "afd_required_async"
	}
	if windowsAFDCallStateSensitive(name) && windowsAFDCallSharesStateResourceWithNext(calls, idx) {
		return false, "shared_resource"
	}
	if windowsAFDCallMustStaySynchronous(name) {
		return false, "afd_state"
	}
	return true, ""
}

func windowsAFDSelectCollideCallIndices(target *prog.Target, calls []*prog.Call) ([]int, bool) {
	indices, blocked := prog.SelectResourceLineageCollideCallIndices(target, calls)
	if blocked {
		return nil, true
	}
	if filtered := windowsAFDFilterAsyncCollideIndices(calls, indices); len(filtered) != 0 {
		return filtered, false
	}
	p := &prog.Prog{Target: target, Calls: calls}
	bestScore := 0
	var allowed []int
	for idx, call := range calls {
		if call == nil || call.Meta == nil {
			continue
		}
		if ok, _ := windowsAFDAllowAsyncCollideCall(calls, idx); !ok {
			continue
		}
		if !prog.CallIndexHasResourceOwner(target, p, idx, target.MinimumCollideCallRelevance) {
			continue
		}
		score := target.CallRelevance(call.Meta)
		if score > bestScore {
			bestScore = score
			allowed = allowed[:0]
		}
		if score == bestScore {
			allowed = append(allowed, idx)
		}
	}
	if len(allowed) == 0 {
		return nil, true
	}
	if lineage := prog.SameResourceLineageCallIndices(calls, allowed); len(lineage) != 0 {
		if filtered := windowsAFDFilterAsyncCollideIndices(calls, lineage); len(filtered) != 0 {
			return filtered, false
		}
	}
	return allowed, false
}

func windowsAFDFilterAsyncCollideIndices(calls []*prog.Call, indices []int) []int {
	if len(indices) == 0 {
		return nil
	}
	filtered := make([]int, 0, len(indices))
	for _, idx := range indices {
		if ok, _ := windowsAFDAllowAsyncCollideCall(calls, idx); ok {
			filtered = append(filtered, idx)
		}
	}
	return filtered
}

func windowsAFDCallMustStaySynchronous(name string) bool {
	switch {
	case strings.Contains(name, "_irp"):
		return true
	case strings.HasPrefix(name, "NtCreateFile$afd_"),
		strings.HasPrefix(name, "NtCancelIoFileEx$afd_"),
		strings.HasPrefix(name, "CancelIoEx$afd_"),
		strings.HasPrefix(name, "CancelIo$afd_"),
		strings.HasPrefix(name, "CloseHandle$afd_"),
		strings.HasPrefix(name, "SetKernelObjectSecurity$afd_"):
		return true
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_"):
		return !windowsAFDCallAllowsAsyncDataPath(name)
	case strings.HasPrefix(name, "NtReadFile$afd_"),
		strings.HasPrefix(name, "NtWriteFile$afd_"):
		return !strings.Contains(name, "_nonblock")
	case strings.HasPrefix(name, "GetKernelObjectSecurity$afd_"):
		return true
	case name == "syz_emit_ethernet$windows" ||
		name == "syz_extract_tcp_res$windows" ||
		name == "syz_extract_tcp_res$windows_synack":
		return true
	default:
		return false
	}
}

func windowsAFDCallRequiresAsync(calls []*prog.Call, idx int) bool {
	if idx < 0 || idx >= len(calls) || calls[idx] == nil || calls[idx].Meta == nil {
		return false
	}
	return windowsAFDSyscallRequiresAsync(calls[idx].Meta)
}

func windowsAFDSyscallRequiresAsync(call *prog.Syscall) bool {
	if call == nil || !strings.HasPrefix(call.Name, "NtDeviceIoControlFile$afd_") ||
		!strings.Contains(call.Name, "_pending") || len(call.Args) < 2 {
		return false
	}
	res, ok := call.Args[1].Type.(*prog.ResourceType)
	return ok && res.Desc != nil && res.Desc.Name == "EVENT_HANDLE"
}

func windowsAFDCallAllowsAsyncDataPath(name string) bool {
	if !strings.HasPrefix(name, "NtDeviceIoControlFile$afd_") ||
		strings.Contains(name, "_pending") || strings.Contains(name, "_irp") {
		return false
	}
	switch {
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_"):
		return strings.Contains(name, "_nonblock")
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_receive_"):
		return strings.Contains(name, "_nonblock")
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_query_"):
		return true
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_get_"):
		return true
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_enum_"):
		return true
	default:
		return false
	}
}

func windowsAFDCallStateSensitive(name string) bool {
	if strings.HasPrefix(name, "NtCreateFile$afd_") ||
		strings.HasPrefix(name, "NtCancelIoFileEx$afd_") ||
		strings.HasPrefix(name, "CancelIoEx$afd_") ||
		strings.HasPrefix(name, "CancelIo$afd_") ||
		strings.HasPrefix(name, "CloseHandle$afd_") {
		return true
	}
	if !strings.HasPrefix(name, "NtDeviceIoControlFile$afd_") {
		return false
	}
	op := strings.TrimPrefix(name, "NtDeviceIoControlFile$afd_")
	for _, prefix := range []string{
		"set_information_",
		"bind_",
		"start_listen_",
		"wait_for_listen",
		"connect_",
		"accept_",
		"super_accept_",
		"defer_accept_",
		"partial_disconnect_",
		"super_disconnect_",
		"unbind_",
		"unconnect_",
		"socket_transfer_",
		"transmit_",
	} {
		if strings.HasPrefix(op, prefix) {
			return true
		}
	}
	return false
}

func windowsAFDCallSharesStateResourceWithNext(calls []*prog.Call, idx int) bool {
	if idx < 0 || idx+1 >= len(calls) {
		return false
	}
	current := windowsAFDStateResourceRoots(calls[idx])
	if len(current) == 0 {
		return false
	}
	for root := range windowsAFDStateResourceRoots(calls[idx+1]) {
		if current[root] {
			return true
		}
	}
	return false
}

func windowsAFDStateResourceRoots(call *prog.Call) map[*prog.ResultArg]bool {
	roots := make(map[*prog.ResultArg]bool)
	if call == nil {
		return roots
	}
	prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
		res, ok := arg.(*prog.ResultArg)
		if !ok || res.Dir() == prog.DirOut || res.Res == nil {
			return
		}
		if windowsResultArgWantsAnyResourcePrefix(res, "AFD", "SOCKET", "EVENT_HANDLE") {
			roots[res.Res] = true
		}
	})
	return roots
}

func windowsResultArgWantsAnyResourcePrefix(arg *prog.ResultArg, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if windowsResultArgWantsResourcePrefix(arg, prefix) {
			return true
		}
	}
	return false
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
		if failures := prog.ValidateProgramResourceUse(p); len(failures) != 0 {
			return false
		}
		if !windowsHasCompatibleNetworkResourceFamilies(p) {
			return false
		}
		if !windowsHasMatchingAFDReturnedSequence(p) {
			return false
		}
		if !windowsHasValidAFDNonblockState(p) {
			return false
		}
		if !windowsHasValidAFDRequiredAsync(p) {
			return false
		}
		if !windowsHasValidAFDPendingEventUse(p) {
			return false
		}
		st := prog.BuildSemanticState(p, len(p.Calls))
		if !st.Valid() {
			return false
		}
		if windowsSemanticHasCompletedConnectEx(st) {
			return true
		}
		if windowsSemanticHasResolvedAcceptEx(st) {
			return true
		}
		if windowsSemanticHasResolvedSendRecvPending(st) {
			return true
		}
		if prev != nil {
			return prev(origin, p)
		}
		return true
	}
	return base
}

func windowsHasValidAFDNonblockState(p *prog.Prog) bool {
	if p == nil {
		return true
	}
	afdNonblock := make(map[*prog.ResultArg]bool)
	for idx, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		name := call.Meta.Name
		if windowsCallNeedsUDPBoundNonblock(name) {
			if len(call.Args) == 0 {
				return false
			}
			sock, ok := call.Args[0].(*prog.ResultArg)
			if !ok || sock.Res == nil {
				return false
			}
			producer := prog.ResourceProducer(sock.Res, p, idx)
			if producer == nil || producer.Name != "ioctlsocket$fionbio_udp_bound" {
				return false
			}
		}
		if windowsCallMarksAFDNonblock(name) {
			root := windowsSemanticInputRoot(call, 0)
			if root == nil {
				return false
			}
			afdNonblock[root] = true
			continue
		}
		if !windowsCallRequiresAFDNonblock(name) {
			continue
		}
		root := windowsSemanticInputRoot(call, 0)
		if root == nil || !afdNonblock[root] {
			return false
		}
		for _, nested := range windowsAFDNestedNonblockRoots(call) {
			if nested == nil || !afdNonblock[nested] {
				return false
			}
		}
		for _, accepted := range windowsAFDAcceptedNonblockRoots(call) {
			if accepted != nil {
				afdNonblock[accepted] = true
			}
		}
	}
	return true
}

func windowsHasValidAFDRequiredAsync(p *prog.Prog) bool {
	if p == nil {
		return true
	}
	for idx, call := range p.Calls {
		if call == nil || call.Meta == nil || !windowsAFDCallRequiresAsync(p.Calls, idx) {
			continue
		}
		if !call.Props.Async {
			return false
		}
		if !windowsAFDRequiredAsyncHasResolver(p, idx) {
			return false
		}
	}
	return true
}

func windowsAFDRequiredAsyncHasResolver(p *prog.Prog, idx int) bool {
	if p == nil || idx < 0 || idx >= len(p.Calls) || p.Calls[idx] == nil {
		return false
	}
	root := windowsSemanticInputRoot(p.Calls[idx], 0)
	if root == nil {
		return false
	}
	for _, call := range p.Calls[idx+1:] {
		if windowsAFDCallCanResolvePendingIO(call, root) {
			return true
		}
	}
	return false
}

func windowsAFDCallCanResolvePendingIO(call *prog.Call, pendingRoot *prog.ResultArg) bool {
	if call == nil || call.Meta == nil {
		return false
	}
	name := call.Meta.Name
	switch name {
	case "syz_emit_ethernet$windows":
		return true
	}
	if strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_") {
		return true
	}
	if pendingRoot == nil || !windowsAFDStateResourceRoots(call)[pendingRoot] {
		return false
	}
	switch {
	case strings.HasPrefix(name, "NtCancelIoFileEx$afd_"),
		strings.HasPrefix(name, "CancelIoEx$afd_"),
		strings.HasPrefix(name, "CancelIo$afd_"),
		strings.HasPrefix(name, "CloseHandle$afd_"):
		return true
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_connect_"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_accept_"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_defer_accept_"):
		return true
	default:
		return false
	}
}

func windowsHasValidAFDPendingEventUse(p *prog.Prog) bool {
	if p == nil {
		return true
	}
	pendingEvents := make(map[*prog.ResultArg]string)
	for _, call := range p.Calls {
		if call == nil || call.Meta == nil || !windowsIsPrivateAFDPendingIOCTL(call.Meta.Name) {
			continue
		}
		root := windowsSemanticInputRoot(call, 1)
		if root == nil {
			return false
		}
		if prev := pendingEvents[root]; prev != "" {
			return false
		}
		pendingEvents[root] = call.Meta.Name
	}
	return true
}

func windowsIsPrivateAFDPendingIOCTL(name string) bool {
	return strings.HasPrefix(name, "NtDeviceIoControlFile$afd_") &&
		(strings.Contains(name, "_pending") || strings.Contains(name, "_irp"))
}

func windowsCallMarksAFDNonblock(name string) bool {
	return strings.HasPrefix(name, "NtDeviceIoControlFile$afd_set_information_nonblock_")
}

func windowsCallRequiresAFDNonblock(name string) bool {
	if windowsCallMarksAFDNonblock(name) {
		return false
	}
	switch {
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_"),
		strings.HasPrefix(name, "NtReadFile$afd_"),
		strings.HasPrefix(name, "NtWriteFile$afd_"),
		strings.HasPrefix(name, "NtCancelIoFileEx$afd_"),
		strings.HasPrefix(name, "CancelIoEx$afd_"),
		strings.HasPrefix(name, "CancelIo$afd_"),
		strings.HasPrefix(name, "CloseHandle$afd_"):
		return strings.Contains(name, "_nonblock")
	default:
		return false
	}
}

func windowsAFDNestedNonblockRoots(call *prog.Call) []*prog.ResultArg {
	if call == nil || call.Meta == nil || len(call.Args) <= 6 {
		return nil
	}
	switch call.Meta.Name {
	case "NtDeviceIoControlFile$afd_connect_tcp_client_to_listener_nonblock",
		"NtDeviceIoControlFile$afd_connect_tcp_to_listener_nonblock",
		"NtDeviceIoControlFile$afd_connect_tcp_to_delayed_listener_nonblock":
		return windowsInputResourceRootsWithPrefix(call.Args[6], "AFD_TCP")
	default:
		return nil
	}
}

func windowsAFDAcceptedNonblockRoots(call *prog.Call) []*prog.ResultArg {
	if call == nil || call.Meta == nil || len(call.Args) <= 6 {
		return nil
	}
	switch call.Meta.Name {
	case "NtDeviceIoControlFile$afd_accept_tcp_nonblock",
		"NtDeviceIoControlFile$afd_super_accept_tcp_nonblock":
		return windowsInputResourceRootsWithPrefix(call.Args[6], "AFD_TCP_ACCEPT_SLOT")
	default:
		return nil
	}
}

func windowsHasCompatibleNetworkResourceFamilies(p *prog.Prog) bool {
	if p == nil {
		return true
	}
	for _, call := range p.Calls {
		if call == nil {
			continue
		}
		compatible := true
		prog.ForeachArg(call, func(arg prog.Arg, ctx *prog.ArgCtx) {
			if !compatible || arg.Dir() == prog.DirOut {
				return
			}
			res, ok := arg.(*prog.ResultArg)
			if !ok || res.Res == nil {
				return
			}
			wantType, ok := res.Type().(*prog.ResourceType)
			if !ok || wantType.Desc == nil {
				return
			}
			gotType, ok := res.Res.Type().(*prog.ResourceType)
			if !ok || gotType.Desc == nil {
				return
			}
			wantFamily := windowsNetworkResourceFamily(wantType.Desc.Name)
			gotFamily := windowsNetworkResourceFamily(gotType.Desc.Name)
			if wantFamily == "" || gotFamily == "" || wantFamily == gotFamily {
				return
			}
			compatible = false
			ctx.Stop = true
		})
		if !compatible {
			return false
		}
	}
	return true
}

func windowsHasMatchingAFDReturnedSequence(p *prog.Prog) bool {
	if p == nil {
		return true
	}
	sequenceListener := make(map[*prog.ResultArg]*prog.ResultArg)
	for _, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		if windowsAFDWaitForListenSequenceCall(call.Meta.Name) {
			listener := windowsSemanticInputRoot(call, 0)
			if listener == nil || len(call.Args) <= 8 {
				return false
			}
			seq := windowsFirstResourceArgWithPrefix(call.Args[8], "AFD_TCP_RETURNED_SEQUENCE")
			if seq == nil {
				return false
			}
			sequenceListener[seq] = listener
		}
		if len(call.Args) <= 6 {
			continue
		}
		seq := windowsFirstInputResourceArgWithPrefix(call.Args[6], "AFD_TCP_RETURNED_SEQUENCE")
		if seq == nil {
			continue
		}
		listener := windowsSemanticInputRoot(call, 0)
		if listener == nil || seq.Res == nil {
			return false
		}
		if sequenceListener[seq.Res] != listener {
			return false
		}
	}
	return true
}

func windowsAFDWaitForListenSequenceCall(name string) bool {
	switch name {
	case "NtDeviceIoControlFile$afd_wait_for_listen_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_tcp_nonblock",
		"NtDeviceIoControlFile$afd_wait_for_listen_delayed_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_delayed_tcp_nonblock",
		"NtDeviceIoControlFile$afd_wait_for_listen_lifo_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_lifo_tcp_nonblock":
		return true
	default:
		return false
	}
}

func windowsFirstResourceArgWithPrefix(arg prog.Arg, prefix string) *prog.ResultArg {
	var found *prog.ResultArg
	prog.ForeachSubArg(arg, func(arg prog.Arg, ctx *prog.ArgCtx) {
		if found != nil {
			ctx.Stop = true
			return
		}
		res, ok := arg.(*prog.ResultArg)
		if !ok || !windowsResultArgWantsResourcePrefix(res, prefix) {
			return
		}
		found = res
		ctx.Stop = true
	})
	return found
}

func windowsFirstInputResourceArgWithPrefix(arg prog.Arg, prefix string) *prog.ResultArg {
	var found *prog.ResultArg
	prog.ForeachSubArg(arg, func(arg prog.Arg, ctx *prog.ArgCtx) {
		if found != nil {
			ctx.Stop = true
			return
		}
		res, ok := arg.(*prog.ResultArg)
		if !ok || res.Dir() == prog.DirOut || res.Res == nil ||
			!windowsResultArgWantsResourcePrefix(res, prefix) {
			return
		}
		found = res
		ctx.Stop = true
	})
	return found
}

func windowsInputResourceRootsWithPrefix(arg prog.Arg, prefix string) []*prog.ResultArg {
	var roots []*prog.ResultArg
	prog.ForeachSubArg(arg, func(arg prog.Arg, _ *prog.ArgCtx) {
		res, ok := arg.(*prog.ResultArg)
		if !ok || res.Dir() == prog.DirOut || res.Res == nil ||
			!windowsResultArgWantsResourcePrefix(res, prefix) {
			return
		}
		roots = append(roots, res.Res)
	})
	return roots
}

func windowsResultArgWantsResourcePrefix(arg *prog.ResultArg, prefix string) bool {
	if arg == nil {
		return false
	}
	typ, ok := arg.Type().(*prog.ResourceType)
	if !ok || typ.Desc == nil {
		return false
	}
	return typ.Desc.Name == prefix || strings.HasPrefix(typ.Desc.Name, prefix+"_")
}

func windowsResourceProducerCall(candidate *prog.ResultArg, p *prog.Prog, insertionPoint int) *prog.Call {
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
			return call
		}
	}
	for i := 0; i < limit; i++ {
		call := p.Calls[i]
		if call == nil || call.Ret == candidate {
			continue
		}
		found := false
		prog.ForeachArg(call, func(arg prog.Arg, ctx *prog.ArgCtx) {
			if found || arg.Dir() != prog.DirOut {
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

func windowsNetworkResourceFamily(name string) string {
	if family := windowsSocketResourceFamily(name); family != "" {
		return "winsock-" + family
	}
	switch {
	case name == "AFD_TCP" || strings.HasPrefix(name, "AFD_TCP_"):
		return "afd-tcp"
	case name == "AFD_UDP" || strings.HasPrefix(name, "AFD_UDP_"):
		return "afd-udp"
	default:
		return ""
	}
}

func windowsSocketResourceFamily(name string) string {
	switch {
	case strings.HasPrefix(name, "SOCKET_TCP"),
		name == "SOCKET_LISTENER",
		name == "SOCKET_CONNECTED",
		name == "SOCKET_ACCEPT":
		return "tcp"
	case strings.HasPrefix(name, "SOCKET_UDP"):
		return "udp"
	default:
		return ""
	}
}

func windowsCallNeedsUDPBoundNonblock(name string) bool {
	switch name {
	case "recv$inet_udp_nonblock",
		"recvfrom$udp_bound_nonblock",
		"WSARecvFrom$udp_nonblock",
		"WSARecvMsg$udp_nonblock":
		return true
	default:
		return false
	}
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
	for idx, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		if call.Meta.Name == "WSAStartup" {
			if started || idx != 0 {
				return false
			}
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
		if strings.HasPrefix(res.Desc.Name, "SOCKET") || strings.HasPrefix(res.Desc.Name, "WSA") {
			needsStartup = true
			ctx.Stop = true
		}
	})
	return needsStartup
}

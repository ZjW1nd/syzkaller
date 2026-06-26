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
			return prog.SelectResourceLineageCollideCallIndices(clone, calls)
		}
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
		if call != nil && strings.HasPrefix(call.Name, prefix) {
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

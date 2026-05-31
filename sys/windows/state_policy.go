// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package windows

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
)

const windowsTargetProfileAFD = "afd"

var windowsAutomaticHelpers = []string{
	"CloseHandle",
	"CreateFileA",
	"CreateFile2",
	"CreateEventA$manual",
	"CreateEventA$auto",
	"VirtualAlloc",
	"GetCurrentProcess$process",
	"GetCurrentThread$thread",
	"CreateSemaphoreA$sem",
	"WSAStartup",
	"WSACleanup",
	"WSACloseEvent",
	"WSACreateEvent",
	"socket$inet_tcp",
	"socket$inet_udp",
	"socket$bound_udp",
	"socket$connected_udp",
	"socket$listener_tcp",
	"socket$connected_tcp",
	"socket$accept_tcp",
	"closesocket$any",
	"closesocket$tcp_shutdown_rd",
	"closesocket$tcp_shutdown_wr",
}

var windowsAutomaticHelperSet = windowsCallSet(windowsAutomaticHelpers)

func applyWindowsTargetProfile(target *prog.Target, profile string) (*prog.Target, error) {
	if target == nil {
		return nil, fmt.Errorf("windows target profile %q requires a target", profile)
	}
	switch profile {
	case "", "default":
		return target, nil
	case windowsTargetProfileAFD:
		clone := target.Clone()
		clone.CallRelevanceScore = windowsAFDProfileCallRelevanceScore
		clone.TriageCallScore = windowsAFDProfileCallRelevanceScore
		clone.MinimumHintsCallRelevance = 4
		clone.MinimumTriageCallRelevance = 4
		clone.MinimumCollideCallRelevance = 5
		clone.MinimumMutationCallRelevance = 4
		clone.Bias.MinimumGenerationBiasCallRelevance = 3
		clone.Bias.FilterBiasCalls = windowsFilterAFDGenerationBiasCalls
		clone.Bias.SelectGenerationBiasCall = windowsSelectAFDGenerationBiasCall
		clone.Bias.SelectGeneratedCall = windowsSelectAFDGeneratedCall
		clone.SelectCollideCallIndices = windowsSelectAFDCollideCallIndices
		clone.CorpusResourceScore = windowsAFDCorpusResourceScore
		clone.PreferResourceCentricBorrowing = windowsPreferAFDResourceCentricBorrowing
		clone.RuntimePolicy.PreferCollideProgram = windowsAFDProgramHasDeepCall
		clone.RuntimePolicy.ShouldScheduleImmediateCollide = windowsShouldScheduleAFDImmediateCollide
		clone.RuntimePolicy.ShouldForceTriageCall = windowsShouldForceAFDTriageCall
		clone.RuntimePolicy.ShouldSkipTriageProgram = windowsShouldSkipAFDTriageProgram
		clone.RuntimePolicy.ShouldPersistStableTriageCall = windowsShouldPersistAFDTriageCall
		return clone, nil
	default:
		return nil, fmt.Errorf("unknown windows target profile %q", profile)
	}
}

func windowsAFDProfileCallRelevanceScore(call *prog.Syscall) int {
	score := windowsCallRelevanceScore(call)
	if score != 0 {
		return score
	}
	return 1
}

func windowsFilterAFDGenerationBiasCalls(calls []*prog.Syscall) []*prog.Syscall {
	var filtered []*prog.Syscall
	for _, call := range calls {
		if windowsAFDGenerationBiasScore(call) != 0 {
			filtered = append(filtered, call)
		}
	}
	return filtered
}

func windowsSelectAFDGenerationBiasCall(p *prog.Prog, insertionPoint int) int {
	if p == nil || insertionPoint <= 0 {
		return -1
	}
	if insertionPoint > len(p.Calls) {
		insertionPoint = len(p.Calls)
	}
	bestIdx := -1
	bestScore := 0
	for i := 0; i < insertionPoint; i++ {
		call := p.Calls[i]
		if call == nil {
			continue
		}
		score := windowsAFDGenerationBiasScore(call.Meta)
		if score > bestScore {
			bestIdx = i
			bestScore = score
		}
	}
	if bestIdx < 0 {
		return prog.NoGenerationBiasCall
	}
	return bestIdx
}

func windowsAFDGenerationBiasScore(call *prog.Syscall) int {
	if call == nil || call.Attrs.NoGenerate || windowsCallIsAutomaticHelper(call) {
		return 0
	}
	score := windowsAFDCollideScore(call)
	if score < 40 {
		return 0
	}
	return score
}

func windowsSelectAFDGeneratedCall(p *prog.Prog, insertionPoint int, biasCall int, ct *prog.ChoiceTable) int {
	if p == nil || p.Target == nil || ct == nil || biasCall < 0 || biasCall >= len(p.Target.Syscalls) {
		return -1
	}
	for _, name := range windowsAFDGenerationContinuations(p.Target.Syscalls[biasCall].Name) {
		call := p.Target.SyscallMap[name]
		if call != nil && ct.Generatable(call.ID) {
			return call.ID
		}
	}
	return -1
}

func windowsAFDGenerationContinuations(name string) []string {
	switch name {
	case "recv$inet_accept", "WSARecv$accept", "WSARecvEx$inet_accept":
		return []string{"send$inet_accept", "WSASend$accept"}
	case "send$inet_accept", "WSASend$accept":
		return []string{"recv$inet_accept", "WSARecv$accept", "WSARecvEx$inet_accept"}
	case "recv$inet_tcp", "WSARecv$tcp":
		return []string{"send$inet_tcp", "WSASend$tcp"}
	case "send$inet_tcp", "WSASend$tcp":
		return []string{"recv$inet_tcp", "WSARecv$tcp"}
	case "recvfrom$udp_bound", "WSARecvMsg$udp":
		return []string{"sendto$udp_bound"}
	case "sendto$udp_bound":
		return []string{"recvfrom$udp_bound", "WSARecvMsg$udp"}
	case "recvfrom$udp_connected", "WSARecvFrom$udp":
		return []string{"sendto$udp_connected", "WSASendTo$udp"}
	case "sendto$udp_connected", "WSASendTo$udp":
		return []string{"recvfrom$udp_connected", "WSARecvFrom$udp"}
	case "ConnectEx$inet_tcp", "ConnectEx$inet_tcp_reuse":
		return []string{"DisconnectEx$inet_tcp_reuse", "DisconnectEx$inet_tcp"}
	case "DisconnectEx$inet_tcp", "DisconnectEx$inet_tcp_reuse":
		return []string{"ConnectEx$inet_tcp_reuse", "ConnectEx$inet_tcp"}
	default:
		return nil
	}
}

func windowsAFDCorpusResourceScore(current *prog.Syscall, candidate *prog.ResultArg, p *prog.Prog, insertionPoint int, corpusProg *prog.Prog) int {
	if corpusProg != nil {
		score := windowsResourceReuseScore(current, candidate, corpusProg, len(corpusProg.Calls))
		if score != 0 {
			producer := windowsResourceProducer(candidate, corpusProg, len(corpusProg.Calls))
			if producer != nil {
				score += windowsResourceUseScore(producer)
			}
			return score
		}
	}
	return windowsResourceReuseScore(current, candidate, p, insertionPoint)
}

func windowsPreferAFDResourceCentricBorrowing(current *prog.Syscall) bool {
	return windowsAFDGenerationBiasScore(current) >= 40 ||
		windowsCallUsesAnyInputResourceKind(current,
			"SOCKET_TCP_ACCEPT_PENDING",
			"SOCKET_TCP_ACCEPTED_UPDATED",
			"SOCKET_TCP_ACCEPT_RECV_PENDING",
			"SOCKET_TCP_ACCEPT_SEND_PENDING",
			"SOCKET_TCP_RECV_PENDING",
			"SOCKET_TCP_SEND_PENDING",
			"SOCKET_TCP_CONNECTING")
}

func configureWindowsHelpers(target *prog.Target) {
	target.Helpers.AutomaticHelperPredicate = func(call *prog.Syscall) bool {
		return windowsCallIsAutomaticHelper(call)
	}
	target.Helpers.DeprioritizeAutomaticHelpers = true
	target.Helpers.AvoidCollidingAutomaticHelpers = true
	target.Helpers.SkipHintsForAutomaticHelpers = true
	target.Helpers.NoMutateAutomaticHelpers = true
	target.Helpers.SkipCorpusForAutomaticHelpers = true
	target.Helpers.SkipTriageForAutomaticHelpers = true
	target.Helpers.AvoidAutomaticHelperBias = true
}

func windowsCallSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

func windowsCallIsAutomaticHelper(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	return windowsAutomaticHelperSet[call.Name] || call.Attrs.AutomaticHelper
}

func windowsCallRelevanceScore(call *prog.Syscall) int {
	if call == nil {
		return 0
	}
	if windowsCallIsAutomaticHelper(call) {
		return -1
	}
	score := 0
	if windowsCallUsesInputResourcePrefix(call, "HANDLE") {
		score = max(score, 1)
	}
	if windowsCallUsesInputResourcePrefix(call, "FILE_HANDLE") {
		score = max(score, 3)
	}
	if windowsCallUsesInputResourceKind(call, "SOCKET_UDP") {
		score = max(score, 2)
	}
	if windowsCallUsesInputResourceKind(call, "SOCKET_CONNECTED") ||
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_CONNECTED") {
		score = max(score, 3)
	}
	if windowsCallUsesInputResourceKind(call, "SOCKET_LISTENER") ||
		windowsCallUsesInputResourceKind(call, "SOCKET_ACCEPT") ||
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_ACCEPT_PENDING") ||
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_ACCEPTED_UPDATED") ||
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_ACCEPT_RECV_PENDING") ||
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_ACCEPT_SEND_PENDING") ||
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_RECV_PENDING") ||
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_SEND_PENDING") ||
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_CONNECTING") ||
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_LISTENING") ||
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_ACCEPTED") {
		score = max(score, 4)
	}
	if windowsCallUsesInputResourceKind(call, "WAIT_HANDLE") ||
		windowsCallUsesInputResourceKind(call, "EVENT_HANDLE") ||
		windowsCallUsesInputResourceKind(call, "PROCESS_HANDLE") ||
		windowsCallUsesInputResourceKind(call, "THREAD_HANDLE") {
		score = max(score, 2)
	}
	if windowsCallUsesInputResourceKind(call, "TOKEN_HANDLE") ||
		windowsCallUsesInputResourceKind(call, "SECTION_HANDLE") ||
		windowsCallUsesInputResourceKind(call, "IOCP_HANDLE") ||
		windowsCallUsesInputResourcePrefix(call, "PIPE_") {
		score = max(score, 3)
	}
	switch call.Name {
	case "NtQuerySystemInformation", "NtQueryInformationProcess", "NtSetInformationProcess":
		score = max(score, 1)
	case "shutdown$tcp", "shutdown$accept",
		"shutdown$tcp_rd", "shutdown$tcp_wr", "shutdown$accept_rd", "shutdown$accept_wr",
		"getsockname$tcp", "getsockname$udp", "getsockname$accept",
		"getpeername$tcp", "getpeername$udp", "getpeername$accept",
		"select$afd_basic":
		score = max(score, 4)
	case "WSASend$tcp", "WSASend$tcp_pending", "WSASend$accept", "WSASend$accept_pending",
		"WSARecv$tcp", "WSARecv$tcp_pending", "WSARecv$accept", "WSARecv$accept_pending",
		"send$inet_accept_updated", "recv$inet_accept_updated",
		"getsockopt$int_accept_updated", "setsockopt$int_accept_updated",
		"sendto$udp_bound", "sendto$udp_connected",
		"recvfrom$udp_bound", "recvfrom$udp_connected",
		"WSASendTo$udp", "WSARecvFrom$udp",
		"WSAGetOverlappedResult$socket", "CancelIoEx$socket", "CancelIo$socket",
		"WSAGetOverlappedResult$accept_pending", "CancelIoEx$accept_pending", "CancelIo$accept_pending",
		"closesocket$accept_pending",
		"WSAGetOverlappedResult$accept_recv_pending", "CancelIoEx$accept_recv_pending", "CancelIo$accept_recv_pending",
		"closesocket$accept_recv_pending",
		"WSAGetOverlappedResult$accept_send_pending", "CancelIoEx$accept_send_pending", "CancelIo$accept_send_pending",
		"closesocket$accept_send_pending",
		"WSAGetOverlappedResult$tcp_recv_pending", "CancelIoEx$tcp_recv_pending", "CancelIo$tcp_recv_pending",
		"closesocket$tcp_recv_pending",
		"WSAGetOverlappedResult$tcp_send_pending", "CancelIoEx$tcp_send_pending", "CancelIo$tcp_send_pending",
		"closesocket$tcp_send_pending",
		"WSAGetOverlappedResult$connect_pending", "CancelIoEx$connect_pending", "CancelIo$connect_pending",
		"closesocket$connect_pending",
		"CreateIoCompletionPort$socket", "GetQueuedCompletionStatus$socket",
		"CreateIoCompletionPort$accept_pending", "CreateIoCompletionPort$accept_recv_pending",
		"CreateIoCompletionPort$accept_send_pending", "CreateIoCompletionPort$tcp_recv_pending",
		"CreateIoCompletionPort$tcp_send_pending", "CreateIoCompletionPort$connect_pending",
		"WSAIoctl$sio_address_list_query", "WSAIoctl$sio_routing_interface_query",
		"WSAIoctl$sio_keepalive_vals", "WSAIoctl$sio_get_extension_function_pointer",
		"ConnectEx$inet_tcp", "ConnectEx$inet_tcp_pending", "ConnectEx$inet_tcp_reuse",
		"DisconnectEx$inet_tcp", "DisconnectEx$inet_tcp_reuse",
		"GetAcceptExSockaddrs$inet_tcp",
		"TransmitPackets$inet_accept", "WSARecvMsg$udp",
		"WSAEventSelect$tcp", "WSAEventSelect$accept",
		"WSAEnumNetworkEvents$tcp", "WSAEnumNetworkEvents$accept":
		score = max(score, 5)
	case "NtReadFile", "NtWriteFile",
		"NtQueryInformationFile$basic", "NtQueryInformationFile$standard",
		"NtQueryInformationFile$network_open", "NtSetInformationFile$basic":
		score = max(score, 4)
	case "AcceptEx$inet_tcp", "AcceptEx$inet_tcp_pending", "setsockopt$update_accept_context",
		"TransmitFile$inet_accept", "WSARecvEx$inet_accept",
		"NtDeviceIoControlFile", "NtFsControlFile",
		"NtFsControlFile$ntfs_get_compression", "NtFsControlFile$ntfs_set_compression",
		"NtFsControlFile$ntfs_set_sparse", "NtFsControlFile$ntfs_set_zero_data",
		"NtFsControlFile$ntfs_query_allocated_ranges":
		score = max(score, 5)
	}
	return score
}

func windowsResourceUseScore(call *prog.Syscall) int {
	if call == nil {
		return 0
	}
	switch call.Name {
	case "bind$inet_tcp", "bind$inet_udp", "bind$connectex_tcp":
		return 1
	case "listen$inet_tcp", "connect$inet_tcp", "connect$inet_udp":
		return 2
	case "accept$inet_tcp", "AcceptEx$inet_tcp", "AcceptEx$inet_tcp_pending":
		return 3
	case "send$inet_tcp", "send$inet_udp", "send$inet_accept", "send$inet_accept_updated",
		"WSASend$tcp", "WSASend$tcp_pending", "WSASend$accept", "WSASend$accept_pending", "WSASendTo$udp",
		"sendto$udp_bound", "sendto$udp_connected":
		return 4
	case "recv$inet_tcp", "recv$inet_udp", "recv$inet_accept", "recv$inet_accept_updated",
		"WSARecv$tcp", "WSARecv$tcp_pending", "WSARecv$accept", "WSARecv$accept_pending", "WSARecvFrom$udp",
		"recvfrom$udp_bound", "recvfrom$udp_connected",
		"WSARecvEx$inet_accept", "WSARecvMsg$udp":
		return 5
	case "TransmitFile$inet_accept", "TransmitPackets$inet_accept",
		"ConnectEx$inet_tcp", "ConnectEx$inet_tcp_reuse",
		"DisconnectEx$inet_tcp", "DisconnectEx$inet_tcp_reuse",
		"shutdown$tcp_rd", "shutdown$tcp_wr", "shutdown$accept_rd", "shutdown$accept_wr",
		"WSAGetOverlappedResult$socket", "CancelIoEx$socket", "CancelIo$socket",
		"WSAGetOverlappedResult$accept_pending", "CancelIoEx$accept_pending", "CancelIo$accept_pending",
		"closesocket$accept_pending",
		"WSAGetOverlappedResult$accept_recv_pending", "CancelIoEx$accept_recv_pending", "CancelIo$accept_recv_pending",
		"closesocket$accept_recv_pending",
		"WSAGetOverlappedResult$accept_send_pending", "CancelIoEx$accept_send_pending", "CancelIo$accept_send_pending",
		"closesocket$accept_send_pending",
		"WSAGetOverlappedResult$tcp_recv_pending", "CancelIoEx$tcp_recv_pending", "CancelIo$tcp_recv_pending",
		"closesocket$tcp_recv_pending",
		"WSAGetOverlappedResult$tcp_send_pending", "CancelIoEx$tcp_send_pending", "CancelIo$tcp_send_pending",
		"closesocket$tcp_send_pending",
		"WSAGetOverlappedResult$connect_pending", "CancelIoEx$connect_pending", "CancelIo$connect_pending",
		"closesocket$connect_pending",
		"CreateIoCompletionPort$socket", "GetQueuedCompletionStatus$socket",
		"CreateIoCompletionPort$accept_pending", "CreateIoCompletionPort$accept_recv_pending",
		"CreateIoCompletionPort$accept_send_pending", "CreateIoCompletionPort$tcp_recv_pending",
		"CreateIoCompletionPort$tcp_send_pending", "CreateIoCompletionPort$connect_pending",
		"setsockopt$update_accept_context",
		"getsockopt$int_accept_updated", "setsockopt$int_accept_updated",
		"WSAEventSelect$tcp", "WSAEventSelect$accept",
		"WSAEnumNetworkEvents$tcp", "WSAEnumNetworkEvents$accept":
		return 6
	}
	return windowsCallRelevanceScore(call)
}

func windowsSelectAFDCollideCallIndices(calls []*prog.Call) ([]int, bool) {
	var best []int
	bestScore := 0
	hasAFDCall := false
	for i, call := range calls {
		if call == nil || call.Meta == nil || windowsCallIsAutomaticHelper(call.Meta) {
			continue
		}
		score := windowsAFDCollideScore(call.Meta)
		if score == 0 {
			continue
		}
		hasAFDCall = true
		if score > bestScore {
			bestScore = score
			best = best[:0]
		}
		if score == bestScore {
			best = append(best, i)
		}
	}
	if len(best) == 0 && !hasAFDCall {
		return nil, true
	}
	if len(best) > 1 {
		if lineage := windowsAFDSameLineageCollideIndices(calls, best); len(lineage) != 0 {
			return lineage, false
		}
	}
	return best, false
}

func windowsAFDSameLineageCollideIndices(calls []*prog.Call, indices []int) []int {
	preferred := make(map[int]bool, len(indices))
	for _, idx := range indices {
		preferred[idx] = true
	}
	for _, idx := range indices {
		if idx+1 >= len(calls) || !preferred[idx+1] {
			continue
		}
		if windowsCallsShareSocketLineage(calls[idx], calls[idx+1]) {
			return []int{idx}
		}
	}
	return nil
}

func windowsCallsShareSocketLineage(first, second *prog.Call) bool {
	firstResources := windowsInputSocketResources(first)
	if len(firstResources) == 0 {
		return false
	}
	for resource := range windowsInputSocketResources(second) {
		if firstResources[resource] {
			return true
		}
	}
	return false
}

func windowsInputSocketResources(call *prog.Call) map[*prog.ResultArg]bool {
	resources := map[*prog.ResultArg]bool{}
	if call == nil {
		return resources
	}
	prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
		res, ok := arg.(*prog.ResultArg)
		if !ok || res.Dir() == prog.DirOut || res.Res == nil {
			return
		}
		if typ, ok := res.Type().(*prog.ResourceType); ok && windowsResourceTypeIsSocket(typ) {
			resources[res.Res] = true
		}
	})
	return resources
}

func windowsResourceTypeIsSocket(typ *prog.ResourceType) bool {
	if typ == nil || typ.Desc == nil {
		return false
	}
	for _, kind := range typ.Desc.Kind {
		if strings.HasPrefix(kind, "SOCKET") {
			return true
		}
	}
	return false
}

func windowsAFDCollideScore(call *prog.Syscall) int {
	if call == nil {
		return 0
	}
	switch call.Name {
	case "WSARecv$accept", "WSASend$accept", "WSARecv$accept_pending",
		"WSASend$accept_pending", "WSARecv$tcp_pending", "WSASend$tcp_pending", "WSARecvEx$inet_accept",
		"recv$inet_accept", "send$inet_accept",
		"recv$inet_accept_updated", "send$inet_accept_updated",
		"AcceptEx$inet_tcp_pending",
		"WSAGetOverlappedResult$socket", "CancelIoEx$socket", "CancelIo$socket",
		"WSAGetOverlappedResult$accept_pending", "CancelIoEx$accept_pending", "CancelIo$accept_pending",
		"closesocket$accept_pending",
		"WSAGetOverlappedResult$accept_recv_pending", "CancelIoEx$accept_recv_pending", "CancelIo$accept_recv_pending",
		"closesocket$accept_recv_pending",
		"WSAGetOverlappedResult$accept_send_pending", "CancelIoEx$accept_send_pending", "CancelIo$accept_send_pending",
		"closesocket$accept_send_pending",
		"WSAGetOverlappedResult$tcp_recv_pending", "CancelIoEx$tcp_recv_pending", "CancelIo$tcp_recv_pending",
		"closesocket$tcp_recv_pending",
		"WSAGetOverlappedResult$tcp_send_pending", "CancelIoEx$tcp_send_pending", "CancelIo$tcp_send_pending",
		"closesocket$tcp_send_pending",
		"CreateIoCompletionPort$socket", "CreateIoCompletionPort$accept_pending",
		"CreateIoCompletionPort$accept_recv_pending", "CreateIoCompletionPort$accept_send_pending",
		"CreateIoCompletionPort$tcp_recv_pending", "CreateIoCompletionPort$tcp_send_pending",
		"CreateIoCompletionPort$connect_pending",
		"ConnectEx$inet_tcp_pending", "WSAGetOverlappedResult$connect_pending",
		"CancelIoEx$connect_pending", "CancelIo$connect_pending",
		"closesocket$connect_pending", "GetQueuedCompletionStatus$socket":
		return 80
	case "TransmitFile$inet_accept", "TransmitPackets$inet_accept",
		"setsockopt$update_accept_context":
		return 70
	case "WSAIoctl$sio_address_list_query", "WSAIoctl$sio_routing_interface_query",
		"WSAIoctl$sio_keepalive_vals", "WSAIoctl$sio_get_extension_function_pointer",
		"WSAEventSelect$tcp", "WSAEventSelect$accept",
		"WSAEnumNetworkEvents$tcp", "WSAEnumNetworkEvents$accept":
		return 60
	case "ConnectEx$inet_tcp", "ConnectEx$inet_tcp_reuse",
		"DisconnectEx$inet_tcp", "DisconnectEx$inet_tcp_reuse",
		"GetAcceptExSockaddrs$inet_tcp",
		"WSARecvMsg$udp":
		return 55
	case "WSASend$tcp", "WSARecv$tcp", "send$inet_tcp", "recv$inet_tcp":
		return 45
	case "WSASendTo$udp", "WSARecvFrom$udp", "sendto$udp_bound", "sendto$udp_connected",
		"recvfrom$udp_bound", "recvfrom$udp_connected", "send$inet_udp", "recv$inet_udp":
		return 40
	case "shutdown$tcp", "shutdown$accept",
		"shutdown$tcp_rd", "shutdown$tcp_wr", "shutdown$accept_rd", "shutdown$accept_wr",
		"getsockname$tcp", "getsockname$udp", "getsockname$accept",
		"getpeername$tcp", "getpeername$udp", "getpeername$accept",
		"select$afd_basic":
		return 30
	}
	return 0
}

func windowsAFDProgramHasDeepCall(p *prog.Prog) bool {
	if p == nil {
		return false
	}
	for _, call := range p.Calls {
		if call != nil && windowsAFDCollideScore(call.Meta) >= 40 {
			return true
		}
	}
	return false
}

func windowsShouldScheduleAFDImmediateCollide(p *prog.Prog, call int) bool {
	if p == nil || call < 0 || call >= len(p.Calls) {
		return false
	}
	return windowsAFDCollideScore(p.Calls[call].Meta) >= 55
}

func windowsShouldForceAFDTriageCall(origin string, p *prog.Prog, call int) bool {
	return strings.HasPrefix(origin, "collide:") && windowsShouldScheduleAFDImmediateCollide(p, call)
}

func windowsShouldSkipAFDTriageProgram(origin string, p *prog.Prog) bool {
	if p == nil {
		return false
	}
	for _, call := range p.Calls {
		if call != nil && call.Meta != nil && call.Meta.Attrs.NoGenerate {
			return true
		}
	}
	return false
}

func windowsShouldPersistAFDTriageCall(origin string, p *prog.Prog, call int) bool {
	if call < 0 || p == nil || call >= len(p.Calls) {
		return false
	}
	return strings.HasPrefix(origin, "collide:") && windowsAFDCollideScore(p.Calls[call].Meta) >= 55
}

func windowsResourceReuseScore(current *prog.Syscall, candidate *prog.ResultArg, p *prog.Prog, insertionPoint int) int {
	if current == nil || candidate == nil || p == nil {
		return 0
	}
	producer := windowsResourceProducer(candidate, p, insertionPoint)
	if producer == nil {
		return 0
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_TCP_ACCEPT_PENDING") {
		switch producer.Name {
		case "AcceptEx$inet_tcp_pending":
			return 40
		case "accept$inet_tcp", "socket$accept_tcp":
			return 10
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_TCP_ACCEPT_RECV_PENDING") {
		switch producer.Name {
		case "WSARecv$accept_pending":
			return 40
		case "accept$inet_tcp", "socket$accept_tcp":
			return 10
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_TCP_ACCEPT_SEND_PENDING") {
		switch producer.Name {
		case "WSASend$accept_pending":
			return 40
		case "accept$inet_tcp", "socket$accept_tcp":
			return 10
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_TCP_RECV_PENDING") {
		switch producer.Name {
		case "WSARecv$tcp_pending":
			return 40
		case "connect$inet_tcp", "socket$connected_tcp":
			return 10
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_TCP_SEND_PENDING") {
		switch producer.Name {
		case "WSASend$tcp_pending":
			return 40
		case "connect$inet_tcp", "socket$connected_tcp":
			return 10
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_TCP_CONNECTING") {
		switch producer.Name {
		case "ConnectEx$inet_tcp_pending":
			return 40
		case "connect$inet_tcp", "socket$connected_tcp":
			return 10
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_TCP_ACCEPTED_UPDATED") {
		switch producer.Name {
		case "setsockopt$update_accept_context":
			return 40
		case "AcceptEx$inet_tcp_pending":
			return 20
		case "accept$inet_tcp", "socket$accept_tcp":
			return 10
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_TCP_ACCEPTED") ||
		windowsCallUsesInputResourceKind(current, "SOCKET_ACCEPT") {
		switch producer.Name {
		case "accept$inet_tcp", "AcceptEx$inet_tcp":
			return 40
		case "socket$accept_tcp":
			return 10
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_TCP_CONNECTED") ||
		windowsCallUsesInputResourceKind(current, "SOCKET_CONNECTED") {
		switch producer.Name {
		case "connect$inet_tcp", "ConnectEx$inet_tcp":
			return 40
		case "socket$connected_tcp":
			return 10
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_TCP_DISCONNECTED_REUSABLE") {
		if producer.Name == "DisconnectEx$inet_tcp_reuse" {
			return 40
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_TCP_LISTENING") ||
		windowsCallUsesInputResourceKind(current, "SOCKET_LISTENER") {
		if producer.Name == "listen$inet_tcp" {
			return 40
		}
		if producer.Name == "socket$listener_tcp" {
			return 10
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_UDP_BOUND") {
		if producer.Name == "bind$inet_udp" {
			return 40
		}
		if producer.Name == "socket$bound_udp" {
			return 10
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_UDP_PEERED") {
		if producer.Name == "connect$inet_udp" {
			return 40
		}
		if producer.Name == "socket$connected_udp" {
			return 10
		}
	}
	if windowsCallUsesInputResourceKind(current, "SOCKET_UDP_CONNECTED") {
		if producer.Name == "connect$inet_udp" {
			return 40
		}
		if producer.Name == "socket$connected_udp" {
			return 10
		}
	}
	return 0
}

func windowsResourceProducer(candidate *prog.ResultArg, p *prog.Prog, insertionPoint int) *prog.Syscall {
	limit := len(p.Calls)
	if insertionPoint >= 0 && insertionPoint < limit {
		limit = insertionPoint
	}
	for i := 0; i < limit; i++ {
		call := p.Calls[i]
		if call == nil {
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
			return call.Meta
		}
	}
	return nil
}

func windowsSelectResourceCtor(current *prog.Syscall, resourceType string, ctors []prog.ResourceCtor) *prog.Syscall {
	if current == nil {
		return nil
	}
	preferred := map[string][]string{
		"SOCKET_TCP_CREATED":               {"socket$inet_tcp"},
		"SOCKET_TCP_BOUND":                 {"bind$inet_tcp"},
		"SOCKET_TCP_LISTENING":             {"listen$inet_tcp", "socket$listener_tcp"},
		"SOCKET_LISTENER":                  {"socket$listener_tcp", "listen$inet_tcp"},
		"SOCKET_TCP_CONNECTED":             {"connect$inet_tcp", "socket$connected_tcp", "ConnectEx$inet_tcp_reuse"},
		"SOCKET_CONNECTED":                 {"socket$connected_tcp", "connect$inet_tcp"},
		"SOCKET_TCP_DISCONNECTED_REUSABLE": {"DisconnectEx$inet_tcp_reuse"},
		"SOCKET_TCP_SHUTDOWN_RD":           {"shutdown$tcp_rd", "shutdown$accept_rd"},
		"SOCKET_TCP_SHUTDOWN_WR":           {"shutdown$tcp_wr", "shutdown$accept_wr"},
		"SOCKET_TCP_ACCEPTED":              {"accept$inet_tcp", "socket$accept_tcp"},
		"SOCKET_TCP_ACCEPT_PENDING":        {"AcceptEx$inet_tcp_pending"},
		"SOCKET_TCP_ACCEPTED_UPDATED":      {"setsockopt$update_accept_context"},
		"SOCKET_TCP_ACCEPT_RECV_PENDING":   {"WSARecv$accept_pending"},
		"SOCKET_TCP_ACCEPT_SEND_PENDING":   {"WSASend$accept_pending"},
		"SOCKET_TCP_RECV_PENDING":          {"WSARecv$tcp_pending"},
		"SOCKET_TCP_SEND_PENDING":          {"WSASend$tcp_pending"},
		"SOCKET_TCP_CONNECTING":            {"ConnectEx$inet_tcp_pending"},
		"SOCKET_ACCEPT":                    {"socket$accept_tcp", "accept$inet_tcp"},
		"SOCKET_UDP_CREATED":               {"socket$inet_udp"},
		"SOCKET_UDP_BOUND":                 {"bind$inet_udp", "socket$bound_udp"},
		"SOCKET_UDP_CONNECTED":             {"connect$inet_udp", "socket$connected_udp"},
		"SOCKET_UDP_PEERED":                {"connect$inet_udp", "socket$connected_udp"},
	}
	for _, name := range preferred[resourceType] {
		for _, ctor := range ctors {
			if ctor.Call != nil && ctor.Call.Name == name {
				return ctor.Call
			}
		}
	}
	return nil
}

func expandWindowsEnabledCalls(target *prog.Target, enabled map[*prog.Syscall]bool) map[*prog.Syscall]bool {
	if len(enabled) == 0 {
		return enabled
	}
	expanded := cloneEnabledCalls(enabled)
	addWindowsCall(expanded, target, "VirtualAlloc")
	changed := true
	for changed {
		changed = false
		for call := range cloneEnabledCalls(expanded) {
			for _, name := range windowsScaffoldCalls(target, call) {
				if addWindowsCall(expanded, target, name) {
					changed = true
				}
			}
		}
	}
	return expanded
}

func cloneEnabledCalls(enabled map[*prog.Syscall]bool) map[*prog.Syscall]bool {
	clone := make(map[*prog.Syscall]bool, len(enabled))
	for call, on := range enabled {
		if on {
			clone[call] = true
		}
	}
	return clone
}

func addWindowsCall(enabled map[*prog.Syscall]bool, target *prog.Target, name string) bool {
	if target == nil {
		return false
	}
	call := target.SyscallMap[name]
	if call == nil || enabled[call] {
		return false
	}
	enabled[call] = true
	return true
}

func windowsScaffoldCalls(target *prog.Target, call *prog.Syscall) []string {
	if target == nil || call == nil {
		return nil
	}
	socketRoles := windowsSocketScaffoldRolesFor(call)
	required := map[string]bool{}
	for _, name := range windowsAutomaticHelpers {
		if windowsCallMatches(target, call, name) {
			required[name] = true
		}
	}
	if socketRoles.has(windowsSocketScaffoldAny) {
		addWindowsNames(required,
			"WSAStartup", "WSACleanup", "closesocket$any",
		)
	}
	if socketRoles.has(windowsSocketScaffoldTCPAccept) {
		addWindowsNames(required,
			"socket$inet_tcp", "socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp",
			"bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "connect$inet_tcp",
		)
	}
	if socketRoles.has(windowsSocketScaffoldAcceptExPending) {
		addWindowsNames(required, "AcceptEx$inet_tcp_pending")
	}
	if socketRoles.has(windowsSocketScaffoldAcceptRecvPending) {
		addWindowsNames(required, "WSARecv$accept_pending")
	}
	if socketRoles.has(windowsSocketScaffoldAcceptSendPending) {
		addWindowsNames(required, "WSASend$accept_pending")
	}
	if socketRoles.has(windowsSocketScaffoldTCPRecvPending) {
		addWindowsNames(required, "WSARecv$tcp_pending")
	}
	if socketRoles.has(windowsSocketScaffoldTCPSendPending) {
		addWindowsNames(required, "WSASend$tcp_pending")
	}
	if socketRoles.has(windowsSocketScaffoldUpdatedAccept) {
		addWindowsNames(required, "AcceptEx$inet_tcp_pending", "setsockopt$update_accept_context")
	}
	if socketRoles.has(windowsSocketScaffoldConnectExPending) {
		addWindowsNames(required, "ConnectEx$inet_tcp_pending")
	}
	if socketRoles.has(windowsSocketScaffoldTCPConnected) {
		addWindowsNames(required, "socket$inet_tcp", "socket$connected_tcp", "connect$inet_tcp")
	}
	if socketRoles.has(windowsSocketScaffoldConnectEx) {
		addWindowsNames(required, "socket$connected_tcp", "bind$connectex_tcp")
	}
	if socketRoles.has(windowsSocketScaffoldConnectExPendingServer) {
		addWindowsNames(required, "socket$listener_tcp", "bind$inet_tcp", "listen$inet_tcp")
	}
	if socketRoles.has(windowsSocketScaffoldConnectExReuse) {
		addWindowsNames(required,
			"socket$listener_tcp", "socket$connected_tcp", "bind$inet_tcp",
			"listen$inet_tcp", "connect$inet_tcp", "DisconnectEx$inet_tcp_reuse",
		)
	}
	if windowsNeedsShutdownCloseScaffold(call) {
		addWindowsNames(required, windowsShutdownCloseScaffold(call.Name))
	}
	if socketRoles.has(windowsSocketScaffoldUDPConnected) {
		addWindowsNames(required, "socket$inet_udp", "socket$connected_udp", "connect$inet_udp")
	}
	if socketRoles.has(windowsSocketScaffoldUDPBound) {
		addWindowsNames(required, "socket$inet_udp", "socket$bound_udp", "bind$inet_udp")
	}
	if windowsNeedsPeerTrafficScaffold(call) {
		for _, name := range windowsPeerTrafficCallNames(call.Name) {
			required[name] = true
		}
	}
	if windowsNeedsFileScaffold(call) {
		addWindowsNames(required, "CreateFileA", "CreateFile2", "CloseHandle")
	}
	if windowsNeedsProcessScaffold(call) {
		addWindowsNames(required, "GetCurrentProcess$process")
	}
	if windowsNeedsThreadScaffold(call) {
		addWindowsNames(required, "GetCurrentThread$thread")
	}
	if windowsNeedsWaitScaffold(call) {
		addWindowsNames(required, "CreateEventA$manual", "CloseHandle")
	}
	if windowsNeedsWSAEventScaffold(call) {
		addWindowsNames(required, "WSACreateEvent", "WSACloseEvent")
	}
	if windowsNeedsSemaphoreScaffold(call) {
		addWindowsNames(required, "CreateSemaphoreA$sem", "CloseHandle")
	}
	if windowsNeedsTokenScaffold(call) {
		addWindowsNames(required, "GetCurrentProcess$process", "OpenProcessToken$process", "CloseHandle")
	}
	if windowsNeedsSectionScaffold(call) {
		addWindowsNames(required, "CreateFileMappingA$pagefile", "CloseHandle")
	}
	if windowsNeedsIOCPScaffold(call) {
		addWindowsNames(required, "CreateIoCompletionPort$create", "CloseHandle")
	}
	if windowsNeedsSocketIOCPScaffold(call) {
		addWindowsNames(required, "CreateIoCompletionPort$socket", "GetQueuedCompletionStatus$socket")
	}
	if windowsNeedsPipeScaffold(call) {
		addWindowsNames(required, "CreatePipe$anon", "CloseHandle")
	}
	if windowsNeedsFilePayloadScaffold(call) {
		addWindowsNames(required, "WriteFile")
	}
	if windowsNeedsNtFileBridge(call) {
		addWindowsNames(required, "NtReadFile", "NtWriteFile", "NtFsControlFile")
	}
	return windowsPresentCallNames(target, required)
}

func windowsCallMatches(target *prog.Target, current *prog.Syscall, want string) bool {
	meta := target.SyscallMap[want]
	return meta != nil && meta == current
}

func addWindowsNames(required map[string]bool, names ...string) {
	for _, name := range names {
		required[name] = true
	}
}

func windowsPresentCallNames(target *prog.Target, required map[string]bool) []string {
	if len(required) == 0 {
		return nil
	}
	var names []string
	for _, name := range windowsAutomaticHelpers {
		if required[name] && target.SyscallMap[name] != nil {
			names = append(names, name)
			delete(required, name)
		}
	}
	for _, name := range []string{
		"bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "connect$inet_tcp",
		"AcceptEx$inet_tcp_pending", "setsockopt$update_accept_context",
		"shutdown$tcp_rd", "shutdown$tcp_wr", "shutdown$accept_rd", "shutdown$accept_wr",
		"closesocket$tcp_shutdown_rd", "closesocket$tcp_shutdown_wr",
		"bind$connectex_tcp", "ConnectEx$inet_tcp_pending", "bind$inet_udp", "connect$inet_udp",
		"send$inet_tcp", "send$inet_udp", "send$inet_accept", "send$inet_accept_updated",
		"sendto$udp_connected", "sendto$udp_bound",
		"recv$inet_accept_updated",
		"WSASend$tcp", "WSASend$tcp_pending", "WSASend$accept", "WSASend$accept_pending", "WSASendTo$udp",
		"WSARecv$tcp_pending", "WSARecv$accept_pending",
		"WSACreateEvent", "WSACloseEvent", "WSAResetEvent",
		"CreateIoCompletionPort$socket", "CreateIoCompletionPort$accept_pending",
		"CreateIoCompletionPort$accept_recv_pending", "CreateIoCompletionPort$accept_send_pending",
		"CreateIoCompletionPort$tcp_recv_pending", "CreateIoCompletionPort$tcp_send_pending",
		"CreateIoCompletionPort$connect_pending",
		"GetQueuedCompletionStatus$socket",
		"WSAGetOverlappedResult$socket", "WSAGetOverlappedResult$accept_pending",
		"WSAGetOverlappedResult$accept_recv_pending", "WSAGetOverlappedResult$accept_send_pending",
		"WSAGetOverlappedResult$tcp_recv_pending", "WSAGetOverlappedResult$tcp_send_pending",
		"WSAGetOverlappedResult$connect_pending",
		"CancelIoEx$socket", "CancelIoEx$accept_pending", "CancelIoEx$accept_recv_pending",
		"CancelIoEx$accept_send_pending", "CancelIoEx$tcp_recv_pending", "CancelIoEx$tcp_send_pending",
		"CancelIoEx$connect_pending",
		"CancelIo$socket", "CancelIo$accept_pending",
		"CancelIo$accept_recv_pending", "CancelIo$accept_send_pending",
		"CancelIo$tcp_recv_pending", "CancelIo$tcp_send_pending", "CancelIo$connect_pending",
		"closesocket$accept_pending", "closesocket$accept_recv_pending",
		"closesocket$accept_send_pending", "closesocket$tcp_recv_pending",
		"closesocket$tcp_send_pending", "closesocket$connect_pending",
		"WriteFile",
		"NtReadFile", "NtWriteFile", "NtFsControlFile",
		"SetEvent$event", "ResetEvent$event",
		"WaitForSingleObject$wait", "WaitForSingleObjectEx$wait",
		"ReleaseSemaphore$sem",
		"OpenProcessToken$process", "OpenThreadToken$thread",
		"GetTokenInformation$token",
		"CreateFileMappingA$file", "CreateFileMappingA$pagefile",
		"MapViewOfFile$section",
		"CreateIoCompletionPort$create", "CreateIoCompletionPort$associate",
		"PostQueuedCompletionStatus$iocp", "GetQueuedCompletionStatus$iocp",
		"CreatePipe$anon", "ReadFile$pipe", "WriteFile$pipe",
	} {
		if required[name] && target.SyscallMap[name] != nil {
			names = append(names, name)
			delete(required, name)
		}
	}
	for name := range required {
		if target.SyscallMap[name] != nil {
			names = append(names, name)
		}
	}
	return names
}

type windowsSocketScaffoldRole int

const (
	windowsSocketScaffoldAny windowsSocketScaffoldRole = iota
	windowsSocketScaffoldTCPAccept
	windowsSocketScaffoldAcceptExPending
	windowsSocketScaffoldAcceptRecvPending
	windowsSocketScaffoldAcceptSendPending
	windowsSocketScaffoldTCPRecvPending
	windowsSocketScaffoldTCPSendPending
	windowsSocketScaffoldUpdatedAccept
	windowsSocketScaffoldConnectExPending
	windowsSocketScaffoldTCPConnected
	windowsSocketScaffoldConnectEx
	windowsSocketScaffoldConnectExPendingServer
	windowsSocketScaffoldConnectExReuse
	windowsSocketScaffoldUDPConnected
	windowsSocketScaffoldUDPBound
)

type windowsSocketScaffoldRoles map[windowsSocketScaffoldRole]bool

func (roles windowsSocketScaffoldRoles) add(role windowsSocketScaffoldRole) {
	roles[role] = true
}

func (roles windowsSocketScaffoldRoles) has(role windowsSocketScaffoldRole) bool {
	return roles[role]
}

func windowsSocketScaffoldRolesFor(call *prog.Syscall) windowsSocketScaffoldRoles {
	roles := windowsSocketScaffoldRoles{}
	if call == nil {
		return roles
	}
	if windowsCallUsesInputResourcePrefix(call, "SOCKET") {
		roles.add(windowsSocketScaffoldAny)
	}
	windowsAddSocketScaffoldResourceRoles(call, roles)
	windowsAddSocketScaffoldCallRoles(call, roles)
	return roles
}

func windowsAddSocketScaffoldResourceRoles(call *prog.Syscall, roles windowsSocketScaffoldRoles) {
	if windowsCallUsesAnyInputResourceKind(call,
		"SOCKET_ACCEPT", "SOCKET_LISTENER",
		"SOCKET_TCP_ACCEPT_PENDING", "SOCKET_TCP_ACCEPTED_UPDATED",
		"SOCKET_TCP_ACCEPT_RECV_PENDING", "SOCKET_TCP_ACCEPT_SEND_PENDING",
		"SOCKET_TCP_ACCEPTED", "SOCKET_TCP_LISTENING") {
		roles.add(windowsSocketScaffoldTCPAccept)
	}
	if call.Name != "AcceptEx$inet_tcp_pending" &&
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_ACCEPT_PENDING") {
		roles.add(windowsSocketScaffoldAcceptExPending)
	}
	if call.Name != "WSARecv$accept_pending" &&
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_ACCEPT_RECV_PENDING") {
		roles.add(windowsSocketScaffoldAcceptRecvPending)
	}
	if call.Name != "WSASend$accept_pending" &&
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_ACCEPT_SEND_PENDING") {
		roles.add(windowsSocketScaffoldAcceptSendPending)
	}
	if call.Name != "WSARecv$tcp_pending" &&
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_RECV_PENDING") {
		roles.add(windowsSocketScaffoldTCPRecvPending)
	}
	if call.Name != "WSASend$tcp_pending" &&
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_SEND_PENDING") {
		roles.add(windowsSocketScaffoldTCPSendPending)
	}
	if call.Name != "setsockopt$update_accept_context" &&
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_ACCEPTED_UPDATED") {
		roles.add(windowsSocketScaffoldUpdatedAccept)
	}
	if call.Name != "ConnectEx$inet_tcp_pending" &&
		windowsCallUsesInputResourceKind(call, "SOCKET_TCP_CONNECTING") {
		roles.add(windowsSocketScaffoldConnectExPending)
	}
	if call.Name != "ConnectEx$inet_tcp" &&
		call.Name != "ConnectEx$inet_tcp_pending" &&
		!windowsCallUsesInputResourceKind(call, "SOCKET_TCP_CONNECTING") &&
		!windowsCallUsesAnyInputResourceKind(call, "SOCKET_TCP_RECV_PENDING", "SOCKET_TCP_SEND_PENDING") &&
		windowsCallUsesAnyInputResourceKind(call, "SOCKET_CONNECTED", "SOCKET_TCP_CONNECTED") {
		roles.add(windowsSocketScaffoldTCPConnected)
	}
	if windowsCallUsesAnyInputResourceKind(call, "SOCKET_UDP_CONNECTED", "SOCKET_UDP_PEERED") {
		roles.add(windowsSocketScaffoldUDPConnected)
	}
	if windowsCallUsesInputResourceKind(call, "SOCKET_UDP_BOUND") {
		roles.add(windowsSocketScaffoldUDPBound)
	}
}

func windowsAddSocketScaffoldCallRoles(call *prog.Syscall, roles windowsSocketScaffoldRoles) {
	if strings.Contains(call.Name, "$inet_accept") {
		roles.add(windowsSocketScaffoldTCPAccept)
	}
	switch call.Name {
	case "accept$inet_tcp", "AcceptEx$inet_tcp", "AcceptEx$inet_tcp_pending",
		"setsockopt$update_accept_context", "GetAcceptExSockaddrs$inet_tcp":
		roles.add(windowsSocketScaffoldTCPAccept)
	case "ConnectEx$inet_tcp", "ConnectEx$inet_tcp_pending":
		roles.add(windowsSocketScaffoldConnectEx)
	case "ConnectEx$inet_tcp_reuse":
		roles.add(windowsSocketScaffoldConnectExReuse)
	}
	if call.Name == "ConnectEx$inet_tcp_pending" {
		roles.add(windowsSocketScaffoldConnectExPendingServer)
	}
}

func windowsNeedsShutdownCloseScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	return windowsShutdownCloseScaffold(call.Name) != ""
}

func windowsShutdownCloseScaffold(name string) string {
	switch name {
	case "shutdown$tcp_rd", "shutdown$accept_rd":
		return "closesocket$tcp_shutdown_rd"
	case "shutdown$tcp_wr", "shutdown$accept_wr":
		return "closesocket$tcp_shutdown_wr"
	default:
		return ""
	}
}

func windowsNeedsPeerTrafficScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	switch call.Name {
	case "recv$inet_tcp", "WSARecv$tcp", "WSARecv$tcp_pending",
		"recv$inet_udp", "recvfrom$udp_bound", "recvfrom$udp_connected", "WSARecvFrom$udp", "WSARecvMsg$udp",
		"recv$inet_accept", "recv$inet_accept_updated", "WSARecv$accept", "WSARecv$accept_pending",
		"WSARecvEx$inet_accept":
		return true
	}
	return false
}

func windowsPeerTrafficCallNames(name string) []string {
	switch name {
	case "recv$inet_tcp", "WSARecv$tcp", "WSARecv$tcp_pending":
		return []string{"send$inet_accept", "WSASend$accept"}
	case "recv$inet_udp", "recvfrom$udp_bound", "WSARecvFrom$udp", "WSARecvMsg$udp":
		return []string{"send$inet_udp", "sendto$udp_connected", "WSASendTo$udp"}
	case "recvfrom$udp_connected":
		return []string{"sendto$udp_bound"}
	case "recv$inet_accept", "recv$inet_accept_updated", "WSARecv$accept", "WSARecv$accept_pending",
		"WSARecvEx$inet_accept":
		return []string{"send$inet_tcp", "WSASend$tcp"}
	default:
		return nil
	}
}

func windowsNeedsFileScaffold(call *prog.Syscall) bool {
	return windowsCallUsesInputResourcePrefix(call, "FILE_HANDLE")
}

func windowsNeedsProcessScaffold(call *prog.Syscall) bool {
	return windowsCallUsesInputResourceKind(call, "PROCESS_HANDLE")
}

func windowsNeedsThreadScaffold(call *prog.Syscall) bool {
	return windowsCallUsesInputResourceKind(call, "THREAD_HANDLE")
}

func windowsNeedsWSAEventScaffold(call *prog.Syscall) bool {
	return windowsCallUsesInputResourceKind(call, "WSAEVENT_HANDLE")
}

func windowsNeedsSocketIOCPScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	switch call.Name {
	case "GetQueuedCompletionStatus$socket":
		return true
	}
	return false
}

func windowsNeedsWaitScaffold(call *prog.Syscall) bool {
	if windowsNeedsWSAEventScaffold(call) {
		return false
	}
	return windowsCallUsesInputResourceKind(call, "WAIT_HANDLE") ||
		windowsCallUsesInputResourceKind(call, "EVENT_HANDLE")
}

func windowsNeedsSemaphoreScaffold(call *prog.Syscall) bool {
	return windowsCallUsesInputResourceKind(call, "SEMAPHORE_HANDLE")
}

func windowsNeedsTokenScaffold(call *prog.Syscall) bool {
	return windowsCallUsesInputResourceKind(call, "TOKEN_HANDLE")
}

func windowsNeedsSectionScaffold(call *prog.Syscall) bool {
	return windowsCallUsesInputResourceKind(call, "SECTION_HANDLE")
}

func windowsNeedsIOCPScaffold(call *prog.Syscall) bool {
	if windowsNeedsSocketIOCPScaffold(call) {
		return false
	}
	return windowsCallUsesInputResourceKind(call, "IOCP_HANDLE")
}

func windowsNeedsPipeScaffold(call *prog.Syscall) bool {
	return windowsCallUsesInputResourceKind(call, "PIPE_READ_HANDLE") ||
		windowsCallUsesInputResourceKind(call, "PIPE_WRITE_HANDLE")
}

func windowsNeedsFilePayloadScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	switch call.Name {
	case "TransmitFile$inet_accept", "WriteFile", "NtWriteFile",
		"NtFsControlFile$ntfs_set_zero_data", "NtFsControlFile$ntfs_query_allocated_ranges":
		return true
	}
	return false
}

func windowsNeedsNtFileBridge(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	switch call.Name {
	case "ReadFile", "WriteFile", "FlushFileBuffers", "SetFileInformationByHandle", "DeleteFileA":
		return true
	}
	return false
}

func windowsCallUsesInputResourcePrefix(call *prog.Syscall, prefix string) bool {
	if call == nil {
		return false
	}
	uses := false
	prog.ForeachCallType(call, func(typ prog.Type, ctx *prog.TypeCtx) {
		if ctx.Dir == prog.DirOut || ctx.Optional {
			return
		}
		res, ok := typ.(*prog.ResourceType)
		if !ok || res.Desc == nil {
			return
		}
		for _, kind := range res.Desc.Kind {
			if strings.HasPrefix(kind, prefix) {
				uses = true
				ctx.Stop = true
				return
			}
		}
	})
	return uses
}

func windowsCallUsesInputResourceKind(call *prog.Syscall, want string) bool {
	if call == nil {
		return false
	}
	uses := false
	prog.ForeachCallType(call, func(typ prog.Type, ctx *prog.TypeCtx) {
		if ctx.Dir == prog.DirOut || ctx.Optional {
			return
		}
		res, ok := typ.(*prog.ResourceType)
		if !ok || res.Desc == nil {
			return
		}
		for _, kind := range res.Desc.Kind {
			if kind == want {
				uses = true
				ctx.Stop = true
				return
			}
		}
	})
	return uses
}

func windowsCallUsesAnyInputResourceKind(call *prog.Syscall, wants ...string) bool {
	for _, want := range wants {
		if windowsCallUsesInputResourceKind(call, want) {
			return true
		}
	}
	return false
}

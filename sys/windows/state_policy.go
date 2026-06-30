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
		if !windowsHasConsistentAFDPrivateState(p) {
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

type windowsAFDPrivateState struct {
	kind      string
	bound     bool
	listening bool
	connected bool
	accepted  bool
	udpBound  bool
	udpPeered bool
	terminal  bool
	pending   map[string]bool
}

func (st *windowsAFDPrivateState) markPending(kind string) {
	if st == nil || kind == "" {
		return
	}
	if st.pending == nil {
		st.pending = make(map[string]bool)
	}
	st.pending[kind] = true
}

func (st *windowsAFDPrivateState) consumePending(kind string) bool {
	if st == nil || kind == "" || st.pending == nil || !st.pending[kind] {
		return false
	}
	delete(st.pending, kind)
	return true
}

func windowsHasConsistentAFDPrivateState(p *prog.Prog) bool {
	if p == nil {
		return true
	}
	stateByRoot := make(map[*prog.ResultArg]*windowsAFDPrivateState)
	for _, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		name := call.Meta.Name
		switch name {
		case "NtCreateFile$afd_tcp_endpoint":
			root := windowsFirstResourceArgWithPrefix(call.Args[0], "AFD_TCP")
			if root == nil {
				return false
			}
			stateByRoot[root] = &windowsAFDPrivateState{kind: "tcp"}
			continue
		case "NtCreateFile$afd_tcp_accept_slot":
			root := windowsFirstResourceArgWithPrefix(call.Args[0], "AFD_TCP_ACCEPT_SLOT")
			if root == nil {
				return false
			}
			stateByRoot[root] = &windowsAFDPrivateState{kind: "tcp-slot"}
			continue
		case "NtCreateFile$afd_udp_endpoint":
			root := windowsFirstResourceArgWithPrefix(call.Args[0], "AFD_UDP")
			if root == nil {
				return false
			}
			stateByRoot[root] = &windowsAFDPrivateState{kind: "udp"}
			continue
		}
		if !strings.Contains(name, "$afd_") {
			continue
		}
		tracked := windowsAFDPrivateStateTracksCall(name)
		root := windowsSemanticInputRoot(call, 0)
		if root == nil {
			if tracked {
				return false
			}
			continue
		}
		st := stateByRoot[root]
		if st == nil {
			if tracked {
				return false
			}
			continue
		}
		if st.terminal && windowsAFDModeledPendingKindByCleanup(name) == "" {
			return false
		}
		if !tracked {
			continue
		}
		switch {
		case windowsAFDIsTCPBindCall(name):
			if st.kind != "tcp" || st.bound || st.listening || st.connected || st.accepted {
				return false
			}
			st.bound = true
		case windowsAFDIsUDPBindCall(name):
			if st.kind != "udp" || st.udpBound || st.udpPeered {
				return false
			}
			st.udpBound = true
		case windowsAFDIsStartListenCall(name):
			if st.kind != "tcp" || !st.bound || st.listening || st.connected || st.accepted {
				return false
			}
			st.listening = true
		case windowsAFDIsWaitForListenCall(name):
			if st.kind != "tcp" || !st.listening || st.connected || st.accepted {
				return false
			}
			if windowsAFDIsPendingListenCall(name) {
				st.markPending("listen")
			}
		case windowsAFDIsConnectToListenerCall(name):
			if st.kind != "tcp" || !st.bound || st.listening || st.connected || st.accepted {
				return false
			}
			if !windowsAFDCallHasListeningNestedRoot(call, stateByRoot, root) {
				return false
			}
			st.connected = true
			windowsAFDMarkPendingByCall(st, name)
		case windowsAFDIsPlainTCPConnectCall(name):
			if st.kind != "tcp" || st.listening || st.connected || st.accepted {
				return false
			}
			st.connected = true
			windowsAFDMarkPendingByCall(st, name)
		case windowsAFDIsUDPConnectCall(name):
			if st.kind != "udp" || st.udpPeered {
				return false
			}
			st.udpPeered = true
			windowsAFDMarkPendingByCall(st, name)
		case windowsAFDIsAcceptCall(name):
			if st.kind != "tcp" || !st.listening || st.connected || st.accepted {
				return false
			}
			slotRoot := windowsAFDAcceptSlotRoot(call)
			if slotRoot == nil {
				return false
			}
			slotState := stateByRoot[slotRoot]
			if slotState == nil || slotState.kind != "tcp-slot" || slotState.accepted || slotState.terminal {
				return false
			}
			slotState.accepted = true
		case name == "NtDeviceIoControlFile$afd_get_unaccepted_connect_data_tcp":
			if st.kind != "tcp" || !st.listening {
				return false
			}
		case name == "NtDeviceIoControlFile$afd_set_information_nonblock_tcp_created":
			if st.kind != "tcp" || st.bound || st.listening || st.connected || st.accepted {
				return false
			}
		case name == "NtDeviceIoControlFile$afd_set_information_nonblock_tcp_bound":
			if st.kind != "tcp" || !st.bound || st.listening || st.connected || st.accepted {
				return false
			}
		case name == "NtDeviceIoControlFile$afd_set_information_nonblock_tcp_listening":
			if st.kind != "tcp" || !st.listening || st.connected || st.accepted {
				return false
			}
		case name == "NtDeviceIoControlFile$afd_set_information_nonblock_tcp_connected":
			if st.kind != "tcp" || !st.connected || st.accepted {
				return false
			}
		case name == "NtDeviceIoControlFile$afd_set_information_nonblock_tcp_accepted":
			if !st.accepted {
				return false
			}
		case name == "NtDeviceIoControlFile$afd_set_information_nonblock_udp_created":
			if st.kind != "udp" || st.udpBound || st.udpPeered {
				return false
			}
		case name == "NtDeviceIoControlFile$afd_set_information_nonblock_udp_bound":
			if st.kind != "udp" || !st.udpBound || st.udpPeered {
				return false
			}
		case name == "NtDeviceIoControlFile$afd_set_information_nonblock_udp_peered":
			if st.kind != "udp" || !st.udpPeered {
				return false
			}
		case windowsAFDIsAcceptDataPathCall(name):
			if !st.accepted {
				return false
			}
			windowsAFDMarkPendingByCall(st, name)
		case windowsAFDIsConnectedTCPDataPathCall(name):
			if st.kind != "tcp" || !st.connected {
				return false
			}
			windowsAFDMarkPendingByCall(st, name)
		case windowsAFDIsBoundUDPDataPathCall(name):
			if st.kind != "udp" || !st.udpBound {
				return false
			}
			windowsAFDMarkPendingByCall(st, name)
		case windowsAFDIsPeeredUDPDataPathCall(name):
			if st.kind != "udp" || !st.udpPeered {
				return false
			}
			windowsAFDMarkPendingByCall(st, name)
		case windowsAFDModeledPendingKindByCleanup(name) != "":
			if !st.consumePending(windowsAFDModeledPendingKindByCleanup(name)) {
				return false
			}
			if windowsAFDIsCloseLike(name) {
				st.terminal = true
			}
		case windowsAFDIsStateCloseCall(name):
			if !windowsAFDStateCloseMatches(st, name) {
				return false
			}
			st.terminal = true
		case windowsAFDIsTerminalTCPCall(name):
			if st.kind != "tcp" || (!st.connected && !st.accepted) {
				return false
			}
			st.terminal = true
		case windowsAFDIsTerminalUDPCall(name):
			if st.kind != "udp" || (!st.udpBound && !st.udpPeered) {
				return false
			}
			st.terminal = true
		}
	}
	return true
}

func windowsAFDPrivateStateTracksCall(name string) bool {
	switch {
	case windowsAFDIsTCPBindCall(name),
		windowsAFDIsUDPBindCall(name),
		windowsAFDIsStartListenCall(name),
		windowsAFDIsWaitForListenCall(name),
		windowsAFDIsConnectToListenerCall(name),
		windowsAFDIsPlainTCPConnectCall(name),
		windowsAFDIsUDPConnectCall(name),
		windowsAFDIsAcceptCall(name),
		windowsAFDIsAcceptDataPathCall(name),
		windowsAFDIsConnectedTCPDataPathCall(name),
		windowsAFDIsBoundUDPDataPathCall(name),
		windowsAFDIsPeeredUDPDataPathCall(name),
		windowsAFDModeledPendingKindByCleanup(name) != "",
		windowsAFDIsStateCloseCall(name),
		windowsAFDIsTerminalTCPCall(name),
		windowsAFDIsTerminalUDPCall(name):
		return true
	default:
		switch name {
		case "NtDeviceIoControlFile$afd_get_unaccepted_connect_data_tcp",
			"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_created",
			"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_bound",
			"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_listening",
			"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_connected",
			"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_accepted",
			"NtDeviceIoControlFile$afd_set_information_nonblock_udp_created",
			"NtDeviceIoControlFile$afd_set_information_nonblock_udp_bound",
			"NtDeviceIoControlFile$afd_set_information_nonblock_udp_peered":
			return true
		default:
			return false
		}
	}
}

func windowsAFDIsTCPBindCall(name string) bool {
	return strings.HasPrefix(name, "NtDeviceIoControlFile$afd_bind_tcp")
}

func windowsAFDIsUDPBindCall(name string) bool {
	return strings.HasPrefix(name, "NtDeviceIoControlFile$afd_bind_udp")
}

func windowsAFDIsStartListenCall(name string) bool {
	return strings.HasPrefix(name, "NtDeviceIoControlFile$afd_start_listen_tcp")
}

func windowsAFDIsWaitForListenCall(name string) bool {
	return strings.HasPrefix(name, "NtDeviceIoControlFile$afd_wait_for_listen_")
}

func windowsAFDIsPendingListenCall(name string) bool {
	return strings.Contains(name, "_pending_")
}

func windowsAFDIsConnectToListenerCall(name string) bool {
	if !strings.HasPrefix(name, "NtDeviceIoControlFile$afd_connect_tcp") {
		return false
	}
	return strings.Contains(name, "_listener")
}

func windowsAFDIsPlainTCPConnectCall(name string) bool {
	if windowsAFDIsConnectToListenerCall(name) {
		return false
	}
	switch {
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_connect_tcp"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_connectex_tcp"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_super_connect_tcp"):
		return true
	default:
		return false
	}
}

func windowsAFDIsUDPConnectCall(name string) bool {
	switch {
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_connect_udp"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_connectex_udp"):
		return true
	default:
		return false
	}
}

func windowsAFDIsAcceptCall(name string) bool {
	switch name {
	case "NtDeviceIoControlFile$afd_accept_tcp",
		"NtDeviceIoControlFile$afd_accept_tcp_nonblock",
		"NtDeviceIoControlFile$afd_super_accept_tcp",
		"NtDeviceIoControlFile$afd_super_accept_tcp_nonblock":
		return true
	default:
		return false
	}
}

func windowsAFDAcceptSlotRoot(call *prog.Call) *prog.ResultArg {
	if call == nil || len(call.Args) <= 6 {
		return nil
	}
	res := windowsFirstInputResourceArgWithPrefix(call.Args[6], "AFD_TCP_ACCEPT_SLOT")
	if res == nil {
		return nil
	}
	return res.Res
}

func windowsAFDCallHasListeningNestedRoot(call *prog.Call, stateByRoot map[*prog.ResultArg]*windowsAFDPrivateState,
	root *prog.ResultArg) bool {
	if call == nil || len(call.Args) <= 6 {
		return false
	}
	nested := windowsInputResourceRootsWithPrefix(call.Args[6], "AFD_TCP")
	for _, candidate := range nested {
		if candidate == nil || candidate == root {
			continue
		}
		state := stateByRoot[candidate]
		if state != nil && state.listening && !state.terminal {
			return true
		}
	}
	return false
}

func windowsAFDIsAcceptDataPathCall(name string) bool {
	switch {
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_accept"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_receive_accept"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_message_accept"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_transmit_file_accept"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_transmit_packets_accept"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_super_disconnect_accept"),
		strings.HasPrefix(name, "CloseHandle$afd_accept_"),
		name == "NtDeviceIoControlFile$afd_query_recv_accept",
		name == "NtDeviceIoControlFile$afd_query_handles_accept",
		name == "NtDeviceIoControlFile$afd_get_qos_accept",
		name == "NtDeviceIoControlFile$afd_event_select_accept",
		name == "NtDeviceIoControlFile$afd_event_select_accept_nonblock",
		name == "NtDeviceIoControlFile$afd_enum_network_events_accept",
		name == "NtDeviceIoControlFile$afd_enum_network_events_accept_nonblock",
		name == "NtDeviceIoControlFile$afd_poll_accept",
		name == "NtDeviceIoControlFile$afd_poll_accept_nonblock":
		return true
	default:
		return false
	}
}

func windowsAFDIsConnectedTCPDataPathCall(name string) bool {
	switch {
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_tcp"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_receive_tcp"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_message_tcp"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_transmit_file_tcp"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_transmit_packets_tcp"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_transmit_file_buffers_tcp"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_transmit_packets_file_tcp"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_super_disconnect_tcp"),
		name == "NtDeviceIoControlFile$afd_get_remote_address_tcp",
		name == "NtDeviceIoControlFile$afd_partial_disconnect_tcp",
		strings.HasPrefix(name, "CloseHandle$afd_tcp_connected"),
		name == "CloseHandle$afd_tcp_disconnected":
		return true
	default:
		return false
	}
}

func windowsAFDIsBoundUDPDataPathCall(name string) bool {
	switch {
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_datagram_udp_bound"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_receive_datagram_udp_bound"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_receive_message_udp_bound"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_message_udp_bound"),
		name == "NtDeviceIoControlFile$afd_address_list_query_udp",
		name == "NtDeviceIoControlFile$afd_routing_interface_query_udp",
		name == "NtDeviceIoControlFile$afd_address_list_change_udp",
		name == "NtDeviceIoControlFile$afd_address_list_change_udp_nonblock",
		name == "NtDeviceIoControlFile$afd_routing_interface_change_udp",
		name == "NtDeviceIoControlFile$afd_routing_interface_change_udp_nonblock",
		strings.HasPrefix(name, "CloseHandle$afd_udp_bound"):
		return true
	default:
		return false
	}
}

func windowsAFDIsPeeredUDPDataPathCall(name string) bool {
	switch {
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_udp_peer"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_receive_datagram_udp_peer"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_receive_message_udp_peer"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_message_udp_peer"),
		name == "NtDeviceIoControlFile$afd_query_handles_udp_peer",
		strings.HasPrefix(name, "CloseHandle$afd_udp_peered"):
		return true
	default:
		return false
	}
}

func windowsAFDMarkPendingByCall(st *windowsAFDPrivateState, name string) {
	if st == nil {
		return
	}
	switch {
	case windowsAFDIsPendingListenCall(name):
		st.markPending("listen")
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_connect_tcp") && strings.Contains(name, "_nonblock"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_connectex_tcp") && strings.Contains(name, "_nonblock"):
		st.markPending("connect")
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_receive_tcp_pending"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_receive_accept_pending"):
		st.markPending("receive")
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_receive_datagram_udp_") && strings.Contains(name, "_pending"):
		st.markPending("receive_datagram")
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_receive_message_udp_") && strings.Contains(name, "_pending"):
		st.markPending("receive_message")
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_transmit_file_"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_transmit_packets_"):
		st.markPending("transmit")
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_super_disconnect_"):
		st.markPending("super_disconnect")
	case name == "NtDeviceIoControlFile$afd_address_list_change_udp" ||
		name == "NtDeviceIoControlFile$afd_address_list_change_udp_nonblock":
		st.markPending("address_change")
	case name == "NtDeviceIoControlFile$afd_routing_interface_change_udp" ||
		name == "NtDeviceIoControlFile$afd_routing_interface_change_udp_nonblock":
		st.markPending("route_change")
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_udp_peer"):
		st.markPending("udp_send")
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_datagram_udp_bound"):
		st.markPending("udp_send_datagram")
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_message_udp_bound"):
		st.markPending("udp_send_message")
	case strings.HasPrefix(name, "NtDeviceIoControlFile$afd_send_message_udp_peer"):
		st.markPending("udp_peer_send_message")
	case name == "NtDeviceIoControlFile$afd_tli_type3_nobuf_pending":
		st.markPending("tli")
	}
}

func windowsAFDPendingKindByCleanup(name string) string {
	switch {
	case strings.Contains(name, "address_list_change_pending"):
		return "address_change"
	case strings.Contains(name, "routing_interface_change_pending"):
		return "route_change"
	case strings.Contains(name, "listen_irp_pending"):
		return "listen"
	case strings.Contains(name, "tcp_connect_pending"):
		return "connect"
	case strings.Contains(name, "tcp_receive_pending"),
		strings.Contains(name, "accept_receive_pending"):
		return "receive"
	case strings.Contains(name, "udp_receive_datagram_pending"):
		return "receive_datagram"
	case strings.Contains(name, "udp_receive_message_pending"):
		return "receive_message"
	case strings.Contains(name, "tcp_transmit_pending"),
		strings.Contains(name, "accept_transmit_pending"),
		strings.Contains(name, "transmit_closing"):
		return "transmit"
	case strings.Contains(name, "super_disconnect_pending"):
		return "super_disconnect"
	case strings.Contains(name, "udp_send_datagram_pending"):
		return "udp_send_datagram"
	case strings.Contains(name, "udp_peer_send_message_pending"):
		return "udp_peer_send_message"
	case strings.Contains(name, "udp_send_message_pending"):
		return "udp_send_message"
	case strings.Contains(name, "udp_send_pending"):
		return "udp_send"
	case strings.Contains(name, "tli_pending"):
		return "tli"
	case strings.Contains(name, "san_context"):
		return "san"
	default:
		return ""
	}
}

func windowsAFDModeledPendingKindByCleanup(name string) string {
	kind := windowsAFDPendingKindByCleanup(name)
	switch kind {
	case "tli", "san":
		return ""
	default:
		return kind
	}
}

func windowsAFDIsCloseLike(name string) bool {
	return strings.HasPrefix(name, "CloseHandle$afd_")
}

func windowsAFDIsStateCloseCall(name string) bool {
	if !strings.HasPrefix(name, "CloseHandle$afd_") {
		return false
	}
	if windowsAFDPendingKindByCleanup(name) != "" {
		return false
	}
	switch {
	case strings.Contains(name, "_tcp_created"),
		strings.Contains(name, "_tcp_bound"),
		strings.Contains(name, "_tcp_listen_backlog"),
		strings.Contains(name, "_tcp_listening"),
		strings.Contains(name, "_tcp_connected"),
		strings.Contains(name, "_tcp_disconnected"),
		strings.Contains(name, "_tcp_accepted"),
		strings.Contains(name, "_udp_created"),
		strings.Contains(name, "_udp_bound"),
		strings.Contains(name, "_udp_peered"):
		return true
	default:
		return false
	}
}

func windowsAFDStateCloseMatches(st *windowsAFDPrivateState, name string) bool {
	if st == nil {
		return false
	}
	switch {
	case strings.Contains(name, "_tcp_created"):
		return st.kind == "tcp" && !st.bound && !st.listening && !st.connected && !st.accepted
	case strings.Contains(name, "_tcp_bound"):
		return st.kind == "tcp" && st.bound && !st.listening && !st.connected && !st.accepted
	case strings.Contains(name, "_tcp_listen_backlog"),
		strings.Contains(name, "_tcp_listening"):
		return st.kind == "tcp" && st.listening
	case strings.Contains(name, "_tcp_connected"),
		strings.Contains(name, "_tcp_disconnected"):
		return st.kind == "tcp" && st.connected
	case strings.Contains(name, "_tcp_accepted"):
		return st.accepted
	case strings.Contains(name, "_udp_created"):
		return st.kind == "udp" && !st.udpBound && !st.udpPeered
	case strings.Contains(name, "_udp_bound"):
		return st.kind == "udp" && st.udpBound && !st.udpPeered
	case strings.Contains(name, "_udp_peered"):
		return st.kind == "udp" && st.udpPeered
	default:
		return false
	}
}

func windowsAFDIsTerminalTCPCall(name string) bool {
	switch {
	case name == "NtDeviceIoControlFile$afd_partial_disconnect_tcp",
		name == "NtDeviceIoControlFile$afd_unbind_tcp",
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_transmit_file_disconnect_"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_transmit_file_reuse_"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_transmit_packets_disconnect_"),
		strings.HasPrefix(name, "NtDeviceIoControlFile$afd_transmit_packets_reuse_"):
		return true
	default:
		return false
	}
}

func windowsAFDIsTerminalUDPCall(name string) bool {
	return name == "NtDeviceIoControlFile$afd_unconnect_udp" || name == "NtDeviceIoControlFile$afd_unbind_udp"
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

// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package windows

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
)

const (
	windowsSemanticConnectExIssued           = "connectex_issued"
	windowsSemanticAcceptExIssued            = "acceptex_issued"
	windowsSemanticIOCPAssociated            = "iocp_associated"
	windowsSemanticCompletionObserved        = "completion_observed"
	windowsSemanticIOCPCompletion            = "iocp_completion_observed"
	windowsSemanticOverlappedResult          = "overlapped_result_observed"
	windowsSemanticCancelRequested           = "cancel_requested"
	windowsSemanticCancelOverlappedRequested = "cancel_overlapped_requested"
	windowsSemanticConnectContextUpdated     = "connect_context_updated"
	windowsSemanticAcceptContextUpdated      = "accept_context_updated"
	windowsSemanticPendingClosed             = "pending_closed"
	windowsSemanticConnectExLocalDriver      = "connectex_local_driver"
	windowsSemanticConnectExVNetDriver       = "connectex_vnet_driver"
	windowsSemanticAcceptExLocalDriver       = "acceptex_local_driver"
	windowsSemanticAcceptExVNetDriver        = "acceptex_vnet_driver"
	windowsSemanticSendRecvLocalDriver       = "sendrecv_local_driver"
)

type windowsPendingIssue struct {
	kind    string
	ovArg   int
	sockArg int
}

type windowsSockaddrIn struct {
	port uint64
	addr uint64
}

type windowsPriorCall struct {
	idx  int
	name string
}

func windowsAFDSemanticStateModel(p *prog.Prog, insertionPoint int) *prog.SemanticState {
	st := prog.NewSemanticState(p, insertionPoint)
	if p == nil {
		return st
	}
	opsBySocket := make(map[*prog.ResultArg]*prog.SemanticOperation)
	opsByConnectedSocket := make(map[*prog.ResultArg]*prog.SemanticOperation)
	opsByAcceptedSocket := make(map[*prog.ResultArg]*prog.SemanticOperation)
	acceptExOpByOutputBuffer := make(map[uint64]*prog.SemanticOperation)
	acceptedSocketsWithPeer := make(map[*prog.ResultArg]bool)
	opsByIOCP := make(map[*prog.ResultArg][]*prog.SemanticOperation)
	iocpByBaseSocket := make(map[*prog.ResultArg]*prog.ResultArg)
	acceptExListenerByOp := make(map[*prog.SemanticOperation]*prog.ResultArg)
	connectExMaxPointer := make(map[*prog.SemanticOperation]uint64)
	eventSelectBySocket := make(map[*prog.ResultArg]*prog.ResultArg)
	tcpBinds := make(map[*prog.ResultArg]windowsSockaddrIn)
	tcpListeners := make(map[windowsSockaddrIn]bool)
	tcpListenerAddrs := make(map[*prog.ResultArg]windowsSockaddrIn)
	tcpLocalConnects := make(map[windowsSockaddrIn]bool)
	tcpConnectAddrs := make(map[*prog.ResultArg]windowsSockaddrIn)
	connectExAddrs := make(map[*prog.SemanticOperation]windowsSockaddrIn)
	acceptedSocketAddrs := make(map[*prog.ResultArg]windowsSockaddrIn)
	closedAcceptedPeerAddrs := make(map[windowsSockaddrIn]bool)
	tcpRecvLocalDriver := false
	acceptRecvLocalDriver := false
	var priorNonConnectExCalls []windowsPriorCall
	var priorNonAcceptExCalls []windowsPriorCall
	hasConnectEx := false
	hasAcceptEx := false
	acceptExProgram := false
	for idx := 0; idx < st.InsertionPoint; idx++ {
		call := p.Calls[idx]
		if call == nil || call.Meta == nil {
			continue
		}
		if issue, ok := windowsPendingIssueByCall(call.Meta.Name); ok && issue.kind == "acceptex" {
			acceptExProgram = true
			break
		}
	}

	for idx := 0; idx < st.InsertionPoint; idx++ {
		call := p.Calls[idx]
		if call == nil || call.Meta == nil {
			continue
		}
		name := call.Meta.Name
		if !windowsSemanticConnectExChainCallAllowed(name) {
			if hasConnectEx {
				st.AddViolation(idx, name+" inside ConnectEx chain")
			} else {
				priorNonConnectExCalls = append(priorNonConnectExCalls, windowsPriorCall{idx: idx, name: name})
			}
		}
		if !windowsSemanticAcceptExChainCallAllowed(name) {
			if hasAcceptEx {
				st.AddViolation(idx, name+" inside AcceptEx chain")
			} else {
				priorNonAcceptExCalls = append(priorNonAcceptExCalls, windowsPriorCall{idx: idx, name: name})
			}
		}
		if strings.HasPrefix(name, "ConnectEx$inet_tcp") &&
			!windowsSemanticHasPreparedConnectExSocket(call, p, idx) {
			st.AddViolation(idx, "ConnectEx without prepared socket")
		}
		connectExHasLocalDriver := strings.HasPrefix(name, "ConnectEx$inet_tcp") &&
			windowsSemanticHasMatchingListener(call, tcpListeners)
		acceptExHasLocalDriver := name == "AcceptEx$inet_tcp_pending" &&
			windowsSemanticAcceptExHasLocalDriver(call, tcpListenerAddrs, tcpLocalConnects)
		if name == "bind$inet_tcp" {
			windowsSemanticBindTCP(st, tcpBinds, call, p, idx)
		}
		if name == "bind$connectex_tcp" {
			windowsSemanticBindConnectExTCP(st, call, p, idx)
		}
		if name == "connect$inet_tcp_nonblock" &&
			!windowsSemanticArgProducedBy(call, 0, p, idx, "ioctlsocket$fionbio_tcp_created") {
			st.AddViolation(idx, name+" without FIONBIO-created socket")
		}
		if name == "connect$inet_tcp" || name == "connect$inet_tcp_nonblock" {
			windowsSemanticConnectTCP(st, tcpListeners, tcpLocalConnects, tcpConnectAddrs, call, idx)
		}
		if name == "send$inet_accept" || name == "send$inet_accept_updated" {
			tcpRecvLocalDriver = true
		}
		if name == "send$inet_tcp" {
			acceptRecvLocalDriver = true
		}
		if strings.HasPrefix(name, "ioctlsocket$fionbio") {
			windowsSemanticRejectDefaultResourceConversion(st, call, idx)
		}
		if issue, ok := windowsPendingIssueByCall(name); ok {
			if issue.kind == "connectex" {
				hasConnectEx = true
				for _, prior := range priorNonConnectExCalls {
					st.AddViolation(prior.idx, prior.name+" before ConnectEx chain")
				}
			}
			if issue.kind == "acceptex" {
				hasAcceptEx = true
				for _, prior := range priorNonAcceptExCalls {
					st.AddViolation(prior.idx, prior.name+" before AcceptEx chain")
				}
			}
			windowsSemanticIssuePending(st, opsBySocket, opsByIOCP, iocpByBaseSocket, acceptExListenerByOp,
				acceptExOpByOutputBuffer,
				connectExMaxPointer, tcpConnectAddrs, connectExAddrs, closedAcceptedPeerAddrs, call, p, idx, issue,
				connectExHasLocalDriver, acceptExHasLocalDriver, tcpRecvLocalDriver, acceptRecvLocalDriver)
			continue
		}
		switch {
		case strings.HasPrefix(name, "CreateIoCompletionPort$"):
			windowsSemanticAssociateIOCP(st, opsBySocket, opsByIOCP, iocpByBaseSocket, call, idx)
		case name == "GetQueuedCompletionStatus$socket":
			windowsSemanticObserveIOCPCompletion(st, opsByIOCP, connectExMaxPointer, call, idx)
		case strings.HasPrefix(name, "WSAGetOverlappedResult$"):
			windowsSemanticObserveOverlappedResult(st, opsBySocket, connectExMaxPointer, call, idx)
		case strings.HasPrefix(name, "CancelIoEx$"):
			windowsSemanticCancelOverlapped(st, opsBySocket, call, idx)
		case strings.HasPrefix(name, "CancelIo$"):
			windowsSemanticCancelSocket(st, opsBySocket, call, idx)
		case windowsSemanticIsPendingCloseCall(name):
			windowsSemanticClosePending(st, opsBySocket, call, idx)
		case name == "listen$inet_tcp":
			windowsSemanticListenTCP(st, tcpBinds, tcpListeners, tcpListenerAddrs, call, p, idx)
		case name == "ioctlsocket$fionbio_listener":
			windowsSemanticRecordListenerConversion(tcpListenerAddrs, call)
		case name == "accept$inet_tcp":
			windowsSemanticAcceptTCP(acceptedSocketAddrs, tcpListenerAddrs, call)
		case name == "accept$inet_tcp_nonblock":
			windowsSemanticAcceptTCPNonblock(acceptedSocketsWithPeer, acceptedSocketAddrs, tcpListenerAddrs,
				tcpLocalConnects, call)
		case name == "ioctlsocket$fionbio_accept_nonblock":
			windowsSemanticRecordAcceptedSocketConversion(acceptedSocketsWithPeer, call)
			windowsSemanticRecordAcceptedAddrConversion(acceptedSocketAddrs, call)
		case name == "closesocket$any":
			windowsSemanticRecordAcceptedPeerClose(acceptedSocketAddrs, closedAcceptedPeerAddrs, call)
		case name == "setsockopt$update_connect_context":
			windowsSemanticUpdateConnectContext(st, opsBySocket, opsByConnectedSocket, tcpConnectAddrs,
				connectExAddrs, call, idx)
		case name == "setsockopt$update_accept_context":
			windowsSemanticUpdateAcceptContext(st, opsBySocket, opsByAcceptedSocket, acceptExListenerByOp, call, idx)
		case name == "GetAcceptExSockaddrs$inet_tcp":
			windowsSemanticGetAcceptExSockaddrs(st, acceptExOpByOutputBuffer, call, idx)
		case windowsSemanticIsEventSelectCall(name):
			windowsSemanticRecordEventSelect(st, eventSelectBySocket, call, idx)
		case windowsSemanticIsEnumNetworkEventsCall(name):
			windowsSemanticValidateEnumNetworkEvents(st, eventSelectBySocket, call, idx)
		case windowsSemanticIsPrivatePollCall(name):
			windowsSemanticValidatePrivatePoll(st, call, idx)
		case name == "syz_emit_ethernet$windows":
			windowsSemanticBumpActiveConnectExMaxPointer(connectExMaxPointer, opsBySocket, call)
		case strings.HasPrefix(name, "syz_extract_tcp_res$windows"):
			windowsSemanticMarkAcceptExVNetDriver(opsBySocket)
			windowsSemanticMarkConnectExVNetDriver(opsBySocket)
			windowsSemanticBumpActiveConnectExMaxPointer(connectExMaxPointer, opsBySocket, call)
		default:
			windowsSemanticRejectInvalidAcceptExTCPUse(st, opsBySocket, acceptExProgram, call, idx)
			windowsSemanticRejectDirectConnectedUse(st, opsBySocket, opsByConnectedSocket,
				connectExMaxPointer, call, idx)
			windowsSemanticRejectDirectAcceptUpdatedUse(st, opsByAcceptedSocket, call, idx)
			windowsSemanticRejectAcceptedUseWithoutPeer(st, acceptedSocketsWithPeer, call, idx)
		}
	}
	if st.InsertionPoint == len(p.Calls) {
		windowsSemanticValidatePendingOperations(st)
	}
	return st
}

func windowsSemanticBindTCP(st *prog.SemanticState, tcpBinds map[*prog.ResultArg]windowsSockaddrIn,
	call *prog.Call, p *prog.Prog, idx int) {
	if call.Ret == nil {
		st.AddViolation(idx, call.Meta.Name+" without bound socket resource")
		return
	}
	if !windowsSemanticArgProducedByAny(call, 0, p, idx, "socket$inet_tcp", "socket$listener_tcp") {
		st.AddViolation(idx, call.Meta.Name+" without TCP socket")
		return
	}
	addr, ok := windowsSemanticSockaddrIn(call, 1)
	if !ok {
		st.AddViolation(idx, call.Meta.Name+" without sockaddr_in")
		return
	}
	tcpBinds[call.Ret] = addr
}

func windowsSemanticBindConnectExTCP(st *prog.SemanticState, call *prog.Call, p *prog.Prog, idx int) {
	if call.Ret == nil {
		st.AddViolation(idx, call.Meta.Name+" without bound socket resource")
		return
	}
	if !windowsSemanticArgProducedBy(call, 0, p, idx, "socket$inet_tcp") {
		st.AddViolation(idx, call.Meta.Name+" without TCP socket")
		return
	}
	if _, ok := windowsSemanticSockaddrIn(call, 1); !ok {
		st.AddViolation(idx, call.Meta.Name+" without sockaddr_in")
		return
	}
}

func windowsSemanticListenTCP(st *prog.SemanticState, tcpBinds map[*prog.ResultArg]windowsSockaddrIn,
	tcpListeners map[windowsSockaddrIn]bool, tcpListenerAddrs map[*prog.ResultArg]windowsSockaddrIn,
	call *prog.Call, p *prog.Prog, idx int) {
	root := windowsSemanticInputRoot(call, 0)
	addr, ok := tcpBinds[root]
	if root == nil || !ok {
		if windowsSemanticArgProducedBy(call, 0, p, idx, "socket$listener_tcp") {
			return
		}
		st.AddViolation(idx, call.Meta.Name+" without TCP bind")
		return
	}
	if call.Ret != nil {
		tcpListeners[addr] = true
		tcpListenerAddrs[call.Ret] = addr
	}
	tcpListeners[addr] = true
	tcpListenerAddrs[root] = addr
}

func windowsSemanticConnectTCP(st *prog.SemanticState, tcpListeners map[windowsSockaddrIn]bool,
	tcpLocalConnects map[windowsSockaddrIn]bool, tcpConnectAddrs map[*prog.ResultArg]windowsSockaddrIn,
	call *prog.Call, idx int) {
	root := windowsSemanticInputRoot(call, 0)
	if root == nil {
		st.AddViolation(idx, call.Meta.Name+" without TCP socket")
		return
	}
	addr, ok := windowsSemanticSockaddrIn(call, 1)
	if !ok {
		return
	}
	if !windowsSemanticHasLocalListener(addr, tcpListeners) {
		st.AddViolation(idx, call.Meta.Name+" without local listener")
	}
	tcpLocalConnects[addr] = true
	if call.Ret != nil {
		tcpConnectAddrs[call.Ret] = addr
	}
}

func windowsSemanticRecordListenerConversion(tcpListenerAddrs map[*prog.ResultArg]windowsSockaddrIn,
	call *prog.Call) {
	if call.Ret == nil {
		return
	}
	root := windowsSemanticInputRoot(call, 0)
	if root == nil {
		return
	}
	addr, ok := tcpListenerAddrs[root]
	if ok {
		tcpListenerAddrs[call.Ret] = addr
	}
}

func windowsSemanticRejectDefaultResourceConversion(st *prog.SemanticState, call *prog.Call, idx int) {
	if call == nil || call.Ret == nil {
		return
	}
	if windowsSemanticInputRoot(call, 0) == nil {
		st.AddViolation(idx, call.Meta.Name+" from default socket")
	}
}

func windowsSemanticAcceptTCP(acceptedSocketAddrs map[*prog.ResultArg]windowsSockaddrIn,
	listeners map[*prog.ResultArg]windowsSockaddrIn, call *prog.Call) {
	if call.Ret == nil {
		return
	}
	listener := windowsSemanticInputRoot(call, 0)
	if listener == nil {
		return
	}
	if addr, ok := listeners[listener]; ok {
		acceptedSocketAddrs[call.Ret] = addr
	}
}

func windowsSemanticAcceptTCPNonblock(acceptedSocketsWithPeer map[*prog.ResultArg]bool,
	acceptedSocketAddrs map[*prog.ResultArg]windowsSockaddrIn,
	listeners map[*prog.ResultArg]windowsSockaddrIn, tcpLocalConnects map[windowsSockaddrIn]bool,
	call *prog.Call) {
	if call.Ret == nil {
		return
	}
	listener := windowsSemanticInputRoot(call, 0)
	addr, ok := listeners[listener]
	if ok {
		acceptedSocketAddrs[call.Ret] = addr
	}
	acceptedSocketsWithPeer[call.Ret] = ok && windowsSemanticHasLocalConnect(addr, tcpLocalConnects)
}

func windowsSemanticRecordAcceptedSocketConversion(acceptedSocketsWithPeer map[*prog.ResultArg]bool,
	call *prog.Call) {
	if call.Ret == nil {
		return
	}
	root := windowsSemanticInputRoot(call, 0)
	if root == nil {
		return
	}
	hasPeer, ok := acceptedSocketsWithPeer[root]
	if ok {
		acceptedSocketsWithPeer[call.Ret] = hasPeer
	}
}

func windowsSemanticRecordAcceptedAddrConversion(acceptedSocketAddrs map[*prog.ResultArg]windowsSockaddrIn,
	call *prog.Call) {
	if call.Ret == nil {
		return
	}
	root := windowsSemanticInputRoot(call, 0)
	if root == nil {
		return
	}
	addr, ok := acceptedSocketAddrs[root]
	if ok {
		acceptedSocketAddrs[call.Ret] = addr
	}
}

func windowsSemanticRecordAcceptedPeerClose(acceptedSocketAddrs map[*prog.ResultArg]windowsSockaddrIn,
	closedAcceptedPeerAddrs map[windowsSockaddrIn]bool, call *prog.Call) {
	root := windowsSemanticInputRoot(call, 0)
	if root == nil {
		return
	}
	addr, ok := acceptedSocketAddrs[root]
	if ok {
		closedAcceptedPeerAddrs[addr] = true
	}
}

func windowsPendingIssueByCall(name string) (windowsPendingIssue, bool) {
	switch name {
	case "ConnectEx$inet_tcp_pending":
		return windowsPendingIssue{kind: "connectex", ovArg: 6, sockArg: 0}, true
	case "ConnectEx$inet_tcp_reuse":
		return windowsPendingIssue{kind: "connectex", ovArg: 6, sockArg: 0}, true
	case "DisconnectEx$inet_tcp_reuse":
		return windowsPendingIssue{kind: "disconnect_reuse", ovArg: 1, sockArg: 0}, true
	case "AcceptEx$inet_tcp_pending":
		return windowsPendingIssue{kind: "acceptex", ovArg: 7, sockArg: 1}, true
	case "WSARecv$accept_pending":
		return windowsPendingIssue{kind: "accept_recv", ovArg: 5, sockArg: 0}, true
	case "WSASend$accept_pending":
		return windowsPendingIssue{kind: "accept_send", ovArg: 5, sockArg: 0}, true
	case "WSARecv$tcp_pending":
		return windowsPendingIssue{kind: "tcp_recv", ovArg: 5, sockArg: 0}, true
	case "WSASend$tcp_pending":
		return windowsPendingIssue{kind: "tcp_send", ovArg: 5, sockArg: 0}, true
	default:
		return windowsPendingIssue{}, false
	}
}

func windowsSemanticIssuePending(st *prog.SemanticState, opsBySocket map[*prog.ResultArg]*prog.SemanticOperation,
	opsByIOCP map[*prog.ResultArg][]*prog.SemanticOperation, iocpByBaseSocket map[*prog.ResultArg]*prog.ResultArg,
	acceptExListenerByOp map[*prog.SemanticOperation]*prog.ResultArg,
	acceptExOpByOutputBuffer map[uint64]*prog.SemanticOperation,
	connectExMaxPointer map[*prog.SemanticOperation]uint64, tcpConnectAddrs map[*prog.ResultArg]windowsSockaddrIn,
	connectExAddrs map[*prog.SemanticOperation]windowsSockaddrIn,
	closedAcceptedPeerAddrs map[windowsSockaddrIn]bool, call *prog.Call, p *prog.Prog, idx int,
	issue windowsPendingIssue, connectExHasLocalDriver bool, acceptExHasLocalDriver bool,
	tcpRecvLocalDriver bool, acceptRecvLocalDriver bool) {
	ov, ok := windowsSemanticPointerAddress(call, issue.ovArg)
	if !ok {
		st.AddViolation(idx, call.Meta.Name+" without non-null OVERLAPPED")
		return
	}
	if issue.kind == "connectex" && !windowsSemanticOverlappedZero(call, issue.ovArg) {
		st.AddViolation(idx, call.Meta.Name+" with non-zero OVERLAPPED")
		return
	}
	if issue.kind == "disconnect_reuse" && !windowsSemanticOverlappedZero(call, issue.ovArg) {
		st.AddViolation(idx, call.Meta.Name+" with non-zero OVERLAPPED")
		return
	}
	if issue.kind == "connectex" && !windowsSemanticConnectExSendBufferValid(call) {
		st.AddViolation(idx, call.Meta.Name+" without valid send buffer")
		return
	}
	if issue.kind == "disconnect_reuse" && !windowsSemanticDisconnectExReuseArgsValid(call) {
		st.AddViolation(idx, call.Meta.Name+" with invalid reuse arguments")
		return
	}
	if issue.kind == "disconnect_reuse" &&
		!windowsSemanticDisconnectExReusePeerClosed(call, tcpConnectAddrs, closedAcceptedPeerAddrs) {
		st.AddViolation(idx, call.Meta.Name+" without closed accepted peer")
		return
	}
	if issue.kind == "acceptex" && !windowsSemanticAcceptExArgsValid(call, p, idx) {
		st.AddViolation(idx, call.Meta.Name+" without valid AcceptEx resources")
		return
	}
	if windowsSemanticIsSendRecvPendingKind(issue.kind) &&
		!windowsSemanticSendRecvPendingArgsValid(st, call, idx, issue) {
		return
	}
	if issue.kind == "tcp_recv" && !tcpRecvLocalDriver {
		st.AddViolation(idx, call.Meta.Name+" without accept-side send driver")
		return
	}
	if issue.kind == "accept_recv" && !acceptRecvLocalDriver {
		st.AddViolation(idx, call.Meta.Name+" without tcp-side send driver")
		return
	}
	if call.Ret == nil {
		st.AddViolation(idx, call.Meta.Name+" without pending socket resource")
		return
	}
	op := &prog.SemanticOperation{
		Kind:    issue.kind,
		Token:   windowsSemanticToken(issue.kind, call.Ret),
		Socket:  call.Ret,
		Pointer: ov,
	}
	if issue.kind == "connectex" &&
		!windowsSemanticPostConnectExFreshPointers(st, connectExMaxPointer, op, call, idx, 1, 3, 5, 6) {
		return
	}
	if issue.kind == "connectex" {
		op.AddFact(windowsSemanticConnectExIssued)
		if connectExHasLocalDriver {
			op.AddFact(windowsSemanticConnectExLocalDriver)
		}
		if addr, ok := windowsSemanticSockaddrIn(call, 1); ok {
			connectExAddrs[op] = addr
		}
		st.AddResourceFact(call.Ret, windowsSemanticConnectExIssued)
	}
	if issue.kind == "acceptex" {
		op.AddFact(windowsSemanticAcceptExIssued)
		if acceptExHasLocalDriver {
			op.AddFact(windowsSemanticAcceptExLocalDriver)
			op.AddFact(windowsSemanticCompletionObserved)
		}
		if listener := windowsSemanticInputRoot(call, 0); listener != nil {
			acceptExListenerByOp[op] = listener
		}
		if output, ok := windowsSemanticPointerAddress(call, 2); ok {
			acceptExOpByOutputBuffer[output] = op
		}
		st.AddResourceFact(call.Ret, windowsSemanticAcceptExIssued)
	}
	if issue.kind == "tcp_recv" || issue.kind == "accept_recv" {
		op.AddFact(windowsSemanticSendRecvLocalDriver)
	}
	st.AddPointerFact(ov, "overlapped")
	st.AddOperation(op)
	opsBySocket[call.Ret] = op
	if issue.kind == "connectex" {
		windowsSemanticUpdateOperationMaxPointer(connectExMaxPointer, op, call)
	}
	if base := windowsSemanticInputRoot(call, issue.sockArg); base != nil {
		if iocp := iocpByBaseSocket[base]; iocp != nil {
			windowsSemanticBindIOCP(st, opsByIOCP, op, iocp)
		}
	}
}

func windowsSemanticMarkConnectExVNetDriver(opsBySocket map[*prog.ResultArg]*prog.SemanticOperation) {
	for _, op := range opsBySocket {
		if op.Kind == "connectex" {
			op.AddFact(windowsSemanticConnectExVNetDriver)
		}
	}
}

func windowsSemanticMarkAcceptExVNetDriver(opsBySocket map[*prog.ResultArg]*prog.SemanticOperation) {
	for _, op := range opsBySocket {
		if op.Kind == "acceptex" {
			op.AddFact(windowsSemanticAcceptExVNetDriver)
		}
	}
}

func windowsSemanticAssociateIOCP(st *prog.SemanticState, opsBySocket map[*prog.ResultArg]*prog.SemanticOperation,
	opsByIOCP map[*prog.ResultArg][]*prog.SemanticOperation, iocpByBaseSocket map[*prog.ResultArg]*prog.ResultArg,
	call *prog.Call, idx int) {
	if call.Ret == nil {
		st.AddViolation(idx, call.Meta.Name+" without IOCP resource")
		return
	}
	socket := windowsSemanticInputRoot(call, 0)
	if socket == nil {
		if windowsSemanticIsPendingIOCPCall(call.Meta.Name) {
			st.AddViolation(idx, call.Meta.Name+" without pending operation")
		}
		return
	}
	if op := opsBySocket[socket]; op != nil {
		if op.IOCP != nil {
			st.AddViolation(idx, "duplicate IOCP association for pending operation")
			return
		}
		if op.Kind == "acceptex" &&
			(!windowsSemanticConstArgIs(call, 2, 0xafd) ||
				!windowsSemanticConstArgIs(call, 3, 0)) {
			st.AddViolation(idx, call.Meta.Name+" with non-constant IOCP association")
			return
		}
		windowsSemanticBindIOCP(st, opsByIOCP, op, call.Ret)
		return
	}
	if windowsSemanticIsPendingIOCPCall(call.Meta.Name) {
		st.AddViolation(idx, call.Meta.Name+" without pending operation")
		return
	}
	if call.Meta.Name == "CreateIoCompletionPort$socket" {
		iocpByBaseSocket[socket] = call.Ret
		st.AddResourceFact(call.Ret, windowsSemanticIOCPAssociated)
	}
}

func windowsSemanticObserveIOCPCompletion(st *prog.SemanticState,
	opsByIOCP map[*prog.ResultArg][]*prog.SemanticOperation,
	connectExMaxPointer map[*prog.SemanticOperation]uint64, call *prog.Call, idx int) {
	iocp := windowsSemanticInputRoot(call, 0)
	if iocp == nil || len(opsByIOCP[iocp]) == 0 {
		st.AddViolation(idx, "GetQueuedCompletionStatus without associated IOCP")
		return
	}
	for _, argIdx := range []int{1, 2, 3} {
		if _, ok := windowsSemanticPointerAddress(call, argIdx); !ok {
			st.AddViolation(idx, "GetQueuedCompletionStatus with null output pointer")
			return
		}
	}
	for _, op := range opsByIOCP[iocp] {
		if windowsSemanticRejectResultAfterCancel(op) {
			st.AddViolation(idx, "GetQueuedCompletionStatus after canceled pending operation")
			continue
		}
		if op.Kind == "connectex" &&
			!windowsSemanticPostConnectExFreshPointers(st, connectExMaxPointer, op, call, idx, 1, 2, 3) {
			continue
		}
		op.AddFact(windowsSemanticCompletionObserved)
		op.AddFact(windowsSemanticIOCPCompletion)
	}
}

func windowsSemanticObserveOverlappedResult(st *prog.SemanticState,
	opsBySocket map[*prog.ResultArg]*prog.SemanticOperation,
	connectExMaxPointer map[*prog.SemanticOperation]uint64, call *prog.Call, idx int) {
	if !windowsSemanticIsPendingResultCall(call.Meta.Name, "WSAGetOverlappedResult$") {
		return
	}
	if !windowsSemanticConstArgIs(call, 3, 0) {
		st.AddViolation(idx, call.Meta.Name+" with fWait=true")
		return
	}
	op := windowsSemanticOpForInput(opsBySocket, call, 0)
	if op == nil {
		st.AddViolation(idx, call.Meta.Name+" without pending operation")
		return
	}
	if windowsSemanticRejectResultAfterCancel(op) {
		st.AddViolation(idx, call.Meta.Name+" after canceled pending operation")
		return
	}
	ov, ok := windowsSemanticPointerAddress(call, 1)
	if !ok || ov != op.Pointer {
		st.AddViolation(idx, call.Meta.Name+" uses a different OVERLAPPED")
		return
	}
	if (op.Kind == "connectex" || op.Kind == "acceptex" || op.Kind == "disconnect_reuse") &&
		!windowsSemanticOverlappedZero(call, 1) {
		st.AddViolation(idx, call.Meta.Name+" with non-zero OVERLAPPED")
		return
	}
	if !windowsSemanticPointerConstArgIs(call, 4, 0) {
		st.AddViolation(idx, call.Meta.Name+" with non-zero result flags")
		return
	}
	if op.Kind == "connectex" &&
		!windowsSemanticPostConnectExFreshPointers(st, connectExMaxPointer, op, call, idx, 2, 4) {
		return
	}
	op.AddFact(windowsSemanticCompletionObserved)
	op.AddFact(windowsSemanticOverlappedResult)
}

func windowsSemanticCancelOverlapped(st *prog.SemanticState,
	opsBySocket map[*prog.ResultArg]*prog.SemanticOperation, call *prog.Call, idx int) {
	if !windowsSemanticIsPendingResultCall(call.Meta.Name, "CancelIoEx$") {
		return
	}
	op := windowsSemanticOpForInput(opsBySocket, call, 0)
	if op == nil {
		st.AddViolation(idx, call.Meta.Name+" without pending operation")
		return
	}
	if windowsSemanticRejectCancelAfterCompletion(op) {
		st.AddViolation(idx, call.Meta.Name+" after pending completion")
		return
	}
	if op.HasFact(windowsSemanticCancelRequested) {
		st.AddViolation(idx, call.Meta.Name+" after pending cancel request")
		return
	}
	ov, ok := windowsSemanticPointerAddress(call, 1)
	if !ok || ov != op.Pointer {
		st.AddViolation(idx, call.Meta.Name+" uses a different OVERLAPPED")
		return
	}
	if (op.Kind == "connectex" || op.Kind == "acceptex") && !windowsSemanticOverlappedZero(call, 1) {
		st.AddViolation(idx, call.Meta.Name+" with non-zero OVERLAPPED")
		return
	}
	op.AddFact(windowsSemanticCancelRequested)
	op.AddFact(windowsSemanticCancelOverlappedRequested)
}

func windowsSemanticCancelSocket(st *prog.SemanticState,
	opsBySocket map[*prog.ResultArg]*prog.SemanticOperation, call *prog.Call, idx int) {
	if !windowsSemanticIsPendingResultCall(call.Meta.Name, "CancelIo$") {
		return
	}
	op := windowsSemanticOpForInput(opsBySocket, call, 0)
	if op == nil {
		st.AddViolation(idx, call.Meta.Name+" without pending operation")
		return
	}
	if windowsSemanticRejectCancelAfterCompletion(op) {
		st.AddViolation(idx, call.Meta.Name+" after pending completion")
		return
	}
	if op.HasFact(windowsSemanticCancelRequested) {
		st.AddViolation(idx, call.Meta.Name+" after pending cancel request")
		return
	}
	op.AddFact(windowsSemanticCancelRequested)
}

func windowsSemanticClosePending(st *prog.SemanticState,
	opsBySocket map[*prog.ResultArg]*prog.SemanticOperation, call *prog.Call, idx int) {
	op := windowsSemanticOpForInput(opsBySocket, call, 0)
	if op == nil {
		st.AddViolation(idx, call.Meta.Name+" without pending operation")
		return
	}
	if op.Kind == "connectex" &&
		!op.HasFact(windowsSemanticCompletionObserved) &&
		!op.HasFact(windowsSemanticCancelRequested) {
		st.AddViolation(idx, call.Meta.Name+" before pending completion")
	}
	if windowsSemanticIsSendRecvPendingKind(op.Kind) &&
		!op.HasFact(windowsSemanticCompletionObserved) {
		st.AddViolation(idx, call.Meta.Name+" before pending send/recv completion")
	}
	if op.Kind == "acceptex" &&
		!op.HasFact(windowsSemanticCompletionObserved) &&
		!op.HasFact(windowsSemanticCancelRequested) {
		st.AddViolation(idx, call.Meta.Name+" before AcceptEx completion")
	}
	if op.HasFact(windowsSemanticCancelRequested) &&
		!op.HasFact(windowsSemanticCompletionObserved) {
		st.AddViolation(idx, call.Meta.Name+" after pending cancel request")
		return
	}
	op.AddFact(windowsSemanticPendingClosed)
}

func windowsSemanticUpdateConnectContext(st *prog.SemanticState, opsBySocket,
	opsByConnectedSocket map[*prog.ResultArg]*prog.SemanticOperation,
	tcpConnectAddrs map[*prog.ResultArg]windowsSockaddrIn,
	connectExAddrs map[*prog.SemanticOperation]windowsSockaddrIn, call *prog.Call, idx int) {
	op := windowsSemanticOpForInput(opsBySocket, call, 0)
	if op == nil || op.Kind != "connectex" {
		st.AddViolation(idx, "SO_UPDATE_CONNECT_CONTEXT without ConnectEx pending socket")
		return
	}
	if op.HasFact(windowsSemanticCancelRequested) {
		st.AddViolation(idx, "SO_UPDATE_CONNECT_CONTEXT after canceled ConnectEx")
		return
	}
	if !op.HasFact(windowsSemanticCompletionObserved) {
		st.AddViolation(idx, "SO_UPDATE_CONNECT_CONTEXT before ConnectEx completion")
		return
	}
	if !op.HasFact(windowsSemanticOverlappedResult) {
		st.AddViolation(idx, "SO_UPDATE_CONNECT_CONTEXT before WSAGetOverlappedResult")
		return
	}
	if !op.HasFact(windowsSemanticIOCPCompletion) {
		st.AddViolation(idx, "SO_UPDATE_CONNECT_CONTEXT before IOCP completion")
		return
	}
	op.AddFact(windowsSemanticConnectContextUpdated)
	if call.Ret != nil {
		st.AddResourceFact(call.Ret, windowsSemanticConnectContextUpdated)
		opsByConnectedSocket[call.Ret] = op
		if addr, ok := connectExAddrs[op]; ok {
			tcpConnectAddrs[call.Ret] = addr
		}
	}
}

func windowsSemanticUpdateAcceptContext(st *prog.SemanticState, opsBySocket,
	opsByAcceptedSocket map[*prog.ResultArg]*prog.SemanticOperation,
	acceptExListenerByOp map[*prog.SemanticOperation]*prog.ResultArg, call *prog.Call, idx int) {
	op := windowsSemanticOpForInput(opsBySocket, call, 0)
	if op == nil || op.Kind != "acceptex" {
		st.AddViolation(idx, "SO_UPDATE_ACCEPT_CONTEXT without AcceptEx pending socket")
		return
	}
	if op.HasFact(windowsSemanticCancelRequested) {
		st.AddViolation(idx, "SO_UPDATE_ACCEPT_CONTEXT after canceled AcceptEx")
		return
	}
	if !op.HasFact(windowsSemanticCompletionObserved) {
		st.AddViolation(idx, "SO_UPDATE_ACCEPT_CONTEXT before AcceptEx completion")
		return
	}
	if !op.HasFact(windowsSemanticOverlappedResult) {
		st.AddViolation(idx, "SO_UPDATE_ACCEPT_CONTEXT before WSAGetOverlappedResult")
		return
	}
	if !op.HasFact(windowsSemanticIOCPCompletion) {
		st.AddViolation(idx, "SO_UPDATE_ACCEPT_CONTEXT before IOCP completion")
		return
	}
	listener := windowsSemanticPointerInputRoot(call, 3)
	if listener == nil || listener != acceptExListenerByOp[op] {
		st.AddViolation(idx, "SO_UPDATE_ACCEPT_CONTEXT uses a different listener socket")
		return
	}
	op.AddFact(windowsSemanticAcceptContextUpdated)
	if call.Ret != nil {
		st.AddResourceFact(call.Ret, windowsSemanticAcceptContextUpdated)
		opsByAcceptedSocket[call.Ret] = op
	}
}

func windowsSemanticGetAcceptExSockaddrs(st *prog.SemanticState,
	acceptExOpByOutputBuffer map[uint64]*prog.SemanticOperation, call *prog.Call, idx int) {
	output, ok := windowsSemanticPointerAddress(call, 0)
	if !ok {
		st.AddViolation(idx, "GetAcceptExSockaddrs without AcceptEx output buffer")
		return
	}
	op := acceptExOpByOutputBuffer[output]
	if op == nil || op.Kind != "acceptex" {
		st.AddViolation(idx, "GetAcceptExSockaddrs with buffer not produced by AcceptEx")
		return
	}
	if op.HasFact(windowsSemanticCancelRequested) {
		st.AddViolation(idx, "GetAcceptExSockaddrs after canceled AcceptEx")
		return
	}
	if !op.HasFact(windowsSemanticOverlappedResult) {
		st.AddViolation(idx, "GetAcceptExSockaddrs before WSAGetOverlappedResult")
		return
	}
	if !op.HasFact(windowsSemanticIOCPCompletion) {
		st.AddViolation(idx, "GetAcceptExSockaddrs before IOCP completion")
		return
	}
	if !windowsSemanticConstArgIs(call, 1, 0) ||
		!windowsSemanticConstArgIs(call, 2, 0x20) ||
		!windowsSemanticConstArgIs(call, 3, 0x20) {
		st.AddViolation(idx, "GetAcceptExSockaddrs with mismatched AcceptEx lengths")
		return
	}
	for _, argIdx := range []int{4, 5, 6, 7} {
		if _, ok := windowsSemanticPointerAddress(call, argIdx); !ok {
			st.AddViolation(idx, "GetAcceptExSockaddrs with null output pointer")
			return
		}
	}
}

func windowsSemanticRecordEventSelect(st *prog.SemanticState,
	eventSelectBySocket map[*prog.ResultArg]*prog.ResultArg, call *prog.Call, idx int) {
	socket := windowsSemanticInputRoot(call, 0)
	if socket == nil {
		st.AddViolation(idx, call.Meta.Name+" without socket resource")
		return
	}
	if strings.HasPrefix(call.Meta.Name, "WSAEventSelect$") {
		event := windowsSemanticInputRoot(call, 1)
		if event == nil {
			st.AddViolation(idx, call.Meta.Name+" without event resource")
			return
		}
		if !windowsSemanticConstArgBetween(call, 2, 1, 0x3f) {
			st.AddViolation(idx, call.Meta.Name+" without network events")
			return
		}
		eventSelectBySocket[socket] = event
		return
	}
	if call.Meta.Name == "NtDeviceIoControlFile$afd_event_select_accept_nonblock" {
		if !windowsSemanticPrivateEventSelectInfoNoEvent(call, 6) {
			st.AddViolation(idx, call.Meta.Name+" with invalid no-event select info")
			return
		}
		eventSelectBySocket[socket] = nil
		return
	}
	event := windowsSemanticPrivateEventSelectInfoEvent(call, 6)
	if event == nil {
		st.AddViolation(idx, call.Meta.Name+" without event resource")
		return
	}
	eventSelectBySocket[socket] = event
}

func windowsSemanticValidateEnumNetworkEvents(st *prog.SemanticState,
	eventSelectBySocket map[*prog.ResultArg]*prog.ResultArg, call *prog.Call, idx int) {
	socket := windowsSemanticInputRoot(call, 0)
	if socket == nil {
		st.AddViolation(idx, call.Meta.Name+" without socket resource")
		return
	}
	event, ok := eventSelectBySocket[socket]
	if !ok {
		st.AddViolation(idx, call.Meta.Name+" without prior event select")
		return
	}
	if strings.HasPrefix(call.Meta.Name, "WSAEnumNetworkEvents$") {
		gotEvent := windowsSemanticInputRoot(call, 1)
		if gotEvent == nil || gotEvent != event {
			st.AddViolation(idx, call.Meta.Name+" uses a different event")
			return
		}
		if _, ok := windowsSemanticPointerAddress(call, 2); !ok {
			st.AddViolation(idx, call.Meta.Name+" without output buffer")
			return
		}
		return
	}
	if call.Meta.Name == "NtDeviceIoControlFile$afd_enum_network_events_accept" && event == nil {
		st.AddViolation(idx, call.Meta.Name+" without blocking event select")
		return
	}
	if !windowsSemanticNullPointerArg(call, 6) ||
		!windowsSemanticConstArgIs(call, 7, 0) {
		st.AddViolation(idx, call.Meta.Name+" with non-null event input")
		return
	}
	if _, ok := windowsSemanticPointerAddress(call, 8); !ok {
		st.AddViolation(idx, call.Meta.Name+" without output buffer")
	}
}

func windowsSemanticValidatePrivatePoll(st *prog.SemanticState, call *prog.Call, idx int) {
	socket := windowsSemanticInputRoot(call, 0)
	if socket == nil {
		st.AddViolation(idx, call.Meta.Name+" without socket resource")
		return
	}
	for _, argIdx := range []int{6, 8} {
		if _, ok := windowsSemanticPointerAddress(call, argIdx); !ok {
			st.AddViolation(idx, call.Meta.Name+" without poll buffer")
			return
		}
	}
	if !windowsSemanticPrivatePollInfoAcceptNonblock(call, 6, socket) ||
		!windowsSemanticPrivatePollInfoAcceptNonblock(call, 8, socket) {
		st.AddViolation(idx, call.Meta.Name+" with invalid poll info")
	}
}

func windowsSemanticDisconnectExReuseArgsValid(call *prog.Call) bool {
	if windowsSemanticInputRoot(call, 0) == nil {
		return false
	}
	if _, ok := windowsSemanticPointerAddress(call, 1); !ok {
		return false
	}
	if !windowsSemanticConstArgIs(call, 2, 0x2) || !windowsSemanticConstArgIs(call, 3, 0) {
		return false
	}
	return call.Ret != nil
}

func windowsSemanticDisconnectExReusePeerClosed(call *prog.Call,
	tcpConnectAddrs map[*prog.ResultArg]windowsSockaddrIn,
	closedAcceptedPeerAddrs map[windowsSockaddrIn]bool) bool {
	root := windowsSemanticInputRoot(call, 0)
	if root == nil {
		return false
	}
	addr, ok := tcpConnectAddrs[root]
	return ok && closedAcceptedPeerAddrs[addr]
}

func windowsSemanticRejectDirectConnectedUse(st *prog.SemanticState,
	opsBySocket, opsByConnectedSocket map[*prog.ResultArg]*prog.SemanticOperation,
	connectExMaxPointer map[*prog.SemanticOperation]uint64, call *prog.Call, idx int) {
	if call.Meta == nil || windowsSemanticAllowedPendingConsumer(call.Meta.Name) {
		return
	}
	hasConnectEx := false
	for _, op := range opsBySocket {
		if op.Kind == "connectex" {
			hasConnectEx = true
			break
		}
	}
	for argIdx, arg := range call.Args {
		if !windowsSemanticArgWantsTCPConnected(call, argIdx) {
			continue
		}
		res, ok := arg.(*prog.ResultArg)
		if !ok {
			continue
		}
		root := res.Res
		if op := opsBySocket[root]; op != nil && op.Kind == "connectex" {
			st.AddViolation(idx, call.Meta.Name+" uses ConnectEx pending socket before SO_UPDATE_CONNECT_CONTEXT")
			return
		}
		if hasConnectEx {
			op := opsByConnectedSocket[root]
			if op == nil || !st.ResourceHasFact(root, windowsSemanticConnectContextUpdated) {
				st.AddViolation(idx, call.Meta.Name+" uses TCP connected socket not produced by SO_UPDATE_CONNECT_CONTEXT")
				return
			}
			if !windowsSemanticPostConnectExTCPUseValid(st, connectExMaxPointer, op, call, idx) {
				return
			}
		}
	}
}

func windowsSemanticRejectDirectAcceptUpdatedUse(st *prog.SemanticState,
	opsByAcceptedSocket map[*prog.ResultArg]*prog.SemanticOperation, call *prog.Call, idx int) {
	if call.Meta == nil {
		return
	}
	hasAcceptUpdated := false
	for argIdx, arg := range call.Args {
		if !windowsSemanticArgWantsResource(call, argIdx, "SOCKET_TCP_ACCEPTED_UPDATED") {
			continue
		}
		hasAcceptUpdated = true
		res, ok := arg.(*prog.ResultArg)
		if !ok || res.Res == nil {
			st.AddViolation(idx, call.Meta.Name+" uses default accept-updated socket")
			return
		}
		root := res.Res
		if opsByAcceptedSocket[root] == nil || !st.ResourceHasFact(root, windowsSemanticAcceptContextUpdated) {
			st.AddViolation(idx, call.Meta.Name+" uses accept socket not produced by SO_UPDATE_ACCEPT_CONTEXT")
			return
		}
	}
	if !hasAcceptUpdated {
		return
	}
	switch call.Meta.Name {
	case "send$inet_accept_updated", "recv$inet_accept_updated":
		if _, ok := windowsSemanticPointerAddress(call, 1); !ok {
			st.AddViolation(idx, call.Meta.Name+" without data buffer")
			return
		}
		if !windowsSemanticConstArgBetween(call, 2, 1, 0x100) {
			st.AddViolation(idx, call.Meta.Name+" with invalid data length")
			return
		}
		if !windowsSemanticConstArgIs(call, 3, 0) {
			st.AddViolation(idx, call.Meta.Name+" with non-zero flags")
			return
		}
	}
}

func windowsSemanticRejectInvalidAcceptExTCPUse(st *prog.SemanticState,
	opsBySocket map[*prog.ResultArg]*prog.SemanticOperation, acceptExProgram bool,
	call *prog.Call, idx int) {
	if call.Meta == nil || call.Meta.Name != "send$inet_tcp" {
		return
	}
	hasAcceptEx := false
	hasUpdatedAcceptEx := false
	for _, op := range opsBySocket {
		if op.Kind != "acceptex" {
			continue
		}
		hasAcceptEx = true
		if op.HasFact(windowsSemanticAcceptContextUpdated) {
			hasUpdatedAcceptEx = true
		}
	}
	if !hasAcceptEx {
		if acceptExProgram {
			st.AddViolation(idx, call.Meta.Name+" before SO_UPDATE_ACCEPT_CONTEXT")
		}
		return
	}
	if !hasUpdatedAcceptEx {
		st.AddViolation(idx, call.Meta.Name+" before SO_UPDATE_ACCEPT_CONTEXT")
		return
	}
	root := windowsSemanticInputRoot(call, 0)
	if root == nil {
		st.AddViolation(idx, call.Meta.Name+" uses default TCP connected socket")
		return
	}
	if _, ok := windowsSemanticPointerAddress(call, 1); !ok {
		st.AddViolation(idx, call.Meta.Name+" without send buffer")
		return
	}
	if !windowsSemanticConstArgBetween(call, 2, 1, 0x100) {
		st.AddViolation(idx, call.Meta.Name+" with invalid AcceptEx driver send length")
		return
	}
	if !windowsSemanticConstArgIs(call, 3, 0) {
		st.AddViolation(idx, call.Meta.Name+" with non-zero AcceptEx driver send flags")
		return
	}
}

func windowsSemanticRejectAcceptedUseWithoutPeer(st *prog.SemanticState,
	acceptedSocketsWithPeer map[*prog.ResultArg]bool, call *prog.Call, idx int) {
	if call.Meta == nil {
		return
	}
	for argIdx, arg := range call.Args {
		if !windowsSemanticArgWantsResource(call, argIdx, "SOCKET_TCP_ACCEPTED") &&
			!windowsSemanticArgWantsResource(call, argIdx, "SOCKET_TCP_ACCEPTED_NONBLOCK") {
			continue
		}
		res, ok := arg.(*prog.ResultArg)
		if !ok || res.Res == nil {
			continue
		}
		hasPeer, ok := acceptedSocketsWithPeer[res.Res]
		if ok && !hasPeer {
			st.AddViolation(idx, call.Meta.Name+" uses accepted socket without local peer")
			return
		}
	}
}

func windowsSemanticAllowedPendingConsumer(name string) bool {
	switch name {
	case "CreateIoCompletionPort$connect_pending",
		"CreateIoCompletionPort$disconnect_reuse_pending",
		"CreateIoCompletionPort$accept_pending",
		"CreateIoCompletionPort$accept_recv_pending",
		"CreateIoCompletionPort$accept_send_pending",
		"CreateIoCompletionPort$tcp_recv_pending",
		"CreateIoCompletionPort$tcp_send_pending",
		"WSAGetOverlappedResult$connect_pending",
		"WSAGetOverlappedResult$disconnect_reuse_pending",
		"WSAGetOverlappedResult$accept_pending",
		"WSAGetOverlappedResult$accept_recv_pending",
		"WSAGetOverlappedResult$accept_send_pending",
		"WSAGetOverlappedResult$tcp_recv_pending",
		"WSAGetOverlappedResult$tcp_send_pending",
		"CancelIoEx$connect_pending",
		"CancelIoEx$accept_pending",
		"CancelIoEx$accept_recv_pending",
		"CancelIoEx$accept_send_pending",
		"CancelIoEx$tcp_recv_pending",
		"CancelIoEx$tcp_send_pending",
		"CancelIo$connect_pending",
		"CancelIo$accept_pending",
		"CancelIo$accept_recv_pending",
		"CancelIo$accept_send_pending",
		"CancelIo$tcp_recv_pending",
		"CancelIo$tcp_send_pending",
		"closesocket$connect_pending",
		"closesocket$accept_pending",
		"closesocket$accept_recv_pending",
		"closesocket$accept_send_pending",
		"closesocket$tcp_recv_pending",
		"closesocket$tcp_send_pending",
		"setsockopt$update_connect_context",
		"setsockopt$update_accept_context",
		"GetAcceptExSockaddrs$inet_tcp":
		return true
	default:
		return false
	}
}

func windowsSemanticIsPendingResultCall(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	switch strings.TrimPrefix(name, prefix) {
	case "accept_pending", "accept_recv_pending", "accept_send_pending",
		"tcp_recv_pending", "tcp_send_pending", "connect_pending",
		"disconnect_reuse_pending":
		return true
	default:
		return false
	}
}

func windowsSemanticIsPendingIOCPCall(name string) bool {
	return windowsSemanticIsPendingResultCall(name, "CreateIoCompletionPort$")
}

func windowsSemanticIsPendingCloseCall(name string) bool {
	if !strings.HasPrefix(name, "closesocket$") {
		return false
	}
	switch strings.TrimPrefix(name, "closesocket$") {
	case "accept_pending", "accept_recv_pending", "accept_send_pending",
		"tcp_recv_pending", "tcp_send_pending", "connect_pending":
		return true
	default:
		return false
	}
}

func windowsSemanticBindIOCP(st *prog.SemanticState,
	opsByIOCP map[*prog.ResultArg][]*prog.SemanticOperation, op *prog.SemanticOperation, iocp *prog.ResultArg) {
	op.IOCP = iocp
	op.AddFact(windowsSemanticIOCPAssociated)
	st.AddResourceFact(iocp, windowsSemanticIOCPAssociated)
	opsByIOCP[iocp] = append(opsByIOCP[iocp], op)
}

func windowsSemanticValidatePendingOperations(st *prog.SemanticState) {
	if st == nil {
		return
	}
	for _, op := range st.Operations {
		switch op.Kind {
		case "connectex":
			if !op.HasFact(windowsSemanticCancelRequested) &&
				!op.HasFact(windowsSemanticConnectExLocalDriver) &&
				!op.HasFact(windowsSemanticConnectExVNetDriver) {
				st.AddViolation(st.InsertionPoint, "ConnectEx completion path without local or vnet driver")
			}
			if op.HasFact(windowsSemanticCancelRequested) {
				continue
			}
			if op.HasFact(windowsSemanticConnectContextUpdated) ||
				op.HasFact(windowsSemanticPendingClosed) {
				continue
			}
			if op.HasFact(windowsSemanticCompletionObserved) {
				st.AddViolation(st.InsertionPoint,
					"completed ConnectEx pending operation left without SO_UPDATE_CONNECT_CONTEXT or closesocket")
				continue
			}
			st.AddViolation(st.InsertionPoint, "ConnectEx pending operation left without observed completion")
		case "disconnect_reuse":
			if !op.HasFact(windowsSemanticCompletionObserved) {
				st.AddViolation(st.InsertionPoint,
					"DisconnectEx reuse pending operation left without observed completion")
			}
		case "acceptex":
			if op.HasFact(windowsSemanticCancelRequested) {
				continue
			}
			if op.HasFact(windowsSemanticAcceptContextUpdated) ||
				op.HasFact(windowsSemanticPendingClosed) {
				continue
			}
			if !op.HasFact(windowsSemanticCompletionObserved) {
				st.AddViolation(st.InsertionPoint, "AcceptEx pending operation left without observed completion")
				continue
			}
			st.AddViolation(st.InsertionPoint,
				"completed AcceptEx pending operation left without SO_UPDATE_ACCEPT_CONTEXT or closesocket")
		case "accept_recv", "accept_send", "tcp_recv", "tcp_send":
			if op.HasFact(windowsSemanticCancelRequested) {
				st.AddViolation(st.InsertionPoint,
					op.Kind+" pending cancel path is not enabled for generation")
				continue
			}
			if op.HasFact(windowsSemanticCompletionObserved) {
				continue
			}
			st.AddViolation(st.InsertionPoint, op.Kind+" pending operation left without observed completion")
		default:
			continue
		}
	}
}

func windowsSemanticHasCompletedConnectEx(st *prog.SemanticState) bool {
	if st == nil {
		return false
	}
	for _, op := range st.Operations {
		if op.Kind == "connectex" &&
			(op.HasFact(windowsSemanticConnectContextUpdated) ||
				op.HasFact(windowsSemanticPendingClosed)) {
			return true
		}
	}
	return false
}

func windowsSemanticHasResolvedAcceptEx(st *prog.SemanticState) bool {
	if st == nil {
		return false
	}
	for _, op := range st.Operations {
		if op.Kind != "acceptex" {
			continue
		}
		if op.HasFact(windowsSemanticCancelRequested) {
			if op.HasFact(windowsSemanticPendingClosed) {
				return true
			}
			continue
		}
		if op.HasFact(windowsSemanticOverlappedResult) ||
			op.HasFact(windowsSemanticAcceptContextUpdated) {
			return true
		}
	}
	return false
}

func windowsSemanticHasResolvedSendRecvPending(st *prog.SemanticState) bool {
	if st == nil {
		return false
	}
	for _, op := range st.Operations {
		if !windowsSemanticIsSendRecvPendingKind(op.Kind) {
			continue
		}
		if op.HasFact(windowsSemanticCompletionObserved) {
			return true
		}
	}
	return false
}

func windowsSemanticOpForInput(opsBySocket map[*prog.ResultArg]*prog.SemanticOperation,
	call *prog.Call, argIdx int) *prog.SemanticOperation {
	return opsBySocket[windowsSemanticInputRoot(call, argIdx)]
}

func windowsSemanticInputRoot(call *prog.Call, argIdx int) *prog.ResultArg {
	if call == nil || argIdx < 0 || argIdx >= len(call.Args) {
		return nil
	}
	res, ok := call.Args[argIdx].(*prog.ResultArg)
	if !ok {
		return nil
	}
	return res.Res
}

func windowsSemanticArgProducedBy(call *prog.Call, argIdx int, p *prog.Prog, insertionPoint int,
	producerName string) bool {
	root := windowsSemanticInputRoot(call, argIdx)
	if root == nil {
		return false
	}
	producer := prog.ResourceProducer(root, p, insertionPoint)
	return producer != nil && producer.Name == producerName
}

func windowsSemanticArgProducedByAny(call *prog.Call, argIdx int, p *prog.Prog, insertionPoint int,
	producerNames ...string) bool {
	root := windowsSemanticInputRoot(call, argIdx)
	if root == nil {
		return false
	}
	producer := prog.ResourceProducer(root, p, insertionPoint)
	if producer == nil {
		return false
	}
	for _, name := range producerNames {
		if producer.Name == name {
			return true
		}
	}
	return false
}

func windowsSemanticPointerInputRoot(call *prog.Call, argIdx int) *prog.ResultArg {
	if call == nil || argIdx < 0 || argIdx >= len(call.Args) {
		return nil
	}
	ptr, ok := call.Args[argIdx].(*prog.PointerArg)
	if !ok || ptr.IsSpecial() {
		return nil
	}
	res, ok := ptr.Res.(*prog.ResultArg)
	if !ok {
		return nil
	}
	return res.Res
}

func windowsSemanticHasPreparedConnectExSocket(call *prog.Call, p *prog.Prog, insertionPoint int) bool {
	root := windowsSemanticInputRoot(call, 0)
	if root == nil {
		return false
	}
	producer := prog.ResourceProducer(root, p, insertionPoint)
	if producer == nil {
		return false
	}
	switch call.Meta.Name {
	case "ConnectEx$inet_tcp", "ConnectEx$inet_tcp_pending":
		return producer.Name == "bind$connectex_tcp"
	case "ConnectEx$inet_tcp_reuse":
		return producer.Name == "WSAGetOverlappedResult$disconnect_reuse_pending"
	default:
		return false
	}
}

func windowsSemanticAcceptExHasLocalDriver(call *prog.Call, listeners map[*prog.ResultArg]windowsSockaddrIn,
	tcpLocalConnects map[windowsSockaddrIn]bool) bool {
	listener := windowsSemanticInputRoot(call, 0)
	if listener == nil {
		return false
	}
	addr, ok := listeners[listener]
	if !ok {
		return false
	}
	return windowsSemanticHasLocalConnect(addr, tcpLocalConnects)
}

func windowsSemanticHasLocalConnect(addr windowsSockaddrIn, tcpLocalConnects map[windowsSockaddrIn]bool) bool {
	for target := range tcpLocalConnects {
		if target.port != addr.port {
			continue
		}
		if addr.addr == 0 || target.addr == 0 || target.addr == addr.addr {
			return true
		}
	}
	return false
}

func windowsSemanticHasLocalListener(target windowsSockaddrIn, tcpListeners map[windowsSockaddrIn]bool) bool {
	for addr := range tcpListeners {
		if target.port != addr.port {
			continue
		}
		if addr.addr == 0 || target.addr == 0 || target.addr == addr.addr {
			return true
		}
	}
	return false
}

func windowsSemanticAcceptExArgsValid(call *prog.Call, p *prog.Prog, insertionPoint int) bool {
	if !windowsSemanticArgProducedByAny(call, 0, p, insertionPoint, "listen$inet_tcp", "socket$listener_tcp") {
		return false
	}
	if !windowsSemanticArgProducedBy(call, 1, p, insertionPoint, "socket$accept_tcp") {
		return false
	}
	if _, ok := windowsSemanticPointerAddress(call, 2); !ok {
		return false
	}
	if !windowsSemanticPointerZero(call, 2) {
		return false
	}
	if !windowsSemanticConstArgBetween(call, 3, 0, 0x100) {
		return false
	}
	if !windowsSemanticConstArgBetween(call, 4, 0x20, 0x100) ||
		!windowsSemanticConstArgBetween(call, 5, 0x20, 0x100) {
		return false
	}
	if _, ok := windowsSemanticPointerAddress(call, 6); !ok {
		return false
	}
	if !windowsSemanticPointerZero(call, 6) {
		return false
	}
	return windowsSemanticOverlappedZero(call, 7)
}

func windowsSemanticSendRecvPendingArgsValid(st *prog.SemanticState, call *prog.Call, idx int,
	issue windowsPendingIssue) bool {
	if windowsSemanticInputRoot(call, issue.sockArg) == nil {
		st.AddViolation(idx, call.Meta.Name+" without socket resource")
		return false
	}
	if _, ok := windowsSemanticPointerAddress(call, 1); !ok {
		st.AddViolation(idx, call.Meta.Name+" without WSABUF")
		return false
	}
	if _, ok := windowsSemanticPointerAddress(call, 3); !ok {
		st.AddViolation(idx, call.Meta.Name+" without byte-count pointer")
		return false
	}
	switch issue.kind {
	case "accept_send", "tcp_send":
		if !windowsSemanticConstArgIs(call, 4, 0) {
			st.AddViolation(idx, call.Meta.Name+" with non-zero flags")
			return false
		}
	case "accept_recv", "tcp_recv":
		if !windowsSemanticPointerConstArgIs(call, 4, 0) {
			st.AddViolation(idx, call.Meta.Name+" with non-zero receive flags")
			return false
		}
	}
	if !windowsSemanticNullPointerArg(call, 6) {
		st.AddViolation(idx, call.Meta.Name+" with completion routine")
		return false
	}
	return true
}

func windowsSemanticIsSendRecvPendingKind(kind string) bool {
	switch kind {
	case "accept_recv", "accept_send", "tcp_recv", "tcp_send":
		return true
	default:
		return false
	}
}

func windowsSemanticRejectResultAfterCancel(op *prog.SemanticOperation) bool {
	return op != nil && (op.Kind == "connectex" || op.Kind == "acceptex" ||
		windowsSemanticIsSendRecvPendingKind(op.Kind)) &&
		op.HasFact(windowsSemanticCancelRequested)
}

func windowsSemanticRejectCancelAfterCompletion(op *prog.SemanticOperation) bool {
	return op != nil && (op.Kind == "connectex" || op.Kind == "acceptex" ||
		windowsSemanticIsSendRecvPendingKind(op.Kind)) &&
		op.HasFact(windowsSemanticCompletionObserved)
}

func windowsSemanticHasMatchingListener(call *prog.Call, listeners map[windowsSockaddrIn]bool) bool {
	target, ok := windowsSemanticSockaddrIn(call, 1)
	if !ok {
		return false
	}
	for listener := range listeners {
		if listener.port != target.port {
			continue
		}
		if listener.addr == 0 || listener.addr == target.addr {
			return true
		}
	}
	return false
}

func windowsSemanticSockaddrIn(call *prog.Call, argIdx int) (windowsSockaddrIn, bool) {
	if call == nil || argIdx < 0 || argIdx >= len(call.Args) {
		return windowsSockaddrIn{}, false
	}
	ptr, ok := call.Args[argIdx].(*prog.PointerArg)
	if !ok || ptr.IsSpecial() {
		return windowsSockaddrIn{}, false
	}
	group, ok := ptr.Res.(*prog.GroupArg)
	if !ok || len(group.Inner) < 3 {
		return windowsSockaddrIn{}, false
	}
	port, ok := group.Inner[1].(*prog.ConstArg)
	if !ok {
		return windowsSockaddrIn{}, false
	}
	addr, ok := group.Inner[2].(*prog.ConstArg)
	if !ok {
		return windowsSockaddrIn{}, false
	}
	return windowsSockaddrIn{port: port.Val, addr: addr.Val}, true
}

func windowsSemanticPointerAddress(call *prog.Call, argIdx int) (uint64, bool) {
	if call == nil || argIdx < 0 || argIdx >= len(call.Args) {
		return 0, false
	}
	ptr, ok := call.Args[argIdx].(*prog.PointerArg)
	if !ok || ptr.IsSpecial() {
		return 0, false
	}
	return ptr.Address, true
}

func windowsSemanticConnectExSendBufferValid(call *prog.Call) bool {
	if call == nil || len(call.Args) <= 4 {
		return false
	}
	if _, ok := windowsSemanticPointerAddress(call, 3); !ok {
		return false
	}
	length, ok := windowsSemanticConstArgValue(call, 4)
	return ok && length > 0 && length <= 0x40
}

func windowsSemanticPostConnectExTCPUseValid(st *prog.SemanticState,
	connectExMaxPointer map[*prog.SemanticOperation]uint64, op *prog.SemanticOperation,
	call *prog.Call, idx int) bool {
	switch call.Meta.Name {
	case "send$inet_tcp":
		if !windowsSemanticConstArgBetween(call, 2, 1, 0x100) {
			st.AddViolation(idx, call.Meta.Name+" with invalid ConnectEx send length")
			return false
		}
		if !windowsSemanticConstArgIs(call, 3, 0) {
			st.AddViolation(idx, call.Meta.Name+" with non-zero ConnectEx send flags")
			return false
		}
		return windowsSemanticPostConnectExFreshPointers(st, connectExMaxPointer, op, call, idx, 1)
	case "getsockname$tcp", "getpeername$tcp":
		if !windowsSemanticPointerConstArgIs(call, 2, 0x10) {
			st.AddViolation(idx, call.Meta.Name+" with invalid sockaddr length")
			return false
		}
		return windowsSemanticPostConnectExFreshPointers(st, connectExMaxPointer, op, call, idx, 1, 2)
	default:
		return true
	}
}

func windowsSemanticPostConnectExFreshPointers(st *prog.SemanticState,
	connectExMaxPointer map[*prog.SemanticOperation]uint64, op *prog.SemanticOperation,
	call *prog.Call, idx int, argIdxs ...int) bool {
	high := connectExMaxPointer[op]
	for _, argIdx := range argIdxs {
		addr, ok := windowsSemanticPointerAddress(call, argIdx)
		if !ok {
			st.AddViolation(idx, call.Meta.Name+" without fresh ConnectEx buffer")
			return false
		}
		if addr <= high {
			st.AddViolation(idx, call.Meta.Name+" reuses earlier ConnectEx buffer range")
			return false
		}
		high = addr
	}
	windowsSemanticUpdateOperationMaxPointer(connectExMaxPointer, op, call)
	return true
}

func windowsSemanticConstArgIs(call *prog.Call, argIdx int, want uint64) bool {
	val, ok := windowsSemanticConstArgValue(call, argIdx)
	return ok && val == want
}

func windowsSemanticConstArgBetween(call *prog.Call, argIdx int, min uint64, max uint64) bool {
	val, ok := windowsSemanticConstArgValue(call, argIdx)
	return ok && val >= min && val <= max
}

func windowsSemanticConstArgValue(call *prog.Call, argIdx int) (uint64, bool) {
	if call == nil || argIdx < 0 || argIdx >= len(call.Args) {
		return 0, false
	}
	arg, ok := call.Args[argIdx].(*prog.ConstArg)
	if !ok {
		return 0, false
	}
	return arg.Val, true
}

func windowsSemanticPointerConstArgIs(call *prog.Call, argIdx int, want uint64) bool {
	if call == nil || argIdx < 0 || argIdx >= len(call.Args) {
		return false
	}
	ptr, ok := call.Args[argIdx].(*prog.PointerArg)
	if !ok || ptr.IsSpecial() {
		return false
	}
	arg, ok := ptr.Res.(*prog.ConstArg)
	return ok && arg.Val == want
}

func windowsSemanticNullPointerArg(call *prog.Call, argIdx int) bool {
	if call == nil || argIdx < 0 || argIdx >= len(call.Args) {
		return false
	}
	switch arg := call.Args[argIdx].(type) {
	case *prog.ConstArg:
		return arg.Val == 0
	case *prog.PointerArg:
		return arg.IsSpecial()
	default:
		return false
	}
}

func windowsSemanticIsEventSelectCall(name string) bool {
	switch name {
	case "WSAEventSelect$tcp_nonblock",
		"WSAEventSelect$accept_nonblock",
		"NtDeviceIoControlFile$afd_event_select_accept",
		"NtDeviceIoControlFile$afd_event_select_accept_nonblock":
		return true
	default:
		return false
	}
}

func windowsSemanticIsEnumNetworkEventsCall(name string) bool {
	switch name {
	case "WSAEnumNetworkEvents$tcp_nonblock",
		"WSAEnumNetworkEvents$accept_nonblock",
		"NtDeviceIoControlFile$afd_enum_network_events_accept",
		"NtDeviceIoControlFile$afd_enum_network_events_accept_nonblock":
		return true
	default:
		return false
	}
}

func windowsSemanticIsPrivatePollCall(name string) bool {
	return name == "NtDeviceIoControlFile$afd_poll_accept" ||
		name == "NtDeviceIoControlFile$afd_poll_accept_nonblock"
}

func windowsSemanticPrivateEventSelectInfoNoEvent(call *prog.Call, argIdx int) bool {
	group := windowsSemanticPointerGroupArg(call, argIdx)
	if group == nil || len(group.Inner) < 3 {
		return false
	}
	event, ok := group.Inner[0].(*prog.ConstArg)
	if !ok || event.Val != 0 {
		return false
	}
	events, ok := group.Inner[1].(*prog.ConstArg)
	if !ok || events.Val == 0 || events.Val > 0x3ff {
		return false
	}
	return windowsSemanticArgZero(group.Inner[2])
}

func windowsSemanticPrivateEventSelectInfoEvent(call *prog.Call, argIdx int) *prog.ResultArg {
	group := windowsSemanticPointerGroupArg(call, argIdx)
	if group == nil || len(group.Inner) < 3 {
		return nil
	}
	event, ok := group.Inner[0].(*prog.ResultArg)
	if !ok || event.Res == nil {
		return nil
	}
	events, ok := group.Inner[1].(*prog.ConstArg)
	if !ok || events.Val == 0 || events.Val > 0x3ff {
		return nil
	}
	if !windowsSemanticArgZero(group.Inner[2]) {
		return nil
	}
	return event.Res
}

func windowsSemanticPrivatePollInfoAcceptNonblock(call *prog.Call, argIdx int, socket *prog.ResultArg) bool {
	group := windowsSemanticPointerGroupArg(call, argIdx)
	if group == nil || len(group.Inner) < 5 {
		return false
	}
	if !windowsSemanticArgZero(group.Inner[0]) {
		return false
	}
	count, ok := group.Inner[1].(*prog.ConstArg)
	if !ok || count.Val != 1 {
		return false
	}
	handles, ok := group.Inner[4].(*prog.GroupArg)
	if !ok || len(handles.Inner) != 1 {
		return false
	}
	handle, ok := handles.Inner[0].(*prog.GroupArg)
	if !ok || len(handle.Inner) < 3 {
		return false
	}
	res, ok := handle.Inner[0].(*prog.ResultArg)
	if !ok || res.Res != socket {
		return false
	}
	events, ok := handle.Inner[1].(*prog.ConstArg)
	return ok && events.Val <= 0x3ff
}

func windowsSemanticPointerGroupArg(call *prog.Call, argIdx int) *prog.GroupArg {
	if call == nil || argIdx < 0 || argIdx >= len(call.Args) {
		return nil
	}
	ptr, ok := call.Args[argIdx].(*prog.PointerArg)
	if !ok || ptr.IsSpecial() {
		return nil
	}
	group, ok := ptr.Res.(*prog.GroupArg)
	if !ok {
		return nil
	}
	return group
}

func windowsSemanticBumpActiveConnectExMaxPointer(connectExMaxPointer map[*prog.SemanticOperation]uint64,
	opsBySocket map[*prog.ResultArg]*prog.SemanticOperation, call *prog.Call) {
	high := windowsSemanticMaxPointerAddress(call)
	if high == 0 {
		return
	}
	for _, op := range opsBySocket {
		if op.Kind == "connectex" && !op.HasFact(windowsSemanticConnectContextUpdated) &&
			high > connectExMaxPointer[op] {
			connectExMaxPointer[op] = high
		}
	}
}

func windowsSemanticUpdateOperationMaxPointer(connectExMaxPointer map[*prog.SemanticOperation]uint64,
	op *prog.SemanticOperation, call *prog.Call) {
	if connectExMaxPointer == nil || op == nil {
		return
	}
	if high := windowsSemanticMaxPointerAddress(call); high > connectExMaxPointer[op] {
		connectExMaxPointer[op] = high
	}
}

func windowsSemanticMaxPointerAddress(call *prog.Call) uint64 {
	var high uint64
	if call == nil {
		return high
	}
	prog.ForeachArg(call, func(arg prog.Arg, _ *prog.ArgCtx) {
		ptr, ok := arg.(*prog.PointerArg)
		if !ok || ptr.IsSpecial() {
			return
		}
		if ptr.Address > high {
			high = ptr.Address
		}
	})
	return high
}

func windowsSemanticOverlappedZero(call *prog.Call, argIdx int) bool {
	return windowsSemanticPointerZero(call, argIdx)
}

func windowsSemanticPointerZero(call *prog.Call, argIdx int) bool {
	if call == nil || argIdx < 0 || argIdx >= len(call.Args) {
		return false
	}
	ptr, ok := call.Args[argIdx].(*prog.PointerArg)
	if !ok || ptr.IsSpecial() {
		return false
	}
	return windowsSemanticArgZero(ptr.Res)
}

func windowsSemanticArgZero(arg prog.Arg) bool {
	switch a := arg.(type) {
	case nil:
		return true
	case *prog.ConstArg:
		return a.Val == 0
	case *prog.ResultArg:
		return a.Res == nil && a.Val == 0 && a.OpDiv == 0 && a.OpAdd == 0 && !a.HasUses()
	case *prog.DataArg:
		if a.Dir() == prog.DirOut {
			return true
		}
		for _, b := range a.Data() {
			if b != 0 {
				return false
			}
		}
		return true
	case *prog.GroupArg:
		for _, inner := range a.Inner {
			if !windowsSemanticArgZero(inner) {
				return false
			}
		}
		return true
	case *prog.UnionArg:
		return windowsSemanticArgZero(a.Option)
	case *prog.PointerArg:
		return a.Address == 0 && windowsSemanticArgZero(a.Res)
	default:
		return false
	}
}

func windowsSemanticConnectExChainCallAllowed(name string) bool {
	switch name {
	case "WSAStartup",
		"socket$inet_tcp",
		"bind$inet_tcp",
		"listen$inet_tcp",
		"ioctlsocket$fionbio_listener",
		"ioctlsocket$fionbio_tcp_created",
		"connect$inet_tcp",
		"connect$inet_tcp_nonblock",
		"accept$inet_tcp",
		"accept$inet_tcp_nonblock",
		"closesocket$any",
		"bind$connectex_tcp",
		"ConnectEx$inet_tcp_pending",
		"DisconnectEx$inet_tcp_reuse",
		"CreateIoCompletionPort$disconnect_reuse_pending",
		"WSAGetOverlappedResult$disconnect_reuse_pending",
		"ConnectEx$inet_tcp_reuse",
		"CreateIoCompletionPort$connect_pending",
		"WSAGetOverlappedResult$connect_pending",
		"GetQueuedCompletionStatus$socket",
		"CancelIoEx$connect_pending",
		"CancelIo$connect_pending",
		"closesocket$connect_pending",
		"setsockopt$update_connect_context",
		"send$inet_tcp",
		"getsockname$tcp",
		"getpeername$tcp",
		"syz_emit_ethernet$windows",
		"syz_extract_tcp_res$windows":
		return true
	default:
		return false
	}
}

func windowsSemanticAcceptExChainCallAllowed(name string) bool {
	switch name {
	case "WSAStartup",
		"socket$inet_tcp",
		"bind$inet_tcp",
		"listen$inet_tcp",
		"ioctlsocket$fionbio_tcp_created",
		"connect$inet_tcp_nonblock",
		"socket$accept_tcp",
		"AcceptEx$inet_tcp_pending",
		"CreateIoCompletionPort$accept_pending",
		"WSAGetOverlappedResult$accept_pending",
		"GetQueuedCompletionStatus$socket",
		"GetAcceptExSockaddrs$inet_tcp",
		"setsockopt$update_accept_context",
		"CancelIoEx$accept_pending",
		"CancelIo$accept_pending",
		"closesocket$accept_pending",
		"send$inet_tcp",
		"recv$inet_accept_updated",
		"send$inet_accept_updated",
		"setsockopt$int_accept_updated",
		"getsockopt$int_accept_updated",
		"syz_emit_ethernet$windows",
		"syz_extract_tcp_res$windows",
		"syz_extract_tcp_res$windows_synack":
		return true
	default:
		return false
	}
}

func windowsSemanticArgWantsTCPConnected(call *prog.Call, argIdx int) bool {
	return windowsSemanticArgWantsResourcePrefix(call, argIdx, "SOCKET_TCP_CONNECTED")
}

func windowsSemanticArgWantsResourcePrefix(call *prog.Call, argIdx int, prefix string) bool {
	if call == nil || call.Meta == nil || argIdx < 0 || argIdx >= len(call.Meta.Args) {
		return false
	}
	res, ok := call.Meta.Args[argIdx].Type.(*prog.ResourceType)
	return ok && res.Desc != nil && strings.HasPrefix(res.Desc.Name, prefix)
}

func windowsSemanticArgWantsResource(call *prog.Call, argIdx int, name string) bool {
	if call == nil || call.Meta == nil || argIdx < 0 || argIdx >= len(call.Meta.Args) {
		return false
	}
	res, ok := call.Meta.Args[argIdx].Type.(*prog.ResourceType)
	return ok && res.Desc != nil && res.Desc.Name == name
}

func windowsSemanticToken(kind string, res *prog.ResultArg) string {
	return fmt.Sprintf("%s:%p", kind, res)
}

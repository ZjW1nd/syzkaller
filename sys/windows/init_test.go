package windows_test

import (
	"encoding/binary"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestInitTargetMarksWindowsHelpers(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if !target.Helpers.DeprioritizeAutomaticHelpers {
		t.Fatal("windows target did not enable helper deprioritization")
	}
	if !target.Helpers.NoGenerateAutomaticHelpers {
		t.Fatal("windows target did not protect helper syscalls from top-level generation")
	}
	if !target.Helpers.AvoidCollidingAutomaticHelpers {
		t.Fatal("windows target did not avoid colliding automatic helpers")
	}
	if !target.Helpers.SkipHintsForAutomaticHelpers {
		t.Fatal("windows target did not skip helper hints jobs")
	}
	if !target.Helpers.NoMutateAutomaticHelpers {
		t.Fatal("windows target did not auto-protect helper syscalls from direct mutation")
	}
	if !target.Helpers.SkipCorpusForAutomaticHelpers {
		t.Fatal("windows target did not skip helper-owned corpus persistence")
	}
	if !target.Helpers.SkipTriageForAutomaticHelpers {
		t.Fatal("windows target did not skip helper-owned triage jobs")
	}
	if !target.Helpers.AvoidAutomaticHelperBias {
		t.Fatal("windows target did not avoid helper bias during call generation")
	}
	for _, name := range []string{
		"CloseHandle", "CreateFileA", "VirtualAlloc",
		"GetCurrentProcess$process", "GetCurrentThread$thread",
		"CreateEventA$manual", "CreateEventA$auto", "CreateSemaphoreA$sem",
		"WSAStartup", "WSACleanup",
		"socket$inet_tcp", "socket$inet_udp", "socket$bound_udp", "socket$connected_udp",
		"socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp",
		"closesocket$any",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !target.CallIsAutomaticHelper(call) {
			t.Fatalf("syscall %q is not classified as AutomaticHelper", name)
		}
	}
}

func TestWindowsWinsockStartupScaffoldPolicy(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	sendto := target.SyscallMap["sendto$udp_bound"]
	startup := target.SyscallMap["WSAStartup"]
	socket := target.SyscallMap["socket$inet_udp"]
	if sendto == nil || startup == nil || socket == nil {
		t.Fatal("missing Winsock test syscalls")
	}

	expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{sendto: true})
	if !expanded[startup] {
		t.Fatal("Winsock expansion did not add WSAStartup scaffold")
	}
	if !expanded[socket] {
		t.Fatal("Winsock expansion did not keep UDP socket constructor enabled")
	}
	ct := target.BuildChoiceTable(nil, expanded)
	if !ct.Generatable(socket.ID) {
		t.Fatal("UDP socket helper should remain enabled as a constructor")
	}
	if ct.DirectlyGeneratable(socket.ID) {
		t.Fatal("UDP socket helper should not be a direct top-level choice")
	}
	if ct.DirectlyGeneratable(startup.ID) {
		t.Fatal("WSAStartup should be inserted by target policy, not random top-level choice")
	}
	if got := target.Bias.SelectGeneratedCall(&prog.Prog{Target: target}, 0, -1, ct); got != startup.ID {
		t.Fatalf("prefix generation selected %d, want WSAStartup id %d", got, startup.ID)
	}
}

func TestWindowsAFDProfileSkipsMalformedWinsockStartupOrder(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	afd, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	if afd.RuntimePolicy.ShouldScheduleProgram == nil {
		t.Fatal("AFD profile did not install runtime scheduler policy")
	}
	bad, err := afd.Deserialize([]byte(
		"r0 = socket$bound_udp(0x2, 0x2, 0x11)\n"+
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"sendto$udp_bound(r0, &(0x7f0000000100)='x', 0x1, 0x0, &(0x7f0000000200)={0x2, 0x4e26, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize bad program: %v", err)
	}
	if afd.RuntimePolicy.ShouldScheduleProgram("gen", bad) {
		t.Fatal("malformed Winsock startup order was scheduled")
	}
	duplicate, err := afd.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$bound_udp(0x2, 0x2, 0x11)\n"+
			"sendto$udp_bound(r0, &(0x7f0000000100)='x', 0x1, 0x0, &(0x7f0000000200)={0x2, 0x4e26, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"WSAStartup(0x202, &(0x7f0000000300)=0x0)\n"+
			"r1 = socket$bound_udp(0x2, 0x2, 0x11)\n"+
			"sendto$udp_bound(r1, &(0x7f0000000400)='y', 0x1, 0x0, &(0x7f0000000500)={0x2, 0x4e26, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize duplicate startup program: %v", err)
	}
	if afd.RuntimePolicy.ShouldScheduleProgram("gen", duplicate) {
		t.Fatal("duplicate Winsock startup scaffold was scheduled")
	}
	nonFirst, err := afd.Deserialize([]byte(
		"Sleep(0x0)\n"+
			"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$bound_udp(0x2, 0x2, 0x11)\n"+
			"sendto$udp_bound(r0, &(0x7f0000000100)='x', 0x1, 0x0, &(0x7f0000000200)={0x2, 0x4e26, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize non-first startup program: %v", err)
	}
	if afd.RuntimePolicy.ShouldScheduleProgram("gen", nonFirst) {
		t.Fatal("non-first Winsock startup scaffold was scheduled")
	}
	good, err := afd.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$bound_udp(0x2, 0x2, 0x11)\n"+
			"sendto$udp_bound(r0, &(0x7f0000000100)='x', 0x1, 0x0, &(0x7f0000000200)={0x2, 0x4e26, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize good program: %v", err)
	}
	if !afd.RuntimePolicy.ShouldScheduleProgram("gen", good) {
		t.Fatal("valid Winsock startup order was not scheduled")
	}
}

func TestWindowsAFDProfileSkipsUnusedResourceScaffolds(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	afd, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	if afd.RuntimePolicy.ShouldScheduleProgram == nil {
		t.Fatal("AFD profile did not install runtime scheduler policy")
	}
	unused, err := afd.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$bound_udp(0x2, 0x2, 0x11)\n"+
			"sendto$udp_bound(r0, &(0x7f0000000100)='x', 0x1, 0x0, &(0x7f0000000200)={0x2, 0x4e26, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r1 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r1, &(0x7f0000000300)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize unused scaffold program: %v", err)
	}
	if afd.RuntimePolicy.ShouldScheduleProgram("gen", unused) {
		t.Fatal("unused resource scaffold was scheduled")
	}
	validChain, err := afd.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = listen$inet_tcp(r1, 0x1)\n"+
			"r3 = accept$inet_tcp(r2, 0x0, 0x0)\n"+
			"WSARecv$accept(r3, &(0x7f0000000200)=[{0x40, &(0x7f0000000280)='\\x00'/64}], 0x1, &(0x7f0000000300), &(0x7f0000000340)=0x0, 0x0, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize valid chain program: %v", err)
	}
	if !afd.RuntimePolicy.ShouldScheduleProgram("gen", validChain) {
		t.Fatal("valid resource chain was not scheduled")
	}
}

func TestWindowsSocketOptionSurfaceUsesTypedSolSocketOptions(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, name := range []string{
		"setsockopt$int_tcp", "setsockopt$int_udp", "setsockopt$int_accept",
		"getsockopt$int_tcp", "getsockopt$int_udp", "getsockopt$int_accept",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		level, ok := call.Args[1].Type.(*prog.ConstType)
		if !ok {
			t.Fatalf("%s level type is %T, want *prog.ConstType", name, call.Args[1].Type)
		}
		if level.Val != 0xffff {
			t.Fatalf("%s level=%#x, want SOL_SOCKET", name, level.Val)
		}
		optname, ok := call.Args[2].Type.(*prog.FlagsType)
		if !ok {
			t.Fatalf("%s optname type is %T, want *prog.FlagsType", name, call.Args[2].Type)
		}
		if hasFlagValue(optname.Vals, 0xbfb) {
			t.Fatalf("%s still permits observed invalid socket option level as an option value", name)
		}
		if !hasFlagValue(optname.Vals, 0x4) {
			t.Fatalf("%s lost SO_REUSEADDR coverage", name)
		}
	}
}

func TestWindowsSlowPublicWinsockSurfaceIsBorrowingOnly(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, name := range []string{
		"select$afd_basic",
		"WSAIoctl$sio_address_list_query",
		"GetAcceptExSockaddrs$inet_tcp",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !call.Attrs.NoGenerate || !call.Attrs.NoMinimize {
			t.Fatalf("%s should be borrowing-only to keep broad AFD sessions out of known slow waits", name)
		}
	}

	sockaddrs := target.SyscallMap["GetAcceptExSockaddrs$inet_tcp"]
	buf, ok := sockaddrs.Args[0].Type.(*prog.PtrType)
	if !ok {
		t.Fatalf("GetAcceptExSockaddrs buffer type is %T, want *prog.PtrType",
			sockaddrs.Args[0].Type)
	}
	st, ok := buf.Elem.(*prog.StructType)
	if !ok {
		t.Fatalf("GetAcceptExSockaddrs buffer points to %T, want *prog.StructType", buf.Elem)
	}
	if st.Name() != "acceptex_sockaddrs_buffer" {
		t.Fatalf("GetAcceptExSockaddrs buffer struct=%q, want acceptex_sockaddrs_buffer", st.Name())
	}
	for idx, want := range map[int]uint64{1: 0, 2: 32, 3: 32} {
		arg, ok := sockaddrs.Args[idx].Type.(*prog.ConstType)
		if !ok {
			t.Fatalf("GetAcceptExSockaddrs arg %d type is %T, want *prog.ConstType",
				idx, sockaddrs.Args[idx].Type)
		}
		if arg.Val != want {
			t.Fatalf("GetAcceptExSockaddrs arg %d const=%d, want %d", idx, arg.Val, want)
		}
	}
}

func hasFlagValue(vals []uint64, want uint64) bool {
	for _, val := range vals {
		if val == want {
			return true
		}
	}
	return false
}

func TestWindowsCallRelevance(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if target.CallRelevanceScore == nil {
		t.Fatal("windows target did not set CallRelevanceScore")
	}
	helper := target.SyscallMap["CreateFileA"]
	shallow := target.SyscallMap["Sleep"]
	listen := target.SyscallMap["listen$inet_tcp"]
	recvAccept := target.SyscallMap["recv$inet_accept"]
	cancelPending := target.SyscallMap["CancelIoEx$connect_pending"]
	pendingCtor := target.SyscallMap["WSARecv$accept_pending"]
	if helper == nil || shallow == nil || listen == nil || recvAccept == nil ||
		cancelPending == nil || pendingCtor == nil {
		t.Fatal("missing syscall for relevance test")
	}
	if target.CallRelevance(helper) >= 0 {
		t.Fatalf("automatic helper relevance=%d, want negative", target.CallRelevance(helper))
	}
	if target.CallRelevance(shallow) != 1 {
		t.Fatalf("shallow relevance=%d, want 1", target.CallRelevance(shallow))
	}
	if target.CallRelevance(recvAccept) <= target.CallRelevance(listen) {
		t.Fatalf("deep consumer relevance=%d setup relevance=%d",
			target.CallRelevance(recvAccept), target.CallRelevance(listen))
	}
	if target.CallRelevance(cancelPending) <= target.CallRelevance(pendingCtor) {
		t.Fatalf("pending consumer relevance=%d pending ctor relevance=%d",
			target.CallRelevance(cancelPending), target.CallRelevance(pendingCtor))
	}
	if target.CallEligibleForTriage(target.SyscallMap["CreateFileA"]) {
		t.Fatal("automatic helper should not be eligible for triage")
	}
	if !target.CallEligibleForTriage(target.SyscallMap["Sleep"]) {
		t.Fatal("shallow non-helper syscall should remain eligible for default triage")
	}
}

func TestWindowsExpandEnabledCallsUsesResourceConstructors(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if target.ExpandEnabledCalls == nil {
		t.Fatal("windows target did not set ExpandEnabledCalls")
	}
	tests := []struct {
		root string
		want []string
	}{
		{
			root: "TransmitFile$inet_accept",
			want: []string{
				"TransmitFile$inet_accept",
				"socket$inet_tcp", "bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp",
				"CreateFileA",
			},
		},
		{
			root: "WSARecvEx$inet_accept",
			want: []string{
				"WSARecvEx$inet_accept",
				"socket$inet_tcp", "bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp",
			},
		},
		{
			root: "recvfrom$udp_bound",
			want: []string{"recvfrom$udp_bound", "socket$inet_udp", "bind$inet_udp"},
		},
		{
			root: "sendto$udp_connected",
			want: []string{"sendto$udp_connected", "socket$inet_udp", "connect$inet_udp"},
		},
		{
			root: "ConnectEx$inet_tcp_reuse",
			want: []string{
				"ConnectEx$inet_tcp_reuse",
				"socket$inet_tcp", "connect$inet_tcp", "DisconnectEx$inet_tcp_reuse",
			},
		},
		{
			root: "setsockopt$update_accept_context",
			want: []string{
				"setsockopt$update_accept_context",
				"socket$inet_tcp", "bind$inet_tcp", "listen$inet_tcp",
				"socket$accept_tcp", "AcceptEx$inet_tcp_pending",
			},
		},
	}
	for _, test := range tests {
		root := target.SyscallMap[test.root]
		if root == nil {
			t.Fatalf("missing syscall %q", test.root)
		}
		expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{
			root: true,
		})
		assertExpandedCalls(t, target, expanded, test.root, test.want)
	}
}

func TestWindowsExpandEnabledCallsUsesSocketResourceRoles(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	tests := []struct {
		root string
		want []string
	}{
		{
			root: "setsockopt$int_tcp",
			want: []string{"socket$inet_tcp", "connect$inet_tcp"},
		},
		{
			root: "CancelIoEx$accept_pending",
			want: []string{
				"socket$inet_tcp", "bind$inet_tcp", "listen$inet_tcp",
				"socket$accept_tcp", "AcceptEx$inet_tcp_pending",
			},
		},
		{
			root: "CancelIoEx$connect_pending",
			want: []string{"socket$inet_tcp", "bind$connectex_tcp", "ConnectEx$inet_tcp_pending"},
		},
		{
			root: "WSAEventSelect$accept",
			want: []string{
				"socket$inet_tcp", "bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp",
				"WSACreateEvent",
			},
		},
		{
			root: "GetQueuedCompletionStatus$socket",
			want: []string{
				"socket$inet_tcp", "bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp",
				"CreateIoCompletionPort$socket",
			},
		},
	}
	for _, test := range tests {
		root := target.SyscallMap[test.root]
		if root == nil {
			t.Fatalf("missing syscall %q", test.root)
		}
		expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{root: true})
		assertExpandedCalls(t, target, expanded, test.root, append([]string{test.root}, test.want...))
	}
}

func TestWindowsExpandEnabledCallsAddsFileAndObjectConstructors(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	tests := []struct {
		root string
		want []string
	}{
		{
			root: "FlushFileBuffers",
			want: []string{"FlushFileBuffers", "CreateFileA"},
		},
		{
			root: "SetEvent$event",
			want: []string{"SetEvent$event"},
		},
		{
			root: "GetTokenInformation$token",
			want: []string{"GetTokenInformation$token", "GetCurrentProcess$process", "OpenProcessToken$process"},
		},
		{
			root: "MapViewOfFile$section",
			want: []string{"MapViewOfFile$section", "CreateFileMappingA$pagefile"},
		},
		{
			root: "GetQueuedCompletionStatus$iocp",
			want: []string{"GetQueuedCompletionStatus$iocp", "CreateIoCompletionPort$create"},
		},
		{
			root: "ReadFile$pipe",
			want: []string{"ReadFile$pipe", "CreatePipe$anon"},
		},
		{
			root: "NtDeviceIoControlFile$afd_query_recv_tcp",
			want: []string{"NtDeviceIoControlFile$afd_query_recv_tcp", "socket$inet_tcp", "connect$inet_tcp"},
		},
		{
			root: "NtDeviceIoControlFile$afd_query_recv_accept",
			want: []string{
				"NtDeviceIoControlFile$afd_query_recv_accept",
				"socket$inet_tcp", "bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp",
			},
		},
		{
			root: "NtDeviceIoControlFile$afd_address_list_query_udp",
			want: []string{"NtDeviceIoControlFile$afd_address_list_query_udp", "socket$inet_udp", "bind$inet_udp"},
		},
		{
			root: "NtDeviceIoControlFile$afd_routing_interface_query_udp",
			want: []string{"NtDeviceIoControlFile$afd_routing_interface_query_udp", "socket$inet_udp", "connect$inet_udp"},
		},
		{
			root: "NtDeviceIoControlFile$afd_event_select_accept",
			want: []string{
				"NtDeviceIoControlFile$afd_event_select_accept",
				"socket$inet_tcp", "bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "WSACreateEvent",
			},
		},
	}
	for _, test := range tests {
		root := target.SyscallMap[test.root]
		if root == nil {
			t.Fatalf("missing syscall %q", test.root)
		}
		expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{root: true})
		assertExpandedCalls(t, target, expanded, test.root, test.want)
	}
	expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{
		target.SyscallMap["SetEvent$event"]: true,
	})
	if !expanded[target.SyscallMap["CreateEventA$manual"]] && !expanded[target.SyscallMap["CreateEventA$auto"]] {
		t.Fatal("SetEvent$event expansion did not add an EVENT_HANDLE constructor")
	}
}

func assertExpandedCalls(t *testing.T, target *prog.Target, expanded map[*prog.Syscall]bool, root string, names []string) {
	t.Helper()
	for _, name := range names {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("%s expansion is missing %q", root, name)
		}
	}
}

func TestWindowsExpandEnabledCallsDoesNotAddNameOnlyScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	root := target.SyscallMap["recv$inet_accept"]
	expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{root: true})
	startup := target.SyscallMap["WSAStartup"]
	if startup == nil {
		t.Fatal("missing syscall \"WSAStartup\"")
	}
	if !expanded[startup] {
		t.Fatal("Winsock resource closure did not add WSAStartup scaffold")
	}
	for _, name := range []string{"WSACleanup", "closesocket$any"} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if expanded[call] {
			t.Fatalf("resource closure should not add name-only scaffold %q", name)
		}
	}
}

func TestWindowsObjectResourceHierarchy(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	assertResource := func(callName string, index int, want string) {
		t.Helper()
		meta := target.SyscallMap[callName]
		if meta == nil {
			t.Fatalf("missing syscall %q", callName)
		}
		var typ prog.Type
		if index < 0 {
			typ = meta.Ret
		}
		if index >= 0 {
			typ = meta.Args[index].Type
		}
		res, ok := typ.(*prog.ResourceType)
		if !ok {
			t.Fatalf("%s[%d] has unexpected type %T", callName, index, typ)
		}
		if res.TypeName != want {
			t.Fatalf("%s[%d] resource=%q want=%q", callName, index, res.TypeName, want)
		}
	}
	assertPtrResource := func(callName string, index int, want string) {
		t.Helper()
		meta := target.SyscallMap[callName]
		if meta == nil {
			t.Fatalf("missing syscall %q", callName)
		}
		ptr, ok := meta.Args[index].Type.(*prog.PtrType)
		if !ok {
			t.Fatalf("%s[%d] has unexpected type %T", callName, index, meta.Args[index].Type)
		}
		res, ok := ptr.Elem.(*prog.ResourceType)
		if !ok {
			t.Fatalf("%s[%d] points to unexpected type %T", callName, index, ptr.Elem)
		}
		if res.TypeName != want {
			t.Fatalf("%s[%d] points to resource=%q want=%q", callName, index, res.TypeName, want)
		}
	}
	assertPtrStruct := func(callName string, index int, want string) {
		t.Helper()
		meta := target.SyscallMap[callName]
		if meta == nil {
			t.Fatalf("missing syscall %q", callName)
		}
		ptr, ok := meta.Args[index].Type.(*prog.PtrType)
		if !ok {
			t.Fatalf("%s[%d] has unexpected type %T", callName, index, meta.Args[index].Type)
		}
		st, ok := ptr.Elem.(*prog.StructType)
		if !ok {
			t.Fatalf("%s[%d] points to unexpected type %T", callName, index, ptr.Elem)
		}
		if st.Name() != want {
			t.Fatalf("%s[%d] points to struct=%q want=%q", callName, index, st.Name(), want)
		}
	}
	assertPtrArrayStruct := func(callName string, index int, want string) {
		t.Helper()
		meta := target.SyscallMap[callName]
		if meta == nil {
			t.Fatalf("missing syscall %q", callName)
		}
		ptr, ok := meta.Args[index].Type.(*prog.PtrType)
		if !ok {
			t.Fatalf("%s[%d] has unexpected type %T", callName, index, meta.Args[index].Type)
		}
		arr, ok := ptr.Elem.(*prog.ArrayType)
		if !ok {
			t.Fatalf("%s[%d] points to unexpected type %T", callName, index, ptr.Elem)
		}
		st, ok := arr.Elem.(*prog.StructType)
		if !ok {
			t.Fatalf("%s[%d] points to array of unexpected type %T", callName, index, arr.Elem)
		}
		if st.Name() != want {
			t.Fatalf("%s[%d] points to array struct=%q want=%q", callName, index, st.Name(), want)
		}
	}
	assertResource("GetCurrentProcess$process", -1, "PROCESS_HANDLE")
	assertResource("GetCurrentThread$thread", -1, "THREAD_HANDLE")
	assertResource("NtQueryInformationProcess", 0, "PROCESS_HANDLE")
	assertResource("NtSetInformationProcess", 0, "PROCESS_HANDLE")
	assertResource("NtFlushInstructionCache", 0, "PROCESS_HANDLE")
	assertResource("CreateEventA$manual", -1, "EVENT_HANDLE")
	assertResource("WSACreateEvent", -1, "WSAEVENT_HANDLE")
	assertResource("WSAEventSelect$accept", 1, "WSAEVENT_HANDLE")
	assertResource("WSAEnumNetworkEvents$accept", 1, "WSAEVENT_HANDLE")
	assertResource("SetEvent$event", 0, "EVENT_HANDLE")
	assertResource("WaitForSingleObject$wait", 0, "WAIT_HANDLE")
	assertResource("CreateSemaphoreA$sem", -1, "SEMAPHORE_HANDLE")
	assertResource("ReleaseSemaphore$sem", 0, "SEMAPHORE_HANDLE")
	assertPtrResource("OpenProcessToken$process", 2, "TOKEN_HANDLE")
	assertResource("GetTokenInformation$token", 0, "TOKEN_HANDLE")
	assertResource("CreateFileMappingA$file", -1, "SECTION_HANDLE")
	assertResource("MapViewOfFile$section", 0, "SECTION_HANDLE")
	assertResource("socket$inet_tcp", -1, "SOCKET_TCP_CREATED")
	assertResource("socket$inet_udp", -1, "SOCKET_UDP_CREATED")
	assertResource("bind$inet_tcp", 0, "SOCKET_TCP_CREATED")
	assertResource("bind$inet_tcp", -1, "SOCKET_TCP_BOUND")
	assertResource("bind$connectex_tcp", 0, "SOCKET_TCP_CREATED")
	assertResource("bind$connectex_tcp", -1, "SOCKET_TCP_CONNECTEX_BOUND")
	assertResource("connect$inet_tcp", 0, "SOCKET_TCP_CREATED")
	assertResource("connect$inet_tcp", -1, "SOCKET_TCP_CONNECTED")
	assertResource("bind$inet_udp", 0, "SOCKET_UDP_CREATED")
	assertResource("bind$inet_udp", -1, "SOCKET_UDP_BOUND")
	assertResource("connect$inet_udp", 0, "SOCKET_UDP_CREATED")
	assertResource("connect$inet_udp", -1, "SOCKET_UDP_PEERED")
	assertResource("CreateIoCompletionPort$create", -1, "IOCP_HANDLE")
	assertResource("CreateIoCompletionPort$associate", 1, "IOCP_HANDLE")
	assertResource("GetQueuedCompletionStatus$iocp", 0, "IOCP_HANDLE")
	assertResource("CreateIoCompletionPort$socket", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("CreateIoCompletionPort$accept_pending", 0, "SOCKET_TCP_ACCEPT_PENDING")
	assertResource("CreateIoCompletionPort$accept_recv_pending", 0, "SOCKET_TCP_ACCEPT_RECV_PENDING")
	assertResource("CreateIoCompletionPort$accept_send_pending", 0, "SOCKET_TCP_ACCEPT_SEND_PENDING")
	assertResource("CreateIoCompletionPort$tcp_recv_pending", 0, "SOCKET_TCP_RECV_PENDING")
	assertResource("CreateIoCompletionPort$tcp_send_pending", 0, "SOCKET_TCP_SEND_PENDING")
	assertResource("CreateIoCompletionPort$connect_pending", 0, "SOCKET_TCP_CONNECTING")
	assertResource("CreateIoCompletionPort$socket", -1, "IOCP_SOCKET")
	assertResource("CreateIoCompletionPort$accept_pending", -1, "IOCP_SOCKET")
	assertResource("CreateIoCompletionPort$accept_recv_pending", -1, "IOCP_SOCKET")
	assertResource("CreateIoCompletionPort$accept_send_pending", -1, "IOCP_SOCKET")
	assertResource("CreateIoCompletionPort$tcp_recv_pending", -1, "IOCP_SOCKET")
	assertResource("CreateIoCompletionPort$tcp_send_pending", -1, "IOCP_SOCKET")
	assertResource("CreateIoCompletionPort$connect_pending", -1, "IOCP_SOCKET")
	assertResource("GetQueuedCompletionStatus$socket", 0, "IOCP_SOCKET")
	assertPtrResource("CreatePipe$anon", 0, "PIPE_READ_HANDLE")
	assertPtrResource("CreatePipe$anon", 1, "PIPE_WRITE_HANDLE")
	assertResource("ReadFile$pipe", 0, "PIPE_READ_HANDLE")
	assertResource("WriteFile$pipe", 0, "PIPE_WRITE_HANDLE")
	assertResource("NtReadFile", 1, "EVENT_HANDLE")
	assertResource("NtWriteFile", 1, "EVENT_HANDLE")
	assertResource("NtDeviceIoControlFile", 0, "FILE_HANDLE")
	assertResource("NtDeviceIoControlFile", 1, "EVENT_HANDLE")
	assertResource("NtDeviceIoControlFile$afd_query_recv_tcp", 0, "SOCKET_TCP_CONNECTED")
	assertResource("NtDeviceIoControlFile$afd_query_recv_accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("NtDeviceIoControlFile$afd_get_remote_address_tcp", 0, "SOCKET_TCP_CONNECTED")
	assertResource("NtDeviceIoControlFile$afd_get_context_tcp", 0, "SOCKET_TCP_CONNECTED")
	assertResource("NtDeviceIoControlFile$afd_address_list_query_udp", 0, "SOCKET_UDP_BOUND")
	assertResource("NtDeviceIoControlFile$afd_routing_interface_query_udp", 0, "SOCKET_UDP_PEERED")
	assertResource("NtDeviceIoControlFile$afd_event_select_accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("NtDeviceIoControlFile$afd_enum_network_events_accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("NtDeviceIoControlFile$afd_poll_accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("NtFsControlFile", 0, "FILE_HANDLE")
	assertResource("NtFsControlFile", 1, "EVENT_HANDLE")
	assertResource("NtFsControlFile$ntfs_get_compression", 0, "FILE_HANDLE")
	assertResource("NtFsControlFile$ntfs_get_compression", 1, "EVENT_HANDLE")
	assertResource("NtFsControlFile$ntfs_set_compression", 0, "FILE_HANDLE")
	assertResource("NtFsControlFile$ntfs_set_compression", 1, "EVENT_HANDLE")
	assertResource("NtFsControlFile$ntfs_set_sparse", 0, "FILE_HANDLE")
	assertResource("NtFsControlFile$ntfs_set_sparse", 1, "EVENT_HANDLE")
	assertResource("NtFsControlFile$ntfs_set_zero_data", 0, "FILE_HANDLE")
	assertResource("NtFsControlFile$ntfs_set_zero_data", 1, "EVENT_HANDLE")
	assertResource("NtFsControlFile$ntfs_query_allocated_ranges", 0, "FILE_HANDLE")
	assertResource("NtFsControlFile$ntfs_query_allocated_ranges", 1, "EVENT_HANDLE")
	assertPtrStruct("NtFsControlFile$ntfs_get_compression", 8, "NTFS_COMPRESSION_FORMAT")
	assertPtrStruct("NtFsControlFile$ntfs_set_compression", 6, "NTFS_COMPRESSION_FORMAT")
	assertPtrStruct("NtFsControlFile$ntfs_set_sparse", 6, "FILE_SET_SPARSE_BUFFER")
	assertPtrStruct("NtFsControlFile$ntfs_set_zero_data", 6, "FILE_ZERO_DATA_INFORMATION")
	assertPtrStruct("NtFsControlFile$ntfs_query_allocated_ranges", 6, "FILE_ALLOCATED_RANGE_BUFFER")
	assertPtrArrayStruct("NtFsControlFile$ntfs_query_allocated_ranges", 8, "FILE_ALLOCATED_RANGE_BUFFER")
	assertPtrStruct("NtDeviceIoControlFile$afd_query_recv_tcp", 8, "AFD_RECEIVE_INFORMATION")
	assertPtrStruct("NtDeviceIoControlFile$afd_query_recv_accept", 8, "AFD_RECEIVE_INFORMATION")
	assertPtrStruct("NtDeviceIoControlFile$afd_get_remote_address_tcp", 8, "sockaddr_in")
	assertPtrStruct("NtDeviceIoControlFile$afd_address_list_query_udp", 8, "afd_address_list")
	assertPtrStruct("NtDeviceIoControlFile$afd_routing_interface_query_udp", 6, "sockaddr_in")
	assertPtrStruct("NtDeviceIoControlFile$afd_routing_interface_query_udp", 8, "sockaddr_in")
	assertPtrStruct("NtDeviceIoControlFile$afd_event_select_accept", 6, "AFD_EVENT_SELECT_INFO")
	assertPtrStruct("NtDeviceIoControlFile$afd_enum_network_events_accept", 8, "AFD_ENUM_NETWORK_EVENTS_INFO")
	assertPtrStruct("NtDeviceIoControlFile$afd_poll_accept", 6, "AFD_POLL_INFO")
	assertPtrStruct("NtDeviceIoControlFile$afd_poll_accept", 8, "AFD_POLL_INFO")
	assertPtrStruct("AcceptEx$inet_tcp", 7, "OVERLAPPED")
	assertResource("AcceptEx$inet_tcp_pending", 0, "SOCKET_LISTENER")
	assertResource("AcceptEx$inet_tcp_pending", 1, "SOCKET_ACCEPT")
	assertResource("AcceptEx$inet_tcp_pending", -1, "SOCKET_TCP_ACCEPT_PENDING")
	assertPtrStruct("AcceptEx$inet_tcp_pending", 7, "OVERLAPPED")
	assertResource("setsockopt$update_accept_context", 0, "SOCKET_TCP_ACCEPT_PENDING")
	assertPtrResource("setsockopt$update_accept_context", 3, "SOCKET_LISTENER")
	assertResource("setsockopt$update_accept_context", -1, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("send$inet_accept_updated", 0, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("recv$inet_accept_updated", 0, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("setsockopt$int_accept_updated", 0, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("getsockopt$int_accept_updated", 0, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertPtrStruct("TransmitFile$inet_accept", 4, "OVERLAPPED")
	assertPtrStruct("WSAIoctl$sio_address_list_query", 4, "afd_address_list")
	assertPtrStruct("WSAIoctl$sio_routing_interface_query", 2, "sockaddr_in")
	assertPtrStruct("WSAIoctl$sio_routing_interface_query", 4, "sockaddr_in")
	assertResource("WSAIoctl$sio_routing_interface_query", 0, "SOCKET_UDP_PEERED")
	assertPtrStruct("WSAIoctl$sio_keepalive_vals", 2, "tcp_keepalive")
	assertPtrStruct("WSAIoctl$sio_get_extension_function_pointer", 2, "wsa_guid_connectex")
	assertResource("ConnectEx$inet_tcp", 0, "SOCKET_TCP_CONNECTEX_BOUND")
	assertResource("ConnectEx$inet_tcp", -1, "SOCKET_TCP_CONNECTED")
	assertPtrStruct("ConnectEx$inet_tcp", 1, "sockaddr_in")
	assertResource("ConnectEx$inet_tcp_pending", 0, "SOCKET_TCP_CONNECTEX_BOUND")
	assertResource("ConnectEx$inet_tcp_pending", -1, "SOCKET_TCP_CONNECTING")
	assertPtrStruct("ConnectEx$inet_tcp_pending", 1, "sockaddr_in")
	assertPtrStruct("ConnectEx$inet_tcp_pending", 6, "OVERLAPPED")
	assertPtrStruct("DisconnectEx$inet_tcp", 1, "OVERLAPPED")
	assertPtrArrayStruct("TransmitPackets$inet_accept", 1, "transmit_packet_memory")
	assertResource("WSARecvMsg$udp", 0, "SOCKET_UDP_BOUND")
	assertPtrStruct("WSARecvMsg$udp", 1, "WSAMSG_OUT")
	assertPtrStruct("WSAEnumNetworkEvents$tcp", 2, "WSANETWORKEVENTS")
	assertResource("WSAGetOverlappedResult$socket", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("WSAGetOverlappedResult$accept_pending", 0, "SOCKET_TCP_ACCEPT_PENDING")
	assertResource("WSAGetOverlappedResult$accept_recv_pending", 0, "SOCKET_TCP_ACCEPT_RECV_PENDING")
	assertResource("WSAGetOverlappedResult$accept_send_pending", 0, "SOCKET_TCP_ACCEPT_SEND_PENDING")
	assertResource("WSAGetOverlappedResult$tcp_recv_pending", 0, "SOCKET_TCP_RECV_PENDING")
	assertResource("WSAGetOverlappedResult$tcp_send_pending", 0, "SOCKET_TCP_SEND_PENDING")
	assertResource("WSAGetOverlappedResult$connect_pending", 0, "SOCKET_TCP_CONNECTING")
	assertResource("CancelIoEx$socket", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("CancelIoEx$accept_pending", 0, "SOCKET_TCP_ACCEPT_PENDING")
	assertResource("CancelIoEx$accept_recv_pending", 0, "SOCKET_TCP_ACCEPT_RECV_PENDING")
	assertResource("CancelIoEx$accept_send_pending", 0, "SOCKET_TCP_ACCEPT_SEND_PENDING")
	assertResource("CancelIoEx$tcp_recv_pending", 0, "SOCKET_TCP_RECV_PENDING")
	assertResource("CancelIoEx$tcp_send_pending", 0, "SOCKET_TCP_SEND_PENDING")
	assertResource("CancelIoEx$connect_pending", 0, "SOCKET_TCP_CONNECTING")
	assertResource("CancelIo$socket", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("CancelIo$accept_pending", 0, "SOCKET_TCP_ACCEPT_PENDING")
	assertResource("CancelIo$accept_recv_pending", 0, "SOCKET_TCP_ACCEPT_RECV_PENDING")
	assertResource("CancelIo$accept_send_pending", 0, "SOCKET_TCP_ACCEPT_SEND_PENDING")
	assertResource("CancelIo$tcp_recv_pending", 0, "SOCKET_TCP_RECV_PENDING")
	assertResource("CancelIo$tcp_send_pending", 0, "SOCKET_TCP_SEND_PENDING")
	assertResource("CancelIo$connect_pending", 0, "SOCKET_TCP_CONNECTING")
	assertResource("closesocket$accept_pending", 0, "SOCKET_TCP_ACCEPT_PENDING")
	assertResource("closesocket$accept_recv_pending", 0, "SOCKET_TCP_ACCEPT_RECV_PENDING")
	assertResource("closesocket$accept_send_pending", 0, "SOCKET_TCP_ACCEPT_SEND_PENDING")
	assertResource("closesocket$tcp_recv_pending", 0, "SOCKET_TCP_RECV_PENDING")
	assertResource("closesocket$tcp_send_pending", 0, "SOCKET_TCP_SEND_PENDING")
	assertResource("closesocket$connect_pending", 0, "SOCKET_TCP_CONNECTING")
	assertPtrStruct("WSAGetOverlappedResult$socket", 1, "OVERLAPPED")
	assertPtrStruct("WSAGetOverlappedResult$accept_pending", 1, "OVERLAPPED")
	assertPtrStruct("WSAGetOverlappedResult$accept_recv_pending", 1, "OVERLAPPED")
	assertPtrStruct("WSAGetOverlappedResult$accept_send_pending", 1, "OVERLAPPED")
	assertPtrStruct("WSAGetOverlappedResult$tcp_recv_pending", 1, "OVERLAPPED")
	assertPtrStruct("WSAGetOverlappedResult$tcp_send_pending", 1, "OVERLAPPED")
	assertPtrStruct("WSAGetOverlappedResult$connect_pending", 1, "OVERLAPPED")
	assertPtrStruct("CancelIoEx$socket", 1, "OVERLAPPED")
	assertPtrStruct("CancelIoEx$accept_pending", 1, "OVERLAPPED")
	assertPtrStruct("CancelIoEx$accept_recv_pending", 1, "OVERLAPPED")
	assertPtrStruct("CancelIoEx$accept_send_pending", 1, "OVERLAPPED")
	assertPtrStruct("CancelIoEx$tcp_recv_pending", 1, "OVERLAPPED")
	assertPtrStruct("CancelIoEx$tcp_send_pending", 1, "OVERLAPPED")
	assertPtrStruct("CancelIoEx$connect_pending", 1, "OVERLAPPED")
	assertResource("WSARecv$accept_pending", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("WSARecv$accept_pending", -1, "SOCKET_TCP_ACCEPT_RECV_PENDING")
	assertResource("WSASend$accept_pending", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("WSASend$accept_pending", -1, "SOCKET_TCP_ACCEPT_SEND_PENDING")
	assertResource("WSARecv$tcp_pending", 0, "SOCKET_TCP_CONNECTED")
	assertResource("WSARecv$tcp_pending", -1, "SOCKET_TCP_RECV_PENDING")
	assertResource("WSASend$tcp_pending", 0, "SOCKET_TCP_CONNECTED")
	assertResource("WSASend$tcp_pending", -1, "SOCKET_TCP_SEND_PENDING")
	assertPtrStruct("WSARecv$accept_pending", 5, "OVERLAPPED")
	assertPtrStruct("WSASend$accept_pending", 5, "OVERLAPPED")
	assertPtrStruct("WSARecv$tcp_pending", 5, "OVERLAPPED")
	assertPtrStruct("WSASend$tcp_pending", 5, "OVERLAPPED")
}

func TestWindowsObjectStructLayouts(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	typeByName := func(name string) prog.Type {
		t.Helper()
		for _, typ := range target.Types {
			if typ.Name() == name {
				return typ
			}
		}
		t.Fatalf("missing type %q", name)
		return nil
	}
	tests := []struct {
		name string
		size uint64
	}{
		{name: "SECURITY_ATTRIBUTES", size: 0x18},
		{name: "SECURITY_DESCRIPTOR", size: 0x28},
		{name: "ACL", size: 0x8},
		{name: "OVERLAPPED", size: 0x20},
		{name: "IO_STATUS_BLOCK", size: 0x10},
		{name: "LARGE_INTEGER", size: 0x8},
		{name: "FILE_BASIC_INFORMATION", size: 0x28},
		{name: "FILE_STANDARD_INFORMATION", size: 0x18},
		{name: "FILE_NETWORK_OPEN_INFORMATION", size: 0x38},
		{name: "NTFS_COMPRESSION_FORMAT", size: 0x2},
		{name: "FILE_SET_SPARSE_BUFFER", size: 0x1},
		{name: "FILE_ZERO_DATA_INFORMATION", size: 0x10},
		{name: "FILE_ALLOCATED_RANGE_BUFFER", size: 0x10},
		{name: "AFD_RECEIVE_INFORMATION", size: 0x8},
		{name: "AFD_POLL_HANDLE_INFO", size: 0x10},
		{name: "AFD_POLL_INFO", size: 0x20},
		{name: "AFD_EVENT_SELECT_INFO", size: 0x10},
		{name: "AFD_ENUM_NETWORK_EVENTS_INFO", size: 0x38},
		{name: "tcp_keepalive", size: 0xc},
		{name: "wsa_guid_connectex", size: 0x10},
		{name: "afd_address_list", size: 0x44},
		{name: "WSAMSG_OUT", size: 0x38},
		{name: "transmit_packet_memory", size: 0x18},
		{name: "WSANETWORKEVENTS", size: 0x2c},
	}
	for _, test := range tests {
		if got := typeByName(test.name).Size(); got != test.size {
			t.Fatalf("%s size: got %#x, want %#x", test.name, got, test.size)
		}
	}
}

func TestWindowsNtControlCallsHaveFullArity(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, name := range []string{
		"NtDeviceIoControlFile",
		"NtDeviceIoControlFile$afd_query_recv_tcp",
		"NtDeviceIoControlFile$afd_query_recv_accept",
		"NtDeviceIoControlFile$afd_get_remote_address_tcp",
		"NtDeviceIoControlFile$afd_get_context_tcp",
		"NtDeviceIoControlFile$afd_address_list_query_udp",
		"NtDeviceIoControlFile$afd_routing_interface_query_udp",
		"NtDeviceIoControlFile$afd_event_select_accept",
		"NtDeviceIoControlFile$afd_enum_network_events_accept",
		"NtDeviceIoControlFile$afd_poll_accept",
		"NtFsControlFile",
		"NtFsControlFile$ntfs_get_compression",
		"NtFsControlFile$ntfs_set_compression",
		"NtFsControlFile$ntfs_set_sparse",
		"NtFsControlFile$ntfs_set_zero_data",
		"NtFsControlFile$ntfs_query_allocated_ranges",
	} {
		meta := target.SyscallMap[name]
		if meta == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if got := len(meta.Args); got != 10 {
			t.Fatalf("%s arg count: got %d, want 10", name, got)
		}
		if got := prog.MaxArgs; got < len(meta.Args) {
			t.Fatalf("prog.MaxArgs=%d does not cover %s arg count %d", got, name, len(meta.Args))
		}
	}
}

func TestWindowsAuxResources(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if !target.AuxResources["HANDLE"] {
		t.Fatal("HANDLE not marked as AuxResources")
	}
	if !target.AuxResources["SOCKET"] {
		t.Fatal("SOCKET not marked as AuxResources")
	}
	if target.AuxResources["FILE_HANDLE"] {
		t.Fatal("FILE_HANDLE should not be marked as AuxResources")
	}
	if target.AuxResources["SOCKET_TCP"] {
		t.Fatal("SOCKET_TCP should not be marked as AuxResources")
	}
}

func TestWindowsSpecialPointers(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if len(target.SpecialPointers) < 5 {
		t.Fatalf("expected at least 5 SpecialPointers (3 defaults + NT addresses), got %d", len(target.SpecialPointers))
	}
	ntAddrs := []uint64{
		0xFFFFF78000000000,
		0xFFFFF80000000000,
		0xFFFFFF7F00000000,
		0x000007FFFFFE0000,
	}
	for _, addr := range ntAddrs {
		found := false
		for _, p := range target.SpecialPointers {
			if p == addr {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("NT kernel address 0x%016X missing from SpecialPointers", addr)
		}
	}
}

func TestWindowsNeutralize(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if target.Neutralize == nil {
		t.Fatal("Neutralize not set")
	}
	tests := []struct {
		name     string
		argIndex int
	}{
		{name: "ExitProcess", argIndex: 0},
		{name: "ExitThread", argIndex: 0},
		{name: "TerminateProcess", argIndex: 1},
		{name: "TerminateJobObject", argIndex: 1},
		{name: "Sleep", argIndex: 0},
		{name: "SleepEx", argIndex: 0},
		{name: "WaitForSingleObject", argIndex: 1},
		{name: "WaitForSingleObjectEx", argIndex: 1},
		{name: "WaitForMultipleObjects", argIndex: 3},
		{name: "WaitForMultipleObjectsEx", argIndex: 3},
		{name: "WaitOnAddress", argIndex: 3},
		{name: "MsgWaitForMultipleObjectsEx", argIndex: 2},
		{name: "RegisterWaitForSingleObject", argIndex: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := target.SyscallMap[tt.name]
			if meta == nil {
				t.Fatalf("syscall %q not found", tt.name)
			}
			args := make([]prog.Arg, len(meta.Args))
			args[tt.argIndex] = prog.MakeConstArg(meta.Args[tt.argIndex].Type, prog.DirIn, 5000)
			call := &prog.Call{Meta: meta, Args: args}
			if err := target.Neutralize(call, false); err != nil {
				t.Fatalf("Neutralize error: %v", err)
			}
			value := call.Args[tt.argIndex].(*prog.ConstArg)
			if value.Val != 0 {
				t.Fatalf("%s argument %d not neutralized: got %d, want 0", tt.name, tt.argIndex, value.Val)
			}
		})
	}
	meta := target.SyscallMap["NtQuerySystemInformation"]
	if meta == nil {
		t.Fatal("NtQuerySystemInformation not found")
	}
	call := &prog.Call{
		Meta: meta,
		Args: []prog.Arg{
			prog.MakeConstArg(meta.Args[0].Type, prog.DirIn, 7),
		},
	}
	if err := target.Neutralize(call, false); err != nil {
		t.Fatalf("Neutralize error: %v", err)
	}
	if got := call.Args[0].(*prog.ConstArg).Val; got != 7 {
		t.Fatalf("ordinary syscall was changed: got %d, want 7", got)
	}
}

func TestWindowsChoiceTableResourcePriorities(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	// Enable FILE_HANDLE consumers + socket CONNECTED consumer + a plain query.
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["NtFsControlFile"]:          true, // uses FILE_HANDLE
		target.SyscallMap["getsockopt$int_tcp"]:       true, // uses SOCKET_CONNECTED
		target.SyscallMap["NtQuerySystemInformation"]: true, // no resources
	}
	// ExpandEnabledCalls auto-adds scaffold.
	ct := target.BuildChoiceTable(nil, enabled)
	if ct == nil {
		t.Fatal("BuildChoiceTable returned nil")
	}
	// Verify all enabled syscalls are generatable.
	for _, name := range []string{
		"NtFsControlFile", "getsockopt$int_tcp", "NtQuerySystemInformation",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !ct.Generatable(call.ID) {
			t.Fatalf("syscall %q is not generatable", name)
		}
	}
	// Verify that expanded scaffold syscalls are also generatable.
	for _, name := range []string{
		"CreateFileA",
		"socket$inet_tcp",
		"connect$inet_tcp",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			continue
		}
		if !ct.Generatable(call.ID) {
			t.Fatalf("scaffold syscall %q is not generatable after expansion", name)
		}
	}
}

func TestWindowsAFDAsyncSeedOnlyCallsAreNotGeneratedStandalone(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	helper := target.SyscallMap["socket$listener_tcp"]
	if helper == nil {
		t.Fatal("socket$listener_tcp missing from windows/amd64 target")
	}
	for _, name := range []string{
		"GetQueuedCompletionStatus$socket",
		"WSAEventSelect$tcp",
		"WSAEventSelect$accept",
		"WSAEnumNetworkEvents$tcp",
		"WSAEnumNetworkEvents$accept",
		"AcceptEx$inet_tcp_pending",
		"ConnectEx$inet_tcp_pending",
		"WSARecv$tcp_pending",
		"WSASend$tcp_pending",
		"WSARecv$accept_pending",
		"WSASend$accept_pending",
		"CreateIoCompletionPort$accept_pending",
		"CreateIoCompletionPort$accept_recv_pending",
		"CreateIoCompletionPort$accept_send_pending",
		"CreateIoCompletionPort$tcp_recv_pending",
		"CreateIoCompletionPort$tcp_send_pending",
		"CreateIoCompletionPort$connect_pending",
		"WSAGetOverlappedResult$socket",
		"WSAGetOverlappedResult$accept_pending",
		"WSAGetOverlappedResult$accept_recv_pending",
		"WSAGetOverlappedResult$accept_send_pending",
		"WSAGetOverlappedResult$tcp_recv_pending",
		"WSAGetOverlappedResult$tcp_send_pending",
		"WSAGetOverlappedResult$connect_pending",
		"CancelIoEx$socket",
		"CancelIoEx$accept_pending",
		"CancelIoEx$accept_recv_pending",
		"CancelIoEx$accept_send_pending",
		"CancelIoEx$tcp_recv_pending",
		"CancelIoEx$tcp_send_pending",
		"CancelIoEx$connect_pending",
		"CancelIo$socket",
		"CancelIo$accept_pending",
		"CancelIo$accept_recv_pending",
		"CancelIo$accept_send_pending",
		"CancelIo$tcp_recv_pending",
		"CancelIo$tcp_send_pending",
		"CancelIo$connect_pending",
		"closesocket$accept_pending",
		"closesocket$accept_recv_pending",
		"closesocket$accept_send_pending",
		"closesocket$tcp_recv_pending",
		"closesocket$tcp_send_pending",
		"closesocket$connect_pending",
		"NtDeviceIoControlFile$afd_event_select_accept",
		"NtDeviceIoControlFile$afd_enum_network_events_accept",
		"NtDeviceIoControlFile$afd_poll_accept",
	} {
		meta := target.SyscallMap[name]
		if meta == nil {
			t.Fatalf("%s missing from windows/amd64 target", name)
		}
		if !meta.Attrs.NoGenerate || !meta.Attrs.NoMinimize {
			t.Fatalf("%s should stay scaffold/seed-only and no_minimize", name)
		}
		ct := target.BuildChoiceTable(nil, map[*prog.Syscall]bool{
			meta:   true,
			helper: true,
		})
		if ct.Generatable(meta.ID) {
			t.Fatalf("%s should not be chosen as a standalone generated call", name)
		}
	}
}

func TestWindowsAFDCompletionStatusSeedsPollWithoutWaiting(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	files, err := filepath.Glob("test/nyx_afd_*.txt")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	checked := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", file, err)
		}
		if !strings.Contains(string(data), "GetQueuedCompletionStatus$socket") {
			continue
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("Deserialize(%s): %v", file, err)
		}
		for _, call := range p.Calls {
			if call.Meta == nil || call.Meta.Name != "GetQueuedCompletionStatus$socket" {
				continue
			}
			checked++
			if len(call.Args) != 5 {
				t.Fatalf("%s unexpected GetQueuedCompletionStatus$socket arg count: %d",
					file, len(call.Args))
			}
			timeout, ok := call.Args[4].(*prog.ConstArg)
			if !ok {
				t.Fatalf("%s unexpected timeout arg: %#v", file, call.Args[4])
			}
			if timeout.Val != 0 {
				t.Fatalf("%s GetQueuedCompletionStatus$socket timeout=%#x, want non-blocking poll",
					file, timeout.Val)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no AFD GetQueuedCompletionStatus$socket seeds checked")
	}
}

func TestWindowsAFDSelectBasicPollsWithoutWaiting(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	meta := target.SyscallMap["select$afd_basic"]
	if meta == nil {
		t.Fatal("select$afd_basic missing from windows/amd64 target")
	}
	if len(meta.Args) != 5 {
		t.Fatalf("select$afd_basic arg count=%d, want 5", len(meta.Args))
	}
	timeout, ok := meta.Args[4].Type.(*prog.PtrType)
	if !ok {
		t.Fatalf("select$afd_basic timeout type=%T, want *prog.PtrType", meta.Args[4].Type)
	}
	if timeout.Optional() {
		t.Fatal("select$afd_basic timeout must not be optional")
	}
	tv, ok := timeout.Elem.(*prog.StructType)
	if !ok || tv.Name() != "timeval_zero" {
		t.Fatalf("select$afd_basic timeout elem=%T/%q, want timeval_zero", timeout.Elem, timeout.Elem.Name())
	}
	for _, field := range tv.Fields {
		c, ok := field.Type.(*prog.ConstType)
		var val uint64
		if ok {
			val = c.Val
		}
		if !ok || c.Val != 0 {
			t.Fatalf("select$afd_basic timeout field %s type=%T val=%#v, want const[0]",
				field.Name, field.Type, val)
		}
	}
}

func TestWindowsVNetPseudoSyscallsAreSeedOnly(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	helper := target.SyscallMap["socket$listener_tcp"]
	if helper == nil {
		t.Fatal("socket$listener_tcp missing from windows/amd64 target")
	}
	direct := target.SyscallMap["Sleep"]
	if direct == nil {
		t.Fatal("Sleep missing from windows/amd64 target")
	}
	for _, name := range []string{
		"syz_emit_ethernet$windows",
		"syz_extract_tcp_res$windows",
		"syz_extract_tcp_res$windows_synack",
	} {
		meta := target.SyscallMap[name]
		if meta == nil {
			t.Fatalf("%s missing from windows/amd64 target", name)
		}
		if !meta.Attrs.NoGenerate || !meta.Attrs.NoMinimize {
			t.Fatalf("%s should stay seed-only until the Windows injection model is generation-ready", name)
		}
		ct := target.BuildChoiceTable(nil, map[*prog.Syscall]bool{
			meta:   true,
			helper: true,
			direct: true,
		})
		if ct.Generatable(meta.ID) {
			t.Fatalf("%s should not be chosen as a standalone generated call", name)
		}
	}
}

func TestWindowsVNetSeedsCoverTCPAndUDPPayloads(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, file := range []string{
		"test/nyx_vnet_ipv4_tcp_syn.txt",
		"test/nyx_vnet_ipv4_udp_payload.txt",
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", file, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("Deserialize(%s): %v", file, err)
		}
		if _, err := p.SerializeForExec(); err != nil {
			t.Fatalf("SerializeForExec(%s): %v", file, err)
		}
		if len(p.Calls) == 0 || p.Calls[0].Meta.Name != "syz_emit_ethernet$windows" {
			t.Fatalf("%s should start with syz_emit_ethernet$windows", file)
		}
	}
}

func TestWindowsVNetTCPSeedsUseStructuredPackets(t *testing.T) {
	for _, file := range []string{
		"test/nyx_vnet_ipv4_tcp_syn.txt",
		"test/nyx_afd_acceptex_vnet_iocp.txt",
		"test/nyx_afd_acceptex_vnet_sockaddrs.txt",
		"test/nyx_afd_accept_vnet_syn.txt",
		"test/nyx_afd_listener_vnet_synack_tapmac_any.txt",
		"test/nyx_afd_listener_vnet_synack_tapmac_any_retry.txt",
		"test/nyx_afd_listener_vnet_syn_tapmac_any_stage1.txt",
		"test/nyx_afd_listener_vnet_arp_syn_tapmac_any_bind_any_stage1.txt",
		"test/nyx_afd_accept_vnet_syn_tapmac.txt",
		"test/nyx_afd_accept_vnet_syn_tapmac_any.txt",
		"test/nyx_afd_accept_vnet_recv.txt",
		"test/nyx_afd_accept_vnet_recv_nonblock.txt",
		"test/nyx_afd_accept_vnet_wsarecv_pending_iocp.txt",
		"test/nyx_afd_accept_vnet_wsarecv.txt",
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", file, err)
		}
		text := string(data)
		if strings.Contains(text, "vnet-ipv4-tcp-") || strings.Contains(text, "@raw=") {
			t.Fatalf("%s should use structured IPv4/TCP packets, not raw placeholders", file)
		}
		if !strings.Contains(text, "@ipv4={0x800, @tcp=") || !strings.Contains(text, "0x6") {
			t.Fatalf("%s should describe an IPv4 TCP packet", file)
		}
	}
	data, err := os.ReadFile("test/nyx_afd_accept_vnet_wsarecv.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "{{0x9c40, 0x4e20, r2, r1, 0x0, 0x0, 0x5, 0x18") || !strings.Contains(text, "'afd-vnet'") {
		t.Fatal("WSARecv vnet seed should inject structured TCP payload using extracted seq/ack resources")
	}
	for _, file := range []string{
		"test/nyx_afd_accept_vnet_syn.txt",
		"test/nyx_afd_accept_vnet_syn_tapmac.txt",
		"test/nyx_afd_accept_vnet_recv.txt",
		"test/nyx_afd_accept_vnet_recv_nonblock.txt",
		"test/nyx_afd_accept_vnet_wsarecv_pending_iocp.txt",
		"test/nyx_afd_accept_vnet_wsarecv.txt",
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", file, err)
		}
		text := string(data)
		if !strings.Contains(text, "{{0x4e20, 0x4e20, r2, r1, 0x0, 0x0, 0x5, 0x10") &&
			!strings.Contains(text, "{{0x9c40, 0x4e20, r2, r1, 0x0, 0x0, 0x5, 0x10") {
			t.Fatalf("%s should inject a structured TCP ACK using extracted seq/ack before accept", file)
		}
	}
}

func TestWindowsVNetTAPSynSeedExecPacketBytes(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	packet := windowsVNetExecPacketBytes(t, target, "test/nyx_afd_listener_vnet_syn_tapmac_any_stage1.txt")
	if len(packet) != 54 {
		t.Fatalf("unexpected packet length: got %d want 54", len(packet))
	}
	wantPrefix := []byte{
		0x00, 0xff, 0xa3, 0x87, 0x5e, 0x0b,
		0x02, 0xbb, 0xcc, 0xdd, 0xee, 0x02,
		0x08, 0x00, 0x45, 0x00,
	}
	if string(packet[:len(wantPrefix)]) != string(wantPrefix) {
		t.Fatalf("unexpected L2/IP prefix: got % x want % x", packet[:len(wantPrefix)], wantPrefix)
	}
	if packet[23] != 6 {
		t.Fatalf("unexpected IPv4 protocol: got 0x%x want TCP", packet[23])
	}
	if src := packet[26:30]; string(src) != string([]byte{172, 20, 0, 187}) {
		t.Fatalf("unexpected IPv4 src: got %v", src)
	}
	if dst := packet[30:34]; string(dst) != string([]byte{172, 20, 0, 170}) {
		t.Fatalf("unexpected IPv4 dst: got %v", dst)
	}
	if port := binary.BigEndian.Uint16(packet[34:36]); port != 0x9c40 {
		t.Fatalf("unexpected TCP src port: got 0x%x", port)
	}
	if port := binary.BigEndian.Uint16(packet[36:38]); port != 0x4e20 {
		t.Fatalf("unexpected TCP dst port: got 0x%x", port)
	}
	if packet[46] != 0x50 || packet[47] != 0x02 {
		t.Fatalf("unexpected TCP data offset/flags: got %02x %02x want 50 02", packet[46], packet[47])
	}
}

func TestWindowsVNetARPSeedExecPacketBytes(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	packet := windowsVNetExecPacketBytes(t, target, "test/nyx_afd_listener_vnet_arp_syn_tapmac_any_bind_any_stage1.txt")
	if len(packet) != 42 {
		t.Fatalf("unexpected packet length: got %d want 42", len(packet))
	}
	wantPrefix := []byte{
		0x00, 0xff, 0xa3, 0x87, 0x5e, 0x0b,
		0x02, 0xbb, 0xcc, 0xdd, 0xee, 0x02,
		0x08, 0x06,
	}
	if string(packet[:len(wantPrefix)]) != string(wantPrefix) {
		t.Fatalf("unexpected ARP L2 prefix: got % x want % x", packet[:len(wantPrefix)], wantPrefix)
	}
	if binary.BigEndian.Uint16(packet[14:16]) != 0x1 || binary.BigEndian.Uint16(packet[16:18]) != 0x0800 {
		t.Fatalf("unexpected ARP hardware/protocol: got % x", packet[14:18])
	}
	if packet[18] != 6 || packet[19] != 4 {
		t.Fatalf("unexpected ARP address sizes: got hlen=%d plen=%d", packet[18], packet[19])
	}
	if op := binary.BigEndian.Uint16(packet[20:22]); op != 0x2 {
		t.Fatalf("unexpected ARP op: got 0x%x want reply", op)
	}
	if sha := packet[22:28]; string(sha) != string([]byte{0x02, 0xbb, 0xcc, 0xdd, 0xee, 0x02}) {
		t.Fatalf("unexpected ARP sender MAC: got % x", sha)
	}
	if spa := packet[28:32]; string(spa) != string([]byte{172, 20, 0, 187}) {
		t.Fatalf("unexpected ARP sender IP: got %v", spa)
	}
	if tha := packet[32:38]; string(tha) != string([]byte{0x00, 0xff, 0xa3, 0x87, 0x5e, 0x0b}) {
		t.Fatalf("unexpected ARP target MAC: got % x", tha)
	}
	if tpa := packet[38:42]; string(tpa) != string([]byte{172, 20, 0, 170}) {
		t.Fatalf("unexpected ARP target IP: got %v", tpa)
	}
}

func windowsVNetExecPacketBytes(t *testing.T, target *prog.Target, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", file, err)
	}
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize(%s): %v", file, err)
	}
	exec, err := p.SerializeForExec()
	if err != nil {
		t.Fatalf("SerializeForExec(%s): %v", file, err)
	}
	decoded, err := target.DeserializeExec(exec, nil)
	if err != nil {
		t.Fatalf("DeserializeExec(%s): %v", file, err)
	}
	var emit *prog.ExecCall
	for i := range decoded.Calls {
		if decoded.Calls[i].Meta != nil && decoded.Calls[i].Meta.Name == "syz_emit_ethernet$windows" {
			emit = &decoded.Calls[i]
			break
		}
	}
	if emit == nil {
		t.Fatalf("%s is missing syz_emit_ethernet$windows", file)
	}
	if len(emit.Args) != 2 {
		t.Fatalf("unexpected syz_emit_ethernet arg count: %d", len(emit.Args))
	}
	lenArg, ok := emit.Args[0].(prog.ExecArgConst)
	if !ok || lenArg.Value == 0 {
		t.Fatalf("unexpected packet length arg: %#v", emit.Args[0])
	}
	packetArg, ok := emit.Args[1].(prog.ExecArgConst)
	if !ok {
		t.Fatalf("unexpected packet pointer arg: %#v", emit.Args[1])
	}
	packet := make([]byte, lenArg.Value)
	base := packetArg.Value
	for _, copyin := range emit.Copyin {
		if copyin.Addr < base || copyin.Addr >= base+uint64(len(packet)) {
			continue
		}
		off := copyin.Addr - base
		applyWindowsVNetExecCopyin(t, packet, off, copyin.Arg)
	}
	return packet
}

func applyWindowsVNetExecCopyin(t *testing.T, packet []byte, off uint64, arg prog.ExecArg) {
	t.Helper()
	switch arg := arg.(type) {
	case prog.ExecArgConst:
		if off+arg.Size > uint64(len(packet)) {
			t.Fatalf("copyin const outside packet: off=%d size=%d packet=%d", off, arg.Size, len(packet))
		}
		applyWindowsVNetExecConst(t, packet[off:off+arg.Size], arg)
	case prog.ExecArgData:
		if off+uint64(len(arg.Data)) > uint64(len(packet)) {
			t.Fatalf("copyin data outside packet: off=%d size=%d packet=%d", off, len(arg.Data), len(packet))
		}
		copy(packet[off:], arg.Data)
	case prog.ExecArgCsum:
		// Runtime checksum calculation is validated by executor-side logging; this
		// seed-shape test only needs the fixed header bytes that select the packet.
	case prog.ExecArgResult:
		// This seed does not use result-backed packet fields.
	default:
		t.Fatalf("unsupported exec copyin arg: %#v", arg)
	}
}

func applyWindowsVNetExecConst(t *testing.T, dst []byte, arg prog.ExecArgConst) {
	t.Helper()
	if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
		t.Fatalf("unsupported const format: %v", arg.Format)
	}
	if arg.BitfieldLength != 0 {
		if len(dst) != 1 {
			t.Fatalf("unsupported bitfield size: %d", len(dst))
		}
		mask := byte((uint64(1)<<arg.BitfieldLength - 1) << arg.BitfieldOffset)
		dst[0] = (dst[0] &^ mask) | (byte(arg.Value<<arg.BitfieldOffset) & mask)
		return
	}
	switch len(dst) {
	case 1:
		dst[0] = byte(arg.Value)
	case 2:
		if arg.Format == prog.FormatBigEndian {
			binary.BigEndian.PutUint16(dst, uint16(arg.Value))
		} else {
			binary.LittleEndian.PutUint16(dst, uint16(arg.Value))
		}
	case 4:
		if arg.Format == prog.FormatBigEndian {
			binary.BigEndian.PutUint32(dst, uint32(arg.Value))
		} else {
			binary.LittleEndian.PutUint32(dst, uint32(arg.Value))
		}
	case 8:
		if arg.Format == prog.FormatBigEndian {
			binary.BigEndian.PutUint64(dst, arg.Value)
		} else {
			binary.LittleEndian.PutUint64(dst, arg.Value)
		}
	default:
		t.Fatalf("unsupported const size: %d", len(dst))
	}
}

func TestWindowsAFDVNetSeedsBindToVNetLocalIPv4(t *testing.T) {
	for _, file := range []string{
		"test/nyx_afd_acceptex_vnet_iocp.txt",
		"test/nyx_afd_acceptex_vnet_sockaddrs.txt",
		"test/nyx_afd_accept_vnet_syn.txt",
		"test/nyx_afd_accept_vnet_syn_tapmac.txt",
		"test/nyx_afd_accept_vnet_syn_tapmac_any.txt",
		"test/nyx_afd_accept_vnet_recv.txt",
		"test/nyx_afd_accept_vnet_recv_nonblock.txt",
		"test/nyx_afd_accept_vnet_wsarecv_pending_iocp.txt",
		"test/nyx_afd_accept_vnet_wsarecv.txt",
		"test/nyx_afd_listener_vnet_synack_tapmac_any.txt",
		"test/nyx_afd_listener_vnet_synack_tapmac_any_retry.txt",
		"test/nyx_afd_listener_vnet_syn_tapmac_any_stage1.txt",
		"test/nyx_afd_udp_vnet_recvfrom.txt",
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", file, err)
		}
		text := string(data)
		if !strings.Contains(text, "0xac1400aa") {
			t.Fatalf("%s should bind the local socket to the Windows vnet IPv4 172.20.0.170", file)
		}
		if strings.Contains(text, "0x7f000001") {
			t.Fatalf("%s should not bind vnet-driven receive/accept seeds to loopback", file)
		}
		if !strings.Contains(text, "@remote, @local") {
			t.Fatalf("%s should inject packets from the vnet peer to the vnet local address", file)
		}
	}
}

func TestWindowsAFDListenerSynAckSeedIsBounded(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, file := range []string{
		"test/nyx_afd_listener_vnet_synack_tapmac_any.txt",
		"test/nyx_afd_listener_vnet_synack_tapmac_any_retry.txt",
		"test/nyx_afd_listener_vnet_syn_tapmac_any_stage1.txt",
		"test/nyx_afd_listener_vnet_syn_tapmac_any_bind_any_stage1.txt",
		"test/nyx_afd_listener_vnet_arp_syn_tapmac_any_bind_any_stage1.txt",
		"test/nyx_vnet_extract_tcp_cache_stage2.txt",
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", file, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("Deserialize(%s): %v", file, err)
		}
		if _, err := p.SerializeForExec(); err != nil {
			t.Fatalf("SerializeForExec(%s): %v", file, err)
		}
		listen := -1
		inject := -1
		extract := -1
		extractCount := 0
		for i, call := range p.Calls {
			if call.Meta == nil {
				continue
			}
			switch call.Meta.Name {
			case "listen$inet_tcp":
				listen = i
			case "syz_emit_ethernet$windows":
				inject = i
			case "syz_extract_tcp_res$windows_synack":
				if extract == -1 {
					extract = i
				}
				extractCount++
			case "accept$inet_tcp", "recv$inet_accept", "WSARecv$accept":
				t.Fatalf("%s should not contain blocking %s", file, call.Meta.Name)
			}
		}
		if strings.Contains(file, "stage1") {
			if listen == -1 || inject == -1 || !(listen < inject) {
				t.Fatalf("%s should listen, then emit SYN", file)
			}
			if extractCount != 0 {
				t.Fatalf("%s should only listen and emit SYN; extract belongs to stage2", file)
			}
			continue
		}
		if strings.Contains(file, "stage2") {
			if listen != -1 || inject != -1 || extractCount != 1 {
				t.Fatalf("%s should only perform a single cache/extract call", file)
			}
			continue
		}
		if listen == -1 {
			t.Fatalf("%s is missing listen$inet_tcp", file)
		}
		if inject == -1 {
			t.Fatalf("%s is missing syz_emit_ethernet$windows", file)
		}
		if extract == -1 {
			t.Fatalf("%s is missing syz_extract_tcp_res$windows_synack", file)
		}
		if !(listen < inject && inject < extract) {
			t.Fatalf("%s should listen, inject SYN, then bounded extract SYN/ACK", file)
		}
		if strings.Contains(file, "retry") && extractCount < 3 {
			t.Fatalf("%s should retry bounded extract calls without blocking socket calls", file)
		}
	}
}

func TestWindowsAFDUDPSeedInjectsBeforeReceive(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, file := range []string{
		"test/nyx_afd_udp_vnet_recvfrom.txt",
		"test/nyx_afd_udp_vnet_recvfrom_tapmac_any.txt",
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", file, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("Deserialize(%s): %v", file, err)
		}
		if _, err := p.SerializeForExec(); err != nil {
			t.Fatalf("SerializeForExec(%s): %v", file, err)
		}
		inject := -1
		nonblock := -1
		receive := -1
		for i, call := range p.Calls {
			if call.Meta == nil {
				continue
			}
			switch call.Meta.Name {
			case "syz_emit_ethernet$windows":
				inject = i
			case "ioctlsocket$fionbio_udp":
				nonblock = i
			case "recvfrom$udp_bound":
				receive = i
			}
		}
		if inject == -1 {
			t.Fatalf("%s is missing syz_emit_ethernet$windows", file)
		}
		if nonblock == -1 {
			t.Fatalf("%s should set the UDP socket nonblocking before recvfrom$udp_bound", file)
		}
		if receive == -1 {
			t.Fatalf("%s is missing recvfrom$udp_bound", file)
		}
		if receive < nonblock {
			t.Fatalf("%s should set ioctlsocket$fionbio_udp before recvfrom$udp_bound", file)
		}
		if receive < inject {
			t.Fatalf("%s should inject payload before recvfrom$udp_bound", file)
		}
	}
}

func TestWindowsAFDAcceptSeedInjectsBeforeAccept(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, file := range []string{
		"test/nyx_afd_accept_vnet_syn.txt",
		"test/nyx_afd_accept_vnet_recv.txt",
		"test/nyx_afd_accept_vnet_recv_nonblock.txt",
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", file, err)
		}
		text := string(data)
		for _, want := range []string{
			"@tap_openvpn, @peer_openvpn",
			"@arp={0x806",
			"{{0x9c40, 0x4e20",
			"'afd-vnet'",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s should use the proven OpenVPN TAP payload template, missing %q", file, want)
			}
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("Deserialize(%s): %v", file, err)
		}
		if _, err := p.SerializeForExec(); err != nil {
			t.Fatalf("SerializeForExec(%s): %v", file, err)
		}
		arp := -1
		syn := -1
		ack := -1
		payload := -1
		extract := -1
		accept := -1
		receive := -1
		for i, call := range p.Calls {
			if call.Meta == nil {
				continue
			}
			switch call.Meta.Name {
			case "syz_emit_ethernet$windows":
				if arp == -1 {
					arp = i
				} else if syn == -1 {
					syn = i
				} else if ack == -1 {
					ack = i
				} else if payload == -1 {
					payload = i
				}
			case "syz_extract_tcp_res$windows_synack":
				extract = i
			case "accept$inet_tcp":
				accept = i
			case "recv$inet_accept":
				receive = i
			}
		}
		if arp == -1 {
			t.Fatal("TCP accept vnet seed is missing ARP syz_emit_ethernet$windows")
		}
		if syn == -1 {
			t.Fatal("TCP accept vnet seed is missing SYN syz_emit_ethernet$windows")
		}
		if ack == -1 {
			t.Fatal("TCP accept vnet seed is missing ACK syz_emit_ethernet$windows")
		}
		if payload == -1 {
			t.Fatal("TCP accept vnet seed is missing payload syz_emit_ethernet$windows")
		}
		if extract == -1 {
			t.Fatal("TCP accept vnet seed is missing syz_extract_tcp_res$windows_synack")
		}
		if accept == -1 {
			t.Fatal("TCP accept vnet seed is missing accept$inet_tcp")
		}
		if receive == -1 {
			t.Fatal("TCP accept vnet seed is missing recv$inet_accept")
		}
		if !(arp < syn && syn < extract && extract < ack && ack < accept && accept < payload && payload < receive) {
			t.Fatalf("%s should inject ARP, inject SYN, extract SYN/ACK, inject ACK, accept, inject payload, then recv$inet_accept", file)
		}
	}
}

func TestWindowsAFDAcceptNonblockRecvSeedSetsNonblockingBeforeReceive(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	data, err := os.ReadFile("test/nyx_afd_accept_vnet_recv_nonblock.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"@tap_openvpn, @peer_openvpn",
		"@arp={0x806",
		"{{0x9c40, 0x4e20",
		"'afd-vnet'",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("TCP nonblocking recv vnet seed should use the proven OpenVPN TAP template, missing %q", want)
		}
	}
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if _, err := p.SerializeForExec(); err != nil {
		t.Fatalf("SerializeForExec: %v", err)
	}
	accept := -1
	nonblock := -1
	payload := -1
	receive := -1
	for i, call := range p.Calls {
		if call.Meta == nil {
			continue
		}
		switch call.Meta.Name {
		case "accept$inet_tcp":
			accept = i
		case "ioctlsocket$fionbio_accept":
			nonblock = i
		case "syz_emit_ethernet$windows":
			if accept != -1 {
				payload = i
			}
		case "recv$inet_accept":
			receive = i
		}
	}
	if accept == -1 {
		t.Fatal("TCP nonblocking recv vnet seed is missing accept$inet_tcp")
	}
	if nonblock == -1 {
		t.Fatal("TCP nonblocking recv vnet seed should set ioctlsocket$fionbio_accept before recv$inet_accept")
	}
	if payload == -1 {
		t.Fatal("TCP nonblocking recv vnet seed is missing payload syz_emit_ethernet$windows after accept")
	}
	if receive == -1 {
		t.Fatal("TCP nonblocking recv vnet seed is missing recv$inet_accept")
	}
	if !(accept < nonblock && nonblock < payload && payload < receive) {
		t.Fatal("TCP nonblocking recv vnet seed should accept, set nonblocking, inject payload, then recv$inet_accept")
	}
}

func TestWindowsAFDWSARecvSeedInjectsBeforeReceive(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, test := range []struct {
		file    string
		receive string
	}{
		{file: "test/nyx_afd_accept_vnet_wsarecv.txt", receive: "WSARecv$accept"},
		{file: "test/nyx_afd_accept_vnet_wsarecv_pending_iocp.txt", receive: "WSARecv$accept_pending"},
	} {
		data, err := os.ReadFile(test.file)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", test.file, err)
		}
		text := string(data)
		for _, want := range []string{
			"@tap_openvpn, @peer_openvpn",
			"@arp={0x806",
			"{{0x9c40, 0x4e20",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s should use the proven OpenVPN TAP template, missing %q", test.file, want)
			}
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("Deserialize(%s): %v", test.file, err)
		}
		if _, err := p.SerializeForExec(); err != nil {
			t.Fatalf("SerializeForExec(%s): %v", test.file, err)
		}
		accept := -1
		ack := -1
		nonblock := -1
		payload := -1
		receive := -1
		for i, call := range p.Calls {
			if call.Meta == nil {
				continue
			}
			switch call.Meta.Name {
			case "syz_emit_ethernet$windows":
				if accept == -1 {
					ack = i
				} else {
					payload = i
				}
			case "accept$inet_tcp":
				accept = i
			case "ioctlsocket$fionbio_accept":
				nonblock = i
			case test.receive:
				receive = i
			}
		}
		if accept == -1 {
			t.Fatalf("%s is missing accept$inet_tcp", test.file)
		}
		if ack == -1 {
			t.Fatalf("%s is missing ACK syz_emit_ethernet$windows before accept", test.file)
		}
		if payload == -1 {
			t.Fatalf("%s is missing payload syz_emit_ethernet$windows after accept", test.file)
		}
		if receive == -1 {
			t.Fatalf("%s is missing %s", test.file, test.receive)
		}
		if test.receive == "WSARecv$accept" {
			if nonblock == -1 {
				t.Fatalf("%s should set ioctlsocket$fionbio_accept before WSARecv$accept", test.file)
			}
			if !(ack < accept && accept < nonblock && nonblock < payload && payload < receive) {
				t.Fatalf("%s should inject ACK, accept, set nonblocking, inject payload, then WSARecv$accept", test.file)
			}
		}
		if test.receive == "WSARecv$accept_pending" && !(ack < accept && accept < receive && receive < payload) {
			t.Fatalf("%s should inject ACK, accept, issue WSARecv$accept_pending, then inject payload", test.file)
		}
	}
}

func TestWindowsAFDWSARecvPendingIOCPSeedCompletesAfterPayload(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	data, err := os.ReadFile("test/nyx_afd_accept_vnet_wsarecv_pending_iocp.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(data)
	if strings.Contains(text, "CancelIo") {
		t.Fatal("WSARecv pending IOCP vnet seed should be completion-driven, not cancel-driven")
	}
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if _, err := p.SerializeForExec(); err != nil {
		t.Fatalf("SerializeForExec: %v", err)
	}
	accept := -1
	iocp := -1
	pending := -1
	payload := -1
	result := -1
	gqcs := -1
	for i, call := range p.Calls {
		if call.Meta == nil {
			continue
		}
		switch call.Meta.Name {
		case "accept$inet_tcp":
			accept = i
		case "CreateIoCompletionPort$socket":
			iocp = i
		case "WSARecv$accept_pending":
			pending = i
		case "syz_emit_ethernet$windows":
			if pending != -1 {
				payload = i
			}
		case "WSAGetOverlappedResult$accept_recv_pending":
			result = i
		case "GetQueuedCompletionStatus$socket":
			gqcs = i
		case "CancelIoEx$accept_recv_pending", "CancelIo$accept_recv_pending":
			t.Fatalf("completion seed should not contain %s", call.Meta.Name)
		}
	}
	for name, index := range map[string]int{
		"accept$inet_tcp":                            accept,
		"CreateIoCompletionPort$socket":              iocp,
		"WSARecv$accept_pending":                     pending,
		"payload syz_emit_ethernet$windows":          payload,
		"WSAGetOverlappedResult$accept_recv_pending": result,
		"GetQueuedCompletionStatus$socket":           gqcs,
	} {
		if index == -1 {
			t.Fatalf("WSARecv pending IOCP vnet seed is missing %s", name)
		}
	}
	if !(accept < iocp && iocp < pending && pending < payload && payload < result && result < gqcs) {
		t.Fatal("WSARecv pending IOCP vnet seed should accept, associate IOCP, issue pending receive, inject payload, check overlapped result, then poll IOCP")
	}
}

func TestWindowsAFDAcceptExVNetIOCPSeedCompletesBeforeUpdatedReceive(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, test := range []struct {
		file          string
		wantSockaddrs bool
	}{
		{file: "test/nyx_afd_acceptex_vnet_iocp.txt"},
		{file: "test/nyx_afd_acceptex_vnet_sockaddrs.txt", wantSockaddrs: true},
	} {
		data, err := os.ReadFile(test.file)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", test.file, err)
		}
		text := string(data)
		for _, want := range []string{
			"@tap_openvpn, @peer_openvpn",
			"@arp={0x806",
			"{{0x9c40, 0x4e20",
			"'afd-vnet'",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s should use the proven OpenVPN TAP template, missing %q", test.file, want)
			}
		}
		if strings.Contains(text, "CancelIo") {
			t.Fatalf("%s should be completion-driven, not cancel-driven", test.file)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("Deserialize(%s): %v", test.file, err)
		}
		if _, err := p.SerializeForExec(); err != nil {
			t.Fatalf("SerializeForExec(%s): %v", test.file, err)
		}
		acceptex := -1
		iocp := -1
		arp := -1
		syn := -1
		extract := -1
		ack := -1
		result := -1
		gqcs := -1
		sockaddrs := -1
		update := -1
		payload := -1
		receive := -1
		for i, call := range p.Calls {
			if call.Meta == nil {
				continue
			}
			switch call.Meta.Name {
			case "AcceptEx$inet_tcp_pending":
				acceptex = i
			case "CreateIoCompletionPort$accept_pending":
				iocp = i
			case "syz_extract_tcp_res$windows_synack":
				extract = i
			case "syz_emit_ethernet$windows":
				if arp == -1 {
					arp = i
				} else if syn == -1 {
					syn = i
				} else if ack == -1 {
					ack = i
				} else if payload == -1 {
					payload = i
				}
			case "WSAGetOverlappedResult$accept_pending":
				result = i
			case "GetQueuedCompletionStatus$socket":
				gqcs = i
			case "GetAcceptExSockaddrs$inet_tcp":
				sockaddrs = i
			case "setsockopt$update_accept_context":
				update = i
			case "recv$inet_accept_updated":
				receive = i
			case "CancelIoEx$accept_pending", "CancelIo$accept_pending":
				t.Fatalf("completion seed should not contain %s", call.Meta.Name)
			}
		}
		for name, index := range map[string]int{
			"AcceptEx$inet_tcp_pending":             acceptex,
			"CreateIoCompletionPort$accept_pending": iocp,
			"ARP syz_emit_ethernet$windows":         arp,
			"SYN syz_emit_ethernet$windows":         syn,
			"syz_extract_tcp_res$windows_synack":    extract,
			"ACK syz_emit_ethernet$windows":         ack,
			"WSAGetOverlappedResult$accept_pending": result,
			"GetQueuedCompletionStatus$socket":      gqcs,
			"setsockopt$update_accept_context":      update,
			"payload syz_emit_ethernet$windows":     payload,
			"recv$inet_accept_updated":              receive,
		} {
			if index == -1 {
				t.Fatalf("%s is missing %s", test.file, name)
			}
		}
		if test.wantSockaddrs && sockaddrs == -1 {
			t.Fatalf("%s is missing GetAcceptExSockaddrs$inet_tcp", test.file)
		}
		if !test.wantSockaddrs && sockaddrs != -1 {
			t.Fatalf("%s should leave GetAcceptExSockaddrs$inet_tcp to the dedicated sockaddrs seed", test.file)
		}
		if !(acceptex < iocp && iocp < arp && arp < syn && syn < extract && extract < ack && ack < result &&
			result < gqcs && gqcs < update && update < payload && payload < receive) {
			t.Fatalf("%s should post AcceptEx, associate IOCP, complete TCP handshake, observe completion, update accept context, inject payload, then recv on updated accept socket", test.file)
		}
		if test.wantSockaddrs && !(gqcs < sockaddrs && sockaddrs < update) {
			t.Fatalf("%s should parse AcceptEx sockaddrs after completion and before update accept context", test.file)
		}
	}
}

func TestWindowsAFDAcceptExVNetCancelSeedCancelsBeforeHandshake(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	data, err := os.ReadFile("test/nyx_afd_acceptex_vnet_cancel.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"@tap_openvpn, @peer_openvpn",
		"@arp={0x806",
		"0xac1400aa",
		"CancelIoEx$accept_pending",
		"CancelIo$accept_pending",
		"closesocket$accept_pending",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("AcceptEx cancel vnet seed is missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"0x7f000001",
		"@ipv4={0x800, @tcp=",
		"syz_extract_tcp_res$windows_synack",
		"setsockopt$update_accept_context",
		"recv$inet_accept_updated",
		"GetAcceptExSockaddrs$inet_tcp",
		"'afd-vnet'",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("AcceptEx cancel vnet seed should not complete/update/receive the accept path, found %q", forbidden)
		}
	}
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if _, err := p.SerializeForExec(); err != nil {
		t.Fatalf("SerializeForExec: %v", err)
	}
	acceptex := -1
	iocp := -1
	arp := -1
	syn := -1
	cancelEx := -1
	result := -1
	gqcs := -1
	cancel := -1
	closePending := -1
	for i, call := range p.Calls {
		if call.Meta == nil {
			continue
		}
		switch call.Meta.Name {
		case "AcceptEx$inet_tcp_pending":
			acceptex = i
		case "CreateIoCompletionPort$accept_pending":
			iocp = i
		case "syz_emit_ethernet$windows":
			if arp == -1 {
				arp = i
			} else if syn == -1 {
				syn = i
			}
		case "CancelIoEx$accept_pending":
			cancelEx = i
		case "WSAGetOverlappedResult$accept_pending":
			result = i
		case "GetQueuedCompletionStatus$socket":
			gqcs = i
		case "CancelIo$accept_pending":
			cancel = i
		case "closesocket$accept_pending":
			closePending = i
		case "setsockopt$update_accept_context", "recv$inet_accept_updated",
			"GetAcceptExSockaddrs$inet_tcp", "syz_extract_tcp_res$windows_synack":
			t.Fatalf("AcceptEx cancel vnet seed should not contain %s", call.Meta.Name)
		}
	}
	for name, index := range map[string]int{
		"AcceptEx$inet_tcp_pending":             acceptex,
		"CreateIoCompletionPort$accept_pending": iocp,
		"ARP syz_emit_ethernet$windows":         arp,
		"CancelIoEx$accept_pending":             cancelEx,
		"WSAGetOverlappedResult$accept_pending": result,
		"GetQueuedCompletionStatus$socket":      gqcs,
		"CancelIo$accept_pending":               cancel,
		"closesocket$accept_pending":            closePending,
	} {
		if index == -1 {
			t.Fatalf("AcceptEx cancel vnet seed is missing %s", name)
		}
	}
	if syn != -1 {
		t.Fatal("AcceptEx cancel vnet seed should not inject TCP SYN before cancel")
	}
	if !(acceptex < iocp && iocp < arp && arp < cancelEx && cancelEx < result &&
		result < gqcs && gqcs < cancel && cancel < closePending) {
		t.Fatal("AcceptEx cancel vnet seed should post AcceptEx, associate IOCP, initialize TAP with ARP, cancel pending accept, inspect result/IOCP, then cleanup")
	}
}

func TestWindowsAFDVNetSeedsUseNativeResultSeqAck(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, file := range []string{
		"test/nyx_afd_acceptex_vnet_iocp.txt",
		"test/nyx_afd_acceptex_vnet_sockaddrs.txt",
		"test/nyx_afd_accept_vnet_recv.txt",
		"test/nyx_afd_accept_vnet_recv_nonblock.txt",
		"test/nyx_afd_accept_vnet_wsarecv_pending_iocp.txt",
		"test/nyx_afd_accept_vnet_wsarecv.txt",
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", file, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("Deserialize(%s): %v", file, err)
		}
		exec, err := p.SerializeForExec()
		if err != nil {
			t.Fatalf("SerializeForExec(%s): %v", file, err)
		}
		decoded, err := target.DeserializeExec(exec, nil)
		if err != nil {
			t.Fatalf("DeserializeExec(%s): %v", file, err)
		}
		emitIndex := 0
		var resultFields []prog.ExecArgResult
		for i := range decoded.Calls {
			call := &decoded.Calls[i]
			if call.Meta == nil || call.Meta.Name != "syz_emit_ethernet$windows" {
				continue
			}
			emitIndex++
			if emitIndex < 3 {
				continue
			}
			if len(call.Args) != 2 {
				t.Fatalf("%s unexpected syz_emit_ethernet arg count: %d", file, len(call.Args))
			}
			packetArg, ok := call.Args[1].(prog.ExecArgConst)
			if !ok {
				t.Fatalf("%s unexpected packet pointer arg: %#v", file, call.Args[1])
			}
			tcpBase := packetArg.Value + 14 + 20
			for _, copyin := range call.Copyin {
				if copyin.Addr != tcpBase+4 && copyin.Addr != tcpBase+8 {
					continue
				}
				result, ok := copyin.Arg.(prog.ExecArgResult)
				if !ok {
					t.Fatalf("%s TCP seq/ack copyin at 0x%x should be result-backed, got %#v", file, copyin.Addr, copyin.Arg)
				}
				resultFields = append(resultFields, result)
			}
		}
		if len(resultFields) != 4 {
			t.Fatalf("%s expected result-backed seq/ack in ACK and payload packets, got %d fields", file, len(resultFields))
		}
		for _, result := range resultFields {
			if result.Format != prog.FormatNative {
				t.Fatalf("%s TCP seq/ack resource copyin should use native format and rely on executor-side htonl, got %v", file, result.Format)
			}
		}
	}
}

func TestWindowsAFDStateMachineCallsAreGeneratable(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	tests := []struct {
		root string
		want []string
	}{
		{
			root: "recv$inet_accept",
			want: []string{"socket$inet_tcp", "bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "recv$inet_accept"},
		},
		{
			root: "send$inet_tcp",
			want: []string{"socket$inet_tcp", "connect$inet_tcp", "send$inet_tcp"},
		},
		{
			root: "recvfrom$udp_bound",
			want: []string{"socket$inet_udp", "bind$inet_udp", "recvfrom$udp_bound"},
		},
		{
			root: "sendto$udp_connected",
			want: []string{"socket$inet_udp", "connect$inet_udp", "sendto$udp_connected"},
		},
		{
			root: "shutdown$tcp_wr",
			want: []string{"socket$inet_tcp", "connect$inet_tcp", "shutdown$tcp_wr"},
		},
		{
			root: "ConnectEx$inet_tcp",
			want: []string{"socket$inet_tcp", "bind$connectex_tcp", "ConnectEx$inet_tcp"},
		},
		{
			root: "ConnectEx$inet_tcp_reuse",
			want: []string{
				"socket$inet_tcp", "bind$connectex_tcp", "ConnectEx$inet_tcp",
				"DisconnectEx$inet_tcp_reuse", "ConnectEx$inet_tcp_reuse",
			},
		},
	}
	for _, test := range tests {
		root := target.SyscallMap[test.root]
		if root == nil {
			t.Fatalf("missing syscall %q", test.root)
		}
		ct := target.BuildChoiceTable(nil, map[*prog.Syscall]bool{root: true})
		if ct == nil {
			t.Fatalf("BuildChoiceTable(%s) returned nil", test.root)
		}
		for _, name := range test.want {
			call := target.SyscallMap[name]
			if call == nil {
				t.Fatalf("missing syscall %q", name)
			}
			if !ct.Generatable(call.ID) {
				t.Fatalf("%s scaffold call %q is not generatable", test.root, name)
			}
		}
	}
}

func TestWindowsAFDStateMachineGeneratesResourceChains(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	tests := []struct {
		root string
		want []string
	}{
		{
			root: "recv$inet_accept",
			want: []string{"socket$inet_tcp", "bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "recv$inet_accept"},
		},
		{
			root: "setsockopt$int_accept",
			want: []string{"socket$inet_tcp", "bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "setsockopt$int_accept"},
		},
		{
			root: "send$inet_tcp",
			want: []string{"socket$inet_tcp", "connect$inet_tcp", "send$inet_tcp"},
		},
		{
			root: "shutdown$tcp",
			want: []string{"socket$inet_tcp", "connect$inet_tcp", "shutdown$tcp"},
		},
		{
			root: "recvfrom$udp_bound",
			want: []string{"socket$inet_udp", "bind$inet_udp", "recvfrom$udp_bound"},
		},
		{
			root: "sendto$udp_connected",
			want: []string{"socket$inet_udp", "connect$inet_udp", "sendto$udp_connected"},
		},
	}
	for _, test := range tests {
		root := target.SyscallMap[test.root]
		if root == nil {
			t.Fatalf("missing syscall %q", test.root)
		}
		var last *prog.Prog
		for seed := int64(0); seed < 128; seed++ {
			p := generateWindowsProgramFromRoot(target, root, seed, 12)
			last = p
			if windowsTestHasOrderedCalls(p, test.want) {
				last = nil
				break
			}
		}
		if last != nil {
			t.Fatalf("%s generation did not produce ordered chain %v; last program:\n%s",
				test.root, test.want, last.Serialize())
		}
	}
}

func generateWindowsProgramFromRoot(target *prog.Target, root *prog.Syscall, seed int64, ncalls int) *prog.Prog {
	clone := target.Clone()
	clone.Bias.SelectGeneratedCall = func(_ *prog.Prog, insertionPoint int, _ int, ct *prog.ChoiceTable) int {
		if insertionPoint == 0 && ct.Generatable(root.ID) {
			return root.ID
		}
		return -1
	}
	ct := clone.BuildChoiceTable(nil, map[*prog.Syscall]bool{
		root: true,
	})
	return clone.Generate(rand.NewSource(seed), ncalls, ct)
}

func windowsTestHasOrderedCalls(p *prog.Prog, want []string) bool {
	next := 0
	for _, call := range p.Calls {
		if call.Meta == nil || call.Meta.Name != want[next] {
			continue
		}
		next++
		if next == len(want) {
			return true
		}
	}
	return false
}

func TestWindowsAFDResourceReusePrefersStatefulSocket(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if target.ResourceReuseScore == nil {
		t.Fatal("windows target did not set ResourceReuseScore")
	}
	tests := []struct {
		name       string
		program    string
		current    string
		deepCall   string
		compatCall string
	}{
		{
			name: "accepted socket",
			program: strings.Join([]string{
				"r0 = socket$accept_tcp(0x2, 0x1, 0x6)",
				"r1 = socket$inet_tcp(0x2, 0x1, 0x6)",
				"r2 = bind$inet_tcp(r1, &(0x7f0000000000)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
				"r3 = listen$inet_tcp(r2, 0x1)",
				"r4 = accept$inet_tcp(r3, 0x0, 0x0)",
			}, "\n") + "\n",
			current:    "recv$inet_accept",
			deepCall:   "accept$inet_tcp",
			compatCall: "socket$accept_tcp",
		},
		{
			name: "connected tcp",
			program: strings.Join([]string{
				"r0 = socket$connected_tcp(0x2, 0x1, 0x6)",
				"r1 = socket$inet_tcp(0x2, 0x1, 0x6)",
				"r2 = connect$inet_tcp(r1, &(0x7f0000000000)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
			}, "\n") + "\n",
			current:    "send$inet_tcp",
			deepCall:   "connect$inet_tcp",
			compatCall: "socket$connected_tcp",
		},
		{
			name: "disconnectex reusable tcp",
			program: strings.Join([]string{
				"r0 = socket$connected_tcp(0x2, 0x1, 0x6)",
				"r1 = socket$inet_tcp(0x2, 0x1, 0x6)",
				"r2 = connect$inet_tcp(r1, &(0x7f0000000000)={0x2, 0x4e24, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
				"r3 = DisconnectEx$inet_tcp_reuse(r2, 0x0, 0x2, 0x0)",
			}, "\n") + "\n",
			current:    "ConnectEx$inet_tcp_reuse",
			deepCall:   "DisconnectEx$inet_tcp_reuse",
			compatCall: "socket$connected_tcp",
		},
		{
			name: "connectex pending",
			program: strings.Join([]string{
				"r0 = socket$connected_tcp(0x2, 0x1, 0x6)",
				"r1 = socket$listener_tcp(0x2, 0x1, 0x6)",
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)",
				"r3 = bind$inet_tcp(r2, &(0x7f0000000000)={0x2, 0x4e29, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
				"listen$inet_tcp(r3, 0x1)",
				"bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
				"r4 = ConnectEx$inet_tcp_pending(r0, &(0x7f0000000180)={0x2, 0x4e29, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})",
			}, "\n") + "\n",
			current:    "CancelIoEx$connect_pending",
			deepCall:   "ConnectEx$inet_tcp_pending",
			compatCall: "socket$connected_tcp",
		},
		{
			name: "tcp recv pending",
			program: strings.Join([]string{
				"r0 = socket$connected_tcp(0x2, 0x1, 0x6)",
				"r1 = socket$listener_tcp(0x2, 0x1, 0x6)",
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)",
				"r3 = bind$inet_tcp(r2, &(0x7f0000000000)={0x2, 0x4e2a, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
				"listen$inet_tcp(r3, 0x1)",
				"connect$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e2a, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
				"r4 = WSARecv$tcp_pending(r0, &(0x7f0000000180)=[{0x40, &(0x7f0000000200)='\\x00'/64}], 0x1, &(0x7f0000000280), &(0x7f00000002c0)=0x0, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)",
			}, "\n") + "\n",
			current:    "CancelIoEx$tcp_recv_pending",
			deepCall:   "WSARecv$tcp_pending",
			compatCall: "socket$connected_tcp",
		},
		{
			name: "tcp send pending",
			program: strings.Join([]string{
				"r0 = socket$connected_tcp(0x2, 0x1, 0x6)",
				"r1 = socket$listener_tcp(0x2, 0x1, 0x6)",
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)",
				"r3 = bind$inet_tcp(r2, &(0x7f0000000000)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
				"listen$inet_tcp(r3, 0x1)",
				"connect$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
				"r4 = WSASend$tcp_pending(r0, &(0x7f0000000180)=[{0x4, &(0x7f0000000200)='send'}], 0x1, &(0x7f0000000280), 0x0, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)",
			}, "\n") + "\n",
			current:    "CancelIoEx$tcp_send_pending",
			deepCall:   "WSASend$tcp_pending",
			compatCall: "socket$connected_tcp",
		},
		{
			name: "udp bound",
			program: strings.Join([]string{
				"r0 = socket$bound_udp(0x2, 0x2, 0x11)",
				"r1 = socket$inet_udp(0x2, 0x2, 0x11)",
				"r2 = bind$inet_udp(r1, &(0x7f0000000000)={0x2, 0x4e22, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
			}, "\n") + "\n",
			current:    "recv$inet_udp",
			deepCall:   "bind$inet_udp",
			compatCall: "socket$bound_udp",
		},
		{
			name: "udp connected",
			program: strings.Join([]string{
				"r0 = socket$connected_udp(0x2, 0x2, 0x11)",
				"r1 = socket$inet_udp(0x2, 0x2, 0x11)",
				"r2 = connect$inet_udp(r1, &(0x7f0000000000)={0x2, 0x4e23, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
			}, "\n") + "\n",
			current:    "send$inet_udp",
			deepCall:   "connect$inet_udp",
			compatCall: "socket$connected_udp",
		},
		{
			name: "accept pending",
			program: strings.Join([]string{
				"r0 = socket$accept_tcp(0x2, 0x1, 0x6)",
				"r1 = socket$listener_tcp(0x2, 0x1, 0x6)",
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)",
				"r3 = bind$inet_tcp(r2, &(0x7f0000000000)={0x2, 0x4e25, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
				"r4 = listen$inet_tcp(r3, 0x1)",
				"r5 = AcceptEx$inet_tcp_pending(r4, r0, &(0x7f0000000100)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000200), &(0x7f0000000240)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})",
			}, "\n") + "\n",
			current:    "CancelIoEx$accept_pending",
			deepCall:   "AcceptEx$inet_tcp_pending",
			compatCall: "socket$accept_tcp",
		},
		{
			name: "accept recv pending",
			program: strings.Join([]string{
				"r0 = socket$accept_tcp(0x2, 0x1, 0x6)",
				"r1 = socket$listener_tcp(0x2, 0x1, 0x6)",
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)",
				"r3 = bind$inet_tcp(r2, &(0x7f0000000000)={0x2, 0x4e27, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
				"r4 = listen$inet_tcp(r3, 0x1)",
				"r5 = accept$inet_tcp(r4, 0x0, 0x0)",
				"r6 = WSARecv$accept_pending(r5, &(0x7f0000000100)=[{0x40, &(0x7f0000000180)='\\x00'/64}], 0x1, &(0x7f0000000200), &(0x7f0000000240)=0x0, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)",
			}, "\n") + "\n",
			current:    "CancelIoEx$accept_recv_pending",
			deepCall:   "WSARecv$accept_pending",
			compatCall: "socket$accept_tcp",
		},
		{
			name: "accept send pending",
			program: strings.Join([]string{
				"r0 = socket$accept_tcp(0x2, 0x1, 0x6)",
				"r1 = socket$listener_tcp(0x2, 0x1, 0x6)",
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)",
				"r3 = bind$inet_tcp(r2, &(0x7f0000000000)={0x2, 0x4e28, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
				"r4 = listen$inet_tcp(r3, 0x1)",
				"r5 = accept$inet_tcp(r4, 0x0, 0x0)",
				"r6 = WSASend$accept_pending(r5, &(0x7f0000000100)=[{0x4, &(0x7f0000000180)='send'}], 0x1, &(0x7f0000000200), 0x0, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)",
			}, "\n") + "\n",
			current:    "CancelIoEx$accept_send_pending",
			deepCall:   "WSASend$accept_pending",
			compatCall: "socket$accept_tcp",
		},
		{
			name: "updated accept",
			program: strings.Join([]string{
				"r0 = socket$accept_tcp(0x2, 0x1, 0x6)",
				"r1 = socket$listener_tcp(0x2, 0x1, 0x6)",
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)",
				"r3 = bind$inet_tcp(r2, &(0x7f0000000000)={0x2, 0x4e26, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)",
				"r4 = listen$inet_tcp(r3, 0x1)",
				"r5 = AcceptEx$inet_tcp_pending(r4, r0, &(0x7f0000000100)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000200), &(0x7f0000000240)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})",
				"r6 = setsockopt$update_accept_context(r5, 0xffff, 0x700b, &(0x7f0000000300)=r4, 0x8)",
			}, "\n") + "\n",
			current:    "send$inet_accept_updated",
			deepCall:   "setsockopt$update_accept_context",
			compatCall: "socket$accept_tcp",
		},
	}
	for _, test := range tests {
		base, err := target.Deserialize([]byte(test.program), prog.NonStrict)
		if err != nil {
			t.Fatalf("%s Deserialize: %v", test.name, err)
		}
		root := target.SyscallMap[test.current]
		if root == nil {
			t.Fatalf("missing syscall %q", test.current)
		}
		deep := windowsTestCallReturn(t, base, test.deepCall)
		compat := windowsTestCallReturn(t, base, test.compatCall)
		deepScore := target.ResourceReuseScore(root, deep, base, len(base.Calls))
		compatScore := target.ResourceReuseScore(root, compat, base, len(base.Calls))
		if deepScore <= compatScore {
			t.Fatalf("%s reuse score: deep=%d compat=%d", test.name, deepScore, compatScore)
		}
	}
}

func windowsTestCallReturn(t *testing.T, p *prog.Prog, callName string) *prog.ResultArg {
	t.Helper()
	for _, call := range p.Calls {
		if call.Meta == nil || call.Meta.Name != callName {
			continue
		}
		if call.Ret == nil {
			t.Fatalf("%s has no return resource", callName)
		}
		return call.Ret
	}
	t.Fatalf("program is missing %s", callName)
	return nil
}

func TestWindowsSeedProgramsDeserialize(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	files, err := filepath.Glob("test/*.txt")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no windows seed programs found")
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", file, err)
		}
		if _, err := target.Deserialize(data, prog.NonStrict); err != nil {
			t.Fatalf("Deserialize(%s): %v", file, err)
		}
	}
}

package windows_test

import (
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
			want: []string{"socket$inet_tcp", "connect$inet_tcp", "ConnectEx$inet_tcp_pending"},
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
	for _, name := range []string{"WSAStartup", "WSACleanup", "closesocket$any"} {
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
	assertPtrStruct("ConnectEx$inet_tcp", 1, "sockaddr_in")
	assertResource("ConnectEx$inet_tcp_pending", 0, "SOCKET_CONNECTED")
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
			root: "ConnectEx$inet_tcp_reuse",
			want: []string{"socket$connected_tcp", "connect$inet_tcp", "DisconnectEx$inet_tcp_reuse", "ConnectEx$inet_tcp_reuse"},
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

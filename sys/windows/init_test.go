package windows_test

import (
	"os"
	"path/filepath"
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
		"CloseHandle", "CreateFileA", "CreateFile2", "VirtualAlloc",
		"GetCurrentProcess$process", "GetCurrentThread$thread",
		"CreateEventA$manual", "CreateEventA$auto", "CreateSemaphoreA$sem",
		"WSAStartup", "WSACleanup",
		"socket$inet_tcp", "socket$inet_udp", "socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp",
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
	tests := []struct {
		name string
		want int
	}{
		{name: "CreateFileA", want: -1},
		{name: "Sleep", want: 0},
		{name: "NtQuerySystemInformation", want: 1},
		{name: "recv$inet_udp", want: 2},
		{name: "send$inet_tcp", want: 3},
		{name: "recv$inet_accept", want: 4},
		{name: "WaitForSingleObject$wait", want: 2},
		{name: "GetTokenInformation$token", want: 3},
		{name: "MapViewOfFile$section", want: 3},
		{name: "GetQueuedCompletionStatus$iocp", want: 3},
		{name: "ReadFile$pipe", want: 3},
		{name: "NtQueryInformationFile$basic", want: 4},
		{name: "NtSetInformationFile$basic", want: 4},
		{name: "TransmitFile$inet_accept", want: 5},
		{name: "NtDeviceIoControlFile", want: 5},
		{name: "NtFsControlFile", want: 5},
		{name: "NtFsControlFile$ntfs_get_compression", want: 5},
		{name: "NtFsControlFile$ntfs_set_compression", want: 5},
		{name: "NtFsControlFile$ntfs_set_sparse", want: 5},
		{name: "NtFsControlFile$ntfs_set_zero_data", want: 5},
		{name: "NtFsControlFile$ntfs_query_allocated_ranges", want: 5},
	}
	for _, test := range tests {
		call := target.SyscallMap[test.name]
		if call == nil {
			t.Fatalf("missing syscall %q", test.name)
		}
		if got := target.CallRelevance(call); got != test.want {
			t.Fatalf("%s relevance: got %d, want %d", test.name, got, test.want)
		}
		if got := target.TriageRelevance(call); got != test.want {
			t.Fatalf("%s triage relevance: got %d, want %d", test.name, got, test.want)
		}
	}
	if target.CallEligibleForTriage(target.SyscallMap["CreateFileA"]) {
		t.Fatal("automatic helper should not be eligible for triage")
	}
	if !target.CallEligibleForTriage(target.SyscallMap["Sleep"]) {
		t.Fatal("unscored non-helper syscall should remain eligible for triage")
	}
}

func TestWindowsExpandEnabledCallsForNetworkAndFileTargets(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if target.ExpandEnabledCalls == nil {
		t.Fatal("windows target did not set ExpandEnabledCalls")
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["TransmitFile$inet_accept"]: true,
	}
	expanded := target.ExpandEnabledCalls(target, enabled)
	for _, name := range []string{
		"VirtualAlloc",
		"TransmitFile$inet_accept",
		"WSAStartup", "WSACleanup", "socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp", "closesocket$any",
		"bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "connect$inet_tcp",
		"CreateFileA", "CreateFile2", "CloseHandle", "WriteFile",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("expanded enabled calls are missing %q", name)
		}
	}
}

func TestWindowsExpandEnabledCallsAddsAcceptScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["WSARecvEx$inet_accept"]: true,
	}
	expanded := target.ExpandEnabledCalls(target, enabled)
	for _, name := range []string{
		"VirtualAlloc",
		"WSARecvEx$inet_accept",
		"WSAStartup", "WSACleanup", "socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp", "closesocket$any",
		"bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "connect$inet_tcp",
		"send$inet_tcp",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("expanded enabled calls are missing %q", name)
		}
	}
}

func TestWindowsExpandEnabledCallsAddsPeerTrafficScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	tests := []struct {
		root string
		want []string
	}{
		{
			root: "recv$inet_tcp",
			want: []string{"send$inet_accept", "socket$listener_tcp", "listen$inet_tcp", "accept$inet_tcp"},
		},
		{
			root: "recv$inet_udp",
			want: []string{"send$inet_udp", "socket$inet_udp", "connect$inet_udp"},
		},
		{
			root: "recv$inet_accept",
			want: []string{"send$inet_tcp", "socket$listener_tcp", "accept$inet_tcp"},
		},
	}
	for _, test := range tests {
		expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{
			target.SyscallMap[test.root]: true,
		})
		for _, name := range append([]string{test.root}, test.want...) {
			call := target.SyscallMap[name]
			if call == nil {
				t.Fatalf("missing syscall %q", name)
			}
			if !expanded[call] {
				t.Fatalf("%s expansion is missing %q", test.root, name)
			}
		}
	}
}

func TestWindowsExpandEnabledCallsAddsTCPAndUDPConnectScaffold(t *testing.T) {
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
			want: []string{"WSAStartup", "WSACleanup", "socket$connected_tcp", "closesocket$any", "connect$inet_tcp"},
		},
		{
			root: "getsockopt$int_udp",
			want: []string{"WSAStartup", "WSACleanup", "socket$inet_udp", "closesocket$any", "connect$inet_udp"},
		},
	}
	for _, test := range tests {
		expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{
			target.SyscallMap[test.root]: true,
		})
		for _, name := range append([]string{test.root}, test.want...) {
			call := target.SyscallMap[name]
			if call == nil {
				t.Fatalf("missing syscall %q", name)
			}
			if !expanded[call] {
				t.Fatalf("%s expansion is missing %q", test.root, name)
			}
		}
	}
}

func TestWindowsExpandEnabledCallsAddsFileScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["FlushFileBuffers"]: true,
	}
	expanded := target.ExpandEnabledCalls(target, enabled)
	for _, name := range []string{
		"VirtualAlloc",
		"FlushFileBuffers",
		"CreateFileA", "CreateFile2", "CloseHandle",
		"NtReadFile", "NtWriteFile", "NtFsControlFile",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("expanded enabled calls are missing %q", name)
		}
	}
}

func TestWindowsExpandEnabledCallsAddsObjectScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	tests := []struct {
		root string
		want []string
	}{
		{
			root: "NtQueryInformationProcess",
			want: []string{"GetCurrentProcess$process"},
		},
		{
			root: "SetEvent$event",
			want: []string{"CreateEventA$manual", "CloseHandle"},
		},
		{
			root: "WaitForSingleObject$wait",
			want: []string{"CreateEventA$manual", "CloseHandle"},
		},
		{
			root: "GetTokenInformation$token",
			want: []string{"GetCurrentProcess$process", "OpenProcessToken$process", "CloseHandle"},
		},
		{
			root: "MapViewOfFile$section",
			want: []string{"CreateFileMappingA$pagefile", "CloseHandle"},
		},
		{
			root: "GetQueuedCompletionStatus$iocp",
			want: []string{"CreateIoCompletionPort$create", "CloseHandle"},
		},
		{
			root: "ReadFile$pipe",
			want: []string{"CreatePipe$anon", "CloseHandle"},
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
		for _, name := range append([]string{test.root, "VirtualAlloc"}, test.want...) {
			call := target.SyscallMap[name]
			if call == nil {
				t.Fatalf("missing syscall %q", name)
			}
			if !expanded[call] {
				t.Fatalf("%s expansion is missing %q", test.root, name)
			}
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
	assertResource("SetEvent$event", 0, "EVENT_HANDLE")
	assertResource("WaitForSingleObject$wait", 0, "WAIT_HANDLE")
	assertResource("CreateSemaphoreA$sem", -1, "SEMAPHORE_HANDLE")
	assertResource("ReleaseSemaphore$sem", 0, "SEMAPHORE_HANDLE")
	assertPtrResource("OpenProcessToken$process", 2, "TOKEN_HANDLE")
	assertResource("GetTokenInformation$token", 0, "TOKEN_HANDLE")
	assertResource("CreateFileMappingA$file", -1, "SECTION_HANDLE")
	assertResource("MapViewOfFile$section", 0, "SECTION_HANDLE")
	assertResource("CreateIoCompletionPort$create", -1, "IOCP_HANDLE")
	assertResource("CreateIoCompletionPort$associate", 1, "IOCP_HANDLE")
	assertResource("GetQueuedCompletionStatus$iocp", 0, "IOCP_HANDLE")
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
	assertPtrStruct("TransmitFile$inet_accept", 4, "OVERLAPPED")
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
		"WSAStartup", "WSACleanup", "closesocket$any",
		"CreateFileA", "CreateFile2", "CloseHandle",
		"VirtualAlloc",
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

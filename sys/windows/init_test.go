package windows_test

import (
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
		name   string
		args   []prog.Arg
		verify func(t *testing.T, c *prog.Call)
	}{
		{
			name: "ExitProcess",
			args: []prog.Arg{
				prog.MakeConstArg(target.SyscallMap["ExitProcess"].Args[0].Type, prog.DirIn, 42),
			},
			verify: func(t *testing.T, c *prog.Call) {
				code := c.Args[0].(*prog.ConstArg)
				if code.Val != 0 {
					t.Fatalf("ExitProcess exit code not neutralized: got %d, want 0", code.Val)
				}
			},
		},
		{
			name: "Sleep",
			args: []prog.Arg{
				prog.MakeConstArg(target.SyscallMap["Sleep"].Args[0].Type, prog.DirIn, 5000),
			},
			verify: func(t *testing.T, c *prog.Call) {
				ms := c.Args[0].(*prog.ConstArg)
				if ms.Val != 0 {
					t.Fatalf("Sleep duration not neutralized: got %d, want 0", ms.Val)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := target.SyscallMap[tt.name]
			if meta == nil {
				t.Fatalf("syscall %q not found", tt.name)
			}
			call := &prog.Call{Meta: meta, Args: tt.args}
			if err := target.Neutralize(call, false); err != nil {
				t.Fatalf("Neutralize error: %v", err)
			}
			tt.verify(t, call)
		})
	}
}

func TestWindowsChoiceTableResourcePriorities(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	// Enable FILE_HANDLE consumers + socket CONNECTED consumer + a plain query.
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["NtFsControlFile"]:   true, // uses FILE_HANDLE
		target.SyscallMap["getsockopt$int_tcp"]: true, // uses SOCKET_CONNECTED
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

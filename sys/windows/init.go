// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package windows

import (
	"strings"

	"github.com/google/syzkaller/prog"
)

var windowsAutomaticHelpers = []string{
	"CloseHandle",
	"CreateFileA",
	"CreateFile2",
	"VirtualAlloc",
	"WSAStartup",
	"WSACleanup",
	"socket$inet_tcp",
	"socket$inet_udp",
	"socket$listener_tcp",
	"socket$connected_tcp",
	"socket$accept_tcp",
	"closesocket$any",
}

func InitTarget(target *prog.Target) {
	arch := &arch{
		target:                 target,
		virtualAllocSyscall:    target.SyscallMap["VirtualAlloc"],
		MEM_COMMIT:             target.GetConst("MEM_COMMIT"),
		MEM_RESERVE:            target.GetConst("MEM_RESERVE"),
		PAGE_EXECUTE_READWRITE: target.GetConst("PAGE_EXECUTE_READWRITE"),
	}

	configureWindowsHelpers(target)
	target.ExpandEnabledCalls = expandWindowsEnabledCalls
	target.MakeDataMmap = arch.makeMmap
	target.Neutralize = arch.neutralize

	target.AuxResources = map[string]bool{
		"HANDLE": true,
		"SOCKET": true,
	}

	target.SpecialPointers = []uint64{
		0xFFFFF78000000000, // KUSER_SHARED_DATA
		0xFFFFF80000000000, // ntoskrnl base region
		0xFFFFFF7F00000000, // user/kernel address space boundary
		0x000007FFFFFE0000, // top of user-mode address space
	}
}

func configureWindowsHelpers(target *prog.Target) {
	helperSet := make(map[string]bool, len(windowsAutomaticHelpers))
	for _, name := range windowsAutomaticHelpers {
		helperSet[name] = true
	}
	target.Helpers.AutomaticHelperPredicate = func(call *prog.Syscall) bool {
		if call == nil {
			return false
		}
		return helperSet[call.Name] || call.Attrs.AutomaticHelper
	}
	target.Helpers.DeprioritizeAutomaticHelpers = true
	target.Helpers.AvoidCollidingAutomaticHelpers = true
	target.Helpers.SkipHintsForAutomaticHelpers = true
	target.Helpers.NoMutateAutomaticHelpers = true
	target.Helpers.SkipCorpusForAutomaticHelpers = true
	target.Helpers.SkipTriageForAutomaticHelpers = true
	target.Helpers.AvoidAutomaticHelperBias = true
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
	required := map[string]bool{}
	for _, name := range windowsAutomaticHelpers {
		if windowsCallMatches(target, call, name) {
			required[name] = true
		}
	}
	if windowsNeedsSocketScaffold(call) {
		addWindowsNames(required,
			"WSAStartup", "WSACleanup", "closesocket$any",
		)
	}
	if windowsNeedsTCPAcceptScaffold(call) {
		addWindowsNames(required,
			"socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp",
			"bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "connect$inet_tcp",
		)
	}
	if windowsNeedsTCPConnectScaffold(call) {
		addWindowsNames(required, "socket$connected_tcp", "connect$inet_tcp")
	}
	if windowsNeedsUDPConnectScaffold(call) {
		addWindowsNames(required, "socket$inet_udp", "connect$inet_udp")
	}
	if windowsNeedsPeerTrafficScaffold(call) {
		for _, name := range windowsPeerTrafficCallNames(call.Name) {
			required[name] = true
		}
	}
	if windowsNeedsFileScaffold(call) {
		addWindowsNames(required, "CreateFileA", "CreateFile2", "CloseHandle")
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
		"connect$inet_udp",
		"send$inet_tcp", "send$inet_udp", "send$inet_accept",
		"WriteFile",
		"NtReadFile", "NtWriteFile", "NtFsControlFile",
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

func windowsNeedsSocketScaffold(call *prog.Syscall) bool {
	return windowsCallUsesInputResourcePrefix(call, "SOCKET")
}

func windowsNeedsTCPAcceptScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	if strings.Contains(call.Name, "$inet_accept") {
		return true
	}
	switch call.Name {
	case "accept$inet_tcp", "AcceptEx$inet_tcp":
		return true
	}
	return windowsCallUsesInputResourceKind(call, "SOCKET_ACCEPT") ||
		windowsCallUsesInputResourceKind(call, "SOCKET_LISTENER")
}

func windowsNeedsTCPConnectScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	return windowsCallUsesInputResourceKind(call, "SOCKET_CONNECTED")
}

func windowsNeedsUDPConnectScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	return windowsCallUsesInputResourceKind(call, "SOCKET_UDP")
}

func windowsNeedsPeerTrafficScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	switch call.Name {
	case "recv$inet_tcp", "recv$inet_udp", "recv$inet_accept", "WSARecvEx$inet_accept":
		return true
	}
	return false
}

func windowsPeerTrafficCallNames(name string) []string {
	switch name {
	case "recv$inet_tcp":
		return []string{"send$inet_accept"}
	case "recv$inet_udp":
		return []string{"send$inet_udp"}
	case "recv$inet_accept", "WSARecvEx$inet_accept":
		return []string{"send$inet_tcp"}
	default:
		return nil
	}
}

func windowsNeedsFileScaffold(call *prog.Syscall) bool {
	return windowsCallUsesInputResourcePrefix(call, "FILE_HANDLE")
}

func windowsNeedsFilePayloadScaffold(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	switch call.Name {
	case "TransmitFile$inet_accept", "WriteFile", "NtWriteFile":
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

type arch struct {
	target              *prog.Target
	virtualAllocSyscall *prog.Syscall

	MEM_COMMIT             uint64
	MEM_RESERVE            uint64
	PAGE_EXECUTE_READWRITE uint64
}

func (arch *arch) makeMmap() []*prog.Call {
	meta := arch.virtualAllocSyscall
	size := arch.target.NumPages * arch.target.PageSize
	return []*prog.Call{
		prog.MakeCall(meta, []prog.Arg{
			prog.MakeVmaPointerArg(meta.Args[0].Type, prog.DirIn, 0, size),
			prog.MakeConstArg(meta.Args[1].Type, prog.DirIn, size),
			prog.MakeConstArg(meta.Args[2].Type, prog.DirIn, arch.MEM_COMMIT|arch.MEM_RESERVE),
			prog.MakeConstArg(meta.Args[3].Type, prog.DirIn, arch.PAGE_EXECUTE_READWRITE),
		}),
	}
}

func (arch *arch) neutralize(c *prog.Call, fixStructure bool) error {
	switch c.Meta.CallName {
	case "ExitProcess", "TerminateProcess", "TerminateJobObject":
		if n := len(c.Args); n > 0 {
			if code, ok := c.Args[n-1].(*prog.ConstArg); ok {
				code.Val = 0
			}
		}
	case "Sleep", "SleepEx":
		if len(c.Args) > 0 {
			if ms, ok := c.Args[0].(*prog.ConstArg); ok {
				ms.Val = 0
			}
		}
	}
	return nil
}

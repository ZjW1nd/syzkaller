// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package windows

import "github.com/google/syzkaller/prog"

func InitTarget(target *prog.Target) {
	arch := &arch{
		target:                 target,
		virtualAllocSyscall:    target.SyscallMap["VirtualAlloc"],
		MEM_COMMIT:             target.GetConst("MEM_COMMIT"),
		MEM_RESERVE:            target.GetConst("MEM_RESERVE"),
		PAGE_EXECUTE_READWRITE: target.GetConst("PAGE_EXECUTE_READWRITE"),
	}

	configureWindowsHelpers(target)
	target.ApplyTargetProfile = applyWindowsTargetProfile
	target.CallRelevanceScore = windowsCallRelevanceScore
	target.TriageCallScore = windowsCallRelevanceScore
	target.ResourceUseScore = windowsResourceUseScore
	target.ResourceReuseScore = windowsResourceReuseScore
	target.SelectResourceCtor = windowsSelectResourceCtor
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
	case "ExitProcess", "ExitThread", "FatalExit",
		"TerminateProcess", "TerminateThread", "TerminateJobObject":
		windowsNeutralizeConstArg(c, len(c.Args)-1)
	case "Sleep", "SleepEx":
		windowsNeutralizeConstArg(c, 0)
	case "WaitForDebugEvent", "WaitForDebugEventEx",
		"WaitForSingleObject", "WaitForSingleObjectEx",
		"WaitForInputIdle", "WaitNamedPipeA":
		windowsNeutralizeConstArg(c, 1)
	case "SleepConditionVariableCS", "SignalObjectAndWait",
		"MsgWaitForMultipleObjectsEx":
		windowsNeutralizeConstArg(c, 2)
	case "WaitForMultipleObjects", "WaitForMultipleObjectsEx",
		"WaitOnAddress", "MsgWaitForMultipleObjects",
		"RegisterWaitForSingleObject":
		windowsNeutralizeConstArg(c, 3)
	}
	return nil
}

func windowsNeutralizeConstArg(c *prog.Call, arg int) {
	if arg < 0 || arg >= len(c.Args) {
		return
	}
	if value, ok := c.Args[arg].(*prog.ConstArg); ok {
		value.Val = 0
	}
}

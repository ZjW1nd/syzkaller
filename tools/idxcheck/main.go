package main

import (
	"fmt"
	"os"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys" // trigger register.go init()
)

func main() {
	t, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERR:", err)
		os.Exit(1)
	}
	fmt.Printf("Total syscalls: %d\n", len(t.Syscalls))
	names := []string{"CloseHandle","CreateFile2","DeleteFileA","FlushFileBuffers",
		"ReadFile","SetFileInformationByHandle","WriteFile","VirtualAlloc",
		"NtDelayExecution","NtFlushInstructionCache","NtFlushWriteBuffer",
		"NtPowerInformation","NtQueryDefaultLocale","NtQueryDefaultUILanguage",
		"NtQueryInformationProcess","NtQueryPerformanceCounter",
		"NtQuerySystemInformation","NtQuerySystemTime",
		"NtQueryTimerResolution","NtSetInformationProcess",
		"NtSetTimerResolution","NtYieldExecution"}
	for _, name := range names {
		if s := t.SyscallMap[name]; s != nil {
			fmt.Printf("  W32_%-25s = %d\n", name, s.ID)
		} else {
			fmt.Printf("  MISSING: %s\n", name)
		}
	}
}

// Minimal sparse syscall table for the Windows Nyx demo pipeline.
// The indices must match the IDs in prog.GetTarget("windows", "amd64").

#include <winternl.h>

static call_t syscalls[2655];

static void init_demo_syscalls()
{
	static bool initialized;
	if (initialized)
		return;
	initialized = true;
		syscalls[2654] = call_t{"VirtualAlloc", 0, {}, (syscall_t)VirtualAlloc};
		syscalls[1794] = call_t{"NtQueryInformationProcess", 0, {}, (syscall_t)NtQueryInformationProcess};
		syscalls[1795] = call_t{"NtQuerySystemInformation", 0, {}, (syscall_t)NtQuerySystemInformation};
		syscalls[1796] = call_t{"NtSetInformationProcess", 0, {}, (syscall_t)NtSetInformationProcess};
}

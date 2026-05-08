// Minimal sparse syscall table for the Windows Nyx pipeline.
// The indices must match the IDs in prog.GetTarget("windows", "amd64").

#include <winternl.h>

// Declare NT APIs not in mingw headers (exported by ntdll.dll, linked via -lntdll)
extern "C" {
NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
NTSTATUS NTAPI NtFsControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
NTSTATUS NTAPI NtYieldExecution();
NTSTATUS NTAPI NtQueryTimerResolution(PULONG, PULONG, PULONG);
NTSTATUS NTAPI NtSetTimerResolution(ULONG, BOOLEAN, PULONG);
NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER);
NTSTATUS NTAPI NtQueryPerformanceCounter(PLARGE_INTEGER, PLARGE_INTEGER);
NTSTATUS NTAPI NtPowerInformation(POWER_INFORMATION_LEVEL, PVOID, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtFlushInstructionCache(HANDLE, PVOID, ULONG);
NTSTATUS NTAPI NtFlushWriteBuffer();
NTSTATUS NTAPI NtQueryDefaultLocale(BOOLEAN, PLCID);
NTSTATUS NTAPI NtQueryDefaultUILanguage(LANGID*);
}

// NTFS syscall IDs — from prog.GetTarget("windows","amd64").SyscallMap
// Generated: go build ./tools/idxcheck/ && /tmp/idxcheck
#define W32_VIRTUALALLOC 2670
#define W32_NTQINFO_PROC 1802
#define W32_NTQINFO_SYS 1804
#define W32_NTSETINFO_PROC 1808
#define W32_NTDELAYEXEC 1795
#define W32_NTYIELDEXEC 1811
#define W32_NTQUERYTIMERRES 1806
#define W32_NTSETTIMERRES 1809
#define W32_NTQUERYSYSTIME 1805
#define W32_NTQUERYPERFCTR 1803
#define W32_NTPOWERINFO 1799
#define W32_NTFLUSHICACHE 1796
#define W32_NTFLUSHWBUF 1797
#define W32_NTQUERYDEFLOCALE 1800
#define W32_NTQUERYDEFUILANG 1801
#define W32_NTFSCONTROLFILE 1798
#define W32_NTREADFILE 1807
#define W32_NTWRITEFILE 1810
// Win32 file I/O
#define W32_CLOSEHANDLE 295
#define W32_CREATEFILEA 383
#define W32_CREATEFILE2 382
#define W32_DELETEFILEA 640
#define W32_FLUSHFILEBUFFERS 884
#define W32_READFILE 1959
#define W32_SETFILEINFOBYHANDLE 2345
#define W32_WRITEFILE 2769
// Winsock / afd.sys user-mode entry points
#define W32_ACCEPTEX 5
#define W32_TRANSMITFILE_INET 2603
#define W32_WSACLEANUP 2715
#define W32_WSARECVEX 2719
#define W32_WSASTARTUP 2722
#define W32_ACCEPT_INET 2782
#define W32_BIND_INET 2789
#define W32_CLOSESOCKET_ANY 2791
#define W32_CONNECT_INET 2793
#define W32_GETSOCKOPT_INT 2804
#define W32_IOCTLSOCKET_FIONBIO 2810
#define W32_LISTEN_INET 2822
#define W32_RECV_INET 2914
#define W32_SEND_INET 2918
#define W32_SETSOCKOPT_INT 2921
#define W32_SOCKET_INET_TCP 2924
#define W32_SOCKET_INET_UDP 2925

static call_t syscalls[3000];

static void init_nyx_syscalls()
{
	static bool initialized;
	if (initialized)
		return;
	initialized = true;
	syscalls[W32_VIRTUALALLOC] = call_t{"VirtualAlloc", 0, {}, (syscall_t)VirtualAlloc};
	syscalls[W32_NTQINFO_PROC] = call_t{"NtQueryInformationProcess", 0, {}, (syscall_t)NtQueryInformationProcess};
	syscalls[W32_NTQINFO_SYS] = call_t{"NtQuerySystemInformation", 0, {}, (syscall_t)NtQuerySystemInformation};
	syscalls[W32_NTSETINFO_PROC] = call_t{"NtSetInformationProcess", 0, {}, (syscall_t)NtSetInformationProcess};
	syscalls[W32_CLOSEHANDLE] = call_t{"CloseHandle", 0, {}, (syscall_t)CloseHandle};
	syscalls[W32_CREATEFILEA] = call_t{"CreateFileA", 0, {}, (syscall_t)CreateFileA};
	syscalls[W32_CREATEFILE2] = call_t{"CreateFile2", 0, {}, (syscall_t)CreateFile2};
	syscalls[W32_DELETEFILEA] = call_t{"DeleteFileA", 0, {}, (syscall_t)DeleteFileA};
	syscalls[W32_FLUSHFILEBUFFERS] = call_t{"FlushFileBuffers", 0, {}, (syscall_t)FlushFileBuffers};
	syscalls[W32_READFILE] = call_t{"ReadFile", 0, {}, (syscall_t)ReadFile};
	syscalls[W32_SETFILEINFOBYHANDLE] = call_t{"SetFileInformationByHandle", 0, {}, (syscall_t)SetFileInformationByHandle};
	syscalls[W32_WRITEFILE] = call_t{"WriteFile", 0, {}, (syscall_t)WriteFile};
	syscalls[W32_ACCEPTEX] = call_t{"AcceptEx$inet", 0, {}, (syscall_t)AcceptEx};
	syscalls[W32_TRANSMITFILE_INET] = call_t{"TransmitFile$inet", 0, {}, (syscall_t)TransmitFile};
	syscalls[W32_WSACLEANUP] = call_t{"WSACleanup", 0, {}, (syscall_t)WSACleanup};
	syscalls[W32_WSARECVEX] = call_t{"WSARecvEx$inet", 0, {}, (syscall_t)WSARecvEx};
	syscalls[W32_WSASTARTUP] = call_t{"WSAStartup", 0, {}, (syscall_t)WSAStartup};
	syscalls[W32_ACCEPT_INET] = call_t{"accept$inet", 0, {}, (syscall_t)accept};
	syscalls[W32_BIND_INET] = call_t{"bind$inet", 0, {}, (syscall_t)bind};
	syscalls[W32_CLOSESOCKET_ANY] = call_t{"closesocket$any", 0, {}, (syscall_t)closesocket};
	syscalls[W32_CONNECT_INET] = call_t{"connect$inet", 0, {}, (syscall_t)connect};
	syscalls[W32_GETSOCKOPT_INT] = call_t{"getsockopt$int", 0, {}, (syscall_t)getsockopt};
	syscalls[W32_IOCTLSOCKET_FIONBIO] = call_t{"ioctlsocket$fionbio", 0, {}, (syscall_t)ioctlsocket};
	syscalls[W32_LISTEN_INET] = call_t{"listen$inet", 0, {}, (syscall_t)listen};
	syscalls[W32_RECV_INET] = call_t{"recv$inet", 0, {}, (syscall_t)recv};
	syscalls[W32_SEND_INET] = call_t{"send$inet", 0, {}, (syscall_t)send};
	syscalls[W32_SETSOCKOPT_INT] = call_t{"setsockopt$int", 0, {}, (syscall_t)setsockopt};
	syscalls[W32_SOCKET_INET_TCP] = call_t{"socket$inet_tcp", 0, {}, (syscall_t)socket};
	syscalls[W32_SOCKET_INET_UDP] = call_t{"socket$inet_udp", 0, {}, (syscall_t)socket};
	// New no-context NT syscalls
	syscalls[W32_NTDELAYEXEC] = call_t{"NtDelayExecution", 0, {}, (syscall_t)NtDelayExecution};
	syscalls[W32_NTYIELDEXEC] = call_t{"NtYieldExecution", 0, {}, (syscall_t)NtYieldExecution};
	syscalls[W32_NTQUERYTIMERRES] = call_t{"NtQueryTimerResolution", 0, {}, (syscall_t)NtQueryTimerResolution};
	syscalls[W32_NTSETTIMERRES] = call_t{"NtSetTimerResolution", 0, {}, (syscall_t)NtSetTimerResolution};
	syscalls[W32_NTQUERYSYSTIME] = call_t{"NtQuerySystemTime", 0, {}, (syscall_t)NtQuerySystemTime};
	syscalls[W32_NTQUERYPERFCTR] = call_t{"NtQueryPerformanceCounter", 0, {}, (syscall_t)NtQueryPerformanceCounter};
	syscalls[W32_NTPOWERINFO] = call_t{"NtPowerInformation", 0, {}, (syscall_t)NtPowerInformation};
	syscalls[W32_NTFLUSHICACHE] = call_t{"NtFlushInstructionCache", 0, {}, (syscall_t)NtFlushInstructionCache};
	syscalls[W32_NTFLUSHWBUF] = call_t{"NtFlushWriteBuffer", 0, {}, (syscall_t)NtFlushWriteBuffer};
	syscalls[W32_NTQUERYDEFLOCALE] = call_t{"NtQueryDefaultLocale", 0, {}, (syscall_t)NtQueryDefaultLocale};
	syscalls[W32_NTQUERYDEFUILANG] = call_t{"NtQueryDefaultUILanguage", 0, {}, (syscall_t)NtQueryDefaultUILanguage};
	syscalls[W32_NTFSCONTROLFILE] = call_t{"NtFsControlFile", 0, {}, (syscall_t)NtFsControlFile};
	syscalls[W32_NTREADFILE] = call_t{"NtReadFile", 0, {}, (syscall_t)NtReadFile};
	syscalls[W32_NTWRITEFILE] = call_t{"NtWriteFile", 0, {}, (syscall_t)NtWriteFile};
}

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
#define W32_ACCEPTEX_INET_TCP 5
#define W32_TRANSMITFILE_INET_ACCEPT 2603
#define W32_WSACLEANUP 2715
#define W32_WSARECVEX_INET_ACCEPT 2719
#define W32_WSASTARTUP 2722
#define W32_ACCEPT_INET_TCP 2782
#define W32_BIND_INET_TCP 2789
#define W32_BIND_INET_UDP 2790
#define W32_CLOSESOCKET_ANY 2792
#define W32_CONNECT_INET_TCP 2794
#define W32_CONNECT_INET_UDP 2795
#define W32_GETSOCKOPT_INT_ACCEPT 2806
#define W32_GETSOCKOPT_INT_TCP 2807
#define W32_GETSOCKOPT_INT_UDP 2808
#define W32_IOCTLSOCKET_FIONBIO_ACCEPT 2814
#define W32_IOCTLSOCKET_FIONBIO_TCP 2815
#define W32_IOCTLSOCKET_FIONBIO_UDP 2816
#define W32_LISTEN_INET_TCP 2828
#define W32_RECV_INET_ACCEPT 2920
#define W32_RECV_INET_TCP 2921
#define W32_RECV_INET_UDP 2922
#define W32_SEND_INET_ACCEPT 2926
#define W32_SEND_INET_TCP 2927
#define W32_SEND_INET_UDP 2928
#define W32_SETSOCKOPT_INT_ACCEPT 2931
#define W32_SETSOCKOPT_INT_TCP 2932
#define W32_SETSOCKOPT_INT_UDP 2933
#define W32_SOCKET_ACCEPT_TCP 2936
#define W32_SOCKET_CONNECTED_TCP 2937
#define W32_SOCKET_INET_TCP 2938
#define W32_SOCKET_INET_UDP 2939
#define W32_SOCKET_LISTENER_TCP 2940

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
	syscalls[W32_ACCEPTEX_INET_TCP] = call_t{"AcceptEx$inet_tcp", 0, {}, (syscall_t)AcceptEx};
	syscalls[W32_TRANSMITFILE_INET_ACCEPT] = call_t{"TransmitFile$inet_accept", 0, {}, (syscall_t)TransmitFile};
	syscalls[W32_WSACLEANUP] = call_t{"WSACleanup", 0, {}, (syscall_t)WSACleanup};
	syscalls[W32_WSARECVEX_INET_ACCEPT] = call_t{"WSARecvEx$inet_accept", 0, {}, (syscall_t)WSARecvEx};
	syscalls[W32_WSASTARTUP] = call_t{"WSAStartup", 0, {}, (syscall_t)WSAStartup};
	syscalls[W32_ACCEPT_INET_TCP] = call_t{"accept$inet_tcp", 0, {}, (syscall_t)accept};
	syscalls[W32_BIND_INET_TCP] = call_t{"bind$inet_tcp", 0, {}, (syscall_t)bind};
	syscalls[W32_BIND_INET_UDP] = call_t{"bind$inet_udp", 0, {}, (syscall_t)bind};
	syscalls[W32_CLOSESOCKET_ANY] = call_t{"closesocket$any", 0, {}, (syscall_t)closesocket};
	syscalls[W32_CONNECT_INET_TCP] = call_t{"connect$inet_tcp", 0, {}, (syscall_t)connect};
	syscalls[W32_CONNECT_INET_UDP] = call_t{"connect$inet_udp", 0, {}, (syscall_t)connect};
	syscalls[W32_GETSOCKOPT_INT_ACCEPT] = call_t{"getsockopt$int_accept", 0, {}, (syscall_t)getsockopt};
	syscalls[W32_GETSOCKOPT_INT_TCP] = call_t{"getsockopt$int_tcp", 0, {}, (syscall_t)getsockopt};
	syscalls[W32_GETSOCKOPT_INT_UDP] = call_t{"getsockopt$int_udp", 0, {}, (syscall_t)getsockopt};
	syscalls[W32_IOCTLSOCKET_FIONBIO_ACCEPT] = call_t{"ioctlsocket$fionbio_accept", 0, {}, (syscall_t)ioctlsocket};
	syscalls[W32_IOCTLSOCKET_FIONBIO_TCP] = call_t{"ioctlsocket$fionbio_tcp", 0, {}, (syscall_t)ioctlsocket};
	syscalls[W32_IOCTLSOCKET_FIONBIO_UDP] = call_t{"ioctlsocket$fionbio_udp", 0, {}, (syscall_t)ioctlsocket};
	syscalls[W32_LISTEN_INET_TCP] = call_t{"listen$inet_tcp", 0, {}, (syscall_t)listen};
	syscalls[W32_RECV_INET_ACCEPT] = call_t{"recv$inet_accept", 0, {}, (syscall_t)recv};
	syscalls[W32_RECV_INET_TCP] = call_t{"recv$inet_tcp", 0, {}, (syscall_t)recv};
	syscalls[W32_RECV_INET_UDP] = call_t{"recv$inet_udp", 0, {}, (syscall_t)recv};
	syscalls[W32_SEND_INET_ACCEPT] = call_t{"send$inet_accept", 0, {}, (syscall_t)send};
	syscalls[W32_SEND_INET_TCP] = call_t{"send$inet_tcp", 0, {}, (syscall_t)send};
	syscalls[W32_SEND_INET_UDP] = call_t{"send$inet_udp", 0, {}, (syscall_t)send};
	syscalls[W32_SETSOCKOPT_INT_ACCEPT] = call_t{"setsockopt$int_accept", 0, {}, (syscall_t)setsockopt};
	syscalls[W32_SETSOCKOPT_INT_TCP] = call_t{"setsockopt$int_tcp", 0, {}, (syscall_t)setsockopt};
	syscalls[W32_SETSOCKOPT_INT_UDP] = call_t{"setsockopt$int_udp", 0, {}, (syscall_t)setsockopt};
	syscalls[W32_SOCKET_ACCEPT_TCP] = call_t{"socket$accept_tcp", 0, {}, (syscall_t)socket};
	syscalls[W32_SOCKET_CONNECTED_TCP] = call_t{"socket$connected_tcp", 0, {}, (syscall_t)socket};
	syscalls[W32_SOCKET_INET_TCP] = call_t{"socket$inet_tcp", 0, {}, (syscall_t)socket};
	syscalls[W32_SOCKET_INET_UDP] = call_t{"socket$inet_udp", 0, {}, (syscall_t)socket};
	syscalls[W32_SOCKET_LISTENER_TCP] = call_t{"socket$listener_tcp", 0, {}, (syscall_t)socket};
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

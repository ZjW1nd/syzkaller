// Minimal sparse syscall table for the Windows Nyx pipeline.
// The indices must match the IDs in prog.GetTarget("windows", "amd64").

#include <winternl.h>

// Declare NT APIs not in mingw headers (exported by ntdll.dll, linked via -lntdll)
extern "C" {
NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
NTSTATUS NTAPI NtFsControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtQueryInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
NTSTATUS NTAPI NtSetInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
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
#define W32_VIRTUALALLOC 2700
#define W32_GETCURRENTPROCESS_PROCESS 1029
#define W32_GETCURRENTTHREAD_THREAD 1034
#define W32_NTQINFOFILE_BASIC 1821
#define W32_NTQINFOFILE_NETOPEN 1822
#define W32_NTQINFOFILE_STANDARD 1823
#define W32_NTQINFO_PROC 1824
#define W32_NTQINFO_SYS 1826
#define W32_NTSETINFO_PROC 1831
#define W32_NTDELAYEXEC 1808
#define W32_NTDEVICEIOCTLFILE 1809
#define W32_NTYIELDEXEC 1834
#define W32_NTQUERYTIMERRES 1828
#define W32_NTSETTIMERRES 1832
#define W32_NTQUERYSYSTIME 1827
#define W32_NTQUERYPERFCTR 1825
#define W32_NTPOWERINFO 1818
#define W32_NTFLUSHICACHE 1810
#define W32_NTFLUSHWBUF 1811
#define W32_NTQUERYDEFLOCALE 1819
#define W32_NTQUERYDEFUILANG 1820
#define W32_NTFSCONTROLFILE 1812
#define W32_NTFSCONTROLFILE_NTFS_GET_COMP 1813
#define W32_NTFSCONTROLFILE_NTFS_QUERY_ALLOC_RANGES 1814
#define W32_NTFSCONTROLFILE_NTFS_SET_COMP 1815
#define W32_NTFSCONTROLFILE_NTFS_SET_SPARSE 1816
#define W32_NTFSCONTROLFILE_NTFS_SET_ZERO_DATA 1817
#define W32_NTREADFILE 1829
#define W32_NTSETINFOFILE_BASIC 1830
#define W32_NTWRITEFILE 1833
// Win32 file I/O
#define W32_CLOSEHANDLE 295
#define W32_CREATEFILEA 385
#define W32_CREATEFILE2 384
#define W32_DELETEFILEA 648
#define W32_FLUSHFILEBUFFERS 892
#define W32_READFILE 1985
#define W32_SETFILEINFOBYHANDLE 2375
#define W32_WRITEFILE 2801
// Winsock / afd.sys user-mode entry points
#define W32_ACCEPTEX_INET_TCP 5
#define W32_TRANSMITFILE_INET_ACCEPT 2633
#define W32_WSACLEANUP 2745
#define W32_WSARECVEX_INET_ACCEPT 2749
#define W32_WSASTARTUP 2752
#define W32_ACCEPT_INET_TCP 2815
#define W32_BIND_INET_TCP 2822
#define W32_BIND_INET_UDP 2823
#define W32_CLOSESOCKET_ANY 2825
#define W32_CONNECT_INET_TCP 2827
#define W32_CONNECT_INET_UDP 2828
#define W32_GETSOCKOPT_INT_ACCEPT 2839
#define W32_GETSOCKOPT_INT_TCP 2840
#define W32_GETSOCKOPT_INT_UDP 2841
#define W32_IOCTLSOCKET_FIONBIO_ACCEPT 2847
#define W32_IOCTLSOCKET_FIONBIO_TCP 2848
#define W32_IOCTLSOCKET_FIONBIO_UDP 2849
#define W32_LISTEN_INET_TCP 2861
#define W32_RECV_INET_ACCEPT 2953
#define W32_RECV_INET_TCP 2954
#define W32_RECV_INET_UDP 2955
#define W32_SEND_INET_ACCEPT 2959
#define W32_SEND_INET_TCP 2960
#define W32_SEND_INET_UDP 2961
#define W32_SETSOCKOPT_INT_ACCEPT 2964
#define W32_SETSOCKOPT_INT_TCP 2965
#define W32_SETSOCKOPT_INT_UDP 2966
#define W32_SOCKET_ACCEPT_TCP 2969
#define W32_SOCKET_CONNECTED_TCP 2970
#define W32_SOCKET_INET_TCP 2971
#define W32_SOCKET_INET_UDP 2972
#define W32_SOCKET_LISTENER_TCP 2973

#include "windows_service_26200.h"

static call_t syscalls[3000];

static syscall_t make_nyx_ntos_service_stub(uint32 service_number)
{
	const SIZE_T stub_size = 11;
	auto* code = reinterpret_cast<unsigned char*>(
	    VirtualAlloc(nullptr, stub_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!code)
		failmsg("ntos service stub allocation failed", "service=%u", service_number);
	code[0] = 0x4c;
	code[1] = 0x8b;
	code[2] = 0xd1;
	code[3] = 0xb8;
	memcpy(code + 4, &service_number, sizeof(service_number));
	code[8] = 0x0f;
	code[9] = 0x05;
	code[10] = 0xc3;
	return reinterpret_cast<syscall_t>(code);
}

static void init_nyx_ntos_service(int target_id, const char* target_name, const char* service_name,
				  uint32 service_number)
{
	(void)service_name;
	syscalls[target_id] =
	    call_t{target_name, static_cast<int>(service_number), {}, make_nyx_ntos_service_stub(service_number)};
}

static void init_nyx_syscalls()
{
	static bool initialized;
	if (initialized)
		return;
	initialized = true;
	syscalls[W32_VIRTUALALLOC] = call_t{"VirtualAlloc", 0, {}, (syscall_t)VirtualAlloc};
	syscalls[W32_GETCURRENTPROCESS_PROCESS] = call_t{"GetCurrentProcess$process", 0, {}, (syscall_t)GetCurrentProcess};
	syscalls[W32_GETCURRENTTHREAD_THREAD] = call_t{"GetCurrentThread$thread", 0, {}, (syscall_t)GetCurrentThread};
	syscalls[W32_NTQINFOFILE_BASIC] = call_t{"NtQueryInformationFile$basic", 0, {}, (syscall_t)NtQueryInformationFile};
	syscalls[W32_NTQINFOFILE_NETOPEN] = call_t{"NtQueryInformationFile$network_open", 0, {}, (syscall_t)NtQueryInformationFile};
	syscalls[W32_NTQINFOFILE_STANDARD] = call_t{"NtQueryInformationFile$standard", 0, {}, (syscall_t)NtQueryInformationFile};
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
	syscalls[W32_NTDEVICEIOCTLFILE] = call_t{"NtDeviceIoControlFile", 0, {}, (syscall_t)NtDeviceIoControlFile};
	syscalls[W32_NTFSCONTROLFILE] = call_t{"NtFsControlFile", 0, {}, (syscall_t)NtFsControlFile};
	syscalls[W32_NTFSCONTROLFILE_NTFS_GET_COMP] = call_t{"NtFsControlFile$ntfs_get_compression", 0, {}, (syscall_t)NtFsControlFile};
	syscalls[W32_NTFSCONTROLFILE_NTFS_QUERY_ALLOC_RANGES] = call_t{"NtFsControlFile$ntfs_query_allocated_ranges", 0, {}, (syscall_t)NtFsControlFile};
	syscalls[W32_NTFSCONTROLFILE_NTFS_SET_COMP] = call_t{"NtFsControlFile$ntfs_set_compression", 0, {}, (syscall_t)NtFsControlFile};
	syscalls[W32_NTFSCONTROLFILE_NTFS_SET_SPARSE] = call_t{"NtFsControlFile$ntfs_set_sparse", 0, {}, (syscall_t)NtFsControlFile};
	syscalls[W32_NTFSCONTROLFILE_NTFS_SET_ZERO_DATA] = call_t{"NtFsControlFile$ntfs_set_zero_data", 0, {}, (syscall_t)NtFsControlFile};
	syscalls[W32_NTREADFILE] = call_t{"NtReadFile", 0, {}, (syscall_t)NtReadFile};
	syscalls[W32_NTSETINFOFILE_BASIC] = call_t{"NtSetInformationFile$basic", 0, {}, (syscall_t)NtSetInformationFile};
	syscalls[W32_NTWRITEFILE] = call_t{"NtWriteFile", 0, {}, (syscall_t)NtWriteFile};
#define INIT_NYX_SERVICE_ENTRY(kind, target_id, target_name, service_name, service_number) \
	init_nyx_##kind##_service(target_id, target_name, service_name, service_number);
	WINDOWS_NYX_SERVICE_TABLE_26200(INIT_NYX_SERVICE_ENTRY)
#undef INIT_NYX_SERVICE_ENTRY
}

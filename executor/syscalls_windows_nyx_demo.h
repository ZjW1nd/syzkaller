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
// Generated: go run ./tools/idxcheck/main.go
#define W32_VIRTUALALLOC 2733
#define W32_GETCURRENTPROCESS_PROCESS 1059
#define W32_GETCURRENTTHREAD_THREAD 1064
#define W32_NTQINFOFILE_BASIC 1852
#define W32_NTQINFOFILE_NETOPEN 1853
#define W32_NTQINFOFILE_STANDARD 1854
#define W32_NTQINFO_PROC 1855
#define W32_NTQINFO_SYS 1857
#define W32_NTSETINFO_PROC 1862
#define W32_NTDELAYEXEC 1839
#define W32_NTDEVICEIOCTLFILE 1840
#define W32_NTYIELDEXEC 1865
#define W32_NTQUERYTIMERRES 1859
#define W32_NTSETTIMERRES 1863
#define W32_NTQUERYSYSTIME 1858
#define W32_NTQUERYPERFCTR 1856
#define W32_NTPOWERINFO 1849
#define W32_NTFLUSHICACHE 1841
#define W32_NTFLUSHWBUF 1842
#define W32_NTQUERYDEFLOCALE 1850
#define W32_NTQUERYDEFUILANG 1851
#define W32_NTFSCONTROLFILE 1843
#define W32_NTFSCONTROLFILE_NTFS_GET_COMP 1844
#define W32_NTFSCONTROLFILE_NTFS_QUERY_ALLOC_RANGES 1845
#define W32_NTFSCONTROLFILE_NTFS_SET_COMP 1846
#define W32_NTFSCONTROLFILE_NTFS_SET_SPARSE 1847
#define W32_NTFSCONTROLFILE_NTFS_SET_ZERO_DATA 1848
#define W32_NTREADFILE 1860
#define W32_NTSETINFOFILE_BASIC 1861
#define W32_NTWRITEFILE 1864
// Win32 file I/O
#define W32_CANCELIO_SOCKET 127
#define W32_CANCELIOEX_SOCKET 135
#define W32_CLOSEHANDLE 310
#define W32_CREATEFILEA 404
#define W32_CREATEFILE2 403
#define W32_CREATEIOCOMPLETIONPORT_SOCKET 431
#define W32_DELETEFILEA 674
#define W32_FLUSHFILEBUFFERS 921
#define W32_GETQUEUEDCOMPLETIONSTATUS_SOCKET 1341
#define W32_CANCELIO_ACCEPT_PENDING 123
#define W32_CANCELIO_ACCEPT_RECV_PENDING 124
#define W32_CANCELIO_ACCEPT_SEND_PENDING 125
#define W32_CANCELIO_CONNECT_PENDING 126
#define W32_CANCELIO_TCP_RECV_PENDING 128
#define W32_CANCELIO_TCP_SEND_PENDING 129
#define W32_CANCELIOEX_ACCEPT_PENDING 131
#define W32_CANCELIOEX_ACCEPT_RECV_PENDING 132
#define W32_CANCELIOEX_ACCEPT_SEND_PENDING 133
#define W32_CANCELIOEX_CONNECT_PENDING 134
#define W32_CANCELIOEX_TCP_RECV_PENDING 136
#define W32_CANCELIOEX_TCP_SEND_PENDING 137
#define W32_CREATEIOCOMPLETIONPORT_ACCEPT_PENDING 425
#define W32_CREATEIOCOMPLETIONPORT_ACCEPT_RECV_PENDING 426
#define W32_CREATEIOCOMPLETIONPORT_ACCEPT_SEND_PENDING 427
#define W32_CREATEIOCOMPLETIONPORT_CONNECT_PENDING 429
#define W32_CREATEIOCOMPLETIONPORT_TCP_RECV_PENDING 432
#define W32_CREATEIOCOMPLETIONPORT_TCP_SEND_PENDING 433
#define W32_READFILE 2016
#define W32_SETFILEINFOBYHANDLE 2406
#define W32_WRITEFILE 2869
// Winsock / afd.sys user-mode entry points
#define W32_ACCEPTEX_INET_TCP 5
#define W32_ACCEPTEX_INET_TCP_PENDING 6
#define W32_CONNECTEX_INET_TCP 340
#define W32_CONNECTEX_INET_TCP_PENDING 341
#define W32_CONNECTEX_INET_TCP_REUSE 342
#define W32_DISCONNECTEX_INET_TCP 723
#define W32_DISCONNECTEX_INET_TCP_REUSE 724
#define W32_GETACCEPTEXSOCKADDRS_INET_TCP 956
#define W32_TRANSMITFILE_INET_ACCEPT 2664
#define W32_TRANSMITPACKETS_INET_ACCEPT 2666
#define W32_WSACLEANUP 2778
#define W32_WSACLOSEEVENT 2779
#define W32_WSACREATEEVENT 2780
#define W32_WSAENUMNETWORKEVENTS_ACCEPT 2781
#define W32_WSAENUMNETWORKEVENTS_TCP 2782
#define W32_WSAEVENTSELECT_ACCEPT 2783
#define W32_WSAEVENTSELECT_TCP 2784
#define W32_WSAGETOVERLAPPEDRESULT_SOCKET 2790
#define W32_WSAGETOVERLAPPEDRESULT_ACCEPT_PENDING 2786
#define W32_WSAGETOVERLAPPEDRESULT_ACCEPT_RECV_PENDING 2787
#define W32_WSAGETOVERLAPPEDRESULT_ACCEPT_SEND_PENDING 2788
#define W32_WSAGETOVERLAPPEDRESULT_CONNECT_PENDING 2789
#define W32_WSAGETOVERLAPPEDRESULT_TCP_RECV_PENDING 2791
#define W32_WSAGETOVERLAPPEDRESULT_TCP_SEND_PENDING 2792
#define W32_WSAIOCTL_SIO_ADDRESS_LIST_QUERY 2794
#define W32_WSAIOCTL_SIO_GET_EXTENSION_FUNCTION_POINTER 2795
#define W32_WSAIOCTL_SIO_KEEPALIVE_VALS 2796
#define W32_WSAIOCTL_SIO_ROUTING_INTERFACE_QUERY 2797
#define W32_WSARECV_ACCEPT 2800
#define W32_WSARECV_ACCEPT_PENDING 2801
#define W32_WSARECVMSG_UDP 2809
#define W32_WSARECV_TCP 2802
#define W32_WSARECV_TCP_PENDING 2803
#define W32_WSARECVEX_INET_ACCEPT 2805
#define W32_WSARECVFROM_UDP 2807
#define W32_WSARESETEVENT 2810
#define W32_WSASEND_ACCEPT 2812
#define W32_WSASEND_ACCEPT_PENDING 2813
#define W32_WSASEND_TCP 2814
#define W32_WSASEND_TCP_PENDING 2815
#define W32_WSASENDTO_UDP 2817
#define W32_WSASTARTUP 2820
#define W32_ACCEPT_INET_TCP 2883
#define W32_BIND_CONNECTEX_TCP 2890
#define W32_BIND_INET_TCP 2891
#define W32_BIND_INET_UDP 2892
#define W32_CLOSESOCKET_ACCEPT_PENDING 2894
#define W32_CLOSESOCKET_ACCEPT_RECV_PENDING 2895
#define W32_CLOSESOCKET_ACCEPT_SEND_PENDING 2896
#define W32_CLOSESOCKET_ANY 2897
#define W32_CLOSESOCKET_CONNECT_PENDING 2898
#define W32_CLOSESOCKET_TCP_RECV_PENDING 2899
#define W32_CLOSESOCKET_TCP_SEND_PENDING 2900
#define W32_CLOSESOCKET_TCP_SHUTDOWN_RD 2901
#define W32_CLOSESOCKET_TCP_SHUTDOWN_WR 2902
#define W32_CONNECT_INET_TCP 2904
#define W32_CONNECT_INET_UDP 2905
#define W32_GETPEERNAME_ACCEPT 2910
#define W32_GETPEERNAME_TCP 2911
#define W32_GETPEERNAME_UDP 2912
#define W32_GETSOCKNAME_ACCEPT 2918
#define W32_GETSOCKNAME_TCP 2919
#define W32_GETSOCKNAME_UDP 2920
#define W32_GETSOCKOPT_INT_ACCEPT 2922
#define W32_GETSOCKOPT_INT_ACCEPT_UPDATED 2923
#define W32_GETSOCKOPT_INT_TCP 2924
#define W32_GETSOCKOPT_INT_UDP 2925
#define W32_IOCTLSOCKET_FIONBIO_ACCEPT 2931
#define W32_IOCTLSOCKET_FIONBIO_TCP 2932
#define W32_IOCTLSOCKET_FIONBIO_UDP 2933
#define W32_LISTEN_INET_TCP 2945
#define W32_RECV_INET_ACCEPT 3037
#define W32_RECV_INET_ACCEPT_UPDATED 3038
#define W32_RECV_INET_TCP 3039
#define W32_RECV_INET_UDP 3040
#define W32_RECVFROM_UDP_BOUND 3042
#define W32_RECVFROM_UDP_CONNECTED 3043
#define W32_SELECT_AFD_BASIC 3045
#define W32_SEND_INET_ACCEPT 3047
#define W32_SEND_INET_ACCEPT_UPDATED 3048
#define W32_SEND_INET_TCP 3049
#define W32_SEND_INET_UDP 3050
#define W32_SENDTO_UDP_BOUND 3052
#define W32_SENDTO_UDP_CONNECTED 3053
#define W32_SETSOCKOPT_INT_ACCEPT 3055
#define W32_SETSOCKOPT_INT_ACCEPT_UPDATED 3056
#define W32_SETSOCKOPT_UPDATE_ACCEPT_CONTEXT 3059
#define W32_SETSOCKOPT_INT_TCP 3057
#define W32_SETSOCKOPT_INT_UDP 3058
#define W32_SHUTDOWN_ACCEPT 3060
#define W32_SHUTDOWN_ACCEPT_RD 3061
#define W32_SHUTDOWN_ACCEPT_WR 3062
#define W32_SHUTDOWN_TCP 3063
#define W32_SHUTDOWN_TCP_RD 3064
#define W32_SHUTDOWN_TCP_WR 3065
#define W32_SOCKET_ACCEPT_TCP 3068
#define W32_SOCKET_BOUND_UDP 3069
#define W32_SOCKET_CONNECTED_TCP 3070
#define W32_SOCKET_CONNECTED_UDP 3071
#define W32_SOCKET_INET_TCP 3072
#define W32_SOCKET_INET_UDP 3073
#define W32_SOCKET_LISTENER_TCP 3074

#include "windows_service_26200.h"

static call_t syscalls[4096];

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
	syscalls[W32_CANCELIO_SOCKET] = call_t{"CancelIo$socket", 0, {}, (syscall_t)windows_cancel_io};
	syscalls[W32_CANCELIOEX_SOCKET] = call_t{"CancelIoEx$socket", 0, {}, (syscall_t)windows_cancel_io_ex};
	syscalls[W32_CLOSEHANDLE] = call_t{"CloseHandle", 0, {}, (syscall_t)CloseHandle};
	syscalls[W32_CREATEFILEA] = call_t{"CreateFileA", 0, {}, (syscall_t)CreateFileA};
	syscalls[W32_CREATEFILE2] = call_t{"CreateFile2", 0, {}, (syscall_t)CreateFile2};
	syscalls[W32_CREATEIOCOMPLETIONPORT_SOCKET] = call_t{"CreateIoCompletionPort$socket", 0, {}, (syscall_t)windows_create_iocp_socket};
	syscalls[W32_DELETEFILEA] = call_t{"DeleteFileA", 0, {}, (syscall_t)DeleteFileA};
	syscalls[W32_FLUSHFILEBUFFERS] = call_t{"FlushFileBuffers", 0, {}, (syscall_t)FlushFileBuffers};
	syscalls[W32_GETQUEUEDCOMPLETIONSTATUS_SOCKET] = call_t{"GetQueuedCompletionStatus$socket", 0, {}, (syscall_t)windows_get_queued_completion_status};
	syscalls[W32_CANCELIO_ACCEPT_PENDING] = call_t{"CancelIo$accept_pending", 0, {}, (syscall_t)windows_cancel_io};
	syscalls[W32_CANCELIO_ACCEPT_RECV_PENDING] = call_t{"CancelIo$accept_recv_pending", 0, {}, (syscall_t)windows_cancel_io};
	syscalls[W32_CANCELIO_ACCEPT_SEND_PENDING] = call_t{"CancelIo$accept_send_pending", 0, {}, (syscall_t)windows_cancel_io};
	syscalls[W32_CANCELIO_CONNECT_PENDING] = call_t{"CancelIo$connect_pending", 0, {}, (syscall_t)windows_cancel_io};
	syscalls[W32_CANCELIO_TCP_RECV_PENDING] = call_t{"CancelIo$tcp_recv_pending", 0, {}, (syscall_t)windows_cancel_io};
	syscalls[W32_CANCELIO_TCP_SEND_PENDING] = call_t{"CancelIo$tcp_send_pending", 0, {}, (syscall_t)windows_cancel_io};
	syscalls[W32_CANCELIOEX_ACCEPT_PENDING] = call_t{"CancelIoEx$accept_pending", 0, {}, (syscall_t)windows_cancel_io_ex};
	syscalls[W32_CANCELIOEX_ACCEPT_RECV_PENDING] = call_t{"CancelIoEx$accept_recv_pending", 0, {}, (syscall_t)windows_cancel_io_ex};
	syscalls[W32_CANCELIOEX_ACCEPT_SEND_PENDING] = call_t{"CancelIoEx$accept_send_pending", 0, {}, (syscall_t)windows_cancel_io_ex};
	syscalls[W32_CANCELIOEX_CONNECT_PENDING] = call_t{"CancelIoEx$connect_pending", 0, {}, (syscall_t)windows_cancel_io_ex};
	syscalls[W32_CANCELIOEX_TCP_RECV_PENDING] = call_t{"CancelIoEx$tcp_recv_pending", 0, {}, (syscall_t)windows_cancel_io_ex};
	syscalls[W32_CANCELIOEX_TCP_SEND_PENDING] = call_t{"CancelIoEx$tcp_send_pending", 0, {}, (syscall_t)windows_cancel_io_ex};
	syscalls[W32_CREATEIOCOMPLETIONPORT_ACCEPT_PENDING] = call_t{"CreateIoCompletionPort$accept_pending", 0, {}, (syscall_t)windows_create_iocp_socket};
	syscalls[W32_CREATEIOCOMPLETIONPORT_ACCEPT_RECV_PENDING] = call_t{"CreateIoCompletionPort$accept_recv_pending", 0, {}, (syscall_t)windows_create_iocp_socket};
	syscalls[W32_CREATEIOCOMPLETIONPORT_ACCEPT_SEND_PENDING] = call_t{"CreateIoCompletionPort$accept_send_pending", 0, {}, (syscall_t)windows_create_iocp_socket};
	syscalls[W32_CREATEIOCOMPLETIONPORT_CONNECT_PENDING] = call_t{"CreateIoCompletionPort$connect_pending", 0, {}, (syscall_t)windows_create_iocp_socket};
	syscalls[W32_CREATEIOCOMPLETIONPORT_TCP_RECV_PENDING] = call_t{"CreateIoCompletionPort$tcp_recv_pending", 0, {}, (syscall_t)windows_create_iocp_socket};
	syscalls[W32_CREATEIOCOMPLETIONPORT_TCP_SEND_PENDING] = call_t{"CreateIoCompletionPort$tcp_send_pending", 0, {}, (syscall_t)windows_create_iocp_socket};
	syscalls[W32_READFILE] = call_t{"ReadFile", 0, {}, (syscall_t)ReadFile};
	syscalls[W32_SETFILEINFOBYHANDLE] = call_t{"SetFileInformationByHandle", 0, {}, (syscall_t)SetFileInformationByHandle};
	syscalls[W32_WRITEFILE] = call_t{"WriteFile", 0, {}, (syscall_t)WriteFile};
	syscalls[W32_ACCEPTEX_INET_TCP] = call_t{"AcceptEx$inet_tcp", 0, {}, (syscall_t)AcceptEx};
	syscalls[W32_ACCEPTEX_INET_TCP_PENDING] = call_t{"AcceptEx$inet_tcp_pending", 0, {}, (syscall_t)windows_accept_ex_state};
	syscalls[W32_CONNECTEX_INET_TCP] = call_t{"ConnectEx$inet_tcp", 0, {}, (syscall_t)ConnectEx};
	syscalls[W32_CONNECTEX_INET_TCP_PENDING] = call_t{"ConnectEx$inet_tcp_pending", 0, {}, (syscall_t)windows_connect_ex_state};
	syscalls[W32_CONNECTEX_INET_TCP_REUSE] = call_t{"ConnectEx$inet_tcp_reuse", 0, {}, (syscall_t)windows_connect_ex_state};
	syscalls[W32_DISCONNECTEX_INET_TCP] = call_t{"DisconnectEx$inet_tcp", 0, {}, (syscall_t)DisconnectEx};
	syscalls[W32_DISCONNECTEX_INET_TCP_REUSE] = call_t{"DisconnectEx$inet_tcp_reuse", 0, {}, (syscall_t)windows_disconnect_ex_state};
	syscalls[W32_GETACCEPTEXSOCKADDRS_INET_TCP] = call_t{"GetAcceptExSockaddrs$inet_tcp", 0, {}, (syscall_t)GetAcceptExSockaddrs};
	syscalls[W32_TRANSMITFILE_INET_ACCEPT] = call_t{"TransmitFile$inet_accept", 0, {}, (syscall_t)TransmitFile};
	syscalls[W32_TRANSMITPACKETS_INET_ACCEPT] = call_t{"TransmitPackets$inet_accept", 0, {}, (syscall_t)TransmitPackets};
	syscalls[W32_WSACLEANUP] = call_t{"WSACleanup", 0, {}, (syscall_t)WSACleanup};
	syscalls[W32_WSACLOSEEVENT] = call_t{"WSACloseEvent", 0, {}, (syscall_t)WSACloseEvent};
	syscalls[W32_WSACREATEEVENT] = call_t{"WSACreateEvent", 0, {}, (syscall_t)WSACreateEvent};
	syscalls[W32_WSAENUMNETWORKEVENTS_ACCEPT] = call_t{"WSAEnumNetworkEvents$accept", 0, {}, (syscall_t)WSAEnumNetworkEvents};
	syscalls[W32_WSAENUMNETWORKEVENTS_TCP] = call_t{"WSAEnumNetworkEvents$tcp", 0, {}, (syscall_t)WSAEnumNetworkEvents};
	syscalls[W32_WSAEVENTSELECT_ACCEPT] = call_t{"WSAEventSelect$accept", 0, {}, (syscall_t)WSAEventSelect};
	syscalls[W32_WSAEVENTSELECT_TCP] = call_t{"WSAEventSelect$tcp", 0, {}, (syscall_t)WSAEventSelect};
	syscalls[W32_WSAGETOVERLAPPEDRESULT_SOCKET] = call_t{"WSAGetOverlappedResult$socket", 0, {}, (syscall_t)WSAGetOverlappedResult};
	syscalls[W32_WSAGETOVERLAPPEDRESULT_ACCEPT_PENDING] = call_t{"WSAGetOverlappedResult$accept_pending", 0, {}, (syscall_t)WSAGetOverlappedResult};
	syscalls[W32_WSAGETOVERLAPPEDRESULT_ACCEPT_RECV_PENDING] = call_t{"WSAGetOverlappedResult$accept_recv_pending", 0, {}, (syscall_t)WSAGetOverlappedResult};
	syscalls[W32_WSAGETOVERLAPPEDRESULT_ACCEPT_SEND_PENDING] = call_t{"WSAGetOverlappedResult$accept_send_pending", 0, {}, (syscall_t)WSAGetOverlappedResult};
	syscalls[W32_WSAGETOVERLAPPEDRESULT_CONNECT_PENDING] = call_t{"WSAGetOverlappedResult$connect_pending", 0, {}, (syscall_t)WSAGetOverlappedResult};
	syscalls[W32_WSAGETOVERLAPPEDRESULT_TCP_RECV_PENDING] = call_t{"WSAGetOverlappedResult$tcp_recv_pending", 0, {}, (syscall_t)WSAGetOverlappedResult};
	syscalls[W32_WSAGETOVERLAPPEDRESULT_TCP_SEND_PENDING] = call_t{"WSAGetOverlappedResult$tcp_send_pending", 0, {}, (syscall_t)WSAGetOverlappedResult};
	syscalls[W32_WSAIOCTL_SIO_ADDRESS_LIST_QUERY] = call_t{"WSAIoctl$sio_address_list_query", 0, {}, (syscall_t)WSAIoctl};
	syscalls[W32_WSAIOCTL_SIO_GET_EXTENSION_FUNCTION_POINTER] = call_t{"WSAIoctl$sio_get_extension_function_pointer", 0, {}, (syscall_t)WSAIoctl};
	syscalls[W32_WSAIOCTL_SIO_KEEPALIVE_VALS] = call_t{"WSAIoctl$sio_keepalive_vals", 0, {}, (syscall_t)WSAIoctl};
	syscalls[W32_WSAIOCTL_SIO_ROUTING_INTERFACE_QUERY] = call_t{"WSAIoctl$sio_routing_interface_query", 0, {}, (syscall_t)WSAIoctl};
	syscalls[W32_WSARECV_ACCEPT] = call_t{"WSARecv$accept", 0, {}, (syscall_t)WSARecv};
	syscalls[W32_WSARECV_ACCEPT_PENDING] = call_t{"WSARecv$accept_pending", 0, {}, (syscall_t)windows_wsa_recv_state};
	syscalls[W32_WSARECVMSG_UDP] = call_t{"WSARecvMsg$udp", 0, {}, (syscall_t)WSARecvMsg};
	syscalls[W32_WSARECV_TCP] = call_t{"WSARecv$tcp", 0, {}, (syscall_t)WSARecv};
	syscalls[W32_WSARECV_TCP_PENDING] = call_t{"WSARecv$tcp_pending", 0, {}, (syscall_t)windows_wsa_recv_state};
	syscalls[W32_WSARECVEX_INET_ACCEPT] = call_t{"WSARecvEx$inet_accept", 0, {}, (syscall_t)WSARecvEx};
	syscalls[W32_WSARECVFROM_UDP] = call_t{"WSARecvFrom$udp", 0, {}, (syscall_t)WSARecvFrom};
	syscalls[W32_WSARESETEVENT] = call_t{"WSAResetEvent", 0, {}, (syscall_t)WSAResetEvent};
	syscalls[W32_WSASEND_ACCEPT] = call_t{"WSASend$accept", 0, {}, (syscall_t)WSASend};
	syscalls[W32_WSASEND_ACCEPT_PENDING] = call_t{"WSASend$accept_pending", 0, {}, (syscall_t)windows_wsa_send_state};
	syscalls[W32_WSASEND_TCP] = call_t{"WSASend$tcp", 0, {}, (syscall_t)WSASend};
	syscalls[W32_WSASEND_TCP_PENDING] = call_t{"WSASend$tcp_pending", 0, {}, (syscall_t)windows_wsa_send_state};
	syscalls[W32_WSASENDTO_UDP] = call_t{"WSASendTo$udp", 0, {}, (syscall_t)WSASendTo};
	syscalls[W32_WSASTARTUP] = call_t{"WSAStartup", 0, {}, (syscall_t)WSAStartup};
	syscalls[W32_ACCEPT_INET_TCP] = call_t{"accept$inet_tcp", 0, {}, (syscall_t)accept};
	syscalls[W32_BIND_CONNECTEX_TCP] = call_t{"bind$connectex_tcp", 0, {}, (syscall_t)bind};
	syscalls[W32_BIND_INET_TCP] = call_t{"bind$inet_tcp", 0, {}, (syscall_t)windows_bind_state};
	syscalls[W32_BIND_INET_UDP] = call_t{"bind$inet_udp", 0, {}, (syscall_t)windows_bind_state};
	syscalls[W32_CLOSESOCKET_ACCEPT_PENDING] = call_t{"closesocket$accept_pending", 0, {}, (syscall_t)closesocket};
	syscalls[W32_CLOSESOCKET_ACCEPT_RECV_PENDING] = call_t{"closesocket$accept_recv_pending", 0, {}, (syscall_t)closesocket};
	syscalls[W32_CLOSESOCKET_ACCEPT_SEND_PENDING] = call_t{"closesocket$accept_send_pending", 0, {}, (syscall_t)closesocket};
	syscalls[W32_CLOSESOCKET_ANY] = call_t{"closesocket$any", 0, {}, (syscall_t)closesocket};
	syscalls[W32_CLOSESOCKET_CONNECT_PENDING] = call_t{"closesocket$connect_pending", 0, {}, (syscall_t)closesocket};
	syscalls[W32_CLOSESOCKET_TCP_RECV_PENDING] = call_t{"closesocket$tcp_recv_pending", 0, {}, (syscall_t)closesocket};
	syscalls[W32_CLOSESOCKET_TCP_SEND_PENDING] = call_t{"closesocket$tcp_send_pending", 0, {}, (syscall_t)closesocket};
	syscalls[W32_CLOSESOCKET_TCP_SHUTDOWN_RD] = call_t{"closesocket$tcp_shutdown_rd", 0, {}, (syscall_t)closesocket};
	syscalls[W32_CLOSESOCKET_TCP_SHUTDOWN_WR] = call_t{"closesocket$tcp_shutdown_wr", 0, {}, (syscall_t)closesocket};
	syscalls[W32_CONNECT_INET_TCP] = call_t{"connect$inet_tcp", 0, {}, (syscall_t)windows_connect_state};
	syscalls[W32_CONNECT_INET_UDP] = call_t{"connect$inet_udp", 0, {}, (syscall_t)windows_connect_state};
	syscalls[W32_GETPEERNAME_ACCEPT] = call_t{"getpeername$accept", 0, {}, (syscall_t)getpeername};
	syscalls[W32_GETPEERNAME_TCP] = call_t{"getpeername$tcp", 0, {}, (syscall_t)getpeername};
	syscalls[W32_GETPEERNAME_UDP] = call_t{"getpeername$udp", 0, {}, (syscall_t)getpeername};
	syscalls[W32_GETSOCKNAME_ACCEPT] = call_t{"getsockname$accept", 0, {}, (syscall_t)getsockname};
	syscalls[W32_GETSOCKNAME_TCP] = call_t{"getsockname$tcp", 0, {}, (syscall_t)getsockname};
	syscalls[W32_GETSOCKNAME_UDP] = call_t{"getsockname$udp", 0, {}, (syscall_t)getsockname};
	syscalls[W32_GETSOCKOPT_INT_ACCEPT] = call_t{"getsockopt$int_accept", 0, {}, (syscall_t)getsockopt};
	syscalls[W32_GETSOCKOPT_INT_ACCEPT_UPDATED] = call_t{"getsockopt$int_accept_updated", 0, {}, (syscall_t)getsockopt};
	syscalls[W32_GETSOCKOPT_INT_TCP] = call_t{"getsockopt$int_tcp", 0, {}, (syscall_t)getsockopt};
	syscalls[W32_GETSOCKOPT_INT_UDP] = call_t{"getsockopt$int_udp", 0, {}, (syscall_t)getsockopt};
	syscalls[W32_IOCTLSOCKET_FIONBIO_ACCEPT] = call_t{"ioctlsocket$fionbio_accept", 0, {}, (syscall_t)ioctlsocket};
	syscalls[W32_IOCTLSOCKET_FIONBIO_TCP] = call_t{"ioctlsocket$fionbio_tcp", 0, {}, (syscall_t)ioctlsocket};
	syscalls[W32_IOCTLSOCKET_FIONBIO_UDP] = call_t{"ioctlsocket$fionbio_udp", 0, {}, (syscall_t)ioctlsocket};
	syscalls[W32_LISTEN_INET_TCP] = call_t{"listen$inet_tcp", 0, {}, (syscall_t)windows_listen_state};
	syscalls[W32_RECV_INET_ACCEPT] = call_t{"recv$inet_accept", 0, {}, (syscall_t)recv};
	syscalls[W32_RECV_INET_ACCEPT_UPDATED] = call_t{"recv$inet_accept_updated", 0, {}, (syscall_t)recv};
	syscalls[W32_RECV_INET_TCP] = call_t{"recv$inet_tcp", 0, {}, (syscall_t)recv};
	syscalls[W32_RECV_INET_UDP] = call_t{"recv$inet_udp", 0, {}, (syscall_t)recv};
	syscalls[W32_RECVFROM_UDP_BOUND] = call_t{"recvfrom$udp_bound", 0, {}, (syscall_t)recvfrom};
	syscalls[W32_RECVFROM_UDP_CONNECTED] = call_t{"recvfrom$udp_connected", 0, {}, (syscall_t)recvfrom};
	syscalls[W32_SELECT_AFD_BASIC] = call_t{"select$afd_basic", 0, {}, (syscall_t)select};
	syscalls[W32_SEND_INET_ACCEPT] = call_t{"send$inet_accept", 0, {}, (syscall_t)send};
	syscalls[W32_SEND_INET_ACCEPT_UPDATED] = call_t{"send$inet_accept_updated", 0, {}, (syscall_t)send};
	syscalls[W32_SEND_INET_TCP] = call_t{"send$inet_tcp", 0, {}, (syscall_t)send};
	syscalls[W32_SEND_INET_UDP] = call_t{"send$inet_udp", 0, {}, (syscall_t)send};
	syscalls[W32_SENDTO_UDP_BOUND] = call_t{"sendto$udp_bound", 0, {}, (syscall_t)sendto};
	syscalls[W32_SENDTO_UDP_CONNECTED] = call_t{"sendto$udp_connected", 0, {}, (syscall_t)sendto};
	syscalls[W32_SETSOCKOPT_INT_ACCEPT] = call_t{"setsockopt$int_accept", 0, {}, (syscall_t)setsockopt};
	syscalls[W32_SETSOCKOPT_INT_ACCEPT_UPDATED] = call_t{"setsockopt$int_accept_updated", 0, {}, (syscall_t)setsockopt};
	syscalls[W32_SETSOCKOPT_UPDATE_ACCEPT_CONTEXT] = call_t{"setsockopt$update_accept_context", 0, {}, (syscall_t)windows_update_accept_context_state};
	syscalls[W32_SETSOCKOPT_INT_TCP] = call_t{"setsockopt$int_tcp", 0, {}, (syscall_t)setsockopt};
	syscalls[W32_SETSOCKOPT_INT_UDP] = call_t{"setsockopt$int_udp", 0, {}, (syscall_t)setsockopt};
	syscalls[W32_SHUTDOWN_ACCEPT] = call_t{"shutdown$accept", 0, {}, (syscall_t)shutdown};
	syscalls[W32_SHUTDOWN_ACCEPT_RD] = call_t{"shutdown$accept_rd", 0, {}, (syscall_t)windows_shutdown_state};
	syscalls[W32_SHUTDOWN_ACCEPT_WR] = call_t{"shutdown$accept_wr", 0, {}, (syscall_t)windows_shutdown_state};
	syscalls[W32_SHUTDOWN_TCP] = call_t{"shutdown$tcp", 0, {}, (syscall_t)shutdown};
	syscalls[W32_SHUTDOWN_TCP_RD] = call_t{"shutdown$tcp_rd", 0, {}, (syscall_t)windows_shutdown_state};
	syscalls[W32_SHUTDOWN_TCP_WR] = call_t{"shutdown$tcp_wr", 0, {}, (syscall_t)windows_shutdown_state};
	syscalls[W32_SOCKET_ACCEPT_TCP] = call_t{"socket$accept_tcp", 0, {}, (syscall_t)socket};
	syscalls[W32_SOCKET_BOUND_UDP] = call_t{"socket$bound_udp", 0, {}, (syscall_t)socket};
	syscalls[W32_SOCKET_CONNECTED_TCP] = call_t{"socket$connected_tcp", 0, {}, (syscall_t)socket};
	syscalls[W32_SOCKET_CONNECTED_UDP] = call_t{"socket$connected_udp", 0, {}, (syscall_t)socket};
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

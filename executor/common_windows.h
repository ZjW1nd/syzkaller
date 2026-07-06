// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <direct.h> // for _chdir
#include <io.h> // for mktemp
#if SYZ_NET_INJECTION
#include <winsock2.h>
#endif
#include <windows.h>
#if SYZ_NET_INJECTION
#include <iphlpapi.h>
#include <iptypes.h>
#include <netfw.h>
#include <netioapi.h>
#include <objbase.h>
#include <oleauto.h>
#include <winioctl.h>
#include <ws2tcpip.h>
#endif

#ifndef SYZ_WINDOWS_NET_INJECTION_NETIO2
#define SYZ_WINDOWS_NET_INJECTION_NETIO2 0
#endif

#if SYZ_EXECUTOR || SYZ_HANDLE_SEGV
static void install_segv_handler()
{
}

#if defined(__GNUC__)
#define NONFAILING(...) \
	([&]() { __VA_ARGS__; return true; }())
#else
#define NONFAILING(...) \
	([&]() { __try { __VA_ARGS__; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; } return true; }())
#endif
#endif

#if SYZ_EXECUTOR || SYZ_THREADED || SYZ_REPEAT && SYZ_EXECUTOR_USES_FORK_SERVER
static uint64 current_time_ms()
{
	return GetTickCount64();
}
#endif

#if SYZ_EXECUTOR || SYZ_THREADED || SYZ_REPEAT && SYZ_EXECUTOR_USES_FORK_SERVER
static void sleep_ms(uint64 ms)
{
	Sleep(ms);
}
#endif

#if SYZ_EXECUTOR || SYZ_THREADED
static void thread_start(void* (*fn)(void*), void* arg)
{
	HANDLE th = CreateThread(NULL, 128 << 10, (LPTHREAD_START_ROUTINE)fn, arg, 0, NULL);
	if (th == NULL)
		exitf("CreateThread failed");
}

struct event_t {
	HANDLE handle;
};

static void event_init(event_t* ev)
{
	ev->handle = CreateEventA(NULL, TRUE, FALSE, NULL);
	if (ev->handle == NULL)
		exitf("CreateEvent failed");
}

static void event_reset(event_t* ev)
{
	if (!ResetEvent(ev->handle))
		exitf("ResetEvent failed");
}

static void event_set(event_t* ev)
{
	DWORD state = WaitForSingleObject(ev->handle, 0);
	if (state == WAIT_OBJECT_0)
		exitf("event already set");
	if (state == WAIT_FAILED)
		exitf("WaitForSingleObject failed");
	if (!SetEvent(ev->handle))
		exitf("SetEvent failed");
}

static void event_wait(event_t* ev)
{
	DWORD state = WaitForSingleObject(ev->handle, INFINITE);
	if (state != WAIT_OBJECT_0)
		exitf("WaitForSingleObject failed");
}

static int event_isset(event_t* ev)
{
	DWORD state = WaitForSingleObject(ev->handle, 0);
	if (state == WAIT_FAILED)
		exitf("WaitForSingleObject failed");
	return state == WAIT_OBJECT_0;
}

static int event_timedwait(event_t* ev, uint64 timeout_ms)
{
	DWORD timeout = timeout_ms >= INFINITE ? INFINITE - 1 : (DWORD)timeout_ms;
	DWORD state = WaitForSingleObject(ev->handle, timeout);
	if (state == WAIT_FAILED)
		exitf("WaitForSingleObject failed");
	return state == WAIT_OBJECT_0;
}

static HANDLE event_handle(event_t* ev)
{
	return ev->handle;
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
static void loop();
#if SYZ_NET_INJECTION
static void initialize_windows_net_injection();
#endif
static int do_sandbox_none(void)
{
#if SYZ_NET_INJECTION
	initialize_windows_net_injection();
#endif
	loop();
	return 0;
}
#endif

static void use_temporary_dir(void)
{
	char tmpdir_template[] = "./syzkaller.XXXXXX";
	char* tmpdir = mktemp(tmpdir_template);

	CreateDirectory(tmpdir, NULL);
	_chdir(tmpdir);
}

#if SYZ_NYX_WINDOWS_SPARSE_TABLE
static void nyx_hprintf(const char* fmt, ...);
#define windows_diag_log(...) nyx_hprintf(__VA_ARGS__)
#else
#define windows_diag_log(...) (void)0
#endif

#if SYZ_EXECUTOR || __NR_syz_kafl_bugcheck_trigger
static intptr_t SYSCALLAPI syz_kafl_bugcheck_trigger(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,
						     intptr_t, intptr_t, intptr_t, intptr_t, intptr_t)
{
	// Diagnostic-only pseudo syscall. It starts a preinstalled kernel driver
	// whose DriverEntry calls KeBugCheckEx, so Nyx can validate bugcheck dump
	// collection inside the fuzzing loop.
	SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (scm == nullptr) {
		windows_diag_log("syz_kafl_bugcheck_trigger OpenSCManagerA failed err=%lu\n",
				 (unsigned long)GetLastError());
		return -1;
	}
	SC_HANDLE service = OpenServiceA(scm, "KaflBugcheckTrigger", SERVICE_START);
	if (service == nullptr) {
		windows_diag_log("syz_kafl_bugcheck_trigger OpenServiceA failed err=%lu\n",
				 (unsigned long)GetLastError());
		CloseServiceHandle(scm);
		return -1;
	}
	windows_diag_log("syz_kafl_bugcheck_trigger starting service\n");
	BOOL ok = StartServiceA(service, 0, nullptr);
	DWORD err = ok ? ERROR_SUCCESS : GetLastError();
	windows_diag_log("syz_kafl_bugcheck_trigger StartServiceA ok=%u err=%lu\n",
			 (unsigned)ok, (unsigned long)err);
	CloseServiceHandle(service);
	CloseServiceHandle(scm);
	return ok ? 0 : -(intptr_t)err;
}
#endif

#if SYZ_NET_INJECTION && (SYZ_EXECUTOR || __NR_syz_emit_ethernet || __NR_syz_extract_tcp_res || SYZ_REPEAT)
static HANDLE windows_net_injection = INVALID_HANDLE_VALUE;
static char windows_net_injection_write_buffer[4096];
static volatile LONG windows_net_injection_background_reader_enabled;
static volatile LONG windows_net_injection_cached_tcp_valid;
static volatile LONG windows_net_injection_cached_tcp_seq;
static volatile LONG windows_net_injection_cached_tcp_ack;
static volatile LONG windows_net_injection_refresh_unicast_enabled;
static volatile LONG windows_net_injection_static_neighbor_enabled;
static DWORD windows_net_injection_target_ifindex_cache;
static char windows_net_injection_target_adapter_name[64];

#define SYZ_WINDOWS_NET_INJECTION_DEVICE_ENV "SYZ_WINDOWS_NET_INJECTION_DEVICE"
#define SYZ_WINDOWS_NET_INJECTION_BACKGROUND_READER_ENV "SYZ_WINDOWS_NET_INJECTION_BACKGROUND_READER"
#define SYZ_WINDOWS_NET_INJECTION_REFRESH_UNICAST_ENV "SYZ_WINDOWS_NET_INJECTION_REFRESH_UNICAST"
#define SYZ_WINDOWS_NET_INJECTION_STATIC_NEIGHBOR_ENV "SYZ_WINDOWS_NET_INJECTION_STATIC_NEIGHBOR"
#define SYZ_WINDOWS_NET_INJECTION_FIREWALL_ALLOW_ENV "SYZ_WINDOWS_NET_INJECTION_FIREWALL_ALLOW"
#define SYZ_WINDOWS_NET_INJECTION_SKIP_INIT_IPV4_ENV "SYZ_WINDOWS_NET_INJECTION_SKIP_INIT_IPV4"
#define SYZ_WINDOWS_NET_INJECTION_SKIP_FIREWALL_ENV "SYZ_WINDOWS_NET_INJECTION_SKIP_FIREWALL"
#define SYZ_WINDOWS_NET_INJECTION_PRE_SNAPSHOT_SETTLE_MS_ENV "SYZ_WINDOWS_NET_INJECTION_PRE_SNAPSHOT_SETTLE_MS"
#define SYZ_WINDOWS_NET_INJECTION_POST_WRITE_SETTLE_MS_ENV "SYZ_WINDOWS_NET_INJECTION_POST_WRITE_SETTLE_MS"
#define SYZ_WINDOWS_NET_INJECTION_READ_ATTEMPTS_ENV "SYZ_WINDOWS_NET_INJECTION_READ_ATTEMPTS"
#define SYZ_WINDOWS_NET_INJECTION_IO_TIMEOUT_MS 5
#define SYZ_WINDOWS_NET_INJECTION_READ_POLL_MS 0
#define SYZ_WINDOWS_NET_INJECTION_BACKGROUND_READ_POLL_MS 50
#define SYZ_WINDOWS_NET_INJECTION_READ_ATTEMPTS 64
#define SYZ_WINDOWS_NET_INJECTION_MAX_READ_ATTEMPTS 256
#define SYZ_WINDOWS_NET_INJECTION_READ_TIMEOUT -2
#define SYZ_WINDOWS_NET_INJECTION_MAX_FRAME_SIZE 4096
#define SYZ_WINDOWS_NET_INJECTION_ETH_P_IP 0x0800
#define SYZ_WINDOWS_NET_INJECTION_IPPROTO_TCP 6
#define SYZ_WINDOWS_NET_INJECTION_LOCAL_IPV4 0xac1400aa
#define SYZ_WINDOWS_NET_INJECTION_PEER_IPV4 0xac1400bb
#define SYZ_WINDOWS_NET_INJECTION_LOCAL_IPV4_MASK 0xffffff00
#define SYZ_WINDOWS_NET_INJECTION_LOCAL_TCP_PORT 20000
#define SYZ_WINDOWS_NET_INJECTION_LOCAL_TCP_PORT_MAX 20004
#define SYZ_WINDOWS_NET_INJECTION_PEER_TCP_PORT 40000
#define SYZ_WINDOWS_NET_INJECTION_PEER_TCP_PORT_MAX 40063
#define SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_SYN 0x02
#define SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_ACK 0x10
#define SYZ_WINDOWS_TAP_IOCTL_SET_MEDIA_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

static const UCHAR windows_net_injection_peer_mac[] = {0x02, 0xbb, 0xcc, 0xdd, 0xee, 0x02};

#if SYZ_NET_INJECTION && SYZ_NYX_WINDOWS_SPARSE_TABLE
#define windows_nyx_log(...) nyx_hprintf(__VA_ARGS__)
#else
#define windows_nyx_log(...) (void)0
#endif

static uint16 windows_net_load_be16(const char* data)
{
	return ((uint16)(uint8)data[0] << 8) | (uint8)data[1];
}

static uint32 windows_net_load_be32(const char* data)
{
	return ((uint32)(uint8)data[0] << 24) | ((uint32)(uint8)data[1] << 16) |
	       ((uint32)(uint8)data[2] << 8) | (uint8)data[3];
}

static uint16 windows_net_host_to_be16(uint16 v)
{
	return (uint16)(((v & 0x00ff) << 8) | ((v & 0xff00) >> 8));
}

static uint32 windows_net_host_to_be32(uint32 v)
{
	return ((v & 0x000000ff) << 24) | ((v & 0x0000ff00) << 8) |
	       ((v & 0x00ff0000) >> 8) | ((v & 0xff000000) >> 24);
}

static bool windows_net_injection_is_target_mac(const UCHAR* mac, ULONG length)
{
	static const UCHAR tap_mac[] = {0x00, 0xff, 0xa3, 0x87, 0x5e, 0x0b};
	return length == sizeof(tap_mac) && memcmp(mac, tap_mac, sizeof(tap_mac)) == 0;
}

static bool windows_net_injection_parse_device_adapter_name(const char* device_path, char* out, size_t out_size)
{
	if (out_size == 0)
		return false;
	out[0] = 0;
	const char* guid = strchr(device_path, '{');
	if (guid == NULL)
		return false;
	const char* end = strchr(guid, '}');
	if (end == NULL || end <= guid)
		return false;
	size_t len = (size_t)(end - guid + 1);
	if (len >= out_size)
		return false;
	memcpy(out, guid, len);
	out[len] = 0;
	return true;
}

static bool windows_net_injection_adapter_name_matches(const PIP_ADAPTER_ADDRESSES adapter)
{
	if (windows_net_injection_target_adapter_name[0] == 0)
		return false;
	return adapter->AdapterName != NULL &&
	       _stricmp(adapter->AdapterName, windows_net_injection_target_adapter_name) == 0;
}

static DWORD windows_net_injection_target_ifindex()
{
	if (windows_net_injection_target_ifindex_cache != 0)
		return windows_net_injection_target_ifindex_cache;
	ULONG size = 15 * 1024;
	PIP_ADAPTER_ADDRESSES adapters = NULL;
	ULONG status = ERROR_BUFFER_OVERFLOW;
	for (int attempt = 0; attempt < 2 && status == ERROR_BUFFER_OVERFLOW; attempt++) {
		if (adapters != NULL)
			HeapFree(GetProcessHeap(), 0, adapters);
		adapters = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
		if (adapters == NULL) {
			windows_nyx_log("windows net injection target adapter alloc failed size=%lu\n",
					(unsigned long)size);
			return 0;
		}
		status = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, adapters, &size);
	}
	if (status != NO_ERROR) {
		windows_nyx_log("windows net injection target adapter get-adapters-addresses failed status=%lu size=%lu name=%s\n",
				(unsigned long)status, (unsigned long)size,
				windows_net_injection_target_adapter_name[0] ? windows_net_injection_target_adapter_name : "<unset>");
		if (adapters != NULL)
			HeapFree(GetProcessHeap(), 0, adapters);
		return 0;
	}
	for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter != NULL; adapter = adapter->Next) {
		if (!windows_net_injection_adapter_name_matches(adapter))
			continue;
		windows_net_injection_target_ifindex_cache = adapter->IfIndex;
		windows_nyx_log("windows net injection target adapter ifindex=%lu name=%s friendly=%ls\n",
				(unsigned long)adapter->IfIndex,
				adapter->AdapterName ? adapter->AdapterName : "<null>",
				adapter->FriendlyName ? adapter->FriendlyName : L"<null>");
		HeapFree(GetProcessHeap(), 0, adapters);
		return windows_net_injection_target_ifindex_cache;
	}
	windows_nyx_log("windows net injection target adapter not found name=%s\n",
			windows_net_injection_target_adapter_name[0] ? windows_net_injection_target_adapter_name : "<unset>");
	HeapFree(GetProcessHeap(), 0, adapters);
	return 0;
}

static bool windows_net_injection_local_ipv4_present()
{
	ULONG ip_table_size = 0;
	DWORD ip_status = GetIpAddrTable(NULL, &ip_table_size, TRUE);
	if (ip_status != ERROR_INSUFFICIENT_BUFFER)
		return false;
	PMIB_IPADDRTABLE ip_table = (PMIB_IPADDRTABLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ip_table_size);
	if (ip_table == NULL)
		return false;
	ip_status = GetIpAddrTable(ip_table, &ip_table_size, TRUE);
	bool found = false;
	if (ip_status == NO_ERROR) {
		uint32 local_addr = windows_net_host_to_be32(SYZ_WINDOWS_NET_INJECTION_LOCAL_IPV4);
		for (DWORD i = 0; i < ip_table->dwNumEntries; i++) {
			if (ip_table->table[i].dwAddr == local_addr) {
				found = true;
				break;
			}
		}
	}
	HeapFree(GetProcessHeap(), 0, ip_table);
	return found;
}

static void windows_net_injection_log_adapter_addresses(const char* label)
{
	ULONG size = 15 * 1024;
	PIP_ADAPTER_ADDRESSES adapters = NULL;
	ULONG status = ERROR_BUFFER_OVERFLOW;
	for (int attempt = 0; attempt < 2 && status == ERROR_BUFFER_OVERFLOW; attempt++) {
		if (adapters != NULL)
			HeapFree(GetProcessHeap(), 0, adapters);
		adapters = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
		if (adapters == NULL) {
			windows_nyx_log("windows net state %s adapter-addresses alloc failed size=%lu\n",
					label, (unsigned long)size);
			return;
		}
		status = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, adapters, &size);
	}
	if (status != NO_ERROR) {
		windows_nyx_log("windows net state %s get-adapters-addresses failed status=%lu size=%lu\n",
				label, (unsigned long)status, (unsigned long)size);
		if (adapters != NULL)
			HeapFree(GetProcessHeap(), 0, adapters);
		return;
	}
	bool found = false;
	for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter != NULL; adapter = adapter->Next) {
		if (!windows_net_injection_is_target_mac(adapter->PhysicalAddress,
							 adapter->PhysicalAddressLength))
			continue;
		found = true;
		windows_nyx_log("windows net state %s adapter ifindex=%lu luid=0x%llx luid_index=%llu iftype=%llu oper=%lu name=%s friendly=%ls\n",
				label, (unsigned long)adapter->IfIndex,
				(unsigned long long)adapter->Luid.Value,
				(unsigned long long)adapter->Luid.Info.NetLuidIndex,
				(unsigned long long)adapter->Luid.Info.IfType,
				(unsigned long)adapter->OperStatus,
				adapter->AdapterName ? adapter->AdapterName : "<null>",
				adapter->FriendlyName ? adapter->FriendlyName : L"<null>");
		for (PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress;
		     unicast != NULL; unicast = unicast->Next) {
			if (unicast->Address.lpSockaddr == NULL ||
			    unicast->Address.lpSockaddr->sa_family != AF_INET)
				continue;
			const struct sockaddr_in* in =
			    (const struct sockaddr_in*)unicast->Address.lpSockaddr;
			uint32 addr = in->sin_addr.S_un.S_addr;
			unsigned a0 = (unsigned)(addr & 0xff);
			unsigned a1 = (unsigned)((addr >> 8) & 0xff);
			unsigned a2 = (unsigned)((addr >> 16) & 0xff);
			unsigned a3 = (unsigned)((addr >> 24) & 0xff);
			windows_nyx_log("windows net state %s adapter-unicast ifindex=%lu addr=%u.%u.%u.%u prefix=%u dad=%lu valid=%lu preferred=%lu\n",
					label, (unsigned long)adapter->IfIndex,
					a0, a1, a2, a3,
					(unsigned)unicast->OnLinkPrefixLength,
					(unsigned long)unicast->DadState,
					(unsigned long)unicast->ValidLifetime,
					(unsigned long)unicast->PreferredLifetime);
		}
	}
	if (!found)
		windows_nyx_log("windows net state %s adapter-addresses tap adapter not found by mac\n",
				label);
	HeapFree(GetProcessHeap(), 0, adapters);
}

#if SYZ_WINDOWS_NET_INJECTION_NETIO2
static void windows_net_injection_log_unicast_ipv4_entry(DWORD ifindex, const char* label)
{
	NET_LUID luid;
	memset(&luid, 0, sizeof(luid));
	NETIO_STATUS luid_status = ConvertInterfaceIndexToLuid((NET_IFINDEX)ifindex, &luid);
	if (!NETIO_SUCCESS(luid_status)) {
		windows_nyx_log("windows net state %s unicast-entry ifindex=%lu luid-status=%lu\n",
				label, (unsigned long)ifindex, (unsigned long)luid_status);
		return;
	}
	MIB_UNICASTIPADDRESS_ROW row;
	memset(&row, 0, sizeof(row));
	InitializeUnicastIpAddressEntry(&row);
	row.Address.si_family = AF_INET;
	row.Address.Ipv4.sin_family = AF_INET;
	row.Address.Ipv4.sin_addr.S_un.S_addr =
	    windows_net_host_to_be32(SYZ_WINDOWS_NET_INJECTION_LOCAL_IPV4);
	row.InterfaceLuid = luid;
	row.InterfaceIndex = (NET_IFINDEX)ifindex;
	NETIO_STATUS status = GetUnicastIpAddressEntry(&row);
	if (!NETIO_SUCCESS(status)) {
		windows_nyx_log("windows net state %s unicast-entry ifindex=%lu addr=172.20.0.170 status=%lu luid=0x%llx\n",
				label, (unsigned long)ifindex, (unsigned long)status,
				(unsigned long long)luid.Value);
		return;
	}
	windows_nyx_log("windows net state %s unicast-entry ifindex=%lu addr=172.20.0.170 prefix=%u dad=%lu origin=%lu/%lu skip=%u valid=%lu preferred=%lu luid=0x%llx luid_index=%llu iftype=%llu\n",
			label, (unsigned long)row.InterfaceIndex,
			(unsigned)row.OnLinkPrefixLength,
			(unsigned long)row.DadState,
			(unsigned long)row.PrefixOrigin,
			(unsigned long)row.SuffixOrigin,
			(unsigned)row.SkipAsSource,
			(unsigned long)row.ValidLifetime,
			(unsigned long)row.PreferredLifetime,
			(unsigned long long)row.InterfaceLuid.Value,
			(unsigned long long)row.InterfaceLuid.Info.NetLuidIndex,
			(unsigned long long)row.InterfaceLuid.Info.IfType);
}

static void windows_net_injection_format_mac(const UCHAR* mac, ULONG length, char* out, size_t out_size)
{
	if (out_size == 0)
		return;
	if (length == 0) {
		out[0] = 0;
		return;
	}
	size_t used = 0;
	for (ULONG i = 0; i < length && used + 4 < out_size; i++) {
		int n = _snprintf(out + used, out_size - used, "%s%02x",
				  i == 0 ? "" : "-", (unsigned)mac[i]);
		if (n < 0)
			break;
		used += (size_t)n;
	}
	out[out_size - 1] = 0;
}

static bool windows_net_injection_is_peer_neighbor(const MIB_IPNET_ROW2* row, DWORD ifindex)
{
	if (row->InterfaceIndex != (NET_IFINDEX)ifindex)
		return false;
	if (row->Address.si_family != AF_INET)
		return false;
	return row->Address.Ipv4.sin_addr.S_un.S_addr ==
	       windows_net_host_to_be32(SYZ_WINDOWS_NET_INJECTION_PEER_IPV4);
}

static void windows_net_injection_log_neighbor_ipv4_table_for_index(DWORD ifindex, const char* label)
{
	PMIB_IPNET_TABLE2 table = NULL;
	NETIO_STATUS status = GetIpNetTable2(AF_INET, &table);
	if (!NETIO_SUCCESS(status)) {
		windows_nyx_log("windows net state %s neighbor-table ifindex=%lu status=%lu\n",
				label, (unsigned long)ifindex, (unsigned long)status);
		return;
	}
	bool found = false;
	for (ULONG i = 0; i < table->NumEntries; i++) {
		MIB_IPNET_ROW2* row = &table->Table[i];
		if (!windows_net_injection_is_peer_neighbor(row, ifindex))
			continue;
		found = true;
		char mac[3 * IF_MAX_PHYS_ADDRESS_LENGTH + 1];
		windows_net_injection_format_mac(row->PhysicalAddress,
						 row->PhysicalAddressLength,
						 mac, sizeof(mac));
		uint32 addr = row->Address.Ipv4.sin_addr.S_un.S_addr;
		windows_nyx_log("windows net state %s neighbor ifindex=%lu addr=%u.%u.%u.%u mac=%s mac_len=%lu state=%lu router=%u unreachable=%u luid=0x%llx\n",
				label, (unsigned long)row->InterfaceIndex,
				(unsigned)(addr & 0xff),
				(unsigned)((addr >> 8) & 0xff),
				(unsigned)((addr >> 16) & 0xff),
				(unsigned)((addr >> 24) & 0xff),
				mac, (unsigned long)row->PhysicalAddressLength,
				(unsigned long)row->State,
				(unsigned)row->IsRouter,
				(unsigned)row->IsUnreachable,
				(unsigned long long)row->InterfaceLuid.Value);
	}
	if (!found)
		windows_nyx_log("windows net state %s neighbor ifindex=%lu addr=172.20.0.187 not found\n",
				label, (unsigned long)ifindex);
	FreeMibTable(table);
}

static void windows_net_injection_configure_static_neighbor(DWORD ifindex, const char* label)
{
	if (InterlockedCompareExchange(&windows_net_injection_static_neighbor_enabled, 0, 0) == 0)
		return;
	NET_LUID luid;
	memset(&luid, 0, sizeof(luid));
	NETIO_STATUS luid_status = ConvertInterfaceIndexToLuid((NET_IFINDEX)ifindex, &luid);
	if (!NETIO_SUCCESS(luid_status)) {
		windows_nyx_log("windows net injection static-neighbor %s ifindex=%lu luid-status=%lu\n",
				label, (unsigned long)ifindex, (unsigned long)luid_status);
		return;
	}
	MIB_IPNET_ROW2 row;
	memset(&row, 0, sizeof(row));
	row.Address.si_family = AF_INET;
	row.Address.Ipv4.sin_family = AF_INET;
	row.Address.Ipv4.sin_addr.S_un.S_addr =
	    windows_net_host_to_be32(SYZ_WINDOWS_NET_INJECTION_PEER_IPV4);
	row.InterfaceIndex = (NET_IFINDEX)ifindex;
	row.InterfaceLuid = luid;
	memcpy(row.PhysicalAddress, windows_net_injection_peer_mac,
	       sizeof(windows_net_injection_peer_mac));
	row.PhysicalAddressLength = sizeof(windows_net_injection_peer_mac);
	row.State = NlnsPermanent;
	NETIO_STATUS create_status = CreateIpNetEntry2(&row);
	NETIO_STATUS set_status = create_status;
	if (!NETIO_SUCCESS(create_status))
		set_status = SetIpNetEntry2(&row);
	windows_nyx_log("windows net injection static-neighbor %s ifindex=%lu create-status=%lu set-status=%lu addr=172.20.0.187 mac=02-bb-cc-dd-ee-02 luid=0x%llx\n",
			label, (unsigned long)ifindex,
			(unsigned long)create_status,
			(unsigned long)set_status,
			(unsigned long long)luid.Value);
	windows_net_injection_log_neighbor_ipv4_table_for_index(ifindex, "after-static-neighbor");
}

static void windows_net_injection_refresh_unicast_ipv4_entry(DWORD ifindex, const char* label)
{
	if (InterlockedCompareExchange(&windows_net_injection_refresh_unicast_enabled, 0, 0) == 0)
		return;
	NET_LUID luid;
	memset(&luid, 0, sizeof(luid));
	NETIO_STATUS luid_status = ConvertInterfaceIndexToLuid((NET_IFINDEX)ifindex, &luid);
	if (!NETIO_SUCCESS(luid_status)) {
		windows_nyx_log("windows net injection refresh-unicast %s ifindex=%lu luid-status=%lu\n",
				label, (unsigned long)ifindex, (unsigned long)luid_status);
		return;
	}
	MIB_UNICASTIPADDRESS_ROW row;
	memset(&row, 0, sizeof(row));
	InitializeUnicastIpAddressEntry(&row);
	row.Address.si_family = AF_INET;
	row.Address.Ipv4.sin_family = AF_INET;
	row.Address.Ipv4.sin_addr.S_un.S_addr =
	    windows_net_host_to_be32(SYZ_WINDOWS_NET_INJECTION_LOCAL_IPV4);
	row.InterfaceLuid = luid;
	row.InterfaceIndex = (NET_IFINDEX)ifindex;
	NETIO_STATUS get_status = GetUnicastIpAddressEntry(&row);
	if (!NETIO_SUCCESS(get_status)) {
		windows_nyx_log("windows net injection refresh-unicast %s ifindex=%lu get-status=%lu\n",
				label, (unsigned long)ifindex, (unsigned long)get_status);
		return;
	}
	NETIO_STATUS set_status = SetUnicastIpAddressEntry(&row);
	windows_nyx_log("windows net injection refresh-unicast %s ifindex=%lu set-status=%lu prefix=%u dad=%lu skip=%u valid=%lu preferred=%lu luid=0x%llx\n",
			label, (unsigned long)row.InterfaceIndex,
			(unsigned long)set_status,
			(unsigned)row.OnLinkPrefixLength,
			(unsigned long)row.DadState,
			(unsigned)row.SkipAsSource,
			(unsigned long)row.ValidLifetime,
			(unsigned long)row.PreferredLifetime,
			(unsigned long long)row.InterfaceLuid.Value);
}
#else
static void windows_net_injection_log_unicast_ipv4_entry(DWORD, const char*)
{
}

static void windows_net_injection_log_neighbor_ipv4_table_for_index(DWORD, const char*)
{
}

static void windows_net_injection_configure_static_neighbor(DWORD ifindex, const char* label)
{
	if (InterlockedCompareExchange(&windows_net_injection_static_neighbor_enabled, 0, 0) == 0)
		return;
	windows_nyx_log("windows net injection static-neighbor %s ifindex=%lu skipped: netio2 unavailable\n",
			label, (unsigned long)ifindex);
}

static void windows_net_injection_refresh_unicast_ipv4_entry(DWORD ifindex, const char* label)
{
	if (InterlockedCompareExchange(&windows_net_injection_refresh_unicast_enabled, 0, 0) == 0)
		return;
	windows_nyx_log("windows net injection refresh-unicast %s ifindex=%lu skipped: netio2 unavailable\n",
			label, (unsigned long)ifindex);
}
#endif

static DWORD windows_net_injection_env_dword(const char* name, DWORD max_value)
{
	char value[16];
	DWORD len = GetEnvironmentVariableA(name, value, sizeof(value));
	if (len == 0 || len >= sizeof(value))
		return 0;
	DWORD parsed = 0;
	for (DWORD i = 0; i < len; i++) {
		if (value[i] < '0' || value[i] > '9')
			return 0;
		DWORD digit = (DWORD)(value[i] - '0');
		if (parsed > (max_value - digit) / 10)
			return max_value;
		parsed = parsed * 10 + digit;
	}
	if (parsed > max_value)
		return max_value;
	return parsed;
}

#if SYZ_WINDOWS_NET_INJECTION_NETIO2
static void windows_net_injection_log_ip_interface_for_index(DWORD ifindex, const char* label)
{
	NET_LUID luid;
	memset(&luid, 0, sizeof(luid));
	NETIO_STATUS luid_status = ConvertInterfaceIndexToLuid((NET_IFINDEX)ifindex, &luid);
	if (!NETIO_SUCCESS(luid_status)) {
		windows_nyx_log("windows net state %s ip-interface ifindex=%lu luid-status=%lu\n",
				label, (unsigned long)ifindex, (unsigned long)luid_status);
		return;
	}
	MIB_IPINTERFACE_ROW row;
	memset(&row, 0, sizeof(row));
	InitializeIpInterfaceEntry(&row);
	row.Family = AF_INET;
	row.InterfaceLuid = luid;
	NETIO_STATUS status = GetIpInterfaceEntry(&row);
	if (!NETIO_SUCCESS(status)) {
		windows_nyx_log("windows net state %s ip-interface ifindex=%lu status=%lu\n",
				label, (unsigned long)ifindex, (unsigned long)status);
		return;
	}
	windows_nyx_log("windows net state %s ip-interface ifindex=%lu connected=%u mtu=%lu metric=%lu dad=%lu weak_send=%u weak_recv=%u dhcp_managed=%u other_stateful=%u\n",
			label, (unsigned long)ifindex,
			(unsigned)row.Connected,
			(unsigned long)row.NlMtu,
			(unsigned long)row.Metric,
			(unsigned long)row.DadTransmits,
			(unsigned)row.WeakHostSend,
			(unsigned)row.WeakHostReceive,
			(unsigned)row.ManagedAddressConfigurationSupported,
			(unsigned)row.OtherStatefulConfigurationSupported);
}

static void windows_net_injection_log_unicast_ipv4_table(const char* label)
{
	PMIB_UNICASTIPADDRESS_TABLE table = NULL;
	NETIO_STATUS status = GetUnicastIpAddressTable(AF_INET, &table);
	if (!NETIO_SUCCESS(status)) {
		windows_nyx_log("windows net state %s get-unicast-ip-address-table failed status=%lu\n",
				label, (unsigned long)status);
		return;
	}
	bool found = false;
	for (ULONG i = 0; i < table->NumEntries; i++) {
		MIB_UNICASTIPADDRESS_ROW* row = &table->Table[i];
		uint32 addr = row->Address.Ipv4.sin_addr.S_un.S_addr;
		unsigned a0 = (unsigned)(addr & 0xff);
		unsigned a1 = (unsigned)((addr >> 8) & 0xff);
		unsigned a2 = (unsigned)((addr >> 16) & 0xff);
		unsigned a3 = (unsigned)((addr >> 24) & 0xff);
		if (a0 != 172 || a1 != 20 || a2 != 0)
			continue;
		found = true;
		windows_nyx_log("windows net state %s unicast ifindex=%lu addr=%u.%u.%u.%u prefix=%u dad=%lu origin=%lu/%lu skip=%u valid=%lu preferred=%lu\n",
				label, (unsigned long)row->InterfaceIndex, a0, a1, a2, a3,
				(unsigned)row->OnLinkPrefixLength,
				(unsigned long)row->DadState,
				(unsigned long)row->PrefixOrigin,
				(unsigned long)row->SuffixOrigin,
				(unsigned)row->SkipAsSource,
				(unsigned long)row->ValidLifetime,
				(unsigned long)row->PreferredLifetime);
	}
	if (!found)
		windows_nyx_log("windows net state %s unicast 172.20.0.0/24 not found\n", label);
	FreeMibTable(table);
}
#else
static void windows_net_injection_log_ip_interface_for_index(DWORD, const char*)
{
}

static void windows_net_injection_log_unicast_ipv4_table(const char*)
{
}
#endif

static void windows_net_injection_log_ip_tcp_statistics(const char* label)
{
	MIB_TCPSTATS tcp_stats;
	memset(&tcp_stats, 0, sizeof(tcp_stats));
	DWORD tcp_status = GetTcpStatisticsEx(&tcp_stats, AF_INET);
	if (tcp_status == NO_ERROR) {
		windows_nyx_log("windows net state %s tcp-stats active=%lu passive=%lu attemptfails=%lu estabresets=%lu insegs=%lu outsegs=%lu retrans=%lu inerrs=%lu outrsts=%lu numconns=%lu\n",
				label,
				(unsigned long)tcp_stats.dwActiveOpens,
				(unsigned long)tcp_stats.dwPassiveOpens,
				(unsigned long)tcp_stats.dwAttemptFails,
				(unsigned long)tcp_stats.dwEstabResets,
				(unsigned long)tcp_stats.dwInSegs,
				(unsigned long)tcp_stats.dwOutSegs,
				(unsigned long)tcp_stats.dwRetransSegs,
				(unsigned long)tcp_stats.dwInErrs,
				(unsigned long)tcp_stats.dwOutRsts,
				(unsigned long)tcp_stats.dwNumConns);
	} else {
		windows_nyx_log("windows net state %s tcp-stats failed status=%lu\n",
				label, (unsigned long)tcp_status);
	}

	MIB_IPSTATS ip_stats;
	memset(&ip_stats, 0, sizeof(ip_stats));
	DWORD ip_status = GetIpStatisticsEx(&ip_stats, AF_INET);
	if (ip_status == NO_ERROR) {
		windows_nyx_log("windows net state %s ip-stats inrecv=%lu hdrerrs=%lu addrerrs=%lu unknownproto=%lu discarded=%lu delivered=%lu outreq=%lu routingdisc=%lu outdisc=%lu outerrs=%lu noreasm=%lu\n",
				label,
				(unsigned long)ip_stats.dwInReceives,
				(unsigned long)ip_stats.dwInHdrErrors,
				(unsigned long)ip_stats.dwInAddrErrors,
				(unsigned long)ip_stats.dwInUnknownProtos,
				(unsigned long)ip_stats.dwInDiscards,
				(unsigned long)ip_stats.dwInDelivers,
				(unsigned long)ip_stats.dwOutRequests,
				(unsigned long)ip_stats.dwRoutingDiscards,
				(unsigned long)ip_stats.dwOutDiscards,
				(unsigned long)ip_stats.dwOutNoRoutes,
				(unsigned long)ip_stats.dwReasmFails);
	} else {
		windows_nyx_log("windows net state %s ip-stats failed status=%lu\n",
				label, (unsigned long)ip_status);
	}
}

static void windows_net_injection_allow_firewall_tcp_inbound()
{
	HRESULT hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	bool initialized = SUCCEEDED(hr_init);
	if (hr_init == RPC_E_CHANGED_MODE)
		initialized = false;
	else if (FAILED(hr_init)) {
		windows_nyx_log("windows net injection firewall-allow coinit failed hr=0x%lx\n",
				(unsigned long)hr_init);
		return;
	}
	INetFwPolicy2* policy = NULL;
	HRESULT hr_create_policy = CoCreateInstance(__uuidof(NetFwPolicy2), NULL,
						    CLSCTX_INPROC_SERVER,
						    __uuidof(INetFwPolicy2),
						    (void**)&policy);
	if (FAILED(hr_create_policy) || policy == NULL) {
		windows_nyx_log("windows net injection firewall-allow policy cocreate failed hr=0x%lx coinit=0x%lx\n",
				(unsigned long)hr_create_policy, (unsigned long)hr_init);
		if (initialized)
			CoUninitialize();
		return;
	}

	INetFwRules* rules = NULL;
	HRESULT hr_rules = policy->get_Rules(&rules);
	if (FAILED(hr_rules) || rules == NULL) {
		windows_nyx_log("windows net injection firewall-allow get-rules failed hr=0x%lx coinit=0x%lx\n",
				(unsigned long)hr_rules, (unsigned long)hr_init);
		policy->Release();
		if (initialized)
			CoUninitialize();
		return;
	}

	BSTR name = SysAllocString(L"NTSyzkaller Windows vnet TCP 20000 allow");
	BSTR desc = SysAllocString(L"NTSyzkaller controlled vnet TCP listener experiment");
	BSTR ports = SysAllocString(L"20000");
	if (name == NULL || desc == NULL || ports == NULL) {
		windows_nyx_log("windows net injection firewall-allow bstr allocation failed name=%p desc=%p ports=%p\n",
				name, desc, ports);
		if (name != NULL)
			SysFreeString(name);
		if (desc != NULL)
			SysFreeString(desc);
		if (ports != NULL)
			SysFreeString(ports);
		rules->Release();
		policy->Release();
		if (initialized)
			CoUninitialize();
		return;
	}

	HRESULT hr_remove = rules->Remove(name);
	INetFwRule* rule = NULL;
	HRESULT hr_create_rule = CoCreateInstance(__uuidof(NetFwRule), NULL,
						  CLSCTX_INPROC_SERVER,
						  __uuidof(INetFwRule),
						  (void**)&rule);
	HRESULT hr_name = E_POINTER;
	HRESULT hr_desc = E_POINTER;
	HRESULT hr_protocol = E_POINTER;
	HRESULT hr_ports = E_POINTER;
	HRESULT hr_direction = E_POINTER;
	HRESULT hr_profiles = E_POINTER;
	HRESULT hr_action = E_POINTER;
	HRESULT hr_enabled = E_POINTER;
	HRESULT hr_add = E_POINTER;
	if (SUCCEEDED(hr_create_rule) && rule != NULL) {
		hr_name = rule->put_Name(name);
		hr_desc = rule->put_Description(desc);
		hr_protocol = rule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
		hr_ports = rule->put_LocalPorts(ports);
		hr_direction = rule->put_Direction(NET_FW_RULE_DIR_IN);
		hr_profiles = rule->put_Profiles(NET_FW_PROFILE2_ALL);
		hr_action = rule->put_Action(NET_FW_ACTION_ALLOW);
		hr_enabled = rule->put_Enabled(VARIANT_TRUE);
		hr_add = rules->Add(rule);
		rule->Release();
	}
	windows_nyx_log("windows net injection firewall-allow rule name=\"NTSyzkaller Windows vnet TCP 20000 allow\" scope=local-port-only remove_hr=0x%lx create_hr=0x%lx name_hr=0x%lx desc_hr=0x%lx proto_hr=0x%lx ports_hr=0x%lx dir_hr=0x%lx profiles_hr=0x%lx action_hr=0x%lx enabled_hr=0x%lx add_hr=0x%lx coinit=0x%lx\n",
			(unsigned long)hr_remove,
			(unsigned long)hr_create_rule,
			(unsigned long)hr_name,
			(unsigned long)hr_desc,
			(unsigned long)hr_protocol,
			(unsigned long)hr_ports,
			(unsigned long)hr_direction,
			(unsigned long)hr_profiles,
			(unsigned long)hr_action,
			(unsigned long)hr_enabled,
			(unsigned long)hr_add,
			(unsigned long)hr_init);

	SysFreeString(ports);
	SysFreeString(desc);
	SysFreeString(name);
	rules->Release();
	policy->Release();
	if (initialized)
		CoUninitialize();
}

static bool windows_net_injection_ipv4_prefix_contains(uint32 prefix_addr,
						       UCHAR prefix_length,
						       uint32 addr_host)
{
	if (prefix_length > 32)
		return false;
	if (prefix_length == 0)
		return true;
	uint32 prefix_host = windows_net_host_to_be32(prefix_addr);
	uint32 mask = prefix_length == 32 ? 0xffffffffU : ~((1U << (32 - prefix_length)) - 1);
	return (prefix_host & mask) == (addr_host & mask);
}

#if SYZ_WINDOWS_NET_INJECTION_NETIO2
static void windows_net_injection_log_peer_route(DWORD ifindex, const char* label)
{
	NET_LUID luid;
	memset(&luid, 0, sizeof(luid));
	NETIO_STATUS luid_status = ConvertInterfaceIndexToLuid((NET_IFINDEX)ifindex, &luid);
	if (!NETIO_SUCCESS(luid_status)) {
		windows_nyx_log("windows net state %s peer-route ifindex=%lu luid-status=%lu\n",
				label, (unsigned long)ifindex, (unsigned long)luid_status);
		return;
	}
	PMIB_IPFORWARD_TABLE2 table = NULL;
	NETIO_STATUS status = GetIpForwardTable2(AF_INET, &table);
	if (!NETIO_SUCCESS(status)) {
		windows_nyx_log("windows net state %s peer-route-table ifindex=%lu status=%lu dest=172.20.0.187 luid=0x%llx\n",
				label, (unsigned long)ifindex, (unsigned long)status,
				(unsigned long long)luid.Value);
		return;
	}
	bool found = false;
	for (ULONG i = 0; i < table->NumEntries; i++) {
		MIB_IPFORWARD_ROW2* route = &table->Table[i];
		uint32 prefix = route->DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr;
		uint32 next = route->NextHop.Ipv4.sin_addr.S_un.S_addr;
		UCHAR prefix_length = route->DestinationPrefix.PrefixLength;
		bool route_on_ifindex = route->InterfaceIndex == (NET_IFINDEX)ifindex;
		bool route_matches_peer = windows_net_injection_ipv4_prefix_contains(
		    prefix, prefix_length, SYZ_WINDOWS_NET_INJECTION_PEER_IPV4);
		bool route_default = prefix_length == 0;
		if (!route_on_ifindex && !route_matches_peer && !route_default)
			continue;
		found = true;
		windows_nyx_log("windows net state %s peer-route-row ifindex=%lu route-ifindex=%lu dest=%u.%u.%u.%u/%u peer-match=%u on-ifindex=%u default=%u next=%u.%u.%u.%u metric=%lu protocol=%lu loopback=%u autoconf=%u publish=%u immortal=%u route-luid=0x%llx tap-luid=0x%llx\n",
				label, (unsigned long)ifindex,
				(unsigned long)route->InterfaceIndex,
				(unsigned)(prefix & 0xff),
				(unsigned)((prefix >> 8) & 0xff),
				(unsigned)((prefix >> 16) & 0xff),
				(unsigned)((prefix >> 24) & 0xff),
				(unsigned)prefix_length,
				(unsigned)route_matches_peer,
				(unsigned)route_on_ifindex,
				(unsigned)route_default,
				(unsigned)(next & 0xff),
				(unsigned)((next >> 8) & 0xff),
				(unsigned)((next >> 16) & 0xff),
				(unsigned)((next >> 24) & 0xff),
				(unsigned long)route->Metric,
				(unsigned long)route->Protocol,
				(unsigned)route->Loopback,
				(unsigned)route->AutoconfigureAddress,
				(unsigned)route->Publish,
				(unsigned)route->Immortal,
				(unsigned long long)route->InterfaceLuid.Value,
				(unsigned long long)luid.Value);
	}
	if (!found)
		windows_nyx_log("windows net state %s peer-route-row ifindex=%lu no relevant rows dest=172.20.0.187 luid=0x%llx\n",
				label, (unsigned long)ifindex,
				(unsigned long long)luid.Value);
	FreeMibTable(table);
}
#else
static void windows_net_injection_log_peer_route(DWORD, const char*)
{
}
#endif

static const char* windows_net_injection_tcp_state_name(DWORD state)
{
	switch (state) {
	case MIB_TCP_STATE_CLOSED:
		return "CLOSED";
	case MIB_TCP_STATE_LISTEN:
		return "LISTEN";
	case MIB_TCP_STATE_SYN_SENT:
		return "SYN_SENT";
	case MIB_TCP_STATE_SYN_RCVD:
		return "SYN_RCVD";
	case MIB_TCP_STATE_ESTAB:
		return "ESTAB";
	case MIB_TCP_STATE_FIN_WAIT1:
		return "FIN_WAIT1";
	case MIB_TCP_STATE_FIN_WAIT2:
		return "FIN_WAIT2";
	case MIB_TCP_STATE_CLOSE_WAIT:
		return "CLOSE_WAIT";
	case MIB_TCP_STATE_CLOSING:
		return "CLOSING";
	case MIB_TCP_STATE_LAST_ACK:
		return "LAST_ACK";
	case MIB_TCP_STATE_TIME_WAIT:
		return "TIME_WAIT";
	case MIB_TCP_STATE_DELETE_TCB:
		return "DELETE_TCB";
	default:
		return "UNKNOWN";
	}
}

static void windows_net_injection_log_extended_tcp_table(const char* label)
{
	DWORD owner_table_size = 0;
	DWORD tcp_status = GetExtendedTcpTable(NULL, &owner_table_size, TRUE, AF_INET,
					       TCP_TABLE_OWNER_PID_ALL, 0);
	if (tcp_status != ERROR_INSUFFICIENT_BUFFER) {
		windows_nyx_log("windows net state %s get-extended-tcp-table size failed status=%lu size=%lu\n",
				label, (unsigned long)tcp_status, (unsigned long)owner_table_size);
		return;
	}
	PMIB_TCPTABLE_OWNER_PID owner_table = (PMIB_TCPTABLE_OWNER_PID)HeapAlloc(GetProcessHeap(),
										 HEAP_ZERO_MEMORY, owner_table_size);
	if (owner_table == NULL) {
		windows_nyx_log("windows net state %s get-extended-tcp-table alloc failed size=%lu\n",
				label, (unsigned long)owner_table_size);
		return;
	}
	tcp_status = GetExtendedTcpTable(owner_table, &owner_table_size, TRUE, AF_INET,
					 TCP_TABLE_OWNER_PID_ALL, 0);
	if (tcp_status != NO_ERROR) {
		windows_nyx_log("windows net state %s get-extended-tcp-table failed status=%lu size=%lu\n",
				label, (unsigned long)tcp_status, (unsigned long)owner_table_size);
		HeapFree(GetProcessHeap(), 0, owner_table);
		return;
	}

	bool port_found = false;
	bool target_found = false;
	uint32 peer_addr = windows_net_host_to_be32(SYZ_WINDOWS_NET_INJECTION_PEER_IPV4);
	uint32 local_addr = windows_net_host_to_be32(SYZ_WINDOWS_NET_INJECTION_LOCAL_IPV4);
	uint16 local_port = windows_net_host_to_be16(SYZ_WINDOWS_NET_INJECTION_LOCAL_TCP_PORT);
	uint16 peer_port = windows_net_host_to_be16(SYZ_WINDOWS_NET_INJECTION_PEER_TCP_PORT);
	for (DWORD i = 0; i < owner_table->dwNumEntries; i++) {
		MIB_TCPROW_OWNER_PID* row = &owner_table->table[i];
		if ((uint16)row->dwLocalPort != local_port)
			continue;
		port_found = true;
		bool listener = row->dwRemoteAddr == 0 && row->dwRemotePort == 0;
		bool target = row->dwLocalAddr == local_addr &&
			      row->dwRemoteAddr == peer_addr &&
			      (uint16)row->dwRemotePort == peer_port;
		if (target)
			target_found = true;
		windows_nyx_log("windows net state %s extended-tcp local=%u.%u.%u.%u:%u remote=%u.%u.%u.%u:%u state=%lu(%s) pid=%lu target=%u listener=%u\n",
				label,
				(unsigned)(row->dwLocalAddr & 0xff),
				(unsigned)((row->dwLocalAddr >> 8) & 0xff),
				(unsigned)((row->dwLocalAddr >> 16) & 0xff),
				(unsigned)((row->dwLocalAddr >> 24) & 0xff),
				(unsigned)windows_net_load_be16((const char*)&row->dwLocalPort),
				(unsigned)(row->dwRemoteAddr & 0xff),
				(unsigned)((row->dwRemoteAddr >> 8) & 0xff),
				(unsigned)((row->dwRemoteAddr >> 16) & 0xff),
				(unsigned)((row->dwRemoteAddr >> 24) & 0xff),
				(unsigned)windows_net_load_be16((const char*)&row->dwRemotePort),
				(unsigned long)row->dwState,
				windows_net_injection_tcp_state_name(row->dwState),
				(unsigned long)row->dwOwningPid,
				target ? 1U : 0U,
				listener ? 1U : 0U);
		if (target && row->dwState == MIB_TCP_STATE_SYN_RCVD) {
			windows_nyx_log("windows net state %s extended-tcp target 172.20.0.170:20000->172.20.0.187:40000 state=%lu(%s) pid=%lu\n",
					label, (unsigned long)row->dwState,
					windows_net_injection_tcp_state_name(row->dwState),
					(unsigned long)row->dwOwningPid);
		}
	}
	if (!port_found)
		windows_nyx_log("windows net state %s extended-tcp local-port=%u not found\n",
				label, SYZ_WINDOWS_NET_INJECTION_LOCAL_TCP_PORT);
	else if (!target_found)
		windows_nyx_log("windows net state %s extended-tcp target 172.20.0.170:20000->172.20.0.187:40000 not found\n",
				label);
	HeapFree(GetProcessHeap(), 0, owner_table);
}

static void windows_net_injection_try_configure_local_ipv4()
{
	if (windows_net_injection_local_ipv4_present()) {
		windows_nyx_log("windows net injection local ipv4 already present\n");
		return;
	}

	DWORD ifindex = windows_net_injection_target_ifindex();
	if (ifindex == 0) {
		windows_nyx_log("windows net injection local ipv4 target adapter not found name=%s\n",
				windows_net_injection_target_adapter_name[0] ? windows_net_injection_target_adapter_name : "<unset>");
		return;
	}

	IPAddr local_addr = (IPAddr)windows_net_host_to_be32(SYZ_WINDOWS_NET_INJECTION_LOCAL_IPV4);
	IPMask local_mask = (IPMask)windows_net_host_to_be32(SYZ_WINDOWS_NET_INJECTION_LOCAL_IPV4_MASK);
	windows_net_injection_log_ip_interface_for_index(ifindex, "configure");
	windows_net_injection_refresh_unicast_ipv4_entry(ifindex, "configure");
	windows_net_injection_configure_static_neighbor(ifindex, "configure");
	ULONG nte_context = 0;
	ULONG nte_instance = 0;
	DWORD add_status = AddIPAddress(local_addr, local_mask, ifindex,
					&nte_context, &nte_instance);
	windows_nyx_log("windows net injection local ipv4 add ifindex=%lu status=%lu nte_context=%lu nte_instance=%lu\n",
			(unsigned long)ifindex,
			(unsigned long)add_status,
			(unsigned long)nte_context,
			(unsigned long)nte_instance);
	windows_net_injection_log_unicast_ipv4_table("after-configure");
}

static void windows_net_injection_log_guest_net_state(const char* label)
{
	static int configure_during_log = -1;
	if (configure_during_log < 0) {
		char configure_in_log[8];
		DWORD configure_in_log_len = GetEnvironmentVariableA("SYZ_WINDOWS_NET_INJECTION_CONFIGURE_IN_LOG",
								     configure_in_log,
								     sizeof(configure_in_log));
		configure_during_log = configure_in_log_len > 0 &&
				       configure_in_log_len < sizeof(configure_in_log) &&
				       configure_in_log[0] == '1';
	}
	DWORD target_ifindex = windows_net_injection_target_ifindex();
	ULONG if_table_size = 0;
	DWORD if_status = GetIfTable(NULL, &if_table_size, TRUE);
	PMIB_IFTABLE if_table = NULL;
	if (if_status != ERROR_INSUFFICIENT_BUFFER) {
		windows_nyx_log("windows net state %s get-if-table size failed status=%lu size=%lu\n",
				label, (unsigned long)if_status, (unsigned long)if_table_size);
	} else {
		if_table = (PMIB_IFTABLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, if_table_size);
		if (if_table == NULL) {
			windows_nyx_log("windows net state %s get-if-table alloc failed size=%lu\n",
					label, (unsigned long)if_table_size);
		} else {
			if_status = GetIfTable(if_table, &if_table_size, TRUE);
		}
	}
	if (if_table != NULL && if_status == NO_ERROR) {
		bool found = false;
		for (ULONG i = 0; i < if_table->dwNumEntries; i++) {
			MIB_IFROW* row = &if_table->table[i];
			if (target_ifindex == 0 || row->dwIndex != target_ifindex)
				continue;
			found = true;
			windows_nyx_log("windows net state %s tap ifindex=%lu oper=%lu admin=%lu in_octets=%lu in_ucast=%lu out_octets=%lu out_ucast=%lu in_discards=%lu in_errors=%lu out_discards=%lu out_errors=%lu\n",
					label, (unsigned long)row->dwIndex,
					(unsigned long)row->dwOperStatus,
					(unsigned long)row->dwAdminStatus,
					(unsigned long)row->dwInOctets,
					(unsigned long)row->dwInUcastPkts,
					(unsigned long)row->dwOutOctets,
					(unsigned long)row->dwOutUcastPkts,
					(unsigned long)row->dwInDiscards,
					(unsigned long)row->dwInErrors,
					(unsigned long)row->dwOutDiscards,
					(unsigned long)row->dwOutErrors);
			windows_net_injection_log_ip_interface_for_index(row->dwIndex, label);
			windows_net_injection_log_unicast_ipv4_entry(row->dwIndex, label);
			if (configure_during_log) {
				windows_net_injection_configure_static_neighbor(row->dwIndex, label);
			}
			windows_net_injection_log_neighbor_ipv4_table_for_index(row->dwIndex, label);
			windows_net_injection_log_peer_route(row->dwIndex, label);
		}
		if (!found)
			windows_nyx_log("windows net state %s tap adapter not found by device name=%s\n",
					label,
					windows_net_injection_target_adapter_name[0] ? windows_net_injection_target_adapter_name : "<unset>");
	} else if (if_table != NULL) {
		windows_nyx_log("windows net state %s get-if-table failed status=%lu size=%lu\n",
				label, (unsigned long)if_status, (unsigned long)if_table_size);
	}
	if (if_table != NULL)
		HeapFree(GetProcessHeap(), 0, if_table);
	windows_net_injection_log_adapter_addresses(label);

	ULONG ip_table_size = 0;
	DWORD ip_status = GetIpAddrTable(NULL, &ip_table_size, TRUE);
	PMIB_IPADDRTABLE ip_table = NULL;
	if (ip_status != ERROR_INSUFFICIENT_BUFFER) {
		windows_nyx_log("windows net state %s get-ip-addr-table size failed status=%lu size=%lu\n",
				label, (unsigned long)ip_status, (unsigned long)ip_table_size);
	} else {
		ip_table = (PMIB_IPADDRTABLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ip_table_size);
		if (ip_table == NULL) {
			windows_nyx_log("windows net state %s get-ip-addr-table alloc failed size=%lu\n",
					label, (unsigned long)ip_table_size);
		} else {
			ip_status = GetIpAddrTable(ip_table, &ip_table_size, TRUE);
		}
	}
	if (ip_table != NULL && ip_status == NO_ERROR) {
		bool ip_found = false;
		for (DWORD i = 0; i < ip_table->dwNumEntries; i++) {
			MIB_IPADDRROW* row = &ip_table->table[i];
			unsigned a0 = (unsigned)(row->dwAddr & 0xff);
			unsigned a1 = (unsigned)((row->dwAddr >> 8) & 0xff);
			unsigned a2 = (unsigned)((row->dwAddr >> 16) & 0xff);
			unsigned a3 = (unsigned)((row->dwAddr >> 24) & 0xff);
			if (a0 != 172 || a1 != 20 || a2 != 0)
				continue;
			ip_found = true;
			windows_nyx_log("windows net state %s ip ifindex=%lu addr=%u.%u.%u.%u mask=%u.%u.%u.%u type=0x%x\n",
					label, (unsigned long)row->dwIndex, a0, a1, a2, a3,
					(unsigned)(row->dwMask & 0xff),
					(unsigned)((row->dwMask >> 8) & 0xff),
					(unsigned)((row->dwMask >> 16) & 0xff),
					(unsigned)((row->dwMask >> 24) & 0xff),
					(unsigned)row->wType);
		}
		if (!ip_found)
			windows_nyx_log("windows net state %s ip 172.20.0.0/24 not found\n", label);
	} else if (ip_table != NULL) {
		windows_nyx_log("windows net state %s get-ip-addr-table failed status=%lu size=%lu\n",
				label, (unsigned long)ip_status, (unsigned long)ip_table_size);
	}
	if (ip_table != NULL)
		HeapFree(GetProcessHeap(), 0, ip_table);
	windows_net_injection_log_ip_tcp_statistics(label);
	windows_net_injection_log_unicast_ipv4_table(label);
	windows_net_injection_log_extended_tcp_table(label);

	ULONG table_size = 0;
	ULONG tcp_status = GetTcpTable(NULL, &table_size, TRUE);
	if (tcp_status != ERROR_INSUFFICIENT_BUFFER) {
		windows_nyx_log("windows net state %s get-tcp-table size failed status=%lu size=%lu\n",
				label, (unsigned long)tcp_status, (unsigned long)table_size);
		return;
	}
	PMIB_TCPTABLE tcp_table = (PMIB_TCPTABLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, table_size);
	if (tcp_table == NULL) {
		windows_nyx_log("windows net state %s get-tcp-table alloc failed size=%lu\n",
				label, (unsigned long)table_size);
		return;
	}
	tcp_status = GetTcpTable(tcp_table, &table_size, TRUE);
	if (tcp_status != NO_ERROR) {
		windows_nyx_log("windows net state %s get-tcp-table failed status=%lu size=%lu\n",
				label, (unsigned long)tcp_status, (unsigned long)table_size);
		HeapFree(GetProcessHeap(), 0, tcp_table);
		return;
	}
	bool tcp_found = false;
	uint32 peer_addr = windows_net_host_to_be32(SYZ_WINDOWS_NET_INJECTION_PEER_IPV4);
	uint32 local_port = windows_net_host_to_be16(SYZ_WINDOWS_NET_INJECTION_LOCAL_TCP_PORT);
	for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
		MIB_TCPROW* row = &tcp_table->table[i];
		if (row->dwLocalPort != local_port)
			continue;
		if (row->dwRemoteAddr != 0 && row->dwRemoteAddr != peer_addr)
			continue;
		tcp_found = true;
		windows_nyx_log("windows net state %s tcp local=%u.%u.%u.%u:%u remote=%u.%u.%u.%u:%u state=%lu pid=%lu\n",
				label,
				(unsigned)(row->dwLocalAddr & 0xff),
				(unsigned)((row->dwLocalAddr >> 8) & 0xff),
				(unsigned)((row->dwLocalAddr >> 16) & 0xff),
				(unsigned)((row->dwLocalAddr >> 24) & 0xff),
				SYZ_WINDOWS_NET_INJECTION_LOCAL_TCP_PORT,
				(unsigned)(row->dwRemoteAddr & 0xff),
				(unsigned)((row->dwRemoteAddr >> 8) & 0xff),
				(unsigned)((row->dwRemoteAddr >> 16) & 0xff),
				(unsigned)((row->dwRemoteAddr >> 24) & 0xff),
				(unsigned)windows_net_load_be16((const char*)&row->dwRemotePort),
				(unsigned long)row->dwState,
				0UL);
	}
	if (!tcp_found)
		windows_nyx_log("windows net state %s tcp local-port=%u not found\n",
				label, SYZ_WINDOWS_NET_INJECTION_LOCAL_TCP_PORT);
	HeapFree(GetProcessHeap(), 0, tcp_table);
}

static uint32 windows_net_checksum_add(const void* data, size_t length, uint32 sum)
{
	const uint8* bytes = (const uint8*)data;
	while (length >= 2) {
		sum += ((uint16)bytes[0] << 8) | bytes[1];
		bytes += 2;
		length -= 2;
	}
	if (length != 0)
		sum += (uint16)bytes[0] << 8;
	return sum;
}

static uint16 windows_net_checksum_finish(uint32 sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16)~sum;
}

static void windows_net_injection_log_extract_complete(const char* source)
{
	windows_nyx_log("windows net injection extract complete source=%s\n", source);
}

static void windows_net_injection_log_frame_summary(const char* direction, const char* data, size_t length)
{
	if (length < 14) {
		windows_nyx_log("windows net injection %s frame short ethernet length=%zu\n", direction, length);
		return;
	}
	uint16 eth_type = windows_net_load_be16(data + 12);
	windows_nyx_log("windows net injection %s eth dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x type=0x%04x length=%zu\n",
			direction,
			(uint8)data[0], (uint8)data[1], (uint8)data[2], (uint8)data[3], (uint8)data[4], (uint8)data[5],
			(uint8)data[6], (uint8)data[7], (uint8)data[8], (uint8)data[9], (uint8)data[10], (uint8)data[11],
			eth_type, length);
	if (eth_type != SYZ_WINDOWS_NET_INJECTION_ETH_P_IP || length < 34)
		return;

	const char* ip = data + 14;
	size_t ip_frame_len = length - 14;
	uint8 version = ((uint8)ip[0]) >> 4;
	uint8 ihl = ((uint8)ip[0] & 0x0f) * 4;
	if (version != 4 || ihl < 20 || ip_frame_len < ihl) {
		windows_nyx_log("windows net injection %s ipv4 malformed version=%u ihl=%u frame_len=%zu\n",
				direction, version, ihl, ip_frame_len);
		return;
	}
	uint16 total_len = windows_net_load_be16(ip + 2);
	uint16 ip_csum = windows_net_load_be16(ip + 10);
	uint16 ip_check = windows_net_checksum_finish(windows_net_checksum_add(ip, ihl, 0));
	windows_nyx_log("windows net injection %s ipv4 src=%u.%u.%u.%u dst=%u.%u.%u.%u proto=%u total_len=%u ihl=%u csum=0x%04x verify=0x%04x\n",
			direction,
			(uint8)ip[12], (uint8)ip[13], (uint8)ip[14], (uint8)ip[15],
			(uint8)ip[16], (uint8)ip[17], (uint8)ip[18], (uint8)ip[19],
			(uint8)ip[9], total_len, ihl, ip_csum, ip_check);
	if (ip[9] != SYZ_WINDOWS_NET_INJECTION_IPPROTO_TCP || total_len < ihl + 20 || ip_frame_len < total_len)
		return;

	const char* tcp = ip + ihl;
	size_t tcp_len = total_len - ihl;
	uint8 data_off = (((uint8)tcp[12]) >> 4) * 4;
	uint32 tcp_sum = 0;
	tcp_sum = windows_net_checksum_add(ip + 12, 8, tcp_sum);
	uint8 pseudo[4] = {0, SYZ_WINDOWS_NET_INJECTION_IPPROTO_TCP, (uint8)(tcp_len >> 8), (uint8)tcp_len};
	tcp_sum = windows_net_checksum_add(pseudo, sizeof(pseudo), tcp_sum);
	tcp_sum = windows_net_checksum_add(tcp, tcp_len, tcp_sum);
	uint16 tcp_check = windows_net_checksum_finish(tcp_sum);
	windows_nyx_log("windows net injection %s tcp src_port=%u dst_port=%u flags=0x%02x seq=0x%x ack=0x%x data_off=%u csum=0x%04x verify=0x%04x\n",
			direction,
			windows_net_load_be16(tcp), windows_net_load_be16(tcp + 2),
			(uint8)tcp[13], windows_net_load_be32(tcp + 4), windows_net_load_be32(tcp + 8),
			data_off, windows_net_load_be16(tcp + 16), tcp_check);
}

static bool windows_net_injection_parse_tcp_frame(const char* data, size_t length, uint32* seq, uint32* ack,
						  const char* owner, int attempt)
{
	if (length < 14) {
		windows_nyx_log("windows net injection %s short ethernet frame length=%zu attempt=%d\n", owner, length, attempt);
		return false;
	}
	uint16 eth_type = windows_net_load_be16(data + 12);
	if (eth_type != SYZ_WINDOWS_NET_INJECTION_ETH_P_IP) {
		windows_nyx_log("windows net injection %s non-ip ethernet frame type=0x%x attempt=%d\n", owner, eth_type, attempt);
		return false;
	}

	const char* ip = data + 14;
	size_t ip_len = length - 14;
	if (ip_len < 20) {
		windows_nyx_log("windows net injection %s short ipv4 frame length=%zu attempt=%d\n", owner, ip_len, attempt);
		return false;
	}
	uint8 version = ((uint8)ip[0]) >> 4;
	uint8 ihl = ((uint8)ip[0] & 0x0f) * 4;
	if (version != 4 || ihl < 20 || ip_len < ihl || ip[9] != SYZ_WINDOWS_NET_INJECTION_IPPROTO_TCP) {
		windows_nyx_log("windows net injection %s non-tcp ipv4 frame proto=0x%x attempt=%d\n", owner, (uint8)ip[9], attempt);
		return false;
	}
	uint16 total_len = windows_net_load_be16(ip + 2);
	if (total_len < ihl + 20 || ip_len < total_len) {
		windows_nyx_log("windows net injection %s malformed tcp ipv4 total_len=%u ihl=%u frame_len=%zu attempt=%d\n",
				owner, total_len, ihl, ip_len, attempt);
		return false;
	}

	const char* tcp = ip + ihl;
	size_t tcp_len = total_len - ihl;
	if (tcp_len < 20) {
		windows_nyx_log("windows net injection %s short tcp frame length=%zu attempt=%d\n", owner, tcp_len, attempt);
		return false;
	}
	uint32 src_ip = windows_net_load_be32(ip + 12);
	uint32 dst_ip = windows_net_load_be32(ip + 16);
	uint16 src_port = windows_net_load_be16(tcp);
	uint16 dst_port = windows_net_load_be16(tcp + 2);
	uint8 flags = (uint8)tcp[13];
	bool is_syn = (flags & (SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_SYN | SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_ACK)) == SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_SYN;
	bool is_synack = (flags & (SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_SYN | SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_ACK)) == (SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_SYN | SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_ACK);
	if (src_ip != SYZ_WINDOWS_NET_INJECTION_LOCAL_IPV4 ||
	    dst_ip != SYZ_WINDOWS_NET_INJECTION_PEER_IPV4 ||
	    src_port < SYZ_WINDOWS_NET_INJECTION_LOCAL_TCP_PORT ||
	    src_port > SYZ_WINDOWS_NET_INJECTION_LOCAL_TCP_PORT_MAX ||
	    dst_port < SYZ_WINDOWS_NET_INJECTION_PEER_TCP_PORT ||
	    dst_port > SYZ_WINDOWS_NET_INJECTION_PEER_TCP_PORT_MAX ||
	    (!is_syn && !is_synack)) {
		windows_nyx_log("windows net injection %s non-target tcp src=0x%x dst=0x%x sport=%u dport=%u flags=0x%02x attempt=%d\n",
				owner, src_ip, dst_ip, src_port, dst_port, flags, attempt);
		return false;
	}

	*seq = windows_net_load_be32(tcp + 4);
	*ack = windows_net_load_be32(tcp + 8);
	return true;
}

static long windows_net_injection_read_with_poll(void* data, DWORD length, DWORD poll_ms, bool verbose_timeout)
{
	OVERLAPPED ov = {};
	DWORD read = 0;
	ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
	if (ov.hEvent == NULL) {
		debug("windows net injection read event creation failed: %u\n", GetLastError());
		windows_nyx_log("windows net injection read event creation failed: %u\n", GetLastError());
		return -1;
	}
	windows_nyx_log("windows net injection read begin handle=0x%p event=0x%p length=%u buffer=0x%p\n",
			windows_net_injection, ov.hEvent, length, data);
	BOOL ok = ReadFile(windows_net_injection, data, length, &read, &ov);
	DWORD err = ok ? ERROR_SUCCESS : GetLastError();
	windows_nyx_log("windows net injection read issued ok=%u err=%u read=%u\n", ok, err, read);
	if (!ok && err == ERROR_IO_PENDING) {
		DWORD wait = WaitForSingleObject(ov.hEvent, poll_ms);
		windows_nyx_log("windows net injection read wait result=%u\n", wait);
		if (wait == WAIT_OBJECT_0) {
			ok = GetOverlappedResult(windows_net_injection, &ov, &read, FALSE);
			err = ok ? ERROR_SUCCESS : GetLastError();
			windows_nyx_log("windows net injection read overlapped result ok=%u err=%u read=%u\n", ok, err, read);
		} else {
			BOOL cancel_ok = CancelIoEx(windows_net_injection, &ov);
			DWORD cancel_err = cancel_ok ? ERROR_SUCCESS : GetLastError();
			if (verbose_timeout)
				windows_nyx_log("windows net injection read cancel issued ok=%u err=%u\n", cancel_ok, cancel_err);
			ok = GetOverlappedResult(windows_net_injection, &ov, &read, FALSE);
			err = ok ? ERROR_SUCCESS : GetLastError();
			if (verbose_timeout)
				windows_nyx_log("windows net injection read post-cancel result ok=%u err=%u read=%u\n", ok, err, read);
			CloseHandle(ov.hEvent);
			if (verbose_timeout) {
				debug("windows net injection read timed out\n");
				windows_nyx_log("windows net injection read timed out\n");
			}
			return SYZ_WINDOWS_NET_INJECTION_READ_TIMEOUT;
		}
	}
	CloseHandle(ov.hEvent);
	if (!ok) {
		debug("windows net injection read failed: %u\n", err);
		windows_nyx_log("windows net injection read failed: %u length=%u read=%u\n", err, length, read);
		return -1;
	}
	if (read == 0) {
		debug("windows net injection read returned no data\n");
		windows_nyx_log("windows net injection read returned no data\n");
		return -1;
	}
	windows_nyx_log("windows net injection read frame length=%u\n", read);
	windows_net_injection_log_frame_summary("rx", (const char*)data, read);
	return read;
}

static DWORD WINAPI windows_net_injection_background_reader(void*)
{
	char data[SYZ_WINDOWS_NET_INJECTION_MAX_FRAME_SIZE];
	windows_nyx_log("windows net injection background reader started handle=0x%p\n", windows_net_injection);
	for (;;) {
		long rv = windows_net_injection_read_with_poll(data, sizeof(data),
							       SYZ_WINDOWS_NET_INJECTION_BACKGROUND_READ_POLL_MS, false);
		if (rv < 0)
			continue;
		uint32 seq = 0;
		uint32 ack = 0;
		if (!windows_net_injection_parse_tcp_frame(data, (size_t)rv, &seq, &ack, "background reader", 0))
			continue;
		InterlockedExchange(&windows_net_injection_cached_tcp_seq, (LONG)seq);
		InterlockedExchange(&windows_net_injection_cached_tcp_ack, (LONG)ack);
		InterlockedExchange(&windows_net_injection_cached_tcp_valid, 1);
		windows_nyx_log("windows net injection cached tcp frame seq=0x%x ack=0x%x length=%ld\n", seq, ack, rv);
	}
}

#if SYZ_NET_INJECTION
static void initialize_windows_net_injection()
{
	char device_path[MAX_PATH];
	DWORD path_len = GetEnvironmentVariableA(SYZ_WINDOWS_NET_INJECTION_DEVICE_ENV, device_path, sizeof(device_path));
	if (path_len == 0) {
		debug("windows net injection backend is not configured\n");
		windows_nyx_log("windows net injection backend is not configured\n");
		return;
	}
	if (path_len >= sizeof(device_path)) {
		debug("windows net injection device path is too long\n");
		windows_nyx_log("windows net injection device path is too long\n");
		return;
	}
	windows_net_injection = CreateFileA(device_path, GENERIC_READ | GENERIC_WRITE,
					    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
					    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
	if (windows_net_injection == INVALID_HANDLE_VALUE) {
		debug("failed to open windows net injection device %s: %u\n", device_path, GetLastError());
		windows_nyx_log("failed to open windows net injection device %s: %u\n", device_path, GetLastError());
		return;
	}
	debug("opened windows net injection device %s\n", device_path);
	windows_nyx_log("opened windows net injection device %s\n", device_path);
	if (!windows_net_injection_parse_device_adapter_name(device_path, windows_net_injection_target_adapter_name,
							     sizeof(windows_net_injection_target_adapter_name))) {
		windows_nyx_log("windows net injection target adapter parse failed device=%s\n", device_path);
	}
	char refresh_unicast[8];
	DWORD refresh_unicast_len = GetEnvironmentVariableA(SYZ_WINDOWS_NET_INJECTION_REFRESH_UNICAST_ENV,
							    refresh_unicast, sizeof(refresh_unicast));
	if (refresh_unicast_len > 0 && refresh_unicast_len < sizeof(refresh_unicast) &&
	    refresh_unicast[0] == '1') {
		InterlockedExchange(&windows_net_injection_refresh_unicast_enabled, 1);
		windows_nyx_log("windows net injection refresh unicast enabled\n");
	}
	char static_neighbor[8];
	DWORD static_neighbor_len = GetEnvironmentVariableA(SYZ_WINDOWS_NET_INJECTION_STATIC_NEIGHBOR_ENV,
							    static_neighbor, sizeof(static_neighbor));
	if (static_neighbor_len > 0 && static_neighbor_len < sizeof(static_neighbor) &&
	    static_neighbor[0] == '1') {
		InterlockedExchange(&windows_net_injection_static_neighbor_enabled, 1);
		windows_nyx_log("windows net injection static neighbor enabled\n");
	}
	ULONG media_status = TRUE;
	DWORD bytes_returned = 0;
	if (!DeviceIoControl(windows_net_injection, SYZ_WINDOWS_TAP_IOCTL_SET_MEDIA_STATUS,
			     &media_status, sizeof(media_status), &media_status, sizeof(media_status),
			     &bytes_returned, NULL)) {
		debug("failed to set windows TAP media status: %u\n", GetLastError());
		windows_nyx_log("failed to set windows TAP media status: %u\n", GetLastError());
		return;
	}
	debug("set windows TAP media status connected\n");
	windows_nyx_log("set windows TAP media status connected\n");
	char firewall_allow[8];
	DWORD firewall_allow_len = GetEnvironmentVariableA(SYZ_WINDOWS_NET_INJECTION_FIREWALL_ALLOW_ENV,
							   firewall_allow, sizeof(firewall_allow));
	char skip_firewall[8];
	DWORD skip_firewall_len = GetEnvironmentVariableA(SYZ_WINDOWS_NET_INJECTION_SKIP_FIREWALL_ENV,
							    skip_firewall, sizeof(skip_firewall));
	bool skip_firewall_enabled = skip_firewall_len > 0 && skip_firewall_len < sizeof(skip_firewall) &&
				     skip_firewall[0] == '1';
	windows_nyx_log("windows net injection firewall allow enabled=%u skip=%u\n",
			(firewall_allow_len > 0 && firewall_allow_len < sizeof(firewall_allow) &&
			 firewall_allow[0] == '1') ? 1U : 0U,
			skip_firewall_enabled ? 1U : 0U);
	if (firewall_allow_len > 0 && firewall_allow_len < sizeof(firewall_allow) &&
	    firewall_allow[0] == '1' && !skip_firewall_enabled) {
		windows_net_injection_allow_firewall_tcp_inbound();
	}
	char skip_init_ipv4[8];
	DWORD skip_init_ipv4_len = GetEnvironmentVariableA(SYZ_WINDOWS_NET_INJECTION_SKIP_INIT_IPV4_ENV,
							    skip_init_ipv4, sizeof(skip_init_ipv4));
	bool skip_init_ipv4_enabled = skip_init_ipv4_len > 0 && skip_init_ipv4_len < sizeof(skip_init_ipv4) &&
				       skip_init_ipv4[0] == '1';
	windows_nyx_log("windows net injection init ipv4 configure enabled=%u\n",
			skip_init_ipv4_enabled ? 0U : 1U);
	if (!skip_init_ipv4_enabled) {
		windows_net_injection_try_configure_local_ipv4();
	}
	windows_net_injection_log_guest_net_state("after-open");
	DWORD settle_ms = windows_net_injection_env_dword(SYZ_WINDOWS_NET_INJECTION_PRE_SNAPSHOT_SETTLE_MS_ENV, 30000);
	if (settle_ms != 0) {
		windows_nyx_log("windows net injection pre-snapshot settle begin ms=%lu\n",
				(unsigned long)settle_ms);
		Sleep(settle_ms);
		windows_nyx_log("windows net injection pre-snapshot settle end ms=%lu\n",
				(unsigned long)settle_ms);
		windows_net_injection_log_guest_net_state("after-settle");
	}
	char background_reader[8];
	DWORD background_reader_len = GetEnvironmentVariableA(SYZ_WINDOWS_NET_INJECTION_BACKGROUND_READER_ENV,
							      background_reader, sizeof(background_reader));
	if (background_reader_len > 0 && background_reader_len < sizeof(background_reader) &&
	    background_reader[0] == '1') {
		HANDLE th = CreateThread(NULL, 128 << 10, windows_net_injection_background_reader, NULL, 0, NULL);
		if (th == NULL) {
			debug("failed to start windows net injection background reader: %u\n", GetLastError());
			windows_nyx_log("failed to start windows net injection background reader: %u\n", GetLastError());
		} else {
			CloseHandle(th);
			InterlockedExchange(&windows_net_injection_background_reader_enabled, 1);
			windows_nyx_log("windows net injection background reader enabled\n");
		}
	}
}
#endif

static long windows_net_injection_write(const void* data, DWORD length)
{
	if (length > sizeof(windows_net_injection_write_buffer)) {
		debug("windows net injection write frame too large length=%u max=%u\n", length, (DWORD)sizeof(windows_net_injection_write_buffer));
		windows_nyx_log("windows net injection write frame too large length=%u max=%u\n", length, (DWORD)sizeof(windows_net_injection_write_buffer));
		return -1;
	}
	memcpy(windows_net_injection_write_buffer, data, length);
	windows_net_injection_log_guest_net_state("before-write");
	windows_net_injection_log_frame_summary("tx", windows_net_injection_write_buffer, length);
	OVERLAPPED ov = {};
	DWORD written = 0;
	ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
	if (ov.hEvent == NULL) {
		debug("windows net injection write event creation failed: %u\n", GetLastError());
		windows_nyx_log("windows net injection write event creation failed: %u\n", GetLastError());
		return -1;
	}
	windows_nyx_log("windows net injection write begin handle=0x%p event=0x%p length=%u buffer=0x%p\n",
			windows_net_injection, ov.hEvent, length, windows_net_injection_write_buffer);
	BOOL ok = WriteFile(windows_net_injection, windows_net_injection_write_buffer, length, &written, &ov);
	DWORD err = ok ? ERROR_SUCCESS : GetLastError();
	windows_nyx_log("windows net injection write issued ok=%u err=%u written=%u\n", ok, err, written);
	if (!ok && err == ERROR_IO_PENDING) {
		DWORD wait = WaitForSingleObject(ov.hEvent, SYZ_WINDOWS_NET_INJECTION_IO_TIMEOUT_MS);
		windows_nyx_log("windows net injection write wait result=%u\n", wait);
		if (wait == WAIT_OBJECT_0) {
			ok = GetOverlappedResult(windows_net_injection, &ov, &written, FALSE);
			err = ok ? ERROR_SUCCESS : GetLastError();
			windows_nyx_log("windows net injection write overlapped result ok=%u err=%u written=%u\n", ok, err, written);
		} else {
			CancelIoEx(windows_net_injection, &ov);
			CloseHandle(ov.hEvent);
			debug("windows net injection write timed out\n");
			windows_nyx_log("windows net injection write timed out\n");
			return -1;
		}
	}
	CloseHandle(ov.hEvent);
	if (!ok) {
		debug("windows net injection write failed: %u\n", err);
		windows_nyx_log("windows net injection write failed: %u length=%u written=%u\n", err, length, written);
		return -1;
	}
	if (written != length) {
		debug("windows net injection short write length=%u written=%u\n", length, written);
		windows_nyx_log("windows net injection short write length=%u written=%u\n", length, written);
		return -1;
	}
	debug("windows net injection tx wrote frame length=%u\n", length);
	windows_nyx_log("windows net injection tx wrote frame length=%u\n", length);
	DWORD settle_ms = windows_net_injection_env_dword(SYZ_WINDOWS_NET_INJECTION_POST_WRITE_SETTLE_MS_ENV, 30000);
	if (settle_ms != 0) {
		windows_nyx_log("windows net injection post-write settle begin ms=%lu\n",
				(unsigned long)settle_ms);
		Sleep(settle_ms);
		windows_nyx_log("windows net injection post-write settle end ms=%lu\n",
				(unsigned long)settle_ms);
	}
	windows_net_injection_log_guest_net_state("after-write");
	return 0;
}

static long windows_net_injection_read(void* data, DWORD length)
{
	return windows_net_injection_read_with_poll(data, length, SYZ_WINDOWS_NET_INJECTION_READ_POLL_MS, true);
}

#if SYZ_EXECUTOR || __NR_syz_emit_ethernet && SYZ_NET_INJECTION
static intptr_t SYSCALLAPI syz_emit_ethernet(intptr_t a0, intptr_t a1, intptr_t, intptr_t, intptr_t, intptr_t,
					     intptr_t, intptr_t, intptr_t, intptr_t)
{
	// syz_emit_ethernet$windows(len len[packet], packet ptr[in, win_vnet_eth_packet])
	windows_nyx_log("windows net injection emit begin length=%lld buffer=0x%llx handle=0x%p\n",
			(long long)a0, (unsigned long long)a1, windows_net_injection);
	if (windows_net_injection == INVALID_HANDLE_VALUE)
		return -1;
	if (a0 <= 0 || a0 > SYZ_WINDOWS_NET_INJECTION_MAX_FRAME_SIZE)
		return -1;

	return windows_net_injection_write((const void*)(uintptr_t)a1, (DWORD)a0);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_extract_tcp_res && SYZ_NET_INJECTION
struct windows_tcp_resources {
	uint32 seq;
	uint32 ack;
};

static intptr_t SYSCALLAPI syz_extract_tcp_res(intptr_t a0, intptr_t a1, intptr_t a2, intptr_t, intptr_t,
					       intptr_t, intptr_t, intptr_t, intptr_t, intptr_t)
{
	// syz_extract_tcp_res$windows(res ptr[out, win_vnet_tcp_resources], seq_inc int32, ack_inc int32)
	NONFAILING(memset((void*)(uintptr_t)a0, 0, sizeof(windows_tcp_resources)));
	if (windows_net_injection == INVALID_HANDLE_VALUE)
		return -1;

	windows_net_injection_log_guest_net_state("before-extract");
	if (InterlockedCompareExchange(&windows_net_injection_background_reader_enabled, 0, 0) &&
	    InterlockedCompareExchange(&windows_net_injection_cached_tcp_valid, 0, 1) == 1) {
		uint32 seq = (uint32)InterlockedCompareExchange(&windows_net_injection_cached_tcp_seq, 0, 0);
		uint32 ack = (uint32)InterlockedCompareExchange(&windows_net_injection_cached_tcp_ack, 0, 0);
		seq += (uint32)a1;
		ack += (uint32)a2;
		NONFAILING(((windows_tcp_resources*)(uintptr_t)a0)->seq = windows_net_host_to_be32(seq));
		NONFAILING(((windows_tcp_resources*)(uintptr_t)a0)->ack = windows_net_host_to_be32(ack));
		debug("windows net injection extracted cached tcp seq=0x%x ack=0x%x\n", seq, ack);
		windows_nyx_log("windows net injection extracted cached tcp seq=0x%x ack=0x%x\n", seq, ack);
		windows_net_injection_log_extract_complete("cached");
		return 0;
	}
	if (InterlockedCompareExchange(&windows_net_injection_background_reader_enabled, 0, 0))
		windows_nyx_log("windows net injection tcp cache miss\n");

	char data[256];
	int read_attempts = (int)windows_net_injection_env_dword(SYZ_WINDOWS_NET_INJECTION_READ_ATTEMPTS_ENV,
								 SYZ_WINDOWS_NET_INJECTION_MAX_READ_ATTEMPTS);
	if (read_attempts == 0)
		read_attempts = SYZ_WINDOWS_NET_INJECTION_READ_ATTEMPTS;
	for (int attempt = 0; attempt < read_attempts; attempt++) {
		long rv = windows_net_injection_read(data, sizeof(data));
		if (rv == SYZ_WINDOWS_NET_INJECTION_READ_TIMEOUT)
			continue;
		if (rv < 0)
			return -1;
		size_t length = (size_t)rv;
		debug_dump_data(data, length);

		uint32 seq = 0;
		uint32 ack = 0;
		if (!windows_net_injection_parse_tcp_frame(data, length, &seq, &ack, "read", attempt))
			continue;
		seq += (uint32)a1;
		ack += (uint32)a2;
		NONFAILING(((windows_tcp_resources*)(uintptr_t)a0)->seq = windows_net_host_to_be32(seq));
		NONFAILING(((windows_tcp_resources*)(uintptr_t)a0)->ack = windows_net_host_to_be32(ack));
		debug("windows net injection extracted tcp seq=0x%x ack=0x%x\n", seq, ack);
		windows_nyx_log("windows net injection extracted tcp seq=0x%x ack=0x%x\n", seq, ack);
		windows_net_injection_log_extract_complete("read");
		return 0;
	}
	debug("windows net injection read found no tcp response after attempts=%d\n", read_attempts);
	windows_nyx_log("windows net injection read found no tcp response after attempts=%d\n", read_attempts);
	return -1;
}
#endif

#else

#if SYZ_EXECUTOR || __NR_syz_emit_ethernet
static intptr_t SYSCALLAPI syz_emit_ethernet(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,
					     intptr_t, intptr_t, intptr_t, intptr_t)
{
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_extract_tcp_res
struct windows_tcp_resources {
	uint32 seq;
	uint32 ack;
};

static intptr_t SYSCALLAPI syz_extract_tcp_res(intptr_t a0, intptr_t, intptr_t, intptr_t, intptr_t,
					       intptr_t, intptr_t, intptr_t, intptr_t, intptr_t)
{
	NONFAILING(memset((void*)(uintptr_t)a0, 0, sizeof(windows_tcp_resources)));
	return -1;
}
#endif

#endif

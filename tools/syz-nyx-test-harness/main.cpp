#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "nyx_api.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

static bool fetch_host_config(host_config_t* cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)cfg);
	if (cfg->host_magic != NYX_HOST_MAGIC || cfg->host_version != NYX_HOST_VERSION) {
		hprintf("bad host config magic/version: magic=0x%x version=%u\n",
			cfg->host_magic, cfg->host_version);
		return false;
	}
	return true;
}

static bool enable_debug_privilege()
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		return false;
	LUID luid = {};
	if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luid)) {
		CloseHandle(token);
		return false;
	}
	TOKEN_PRIVILEGES tp = {};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
	CloseHandle(token);
	return GetLastError() == ERROR_SUCCESS;
}

static bool submit_module_range(const char* module_name, uint32_t filter_index)
{
	enable_debug_privilege();
	ULONG len = 1 << 20;
	auto* modules = (PRTL_PROCESS_MODULES)VirtualAlloc(nullptr, len,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!modules) {
		hprintf("VirtualAlloc modules failed err=%lu\n", GetLastError());
		return false;
	}
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, modules, len, &len);
	if (!NT_SUCCESS(status)) {
		hprintf("NtQuerySystemInformation(SystemModuleInformation) failed status=0x%08lx\n",
			(unsigned long)status);
		VirtualFree(modules, 0, MEM_RELEASE);
		return false;
	}
	alignas(4096) static volatile uint64_t range_submit[3];
	bool ok = false;
	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		char* file_name = (char*)modules->Modules[i].FullPathName +
			modules->Modules[i].OffsetToFileName;
		if (_stricmp(file_name, module_name) != 0)
			continue;
		uint64_t base = (uint64_t)modules->Modules[i].ImageBase;
		uint64_t end = base + modules->Modules[i].ImageSize;
		range_submit[0] = base;
		range_submit[1] = end;
		range_submit[2] = filter_index;
		hprintf("submit range %s: 0x%llx-0x%llx filter=%u\n",
			module_name,
			(unsigned long long)base,
			(unsigned long long)end,
			filter_index);
		kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uintptr_t)&range_submit[0]);
		ok = true;
		break;
	}
	VirtualFree(modules, 0, MEM_RELEASE);
	if (!ok)
		hprintf("module range not found: %s\n", module_name);
	return ok;
}

static uint32_t pick_class(const kAFL_payload* payload)
{
	static const uint32_t classes[] = {
		0,   // SystemBasicInformation
		5,   // SystemProcessInformation
		11,  // SystemModuleInformation
		16,  // SystemHandleInformation
		35,  // SystemKernelDebuggerInformation
		57,  // SystemProcessorPerformanceInformation
	};
	uint32_t seed = 0;
	if (payload->size > 0) {
		size_t n = payload->size < (int32_t)sizeof(seed) ? payload->size : sizeof(seed);
		memcpy(&seed, payload->data, n);
	}
	return classes[seed % (sizeof(classes) / sizeof(classes[0]))];
}

static uint32_t pick_buffer_size(const kAFL_payload* payload)
{
	uint8_t b = payload->size > 4 ? payload->data[4] : 0;
	return 0x1000u << (b & 3);
}

static void execute_payload(kAFL_payload* payload)
{
	uint32_t info_class = pick_class(payload);
	uint32_t buffer_size = pick_buffer_size(payload);
	void* buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buffer)
		habort("VirtualAlloc syscall buffer failed");

	ULONG ret_len = 0;
	kafl_syz_cov_cmd_t cov = {0, 0, 0};

	kAFL_hypercall(HYPERCALL_KAFL_SYZ_COV_RESET, (uintptr_t)&cov);
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)info_class,
		buffer, buffer_size, &ret_len);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_SYZ_COV_DUMP, (uintptr_t)&cov);

	hprintf("NtQuerySystemInformation class=%u size=0x%x status=0x%08lx ret=%lu\n",
		info_class, buffer_size, (unsigned long)status, ret_len);
	VirtualFree(buffer, 0, MEM_RELEASE);
}

int main()
{
	host_config_t host = {};
	if (!fetch_host_config(&host))
		return 1;

	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

	agent_config_t agent = {};
	agent.agent_magic = NYX_AGENT_MAGIC;
	agent.agent_version = NYX_AGENT_VERSION;
	agent.agent_non_reload_mode = 1;
	agent.coverage_bitmap_size = host.bitmap_size;
	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent);

	uint32_t payload_size = host.payload_buffer_size;
	if (payload_size < 0x1000)
		payload_size = 0x1000;
	kAFL_payload* payload = (kAFL_payload*)VirtualAlloc(nullptr, payload_size,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!payload)
		habort("VirtualAlloc payload failed");
	memset(payload, 0, payload_size);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload);

	if (!submit_module_range("ntoskrnl.exe", 0))
		habort("failed to submit ntoskrnl.exe range");

	hprintf("syz-nyx-test-harness ready payload_size=0x%x bitmap=0x%x worker=%u\n",
		host.payload_buffer_size, host.bitmap_size, host.worker_id);

	for (;;) {
		kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
		if (payload->size < 0)
			habort("negative payload size");
		execute_payload(payload);
	}
}

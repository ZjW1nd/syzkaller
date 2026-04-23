// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define NYX_HOST_MAGIC 0x4878794e
#define NYX_AGENT_MAGIC 0x4178794e
#define NYX_HOST_VERSION 2
#define NYX_AGENT_VERSION 1

#define HYPERCALL_KAFL_RAX_ID 0x01f
#define HYPERCALL_KAFL_ACQUIRE 0
#define HYPERCALL_KAFL_GET_PAYLOAD 1
#define HYPERCALL_KAFL_RELEASE 4
#define HYPERCALL_KAFL_SUBMIT_CR3 5
#define HYPERCALL_KAFL_NEXT_PAYLOAD 12
#define HYPERCALL_KAFL_USER_SUBMIT_MODE 17
#define HYPERCALL_KAFL_RANGE_SUBMIT 29
#define HYPERCALL_KAFL_GET_HOST_CONFIG 35
#define HYPERCALL_KAFL_SET_AGENT_CONFIG 36
#define HYPERCALL_KAFL_DUMP_FILE 37
#define HYPERCALL_KAFL_SYZ_COV_RESET 42
#define HYPERCALL_KAFL_SYZ_COV_DUMP 43

#define KAFL_MODE_64 0

#define SYZ_NYX_MSG_MAGIC 0x3158594e
#define SYZ_NYX_MSG_VERSION 1
#define SYZ_NYX_KIND_HANDSHAKE 1
#define SYZ_NYX_KIND_EXEC 2

#define FINDCR3_DEVICE_PATH L"\\\\.\\findCR3"
#define IOCTL_SEND_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_FIND_CR3 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NYX_RESULT_BASENAME "syz_nyx_result.bin"
#define NYX_HANDSHAKE_ACK_BASENAME "syz_nyx_handshake.ok"

typedef struct {
	uint32_t host_magic;
	uint32_t host_version;
	uint32_t bitmap_size;
	uint32_t ijon_bitmap_size;
	uint32_t payload_buffer_size;
	uint32_t worker_id;
} __attribute__((packed)) nyx_host_config_t;

typedef struct {
	uint32_t agent_magic;
	uint32_t agent_version;
	uint8_t agent_timeout_detection;
	uint8_t agent_tracing;
	uint8_t agent_ijon_tracing;
	uint8_t agent_non_reload_mode;
	uint64_t trace_buffer_vaddr;
	uint64_t ijon_trace_buffer_vaddr;
	uint32_t coverage_bitmap_size;
	uint32_t input_buffer_size;
	uint8_t dump_payloads;
} __attribute__((packed)) nyx_agent_config_t;

typedef struct {
	int32_t size;
	uint8_t data[];
} kAFL_payload;

typedef struct {
	uint64_t file_name_str_ptr;
	uint64_t data_ptr;
	uint64_t bytes;
	uint8_t append;
} __attribute__((packed)) kafl_dump_file_t;

typedef struct {
	uint32_t call_index;
	uint32_t slot_id;
	uint64_t flags;
} __attribute__((packed)) kafl_syz_cov_cmd_t;

typedef struct {
	uint32_t magic;
	uint16_t version;
	uint16_t kind;
	uint32_t body_size;
} __attribute__((packed)) nyx_msg_header_t;

typedef struct {
	int64_t request_id;
	int32_t proc_id;
	int32_t reserved;
} __attribute__((packed)) nyx_exec_meta_t;

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

#if defined(__x86_64__)
static inline uint64_t nyx_hypercall(uint64_t p1, uint64_t p2)
{
	uint64_t nr = HYPERCALL_KAFL_RAX_ID;
	asm volatile("vmcall" : "=a"(nr) : "a"(nr), "b"(p1), "c"(p2) : "memory");
	return nr;
}
#else
#error "Nyx Windows mode requires x86_64"
#endif

static bool nyx_dump_bytes(const char* basename, const void* data, uint64_t bytes, bool append)
{
	kafl_dump_file_t req = {
	    .file_name_str_ptr = (uint64_t)(uintptr_t)basename,
	    .data_ptr = (uint64_t)(uintptr_t)data,
	    .bytes = bytes,
	    .append = append,
	};
	nyx_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uint64_t)(uintptr_t)&req);
	return true;
}

static bool nyx_fetch_host_config(nyx_host_config_t* host_config)
{
	memset(host_config, 0, sizeof(*host_config));
	nyx_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uint64_t)(uintptr_t)host_config);
	return host_config->host_magic == NYX_HOST_MAGIC &&
	       host_config->host_version == NYX_HOST_VERSION;
}

static DWORD nyx_system_pid()
{
	DWORD pid = 4;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return pid;
	PROCESSENTRY32W pe = {};
	pe.dwSize = sizeof(pe);
	if (Process32FirstW(snap, &pe)) {
		do {
			if (_wcsicmp(pe.szExeFile, L"System") == 0) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32NextW(snap, &pe));
	}
	CloseHandle(snap);
	return pid;
}

static bool nyx_query_cr3(uint64_t* out_cr3)
{
	HANDLE dev = CreateFileW(FINDCR3_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
				 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
				 FILE_ATTRIBUTE_NORMAL, NULL);
	if (dev == INVALID_HANDLE_VALUE)
		return false;
	DWORD bytes = 0;
	DWORD system_pid = nyx_system_pid();
	BOOL ok = DeviceIoControl(dev, IOCTL_SEND_PID, (LPVOID)(ULONG_PTR)system_pid, 0,
				  NULL, 0, &bytes, NULL);
	if (!ok) {
		CloseHandle(dev);
		return false;
	}
	uint64_t cr3 = 0;
	bytes = 0;
	ok = DeviceIoControl(dev, IOCTL_FIND_CR3, NULL, 0, &cr3, sizeof(cr3), &bytes, NULL);
	CloseHandle(dev);
	if (!ok || bytes < sizeof(cr3))
		return false;
	*out_cr3 = cr3;
	return true;
}

static bool nyx_submit_module_range(const char* module_name)
{
	ULONG len = 1 << 20;
	auto* modules = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
							   PAGE_READWRITE);
	if (!modules)
		return false;
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, modules, len, &len);
	if (!NT_SUCCESS(status)) {
		VirtualFree(modules, 0, MEM_RELEASE);
		return false;
	}
	alignas(4096) static volatile uint64_t range_submit[3];
	bool submitted = false;
	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		char* file_name = (char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;
		if (_stricmp(file_name, module_name) != 0)
			continue;
		uint64_t base = (uint64_t)modules->Modules[i].ImageBase;
		uint64_t end = base + modules->Modules[i].ImageSize;
		range_submit[0] = base;
		range_submit[1] = end;
		range_submit[2] = 0;
		nyx_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uint64_t)(uintptr_t)&range_submit[0]);
		submitted = true;
		break;
	}
	VirtualFree(modules, 0, MEM_RELEASE);
	return submitted;
}

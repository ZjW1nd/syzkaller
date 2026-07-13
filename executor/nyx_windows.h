// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <psapi.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define NYX_HOST_MAGIC 0x4878794e
#define NYX_AGENT_MAGIC 0x4178794e
#define NYX_HOST_VERSION 3
#define NYX_AGENT_VERSION 1

#define HYPERCALL_KAFL_RAX_ID 0x01f
#define HYPERCALL_KAFL_ACQUIRE 0
#define HYPERCALL_KAFL_GET_PAYLOAD 1
#define HYPERCALL_KAFL_RELEASE 4
#define HYPERCALL_KAFL_SUBMIT_CR3 5
#define HYPERCALL_KAFL_NEXT_PAYLOAD 12
#define HYPERCALL_KAFL_PRINTF 13
#define HYPERCALL_KAFL_USER_SUBMIT_MODE 17
#define HYPERCALL_KAFL_RANGE_SUBMIT 29
#define HYPERCALL_KAFL_REQ_STREAM_DATA 30
#define HYPERCALL_KAFL_GET_HOST_CONFIG 35
#define HYPERCALL_KAFL_SET_AGENT_CONFIG 36
#define HYPERCALL_KAFL_DUMP_FILE 37
#define HYPERCALL_KAFL_SYZ_COV_RESET 42
#define HYPERCALL_KAFL_SYZ_COV_DUMP 43
#define HYPERCALL_KAFL_REQUEST_RELOAD 44
#define HYPERCALL_KAFL_SYZ_COV_SESSION_BEGIN 45
#define HYPERCALL_KAFL_SYZ_COV_SESSION_END 46

/* Race detector hypercalls (guest → QEMU) — exit reasons 147-155 */
#define HYPERCALL_KAFL_RACE_ARM_WATCHPOINT 47
#define HYPERCALL_KAFL_RACE_CHECK_WATCHPOINT 48
#define HYPERCALL_KAFL_RACE_REPORT 49
#define HYPERCALL_KAFL_RACE_CONFIG 50
#define HYPERCALL_KAFL_RACE_STALL_CPU 51
#define HYPERCALL_KAFL_RACE_RESUME_CPU 52
#define HYPERCALL_KAFL_RACE_GET_STATUS 53
#define HYPERCALL_KAFL_RACE_START_SAMPLING 54
#define HYPERCALL_KAFL_RACE_STOP_SAMPLING 55

/* Race detector access types for arm_watchpoint */
#define NYX_RACE_ACCESS_WRITE 0
#define NYX_RACE_ACCESS_RW 1

#define KAFL_MODE_64 0
#define HPRINTF_MAX_SIZE 0x1000

#define SYZ_NYX_MSG_MAGIC 0x3158594e
#define SYZ_NYX_MSG_VERSION 1
#define SYZ_NYX_KIND_HANDSHAKE 1
#define SYZ_NYX_KIND_EXEC 2
#define SYZ_NYX_KIND_IDLE 3
#define SYZ_NYX_EXEC_KEEP_STATE (1 << 0)

#define FINDCR3_DEVICE_PATH L"\\\\.\\findCR3"
#define IOCTL_SEND_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_FIND_CR3 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NYX_RESULT_BASENAME "syz_nyx_result.bin"
#define NYX_HANDSHAKE_ACK_BASENAME "syz_nyx_handshake.ok"
#define NYX_MAX_IP_FILTER_RANGES 4
#define NYX_MAX_MODULE_RANGE_TARGETS 16
#define NYX_MODULE_RANGE_PATTERN_SIZE 64
#define NYX_MODULE_RANGE_CONFIG_FILE "syz_nyx_module_ranges.bin"
#define SYZ_NYX_MODULE_CONFIG_MAGIC 0x4d52594e
#define SYZ_NYX_MODULE_CONFIG_VERSION 1

typedef struct {
	uint32_t host_magic;
	uint32_t host_version;
	uint32_t bitmap_size;
	uint32_t ijon_bitmap_size;
	uint32_t payload_buffer_size;
	uint32_t worker_id;
	uint32_t protocol_cpu;
	uint32_t smp_enabled;
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
	uint32_t version;
	uint32_t size;
	uint64_t session_id;
	uint32_t call_index;
	uint32_t slot_id;
	uint64_t flags;
	uint64_t tid;
	uint64_t teb;
} __attribute__((packed)) kafl_syz_cov_session_cmd_t;

#define SYZ_COV_SESSION_VERSION 3u
#define SYZ_COV_FLAG_REQUEST_RESET (1ull << 63)

typedef struct {
	uint32_t magic;
	uint16_t version;
	uint16_t kind;
	uint32_t body_size;
} __attribute__((packed)) nyx_msg_header_t;

typedef struct {
	int64_t request_id;
	int32_t proc_id;
	int32_t flags;
} __attribute__((packed)) nyx_exec_meta_t;

typedef struct {
	uint32_t sleep_ms;
	uint32_t reserved;
} __attribute__((packed)) nyx_idle_meta_t;

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

typedef struct {
	const char* pattern;
	bool required;
} nyx_module_target_t;

typedef struct {
	uint32_t magic;
	uint16_t version;
	uint16_t count;
} __attribute__((packed)) nyx_module_config_header_t;

typedef struct {
	uint8_t required;
	char pattern[NYX_MODULE_RANGE_PATTERN_SIZE];
} __attribute__((packed)) nyx_module_config_entry_t;

#if defined(__x86_64__)
static inline uint64_t nyx_hypercall(uint64_t p1, uint64_t p2)
{
	uint64_t nr = HYPERCALL_KAFL_RAX_ID;
	asm volatile("vmcall"
		     : "=a"(nr)
		     : "a"(nr), "b"(p1), "c"(p2)
		     : "memory");
	return nr;
}

static inline void nyx_hprintf(const char* fmt, ...)
{
	static thread_local char buf[HPRINTF_MAX_SIZE] __attribute__((aligned(4096)));
	va_list args;
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	nyx_hypercall(HYPERCALL_KAFL_PRINTF, (uint64_t)(uintptr_t)buf);
}
#else
#error "Nyx Windows mode requires x86_64"
#endif

/* Race detector hypercall wrappers */
static inline void kafl_race_arm_watchpoint(uint64_t addr, uint32_t access_type)
{
	nyx_hypercall(HYPERCALL_KAFL_RACE_ARM_WATCHPOINT,
		      addr | ((uint64_t)access_type << 48));
}

static inline uint64_t kafl_race_check_watchpoint(void)
{
	return nyx_hypercall(HYPERCALL_KAFL_RACE_CHECK_WATCHPOINT, 0);
}

static inline void kafl_race_config(uint32_t rate, uint32_t delay_us,
				    uint32_t mode, bool enable, uint32_t budget)
{
	uint64_t arg = (uint64_t)rate |
		       ((uint64_t)delay_us << 16) |
		       ((uint64_t)mode << 32) |
		       ((uint64_t)(enable ? 1 : 0) << 40) |
		       ((uint64_t)budget << 41);
	nyx_hypercall(HYPERCALL_KAFL_RACE_CONFIG, arg);
}

/* Start random page sampling (Phase 7) */
static inline void kafl_race_start_sampling(uint32_t batch, uint32_t interval_us,
                                             uint32_t stall_us)
{
	uint64_t arg = (uint64_t)batch |
		       ((uint64_t)interval_us << 16) |
		       ((uint64_t)stall_us << 32);
	nyx_hypercall(HYPERCALL_KAFL_RACE_START_SAMPLING, arg);
}

/* Stop random page sampling */
static inline void kafl_race_stop_sampling(void)
{
	nyx_hypercall(HYPERCALL_KAFL_RACE_STOP_SAMPLING, 0);
}

/*
 * Heuristic: determine whether a syscall argument value looks like a
 * user-space pointer on Windows x64.  Pointers live in the canonical
 * low half (0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF); small
 * integers, handles, flags, and NTSTATUS codes are excluded.
 */
static inline bool nyx_race_arg_is_pointer(uint64_t v)
{
	return v >= 0x10000ULL && v < 0x800000000000ULL;
}

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

static void nyx_pin_protocol_thread(const nyx_host_config_t* host_config, const char* reason)
{
	if (!host_config || !host_config->smp_enabled)
		return;
	if (host_config->protocol_cpu >= sizeof(DWORD_PTR) * 8) {
		nyx_hprintf("nyx protocol thread pin skipped cpu=%u reason=%s\n",
			    host_config->protocol_cpu, reason ? reason : "<none>");
		return;
	}
	DWORD_PTR mask = ((DWORD_PTR)1) << host_config->protocol_cpu;
	if (SetThreadAffinityMask(GetCurrentThread(), mask) == 0) {
		nyx_hprintf("nyx protocol thread pin failed cpu=%u err=%lu reason=%s\n",
			    host_config->protocol_cpu, GetLastError(), reason ? reason : "<none>");
	}
}

static bool nyx_query_cr3(uint64_t* out_cr3)
{
	HANDLE dev = CreateFileW(FINDCR3_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
				 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
				 FILE_ATTRIBUTE_NORMAL, NULL);
	if (dev == INVALID_HANDLE_VALUE)
		return false;
	DWORD bytes = 0;
	DWORD current_pid = GetCurrentProcessId();
	BOOL ok = DeviceIoControl(dev, IOCTL_SEND_PID, (LPVOID)(ULONG_PTR)current_pid, 0,
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

static bool nyx_module_name_matches(const char* file_name, const char* pattern)
{
	const char* star = strchr(pattern, '*');
	if (!star)
		return _stricmp(file_name, pattern) == 0;
	size_t prefix_len = star - pattern;
	const char* suffix = star + 1;
	size_t suffix_len = strlen(suffix);
	size_t file_len = strlen(file_name);
	if (file_len < prefix_len + suffix_len)
		return false;
	if (_strnicmp(file_name, pattern, prefix_len) != 0)
		return false;
	return _stricmp(file_name + file_len - suffix_len, suffix) == 0;
}

static PRTL_PROCESS_MODULES nyx_query_loaded_modules()
{
	ULONG len = 1 << 20;
	for (int attempt = 0; attempt < 2; attempt++) {
		ULONG alloc_len = len;
		auto* modules = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, alloc_len,
								   MEM_COMMIT | MEM_RESERVE,
								   PAGE_READWRITE);
		if (!modules)
			return nullptr;
		NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11,
							   modules, alloc_len, &len);
		if (NT_SUCCESS(status))
			return modules;
		VirtualFree(modules, 0, MEM_RELEASE);
		if (len <= alloc_len)
			len = alloc_len * 2;
	}
	return nullptr;
}

static const nyx_module_target_t* nyx_default_module_targets(size_t* count)
{
	static const nyx_module_target_t targets[] = {
	    {"ntoskrnl.exe", true},
	    {"ntfs.sys", false},
	    {"afd.sys", false},
	    {"win32k*.sys", false},
	};
	*count = sizeof(targets) / sizeof(targets[0]);
	return targets;
}

static int nyx_module_targets_from_bytes(const uint8_t* data, int32_t size,
					 nyx_module_target_t* targets,
					 size_t target_capacity,
					 const nyx_module_target_t** out_targets,
					 size_t* out_count)
{
	if (!data || size < (int32_t)sizeof(nyx_module_config_header_t))
		return 0;
	auto* header = reinterpret_cast<const nyx_module_config_header_t*>(data);
	if (header->magic != SYZ_NYX_MODULE_CONFIG_MAGIC)
		return 0;
	if (header->version != SYZ_NYX_MODULE_CONFIG_VERSION ||
	    header->count == 0 || header->count > target_capacity) {
		nyx_hprintf("nyx module range config invalid version=%u count=%u\n",
			    (unsigned)header->version, (unsigned)header->count);
		return -1;
	}
	uint64_t need = sizeof(*header) +
			(uint64_t)header->count * sizeof(nyx_module_config_entry_t);
	if (need > (uint32_t)size) {
		nyx_hprintf("nyx module range config truncated size=%d need=%llu count=%u\n",
			    (int)size, (unsigned long long)need,
			    (unsigned)header->count);
		return -1;
	}
	auto* entries = reinterpret_cast<const nyx_module_config_entry_t*>(
	    data + sizeof(*header));
	for (uint16_t i = 0; i < header->count; i++) {
		if (entries[i].pattern[0] == 0 ||
		    memchr(entries[i].pattern, 0, sizeof(entries[i].pattern)) == nullptr) {
			nyx_hprintf("nyx module range config bad entry=%u\n", (unsigned)i);
			return -1;
		}
		targets[i] = {
		    .pattern = entries[i].pattern,
		    .required = entries[i].required != 0,
		};
	}
	*out_targets = targets;
	*out_count = header->count;
	return 1;
}

static int nyx_module_targets_from_payload(const kAFL_payload* payload,
					   nyx_module_target_t* targets,
					   size_t target_capacity,
					   const nyx_module_target_t** out_targets,
					   size_t* out_count)
{
	if (!payload)
		return 0;
	return nyx_module_targets_from_bytes(payload->data, payload->size, targets,
					     target_capacity, out_targets, out_count);
}

static int nyx_module_targets_from_sharedir(nyx_module_target_t* targets,
					    size_t target_capacity,
					    const nyx_module_target_t** out_targets,
					    size_t* out_count)
{
	alignas(4096) static uint8_t stream[0x1000];
	memset(stream, 0, sizeof(stream));
	strncpy((char*)stream, NYX_MODULE_RANGE_CONFIG_FILE, sizeof(stream) - 1);
	uint64_t bytes = nyx_hypercall(HYPERCALL_KAFL_REQ_STREAM_DATA,
				       (uint64_t)(uintptr_t)&stream[0]);
	if (bytes == 0 || bytes == 0xffffffffffffffffULL)
		return 0;
	if (bytes > sizeof(stream)) {
		nyx_hprintf("nyx module range config sharedir oversized bytes=%llu\n",
			    (unsigned long long)bytes);
		return -1;
	}
	return nyx_module_targets_from_bytes(stream, (int32_t)bytes, targets,
					     target_capacity, out_targets, out_count);
}

static int nyx_submit_module_range_matches(PRTL_PROCESS_MODULES modules,
					   const nyx_module_target_t* target,
					   int* next_range_id)
{
	alignas(4096) static volatile uint64_t range_submit[3];
	int submitted = 0;
	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		char* file_name = (char*)modules->Modules[i].FullPathName +
				  modules->Modules[i].OffsetToFileName;
		if (!nyx_module_name_matches(file_name, target->pattern))
			continue;
		if (*next_range_id >= NYX_MAX_IP_FILTER_RANGES) {
			nyx_hprintf("nyx module range skipped target=%s name=%s reason=no_filter_slot\n",
				    target->pattern, file_name);
			continue;
		}
		uint64_t base = (uint64_t)modules->Modules[i].ImageBase;
		uint64_t end = base + modules->Modules[i].ImageSize;
		int range_id = (*next_range_id)++;
		range_submit[0] = base;
		range_submit[1] = end;
		range_submit[2] = range_id;
		nyx_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT,
			      (uint64_t)(uintptr_t)&range_submit[0]);
		nyx_hprintf("nyx module range submitted slot=%d target=%s name=%s base=0x%llx end=0x%llx size=0x%llx\n",
			    range_id, target->pattern, file_name,
			    (unsigned long long)base, (unsigned long long)end,
			    (unsigned long long)modules->Modules[i].ImageSize);
		submitted++;
	}
	return submitted;
}

static bool nyx_submit_module_ranges(const kAFL_payload* config_payload)
{
	nyx_module_target_t configured[NYX_MAX_MODULE_RANGE_TARGETS] = {};
	const nyx_module_target_t* targets = nullptr;
	size_t target_count = 0;
	const char* source = nullptr;
	int config_status = nyx_module_targets_from_payload(config_payload, configured,
							    NYX_MAX_MODULE_RANGE_TARGETS,
							    &targets, &target_count);
	if (config_status < 0)
		return false;
	if (config_status > 0) {
		source = "payload";
	} else {
		config_status = nyx_module_targets_from_sharedir(configured,
								 NYX_MAX_MODULE_RANGE_TARGETS,
								 &targets, &target_count);
		if (config_status < 0)
			return false;
		if (config_status > 0)
			source = "sharedir";
	}
	if (config_status > 0) {
		nyx_hprintf("nyx module range config source=%s count=%llu\n",
			    source, (unsigned long long)target_count);
	} else {
		targets = nyx_default_module_targets(&target_count);
		nyx_hprintf("nyx module range config source=default count=%llu\n",
			    (unsigned long long)target_count);
	}
	auto* modules = nyx_query_loaded_modules();
	if (!modules) {
		nyx_hprintf("nyx module range query failed\n");
		return false;
	}
	bool required_ok = true;
	int total = 0;
	int next_range_id = 0;
	for (size_t i = 0; i < target_count; i++) {
		int count = nyx_submit_module_range_matches(modules, &targets[i],
							    &next_range_id);
		total += count;
		if (count == 0) {
			nyx_hprintf("nyx module range missing target=%s required=%d\n",
				    targets[i].pattern, targets[i].required ? 1 : 0);
			if (targets[i].required)
				required_ok = false;
		}
	}
	VirtualFree(modules, 0, MEM_RELEASE);
	nyx_hprintf("nyx module range summary submitted=%d slots=%d required_ok=%d\n",
		    total, next_range_id, required_ok ? 1 : 0);
	return required_ok;
}

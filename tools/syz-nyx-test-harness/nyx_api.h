#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

#define HYPERCALL_KAFL_RAX_ID 0x01f
#define HYPERCALL_KAFL_ACQUIRE 0
#define HYPERCALL_KAFL_GET_PAYLOAD 1
#define HYPERCALL_KAFL_RELEASE 4
#define HYPERCALL_KAFL_SUBMIT_CR3 5
#define HYPERCALL_KAFL_NEXT_PAYLOAD 12
#define HYPERCALL_KAFL_PRINTF 13
#define HYPERCALL_KAFL_USER_SUBMIT_MODE 17
#define HYPERCALL_KAFL_USER_ABORT 20
#define HYPERCALL_KAFL_RANGE_SUBMIT 29
#define HYPERCALL_KAFL_GET_HOST_CONFIG 35
#define HYPERCALL_KAFL_SET_AGENT_CONFIG 36
#define HYPERCALL_KAFL_SYZ_COV_RESET 42
#define HYPERCALL_KAFL_SYZ_COV_DUMP 43

#define KAFL_MODE_64 0
#define HPRINTF_MAX_SIZE 0x1000

#define NYX_HOST_MAGIC 0x4878794e
#define NYX_AGENT_MAGIC 0x4178794e
#define NYX_HOST_VERSION 2
#define NYX_AGENT_VERSION 1

typedef struct {
	int32_t size;
	uint8_t data[];
} kAFL_payload;

typedef struct {
	uint32_t host_magic;
	uint32_t host_version;
	uint32_t bitmap_size;
	uint32_t ijon_bitmap_size;
	uint32_t payload_buffer_size;
	uint32_t worker_id;
} __attribute__((packed)) host_config_t;

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
} __attribute__((packed)) agent_config_t;

typedef struct {
	uint32_t call_index;
	uint32_t slot_id;
	uint64_t flags;
} __attribute__((packed)) kafl_syz_cov_cmd_t;

static inline uint64_t kAFL_hypercall(uint64_t p1, uint64_t p2)
{
	uint64_t nr = HYPERCALL_KAFL_RAX_ID;
	asm volatile("vmcall" : "=a"(nr) : "a"(nr), "b"(p1), "c"(p2) : "memory");
	return nr;
}

static inline void habort(const char* msg)
{
	kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)msg);
}

static inline void hprintf(const char* fmt, ...)
{
	static char buf[HPRINTF_MAX_SIZE] __attribute__((aligned(4096)));
	va_list args;
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uintptr_t)buf);
}

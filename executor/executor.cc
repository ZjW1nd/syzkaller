// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#include <algorithm>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <atomic>
#include <optional>

#if !GOOS_windows
#include <unistd.h>
#endif

#include "defs.h"

#include "pkg/flatrpc/flatrpc.h"

#if defined(__GNUC__) && !GOOS_windows
#define SYSCALLAPI
#define NORETURN __attribute__((noreturn))
#define PRINTF(fmt, args) __attribute__((format(printf, fmt, args)))
#else
// Assuming windows/cl.
#define SYSCALLAPI WINAPI
#define NORETURN __declspec(noreturn)
#define PRINTF(fmt, args)
#define __thread __declspec(thread)
#endif

#ifndef GIT_REVISION
#define GIT_REVISION "unknown"
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
constexpr bool kAddressSanitizer = true;
#else
constexpr bool kAddressSanitizer = false;
#endif

// uint64 is impossible to printf without using the clumsy and verbose "%" PRId64.
// So we define and use uint64. Note: pkg/csource does s/uint64/uint64/.
// Also define uint32/16/8 for consistency.
typedef unsigned long long uint64;
typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;

// Note: zircon max fd is 256.
// Some common_OS.h files know about this constant for RLIMIT_NOFILE.
const int kMaxFd = 250;
const int kFdLimit = 256;
const int kMaxThreads = 32;
const int kInPipeFd = kMaxFd - 1; // remapped from stdin
const int kOutPipeFd = kMaxFd - 2; // remapped from stdout
const int kCoverFd = kOutPipeFd - kMaxThreads;
const int kExtraCoverFd = kCoverFd - 1;
const int kMaxArgs = 11;
const int kCoverSize = 512 << 10;
const int kFailStatus = 67;

// Two approaches of dealing with kcov memory.
const int kCoverOptimizedCount = 8; // the max number of kcov instances
const int kCoverOptimizedPreMmap = 3; // this many will be mmapped inside main(), others - when needed.
const int kCoverDefaultCount = 6; // the max number of kcov instances when delayed kcov mmap is not available

// Logical error (e.g. invalid input program), use as an assert() alternative.
// If such error happens 10+ times in a row, it will be detected as a bug by the runner process.
// The runner will fail and syz-manager will create a bug for this.
// Note: err is used for bug deduplication, thus distinction between err (constant message)
// and msg (varying part).
static NORETURN void fail(const char* err);
static NORETURN PRINTF(2, 3) void failmsg(const char* err, const char* msg, ...);
// Just exit (e.g. due to temporal ENOMEM error).
static NORETURN PRINTF(1, 2) void exitf(const char* msg, ...);
static NORETURN void doexit(int status);
#if !GOOS_fuchsia
static NORETURN void doexit_thread(int status);
#endif

// Print debug output that is visible when running syz-manager/execprog with -debug flag.
// Debug output is supposed to be relatively high-level (syscalls executed, return values, timing, etc)
// and is intended mostly for end users. If you need to debug lower-level details, use debug_verbose
// function and temporary enable it in your build by changing #if 0 below.
// This function does not add \n at the end of msg as opposed to the previous functions.
static PRINTF(1, 2) void debug(const char* msg, ...);
void debug_dump_data(const char* data, int length);

#if 0
#define debug_verbose(...) debug(__VA_ARGS__)
#else
#define debug_verbose(...) (void)0
#endif

static void receive_execute();
static void reply_execute(uint32 status);
static void receive_handshake();
static void setup_coverage();
#if GOOS_windows
static int nyx_mode_loop(int argc, char** argv);
#endif

#if SYZ_EXECUTOR_USES_FORK_SERVER
static void SnapshotPrepareParent();

// Allocating (and forking) virtual memory for each executed process is expensive, so we only mmap
// the amount we might possibly need for the specific received prog.
const int kMaxOutputComparisons = 14 << 20; // executions with comparsions enabled are usually < 1% of all executions
const int kMaxOutputCoverage = 6 << 20; // coverage is needed in ~ up to 1/3 of all executions (depending on corpus rotation)
const int kMaxOutputSignal = 4 << 20;
const int kMinOutput = 256 << 10; // if we don't need to send signal, the output is rather short.
const int kInitialOutput = kMinOutput; // the minimal size to be allocated in the parent process
const int kMaxOutput = kMaxOutputComparisons;
#else
// We don't fork and allocate the memory only once, so prepare for the worst case.
const int kInitialOutput = 14 << 20;
const int kMaxOutput = kInitialOutput;
#endif

// For use with flatrpc bit flags.
template <typename T>
bool IsSet(T flags, T f)
{
	return (flags & f) != T::NONE;
}

// TODO: allocate a smaller amount of memory in the parent once we merge the patches that enable
// prog execution with neither signal nor coverage. Likely 64kb will be enough in that case.

const uint32 kMaxCalls = 64;

struct alignas(8) OutputData {
	std::atomic<uint32> size;
	std::atomic<uint32> consumed;
	std::atomic<uint32> completed;
	std::atomic<uint32> num_calls;
	std::atomic<flatbuffers::Offset<flatbuffers::Vector<uint8_t>>> result_offset;
	struct {
		// Call index in the test program (they may be out-of-order is some syscalls block).
		int index;
		// Offset of the CallInfo object in the output region.
		flatbuffers::Offset<rpc::CallInfoRaw> offset;
	} calls[kMaxCalls];

	void Reset()
	{
		size.store(0, std::memory_order_relaxed);
		consumed.store(0, std::memory_order_relaxed);
		completed.store(0, std::memory_order_relaxed);
		num_calls.store(0, std::memory_order_relaxed);
		result_offset.store(0, std::memory_order_relaxed);
	}
};

// ShmemAllocator/ShmemBuilder help to construct flatbuffers ExecResult reply message in shared memory.
//
// To avoid copying the reply (in particular coverage/signal/comparisons which may be large), the child
// process starts forming CallInfo objects as it handles completion of syscalls, then the top-most runner
// process uses these CallInfo to form an array of them, and adds ProgInfo object with a reference to the array.
// In order to make this possible, OutputData object is placed at the beginning of the shared memory region,
// and it records metadata required to start serialization in one process and continue later in another process.
//
// OutputData::size is the size of the whole shmem region that the child uses (it different size when coverage/
// comparisons are requested). Note that flatbuffers serialization happens from the end of the buffer backwards.
// OutputData::consumed records currently consumed amount memory in the shmem region so that the parent process
// can continue from that point.
// OutputData::completed records number of completed calls (entries in OutputData::calls arrays).
// Flatbuffers identifies everything using offsets in the buffer, OutputData::calls::offset records this offset
// for the call object so that we can use it in the parent process to construct the array of calls.
//
// FlatBufferBuilder generally grows the underlying buffer incrementally as necessary and copying data
// (std::vector style). We cannot do this in the shared memory since we have only a single region.
// To allow serialization into the shared memory region, ShmemBuilder passes initial buffer size which is equal
// to the overall shmem region size (minus OutputData header size) to FlatBufferBuilder, and the custom
// ShmemAllocator allocator. As the result, FlatBufferBuilder does exactly one allocation request
// to ShmemAllocator and never reallocates (if we overflow the buffer and FlatBufferBuilder does another request,
// ShmemAllocator will fail).
class ShmemAllocator : public flatbuffers::Allocator
{
public:
	ShmemAllocator(void* buf, size_t size)
	    : buf_(buf),
	      size_(size)
	{
	}

private:
	void* buf_;
	size_t size_;
	bool allocated_ = false;

	uint8_t* allocate(size_t size) override
	{
		if (allocated_ || size != size_)
			failmsg("bad allocate request", "allocated=%d size=%llu/%llu",
				allocated_, (unsigned long long)size_, (unsigned long long)size);
		allocated_ = true;
		return static_cast<uint8_t*>(buf_);
	}

	void deallocate(uint8_t* p, size_t size) override
	{
		if (!allocated_ || buf_ != p || size_ != size)
			failmsg("bad deallocate request", "allocated=%d buf=%p/%p size=%llu/%llu",
				allocated_, buf_, p, (unsigned long long)size_, (unsigned long long)size);
		allocated_ = false;
	}

	uint8_t* reallocate_downward(uint8_t* old_p, size_t old_size,
				     size_t new_size, size_t in_use_back,
				     size_t in_use_front) override
	{
		fail("can't reallocate");
	}
};

class ShmemBuilder : ShmemAllocator, public flatbuffers::FlatBufferBuilder
{
public:
	ShmemBuilder(OutputData* data, size_t size, bool store_size)
	    : ShmemAllocator(data + 1, size - sizeof(*data)),
	      flatbuffers::FlatBufferBuilder(size - sizeof(*data), this)
	{
		if (store_size)
			data->size.store(size, std::memory_order_relaxed);
		size_t consumed = data->consumed.load(std::memory_order_relaxed);
		if (consumed >= size - sizeof(*data))
			failmsg("ShmemBuilder: too large output offset", "size=%llu consumed=%llu",
				(unsigned long long)size, (unsigned long long)consumed);
		if (consumed)
			flatbuffers::FlatBufferBuilder::buf_.make_space(consumed);
	}
};

const int kInFd = 3;
const int kOutFd = 4;
const int kMaxSignalFd = 5;
const int kCoverFilterFd = 6;
static OutputData* output_data;
static std::optional<ShmemBuilder> output_builder;
static uint32 output_size;
static void mmap_output(uint32 size);
static uint32 hash(uint32 a);
static bool dedup(uint8 index, uint64 sig);

static uint64 start_time_ms = 0;
static bool flag_debug;
static bool flag_snapshot;
static bool flag_coverage;
static bool flag_read_only_coverage;
static bool flag_sandbox_none;
static bool flag_sandbox_setuid;
static bool flag_sandbox_namespace;
static bool flag_sandbox_android;
static bool flag_extra_coverage;
static bool flag_net_injection;
static bool flag_net_devices;
static bool flag_net_reset;
static bool flag_cgroups;
static bool flag_close_fds;
static bool flag_devlink_pci;
static bool flag_nic_vf;
static bool flag_vhci_injection;
static bool flag_wifi;
static bool flag_delay_kcov_mmap;

static bool flag_collect_cover;
static bool flag_collect_signal;
static bool flag_dedup_cover;
static bool flag_threaded;

// If true, then executor should write the comparisons data to fuzzer.
static bool flag_comparisons;

static uint64 request_id;
static rpc::RequestType request_type;
static uint64 all_call_signal;
static bool all_extra_signal;

// Tunable timeouts, received with execute_req.
static uint64 syscall_timeout_ms;
static uint64 program_timeout_ms;
static uint64 slowdown_scale;

// Can be used to disginguish whether we're at the initialization stage
// or we already execute programs.
static bool in_execute_one = false;

#define SYZ_EXECUTOR 1
#include "common.h"
#include "executor_common.h"

const size_t kMaxInput = 4 << 20; // keep in sync with prog.ExecBufferSize
const size_t kMaxCommands = 1000; // prog package knows about this constant (prog.execMaxCommands)

const uint64 instr_eof = -1;
const uint64 instr_copyin = -2;
const uint64 instr_copyout = -3;
const uint64 instr_setprops = -4;

const uint64 arg_const = 0;
const uint64 arg_addr32 = 1;
const uint64 arg_addr64 = 2;
const uint64 arg_result = 3;
const uint64 arg_data = 4;
const uint64 arg_csum = 5;

const uint64 binary_format_native = 0;
const uint64 binary_format_bigendian = 1;
const uint64 binary_format_strdec = 2;
const uint64 binary_format_strhex = 3;
const uint64 binary_format_stroct = 4;

const uint64 no_copyout = -1;

static int running;
static uint32 completed;
static bool is_kernel_64_bit;
static bool use_cover_edges;

static uint8* input_data;

// Checksum kinds.
static const uint64 arg_csum_inet = 0;

// Checksum chunk kinds.
static const uint64 arg_csum_chunk_data = 0;
static const uint64 arg_csum_chunk_const = 1;

typedef intptr_t(SYSCALLAPI* syscall_t)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);

struct call_t {
	const char* name;
	int sys_nr;
	call_attrs_t attrs;
	syscall_t call;
};

struct cover_t {
	int fd;
	uint32 size;
	// mmap_alloc_ptr is the internal pointer to KCOV mapping, possibly with guard pages.
	// It is only used to allocate/deallocate the buffer of mmap_alloc_size.
	char* mmap_alloc_ptr;
	uint32 mmap_alloc_size;
	// data is the pointer to the kcov buffer containing the recorded PCs.
	// data may differ from mmap_alloc_ptr.
	char* data;
	// data_size is set by cover_open(). This is the requested kcov buffer size.
	uint32 data_size;
	// data_end is simply data + data_size.
	char* data_end;
	// Currently collecting comparisons.
	bool collect_comps;
	// Note: On everything but darwin the first value in data is the count of
	// recorded PCs, followed by the PCs. We therefore set data_offset to the
	// size of one PC.
	// On darwin data points to an instance of the ksancov_trace struct. Here we
	// set data_offset to the offset between data and the structs 'pcs' member,
	// which contains the PCs.
	intptr_t data_offset;
	// Note: On everything but darwin this is 0, as the PCs contained in data
	// are already correct. XNUs KSANCOV API, however, chose to always squeeze
	// PCs into 32 bit. To make the recorded PC fit, KSANCOV substracts a fixed
	// offset (VM_MIN_KERNEL_ADDRESS for AMD64) and then truncates the result to
	// uint32_t. We get this from the 'offset' member in ksancov_trace.
	intptr_t pc_offset;
	// The coverage buffer has overflowed and we have truncated coverage.
	bool overflow;
	// True if cover_enable() was called for this object.
	bool enabled;
};

struct thread_t {
	int id;
	bool created;
	event_t ready;
	event_t done;
	event_t idle;
	uint8* copyout_pos;
	uint64 copyout_index;
	bool executing;
	uint64 handoff_seq;
	uint64 worker_tid;
	uint64 worker_wait_seq;
	int call_index;
	int call_num;
	int num_args;
	intptr_t args[kMaxArgs];
	call_props_t call_props;
	intptr_t res;
	uint32 reserrno;
	bool fault_injected;
	cover_t cov;
	bool soft_fail_state;
};

static thread_t threads[kMaxThreads];
static thread_t* last_scheduled;
// Threads use this variable to access information about themselves.
static __thread struct thread_t* current_thread;

static cover_t extra_cov;
static bool coverage_initialized;

struct res_t {
	bool executed;
	uint64 val;
};

static res_t results[kMaxCommands];

const uint64 kInMagic = 0xbadc0ffeebadface;

struct handshake_req {
	uint64 magic;
	bool use_cover_edges;
	bool is_kernel_64_bit;
	rpc::ExecEnv flags;
	uint64 pid;
	uint64 sandbox_arg;
	uint64 syscall_timeout_ms;
	uint64 program_timeout_ms;
	uint64 slowdown_scale;
};

struct execute_req {
	uint64 magic;
	uint64 id;
	rpc::RequestType type;
	uint64 exec_flags;
	uint64 all_call_signal;
	bool all_extra_signal;
};

struct execute_reply {
	uint32 magic;
	uint32 done;
	uint32 status;
};

enum {
	KCOV_CMP_CONST = 1,
	KCOV_CMP_SIZE1 = 0,
	KCOV_CMP_SIZE2 = 2,
	KCOV_CMP_SIZE4 = 4,
	KCOV_CMP_SIZE8 = 6,
	KCOV_CMP_SIZE_MASK = 6,
};

struct kcov_comparison_t {
	// Note: comparisons are always 64-bits regardless of kernel bitness.
	uint64 type;
	uint64 arg1;
	uint64 arg2;
	uint64 pc;
};

typedef char kcov_comparison_size[sizeof(kcov_comparison_t) == 4 * sizeof(uint64) ? 1 : -1];

struct feature_t {
	rpc::Feature id;
	const char* (*setup)();
};

static thread_t* schedule_call(int call_index, int call_num, uint64 copyout_index, uint64 num_args, uint64* args, uint8* pos, call_props_t call_props);
static void handle_completion(thread_t* th);
static void copyout_call_results(thread_t* th);
static void write_call_output(thread_t* th, bool finished);
static void write_extra_output();
static void execute_call(thread_t* th);
static void thread_create(thread_t* th, int id, bool need_coverage);
static void thread_mmap_cover(thread_t* th);
static void* worker_thread(void* arg);
static uint64 read_input(uint8** input_posp, bool peek = false);
static uint64 read_arg(uint8** input_posp);
static uint64 read_const_arg(uint8** input_posp, uint64* size_p, uint64* bf, uint64* bf_off_p, uint64* bf_len_p);
static uint64 read_result(uint8** input_posp);
static uint64 swap(uint64 v, uint64 size, uint64 bf);
static void copyin(char* addr, uint64 val, uint64 size, uint64 bf, uint64 bf_off, uint64 bf_len);
static bool copyout(char* addr, uint64 size, uint64* res);
static void setup_control_pipes();
static bool coverage_filter(uint64 pc);
static rpc::ComparisonRaw convert(const kcov_comparison_t& cmp);
static flatbuffers::span<uint8_t> finish_output(OutputData* output, int proc_id, uint64 req_id, uint32 num_calls,
						uint64 elapsed, uint64 freshness, uint32 status, bool hanged,
						const std::vector<uint8_t>* process_output);
static void parse_execute(const execute_req& req);
static void parse_handshake(const handshake_req& req);

static void mmap_input();

#if GOOS_windows
#include <bcrypt.h>
#include <commdlg.h>
#include <imm.h>
#include <lzexpand.h>
#include <mswsock.h>
#include <ncrypt.h>
#include <ole2.h>
#include <oleauto.h>
#include <rpc.h>
#include <rpcndr.h>
#include <shellapi.h>
#include <urlmon.h>
#include <wincrypt.h>
#include <windows.h>
#include <winscard.h>
#include <winsock2.h>
#include <winspool.h>
#include <winternl.h>
#include <ws2tcpip.h>

extern "C" {
NTSTATUS NTAPI NtCancelIoFileEx(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);
NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
				     PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
}

static bool windows_winsock_extension(SOCKET s, const GUID& guid, void** out)
{
	DWORD bytes = 0;
	*out = nullptr;
	return WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, const_cast<GUID*>(&guid),
			sizeof(guid), out, sizeof(*out), &bytes, nullptr, nullptr) == 0 &&
	       *out != nullptr;
}

static intptr_t SYSCALLAPI ConnectEx(intptr_t s, intptr_t name, intptr_t namelen,
				     intptr_t send_buf, intptr_t send_len, intptr_t bytes_sent,
				     intptr_t overlapped, intptr_t, intptr_t, intptr_t);
static intptr_t SYSCALLAPI DisconnectEx(intptr_t s, intptr_t overlapped, intptr_t flags,
					intptr_t reserved, intptr_t, intptr_t, intptr_t,
					intptr_t, intptr_t, intptr_t);

static void windows_log_sockaddr_state(const char* op, SOCKET s, const struct sockaddr* addr,
				       int namelen)
{
	if (addr == nullptr) {
		nyx_hprintf("windows socket state %s socket=0x%llx addr=null namelen=%d\n",
			    op, (unsigned long long)s, namelen);
		return;
	}
	if (namelen >= (int)sizeof(struct sockaddr_in) && addr->sa_family == AF_INET) {
		const struct sockaddr_in* in = (const struct sockaddr_in*)addr;
		uint32 ip = ntohl(in->sin_addr.s_addr);
		nyx_hprintf("windows socket state %s socket=0x%llx family=AF_INET addr=%u.%u.%u.%u port=%u namelen=%d\n",
			    op, (unsigned long long)s, (ip >> 24) & 0xff, (ip >> 16) & 0xff,
			    (ip >> 8) & 0xff, ip & 0xff, (unsigned)ntohs(in->sin_port),
			    namelen);
		return;
	}
	nyx_hprintf("windows socket state %s socket=0x%llx family=%u namelen=%d\n", op,
		    (unsigned long long)s, (unsigned)addr->sa_family, namelen);
}

static void windows_log_getsockname_state(const char* op, SOCKET s)
{
	struct sockaddr_storage storage = {};
	int len = sizeof(storage);
	if (getsockname(s, (struct sockaddr*)&storage, &len) == 0) {
		windows_log_sockaddr_state(op, s, (const struct sockaddr*)&storage, len);
		return;
	}
	nyx_hprintf("windows socket state %s socket=0x%llx getsockname failed wsa=%d errno=%d\n",
		    op, (unsigned long long)s, WSAGetLastError(), errno);
}

static int windows_wsa_error_to_errno(int wsa)
{
	switch (wsa) {
	case WSAEADDRINUSE:
		return EADDRINUSE;
	case WSAEADDRNOTAVAIL:
		return EADDRNOTAVAIL;
	case WSAEAFNOSUPPORT:
		return EAFNOSUPPORT;
	case WSAEINVAL:
		return EINVAL;
	case WSAENOTSOCK:
		return ENOTSOCK;
	case WSAEOPNOTSUPP:
		return EOPNOTSUPP;
	default:
		return EINVAL;
	}
}

static intptr_t SYSCALLAPI windows_bind_state(intptr_t s, intptr_t addr, intptr_t namelen,
					      intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,
					      intptr_t, intptr_t)
{
	SOCKET socket = (SOCKET)s;
	const struct sockaddr* name = (const struct sockaddr*)addr;
	windows_log_sockaddr_state("bind input", socket, name, (int)namelen);
	WSASetLastError(0);
	errno = 0;
	if (bind(socket, name, (int)namelen) == 0) {
		windows_log_getsockname_state("bind result", socket);
		nyx_hprintf("windows socket state bind ok socket=0x%llx\n",
			    (unsigned long long)socket);
		return s;
	}
	int wsa = WSAGetLastError();
	errno = windows_wsa_error_to_errno(wsa);
	nyx_hprintf("windows socket state bind failed socket=0x%llx wsa=%d errno=%d\n",
		    (unsigned long long)socket, wsa, errno);
	return -1;
}

static intptr_t SYSCALLAPI windows_connect_state(intptr_t s, intptr_t name, intptr_t namelen,
						 intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,
						 intptr_t, intptr_t)
{
	return connect((SOCKET)s, (const struct sockaddr*)name, (int)namelen) == 0 ? s : -1;
}

static bool windows_ntstatus_resource_success(NTSTATUS status)
{
	return NT_SUCCESS(status) || status == STATUS_PENDING;
}

static intptr_t windows_ntstatus_resource_result(NTSTATUS status, intptr_t resource)
{
	if (windows_ntstatus_resource_success(status)) {
		errno = 0;
		return resource;
	}
	errno = EIO;
	return -1;
}

static intptr_t SYSCALLAPI windows_nt_device_io_control_file_state(
    intptr_t file_handle, intptr_t event, intptr_t apc_routine, intptr_t apc_context,
    intptr_t io_status_block, intptr_t io_control_code, intptr_t input_buffer,
    intptr_t input_buffer_length, intptr_t output_buffer, intptr_t output_buffer_length)
{
	errno = 0;
	NTSTATUS status = NtDeviceIoControlFile((HANDLE)file_handle, (HANDLE)event,
						(PIO_APC_ROUTINE)apc_routine,
						(PVOID)apc_context,
						(PIO_STATUS_BLOCK)io_status_block,
						(ULONG)io_control_code,
						(PVOID)input_buffer,
						(ULONG)input_buffer_length,
						(PVOID)output_buffer,
						(ULONG)output_buffer_length);
	return windows_ntstatus_resource_result(status, file_handle);
}

static intptr_t SYSCALLAPI windows_nt_device_io_control_file_input_handle8_state(
    intptr_t file_handle, intptr_t event, intptr_t apc_routine, intptr_t apc_context,
    intptr_t io_status_block, intptr_t io_control_code, intptr_t input_buffer,
    intptr_t input_buffer_length, intptr_t output_buffer, intptr_t output_buffer_length)
{
	errno = 0;
	NTSTATUS status = NtDeviceIoControlFile((HANDLE)file_handle, (HANDLE)event,
						(PIO_APC_ROUTINE)apc_routine,
						(PVOID)apc_context,
						(PIO_STATUS_BLOCK)io_status_block,
						(ULONG)io_control_code,
						(PVOID)input_buffer,
						(ULONG)input_buffer_length,
						(PVOID)output_buffer,
						(ULONG)output_buffer_length);
	if (!windows_ntstatus_resource_success(status)) {
		errno = EIO;
		return -1;
	}
	if (!input_buffer || input_buffer_length < 16) {
		errno = EFAULT;
		return -1;
	}
	errno = 0;
	return *(intptr_t*)(input_buffer + 8);
}

static intptr_t SYSCALLAPI windows_nt_device_io_control_file_input_handle16_state(
    intptr_t file_handle, intptr_t event, intptr_t apc_routine, intptr_t apc_context,
    intptr_t io_status_block, intptr_t io_control_code, intptr_t input_buffer,
    intptr_t input_buffer_length, intptr_t output_buffer, intptr_t output_buffer_length)
{
	errno = 0;
	NTSTATUS status = NtDeviceIoControlFile((HANDLE)file_handle, (HANDLE)event,
						(PIO_APC_ROUTINE)apc_routine,
						(PVOID)apc_context,
						(PIO_STATUS_BLOCK)io_status_block,
						(ULONG)io_control_code,
						(PVOID)input_buffer,
						(ULONG)input_buffer_length,
						(PVOID)output_buffer,
						(ULONG)output_buffer_length);
	if (!windows_ntstatus_resource_success(status)) {
		errno = EIO;
		return -1;
	}
	if (!input_buffer || input_buffer_length < 24) {
		errno = EFAULT;
		return -1;
	}
	errno = 0;
	return *(intptr_t*)(input_buffer + 16);
}

static intptr_t SYSCALLAPI windows_nt_device_io_control_file_output_int32_state(
    intptr_t file_handle, intptr_t event, intptr_t apc_routine, intptr_t apc_context,
    intptr_t io_status_block, intptr_t io_control_code, intptr_t input_buffer,
    intptr_t input_buffer_length, intptr_t output_buffer, intptr_t output_buffer_length)
{
	errno = 0;
	NTSTATUS status = NtDeviceIoControlFile((HANDLE)file_handle, (HANDLE)event,
						(PIO_APC_ROUTINE)apc_routine,
						(PVOID)apc_context,
						(PIO_STATUS_BLOCK)io_status_block,
						(ULONG)io_control_code,
						(PVOID)input_buffer,
						(ULONG)input_buffer_length,
						(PVOID)output_buffer,
						(ULONG)output_buffer_length);
	if (!NT_SUCCESS(status)) {
		errno = EIO;
		return -1;
	}
	if (!output_buffer || output_buffer_length < 4) {
		errno = EFAULT;
		return -1;
	}
	errno = 0;
	return *(int32_t*)output_buffer;
}

static intptr_t SYSCALLAPI windows_listen_state(intptr_t s, intptr_t backlog, intptr_t,
						intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,
						intptr_t, intptr_t)
{
	SOCKET socket = (SOCKET)s;
	windows_log_getsockname_state("listen before", socket);
	WSASetLastError(0);
	errno = 0;
	if (listen(socket, (int)backlog) == 0) {
		windows_log_getsockname_state("listen result", socket);
		nyx_hprintf("windows socket state listen ok socket=0x%llx backlog=%lld\n",
			    (unsigned long long)socket, (long long)backlog);
		return s;
	}
	int wsa = WSAGetLastError();
	errno = windows_wsa_error_to_errno(wsa);
	nyx_hprintf("windows socket state listen failed socket=0x%llx backlog=%lld wsa=%d errno=%d\n",
		    (unsigned long long)socket, (long long)backlog, wsa, errno);
	return -1;
}

static intptr_t SYSCALLAPI windows_accept_ex_state(intptr_t listen_socket, intptr_t accept_socket,
						   intptr_t out_buf, intptr_t recv_len,
						   intptr_t local_len, intptr_t remote_len,
						   intptr_t bytes, intptr_t overlapped,
						   intptr_t, intptr_t)
{
	if (AcceptEx((SOCKET)listen_socket, (SOCKET)accept_socket, (PVOID)out_buf,
		     (DWORD)recv_len, (DWORD)local_len, (DWORD)remote_len, (LPDWORD)bytes,
		     (LPOVERLAPPED)overlapped))
		return accept_socket;
	if (WSAGetLastError() == ERROR_IO_PENDING)
		return accept_socket;
	return -1;
}

static intptr_t SYSCALLAPI windows_update_accept_context_state(intptr_t s, intptr_t level,
							       intptr_t optname, intptr_t optval,
							       intptr_t optlen, intptr_t,
							       intptr_t, intptr_t, intptr_t,
							       intptr_t)
{
	return setsockopt((SOCKET)s, (int)level, (int)optname, (const char*)optval,
			  (int)optlen) == 0
		   ? s
		   : -1;
}

static intptr_t SYSCALLAPI windows_update_connect_context_state(intptr_t s, intptr_t level,
								intptr_t optname, intptr_t optval,
								intptr_t optlen, intptr_t,
								intptr_t, intptr_t, intptr_t,
								intptr_t)
{
	return setsockopt((SOCKET)s, (int)level, (int)optname, (const char*)optval,
			  (int)optlen) == 0
		   ? s
		   : -1;
}

static intptr_t SYSCALLAPI windows_wsa_recv_state(intptr_t s, intptr_t buffers,
						  intptr_t buffer_count, intptr_t bytes,
						  intptr_t flags, intptr_t overlapped,
						  intptr_t completion, intptr_t,
						  intptr_t, intptr_t)
{
	if (WSARecv((SOCKET)s, (LPWSABUF)buffers, (DWORD)buffer_count, (LPDWORD)bytes,
		    (LPDWORD)flags, (LPWSAOVERLAPPED)overlapped,
		    (LPWSAOVERLAPPED_COMPLETION_ROUTINE)completion) == 0)
		return s;
	if (WSAGetLastError() == WSA_IO_PENDING)
		return s;
	return -1;
}

static intptr_t SYSCALLAPI windows_wsa_send_state(intptr_t s, intptr_t buffers,
						  intptr_t buffer_count, intptr_t bytes,
						  intptr_t flags, intptr_t overlapped,
						  intptr_t completion, intptr_t,
						  intptr_t, intptr_t)
{
	if (WSASend((SOCKET)s, (LPWSABUF)buffers, (DWORD)buffer_count, (LPDWORD)bytes,
		    (DWORD)flags, (LPWSAOVERLAPPED)overlapped,
		    (LPWSAOVERLAPPED_COMPLETION_ROUTINE)completion) == 0)
		return s;
	if (WSAGetLastError() == WSA_IO_PENDING)
		return s;
	return -1;
}

static intptr_t SYSCALLAPI windows_shutdown_state(intptr_t s, intptr_t how, intptr_t,
						  intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,
						  intptr_t, intptr_t)
{
	return shutdown((SOCKET)s, (int)how) == 0 ? s : -1;
}

static intptr_t SYSCALLAPI windows_connect_ex_state(intptr_t s, intptr_t name, intptr_t namelen,
						    intptr_t send_buf, intptr_t send_len,
						    intptr_t bytes_sent, intptr_t overlapped,
						    intptr_t, intptr_t, intptr_t)
{
	if (ConnectEx(s, name, namelen, send_buf, send_len, bytes_sent, overlapped, 0, 0, 0))
		return s;
	if (WSAGetLastError() == ERROR_IO_PENDING)
		return s;
	return -1;
}

static intptr_t SYSCALLAPI windows_disconnect_ex_state(intptr_t s, intptr_t overlapped,
						       intptr_t flags, intptr_t reserved,
						       intptr_t, intptr_t, intptr_t, intptr_t,
						       intptr_t, intptr_t)
{
	if (DisconnectEx(s, overlapped, flags, reserved, 0, 0, 0, 0, 0, 0))
		return s;
	if (WSAGetLastError() == ERROR_IO_PENDING)
		return s;
	return -1;
}

static intptr_t SYSCALLAPI windows_create_iocp_socket(intptr_t file_handle, intptr_t existing_iocp,
						      intptr_t completion_key, intptr_t threads,
						      intptr_t, intptr_t, intptr_t, intptr_t,
						      intptr_t, intptr_t)
{
	return (intptr_t)CreateIoCompletionPort((HANDLE)file_handle, (HANDLE)existing_iocp,
						(ULONG_PTR)completion_key, (DWORD)threads);
}

static intptr_t SYSCALLAPI windows_get_queued_completion_status(intptr_t iocp,
								intptr_t bytes,
								intptr_t key,
								intptr_t overlapped,
								intptr_t timeout,
								intptr_t, intptr_t,
								intptr_t, intptr_t,
								intptr_t)
{
	return GetQueuedCompletionStatus((HANDLE)iocp, (LPDWORD)bytes, (PULONG_PTR)key,
					 (LPOVERLAPPED*)overlapped, (DWORD)timeout);
}

static intptr_t SYSCALLAPI windows_wsa_get_overlapped_result_state(intptr_t s,
								   intptr_t overlapped,
								   intptr_t bytes,
								   intptr_t wait,
								   intptr_t flags,
								   intptr_t, intptr_t,
								   intptr_t, intptr_t,
								   intptr_t)
{
	return WSAGetOverlappedResult((SOCKET)s, (LPWSAOVERLAPPED)overlapped,
				      (LPDWORD)bytes, (BOOL)wait, (LPDWORD)flags)
		   ? s
		   : -1;
}

static intptr_t SYSCALLAPI windows_cancel_io_ex(intptr_t handle, intptr_t overlapped,
						intptr_t, intptr_t, intptr_t, intptr_t,
						intptr_t, intptr_t, intptr_t, intptr_t)
{
	return CancelIoEx((HANDLE)handle, (LPOVERLAPPED)overlapped);
}

static intptr_t SYSCALLAPI windows_cancel_io(intptr_t handle, intptr_t, intptr_t, intptr_t,
					     intptr_t, intptr_t, intptr_t, intptr_t,
					     intptr_t, intptr_t)
{
	return CancelIo((HANDLE)handle);
}

static intptr_t SYSCALLAPI ConnectEx(intptr_t s, intptr_t name, intptr_t namelen,
				     intptr_t send_buf, intptr_t send_len, intptr_t bytes_sent,
				     intptr_t overlapped, intptr_t, intptr_t, intptr_t)
{
	static const GUID guid = WSAID_CONNECTEX;
	void* fn = nullptr;
	if (!windows_winsock_extension((SOCKET)s, guid, &fn))
		return FALSE;
	return ((LPFN_CONNECTEX)fn)((SOCKET)s, (const struct sockaddr*)name, (int)namelen,
				    (PVOID)send_buf, (DWORD)send_len, (LPDWORD)bytes_sent,
				    (LPOVERLAPPED)overlapped);
}

static intptr_t SYSCALLAPI DisconnectEx(intptr_t s, intptr_t overlapped, intptr_t flags,
					intptr_t reserved, intptr_t, intptr_t, intptr_t,
					intptr_t, intptr_t, intptr_t)
{
	static const GUID guid = WSAID_DISCONNECTEX;
	void* fn = nullptr;
	if (!windows_winsock_extension((SOCKET)s, guid, &fn))
		return FALSE;
	return ((LPFN_DISCONNECTEX)fn)((SOCKET)s, (LPOVERLAPPED)overlapped, (DWORD)flags,
				       (DWORD)reserved);
}

static intptr_t SYSCALLAPI TransmitPackets(intptr_t s, intptr_t packets, intptr_t count,
					   intptr_t send_size, intptr_t overlapped, intptr_t flags,
					   intptr_t, intptr_t, intptr_t, intptr_t)
{
	static const GUID guid = WSAID_TRANSMITPACKETS;
	void* fn = nullptr;
	if (!windows_winsock_extension((SOCKET)s, guid, &fn))
		return FALSE;
	return ((LPFN_TRANSMITPACKETS)fn)((SOCKET)s, (LPTRANSMIT_PACKETS_ELEMENT)packets,
					  (DWORD)count, (DWORD)send_size,
					  (LPOVERLAPPED)overlapped, (DWORD)flags);
}

static intptr_t SYSCALLAPI WSARecvMsg(intptr_t s, intptr_t msg, intptr_t bytes,
				      intptr_t overlapped, intptr_t completion, intptr_t,
				      intptr_t, intptr_t, intptr_t, intptr_t)
{
	static const GUID guid = WSAID_WSARECVMSG;
	void* fn = nullptr;
	if (!windows_winsock_extension((SOCKET)s, guid, &fn))
		return SOCKET_ERROR;
	return ((LPFN_WSARECVMSG)fn)((SOCKET)s, (LPWSAMSG)msg, (LPDWORD)bytes,
				     (LPWSAOVERLAPPED)overlapped,
				     (LPWSAOVERLAPPED_COMPLETION_ROUTINE)completion);
}
#endif

#if GOOS_windows && SYZ_NYX_WINDOWS_SPARSE_TABLE
#include "syscalls_windows_nyx_demo.h"
#else
#include "syscalls.h"
#endif

#if GOOS_linux
#include "executor_linux.h"
#elif GOOS_fuchsia
#include "executor_fuchsia.h"
#elif GOOS_freebsd || GOOS_netbsd || GOOS_openbsd
#include "executor_bsd.h"
#elif GOOS_darwin
#include "executor_darwin.h"
#elif GOOS_windows
#include "executor_windows.h"
#include "nyx_windows.h"
#elif GOOS_test
#include "executor_test.h"
#else
#error "unknown OS"
#endif

#if GOOS_windows
static const uint64 kWindowsWorkerIdleYields = 1 << 15;
static const uint64 kWindowsWorkerIdleWaitMs = 2;
static const uint64 kWindowsWorkerIdleDrainWaitMs = 50;

static void nyx_log_exec_preview(const uint8* prog_data, uint32 prog_size)
{
#if SYZ_NYX_WINDOWS_DEMO
	(void)prog_data;
	(void)prog_size;
	return;
#else
	if (!prog_data || prog_size == 0) {
		nyx_hprintf("nyx exec preview: empty program data\n");
		return;
	}
	uint8* pos = const_cast<uint8*>(prog_data);
	uint64 total_calls = read_input(&pos);
	uint64 call_num = read_input(&pos, true);
	if (call_num == instr_eof) {
		nyx_hprintf("nyx exec preview: total_calls=%llu first=eof\n",
			    (unsigned long long)total_calls);
		return;
	}
	if (call_num == instr_copyin || call_num == instr_copyout || call_num == instr_setprops) {
		nyx_hprintf("nyx exec preview: total_calls=%llu first_instr=%llu\n",
			    (unsigned long long)total_calls,
			    (unsigned long long)call_num);
		return;
	}
	const char* name = "<invalid>";
	if (call_num < ARRAY_SIZE(syscalls) && syscalls[call_num].name)
		name = syscalls[call_num].name;
	read_input(&pos); // syscall number
	uint64 copyout_index = read_input(&pos);
	uint64 num_args = read_input(&pos);
	uint64 args[kMaxArgs] = {};
	uint64 limit = num_args > kMaxArgs ? kMaxArgs : num_args;
	for (uint64 i = 0; i < limit; i++)
		args[i] = read_arg(&pos);
	nyx_hprintf("nyx exec preview: total_calls=%llu call=%llu name=%s copyout=%llu nargs=%llu args=[0x%llx,0x%llx,0x%llx,0x%llx]\n",
		    (unsigned long long)total_calls,
		    (unsigned long long)call_num,
		    name,
		    (unsigned long long)copyout_index,
		    (unsigned long long)num_args,
		    (unsigned long long)args[0],
		    (unsigned long long)args[1],
		    (unsigned long long)args[2],
		    (unsigned long long)args[3]);
#endif
}

static void nyx_log_exec_stage(const char* stage, uint64 a0 = 0, uint64 a1 = 0, uint64 a2 = 0,
			       uint64 a3 = 0)
{
#if SYZ_NYX_WINDOWS_DEMO
	(void)stage;
	(void)a0;
	(void)a1;
	(void)a2;
	(void)a3;
	return;
#else
	int call_index = -1;
	int call_num = -1;
	const char* call_name = "<none>";
	if (current_thread && current_thread->executing) {
		call_index = current_thread->call_index;
		call_num = current_thread->call_num;
		if (call_num >= 0 && (uint64)call_num < ARRAY_SIZE(syscalls) && syscalls[call_num].name)
			call_name = syscalls[call_num].name;
	}
	nyx_hprintf("nyx exec execute_one request=%llu guest_ms=%llu tid=%lu stage=%s call_index=%d call_num=%d call_name=%s a0=0x%llx a1=0x%llx a2=0x%llx a3=0x%llx\n",
		    (unsigned long long)request_id,
		    (unsigned long long)current_time_ms(),
		    (unsigned long)GetCurrentThreadId(),
		    stage,
		    call_index,
		    call_num,
		    call_name,
		    (unsigned long long)a0,
		    (unsigned long long)a1,
		    (unsigned long long)a2,
		    (unsigned long long)a3);
#endif
}

static void nyx_log_thread_stage(const char* stage, const thread_t* th, uint64 a0 = 0,
				 uint64 a1 = 0, uint64 a2 = 0, uint64 a3 = 0)
{
#if SYZ_NYX_WINDOWS_DEMO
	(void)stage;
	(void)th;
	(void)a0;
	(void)a1;
	(void)a2;
	(void)a3;
	return;
#else
	int call_index = -1;
	int call_num = -1;
	const char* call_name = "<none>";
	if (th) {
		call_index = th->call_index;
		call_num = th->call_num;
		if (call_num >= 0 && (uint64)call_num < ARRAY_SIZE(syscalls) && syscalls[call_num].name)
			call_name = syscalls[call_num].name;
	}
	nyx_hprintf("nyx exec execute_one request=%llu guest_ms=%llu tid=%lu stage=%s call_index=%d call_num=%d call_name=%s a0=0x%llx a1=0x%llx a2=0x%llx a3=0x%llx\n",
		    (unsigned long long)request_id,
		    (unsigned long long)current_time_ms(),
		    (unsigned long)GetCurrentThreadId(),
		    stage,
		    call_index,
		    call_num,
		    call_name,
		    (unsigned long long)a0,
		    (unsigned long long)a1,
		    (unsigned long long)a2,
		    (unsigned long long)a3);
#endif
}

static int windows_yield_until_event(event_t* ev, uint64 max_yields, uint64 max_wait_ms)
{
	uint64 deadline_ms = current_time_ms() + max_wait_ms;
	for (uint64 i = 0; i < max_yields; i++) {
		if (event_isset(ev))
			return 1;
		if (current_time_ms() >= deadline_ms)
			break;
		if (!SwitchToThread())
			Sleep(0);
	}
	return event_isset(ev);
}

static void windows_drain_worker_idle_before_nyx_result()
{
	if (!flag_threaded)
		return;
	for (int i = 0; i < kMaxThreads; i++) {
		thread_t* th = &threads[i];
		if (!th->created || th->executing)
			continue;
		nyx_log_thread_stage("nyx_worker_idle_drain_begin", th,
				     event_isset(&th->idle), th->handoff_seq,
				     th->worker_wait_seq);
		int idle_seen = windows_yield_until_event(&th->idle, kWindowsWorkerIdleYields,
							  kWindowsWorkerIdleDrainWaitMs);
		nyx_log_thread_stage("nyx_worker_idle_drain_done", th, idle_seen,
				     event_isset(&th->idle), th->worker_wait_seq);
	}
}
#endif

#if GOOS_linux
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#define MAP_FIXED_EXCLUSIVE MAP_FIXED_NOREPLACE
#elif GOOS_freebsd
#define MAP_FIXED_EXCLUSIVE (MAP_FIXED | MAP_EXCL)
#else
#define MAP_FIXED_EXCLUSIVE MAP_FIXED // The check is not supported.
#endif

class CoverAccessScope final
{
public:
	CoverAccessScope(cover_t* cov)
	    : cov_(cov)
	{
		// CoverAccessScope must not be used recursively b/c on Linux pkeys protection is global,
		// so cover_protect for one cov overrides previous cover_unprotect for another cov.
		if (used_)
			fail("recursion in CoverAccessScope");
		used_ = true;
		if (flag_coverage)
			cover_unprotect(cov_);
	}
	~CoverAccessScope()
	{
		if (flag_coverage)
			cover_protect(cov_);
		used_ = false;
	}

private:
	cover_t* const cov_;
	static bool used_;

	CoverAccessScope(const CoverAccessScope&) = delete;
	CoverAccessScope& operator=(const CoverAccessScope&) = delete;
};

bool CoverAccessScope::used_;

#if !SYZ_HAVE_FEATURES
static feature_t features[] = {};
#endif

#if !GOOS_windows
#include "shmem.h"

#include "conn.h"
#include "cover_filter.h"
#include "files.h"
#include "subprocess.h"

#include "snapshot.h"

#include "executor_runner.h"

#include "test.h"

static std::optional<CoverFilter> max_signal;
static std::optional<CoverFilter> cover_filter;
#else
static void SnapshotSetup(char**, int)
{
	fail("snapshot mode is not supported on Windows Nyx executor");
}

static void SnapshotStart()
{
	fail("snapshot mode is not supported on Windows Nyx executor");
}

static void SnapshotDone(bool)
{
	fail("snapshot mode is not supported on Windows Nyx executor");
}
#endif

#if SYZ_HAVE_SANDBOX_ANDROID
static uint64 sandbox_arg = 0;
#endif

int main(int argc, char** argv)
{
	if (argc == 1) {
		fprintf(stderr, "no command");
		return 1;
	}
#if GOOS_windows
	if (strcmp(argv[1], "exec") != 0 || argc <= 2 || strcmp(argv[2], "nyx") != 0) {
		fprintf(stderr, "windows executor only supports 'exec nyx'\n");
		return 1;
	}

	start_time_ms = current_time_ms();
	os_init(argc, argv, (char*)SYZ_DATA_OFFSET, SYZ_NUM_PAGES * SYZ_PAGE_SIZE);
	use_temporary_dir();
	install_segv_handler();
	current_thread = &threads[0];
#if SYZ_NYX_WINDOWS_SPARSE_TABLE
	init_nyx_syscalls();
#endif
	return nyx_mode_loop(argc, argv);
#else
	if (strcmp(argv[1], "runner") == 0) {
		runner(argv, argc);
		fail("runner returned");
	}
	if (strcmp(argv[1], "leak") == 0) {
#if SYZ_HAVE_LEAK_CHECK
		check_leaks(argv + 2, argc - 2);
#else
		fail("leak checking is not implemented");
#endif
		return 0;
	}
	if (strcmp(argv[1], "test") == 0)
		return run_tests(argc == 3 ? argv[2] : nullptr);

	if (strcmp(argv[1], "exec") != 0) {
		fprintf(stderr, "unknown command");
		return 1;
	}

	start_time_ms = current_time_ms();

	os_init(argc, argv, (char*)SYZ_DATA_OFFSET, SYZ_NUM_PAGES * SYZ_PAGE_SIZE);
	use_temporary_dir();
	install_segv_handler();
	current_thread = &threads[0];
#if GOOS_windows
	if (argc > 2 && strcmp(argv[2], "nyx") == 0)
		return nyx_mode_loop(argc, argv);
#endif

	if (argc > 2 && strcmp(argv[2], "snapshot") == 0) {
		SnapshotSetup(argv, argc);
	} else {
		mmap_input();
		mmap_output(kInitialOutput);

		// Prevent test programs to mess with these fds.
		// Due to races in collider mode, a program can e.g. ftruncate one of these fds,
		// which will cause fuzzer to crash.
		close(kInFd);
#if !SYZ_EXECUTOR_USES_FORK_SERVER
		// For SYZ_EXECUTOR_USES_FORK_SERVER, close(kOutFd) is invoked in the forked child,
		// after the program has been received.
		close(kOutFd);
#endif

		if (fcntl(kMaxSignalFd, F_GETFD) != -1) {
			// Use random addresses for coverage filters to not collide with output_data.
			max_signal.emplace(kMaxSignalFd, reinterpret_cast<void*>(0x110c230000ull));
			close(kMaxSignalFd);
		}
		if (fcntl(kCoverFilterFd, F_GETFD) != -1) {
			cover_filter.emplace(kCoverFilterFd, reinterpret_cast<void*>(0x110f230000ull));
			close(kCoverFilterFd);
		}

		setup_control_pipes();
		receive_handshake();
#if !SYZ_EXECUTOR_USES_FORK_SERVER
		// We receive/reply handshake when fork server is disabled just to simplify runner logic.
		// It's a bit suboptimal, but no fork server is much slower anyway.
		reply_execute(0);
		receive_execute();
#endif
	}

	setup_coverage();

	int status = 0;
	if (flag_sandbox_none)
		status = do_sandbox_none();
#if SYZ_HAVE_SANDBOX_SETUID
	else if (flag_sandbox_setuid)
		status = do_sandbox_setuid();
#endif
#if SYZ_HAVE_SANDBOX_NAMESPACE
	else if (flag_sandbox_namespace)
		status = do_sandbox_namespace();
#endif
#if SYZ_HAVE_SANDBOX_ANDROID
	else if (flag_sandbox_android)
		status = do_sandbox_android(sandbox_arg);
#endif
	else
		fail("unknown sandbox type");

#if SYZ_EXECUTOR_USES_FORK_SERVER
	fprintf(stderr, "loop exited with status %d\n", status);
	// If an external sandbox process wraps executor, the out pipe will be closed
	// before the sandbox process exits this will make ipc package kill the sandbox.
	// As the result sandbox process will exit with exit status 9 instead of the executor
	// exit status (notably kFailStatus). So we duplicate the exit status on the pipe.
	reply_execute(status);
	doexit(status);
	// Unreachable.
	return 1;
#else
	reply_execute(status);
	return status;
#endif
#endif
}

#if !GOOS_windows
static uint32* input_base_address()
{
	if (kAddressSanitizer) {
		// ASan conflicts with -static, so we end up having a dynamically linked syz-executor binary.
		// It's often the case that the libraries are mapped shortly after 0x7f0000000000, so we cannot
		// blindly set some HighMemory address and hope it's free.
		// Since we only run relatively safe (or fake) syscalls under tests, it should be fine to
		// just use whatever address mmap() returns us.
		return 0;
	}
	// It's the first time we map output region - generate its location.
	// The output region is the only thing in executor process for which consistency matters.
	// If it is corrupted ipc package will fail to parse its contents and panic.
	// But fuzzer constantly invents new ways of how to corrupt the region,
	// so we map the region at a (hopefully) hard to guess address with random offset,
	// surrounded by unmapped pages.
	// The address chosen must also work on 32-bit kernels with 1GB user address space.
	const uint64 kOutputBase = 0x1b2bc20000ull;
	return (uint32*)(kOutputBase + (1 << 20) * (getpid() % 128));
}

static void mmap_input()
{
	uint32* mmap_at = input_base_address();
	int flags = MAP_SHARED;
	if (mmap_at != 0)
		// If we map at a specific address, ensure it's not overlapping with anything else.
		flags = flags | MAP_FIXED_EXCLUSIVE;
	void* result = mmap(mmap_at, kMaxInput, PROT_READ, flags, kInFd, 0);
	if (result == MAP_FAILED)
		fail("mmap of input file failed");
	input_data = static_cast<uint8*>(result);
}

static uint32* output_base_address()
{
	if (kAddressSanitizer) {
		// See the comment in input_base_address();
		return 0;
	}
	if (output_data != NULL) {
		// If output_data was already mapped, use the old base address
		// since we could be extending the area from a different pid:
		// realloc_output_data() may be called from a fork, which would cause
		// input_base_address() to return a different address.
		return (uint32*)output_data;
	}
	// Leave some unmmapped area after the input data.
	return input_base_address() + kMaxInput + SYZ_PAGE_SIZE;
}

// This method can be invoked as many times as one likes - MMAP_FIXED can overwrite the previous
// mapping without any problems. The only precondition - kOutFd must not be closed.
static void mmap_output(uint32 size)
{
	if (size <= output_size)
		return;
	if (size % SYZ_PAGE_SIZE != 0)
		failmsg("trying to mmap output area that is not divisible by page size", "page=%d,area=%d", SYZ_PAGE_SIZE, size);
	uint32* mmap_at = output_base_address();
	int flags = MAP_SHARED;
	if (mmap_at == NULL) {
		// We map at an address chosen by the kernel, so if there was any previous mapping, just unmap it.
		if (output_data != NULL) {
			int ret = munmap(output_data, output_size);
			if (ret != 0)
				fail("munmap failed");
			output_size = 0;
		}
	} else {
		// We are possibly expanding the mmapped region. Adjust the parameters to avoid mmapping already
		// mmapped area as much as possible.
		// There exists a mremap call that could have helped, but it's purely Linux-specific.
		mmap_at = (uint32*)((char*)(mmap_at) + output_size);
		// Ensure we don't overwrite anything.
		flags = flags | MAP_FIXED_EXCLUSIVE;
	}
	void* result = mmap(mmap_at, size - output_size, PROT_READ | PROT_WRITE, flags, kOutFd, output_size);
	if (result == MAP_FAILED || (mmap_at && result != mmap_at))
		failmsg("mmap of output file failed", "want %p, got %p", mmap_at, result);
	if (output_size == 0)
		output_data = static_cast<OutputData*>(result);
	output_size = size;
}

void setup_control_pipes()
{
	if (dup2(0, kInPipeFd) < 0)
		fail("dup2(0, kInPipeFd) failed");
	if (dup2(1, kOutPipeFd) < 0)
		fail("dup2(1, kOutPipeFd) failed");
	if (dup2(2, 1) < 0)
		fail("dup2(2, 1) failed");
	// We used to close(0), but now we dup stderr to stdin to keep fd numbers
	// stable across executor and C programs generated by pkg/csource.
	if (dup2(2, 0) < 0)
		fail("dup2(2, 0) failed");
}
#endif

#if !GOOS_windows
void receive_handshake()
{
	handshake_req req = {};
	ssize_t n = read(kInPipeFd, &req, sizeof(req));
	if (n != sizeof(req))
		failmsg("handshake read failed", "read=%zu", n);
	parse_handshake(req);
}
#endif

void parse_handshake(const handshake_req& req)
{
	if (req.magic != kInMagic)
		failmsg("bad handshake magic", "magic=0x%llx", req.magic);
#if SYZ_HAVE_SANDBOX_ANDROID
	sandbox_arg = req.sandbox_arg;
#endif
	is_kernel_64_bit = req.is_kernel_64_bit;
	use_cover_edges = req.use_cover_edges;
	procid = req.pid;
	syscall_timeout_ms = req.syscall_timeout_ms;
	program_timeout_ms = req.program_timeout_ms;
	slowdown_scale = req.slowdown_scale;
	flag_debug = (bool)(req.flags & rpc::ExecEnv::Debug);
	flag_coverage = (bool)(req.flags & rpc::ExecEnv::Signal);
	flag_read_only_coverage = (bool)(req.flags & rpc::ExecEnv::ReadOnlyCoverage);
	flag_sandbox_none = (bool)(req.flags & rpc::ExecEnv::SandboxNone);
	flag_sandbox_setuid = (bool)(req.flags & rpc::ExecEnv::SandboxSetuid);
	flag_sandbox_namespace = (bool)(req.flags & rpc::ExecEnv::SandboxNamespace);
	flag_sandbox_android = (bool)(req.flags & rpc::ExecEnv::SandboxAndroid);
	flag_extra_coverage = (bool)(req.flags & rpc::ExecEnv::ExtraCover);
	flag_net_injection = (bool)(req.flags & rpc::ExecEnv::EnableTun);
	flag_net_devices = (bool)(req.flags & rpc::ExecEnv::EnableNetDev);
	flag_net_reset = (bool)(req.flags & rpc::ExecEnv::EnableNetReset);
	flag_cgroups = (bool)(req.flags & rpc::ExecEnv::EnableCgroups);
	flag_close_fds = (bool)(req.flags & rpc::ExecEnv::EnableCloseFds);
	flag_devlink_pci = (bool)(req.flags & rpc::ExecEnv::EnableDevlinkPCI);
	flag_vhci_injection = (bool)(req.flags & rpc::ExecEnv::EnableVhciInjection);
	flag_wifi = (bool)(req.flags & rpc::ExecEnv::EnableWifi);
	flag_delay_kcov_mmap = (bool)(req.flags & rpc::ExecEnv::DelayKcovMmap);
	flag_nic_vf = (bool)(req.flags & rpc::ExecEnv::EnableNicVF);
}

#if !GOOS_windows
void receive_execute()
{
	execute_req req = {};
	ssize_t n = 0;
	while ((n = read(kInPipeFd, &req, sizeof(req))) == -1 && errno == EINTR)
		;
	if (n != (ssize_t)sizeof(req))
		failmsg("control pipe read failed", "read=%zd want=%zd", n, sizeof(req));
	parse_execute(req);
}
#endif

void parse_execute(const execute_req& req)
{
	request_id = req.id;
	request_type = req.type;
	flag_collect_signal = req.exec_flags & (uint64)rpc::ExecFlag::CollectSignal;
	flag_collect_cover = req.exec_flags & (uint64)rpc::ExecFlag::CollectCover;
	flag_dedup_cover = req.exec_flags & (uint64)rpc::ExecFlag::DedupCover;
	flag_comparisons = req.exec_flags & (uint64)rpc::ExecFlag::CollectComps;
	flag_threaded = req.exec_flags & (uint64)rpc::ExecFlag::Threaded;
#if GOOS_windows
	// The Windows Nyx path sources cover/signal from PT, but it does not yet
	// provide KCOV-style comparison records. Returning an empty comps vector is
	// enough for feature probing to mark comparisons unsupported; trying to walk
	// the nocover-backed buffer here can wedge the guest request path.
	flag_comparisons = false;
#endif
	all_call_signal = req.all_call_signal;
	all_extra_signal = req.all_extra_signal;

	debug("[%llums] exec opts: reqid=%llu type=%llu procid=%llu threaded=%d cover=%d comps=%d dedup=%d signal=%d "
	      " sandbox=%d/%d/%d/%d timeouts=%llu/%llu/%llu kernel_64_bit=%d\n",
	      current_time_ms() - start_time_ms, request_id, (uint64)request_type, procid, flag_threaded, flag_collect_cover,
	      flag_comparisons, flag_dedup_cover, flag_collect_signal, flag_sandbox_none, flag_sandbox_setuid,
	      flag_sandbox_namespace, flag_sandbox_android, syscall_timeout_ms, program_timeout_ms, slowdown_scale,
	      is_kernel_64_bit);
	if (syscall_timeout_ms == 0 || program_timeout_ms <= syscall_timeout_ms || slowdown_scale == 0)
		failmsg("bad timeouts", "syscall=%llu, program=%llu, scale=%llu",
			syscall_timeout_ms, program_timeout_ms, slowdown_scale);
}

bool cover_collection_required()
{
	return flag_coverage && (flag_collect_signal || flag_collect_cover || flag_comparisons);
}

static void setup_coverage()
{
	if (coverage_initialized || !flag_coverage)
		return;
	int create_count = kCoverDefaultCount, mmap_count = create_count;
	if (flag_delay_kcov_mmap) {
		create_count = kCoverOptimizedCount;
		mmap_count = kCoverOptimizedPreMmap;
	}
	if (create_count > kMaxThreads)
		create_count = kMaxThreads;
	for (int i = 0; i < create_count; i++) {
		threads[i].cov.fd = kCoverFd + i;
		cover_open(&threads[i].cov, false);
		if (i < mmap_count) {
			// Pre-mmap coverage collection for some threads. This should be enough for almost
			// all programs, for the remaning few ones coverage will be set up when it's needed.
			thread_mmap_cover(&threads[i]);
		}
	}
	extra_cov.fd = kExtraCoverFd;
	cover_open(&extra_cov, true);
	cover_mmap(&extra_cov);
	cover_protect(&extra_cov);
	if (flag_extra_coverage) {
		// Don't enable comps because we don't use them in the fuzzer yet.
		cover_enable(&extra_cov, false, true);
	}
	coverage_initialized = true;
}

#if !GOOS_windows
void reply_execute(uint32 status)
{
	if (flag_snapshot)
		SnapshotDone(status == kFailStatus);
	if (write(kOutPipeFd, &status, sizeof(status)) != sizeof(status))
		fail("control pipe write failed");
}
#endif

void realloc_output_data()
{
#if SYZ_EXECUTOR_USES_FORK_SERVER
	if (flag_comparisons)
		mmap_output(kMaxOutputComparisons);
	else if (flag_collect_cover)
		mmap_output(kMaxOutputCoverage);
	else if (flag_collect_signal)
		mmap_output(kMaxOutputSignal);
	if (close(kOutFd) < 0)
		fail("failed to close kOutFd");
#endif
}

void execute_glob()
{
#if GOOS_windows
	fail("glob requests are not supported by the Windows Nyx executor");
#else
	const char* pattern = (const char*)input_data;
	const auto& files = Glob(pattern);
	size_t size = 0;
	for (const auto& file : files)
		size += file.size() + 1;
	mmap_output(kMaxOutput);
	ShmemBuilder fbb(output_data, kMaxOutput, true);
	uint8_t* pos = nullptr;
	auto off = fbb.CreateUninitializedVector(size, &pos);
	for (const auto& file : files) {
		memcpy(pos, file.c_str(), file.size() + 1);
		pos += file.size() + 1;
	}
	output_data->consumed.store(fbb.GetSize(), std::memory_order_release);
	output_data->result_offset.store(off, std::memory_order_release);
#endif
}

// execute_one executes program stored in input_data.
void execute_one()
{
	if (request_type == rpc::RequestType::Glob) {
		execute_glob();
		return;
	}
	if (request_type != rpc::RequestType::Program)
		failmsg("bad request type", "type=%llu", (uint64)request_type);

	in_execute_one = true;
#if GOOS_linux
	char buf[64];
	// Linux TASK_COMM_LEN is only 16, so the name needs to be compact.
	snprintf(buf, sizeof(buf), "syz.%llu.%llu", procid, request_id);
	prctl(PR_SET_NAME, buf);
#endif
	if (flag_snapshot)
		SnapshotStart();
	else
		realloc_output_data();
	// Output buffer may be pkey-protected in snapshot mode, so don't write the output size
	// (it's fixed and known anyway).
	output_builder.emplace(output_data, output_size, !flag_snapshot);
	uint64 start = current_time_ms();
	uint8* input_pos = input_data;

	if (cover_collection_required()) {
		if (!flag_threaded)
			cover_enable(&threads[0].cov, flag_comparisons, false);
		if (flag_extra_coverage)
			cover_reset(&extra_cov);
	}

	int call_index = 0;
	uint64 prog_extra_timeout = 0;
	uint64 prog_extra_cover_timeout = 0;
	call_props_t call_props;
	memset(&call_props, 0, sizeof(call_props));

	uint64 total_calls = read_input(&input_pos);
#if GOOS_windows
	nyx_log_exec_stage("begin", total_calls);
#else
	(void)total_calls;
#endif
	for (;;) {
		uint64 instr_off = input_pos - input_data;
		uint64 call_num = read_input(&input_pos);
#if GOOS_windows
		nyx_log_exec_stage("dispatch", instr_off, call_num);
#else
		(void)instr_off;
#endif
		if (call_num == instr_eof)
			break;
		if (call_num == instr_copyin) {
			char* addr = (char*)(read_input(&input_pos) + SYZ_DATA_OFFSET);
			uint64 typ = read_input(&input_pos);
#if GOOS_windows
			nyx_log_exec_stage("copyin_begin", instr_off, (uint64)(uintptr_t)addr, typ);
#endif
			switch (typ) {
			case arg_const: {
				uint64 size, bf, bf_off, bf_len;
				uint64 arg = read_const_arg(&input_pos, &size, &bf, &bf_off, &bf_len);
#if GOOS_windows
				nyx_log_exec_stage("copyin_const", (uint64)(uintptr_t)addr, size, arg, bf);
#endif
				copyin(addr, arg, size, bf, bf_off, bf_len);
				break;
			}
			case arg_addr32:
			case arg_addr64: {
				uint64 val = read_input(&input_pos) + SYZ_DATA_OFFSET;
#if GOOS_windows
				nyx_log_exec_stage("copyin_addr", (uint64)(uintptr_t)addr, typ, val);
#endif
				if (typ == arg_addr32)
					NONFAILING(*(uint32*)addr = val);
				else
					NONFAILING(*(uint64*)addr = val);
				break;
			}
			case arg_result: {
				uint64 meta = read_input(&input_pos);
				uint64 size = meta & 0xff;
				uint64 bf = meta >> 8;
				uint64 val = read_result(&input_pos);
#if GOOS_windows
				nyx_log_exec_stage("copyin_result", (uint64)(uintptr_t)addr, size, bf, val);
#endif
				copyin(addr, val, size, bf, 0, 0);
				break;
			}
			case arg_data: {
				uint64 size = read_input(&input_pos);
				size &= ~(1ull << 63); // readable flag
#if GOOS_windows
				nyx_log_exec_stage("copyin_data_begin", (uint64)(uintptr_t)addr, size,
						   input_pos - input_data);
#endif
				if (input_pos + size > input_data + kMaxInput)
					fail("data arg overflow");
				NONFAILING(memcpy(addr, input_pos, size));
				input_pos += size;
#if GOOS_windows
				nyx_log_exec_stage("copyin_data_done", (uint64)(uintptr_t)addr, size,
						   input_pos - input_data);
#endif
				break;
			}
			case arg_csum: {
				debug_verbose("checksum found at %p\n", addr);
				uint64 size = read_input(&input_pos);
				char* csum_addr = addr;
				uint64 csum_kind = read_input(&input_pos);
				switch (csum_kind) {
				case arg_csum_inet: {
					if (size != 2)
						failmsg("bag inet checksum size", "size=%llu", size);
					debug_verbose("calculating checksum for %p\n", csum_addr);
					struct csum_inet csum;
					csum_inet_init(&csum);
					uint64 chunks_num = read_input(&input_pos);
					uint64 chunk;
					for (chunk = 0; chunk < chunks_num; chunk++) {
						uint64 chunk_kind = read_input(&input_pos);
						uint64 chunk_value = read_input(&input_pos);
						uint64 chunk_size = read_input(&input_pos);
						switch (chunk_kind) {
						case arg_csum_chunk_data:
							chunk_value += SYZ_DATA_OFFSET;
							debug_verbose("#%lld: data chunk, addr: %llx, size: %llu\n",
								      chunk, chunk_value, chunk_size);
							NONFAILING(csum_inet_update(&csum, (const uint8*)chunk_value, chunk_size));
							break;
						case arg_csum_chunk_const:
							if (chunk_size != 2 && chunk_size != 4 && chunk_size != 8)
								failmsg("bad checksum const chunk size", "size=%lld", chunk_size);
							// Here we assume that const values come to us big endian.
							debug_verbose("#%lld: const chunk, value: %llx, size: %llu\n",
								      chunk, chunk_value, chunk_size);
							csum_inet_update(&csum, (const uint8*)&chunk_value, chunk_size);
							break;
						default:
							failmsg("bad checksum chunk kind", "kind=%llu", chunk_kind);
						}
					}
					uint16 csum_value = csum_inet_digest(&csum);
					debug_verbose("writing inet checksum %hx to %p\n", csum_value, csum_addr);
					copyin(csum_addr, csum_value, 2, binary_format_native, 0, 0);
					break;
				}
				default:
					failmsg("bad checksum kind", "kind=%llu", csum_kind);
				}
				break;
			}
			default:
				failmsg("bad argument type", "type=%llu", typ);
			}
#if GOOS_windows
			nyx_log_exec_stage("copyin_done", instr_off, (uint64)(uintptr_t)addr, typ,
					   input_pos - input_data);
#endif
			continue;
		}
		if (call_num == instr_copyout) {
			read_input(&input_pos); // index
			read_input(&input_pos); // addr
			read_input(&input_pos); // size
			// The copyout will happen when/if the call completes.
			continue;
		}
		if (call_num == instr_setprops) {
			read_call_props_t(call_props, read_input(&input_pos, false));
			continue;
		}

		// Normal syscall.
		if (call_num >= ARRAY_SIZE(syscalls))
			failmsg("invalid syscall number", "call_num=%llu", call_num);
		const call_t* call = &syscalls[call_num];
		if (prog_extra_timeout < call->attrs.prog_timeout)
			prog_extra_timeout = call->attrs.prog_timeout * slowdown_scale;
		if (call->attrs.remote_cover)
			prog_extra_cover_timeout = 500 * slowdown_scale; // 500 ms
		uint64 copyout_index = read_input(&input_pos);
		uint64 num_args = read_input(&input_pos);
		if (num_args > kMaxArgs)
			failmsg("command has bad number of arguments", "args=%llu", num_args);
		uint64 args[kMaxArgs] = {};
		for (uint64 i = 0; i < num_args; i++)
			args[i] = read_arg(&input_pos);
		for (uint64 i = num_args; i < kMaxArgs; i++)
			args[i] = 0;
#if GOOS_windows
		nyx_log_exec_stage("schedule_begin", call_index, call_num, copyout_index, num_args);
#endif
		thread_t* th = schedule_call(call_index++, call_num, copyout_index,
					     num_args, args, input_pos, call_props);
#if GOOS_windows
		nyx_log_exec_stage("schedule_done", th->id, th->call_num, th->num_args, running);
#endif

		if (call_props.async && flag_threaded) {
			// Don't wait for an async call to finish. We'll wait at the end.
			// If we're not in the threaded mode, just ignore the async flag - during repro simplification syzkaller
			// will anyway try to make it non-threaded.
		} else if (flag_threaded) {
			// Wait for call completion.
			uint64 timeout_ms = syscall_timeout_ms + call->attrs.timeout * slowdown_scale;
			// This is because of printing pre/post call. Ideally we print everything in the main thread
			// and then remove this (would also avoid intermixed output).
			if (flag_debug && timeout_ms < 1000)
				timeout_ms = 1000;
#if GOOS_windows
			uint64 wait_start = current_time_ms();
			nyx_log_thread_stage("wait_call_done_begin", th, timeout_ms, running,
					     event_isset(&th->done), event_isset(&th->ready));
#endif
			int wait_done = event_timedwait(&th->done, timeout_ms);
#if GOOS_windows
			nyx_log_thread_stage("wait_call_done_result", th, wait_done,
					     current_time_ms() - wait_start,
					     event_isset(&th->done), event_isset(&th->ready));
#endif
			if (wait_done)
				handle_completion(th);

			// Check if any of previous calls have completed.
			for (int i = 0; i < kMaxThreads; i++) {
				th = &threads[i];
				if (th->executing && event_isset(&th->done))
					handle_completion(th);
			}
		} else {
			// Execute directly.
			if (th != &threads[0])
				fail("using non-main thread in non-thread mode");
#if GOOS_windows
			nyx_log_exec_stage("direct_pre_ready_reset", th->id, th->call_num);
#endif
			event_reset(&th->ready);
#if GOOS_windows
			nyx_log_exec_stage("direct_post_ready_reset", th->id, th->call_num);
			nyx_log_exec_stage("direct_pre_execute_call", th->id, th->call_num);
#endif
			execute_call(th);
#if GOOS_windows
			nyx_log_exec_stage("direct_post_execute_call", th->id, th->call_num,
					   (uint64)th->res, th->reserrno);
#endif
			event_set(&th->done);
#if GOOS_windows
			nyx_log_exec_stage("direct_post_done_set", th->id, th->call_num);
#endif
			handle_completion(th);
#if GOOS_windows
			nyx_log_exec_stage("direct_post_completion", th->id, th->call_num, running,
					   completed);
#endif
		}
		memset(&call_props, 0, sizeof(call_props));
	}

	if (running > 0) {
		// Give unfinished syscalls some additional time.
#if GOOS_windows
		nyx_log_exec_stage("wait_unfinished_begin", running, completed);
#endif
		last_scheduled = 0;
		uint64 wait_start = current_time_ms();
		uint64 wait_end = wait_start + 2 * syscall_timeout_ms;
		wait_end = std::max(wait_end, start + program_timeout_ms / 6);
		wait_end = std::max(wait_end, wait_start + prog_extra_timeout);
#if GOOS_windows
		uint64 next_wait_poll_log = wait_start;
#endif
		while (running > 0 && current_time_ms() <= wait_end) {
#if GOOS_windows
			uint64 wait_now = current_time_ms();
			bool log_wait_poll = wait_now >= next_wait_poll_log;
			if (log_wait_poll)
				next_wait_poll_log = wait_now + 100;
			HANDLE wait_handles[kMaxThreads];
			thread_t* wait_threads[kMaxThreads];
			DWORD wait_count = 0;
			for (int i = 0; i < kMaxThreads; i++) {
				thread_t* th = &threads[i];
				if (!th->executing)
					continue;
				wait_handles[wait_count] = event_handle(&th->done);
				wait_threads[wait_count] = th;
				wait_count++;
			}
			if (wait_count == 0)
				break;
			DWORD wait_ms = 1 * slowdown_scale;
			if (wait_ms == 0)
				wait_ms = 1;
			uint64 wait_remaining = wait_now < wait_end ? wait_end - wait_now : 0;
			if (wait_remaining < wait_ms)
				wait_ms = (DWORD)wait_remaining;
			DWORD signaled = WaitForMultipleObjects(wait_count, wait_handles, FALSE, wait_ms);
			if (signaled >= WAIT_OBJECT_0 && signaled < WAIT_OBJECT_0 + wait_count) {
				thread_t* th = wait_threads[signaled - WAIT_OBJECT_0];
				if (th->executing) {
					nyx_log_thread_stage("wait_unfinished_wait_done_seen", th,
							     running, current_time_ms() - wait_start);
					handle_completion(th);
				}
			} else if (signaled != WAIT_TIMEOUT) {
				exitf("WaitForMultipleObjects failed: %lu", (unsigned long)signaled);
			}
#else
			sleep_ms(1 * slowdown_scale);
#endif
			for (int i = 0; i < kMaxThreads; i++) {
				thread_t* th = &threads[i];
				if (th->executing) {
#if GOOS_windows
					int done = event_isset(&th->done);
					if (log_wait_poll)
						nyx_log_thread_stage("wait_unfinished_poll", th,
								     running, wait_now - wait_start,
								     done, event_isset(&th->ready));
					if (done) {
						nyx_log_thread_stage("wait_unfinished_done_seen", th,
								     running, wait_now - wait_start);
						handle_completion(th);
					}
#else
					if (event_isset(&th->done))
						handle_completion(th);
#endif
				}
			}
		}
#if GOOS_windows
		nyx_log_exec_stage("wait_unfinished_done", running, completed,
				   current_time_ms() - wait_start);
#endif
		// Write output coverage for unfinished calls.
		if (running > 0) {
			for (int i = 0; i < kMaxThreads; i++) {
				thread_t* th = &threads[i];
				if (th->executing) {
					if (cover_collection_required()) {
#if GOOS_windows
						nyx_log_thread_stage("unfinished_pre_cover_collect", th,
								     th->cov.size, th->cov.overflow);
#endif
						cover_collect(&th->cov);
#if GOOS_windows
						nyx_log_thread_stage("unfinished_post_cover_collect", th,
								     th->cov.size, th->cov.overflow);
#endif
					}
#if GOOS_windows
					nyx_log_thread_stage("unfinished_pre_write_call_output", th,
							     running, completed);
#endif
					write_call_output(th, false);
#if GOOS_windows
					nyx_log_thread_stage("unfinished_post_write_call_output", th,
							     running, completed);
#endif
				}
			}
		}
	}

#if SYZ_HAVE_CLOSE_FDS
	close_fds();
#endif

#if GOOS_windows
	nyx_log_exec_stage("execute_one_pre_write_extra_output", running, completed);
#endif
	write_extra_output();
#if GOOS_windows
	nyx_log_exec_stage("execute_one_post_write_extra_output", running, completed,
			   output_data ? output_data->completed.load(std::memory_order_relaxed) : 0);
#endif
	if (flag_extra_coverage) {
		// Check for new extra coverage in small intervals to avoid situation
		// that we were killed on timeout before we write any.
		// Check for extra coverage is very cheap, effectively a memory load.
		const uint64 kSleepMs = 100;
		for (uint64 i = 0; i < prog_extra_cover_timeout / kSleepMs &&
				   output_data->completed.load(std::memory_order_relaxed) < kMaxCalls;
		     i++) {
			sleep_ms(kSleepMs);
#if GOOS_windows
			nyx_log_exec_stage("execute_one_extra_cover_poll", i, prog_extra_cover_timeout,
					   output_data->completed.load(std::memory_order_relaxed));
#endif
			write_extra_output();
		}
	}
#if GOOS_windows
	nyx_log_exec_stage("execute_one_done", running, completed,
			   output_data ? output_data->completed.load(std::memory_order_relaxed) : 0);
#endif
}

thread_t* schedule_call(int call_index, int call_num, uint64 copyout_index, uint64 num_args, uint64* args, uint8* pos, call_props_t call_props)
{
	// Find a spare thread to execute the call.
	int i = 0;
	for (; i < kMaxThreads; i++) {
		thread_t* th = &threads[i];
		if (!th->created)
			thread_create(th, i, cover_collection_required());
		if (event_isset(&th->done)) {
			if (th->executing)
				handle_completion(th);
			break;
		}
	}
	if (i == kMaxThreads)
		exitf("out of threads");
	thread_t* th = &threads[i];
	if (event_isset(&th->ready) || !event_isset(&th->done) || th->executing)
		exitf("bad thread state in schedule: ready=%d done=%d executing=%d",
		      event_isset(&th->ready), event_isset(&th->done), th->executing);
#if GOOS_windows
	if (flag_threaded) {
		nyx_log_thread_stage("schedule_pre_idle_wait", th, event_isset(&th->idle),
				     th->handoff_seq, th->worker_tid, kWindowsWorkerIdleWaitMs);
		int idle_seen = windows_yield_until_event(&th->idle, kWindowsWorkerIdleYields,
							  kWindowsWorkerIdleWaitMs);
		nyx_log_thread_stage("schedule_post_idle_wait", th, idle_seen,
				     event_isset(&th->idle), th->worker_tid, running);
	}
#endif
	last_scheduled = th;
	th->copyout_pos = pos;
	th->copyout_index = copyout_index;
#if GOOS_windows
	nyx_log_thread_stage("schedule_pre_done_reset", th, event_isset(&th->ready),
			     event_isset(&th->done), th->executing, running);
#endif
	event_reset(&th->done);
#if GOOS_windows
	nyx_log_thread_stage("schedule_post_done_reset", th, event_isset(&th->ready),
			     event_isset(&th->done), th->executing, running);
#endif
	// We do this both right before execute_syscall in the thread and here because:
	// the former is useful to reset all unrelated coverage from our syscalls (e.g. futex in event_wait),
	// while the reset here is useful to avoid the following scenario that the fuzzer was able to trigger.
	// If the test program contains seccomp syscall that kills the worker thread on the next syscall,
	// then it won't receive this next syscall and won't do cover_reset. If we are collecting comparions
	// then we've already transformed comparison data from the previous syscall into rpc::ComparisonRaw
	// in write_comparisons. That data is still in the buffer. The first word of rpc::ComparisonRaw is PC
	// which overlaps with comparison type in kernel exposed records. As the result write_comparisons
	// that will try to write out data from unfinished syscalls will see these rpc::ComparisonRaw records,
	// mis-interpret PC as type, and fail as: SYZFAIL: invalid kcov comp type (type=ffffffff8100b4e0).
	if (flag_coverage)
		cover_reset(&th->cov);
	th->executing = true;
	th->call_index = call_index;
	th->call_num = call_num;
	th->num_args = num_args;
	th->call_props = call_props;
	for (int i = 0; i < kMaxArgs; i++)
		th->args[i] = args[i];
#if GOOS_windows
	th->handoff_seq++;
	nyx_log_thread_stage("schedule_handoff_seq", th, th->handoff_seq,
			     th->worker_tid, th->worker_wait_seq, running);
	nyx_log_thread_stage("schedule_pre_idle_reset", th, event_isset(&th->idle),
			     th->handoff_seq, th->worker_tid, running);
	event_reset(&th->idle);
	nyx_log_thread_stage("schedule_post_idle_reset", th, event_isset(&th->idle),
			     th->handoff_seq, th->worker_tid, running);
	nyx_log_thread_stage("schedule_pre_ready_set", th, event_isset(&th->ready),
			     event_isset(&th->done), th->executing, running);
#endif
	event_set(&th->ready);
#if GOOS_windows
	nyx_log_thread_stage("schedule_post_ready_set", th, event_isset(&th->ready),
			     event_isset(&th->done), th->executing, running);
#endif
	running++;
#if GOOS_windows
	nyx_log_thread_stage("schedule_running_incremented", th, event_isset(&th->ready),
			     event_isset(&th->done), th->executing, running);
#endif
	return th;
}

template <typename cover_data_t>
uint32 write_signal(flatbuffers::FlatBufferBuilder& fbb, int index, cover_t* cov, bool all)
{
	// Write out feedback signals.
	// Currently it is code edges computed as xor of two subsequent basic block PCs.
	fbb.StartVector<uint64_t>(0);
	cover_data_t* cover_data = (cover_data_t*)(cov->data + cov->data_offset);
	if ((char*)(cover_data + cov->size) > cov->data_end)
		failmsg("too much cover", "cov=%u", cov->size);
	uint32 nsig = 0;
	cover_data_t prev_pc = 0;
	bool prev_filter = true;
	for (uint32 i = 0; i < cov->size; i++) {
		cover_data_t pc = cover_data[i] + cov->pc_offset;
		uint64 sig = pc;
		if (use_cover_edges) {
			// Only hash the lower 12 bits so the hash is independent of any module offsets.
			const uint64 mask = (1 << 12) - 1;
			sig ^= hash(prev_pc & mask) & mask;
		}
		bool filter = coverage_filter(pc);
		// Ignore the edge only if both current and previous PCs are filtered out
		// to capture all incoming and outcoming edges into the interesting code.
		bool ignore = !filter && !prev_filter;
		prev_pc = pc;
		prev_filter = filter;
		if (ignore || dedup(index, sig))
			continue;
		if (!all
#if !GOOS_windows
		    && max_signal && max_signal->Contains(sig)
#endif
		)
			continue;
		fbb.PushElement(uint64(sig));
		nsig++;
	}
	return fbb.EndVector(nsig);
}

template <typename cover_data_t>
uint32 write_cover(flatbuffers::FlatBufferBuilder& fbb, cover_t* cov)
{
	uint32 cover_size = cov->size;
	cover_data_t* cover_data = (cover_data_t*)(cov->data + cov->data_offset);
	if (flag_dedup_cover) {
		cover_data_t* end = cover_data + cover_size;
		std::sort(cover_data, end);
		cover_size = std::unique(cover_data, end) - cover_data;
	}
	fbb.StartVector<uint64_t>(cover_size);
	// Flatbuffer arrays are written backwards, so reverse the order on our side as well.
	for (uint32 i = 0; i < cover_size; i++)
		fbb.PushElement(uint64(cover_data[cover_size - i - 1] + cov->pc_offset));
	return fbb.EndVector(cover_size);
}

uint32 write_comparisons(flatbuffers::FlatBufferBuilder& fbb, cover_t* cov)
{
	// Collect only the comparisons
	uint64 ncomps = *(uint64_t*)cov->data;
	kcov_comparison_t* cov_start = (kcov_comparison_t*)(cov->data + sizeof(uint64));
	if ((char*)(cov_start + ncomps) > cov->data_end)
		failmsg("too many comparisons", "ncomps=%llu", ncomps);
	cov->overflow = ((char*)(cov_start + ncomps + 1) > cov->data_end);
	rpc::ComparisonRaw* start = (rpc::ComparisonRaw*)cov_start;
	rpc::ComparisonRaw* end = start;
	// We will convert kcov_comparison_t to ComparisonRaw inplace.
	static_assert(sizeof(kcov_comparison_t) >= sizeof(rpc::ComparisonRaw));
	for (uint32 i = 0; i < ncomps; i++) {
		auto raw = convert(cov_start[i]);
		if (!raw.pc())
			continue;
		*end++ = raw;
	}
	std::sort(start, end, [](rpc::ComparisonRaw a, rpc::ComparisonRaw b) -> bool {
		if (a.pc() != b.pc())
			return a.pc() < b.pc();
		if (a.op1() != b.op1())
			return a.op1() < b.op1();
		return a.op2() < b.op2();
	});
	ncomps = std::unique(start, end, [](rpc::ComparisonRaw a, rpc::ComparisonRaw b) -> bool {
			 return a.pc() == b.pc() && a.op1() == b.op1() && a.op2() == b.op2();
		 }) -
		 start;
	return fbb.CreateVectorOfStructs(start, ncomps).o;
}

bool coverage_filter(uint64 pc)
{
#if GOOS_windows
	(void)pc;
	return true;
#else
	if (!cover_filter)
		return true;
	return cover_filter->Contains(pc);
#endif
}

void handle_completion(thread_t* th)
{
#if GOOS_windows
	nyx_log_thread_stage("handle_completion_begin", th, running, completed,
			     event_isset(&th->done), th->executing);
#endif
	if (event_isset(&th->ready) || !event_isset(&th->done) || !th->executing)
		exitf("bad thread state in completion: ready=%d done=%d executing=%d",
		      event_isset(&th->ready), event_isset(&th->done), th->executing);
	if (th->res != (intptr_t)-1) {
#if GOOS_windows
		nyx_log_thread_stage("handle_completion_pre_copyout", th, th->copyout_index,
				     (uint64)th->res, th->reserrno);
#endif
		copyout_call_results(th);
#if GOOS_windows
		nyx_log_thread_stage("handle_completion_post_copyout", th, th->copyout_index,
				     (uint64)th->res, th->reserrno);
#endif
	}

#if GOOS_windows
	nyx_log_thread_stage("handle_completion_pre_write_call_output", th, completed,
			     output_data ? output_data->completed.load(std::memory_order_relaxed) : 0);
#endif
	write_call_output(th, true);
#if GOOS_windows
	nyx_log_thread_stage("handle_completion_post_write_call_output", th, completed,
			     output_data ? output_data->completed.load(std::memory_order_relaxed) : 0);
	nyx_log_thread_stage("handle_completion_pre_write_extra_output", th, completed,
			     output_data ? output_data->completed.load(std::memory_order_relaxed) : 0);
#endif
	write_extra_output();
#if GOOS_windows
	nyx_log_thread_stage("handle_completion_post_write_extra_output", th, completed,
			     output_data ? output_data->completed.load(std::memory_order_relaxed) : 0);
#endif
	th->executing = false;
	running--;
#if GOOS_windows
	nyx_log_thread_stage("handle_completion_done", th, running, completed,
			     output_data ? output_data->completed.load(std::memory_order_relaxed) : 0);
#endif
	if (running < 0) {
		// This fires periodically for the past 2 years (see issue #502).
		fprintf(stderr, "running=%d completed=%d flag_threaded=%d current=%d\n",
			running, completed, flag_threaded, th->id);
		for (int i = 0; i < kMaxThreads; i++) {
			thread_t* th1 = &threads[i];
			fprintf(stderr, "th #%2d: created=%d executing=%d"
					" ready=%d done=%d call_index=%d res=%lld reserrno=%d\n",
				i, th1->created, th1->executing,
				event_isset(&th1->ready), event_isset(&th1->done),
				th1->call_index, (uint64)th1->res, th1->reserrno);
		}
		exitf("negative running");
	}
}

void copyout_call_results(thread_t* th)
{
	if (th->copyout_index != no_copyout) {
		if (th->copyout_index >= kMaxCommands)
			failmsg("result overflows kMaxCommands", "index=%lld", th->copyout_index);
		results[th->copyout_index].executed = true;
		results[th->copyout_index].val = th->res;
	}
	for (bool done = false; !done;) {
		uint64 instr = read_input(&th->copyout_pos);
		switch (instr) {
		case instr_copyout: {
			uint64 index = read_input(&th->copyout_pos);
			if (index >= kMaxCommands)
				failmsg("result overflows kMaxCommands", "index=%lld", index);
			char* addr = (char*)(read_input(&th->copyout_pos) + SYZ_DATA_OFFSET);
			uint64 size = read_input(&th->copyout_pos);
			uint64 val = 0;
			if (copyout(addr, size, &val)) {
				results[index].executed = true;
				results[index].val = val;
			}
			debug_verbose("copyout 0x%llx from %p\n", val, addr);
			break;
		}
		default:
			done = true;
			break;
		}
	}
}

void write_output(int index, cover_t* cov, rpc::CallFlag flags, uint32 error, bool all_signal)
{
#if GOOS_windows
	nyx_log_exec_stage("write_output_begin", (uint64)(int64_t)index, static_cast<uint64>(flags), error,
			   output_data ? output_data->completed.load(std::memory_order_relaxed) : 0);
#endif
	CoverAccessScope scope(cov);
	auto& fbb = *output_builder;
	const uint32 start_size = output_builder->GetSize();
	(void)start_size;
	uint32 signal_off = 0;
	uint32 cover_off = 0;
	uint32 comps_off = 0;
	if (flag_comparisons) {
		comps_off = write_comparisons(fbb, cov);
	} else {
		if (flag_collect_signal) {
			if (is_kernel_64_bit)
				signal_off = write_signal<uint64>(fbb, index, cov, all_signal);
			else
				signal_off = write_signal<uint32>(fbb, index, cov, all_signal);
		}
		if (flag_collect_cover) {
			if (is_kernel_64_bit)
				cover_off = write_cover<uint64>(fbb, cov);
			else
				cover_off = write_cover<uint32>(fbb, cov);
		}
	}

	rpc::CallInfoRawBuilder builder(*output_builder);
	if (cov->overflow)
		flags |= rpc::CallFlag::CoverageOverflow;
	builder.add_flags(flags);
	builder.add_error(error);
	if (signal_off)
		builder.add_signal(signal_off);
	if (cover_off)
		builder.add_cover(cover_off);
	if (comps_off)
		builder.add_comps(comps_off);
	auto off = builder.Finish();
	uint32 slot = output_data->completed.load(std::memory_order_relaxed);
	if (slot >= kMaxCalls)
		failmsg("too many calls in output", "slot=%d", slot);
	auto& call = output_data->calls[slot];
	call.index = index;
	call.offset = off;
	output_data->consumed.store(output_builder->GetSize(), std::memory_order_release);
	output_data->completed.store(slot + 1, std::memory_order_release);
	debug_verbose("out #%u: index=%u errno=%d flags=0x%x total_size=%u\n",
		      slot + 1, index, error, static_cast<unsigned>(flags), call.data_size - start_size);
#if GOOS_windows
	nyx_log_exec_stage("write_output_done", (uint64)(int64_t)index, slot + 1, error,
			   output_builder->GetSize());
#endif
}

void write_call_output(thread_t* th, bool finished)
{
	uint32 reserrno = ENOSYS;
	rpc::CallFlag flags = rpc::CallFlag::Executed;
	if (finished && th != last_scheduled)
		flags |= rpc::CallFlag::Blocked;
	if (finished) {
		reserrno = th->res != -1 ? 0 : th->reserrno;
		flags |= rpc::CallFlag::Finished;
		if (th->fault_injected)
			flags |= rpc::CallFlag::FaultInjected;
	}
	bool all_signal = th->call_index < 64 ? (all_call_signal & (1ull << th->call_index)) : false;
	write_output(th->call_index, &th->cov, flags, reserrno, all_signal);
}

void write_extra_output()
{
	if (!cover_collection_required() || !flag_extra_coverage || flag_comparisons)
		return;
	cover_collect(&extra_cov);
	if (!extra_cov.size)
		return;
	write_output(-1, &extra_cov, rpc::CallFlag::NONE, 997, all_extra_signal);
	cover_reset(&extra_cov);
}

flatbuffers::span<uint8_t> finish_output(OutputData* output, int proc_id, uint64 req_id, uint32 num_calls, uint64 elapsed,
					 uint64 freshness, uint32 status, bool hanged, const std::vector<uint8_t>* process_output)
{
	// In snapshot mode the output size is fixed and output_size is always initialized, so use it.
	int out_size = flag_snapshot ? output_size : output->size.load(std::memory_order_relaxed) ?
												  : kMaxOutput;
	uint32 completed = output->completed.load(std::memory_order_relaxed);
	completed = std::min(completed, kMaxCalls);
#if GOOS_windows
	nyx_log_exec_stage("finish_output_begin", num_calls, completed, out_size, hanged);
#endif
	debug("handle completion: completed=%u output_size=%u\n", completed, out_size);
	ShmemBuilder fbb(output, out_size, false);
	auto empty_call = rpc::CreateCallInfoRawDirect(fbb, rpc::CallFlag::NONE, 998);
	std::vector<flatbuffers::Offset<rpc::CallInfoRaw>> calls(num_calls, empty_call);
	std::vector<flatbuffers::Offset<rpc::CallInfoRaw>> extra;
	for (uint32_t i = 0; i < completed; i++) {
		const auto& call = output->calls[i];
		if (call.index == -1) {
			extra.push_back(call.offset);
			continue;
		}
		if (call.index < 0 || call.index >= static_cast<int>(num_calls) || call.offset.o > kMaxOutput) {
			debug("bad call index/offset: proc=%d req=%llu call=%d/%d completed=%d offset=%u",
			      proc_id, req_id, call.index, num_calls,
			      completed, call.offset.o);
			continue;
		}
		calls[call.index] = call.offset;
	}
	auto prog_info_off = rpc::CreateProgInfoRawDirect(fbb, &calls, &extra, 0, elapsed, freshness);
	flatbuffers::Offset<flatbuffers::String> error_off = 0;
	if (status == kFailStatus)
		error_off = fbb.CreateString("process failed");
	// If the request wrote binary result (currently glob requests do this), use it instead of the output.
	auto output_off = output->result_offset.load(std::memory_order_relaxed);
	if (output_off.IsNull() && process_output)
		output_off = fbb.CreateVector(*process_output);
	auto exec_off = rpc::CreateExecResultRaw(fbb, req_id, proc_id, output_off, hanged, error_off, prog_info_off);
	auto msg_off = rpc::CreateExecutorMessageRaw(fbb, rpc::ExecutorMessagesRaw::ExecResult,
						     flatbuffers::Offset<void>(exec_off.o));
	fbb.FinishSizePrefixed(msg_off);
	auto span = fbb.GetBufferSpan();
#if GOOS_windows
	nyx_log_exec_stage("finish_output_done", span.size(), completed, output_off.o, status);
#endif
	return span;
}

#if GOOS_windows
static bool nyx_dump_exec_result(const char* basename, flatbuffers::span<uint8_t> data)
{
	return nyx_dump_bytes(basename, data.data(), data.size(), false);
}

static bool nyx_dump_ack()
{
	static const char ok[] = "ok";
	return nyx_dump_bytes(NYX_HANDSHAKE_ACK_BASENAME, ok, sizeof(ok) - 1, false);
}

#if SYZ_NYX_WINDOWS_DEMO
struct nyx_demo_call_t {
	uint64 call_num;
	uint64 args[kMaxArgs];
	uint64 num_args;
};

struct nyx_demo_program_t {
	uint64 total_calls;
	uint64 num_calls;
	nyx_demo_call_t calls[kMaxCalls];
};

static nyx_demo_program_t nyx_demo_parse_program(const uint8* prog_data, uint32 prog_size)
{
	nyx_demo_program_t parsed = {};
	if (!prog_data || prog_size == 0)
		return parsed;
	uint8* saved_input = input_data;
	input_data = const_cast<uint8*>(prog_data);
	uint8* pos = input_data;

	parsed.total_calls = read_input(&pos);
	for (;;) {
		uint64 call_num = read_input(&pos);
		if (call_num == instr_eof)
			break;
		if (call_num == instr_copyin) {
			char* addr = (char*)(read_input(&pos) + SYZ_DATA_OFFSET);
			uint64 typ = read_input(&pos);
			switch (typ) {
			case arg_const: {
				uint64 size, bf, bf_off, bf_len;
				uint64 arg = read_const_arg(&pos, &size, &bf, &bf_off, &bf_len);
				copyin(addr, arg, size, bf, bf_off, bf_len);
				break;
			}
			case arg_addr32:
			case arg_addr64: {
				uint64 val = read_input(&pos) + SYZ_DATA_OFFSET;
				if (typ == arg_addr32)
					NONFAILING(*(uint32*)addr = val);
				else
					NONFAILING(*(uint64*)addr = val);
				break;
			}
			case arg_result: {
				uint64 meta = read_input(&pos);
				uint64 size = meta & 0xff;
				uint64 bf = meta >> 8;
				uint64 val = read_result(&pos);
				copyin(addr, val, size, bf, 0, 0);
				break;
			}
			case arg_data: {
				uint64 size = read_input(&pos);
				size &= ~(1ull << 63);
				if (pos + size > input_data + prog_size)
					fail("demo data arg overflow");
				NONFAILING(memcpy(addr, pos, size));
				pos += size;
				break;
			}
			default:
				failmsg("bad demo argument type", "type=%llu", typ);
			}
			continue;
		}
		if (call_num == instr_copyout) {
			read_input(&pos);
			read_input(&pos);
			read_input(&pos);
			continue;
		}
		if (call_num == instr_setprops) {
			read_input(&pos);
			continue;
		}
		uint64 copyout_index = read_input(&pos);
		(void)copyout_index;
		uint64 num_args = read_input(&pos);
		if (num_args > kMaxArgs)
			failmsg("demo command has bad number of arguments", "args=%llu", num_args);
		if (parsed.num_calls >= kMaxCalls)
			failmsg("demo program has too many calls", "num_calls=%llu", parsed.num_calls);
		auto& call = parsed.calls[parsed.num_calls++];
		call.call_num = call_num;
		call.num_args = num_args;
		for (uint64 i = 0; i < num_args; i++)
			call.args[i] = read_arg(&pos);
	}
	input_data = saved_input;
	return parsed;
}

static bool nyx_demo_execute_one_call(OutputData* output, const nyx_demo_call_t& call,
				      uint64 call_index, uint64 req_id,
				      kafl_syz_cov_cmd_t* cov_cmd, cover_t* dummy)
{
	if (call.call_num >= ARRAY_SIZE(syscalls))
		failmsg("demo invalid syscall number", "call_index=%llu call_num=%llu",
			call_index, call.call_num);
	const call_t* c = &syscalls[call.call_num];
	if (!c->name)
		failmsg("demo unsupported syscall", "call_index=%llu call_num=%llu name=%s",
			call_index, call.call_num, c->name ? c->name : "<null>");

	cov_cmd->call_index = (uint32)call_index;
	cov_cmd->slot_id = 0;
	cov_cmd->flags = 0;

	if (strcmp(c->name, "VirtualAlloc") == 0) {
		void* addr = (void*)(uintptr_t)call.args[0];
		SIZE_T size = (SIZE_T)call.args[1];
		DWORD alloc_type = (DWORD)call.args[2];
		DWORD protect = (DWORD)call.args[3];
		nyx_hprintf("nyx demo exec call=%llu VirtualAlloc addr=0x%llx size=0x%llx type=0x%lx protect=0x%lx request=%lld\n",
			    (unsigned long long)call_index,
			    (unsigned long long)(uintptr_t)addr,
			    (unsigned long long)size,
			    (unsigned long)alloc_type,
			    (unsigned long)protect,
			    (long long)req_id);
		nyx_hypercall(HYPERCALL_KAFL_SYZ_COV_RESET, (uint64_t)(uintptr_t)cov_cmd);
		nyx_hypercall(HYPERCALL_KAFL_ACQUIRE, ((uint64_t)GetCurrentThreadId() << 32) | (__readgsqword(0x30) & 0xFFFFFFFF));
		void* result = VirtualAlloc(addr, size, alloc_type, protect);
		nyx_hypercall(HYPERCALL_KAFL_RELEASE, 0);
		nyx_hypercall(HYPERCALL_KAFL_SYZ_COV_DUMP, (uint64_t)(uintptr_t)cov_cmd);
		nyx_hprintf("nyx demo exec call=%llu VirtualAlloc done result=0x%llx request=%lld\n",
			    (unsigned long long)call_index,
			    (unsigned long long)(uintptr_t)result,
			    (long long)req_id);
		write_output((uint32)call_index, dummy,
			     rpc::CallFlag::Executed | rpc::CallFlag::Finished,
			     result ? 0 : EINVAL, false);
		return true;
	}

	if (strcmp(c->name, "NtQuerySystemInformation") != 0) {
		nyx_hprintf("nyx demo exec call=%llu unsupported syscall=%s\n",
			    (unsigned long long)call_index, c->name);
		write_output((uint32)call_index, dummy,
			     rpc::CallFlag::Executed | rpc::CallFlag::Finished,
			     ENOSYS, false);
		return true;
	}

	uint32 info_class = (uint32)call.args[0];
	void* orig_buf = (void*)(uintptr_t)call.args[1];
	uint32 buffer_size = (uint32)call.args[2];
	ULONG* orig_ret_len = (ULONG*)(uintptr_t)call.args[3];
	if (buffer_size == 0)
		buffer_size = 0x1000;
	if (buffer_size > 0x10000)
		buffer_size = 0x10000;
	void* buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buffer)
		fail("demo VirtualAlloc syscall buffer failed");
	if (orig_buf)
		memcpy(buffer, orig_buf, buffer_size);
	ULONG ret_len = orig_ret_len ? *orig_ret_len : 0;

	nyx_hprintf("nyx demo exec call=%llu class=%u size=0x%x buf=0x%llx retlen_ptr=0x%llx request=%lld\n",
		    (unsigned long long)call_index, info_class, buffer_size,
		    (unsigned long long)(uintptr_t)orig_buf,
		    (unsigned long long)(uintptr_t)orig_ret_len,
		    (long long)req_id);
	nyx_hypercall(HYPERCALL_KAFL_SYZ_COV_RESET, (uint64_t)(uintptr_t)cov_cmd);
	nyx_hypercall(HYPERCALL_KAFL_ACQUIRE, ((uint64_t)GetCurrentThreadId() << 32) | (__readgsqword(0x30) & 0xFFFFFFFF));
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)info_class,
						   buffer, buffer_size, &ret_len);
	nyx_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	nyx_hypercall(HYPERCALL_KAFL_SYZ_COV_DUMP, (uint64_t)(uintptr_t)cov_cmd);
	if (orig_buf)
		memcpy(orig_buf, buffer, buffer_size);
	if (orig_ret_len)
		*orig_ret_len = ret_len;
	nyx_hprintf("nyx demo exec call=%llu done class=%u size=0x%x status=0x%08lx ret=%lu request=%lld\n",
		    (unsigned long long)call_index, info_class, buffer_size,
		    (unsigned long)status, ret_len, (long long)req_id);
	VirtualFree(buffer, 0, MEM_RELEASE);

	uint32 error = NT_SUCCESS(status) ? 0 : EINVAL;
	write_output((uint32)call_index, dummy,
		     rpc::CallFlag::Executed | rpc::CallFlag::Finished, error, false);
	return true;
}

static flatbuffers::span<uint8_t> nyx_demo_execute_request(OutputData* output,
							   int32_t proc_id,
							   uint64 req_id,
							   uint64 freshness,
							   const rpc::SnapshotRequest* msg,
							   const kafl_syz_cov_cmd_t* cov_cmd_in)
{
	auto parsed = nyx_demo_parse_program(msg->prog_data() ? msg->prog_data()->Data() : nullptr,
					     msg->prog_data() ? msg->prog_data()->size() : 0);
	if (parsed.num_calls == 0)
		fail("demo failed to parse exec program (no calls)");

	nyx_hprintf("nyx demo exec multi-call total=%llu parsed=%llu request=%lld\n",
		    (unsigned long long)parsed.total_calls,
		    (unsigned long long)parsed.num_calls,
		    (long long)req_id);

	uint64 exec_start = current_time_ms();
	output_builder.emplace(output, output_size, !flag_snapshot);
	output_data->num_calls.store((uint32)parsed.num_calls, std::memory_order_relaxed);
	cover_t dummy = {};
	kafl_syz_cov_cmd_t cov_cmd_local = *cov_cmd_in;

	for (uint64 i = 0; i < parsed.num_calls; i++)
		nyx_demo_execute_one_call(output, parsed.calls[i], i, req_id,
					  &cov_cmd_local, &dummy);

	return finish_output(output, proc_id, req_id, (uint32)parsed.num_calls,
			     (current_time_ms() - exec_start) * 1000 * 1000,
			     freshness, 0, false, nullptr);
}
#endif

static void nyx_finish_exec_payload(const nyx_exec_meta_t* meta, uint32 calls)
{
	if (meta->flags & SYZ_NYX_EXEC_KEEP_STATE) {
		nyx_hprintf("nyx result kept guest state request=%lld calls=%u flags=0x%x\n",
			    (long long)meta->request_id, calls, (unsigned)meta->flags);
		return;
	}
	nyx_hprintf("nyx result requesting reload request=%lld calls=%u flags=0x%x\n",
		    (long long)meta->request_id, calls, (unsigned)meta->flags);
	nyx_hypercall(HYPERCALL_KAFL_REQUEST_RELOAD, 0);
}

static int nyx_mode_loop(int argc, char** argv)
{
	(void)argc;
	(void)argv;
	nyx_host_config_t host_cfg = {};
	if (!nyx_fetch_host_config(&host_cfg))
		fail("failed to fetch Nyx host config");

	nyx_hypercall(HYPERCALL_KAFL_ACQUIRE, ((uint64_t)GetCurrentThreadId() << 32) | (__readgsqword(0x30) & 0xFFFFFFFF));
	nyx_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	auto* payload = static_cast<kAFL_payload*>(VirtualAlloc(nullptr, host_cfg.payload_buffer_size,
								MEM_COMMIT | MEM_RESERVE,
								PAGE_READWRITE));
	if (payload == nullptr)
		fail("failed to allocate Nyx payload buffer");
	memset(payload, 0, host_cfg.payload_buffer_size);

	nyx_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

	nyx_agent_config_t agent_cfg = {};
	agent_cfg.agent_magic = NYX_AGENT_MAGIC;
	agent_cfg.agent_version = NYX_AGENT_VERSION;
	agent_cfg.agent_non_reload_mode = 1;
	agent_cfg.coverage_bitmap_size = host_cfg.bitmap_size;
	nyx_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uint64_t)(uintptr_t)&agent_cfg);
	nyx_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint64_t)(uintptr_t)payload);
	if (!nyx_submit_module_ranges(payload))
		fail("failed to submit required module ranges");

#if SYZ_NET_INJECTION
	initialize_windows_net_injection();
#endif

	nyx_hprintf("nyx executor build marker=20260427b demo=%d sparse=%d generic=%d\n",
		    (int)SYZ_NYX_WINDOWS_DEMO,
		    (int)SYZ_NYX_WINDOWS_SPARSE_TABLE,
		    (int)SYZ_NYX_USE_GENERIC_PATH);

	std::vector<uint8_t> output_mem;
	uint64_t freshness = 1;
	bool have_handshake = false;
	handshake_req hs = {};
	kafl_syz_cov_cmd_t cov_cmd = {};

	for (;;) {
		nyx_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
		if (payload->size < (int32_t)sizeof(nyx_msg_header_t))
			fail("Nyx payload too small");

		auto* header = reinterpret_cast<nyx_msg_header_t*>(payload->data);
		if (header->magic != SYZ_NYX_MSG_MAGIC || header->version != SYZ_NYX_MSG_VERSION)
			fail("bad Nyx payload header");
		if (sizeof(*header) + header->body_size > (uint32_t)payload->size)
			fail("Nyx payload body overflow");

		const uint8_t* body = payload->data + sizeof(*header);
		nyx_hprintf("nyx payload header kind=%u body=%u total=%d\n",
			    (unsigned)header->kind,
			    (unsigned)header->body_size,
			    (int)payload->size);
		if (header->kind == SYZ_NYX_KIND_HANDSHAKE) {
			nyx_hprintf("nyx handshake body ready body=%u total=%d\n",
				    (unsigned)header->body_size,
				    (int)payload->size);
			auto* msg = flatbuffers::GetRoot<rpc::SnapshotHandshake>(body);
			nyx_hprintf("nyx handshake root parsed body=%u\n",
				    (unsigned)header->body_size);
			hs = {
			    .magic = kInMagic,
			    .use_cover_edges = msg->cover_edges(),
			    .is_kernel_64_bit = msg->kernel_64_bit(),
			    .flags = msg->env_flags(),
			    .pid = 0,
			    .sandbox_arg = static_cast<uint64>(msg->sandbox_arg()),
			    .syscall_timeout_ms = static_cast<uint64>(msg->syscall_timeout_ms()),
			    .program_timeout_ms = static_cast<uint64>(msg->program_timeout_ms()),
			    .slowdown_scale = static_cast<uint64>(msg->slowdown()),
			};
			nyx_hprintf("nyx handshake begin env=0x%llx features=0x%llx slowdown=%llu timeouts=%llu/%llu\n",
				    (unsigned long long)msg->env_flags(),
				    (unsigned long long)msg->features(),
				    (unsigned long long)msg->slowdown(),
				    (unsigned long long)msg->syscall_timeout_ms(),
				    (unsigned long long)msg->program_timeout_ms());
			parse_handshake(hs);
			setup_coverage();
#if SYZ_NYX_WINDOWS_SUBMIT_CR3
			uint64_t cr3 = 0;
			if (nyx_query_cr3(&cr3)) {
				nyx_hprintf("nyx handshake submit_cr3=0x%llx\n",
					    (unsigned long long)cr3);
				nyx_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, cr3);
			} else {
				nyx_hprintf("nyx handshake query_cr3 unavailable\n");
			}
#else
			nyx_hprintf("nyx handshake submit_cr3 disabled at build time\n");
#endif
			have_handshake = true;
			nyx_hprintf("nyx handshake dumping ack\n");
			nyx_dump_ack();
			nyx_hprintf("nyx handshake ack dumped\n");
			continue;
		}

		if (header->kind == SYZ_NYX_KIND_IDLE) {
			if (!have_handshake)
				fail("received idle payload before handshake");
			if (header->body_size < sizeof(nyx_idle_meta_t))
				fail("Nyx idle payload too small");
			auto* idle = reinterpret_cast<const nyx_idle_meta_t*>(body);
			uint32 sleep_ms = idle->sleep_ms;
			if (sleep_ms > 10000)
				fail("Nyx idle payload sleep too large");
			if (sleep_ms != 0)
				nyx_hprintf("nyx idle begin sleep_ms=%u\n", (unsigned)sleep_ms);
#if GOOS_windows
			Sleep(sleep_ms);
#else
			struct timespec ts = {
			    .tv_sec = sleep_ms / 1000,
			    .tv_nsec = (long)(sleep_ms % 1000) * 1000000L,
			};
			nanosleep(&ts, nullptr);
#endif
			if (output_mem.empty()) {
				output_mem.resize(kMaxOutput);
				output_data = reinterpret_cast<OutputData*>(output_mem.data());
				output_size = output_mem.size();
			}
			output_data->Reset();
			output_data->size.store(output_size, std::memory_order_relaxed);
			output_data->num_calls.store(0, std::memory_order_relaxed);
			auto result = finish_output(output_data, 0, 0, 0, (uint64)sleep_ms * 1000 * 1000,
						    freshness++, 0, false, nullptr);
			nyx_dump_exec_result(NYX_RESULT_BASENAME, result);
			nyx_hprintf("nyx idle kept guest state sleep_ms=%u\n", (unsigned)sleep_ms);
			if (sleep_ms != 0)
				nyx_hprintf("nyx idle result dumped sleep_ms=%u bytes=%u\n",
					    (unsigned)sleep_ms, (unsigned)result.size());
			continue;
		}

		if (header->kind != SYZ_NYX_KIND_EXEC)
			fail("unknown Nyx payload kind");
		if (!have_handshake)
			fail("received exec payload before handshake");
		if (header->body_size < sizeof(nyx_exec_meta_t))
			fail("Nyx exec payload too small");

		auto* meta = reinterpret_cast<const nyx_exec_meta_t*>(body);
		auto* msg = flatbuffers::GetRoot<rpc::SnapshotRequest>(body + sizeof(*meta));
		execute_req req = {
		    .id = static_cast<uint64>(meta->request_id),
		    .type = rpc::RequestType::Program,
		    .exec_flags = static_cast<uint64>(msg->exec_flags()),
		    .all_call_signal = msg->all_call_signal(),
		    .all_extra_signal = msg->all_extra_signal(),
		};
		parse_execute(req);
		input_data = const_cast<uint8*>(msg->prog_data() ? msg->prog_data()->Data() : nullptr);
		nyx_hprintf("nyx exec req=%lld proc=%d body=%u prog=%u calls=%d threaded=%d exec_flags=0x%llx\n",
			    (long long)meta->request_id, meta->proc_id, header->body_size,
			    msg->prog_data() ? msg->prog_data()->size() : 0, msg->num_calls(),
			    flag_threaded, (unsigned long long)req.exec_flags);
		nyx_log_exec_preview(input_data, msg->prog_data() ? msg->prog_data()->size() : 0);

		memset(results, 0, sizeof(results));
		running = 0;
		last_scheduled = nullptr;
		if (output_mem.empty()) {
			output_mem.resize(kMaxOutput);
			output_data = reinterpret_cast<OutputData*>(output_mem.data());
			output_size = output_mem.size();
		}
		output_data->Reset();
		output_data->size.store(output_size, std::memory_order_relaxed);
		output_data->num_calls.store(msg->num_calls(), std::memory_order_relaxed);

		cov_cmd.call_index = 0;
		cov_cmd.slot_id = 0;
		cov_cmd.flags = 0;

#if SYZ_NYX_WINDOWS_DEMO && !SYZ_NYX_USE_GENERIC_PATH
		nyx_hprintf("nyx demo direct path forced calls=%u prog=%u\n",
			    msg->num_calls(),
			    msg->prog_data() ? msg->prog_data()->size() : 0);
		auto demo_result = nyx_demo_execute_request(output_data, meta->proc_id,
							    meta->request_id, freshness++,
							    msg, &cov_cmd);
		nyx_finish_exec_payload(meta, msg->num_calls());
		nyx_dump_exec_result(NYX_RESULT_BASENAME, demo_result);
		nyx_hprintf("nyx result dumped request=%lld bytes=%u\n",
			    (long long)meta->request_id, (unsigned)demo_result.size());
		continue;
#endif
		nyx_hprintf("nyx generic branch selected calls=%u\n", msg->num_calls());

		uint64_t exec_start = current_time_ms();
		nyx_hprintf("nyx exec stage=pre_cov_reset request=%lld\n", (long long)meta->request_id);
		nyx_log_exec_stage("nyx_pre_cov_reset", meta->request_id, msg->num_calls());
		nyx_hypercall(HYPERCALL_KAFL_SYZ_COV_RESET, (uint64_t)(uintptr_t)&cov_cmd);
		nyx_hprintf("nyx exec stage=post_cov_reset request=%lld\n", (long long)meta->request_id);
		nyx_log_exec_stage("nyx_post_cov_reset", meta->request_id, msg->num_calls());
		nyx_hprintf("nyx exec stage=pre_execute_one request=%lld\n", (long long)meta->request_id);
		nyx_log_exec_stage("nyx_pre_execute_one", meta->request_id, msg->num_calls());
		execute_one();
		nyx_hprintf("nyx exec stage=post_execute_one request=%lld\n", (long long)meta->request_id);
		nyx_log_exec_stage("nyx_post_execute_one", meta->request_id, msg->num_calls(),
				   output_data->completed.load(std::memory_order_relaxed));
#if GOOS_windows
		windows_drain_worker_idle_before_nyx_result();
#endif
		nyx_hprintf("nyx exec stage=post_release request=%lld\n", (long long)meta->request_id);
		nyx_hprintf("nyx exec returned request=%lld\n", (long long)meta->request_id);
		nyx_log_exec_stage("nyx_pre_cov_dump", meta->request_id, msg->num_calls());
		nyx_hypercall(HYPERCALL_KAFL_SYZ_COV_DUMP, (uint64_t)(uintptr_t)&cov_cmd);
		nyx_hprintf("nyx cov dumped request=%lld\n", (long long)meta->request_id);
		nyx_log_exec_stage("nyx_post_cov_dump", meta->request_id, msg->num_calls(),
				   output_data->completed.load(std::memory_order_relaxed));

		nyx_log_exec_stage("nyx_pre_finish_output", meta->request_id, msg->num_calls(),
				   current_time_ms() - exec_start);
		auto result = finish_output(output_data, meta->proc_id, meta->request_id, msg->num_calls(),
					    (current_time_ms() - exec_start) * 1000 * 1000,
					    freshness++, 0, false, nullptr);
		nyx_log_exec_stage("nyx_post_finish_output", meta->request_id, result.size(),
				   output_data->completed.load(std::memory_order_relaxed));
		nyx_log_exec_stage("nyx_pre_finish_payload", meta->request_id, msg->num_calls());
		nyx_finish_exec_payload(meta, msg->num_calls());
		nyx_log_exec_stage("nyx_post_finish_payload", meta->request_id, msg->num_calls());
		nyx_log_exec_stage("nyx_pre_result_dump", meta->request_id, result.size());
		bool dumped = nyx_dump_exec_result(NYX_RESULT_BASENAME, result);
		nyx_log_exec_stage("nyx_post_result_dump", meta->request_id, result.size(), dumped);
		nyx_hprintf("nyx result dumped request=%lld bytes=%u\n",
			    (long long)meta->request_id, (unsigned)result.size());
	}
}
#endif

void thread_create(thread_t* th, int id, bool need_coverage)
{
	th->created = true;
	th->id = id;
	th->executing = false;
	th->handoff_seq = 0;
	th->worker_tid = 0;
	th->worker_wait_seq = 0;
	th->call_index = -1;
	th->call_num = -1;
	th->num_args = 0;
	// Lazily set up coverage collection.
	// It is assumed that actually it's already initialized - with a few rare exceptions.
	if (need_coverage) {
		if (!th->cov.fd)
			exitf("out of opened kcov threads");
		thread_mmap_cover(th);
	}
	event_init(&th->ready);
	event_init(&th->done);
	event_init(&th->idle);
#if GOOS_windows
	if (flag_threaded) {
		thread_start(worker_thread, th);
		nyx_log_thread_stage("thread_create_pre_idle_wait", th, event_isset(&th->idle),
				     th->handoff_seq, th->worker_tid, kWindowsWorkerIdleWaitMs);
		int idle_seen = windows_yield_until_event(&th->idle, kWindowsWorkerIdleYields,
							  kWindowsWorkerIdleWaitMs);
		nyx_log_thread_stage("thread_create_post_idle_wait", th, idle_seen,
				     event_isset(&th->idle), th->worker_tid, th->worker_wait_seq);
	}
	event_set(&th->done);
#else
	event_set(&th->done);
	if (flag_threaded)
		thread_start(worker_thread, th);
#endif
}

void thread_mmap_cover(thread_t* th)
{
	if (th->cov.data != NULL)
		return;
	cover_mmap(&th->cov);
	cover_protect(&th->cov);
}

void* worker_thread(void* arg)
{
	thread_t* th = (thread_t*)arg;
	current_thread = th;
#if GOOS_windows
	th->worker_tid = GetCurrentThreadId();
	nyx_log_thread_stage("worker_thread_started", th, th->worker_tid,
			     th->handoff_seq);
#endif
	for (bool first = true;; first = false) {
#if GOOS_windows
		th->worker_wait_seq = th->handoff_seq;
		if (!event_isset(&th->idle))
			event_set(&th->idle);
		nyx_log_thread_stage("worker_wait_ready_begin", th, event_isset(&th->ready),
				     event_isset(&th->done), th->executing, th->worker_wait_seq);
#endif
		event_wait(&th->ready);
#if GOOS_windows
		nyx_log_thread_stage("worker_ready_seen", th, event_isset(&th->ready),
				     event_isset(&th->done), th->executing, th->handoff_seq);
#endif
		event_reset(&th->ready);
#if GOOS_windows
		nyx_log_thread_stage("worker_ready_reset", th, event_isset(&th->ready),
				     event_isset(&th->done), th->executing);
#endif
		// Setup coverage only after receiving the first ready event
		// because in snapshot mode we don't know coverage mode for precreated threads.
		if (first && cover_collection_required())
			cover_enable(&th->cov, flag_comparisons, false);
#if GOOS_windows
		nyx_log_thread_stage("worker_pre_execute_call", th, event_isset(&th->done),
				     th->executing);
#endif
		execute_call(th);
#if GOOS_windows
		nyx_log_thread_stage("worker_after_execute_call", th, event_isset(&th->done),
				     th->executing);
		nyx_log_thread_stage("worker_pre_done_set", th, event_isset(&th->done),
				     th->executing);
#endif
		event_set(&th->done);
	}
	return 0;
}

#if GOOS_windows
static bool is_windows_nyx_vnet_call(const call_t* call)
{
	return call->name && (strcmp(call->name, "syz_emit_ethernet$windows") == 0 ||
			      strcmp(call->name, "syz_extract_tcp_res$windows") == 0 ||
			      strcmp(call->name, "syz_extract_tcp_res$windows_synack") == 0);
}
#endif

void execute_call(thread_t* th)
{
	const call_t* call = &syscalls[th->call_num];
#if GOOS_windows
	if (call->call == nullptr) {
		failmsg("null syscall entry", "call=%d name=%s", th->call_num,
			call->name ? call->name : "<null>");
	}
#endif
	debug("#%d [%llums] -> %s(",
	      th->id, current_time_ms() - start_time_ms, call->name);
	for (int i = 0; i < th->num_args; i++) {
		if (i != 0)
			debug(", ");
		debug("0x%llx", (uint64)th->args[i]);
	}
	debug(")\n");

	int fail_fd = -1;
	th->soft_fail_state = false;
	if (th->call_props.fail_nth > 0) {
		if (th->call_props.rerun > 0)
			fail("both fault injection and rerun are enabled for the same call");
		fail_fd = inject_fault(th->call_props.fail_nth);
		th->soft_fail_state = true;
	}

	if (flag_coverage)
		cover_reset(&th->cov);
	// For pseudo-syscalls and user-space functions NONFAILING can abort before assigning to th->res.
	// Arrange for res = -1 and errno = EFAULT result for such case.
	th->res = -1;
	errno = EFAULT;
#if GOOS_windows
#if SYZ_NYX_WINDOWS_SPARSE_TABLE
	if (call->name && strcmp(call->name, "NtQuerySystemInformation") == 0 &&
	    !nyx_prepare_syscall(call, th->args))
		failmsg("nyx_prepare_syscall failed", "call=%d name=%s", th->call_num,
			call->name ? call->name : "<null>");
#endif
	if (is_windows_nyx_vnet_call(call)) {
		nyx_log_exec_stage("execute_call_vnet_no_acquire", th->id, th->call_num, th->num_args);
		NONFAILING(th->res = execute_syscall(call, th->args));
		nyx_log_exec_stage("execute_call_vnet_done", th->id, th->call_num, (uint64)th->res, errno);
		goto windows_nyx_call_done;
	}
	nyx_log_exec_stage("execute_call_pre_acquire", th->id, th->call_num, th->num_args);
	{
		kafl_syz_cov_cmd_t cov_cmd_ = {(uint32)th->call_index, 0, 0};
		nyx_hypercall(HYPERCALL_KAFL_SYZ_COV_RESET, (uint64_t)(uintptr_t)&cov_cmd_);
	}
	nyx_hypercall(HYPERCALL_KAFL_ACQUIRE, ((uint64_t)GetCurrentThreadId() << 32) | (__readgsqword(0x30) & 0xFFFFFFFF));
#endif
	NONFAILING(th->res = execute_syscall(call, th->args));
#if GOOS_windows
	nyx_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	nyx_log_thread_stage("execute_call_after_release", th, (uint64)th->res, errno);
	// Per-call coverage is dumped by the RELEASE handler in QEMU.
#if SYZ_NYX_WINDOWS_SPARSE_TABLE
	nyx_log_thread_stage("execute_call_pre_finish_syscall", th, (uint64)th->res, errno);
	nyx_finish_syscall(call, th->args);
	nyx_log_thread_stage("execute_call_post_finish_syscall", th, (uint64)th->res, errno);
#endif
	nyx_log_thread_stage("execute_call_post_release", th, (uint64)th->res, errno);
windows_nyx_call_done:
#endif
#if GOOS_windows
	nyx_log_thread_stage("execute_call_pre_reserrno", th, (uint64)th->res, errno);
#endif
	th->reserrno = errno;
	// Our pseudo-syscalls may misbehave.
	if ((th->res == -1 && th->reserrno == 0) || call->attrs.ignore_return)
		th->reserrno = EINVAL;
	// Reset the flag before the first possible fail().
	th->soft_fail_state = false;
#if GOOS_windows
	nyx_log_thread_stage("execute_call_post_reserrno", th, (uint64)th->res, th->reserrno);
#endif

	if (flag_coverage) {
#if GOOS_windows
		nyx_log_thread_stage("execute_call_pre_cover_collect", th, th->cov.size,
				     th->cov.overflow);
#endif
		cover_collect(&th->cov);
#if GOOS_windows
		nyx_log_thread_stage("execute_call_post_cover_collect", th, th->cov.size,
				     th->cov.overflow);
#endif
	}
	th->fault_injected = false;

	if (th->call_props.fail_nth > 0) {
#if GOOS_windows
		nyx_log_thread_stage("execute_call_pre_fault_check", th, th->call_props.fail_nth);
#endif
		th->fault_injected = fault_injected(fail_fd);
#if GOOS_windows
		nyx_log_thread_stage("execute_call_post_fault_check", th, th->fault_injected);
#endif
	}

	// If required, run the syscall some more times.
	// But let's still return res, errno and coverage from the first execution.
	for (int i = 0; i < th->call_props.rerun; i++) {
#if GOOS_windows
		nyx_log_thread_stage("execute_call_pre_rerun", th, i, th->call_props.rerun);
#endif
		NONFAILING(execute_syscall(call, th->args));
#if GOOS_windows
		nyx_log_thread_stage("execute_call_post_rerun", th, i, th->call_props.rerun);
#endif
	}

	debug("#%d [%llums] <- %s=0x%llx",
	      th->id, current_time_ms() - start_time_ms, call->name, (uint64)th->res);
	if (th->res == (intptr_t)-1)
		debug(" errno=%d", th->reserrno);
	if (flag_coverage)
		debug(" cover=%u", th->cov.size);
	if (th->call_props.fail_nth > 0)
		debug(" fault=%d", th->fault_injected);
	if (th->call_props.rerun > 0)
		debug(" rerun=%d", th->call_props.rerun);
	debug("\n");
#if GOOS_windows
	nyx_log_thread_stage("execute_call_done", th, (uint64)th->res, th->reserrno,
			     th->cov.size);
#endif
}

static uint32 hash(uint32 a)
{
	// For test OS we disable hashing for determinism and testability.
#if !GOOS_test
	a = (a ^ 61) ^ (a >> 16);
	a = a + (a << 3);
	a = a ^ (a >> 4);
	a = a * 0x27d4eb2d;
	a = a ^ (a >> 15);
#endif
	return a;
}

const uint32 dedup_table_size = 8 << 10;
uint64 dedup_table_sig[dedup_table_size];
uint8 dedup_table_index[dedup_table_size];

// Poorman's best-effort hashmap-based deduplication.
static bool dedup(uint8 index, uint64 sig)
{
	for (uint32 i = 0; i < 4; i++) {
		uint32 pos = (sig + i) % dedup_table_size;
		if (dedup_table_sig[pos] == sig && dedup_table_index[pos] == index)
			return true;
		if (dedup_table_sig[pos] == 0 || dedup_table_index[pos] != index) {
			dedup_table_index[pos] = index;
			dedup_table_sig[pos] = sig;
			return false;
		}
	}
	uint32 pos = sig % dedup_table_size;
	dedup_table_sig[pos] = sig;
	dedup_table_index[pos] = index;
	return false;
}

template <typename T>
void copyin_int(char* addr, uint64 val, uint64 bf, uint64 bf_off, uint64 bf_len)
{
	if (bf_off == 0 && bf_len == 0) {
		*(T*)addr = swap(val, sizeof(T), bf);
		return;
	}
	T x = swap(*(T*)addr, sizeof(T), bf);
	debug_verbose("copyin_int<%zu>: old x=0x%llx\n", sizeof(T), (uint64)x);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	const uint64 shift = sizeof(T) * CHAR_BIT - bf_off - bf_len;
#else
	const uint64 shift = bf_off;
#endif
	x = (x & ~BITMASK(shift, bf_len)) | ((val << shift) & BITMASK(shift, bf_len));
	debug_verbose("copyin_int<%zu>: x=0x%llx\n", sizeof(T), (uint64)x);
	*(T*)addr = swap(x, sizeof(T), bf);
}

void copyin(char* addr, uint64 val, uint64 size, uint64 bf, uint64 bf_off, uint64 bf_len)
{
	debug_verbose("copyin: addr=%p val=0x%llx size=%llu bf=%llu bf_off=%llu bf_len=%llu\n",
		      addr, val, size, bf, bf_off, bf_len);
	if (bf != binary_format_native && bf != binary_format_bigendian && (bf_off != 0 || bf_len != 0))
		failmsg("bitmask for string format", "off=%llu, len=%llu", bf_off, bf_len);
	switch (bf) {
	case binary_format_native:
	case binary_format_bigendian:
		NONFAILING(switch (size) {
			case 1:
				copyin_int<uint8>(addr, val, bf, bf_off, bf_len);
				break;
			case 2:
				copyin_int<uint16>(addr, val, bf, bf_off, bf_len);
				break;
			case 4:
				copyin_int<uint32>(addr, val, bf, bf_off, bf_len);
				break;
			case 8:
				copyin_int<uint64>(addr, val, bf, bf_off, bf_len);
				break;
			default:
				failmsg("copyin: bad argument size", "size=%llu", size);
		});
		break;
	case binary_format_strdec:
		if (size != 20)
			failmsg("bad strdec size", "size=%llu", size);
		NONFAILING(sprintf((char*)addr, "%020llu", val));
		break;
	case binary_format_strhex:
		if (size != 18)
			failmsg("bad strhex size", "size=%llu", size);
		NONFAILING(sprintf((char*)addr, "0x%016llx", val));
		break;
	case binary_format_stroct:
		if (size != 23)
			failmsg("bad stroct size", "size=%llu", size);
		NONFAILING(sprintf((char*)addr, "%023llo", val));
		break;
	default:
		failmsg("unknown binary format", "format=%llu", bf);
	}
}

bool copyout(char* addr, uint64 size, uint64* res)
{
	return NONFAILING(
	    switch (size) {
		    case 1:
			    *res = *(uint8*)addr;
			    break;
		    case 2:
			    *res = *(uint16*)addr;
			    break;
		    case 4:
			    *res = *(uint32*)addr;
			    break;
		    case 8:
			    *res = *(uint64*)addr;
			    break;
		    default:
			    failmsg("copyout: bad argument size", "size=%llu", size);
	    });
}

uint64 read_arg(uint8** input_posp)
{
	uint64 typ = read_input(input_posp);
	switch (typ) {
	case arg_const: {
		uint64 size, bf, bf_off, bf_len;
		uint64 val = read_const_arg(input_posp, &size, &bf, &bf_off, &bf_len);
		if (bf != binary_format_native && bf != binary_format_bigendian)
			failmsg("bad argument binary format", "format=%llu", bf);
		if (bf_off != 0 || bf_len != 0)
			failmsg("bad argument bitfield", "off=%llu, len=%llu", bf_off, bf_len);
		return swap(val, size, bf);
	}
	case arg_addr32:
	case arg_addr64: {
		return read_input(input_posp) + SYZ_DATA_OFFSET;
	}
	case arg_result: {
		uint64 meta = read_input(input_posp);
		uint64 bf = meta >> 8;
		if (bf != binary_format_native)
			failmsg("bad result argument format", "format=%llu", bf);
		return read_result(input_posp);
	}
	default:
		failmsg("bad argument type", "type=%llu", typ);
	}
}

uint64 swap(uint64 v, uint64 size, uint64 bf)
{
	if (bf == binary_format_native)
		return v;
	if (bf != binary_format_bigendian)
		failmsg("bad binary format in swap", "format=%llu", bf);
	switch (size) {
	case 2:
		return htobe16(v);
	case 4:
		return htobe32(v);
	case 8:
		return htobe64(v);
	default:
		failmsg("bad big-endian int size", "size=%llu", size);
	}
}

uint64 read_const_arg(uint8** input_posp, uint64* size_p, uint64* bf_p, uint64* bf_off_p, uint64* bf_len_p)
{
	uint64 meta = read_input(input_posp);
	uint64 val = read_input(input_posp);
	*size_p = meta & 0xff;
	uint64 bf = (meta >> 8) & 0xff;
	*bf_off_p = (meta >> 16) & 0xff;
	*bf_len_p = (meta >> 24) & 0xff;
	uint64 pid_stride = meta >> 32;
	val += pid_stride * procid;
	*bf_p = bf;
	return val;
}

uint64 read_result(uint8** input_posp)
{
	uint64 idx = read_input(input_posp);
	uint64 op_div = read_input(input_posp);
	uint64 op_add = read_input(input_posp);
	uint64 arg = read_input(input_posp);
	if (idx >= kMaxCommands)
		failmsg("command refers to bad result", "result=%lld", idx);
	if (results[idx].executed) {
		arg = results[idx].val;
		if (op_div != 0)
			arg = arg / op_div;
		arg += op_add;
	}
	return arg;
}

uint64 read_input(uint8** input_posp, bool peek)
{
	uint64 v = 0;
	unsigned shift = 0;
	uint8* input_pos = *input_posp;
	for (int i = 0;; i++, shift += 7) {
		const int maxLen = 10;
		if (i == maxLen)
			failmsg("varint overflow", "pos=%zu", (size_t)(*input_posp - input_data));
		if (input_pos >= input_data + kMaxInput)
			failmsg("input command overflows input", "pos=%p: [%p:%p)",
				input_pos, input_data, input_data + kMaxInput);
		uint8 b = *input_pos++;
		v |= uint64(b & 0x7f) << shift;
		if (b < 0x80) {
			if (i == maxLen - 1 && b > 1)
				failmsg("varint overflow", "pos=%zu", (size_t)(*input_posp - input_data));
			break;
		}
	}
	if (v & 1)
		v = ~(v >> 1);
	else
		v = v >> 1;
	if (!peek)
		*input_posp = input_pos;
	return v;
}

rpc::ComparisonRaw convert(const kcov_comparison_t& cmp)
{
	if (cmp.type > (KCOV_CMP_CONST | KCOV_CMP_SIZE_MASK))
		failmsg("invalid kcov comp type", "type=%llx", cmp.type);
	uint64 arg1 = cmp.arg1;
	uint64 arg2 = cmp.arg2;
	// Comparisons with 0 are not interesting, fuzzer should be able to guess 0's without help.
	if (arg1 == 0 && (arg2 == 0 || (cmp.type & KCOV_CMP_CONST)))
		return {};
	// Successful comparison is not interesting.
	if (arg1 == arg2)
		return {};

	// This can be a pointer (assuming 64-bit kernel).
	// First of all, we want avert fuzzer from our output region.
	// Without this fuzzer manages to discover and corrupt it.
	uint64 out_start = (uint64)output_data;
	uint64 out_end = out_start + output_size;
	if (arg1 >= out_start && arg1 <= out_end)
		return {};
	if (arg2 >= out_start && arg2 <= out_end)
		return {};
	if (!coverage_filter(cmp.pc))
		return {};

	// KCOV converts all arguments of size x first to uintx_t and then to uint64.
	// We want to properly extend signed values, e.g we want int8 c = 0xfe to be represented
	// as 0xfffffffffffffffe. Note that uint8 c = 0xfe will be represented the same way.
	// This is ok because during hints processing we will anyways try the value 0x00000000000000fe.
	switch (cmp.type & KCOV_CMP_SIZE_MASK) {
	case KCOV_CMP_SIZE1:
		arg1 = (uint64)(long long)(signed char)arg1;
		arg2 = (uint64)(long long)(signed char)arg2;
		break;
	case KCOV_CMP_SIZE2:
		arg1 = (uint64)(long long)(short)arg1;
		arg2 = (uint64)(long long)(short)arg2;
		break;
	case KCOV_CMP_SIZE4:
		arg1 = (uint64)(long long)(int)arg1;
		arg2 = (uint64)(long long)(int)arg2;
		break;
	}

	// Prog package expects operands in the opposite order (first operand may come from the input,
	// the second operand was computed in the kernel), so swap operands.
	return {cmp.pc, arg2, arg1, !!(cmp.type & KCOV_CMP_CONST)};
}

void failmsg(const char* err, const char* msg, ...)
{
	int e = errno;
	fprintf(stderr, "SYZFAIL: %s\n", err);
	if (msg) {
		va_list args;
		va_start(args, msg);
		vfprintf(stderr, msg, args);
		va_end(args);
	}
	fprintf(stderr, " (errno %d: %s)\n", e, strerror(e));

	// fail()'s are often used during the validation of kernel reactions to queries
	// that were issued by pseudo syscalls implementations. As fault injection may
	// cause the kernel not to succeed in handling these queries (e.g. socket writes
	// or reads may fail), this could ultimately lead to unwanted "lost connection to
	// test machine" crashes.
	// In order to avoid this and, on the other hand, to still have the ability to
	// signal a disastrous situation, the exit code of this function depends on the
	// current context.
	// All fail() invocations during system call execution with enabled fault injection
	// lead to termination with zero exit code. In all other cases, the exit code is
	// kFailStatus.
	if (current_thread && current_thread->soft_fail_state)
		doexit(0);
	doexit(kFailStatus);
}

void fail(const char* err)
{
	failmsg(err, 0);
}

void exitf(const char* msg, ...)
{
	int e = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	doexit(1);
}

void debug(const char* msg, ...)
{
	if (!flag_debug)
		return;
	int err = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fflush(stderr);
	errno = err;
}

void debug_dump_data(const char* data, int length)
{
	if (!flag_debug)
		return;
	int i = 0;
	for (; i < length; i++) {
		debug("%02x ", data[i] & 0xff);
		if (i % 16 == 15)
			debug("\n");
	}
	if (i % 16 != 0)
		debug("\n");
}

// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <imm.h>
#include <ncrypt.h>
#include <ole2.h>
#include <oleauto.h>
#include <rpc.h>
#include <rpcndr.h>
#include <shellapi.h>
#include <urlmon.h>
#include <wincrypt.h>
#include <winscard.h>
#include <winspool.h>

#include "nocover.h"

#define read read_win
#define write write_win

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	if (VirtualAlloc(data, data_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) != data)
		fail("mmap of data segment failed");
	// Windows commits pages lazily. Touch the whole data segment up front so Nyx
	// root snapshots don't hit first-touch faults inside the ACQUIRE/execute path.
	for (size_t i = 0; i < data_size; i += SYZ_PAGE_SIZE)
		*(volatile char*)((char*)data + i) = 0;
}

#if SYZ_NYX_WINDOWS_DEMO
static intptr_t execute_demo_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	if (c->name && strcmp(c->name, "NtQuerySystemInformation") == 0) {
		auto info_class = static_cast<SYSTEM_INFORMATION_CLASS>(a[0]);
		void* orig_buf = reinterpret_cast<void*>(a[1]);
		ULONG buf_size = static_cast<ULONG>(a[2]);
		auto* orig_ret_len = reinterpret_cast<ULONG*>(a[3]);

		void* tmp_buf = nullptr;
		if (orig_buf && buf_size) {
			tmp_buf = VirtualAlloc(nullptr, buf_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!tmp_buf)
				return -1;
			memcpy(tmp_buf, orig_buf, buf_size);
		}

		ULONG tmp_ret_len = orig_ret_len ? *orig_ret_len : 0;
		NTSTATUS status = NtQuerySystemInformation(info_class, tmp_buf, buf_size,
							      orig_ret_len ? &tmp_ret_len : nullptr);
		if (orig_buf && tmp_buf)
			memcpy(orig_buf, tmp_buf, buf_size);
		if (orig_ret_len)
			*orig_ret_len = tmp_ret_len;
		if (tmp_buf)
			VirtualFree(tmp_buf, 0, MEM_RELEASE);
		return status;
	}

	return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
}
#endif

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
#if SYZ_NYX_WINDOWS_DEMO
	return execute_demo_syscall(c, a);
#elif defined(__GNUC__)
	return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
#else
	__try {
		return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return -1;
	}
#endif
}

static __inline int read_win(int pipe_id, void* input_data, int data_size)
{
	DWORD dwBytesRead = 0;
	ReadFile((HANDLE)_get_osfhandle(pipe_id), input_data, data_size, &dwBytesRead, NULL);

	return (int)dwBytesRead;
}

static __inline int write_win(int pipe_id, void* input_data, int data_size)
{
	DWORD dwBytesWritten = 0;
	WriteFile((HANDLE)_get_osfhandle(pipe_id), input_data, data_size, &dwBytesWritten, NULL);
	return (int)dwBytesWritten;
}

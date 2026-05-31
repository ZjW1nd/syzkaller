package main

import (
	"encoding/json"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/prog"
)

func extractFunctionBody(t *testing.T, src, signature string) string {
	t.Helper()
	start := strings.LastIndex(src, signature)
	if start == -1 {
		t.Fatalf("%s not found in executor.cc", signature)
	}
	openRel := strings.Index(src[start:], "{")
	if openRel == -1 {
		t.Fatalf("opening brace for %s not found", signature)
	}
	bodyStart := start + openRel + 1
	depth := 1
	for i := bodyStart; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[bodyStart:i]
			}
		}
	}
	t.Fatalf("closing brace for %s not found", signature)
	return ""
}

func extractCaseBody(t *testing.T, src, caseName string) string {
	t.Helper()
	start := strings.Index(src, `case "`+caseName+`":`)
	if start == -1 {
		t.Fatalf("case %q not found", caseName)
	}
	rest := src[start:]
	next := strings.Index(rest[len(`case "`+caseName+`":`):], "\n\tcase ")
	if next == -1 {
		t.Fatalf("next case after %q not found", caseName)
	}
	body := rest[:len(`case "`+caseName+`":`)+next]
	return body
}

func loadDemoSyscallTable(t *testing.T) map[string]int {
	t.Helper()
	path := filepath.Join("..", "..", "executor", "syscalls_windows_nyx_demo.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read demo syscall table: %v", err)
	}
	src := string(data)
	defines := make(map[string]int)
	defineRe := regexp.MustCompile(`#define\s+(W32_[A-Z0-9_]+)\s+(\d+)`)
	for _, match := range defineRe.FindAllStringSubmatch(src, -1) {
		id, err := strconv.Atoi(match[2])
		if err != nil {
			t.Fatalf("parse syscall ID %q: %v", match[2], err)
		}
		defines[match[1]] = id
	}
	re := regexp.MustCompile(`syscalls\[(W32_[A-Z0-9_]+|\d+)\]\s*=\s*call_t\{\"([^\"]+)\"`)
	matches := re.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatalf("no demo syscall entries found in %s", path)
	}
	table := make(map[string]int, len(matches))
	for _, match := range matches {
		id, err := strconv.Atoi(match[1])
		if err != nil {
			var ok bool
			id, ok = defines[match[1]]
			if !ok {
				t.Fatalf("unknown syscall macro %q in %s", match[1], path)
			}
		}
		table[match[2]] = id
	}
	return table
}

func loadDemoSyscallTableCapacity(t *testing.T) int {
	t.Helper()
	path := filepath.Join("..", "..", "executor", "syscalls_windows_nyx_demo.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read demo syscall table: %v", err)
	}
	re := regexp.MustCompile(`static\s+call_t\s+syscalls\[(\d+)\]`)
	match := re.FindStringSubmatch(string(data))
	if match == nil {
		t.Fatalf("syscalls table capacity not found in %s", path)
	}
	capacity, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("parse syscalls table capacity %q: %v", match[1], err)
	}
	return capacity
}

func loadWindowsServiceEntries(t *testing.T) []struct {
	kind        string
	macro       string
	targetName  string
	serviceName string
	number      int
} {
	t.Helper()
	path := filepath.Join("..", "..", "executor", "windows_service_26200.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read windows service table: %v", err)
	}
	re := regexp.MustCompile(`X\((ntos|win32k),\s*(W32_[A-Z0-9_]+),\s*"([^"]+)",\s*"([^"]+)",\s*([0-9]+)\)`)
	matches := re.FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		t.Fatalf("no service table entries found in %s", path)
	}
	var entries []struct {
		kind        string
		macro       string
		targetName  string
		serviceName string
		number      int
	}
	for _, match := range matches {
		number, err := strconv.Atoi(match[5])
		if err != nil {
			t.Fatalf("parse service number %q: %v", match[5], err)
		}
		entries = append(entries, struct {
			kind        string
			macro       string
			targetName  string
			serviceName string
			number      int
		}{
			kind:        match[1],
			macro:       match[2],
			targetName:  match[3],
			serviceName: match[4],
			number:      number,
		})
	}
	return entries
}

func loadWindowsNyxConfig(t *testing.T, path string) struct {
	EnabledSyscalls  []string `json:"enable_syscalls"`
	NoMutateSyscalls []string `json:"no_mutate_syscalls"`
	VM               struct {
		ModuleRanges string `json:"module_ranges"`
	} `json:"vm"`
	Experimental struct {
		SeedPrefix           string `json:"seed_prefix"`
		BorrowingSeedPrefix  string `json:"borrowing_seed_prefix"`
		WindowsTargetProfile string `json:"windows_target_profile"`
	} `json:"experimental"`
} {
	t.Helper()
	path = filepath.Join(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read windows nyx config: %v", err)
	}
	var cfg struct {
		EnabledSyscalls  []string `json:"enable_syscalls"`
		NoMutateSyscalls []string `json:"no_mutate_syscalls"`
		VM               struct {
			ModuleRanges string `json:"module_ranges"`
		} `json:"vm"`
		Experimental struct {
			SeedPrefix           string `json:"seed_prefix"`
			BorrowingSeedPrefix  string `json:"borrowing_seed_prefix"`
			WindowsTargetProfile string `json:"windows_target_profile"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse windows nyx config: %v", err)
	}
	return cfg
}

func loadWindowsAutomaticHelpers(t *testing.T) []string {
	t.Helper()
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	var helpers []string
	for _, call := range target.Syscalls {
		if target.CallIsAutomaticHelper(call) {
			helpers = append(helpers, call.Name)
		}
	}
	if len(helpers) == 0 {
		t.Fatal("windows target has no AutomaticHelper syscalls")
	}
	return helpers
}

func requireWindowsHelpersEnabled(t *testing.T, cfgPath string, want []string) {
	t.Helper()
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, cfgPath)
	if len(cfg.EnabledSyscalls) == 0 {
		t.Fatalf("%s has no enable_syscalls", cfgPath)
	}
	enabledCalls := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		meta := target.SyscallMap[name]
		if meta == nil {
			t.Fatalf("windows config syscall %q missing from windows/amd64 target", name)
		}
		enabledCalls[meta] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabledCalls)
	for _, name := range want {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !target.CallIsAutomaticHelper(call) {
			t.Fatalf("syscall %q is not classified as AutomaticHelper", name)
		}
		if !expanded[call] {
			t.Fatalf("automatic helper syscall %q is not transitively enabled in %s", name, cfgPath)
		}
	}
}

func loadWindowsNyxConfigSyscalls(t *testing.T) []string {
	t.Helper()
	cfg := loadWindowsNyxConfig(t, "windows-nyx-test.cfg")
	if len(cfg.EnabledSyscalls) == 0 {
		t.Fatalf("windows nyx config %s has no enable_syscalls", "windows-nyx-test.cfg")
	}
	return cfg.EnabledSyscalls
}

func requireWindowsNyxConfigSyscallsInSparseTable(t *testing.T, cfgPath string) {
	t.Helper()
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, cfgPath)
	if len(cfg.EnabledSyscalls) == 0 {
		t.Fatalf("%s has no enable_syscalls", cfgPath)
	}
	enabledCalls := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		if _, ok := table[name]; !ok {
			t.Fatalf("%s syscall %q missing from sparse Nyx table", cfgPath, name)
		}
		meta := target.SyscallMap[name]
		if meta == nil {
			t.Fatalf("%s syscall %q missing from windows/amd64 target", cfgPath, name)
		}
		enabledCalls[meta] = true
	}
	expanded, disabled := target.TransitivelyEnabledCalls(enabledCalls)
	if len(disabled) != 0 {
		t.Fatalf("%s has disabled calls after expansion: %v", cfgPath, disabled)
	}
	for call := range expanded {
		if _, ok := table[call.Name]; !ok {
			t.Fatalf("%s transitively enabled syscall %q missing from sparse Nyx table", cfgPath, call.Name)
		}
	}
}

func TestWindowsDemoSyscallTableMatchesTargetIDs(t *testing.T) {
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for name, wantID := range table {
		meta := target.SyscallMap[name]
		if meta == nil {
			t.Fatalf("demo syscall %q missing from windows/amd64 target", name)
		}
		if meta.ID != wantID {
			t.Fatalf("demo syscall %q has target ID %d, want %d", name, meta.ID, wantID)
		}
	}
}

func TestWindowsNyxConfigSyscallsPresentInSparseTable(t *testing.T) {
	requireWindowsNyxConfigSyscallsInSparseTable(t, "windows-nyx-test.cfg")
}

func TestWindowsNyxConfigExpandedSyscallsPresentInSparseTable(t *testing.T) {
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	enabledCalls := make(map[*prog.Syscall]bool)
	for _, name := range loadWindowsNyxConfigSyscalls(t) {
		enabledCalls[target.SyscallMap[name]] = true
	}
	expanded, disabled := target.TransitivelyEnabledCalls(enabledCalls)
	if len(disabled) != 0 {
		t.Fatalf("windows nyx config has disabled calls after expansion: %v", disabled)
	}
	for call := range expanded {
		if _, ok := table[call.Name]; !ok {
			t.Fatalf("transitively enabled syscall %q missing from sparse Nyx table", call.Name)
		}
	}
}

func TestWindowsNyxServiceTableMatchesTargetIDs(t *testing.T) {
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, entry := range loadWindowsServiceEntries(t) {
		meta := target.SyscallMap[entry.targetName]
		if meta == nil {
			t.Fatalf("service entry target %q missing from windows/amd64 target", entry.targetName)
		}
		if gotID, ok := table[entry.targetName]; !ok {
			t.Fatalf("service entry target %q missing from sparse Nyx table", entry.targetName)
		} else if gotID != meta.ID {
			t.Fatalf("service entry target %q has sparse ID %d, want %d", entry.targetName, gotID, meta.ID)
		}
		if entry.kind != "ntos" && entry.kind != "win32k" {
			t.Fatalf("service entry target %q has bad kind %q", entry.targetName, entry.kind)
		}
		if entry.kind == "ntos" && !strings.HasPrefix(entry.serviceName, "Nt") {
			t.Fatalf("ntos service entry %q maps to non-NT service %q", entry.targetName, entry.serviceName)
		}
		if entry.number <= 0 {
			t.Fatalf("service entry %q has bad service number %d", entry.targetName, entry.number)
		}
	}
}

func TestWindowsDemoSparseTableCapacityCoversTargetIDs(t *testing.T) {
	table := loadDemoSyscallTable(t)
	capacity := loadDemoSyscallTableCapacity(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if capacity < len(target.Syscalls) {
		t.Fatalf("sparse executor table capacity=%d, target syscalls=%d", capacity, len(target.Syscalls))
	}
	for name, id := range table {
		if id >= capacity {
			t.Fatalf("sparse executor table capacity=%d does not cover %s id=%d", capacity, name, id)
		}
	}
}

func TestWindowsNyxExecutorUsesGeneratedServiceTable(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "syscalls_windows_nyx_demo.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read demo syscall table: %v", err)
	}
	src := string(data)
	for _, needle := range []string{
		`#include "windows_service_26200.h"`,
		"make_nyx_ntos_service_stub",
		"WINDOWS_NYX_SERVICE_TABLE_26200(INIT_NYX_SERVICE_ENTRY)",
	} {
		if !strings.Contains(src, needle) {
			t.Fatalf("sparse executor table is missing %q", needle)
		}
	}
}

func TestWindowsAutomaticHelpersPresentInEnabledSet(t *testing.T) {
	requireWindowsHelpersEnabled(t, "windows-nyx-test.cfg",
		[]string{"CloseHandle", "CreateFileA", "CreateFile2"})
}

func TestWindowsSocketResourceHierarchy(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	assertResource := func(callName string, index int, want string) {
		t.Helper()
		meta := target.SyscallMap[callName]
		if meta == nil {
			t.Fatalf("missing syscall %q", callName)
		}
		var typ prog.Type
		if index < 0 {
			typ = meta.Ret
		} else {
			typ = meta.Args[index].Type
		}
		res, ok := typ.(*prog.ResourceType)
		if !ok {
			t.Fatalf("%s[%d] has unexpected type %T", callName, index, typ)
		}
		if res.TypeName != want {
			t.Fatalf("%s[%d] resource=%q want=%q", callName, index, res.TypeName, want)
		}
	}
	assertResource("socket$inet_tcp", -1, "SOCKET_TCP_CREATED")
	assertResource("socket$inet_udp", -1, "SOCKET_UDP_CREATED")
	assertResource("socket$bound_udp", -1, "SOCKET_UDP_BOUND")
	assertResource("socket$connected_udp", -1, "SOCKET_UDP_CONNECTED")
	assertResource("socket$accept_tcp", -1, "SOCKET_ACCEPT")
	assertResource("socket$listener_tcp", -1, "SOCKET_LISTENER")
	assertResource("socket$connected_tcp", -1, "SOCKET_CONNECTED")
	assertResource("bind$inet_tcp", 0, "SOCKET_TCP_CREATED")
	assertResource("bind$inet_tcp", -1, "SOCKET_TCP_BOUND")
	assertResource("listen$inet_tcp", 0, "SOCKET_TCP_BOUND")
	assertResource("listen$inet_tcp", -1, "SOCKET_TCP_LISTENING")
	assertResource("accept$inet_tcp", 0, "SOCKET_TCP_LISTENING")
	assertResource("accept$inet_tcp", -1, "SOCKET_TCP_ACCEPTED")
	assertResource("connect$inet_tcp", 0, "SOCKET_TCP_CREATED")
	assertResource("connect$inet_tcp", -1, "SOCKET_TCP_CONNECTED")
	assertResource("DisconnectEx$inet_tcp_reuse", 0, "SOCKET_CONNECTED")
	assertResource("DisconnectEx$inet_tcp_reuse", -1, "SOCKET_TCP_DISCONNECTED_REUSABLE")
	assertResource("ConnectEx$inet_tcp_reuse", 0, "SOCKET_TCP_DISCONNECTED_REUSABLE")
	assertResource("ConnectEx$inet_tcp_reuse", -1, "SOCKET_TCP_CONNECTED")
	assertResource("bind$inet_udp", 0, "SOCKET_UDP_CREATED")
	assertResource("bind$inet_udp", -1, "SOCKET_UDP_BOUND")
	assertResource("connect$inet_udp", 0, "SOCKET_UDP_CREATED")
	assertResource("connect$inet_udp", -1, "SOCKET_UDP_PEERED")
	assertResource("send$inet_tcp", 0, "SOCKET_TCP_CONNECTED")
	assertResource("recv$inet_tcp", 0, "SOCKET_TCP_CONNECTED")
	assertResource("WSASend$tcp", 0, "SOCKET_TCP_CONNECTED")
	assertResource("WSASend$tcp_pending", 0, "SOCKET_TCP_CONNECTED")
	assertResource("WSASend$tcp_pending", -1, "SOCKET_TCP_SEND_PENDING")
	assertResource("WSASend$accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("WSASend$accept_pending", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("WSASend$accept_pending", -1, "SOCKET_TCP_ACCEPT_SEND_PENDING")
	assertResource("WSARecv$tcp", 0, "SOCKET_TCP_CONNECTED")
	assertResource("WSARecv$tcp_pending", 0, "SOCKET_TCP_CONNECTED")
	assertResource("WSARecv$tcp_pending", -1, "SOCKET_TCP_RECV_PENDING")
	assertResource("WSARecv$accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("WSARecv$accept_pending", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("WSARecv$accept_pending", -1, "SOCKET_TCP_ACCEPT_RECV_PENDING")
	assertResource("sendto$udp_bound", 0, "SOCKET_UDP_BOUND")
	assertResource("sendto$udp_connected", 0, "SOCKET_UDP_PEERED")
	assertResource("recvfrom$udp_bound", 0, "SOCKET_UDP_BOUND")
	assertResource("recvfrom$udp_connected", 0, "SOCKET_UDP_PEERED")
	assertResource("WSASendTo$udp", 0, "SOCKET_UDP_PEERED")
	assertResource("WSARecvFrom$udp", 0, "SOCKET_UDP_BOUND")
	assertResource("shutdown$tcp", 0, "SOCKET_TCP_CONNECTED")
	assertResource("shutdown$accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("shutdown$tcp_rd", 0, "SOCKET_TCP_CONNECTED")
	assertResource("shutdown$tcp_rd", -1, "SOCKET_TCP_SHUTDOWN_RD")
	assertResource("shutdown$tcp_wr", 0, "SOCKET_TCP_CONNECTED")
	assertResource("shutdown$tcp_wr", -1, "SOCKET_TCP_SHUTDOWN_WR")
	assertResource("shutdown$accept_rd", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("shutdown$accept_rd", -1, "SOCKET_TCP_SHUTDOWN_RD")
	assertResource("shutdown$accept_wr", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("shutdown$accept_wr", -1, "SOCKET_TCP_SHUTDOWN_WR")
	assertResource("closesocket$tcp_shutdown_rd", 0, "SOCKET_TCP_SHUTDOWN_RD")
	assertResource("closesocket$tcp_shutdown_wr", 0, "SOCKET_TCP_SHUTDOWN_WR")
	assertResource("getsockname$tcp", 0, "SOCKET_TCP_CONNECTED")
	assertResource("getsockname$udp", 0, "SOCKET_UDP")
	assertResource("getsockname$accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("getpeername$tcp", 0, "SOCKET_TCP_CONNECTED")
	assertResource("getpeername$udp", 0, "SOCKET_UDP_PEERED")
	assertResource("getpeername$accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("AcceptEx$inet_tcp", 0, "SOCKET_LISTENER")
	assertResource("AcceptEx$inet_tcp", 1, "SOCKET_ACCEPT")
	assertResource("AcceptEx$inet_tcp_pending", 0, "SOCKET_LISTENER")
	assertResource("AcceptEx$inet_tcp_pending", 1, "SOCKET_ACCEPT")
	assertResource("AcceptEx$inet_tcp_pending", -1, "SOCKET_TCP_ACCEPT_PENDING")
	assertResource("setsockopt$update_accept_context", 0, "SOCKET_TCP_ACCEPT_PENDING")
	assertResource("setsockopt$update_accept_context", -1, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("ConnectEx$inet_tcp", 0, "SOCKET_CONNECTED")
	assertResource("ConnectEx$inet_tcp_pending", 0, "SOCKET_CONNECTED")
	assertResource("ConnectEx$inet_tcp_pending", -1, "SOCKET_TCP_CONNECTING")
	assertResource("DisconnectEx$inet_tcp", 0, "SOCKET_CONNECTED")
	assertResource("WSARecvEx$inet_accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("send$inet_accept_updated", 0, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("recv$inet_accept_updated", 0, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("setsockopt$int_accept_updated", 0, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("getsockopt$int_accept_updated", 0, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("TransmitFile$inet_accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("TransmitPackets$inet_accept", 0, "SOCKET_ACCEPT")
	assertResource("WSARecvMsg$udp", 0, "SOCKET_UDP_BOUND")
	assertResource("WSAIoctl$sio_routing_interface_query", 0, "SOCKET_UDP_PEERED")
	assertResource("CreateIoCompletionPort$socket", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("CreateIoCompletionPort$accept_pending", 0, "SOCKET_TCP_ACCEPT_PENDING")
	assertResource("CreateIoCompletionPort$accept_recv_pending", 0, "SOCKET_TCP_ACCEPT_RECV_PENDING")
	assertResource("CreateIoCompletionPort$accept_send_pending", 0, "SOCKET_TCP_ACCEPT_SEND_PENDING")
	assertResource("CreateIoCompletionPort$connect_pending", 0, "SOCKET_TCP_CONNECTING")
	assertResource("CreateIoCompletionPort$tcp_recv_pending", 0, "SOCKET_TCP_RECV_PENDING")
	assertResource("CreateIoCompletionPort$tcp_send_pending", 0, "SOCKET_TCP_SEND_PENDING")
	assertResource("CreateIoCompletionPort$socket", -1, "IOCP_HANDLE")
	assertResource("CreateIoCompletionPort$accept_pending", -1, "IOCP_HANDLE")
	assertResource("CreateIoCompletionPort$accept_recv_pending", -1, "IOCP_HANDLE")
	assertResource("CreateIoCompletionPort$accept_send_pending", -1, "IOCP_HANDLE")
	assertResource("CreateIoCompletionPort$connect_pending", -1, "IOCP_HANDLE")
	assertResource("CreateIoCompletionPort$tcp_recv_pending", -1, "IOCP_HANDLE")
	assertResource("CreateIoCompletionPort$tcp_send_pending", -1, "IOCP_HANDLE")
	assertResource("GetQueuedCompletionStatus$socket", 0, "IOCP_HANDLE")
	assertResource("WSAGetOverlappedResult$socket", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("WSAGetOverlappedResult$accept_pending", 0, "SOCKET_TCP_ACCEPT_PENDING")
	assertResource("WSAGetOverlappedResult$accept_recv_pending", 0, "SOCKET_TCP_ACCEPT_RECV_PENDING")
	assertResource("WSAGetOverlappedResult$accept_send_pending", 0, "SOCKET_TCP_ACCEPT_SEND_PENDING")
	assertResource("WSAGetOverlappedResult$connect_pending", 0, "SOCKET_TCP_CONNECTING")
	assertResource("WSAGetOverlappedResult$tcp_recv_pending", 0, "SOCKET_TCP_RECV_PENDING")
	assertResource("WSAGetOverlappedResult$tcp_send_pending", 0, "SOCKET_TCP_SEND_PENDING")
	assertResource("CancelIoEx$socket", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("CancelIoEx$accept_pending", 0, "SOCKET_TCP_ACCEPT_PENDING")
	assertResource("CancelIoEx$accept_recv_pending", 0, "SOCKET_TCP_ACCEPT_RECV_PENDING")
	assertResource("CancelIoEx$accept_send_pending", 0, "SOCKET_TCP_ACCEPT_SEND_PENDING")
	assertResource("CancelIoEx$connect_pending", 0, "SOCKET_TCP_CONNECTING")
	assertResource("CancelIoEx$tcp_recv_pending", 0, "SOCKET_TCP_RECV_PENDING")
	assertResource("CancelIoEx$tcp_send_pending", 0, "SOCKET_TCP_SEND_PENDING")
	assertResource("CancelIo$socket", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("CancelIo$accept_pending", 0, "SOCKET_TCP_ACCEPT_PENDING")
	assertResource("CancelIo$accept_recv_pending", 0, "SOCKET_TCP_ACCEPT_RECV_PENDING")
	assertResource("CancelIo$accept_send_pending", 0, "SOCKET_TCP_ACCEPT_SEND_PENDING")
	assertResource("CancelIo$connect_pending", 0, "SOCKET_TCP_CONNECTING")
	assertResource("CancelIo$tcp_recv_pending", 0, "SOCKET_TCP_RECV_PENDING")
	assertResource("CancelIo$tcp_send_pending", 0, "SOCKET_TCP_SEND_PENDING")
	assertResource("closesocket$accept_pending", 0, "SOCKET_TCP_ACCEPT_PENDING")
	assertResource("closesocket$accept_recv_pending", 0, "SOCKET_TCP_ACCEPT_RECV_PENDING")
	assertResource("closesocket$accept_send_pending", 0, "SOCKET_TCP_ACCEPT_SEND_PENDING")
	assertResource("closesocket$connect_pending", 0, "SOCKET_TCP_CONNECTING")
	assertResource("closesocket$tcp_recv_pending", 0, "SOCKET_TCP_RECV_PENDING")
	assertResource("closesocket$tcp_send_pending", 0, "SOCKET_TCP_SEND_PENDING")
}

func TestWindowsFileHandleResourceHierarchy(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	assertResource := func(callName string, index int, want string) {
		t.Helper()
		meta := target.SyscallMap[callName]
		if meta == nil {
			t.Fatalf("missing syscall %q", callName)
		}
		var typ prog.Type
		if index < 0 {
			typ = meta.Ret
		} else {
			typ = meta.Args[index].Type
		}
		res, ok := typ.(*prog.ResourceType)
		if !ok {
			t.Fatalf("%s[%d] has unexpected type %T", callName, index, typ)
		}
		if res.TypeName != want {
			t.Fatalf("%s[%d] resource=%q want=%q", callName, index, res.TypeName, want)
		}
	}
	assertResource("CreateFileA", -1, "FILE_HANDLE")
	assertResource("CreateFile2", -1, "FILE_HANDLE")
	assertResource("ReadFile", 0, "FILE_HANDLE")
	assertResource("WriteFile", 0, "FILE_HANDLE")
	assertResource("FlushFileBuffers", 0, "FILE_HANDLE")
	assertResource("SetFileInformationByHandle", 0, "FILE_HANDLE")
	assertResource("NtReadFile", 0, "FILE_HANDLE")
	assertResource("NtWriteFile", 0, "FILE_HANDLE")
	assertResource("NtDeviceIoControlFile", 0, "FILE_HANDLE")
	assertResource("NtFsControlFile", 0, "FILE_HANDLE")
	assertResource("NtFsControlFile$ntfs_get_compression", 0, "FILE_HANDLE")
	assertResource("NtFsControlFile$ntfs_set_compression", 0, "FILE_HANDLE")
	assertResource("NtFsControlFile$ntfs_set_sparse", 0, "FILE_HANDLE")
	assertResource("NtFsControlFile$ntfs_set_zero_data", 0, "FILE_HANDLE")
	assertResource("NtFsControlFile$ntfs_query_allocated_ranges", 0, "FILE_HANDLE")
	assertResource("NtQueryInformationFile$basic", 0, "FILE_HANDLE")
	assertResource("NtQueryInformationFile$standard", 0, "FILE_HANDLE")
	assertResource("NtQueryInformationFile$network_open", 0, "FILE_HANDLE")
	assertResource("NtSetInformationFile$basic", 0, "FILE_HANDLE")
	assertResource("TransmitFile$inet_accept", 1, "FILE_HANDLE")
}

func TestWindowsNyxFuzzConfigSyscallsPresentInSparseTable(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx.cfg")
	if len(cfg.EnabledSyscalls) == 0 {
		t.Fatalf("windows nyx fuzz config has no enable_syscalls")
	}
	requireWindowsNyxConfigSyscallsInSparseTable(t, "windows-nyx.cfg")
	requireWindowsHelpersEnabled(t, "windows-nyx.cfg",
		[]string{"CreateFileA", "CreateFile2", "CloseHandle", "VirtualAlloc"})
	enabledCalls := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		enabledCalls[target.SyscallMap[name]] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabledCalls)
	for _, name := range []string{"CreateFileA", "CreateFile2", "CloseHandle", "VirtualAlloc"} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("windows nyx fuzz config did not transitively enable %q", name)
		}
	}
}

func TestWindowsAfdFocusedConfigs(t *testing.T) {
	for _, cfgPath := range []string{
		"windows-nyx-afd-session.cfg",
		"windows-nyx-afd-accept-race.cfg",
		"windows-nyx-afd-transmit.cfg",
		"windows-nyx-afd-async.cfg",
	} {
		cfgPath := cfgPath
		t.Run(cfgPath, func(t *testing.T) {
			cfg := loadWindowsNyxConfig(t, cfgPath)
			if cfg.VM.ModuleRanges != "ntoskrnl.exe:required,ntfs.sys,afd.sys,win32k*.sys" {
				t.Fatalf("%s module_ranges=%q", cfgPath, cfg.VM.ModuleRanges)
			}
			if cfg.Experimental.SeedPrefix == "" {
				t.Fatalf("%s missing experimental.seed_prefix", cfgPath)
			}
			if matches, err := filepath.Glob(filepath.Join("..", "..", "sys", "windows", "test", cfg.Experimental.SeedPrefix+"*.txt")); err != nil {
				t.Fatalf("glob %s seeds: %v", cfgPath, err)
			} else if len(matches) == 0 {
				t.Fatalf("%s seed_prefix=%q does not match any AFD seed", cfgPath, cfg.Experimental.SeedPrefix)
			}
			if cfg.Experimental.WindowsTargetProfile != "afd" {
				t.Fatalf("%s windows_target_profile=%q, want afd",
					cfgPath, cfg.Experimental.WindowsTargetProfile)
			}
			requireWindowsNyxConfigSyscallsInSparseTable(t, cfgPath)
		})
	}
}

func TestWindowsAfdAsyncConfigAvoidsDisconnectExGeneration(t *testing.T) {
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-async.cfg")
	for _, name := range []string{
		"DisconnectEx$inet_tcp",
		"DisconnectEx$inet_tcp_reuse",
		"ConnectEx$inet_tcp_reuse",
	} {
		if slices.Contains(cfg.EnabledSyscalls, name) {
			t.Fatalf("async config should not generate unstable reuse root %q", name)
		}
	}
}

func TestWindowsDemoExecEncodingUsesTargetIDs(t *testing.T) {
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for name, wantID := range table {
		meta := target.SyscallMap[name]
		ct := target.BuildChoiceTable(nil, map[*prog.Syscall]bool{meta: true})
		p := target.GenSampleProg(meta, rand.NewSource(1), ct)
		execData, err := p.SerializeForExec()
		if err != nil {
			t.Fatalf("SerializeForExec(%s): %v", name, err)
		}
		decoded, err := target.DeserializeExec(execData, nil)
		if err != nil {
			t.Fatalf("DeserializeExec(%s): %v", name, err)
		}
		if len(decoded.Calls) != 1 {
			t.Fatalf("decoded %s into %d calls, want 1", name, len(decoded.Calls))
		}
		if decoded.Calls[0].Meta == nil {
			t.Fatalf("decoded %s call has nil metadata", name)
		}
		if got := decoded.Calls[0].Meta.ID; got != wantID {
			t.Fatalf("decoded %s with target ID %d, want %d", name, got, wantID)
		}
	}
}

func TestNyxQueryCR3TargetsCurrentProcess(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "nyx_windows.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read nyx_windows.h: %v", err)
	}
	src := string(data)
	body := extractFunctionBody(t, src, "static bool nyx_query_cr3(uint64_t* out_cr3)")
	if !strings.Contains(body, "GetCurrentProcessId()") {
		t.Fatalf("nyx_query_cr3 should target the current process PID, body:\n%s", body)
	}
	if strings.Contains(body, "nyx_system_pid()") {
		t.Fatalf("nyx_query_cr3 still references nyx_system_pid(), body:\n%s", body)
	}
}

func TestNyxModuleRangeTargetsDriverModules(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "nyx_windows.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read nyx_windows.h: %v", err)
	}
	src := string(data)
	defaultBody := extractFunctionBody(t, src, "static const nyx_module_target_t* nyx_default_module_targets(size_t* count)")
	for _, want := range []string{
		`"ntoskrnl.exe", true`,
		`"ntfs.sys", false`,
		`"afd.sys", false`,
		`"win32k*.sys", false`,
	} {
		if !strings.Contains(defaultBody, want) {
			t.Fatalf("nyx_default_module_targets missing %q, body:\n%s", want, defaultBody)
		}
	}
	configBody := extractFunctionBody(t, src, "static int nyx_module_targets_from_payload(const kAFL_payload* payload")
	for _, want := range []string{
		"nyx_module_targets_from_bytes",
	} {
		if !strings.Contains(configBody, want) {
			t.Fatalf("nyx_module_targets_from_payload missing %q, body:\n%s", want, configBody)
		}
	}
	bytesBody := extractFunctionBody(t, src, "static int nyx_module_targets_from_bytes(const uint8_t* data")
	for _, want := range []string{
		"SYZ_NYX_MODULE_CONFIG_MAGIC",
		"SYZ_NYX_MODULE_CONFIG_VERSION",
		"nyx module range config invalid",
		"nyx module range config truncated",
		"nyx module range config bad entry",
	} {
		if !strings.Contains(bytesBody, want) {
			t.Fatalf("nyx_module_targets_from_bytes missing %q, body:\n%s", want, bytesBody)
		}
	}
	sharedirBody := extractFunctionBody(t, src, "static int nyx_module_targets_from_sharedir(nyx_module_target_t* targets")
	for _, want := range []string{
		"HYPERCALL_KAFL_REQ_STREAM_DATA",
		"NYX_MODULE_RANGE_CONFIG_FILE",
		"nyx module range config sharedir oversized",
		"nyx_module_targets_from_bytes",
	} {
		if !strings.Contains(sharedirBody, want) {
			t.Fatalf("nyx_module_targets_from_sharedir missing %q, body:\n%s", want, sharedirBody)
		}
	}
	submitBody := extractFunctionBody(t, src, "static bool nyx_submit_module_ranges(const kAFL_payload* config_payload)")
	for _, want := range []string{
		"nyx_module_targets_from_payload",
		"nyx_module_targets_from_sharedir",
		"NYX_MAX_MODULE_RANGE_TARGETS",
		"nyx module range config source=%s",
		`source = "payload"`,
		`source = "sharedir"`,
		"nyx module range config source=default",
		"nyx module range missing",
		"nyx module range summary",
		"next_range_id",
	} {
		if !strings.Contains(submitBody, want) {
			t.Fatalf("nyx_submit_module_ranges missing %q, body:\n%s", want, submitBody)
		}
	}
	submitMatchBody := extractFunctionBody(t, src, "static int nyx_submit_module_range_matches(PRTL_PROCESS_MODULES modules")
	for _, want := range []string{
		"NYX_MAX_IP_FILTER_RANGES",
		"nyx module range skipped",
		"range_submit[2] = range_id",
		"slot=%d",
	} {
		if !strings.Contains(submitMatchBody, want) {
			t.Fatalf("nyx_submit_module_range_matches missing %q, body:\n%s", want, submitMatchBody)
		}
	}
	if !strings.Contains(src, "nyx module range submitted") {
		t.Fatal("nyx_windows.h does not log submitted module ranges")
	}
	matchBody := extractFunctionBody(t, src, "static bool nyx_module_name_matches(const char* file_name, const char* pattern)")
	if !strings.Contains(matchBody, "strchr(pattern, '*')") ||
		!strings.Contains(matchBody, "_strnicmp") ||
		!strings.Contains(matchBody, "_stricmp(file_name + file_len - suffix_len, suffix)") {
		t.Fatalf("module matcher should support win32k*.sys-style suffix patterns, body:\n%s", matchBody)
	}

	execPath := filepath.Join("..", "..", "executor", "executor.cc")
	execData, err := os.ReadFile(execPath)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	execSrc := string(execData)
	if !strings.Contains(execSrc, "nyx_submit_module_ranges(payload)") {
		t.Fatal("nyx_mode_loop does not call nyx_submit_module_ranges")
	}
	if strings.Contains(execSrc, `nyx_submit_module_range("ntoskrnl.exe")`) {
		t.Fatal("nyx_mode_loop still submits only ntoskrnl.exe")
	}

	runnerData, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	runnerSrc := string(runnerData)
	for _, want := range []string{
		"nyxModuleRangeConfigFile",
		"os.WriteFile(path, packModuleRangeConfig(vm.moduleRanges)",
		"sharedir=%s",
	} {
		if !strings.Contains(runnerSrc, want) {
			t.Fatalf("runner main.go missing %q", want)
		}
	}
}

func TestStandaloneBootstrapProgramForNtQuerySystemInformation(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	meta := target.SyscallMap["NtQuerySystemInformation"]
	if meta == nil {
		t.Fatal("NtQuerySystemInformation missing from windows/amd64 target")
	}
	p, bootstrap, err := standaloneProgram(target, meta, 1)
	if err != nil {
		t.Fatalf("standaloneProgram: %v", err)
	}
	if !bootstrap {
		t.Fatal("NtQuerySystemInformation should use deterministic bootstrap program")
	}
	wantCalls := []struct {
		name  string
		async bool
	}{
		{"VirtualAlloc", false},
		{"NtQuerySystemInformation", false},
		{"NtQueryTimerResolution", false},
		{"NtQuerySystemTime", false},
		{"NtQueryPerformanceCounter", false},
		{"NtDelayExecution", true},
		{"CloseHandle", true},
		{"NtYieldExecution", true},
		{"NtFlushWriteBuffer", true},
	}
	if len(p.Calls) != len(wantCalls) {
		t.Fatalf("bootstrap program has %d calls, want %d", len(p.Calls), len(wantCalls))
	}
	for i, want := range wantCalls {
		if got := p.Calls[i].Meta.Name; got != want.name {
			t.Fatalf("bootstrap call[%d] = %q, want %q", i, got, want.name)
		}
		if got := p.Calls[i].Props.Async; got != want.async {
			t.Fatalf("bootstrap call[%d] async=%v, want %v", i, got, want.async)
		}
	}
	serialized := string(p.Serialize())
	if !strings.Contains(serialized, "NtQuerySystemInformation(") ||
		!strings.Contains(serialized, "NtDelayExecution(") ||
		!strings.Contains(serialized, "0xfffffffffff85ee0") ||
		!strings.Contains(serialized, "NtFlushWriteBuffer() (async)") {
		t.Fatalf("unexpected bootstrap program:\n%s", serialized)
	}
	execData, err := p.SerializeForExec()
	if err != nil {
		t.Fatalf("SerializeForExec: %v", err)
	}
	decoded, err := target.DeserializeExec(execData, nil)
	if err != nil {
		t.Fatalf("DeserializeExec: %v", err)
	}
	if len(decoded.Calls) != len(wantCalls) {
		t.Fatalf("decoded bootstrap program into %d calls, want %d", len(decoded.Calls), len(wantCalls))
	}
	for i, want := range wantCalls {
		if decoded.Calls[i].Meta == nil || decoded.Calls[i].Meta.Name != want.name {
			t.Fatalf("decoded bootstrap call[%d] mismatch: got %#v want %q", i, decoded.Calls[i].Meta, want.name)
		}
	}
}

func TestStandaloneBootstrapProgramFitsReferenceNyxPayload(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	meta := target.SyscallMap["NtQuerySystemInformation"]
	if meta == nil {
		t.Fatal("NtQuerySystemInformation missing from windows/amd64 target")
	}
	p, bootstrap, err := standaloneProgram(target, meta, 1)
	if err != nil {
		t.Fatalf("standaloneProgram: %v", err)
	}
	if !bootstrap {
		t.Fatal("NtQuerySystemInformation should use deterministic bootstrap program")
	}
	execData, err := p.SerializeForExec()
	if err != nil {
		t.Fatalf("SerializeForExec: %v", err)
	}
	const (
		oldSmokePayload  = 4096
		referencePayload = 131072
	)
	if got := len(execData) + 4; got > oldSmokePayload {
		t.Logf("bootstrap exec payload=%d exceeds smoke-sized Nyx buffer=%d", got, oldSmokePayload)
	} else {
		t.Fatalf("bootstrap exec payload=%d unexpectedly fits smoke-sized Nyx buffer=%d", got, oldSmokePayload)
	}
	if got := len(execData) + 4; got > referencePayload {
		t.Fatalf("bootstrap exec payload=%d exceeds reference Nyx payload=%d", got, referencePayload)
	}
}

func TestStandaloneGenericProgramsContainRequestedSyscall(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	deterministic := map[string]bool{
		"NtDeviceIoControlFile":                       true,
		"NtFsControlFile":                             true,
		"NtFsControlFile$ntfs_get_compression":        true,
		"NtFsControlFile$ntfs_set_compression":        true,
		"NtFsControlFile$ntfs_set_sparse":             true,
		"NtFsControlFile$ntfs_set_zero_data":          true,
		"NtFsControlFile$ntfs_query_allocated_ranges": true,
		"NtQueryInformationFile$basic":                true,
		"NtQueryInformationFile$standard":             true,
		"NtQueryInformationFile$network_open":         true,
		"NtReadFile":                                  true,
		"NtSetInformationFile$basic":                  true,
		"NtWriteFile":                                 true,
		"TransmitFile$inet_accept":                    true,
		"ConnectEx$inet_tcp":                          true,
		"ConnectEx$inet_tcp_pending":                  true,
		"CreateIoCompletionPort$connect_pending":      true,
		"WSAGetOverlappedResult$connect_pending":      true,
		"CancelIoEx$connect_pending":                  true,
		"CancelIo$connect_pending":                    true,
		"closesocket$connect_pending":                 true,
		"WSARecv$tcp_pending":                         true,
		"WSASend$tcp_pending":                         true,
		"CreateIoCompletionPort$tcp_recv_pending":     true,
		"CreateIoCompletionPort$tcp_send_pending":     true,
		"WSAGetOverlappedResult$tcp_recv_pending":     true,
		"WSAGetOverlappedResult$tcp_send_pending":     true,
		"CancelIoEx$tcp_recv_pending":                 true,
		"CancelIoEx$tcp_send_pending":                 true,
		"CancelIo$tcp_recv_pending":                   true,
		"CancelIo$tcp_send_pending":                   true,
		"closesocket$tcp_recv_pending":                true,
		"closesocket$tcp_send_pending":                true,
		"DisconnectEx$inet_tcp":                       true,
		"DisconnectEx$inet_tcp_reuse":                 true,
		"ConnectEx$inet_tcp_reuse":                    true,
		"GetAcceptExSockaddrs$inet_tcp":               true,
		"TransmitPackets$inet_accept":                 true,
		"WSARecvMsg$udp":                              true,
		"WSAEventSelect$tcp":                          true,
		"WSAEnumNetworkEvents$tcp":                    true,
		"WSAEventSelect$accept":                       true,
		"WSAEnumNetworkEvents$accept":                 true,
		"WSAGetOverlappedResult$socket":               true,
		"CancelIoEx$socket":                           true,
		"CancelIo$socket":                             true,
		"CreateIoCompletionPort$socket":               true,
		"GetQueuedCompletionStatus$socket":            true,
		"AcceptEx$inet_tcp_pending":                   true,
		"setsockopt$update_accept_context":            true,
		"CreateIoCompletionPort$accept_pending":       true,
		"WSAGetOverlappedResult$accept_pending":       true,
		"CancelIoEx$accept_pending":                   true,
		"CancelIo$accept_pending":                     true,
		"closesocket$accept_pending":                  true,
		"WSARecv$accept_pending":                      true,
		"WSASend$accept_pending":                      true,
		"CreateIoCompletionPort$accept_recv_pending":  true,
		"CreateIoCompletionPort$accept_send_pending":  true,
		"WSAGetOverlappedResult$accept_recv_pending":  true,
		"WSAGetOverlappedResult$accept_send_pending":  true,
		"CancelIoEx$accept_recv_pending":              true,
		"CancelIoEx$accept_send_pending":              true,
		"CancelIo$accept_recv_pending":                true,
		"CancelIo$accept_send_pending":                true,
		"closesocket$accept_recv_pending":             true,
		"closesocket$accept_send_pending":             true,
		"send$inet_accept_updated":                    true,
		"recv$inet_accept_updated":                    true,
		"setsockopt$int_accept_updated":               true,
		"getsockopt$int_accept_updated":               true,
		"getsockopt$int_accept":                       true,
	}
	for _, name := range []string{
		"NtDeviceIoControlFile",
		"NtFsControlFile",
		"NtFsControlFile$ntfs_get_compression",
		"NtFsControlFile$ntfs_set_compression",
		"NtFsControlFile$ntfs_set_sparse",
		"NtFsControlFile$ntfs_set_zero_data",
		"NtFsControlFile$ntfs_query_allocated_ranges",
		"NtQueryInformationFile$basic",
		"NtQueryInformationFile$standard",
		"NtQueryInformationFile$network_open",
		"NtReadFile",
		"NtSetInformationFile$basic",
		"NtWriteFile",
		"send$inet_tcp",
		"recv$inet_udp",
		"TransmitFile$inet_accept",
		"ConnectEx$inet_tcp",
		"ConnectEx$inet_tcp_pending",
		"CreateIoCompletionPort$connect_pending",
		"WSAGetOverlappedResult$connect_pending",
		"CancelIoEx$connect_pending",
		"CancelIo$connect_pending",
		"closesocket$connect_pending",
		"WSARecv$tcp_pending",
		"WSASend$tcp_pending",
		"CreateIoCompletionPort$tcp_recv_pending",
		"CreateIoCompletionPort$tcp_send_pending",
		"WSAGetOverlappedResult$tcp_recv_pending",
		"WSAGetOverlappedResult$tcp_send_pending",
		"CancelIoEx$tcp_recv_pending",
		"CancelIoEx$tcp_send_pending",
		"CancelIo$tcp_recv_pending",
		"CancelIo$tcp_send_pending",
		"closesocket$tcp_recv_pending",
		"closesocket$tcp_send_pending",
		"DisconnectEx$inet_tcp",
		"DisconnectEx$inet_tcp_reuse",
		"ConnectEx$inet_tcp_reuse",
		"GetAcceptExSockaddrs$inet_tcp",
		"TransmitPackets$inet_accept",
		"WSARecvMsg$udp",
		"WSAEventSelect$tcp",
		"WSAEnumNetworkEvents$tcp",
		"WSAEventSelect$accept",
		"WSAEnumNetworkEvents$accept",
		"WSAGetOverlappedResult$socket",
		"CancelIoEx$socket",
		"CancelIo$socket",
		"CreateIoCompletionPort$socket",
		"GetQueuedCompletionStatus$socket",
		"AcceptEx$inet_tcp_pending",
		"setsockopt$update_accept_context",
		"CreateIoCompletionPort$accept_pending",
		"WSAGetOverlappedResult$accept_pending",
		"CancelIoEx$accept_pending",
		"CancelIo$accept_pending",
		"closesocket$accept_pending",
		"WSARecv$accept_pending",
		"WSASend$accept_pending",
		"CreateIoCompletionPort$accept_recv_pending",
		"CreateIoCompletionPort$accept_send_pending",
		"WSAGetOverlappedResult$accept_recv_pending",
		"WSAGetOverlappedResult$accept_send_pending",
		"CancelIoEx$accept_recv_pending",
		"CancelIoEx$accept_send_pending",
		"CancelIo$accept_recv_pending",
		"CancelIo$accept_send_pending",
		"closesocket$accept_recv_pending",
		"closesocket$accept_send_pending",
		"send$inet_accept_updated",
		"recv$inet_accept_updated",
		"setsockopt$int_accept_updated",
		"getsockopt$int_accept_updated",
		"getsockopt$int_accept",
	} {
		meta := target.SyscallMap[name]
		if meta == nil {
			t.Fatalf("%s missing from windows/amd64 target", name)
		}
		p, bootstrap, err := standaloneProgram(target, meta, 1)
		if err != nil {
			t.Fatalf("standaloneProgram(%s): %v", name, err)
		}
		if bootstrap != deterministic[name] {
			t.Fatalf("%s bootstrap=%v, want %v", name, bootstrap, deterministic[name])
		}
		serialized := string(p.Serialize())
		if !strings.Contains(serialized, name+"(") {
			t.Fatalf("generated program does not contain %s:\n%s", name, serialized)
		}
		execData, err := p.SerializeForExec()
		if err != nil {
			t.Fatalf("SerializeForExec(%s): %v", name, err)
		}
		decoded, err := target.DeserializeExec(execData, nil)
		if err != nil {
			t.Fatalf("DeserializeExec(%s): %v", name, err)
		}
		found := false
		for _, call := range decoded.Calls {
			if call.Meta != nil && call.Meta.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("exec program does not contain %s after decode:\n%s", name, serialized)
		}
	}
}

func TestDescribeExecProgramReportsFirstDeepAFDCall(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	p, err := target.Deserialize([]byte(
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = bind$inet_tcp(r0, &(0x7f0000000000)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = listen$inet_tcp(r1, 0x1)\n"+
			"r3 = accept$inet_tcp(r2, 0x0, 0x0)\n"+
			"CancelIoEx$socket(r3, 0x0)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	execData, err := p.SerializeForExec()
	if err != nil {
		t.Fatalf("SerializeForExec: %v", err)
	}
	got := describeExecProgram(execData)
	if !strings.Contains(got, "call0=socket$inet_tcp") {
		t.Fatalf("program summary missing setup call0: %q", got)
	}
	if !strings.Contains(got, "deep0=CancelIoEx$socket") {
		t.Fatalf("program summary missing first deep AFD call: %q", got)
	}
}

func TestStandaloneGenericProgramsReceiveTransitiveScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	tests := []struct {
		name string
		want []string
	}{
		{
			name: "NtDeviceIoControlFile",
			want: []string{"CreateFileA(", "NtDeviceIoControlFile("},
		},
		{
			name: "NtFsControlFile",
			want: []string{"CreateFileA(", "NtFsControlFile("},
		},
		{
			name: "NtFsControlFile$ntfs_set_zero_data",
			want: []string{"CreateFileA(", "WriteFile(", "NtFsControlFile$ntfs_set_zero_data("},
		},
		{
			name: "TransmitFile$inet_accept",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "CreateFileA("},
		},
		{
			name: "ConnectEx$inet_tcp",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "bind$connectex_tcp(", "ConnectEx$inet_tcp("},
		},
		{
			name: "CancelIoEx$connect_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "ConnectEx$inet_tcp_pending(", "CancelIoEx$connect_pending("},
		},
		{
			name: "WSAGetOverlappedResult$connect_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "ConnectEx$inet_tcp_pending(", "WSAGetOverlappedResult$connect_pending("},
		},
		{
			name: "closesocket$connect_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "ConnectEx$inet_tcp_pending(", "closesocket$connect_pending("},
		},
		{
			name: "TransmitPackets$inet_accept",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "TransmitPackets$inet_accept("},
		},
		{
			name: "WSARecvMsg$udp",
			want: []string{"WSAStartup(", "socket$bound_udp(", "send$inet_udp(", "WSARecvMsg$udp("},
		},
		{
			name: "WSAEventSelect$tcp",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSACreateEvent(", "WSAEventSelect$tcp("},
		},
		{
			name: "WSAEnumNetworkEvents$tcp",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSAEventSelect$tcp(", "WSAEnumNetworkEvents$tcp("},
		},
		{
			name: "WSAEventSelect$accept",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSACreateEvent(", "WSAEventSelect$accept("},
		},
		{
			name: "WSAEnumNetworkEvents$accept",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSAEventSelect$accept(", "WSAEnumNetworkEvents$accept("},
		},
		{
			name: "CancelIoEx$socket",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSARecv$accept(", "CancelIoEx$socket("},
		},
		{
			name: "WSAGetOverlappedResult$socket",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSARecv$accept(", "WSAGetOverlappedResult$socket("},
		},
		{
			name: "GetQueuedCompletionStatus$socket",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "CreateIoCompletionPort$socket(", "GetQueuedCompletionStatus$socket("},
		},
		{
			name: "CancelIoEx$accept_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "AcceptEx$inet_tcp_pending(", "CancelIoEx$accept_pending("},
		},
		{
			name: "WSAGetOverlappedResult$accept_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "AcceptEx$inet_tcp_pending(", "WSAGetOverlappedResult$accept_pending("},
		},
		{
			name: "closesocket$accept_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "AcceptEx$inet_tcp_pending(", "closesocket$accept_pending("},
		},
		{
			name: "CancelIoEx$accept_recv_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSARecv$accept_pending(", "CancelIoEx$accept_recv_pending("},
		},
		{
			name: "closesocket$accept_recv_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSARecv$accept_pending(", "closesocket$accept_recv_pending("},
		},
		{
			name: "WSAGetOverlappedResult$accept_send_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSASend$accept_pending(", "WSAGetOverlappedResult$accept_send_pending("},
		},
		{
			name: "closesocket$accept_send_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSASend$accept_pending(", "closesocket$accept_send_pending("},
		},
		{
			name: "CancelIoEx$tcp_recv_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSARecv$tcp_pending(", "CancelIoEx$tcp_recv_pending("},
		},
		{
			name: "closesocket$tcp_recv_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSARecv$tcp_pending(", "closesocket$tcp_recv_pending("},
		},
		{
			name: "WSAGetOverlappedResult$tcp_send_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSASend$tcp_pending(", "WSAGetOverlappedResult$tcp_send_pending("},
		},
		{
			name: "closesocket$tcp_send_pending",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "WSASend$tcp_pending(", "closesocket$tcp_send_pending("},
		},
		{
			name: "send$inet_accept_updated",
			want: []string{"WSAStartup(", "socket$listener_tcp(", "AcceptEx$inet_tcp_pending(", "setsockopt$update_accept_context(", "send$inet_accept_updated("},
		},
	}
	for _, test := range tests {
		meta := target.SyscallMap[test.name]
		if meta == nil {
			t.Fatalf("%s missing from windows/amd64 target", test.name)
		}
		p, bootstrap, err := standaloneProgram(target, meta, 1)
		if err != nil {
			t.Fatalf("standaloneProgram(%s): %v", test.name, err)
		}
		deterministic := test.name == "NtDeviceIoControlFile" ||
			test.name == "NtFsControlFile" ||
			test.name == "NtFsControlFile$ntfs_set_zero_data" ||
			test.name == "TransmitFile$inet_accept" ||
			test.name == "ConnectEx$inet_tcp" ||
			test.name == "CancelIoEx$connect_pending" ||
			test.name == "WSAGetOverlappedResult$connect_pending" ||
			test.name == "closesocket$connect_pending" ||
			test.name == "TransmitPackets$inet_accept" ||
			test.name == "WSARecvMsg$udp" ||
			test.name == "WSAEventSelect$tcp" ||
			test.name == "WSAEnumNetworkEvents$tcp" ||
			test.name == "WSAEventSelect$accept" ||
			test.name == "WSAEnumNetworkEvents$accept" ||
			test.name == "CancelIoEx$socket" ||
			test.name == "WSAGetOverlappedResult$socket" ||
			test.name == "GetQueuedCompletionStatus$socket" ||
			test.name == "CancelIoEx$accept_pending" ||
			test.name == "WSAGetOverlappedResult$accept_pending" ||
			test.name == "closesocket$accept_pending" ||
			test.name == "CancelIoEx$accept_recv_pending" ||
			test.name == "closesocket$accept_recv_pending" ||
			test.name == "WSAGetOverlappedResult$accept_send_pending" ||
			test.name == "closesocket$accept_send_pending" ||
			test.name == "CancelIoEx$tcp_recv_pending" ||
			test.name == "closesocket$tcp_recv_pending" ||
			test.name == "WSAGetOverlappedResult$tcp_send_pending" ||
			test.name == "closesocket$tcp_send_pending" ||
			test.name == "send$inet_accept_updated"
		if !deterministic && bootstrap {
			t.Fatalf("%s unexpectedly used deterministic bootstrap", test.name)
		}
		serialized := string(p.Serialize())
		for _, want := range test.want {
			if !strings.Contains(serialized, want) {
				t.Fatalf("generated program for %s is missing %q:\n%s", test.name, want, serialized)
			}
		}
	}
}

func TestFilterCoveragePCsDropsUserAddressesOn64BitKernel(t *testing.T) {
	pcs := []uint64{
		0xfffff8059d89c200,
		0x7ffca8583534,
		0,
		0xfffff8059d89c234,
	}
	got := filterCoveragePCs(slices.Clone(pcs), true)
	want := []uint64{
		0xfffff8059d89c200,
		0xfffff8059d89c234,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("filterCoveragePCs() = %#x, want %#x", got, want)
	}
}

func TestRunQemuWithTimeoutReturnsNetTimeout(t *testing.T) {
	host, peer := net.Pipe()
	defer host.Close()
	defer peer.Close()

	readPing := make(chan error, 1)
	go func() {
		var ping [1]byte
		_, err := peer.Read(ping[:])
		readPing <- err
	}()

	vm := &nyxVM{control: host}
	start := time.Now()
	err := vm.runQemuWithTimeout(20 * time.Millisecond)
	if err == nil {
		t.Fatal("runQemuWithTimeout returned nil, want timeout")
	}
	if !isTimeoutError(err) {
		t.Fatalf("runQemuWithTimeout error %T %v, want net timeout", err, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("runQemuWithTimeout took %s, want bounded timeout", elapsed)
	}
	if err := <-readPing; err != nil {
		t.Fatalf("peer did not receive ping: %v", err)
	}
}

func TestExecutorInitializesInputDataBeforeNyxPreview(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	src := string(data)
	start := strings.Index(src, "parse_execute(req);")
	if start == -1 {
		t.Fatal("parse_execute(req) block not found in executor.cc")
	}
	endRel := strings.Index(src[start:], "uint64_t exec_start = current_time_ms();")
	if endRel == -1 {
		t.Fatal("Nyx exec block end not found in executor.cc")
	}
	block := src[start : start+endRel]
	assign := strings.Index(block, "input_data =")
	if assign == -1 {
		t.Fatal("input_data assignment not found before Nyx execution")
	}
	preview := strings.Index(block, "nyx_log_exec_preview(")
	if preview == -1 {
		t.Fatal("nyx_log_exec_preview call not found in Nyx execution block")
	}
	if assign > preview {
		t.Fatalf("input_data is assigned after nyx_log_exec_preview (assign=%d preview=%d)", assign, preview)
	}
}

func TestNyxModeLoopInitializesCoverageAfterHandshake(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	src := string(data)
	start := strings.Index(src, "if (header->kind == SYZ_NYX_KIND_HANDSHAKE) {")
	if start == -1 {
		t.Fatal("Nyx handshake block not found in executor.cc")
	}
	endRel := strings.Index(src[start:], "have_handshake = true;")
	if endRel == -1 {
		t.Fatal("Nyx handshake block end not found in executor.cc")
	}
	block := src[start : start+endRel]
	parseIdx := strings.Index(block, "parse_handshake(hs);")
	if parseIdx == -1 {
		t.Fatal("parse_handshake(hs) not found in Nyx handshake block")
	}
	setupIdx := strings.Index(block, "setup_coverage();")
	if setupIdx == -1 {
		t.Fatal("setup_coverage() not found in Nyx handshake block")
	}
	if setupIdx < parseIdx {
		t.Fatal("setup_coverage() appears before parse_handshake(hs) in Nyx handshake block")
	}
}

func TestNyxModeLoopLogsBeforeHandshakeDecode(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	src := string(data)
	start := strings.Index(src, "const uint8_t* body = payload->data + sizeof(*header);")
	if start == -1 {
		t.Fatal("Nyx payload body setup not found in executor.cc")
	}
	endRel := strings.Index(src[start:], "hs = {")
	if endRel == -1 {
		t.Fatal("Nyx handshake assignment block not found in executor.cc")
	}
	block := src[start : start+endRel]
	headerLog := strings.Index(block, "nyx_hprintf(\"nyx payload header kind=%u body=%u total=%d\\n\"")
	if headerLog == -1 {
		t.Fatal("Nyx payload header log not found before handshake decode")
	}
	bodyLog := strings.Index(block, "nyx_hprintf(\"nyx handshake body ready body=%u total=%d\\n\"")
	if bodyLog == -1 {
		t.Fatal("Nyx handshake body-ready log not found before handshake decode")
	}
	rootLog := strings.Index(block, "nyx_hprintf(\"nyx handshake root parsed body=%u\\n\"")
	if rootLog == -1 {
		t.Fatal("Nyx handshake root-parsed log not found before handshake decode")
	}
	rootCall := strings.Index(block, "flatbuffers::GetRoot<rpc::SnapshotHandshake>(body)")
	if rootCall == -1 {
		t.Fatal("Nyx handshake flatbuffers GetRoot call not found")
	}
	if rootLog < rootCall {
		t.Fatal("Nyx handshake root-parsed log appears before GetRoot call")
	}
}

func TestNyxModeLoopRequestsReloadAfterResultDump(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	src := string(data)
	check := func(label, block string) {
		t.Helper()
		dump := strings.Index(block, "nyx_dump_exec_result(")
		if dump == -1 {
			t.Fatalf("%s: nyx_dump_exec_result not found", label)
		}
		reload := strings.Index(block, "nyx_hypercall(HYPERCALL_KAFL_REQUEST_RELOAD, 0);")
		if reload == -1 {
			t.Fatalf("%s: request-reload hypercall not found", label)
		}
		log := strings.Index(block, "nyx_hprintf(\"nyx result dumped request=%lld bytes=%u\\n\"")
		if log == -1 {
			t.Fatalf("%s: result-dumped log not found", label)
		}
		if !(dump < reload && reload < log) {
			t.Fatalf("%s: expected dump < request-reload < result-log, got dump=%d reload=%d log=%d",
				label, dump, reload, log)
		}
	}

	demoStart := strings.Index(src, "auto demo_result = nyx_demo_execute_request(")
	if demoStart == -1 {
		t.Fatal("demo result block not found in executor.cc")
	}
	demoEndRel := strings.Index(src[demoStart:], "continue;")
	if demoEndRel == -1 {
		t.Fatal("demo result block end not found in executor.cc")
	}
	check("demo", src[demoStart:demoStart+demoEndRel])

	genericStart := strings.Index(src, "auto result = finish_output(")
	if genericStart == -1 {
		t.Fatal("generic result block not found in executor.cc")
	}
	genericEndRel := strings.Index(src[genericStart:], "}\n}")
	if genericEndRel == -1 {
		t.Fatal("generic result block end not found in executor.cc")
	}
	check("generic", src[genericStart:genericStart+genericEndRel])
}

func assertNoNyxLoggingBetweenAcquireAndRelease(t *testing.T, src string) {
	t.Helper()
	const acquireNeedle = "nyx_hypercall(HYPERCALL_KAFL_ACQUIRE,"
	const releaseNeedle = "nyx_hypercall(HYPERCALL_KAFL_RELEASE, 0);"
	found := 0
	for start := 0; start < len(src); {
		acquireRel := strings.Index(src[start:], acquireNeedle)
		if acquireRel == -1 {
			break
		}
		acquire := start + acquireRel
		releaseRel := strings.Index(src[acquire:], releaseNeedle)
		if releaseRel == -1 {
			t.Fatal("Nyx RELEASE hypercall not found after ACQUIRE")
		}
		window := src[acquire : acquire+releaseRel]
		if strings.Contains(window, "nyx_hprintf(") || strings.Contains(window, "nyx_log_exec_stage(") {
			t.Fatal("executor contains Nyx logging between ACQUIRE and RELEASE")
		}
		found++
		start = acquire + releaseRel + len(releaseNeedle)
	}
	if found == 0 {
		t.Fatal("Nyx ACQUIRE hypercall not found in executor.cc")
	}
}

func TestExecutorAvoidsNyxHprintfBetweenAcquireAndRelease(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	assertNoNyxLoggingBetweenAcquireAndRelease(t, string(data))
}

func TestExecutePathsAvoidNyxHprintf(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	src := string(data)
	body := extractFunctionBody(t, src, "void execute_call(thread_t* th)")
	assertNoNyxLoggingBetweenAcquireAndRelease(t, body)
	if !strings.Contains(body, "GetCurrentThreadId()") {
		t.Fatal("execute_call ACQUIRE path does not capture the current thread ID")
	}
	if !strings.Contains(body, "__readgsqword(0x30)") {
		t.Fatal("execute_call ACQUIRE path does not capture the thread TEB")
	}
	release := strings.Index(body, "nyx_hypercall(HYPERCALL_KAFL_RELEASE, 0);")
	if release == -1 {
		t.Fatal("execute_call RELEASE hypercall not found")
	}
	if strings.Contains(body[release:], "HYPERCALL_KAFL_SYZ_COV_DUMP") {
		t.Fatal("execute_call should rely on RELEASE handling for per-call coverage dump")
	}
}

func TestWindowsExecutorPrefaultsDataSegment(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor_windows.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor_windows.h: %v", err)
	}
	src := string(data)
	virtualAlloc := strings.Index(src, "VirtualAlloc(data, data_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)")
	if virtualAlloc == -1 {
		t.Fatal("VirtualAlloc data segment mapping not found in executor_windows.h")
	}
	prefault := strings.Index(src, "for (size_t i = 0; i < data_size; i += SYZ_PAGE_SIZE)")
	if prefault == -1 {
		t.Fatal("data segment prefault loop not found in executor_windows.h")
	}
	if prefault < virtualAlloc {
		t.Fatal("data segment prefault loop appears before VirtualAlloc mapping")
	}
}

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

	"github.com/google/syzkaller/pkg/mgrconfig"
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
	DisabledSyscalls []string `json:"disable_syscalls"`
	NoMutateSyscalls []string `json:"no_mutate_syscalls"`
	VM               struct {
		ModuleRanges string `json:"module_ranges"`
		KeepState    bool   `json:"keep_state"`
	} `json:"vm"`
	Experimental struct {
		SeedPrefix           string `json:"seed_prefix"`
		BorrowingSeedPrefix  string `json:"borrowing_seed_prefix"`
		WindowsTargetProfile string `json:"windows_target_profile"`
		ForceGenerateEveryN  int    `json:"force_generate_every_n"`
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
		DisabledSyscalls []string `json:"disable_syscalls"`
		NoMutateSyscalls []string `json:"no_mutate_syscalls"`
		VM               struct {
			ModuleRanges string `json:"module_ranges"`
			KeepState    bool   `json:"keep_state"`
		} `json:"vm"`
		Experimental struct {
			SeedPrefix           string `json:"seed_prefix"`
			BorrowingSeedPrefix  string `json:"borrowing_seed_prefix"`
			WindowsTargetProfile string `json:"windows_target_profile"`
			ForceGenerateEveryN  int    `json:"force_generate_every_n"`
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

func windowsSeedPrefixMatches(t *testing.T, prefixes string) []string {
	t.Helper()
	var matches []string
	for _, prefix := range strings.Split(prefixes, ",") {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			continue
		}
		cur, err := filepath.Glob(filepath.Join("..", "..", "sys", "windows", "test", prefix+"*.txt"))
		if err != nil {
			t.Fatalf("glob %s seeds: %v", prefix, err)
		}
		matches = append(matches, cur...)
	}
	slices.Sort(matches)
	return slices.Compact(matches)
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
	_ = expanded
}

func requireWindowsNyxExpandedSyscallsInSparseTable(t *testing.T, cfgPath string) {
	t.Helper()
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, cfgPath)
	enabledCalls := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
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
	requireWindowsNyxExpandedSyscallsInSparseTable(t, "windows-nyx-test.cfg")
}

func TestWindowsVNetPseudoSyscallsPresentInSparseTable(t *testing.T) {
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, name := range []string{
		"syz_emit_ethernet$windows",
		"syz_extract_tcp_res$windows",
		"syz_extract_tcp_res$windows_synack",
	} {
		meta := target.SyscallMap[name]
		if meta == nil {
			t.Fatalf("%s missing from windows/amd64 target", name)
		}
		gotID, ok := table[name]
		if !ok {
			t.Fatalf("%s missing from sparse Nyx table", name)
		}
		if gotID != meta.ID {
			t.Fatalf("%s has sparse ID %d, want %d", name, gotID, meta.ID)
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
		[]string{"CreateFileA"})
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
	assertResource("DisconnectEx$inet_tcp_reuse", 0, "SOCKET_TCP_CONNECTED")
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
	assertResource("ConnectEx$inet_tcp", 0, "SOCKET_TCP_CONNECTEX_BOUND")
	assertResource("ConnectEx$inet_tcp_pending", 0, "SOCKET_TCP_CONNECTEX_BOUND")
	assertResource("ConnectEx$inet_tcp_pending", -1, "SOCKET_TCP_CONNECTING")
	assertResource("DisconnectEx$inet_tcp", 0, "SOCKET_TCP_CONNECTED")
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
	assertResource("CreateIoCompletionPort$socket", -1, "IOCP_SOCKET")
	assertResource("CreateIoCompletionPort$accept_pending", -1, "IOCP_SOCKET")
	assertResource("CreateIoCompletionPort$accept_recv_pending", -1, "IOCP_SOCKET")
	assertResource("CreateIoCompletionPort$accept_send_pending", -1, "IOCP_SOCKET")
	assertResource("CreateIoCompletionPort$connect_pending", -1, "IOCP_SOCKET")
	assertResource("CreateIoCompletionPort$tcp_recv_pending", -1, "IOCP_SOCKET")
	assertResource("CreateIoCompletionPort$tcp_send_pending", -1, "IOCP_SOCKET")
	assertResource("GetQueuedCompletionStatus$socket", 0, "IOCP_SOCKET")
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
		[]string{"CreateFileA"})
	enabledCalls := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		enabledCalls[target.SyscallMap[name]] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabledCalls)
	for _, name := range []string{"CreateFileA"} {
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
		"windows-nyx-afd-vnet-proven.cfg",
		"windows-nyx-afd-private.cfg",
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
			if matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix); len(matches) == 0 {
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

func TestWindowsAfdSessionAvoidsKnownBlockingConstructors(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-session.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
	}

	forbidden := []string{
		"socket$connected_tcp",
		"connect$inet_tcp",
		"bind$connectex_tcp",
		"send$inet_tcp",
		"WSASend$tcp*",
		"shutdown$tcp*",
		"getsockname$tcp",
		"getpeername$tcp",
		"WSAEventSelect$tcp",
		"WSAEnumNetworkEvents$tcp",
		"WSAIoctl$sio_keepalive_vals",
		"WSAIoctl$sio_get_extension_function_pointer",
		"ConnectEx$inet_tcp*",
		"DisconnectEx$inet_tcp*",
		"ioctlsocket$fionbio_tcp",
		"setsockopt$int_tcp",
		"getsockopt$int_tcp",
		"socket$connected_udp",
		"connect$inet_udp",
		"send$inet_udp",
		"sendto$udp_connected",
		"WSASendTo$udp",
		"getpeername$udp",
		"select$afd_basic",
		"WSAIoctl$sio_address_list_query",
		"WSAIoctl$sio_routing_interface_query",
		"GetAcceptExSockaddrs$inet_tcp",
		"accept$inet_tcp",
		"socket$accept_tcp",
		"recv$inet_tcp",
		"recv$inet_accept*",
		"recv$inet_udp",
		"WSARecv$tcp",
		"WSARecv$accept*",
		"recvfrom$udp_bound",
		"recvfrom$udp_connected",
		"WSARecvFrom$udp",
		"WSARecvMsg$udp",
		"WSARecvEx$inet_accept",
		"send$inet_accept*",
		"WSASend$accept*",
		"shutdown$accept*",
		"getsockname$accept",
		"getpeername$accept",
		"WSAEventSelect$accept",
		"WSAEnumNetworkEvents$accept",
		"CreateIoCompletionPort$accept*",
		"WSAGetOverlappedResult$accept*",
		"CancelIoEx$accept*",
		"CancelIo$accept*",
		"closesocket$accept*",
		"AcceptEx$inet_tcp*",
		"setsockopt$update_accept_context",
		"TransmitPackets$inet_accept",
		"setsockopt$int_accept*",
		"getsockopt$int_accept*",
		"ioctlsocket$fionbio_accept",
	}
	for _, name := range cfg.EnabledSyscalls {
		for _, pattern := range forbidden {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("broad AFD session directly enables blocking syscall %q via pattern %q",
					name, pattern)
			}
		}
	}

	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		for _, pattern := range forbidden {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("broad AFD session leaves blocking syscall %q enabled via pattern %q",
					name, pattern)
			}
		}
	}
}

func TestWindowsAfdVNetProvenConfigSeedsStayNarrow(t *testing.T) {
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-vnet-proven.cfg")
	if cfg.Experimental.SeedPrefix != cfg.Experimental.BorrowingSeedPrefix {
		t.Fatalf("vnet proven seed_prefix=%q borrowing_seed_prefix=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	var got []string
	for _, match := range matches {
		got = append(got, filepath.Base(match))
	}
	want := []string{
		"nyx_afd_accept_vnet_recv.txt",
		"nyx_afd_accept_vnet_recv_nonblock.txt",
		"nyx_afd_accept_vnet_wsarecv.txt",
		"nyx_afd_accept_vnet_wsarecv_pending_iocp.txt",
		"nyx_afd_acceptex_vnet_cancel.txt",
		"nyx_afd_acceptex_vnet_iocp.txt",
		"nyx_afd_acceptex_vnet_sockaddrs.txt",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("vnet proven seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	forbidden := []string{"_syn_tapmac", "_listener_", "_udp_"}
	for _, name := range got {
		for _, needle := range forbidden {
			if strings.Contains(name, needle) {
				t.Fatalf("vnet proven gate should not include diagnostic seed %s", name)
			}
		}
	}
}

func TestWindowsAfdVNetProvenConfigForcesGenerationInterleave(t *testing.T) {
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-vnet-proven.cfg")
	if cfg.Experimental.ForceGenerateEveryN != 2 {
		t.Fatalf("vnet proven force_generate_every_n=%d, want 2",
			cfg.Experimental.ForceGenerateEveryN)
	}
}

func TestWindowsAfdVNetProvenConfigCoversSeedSyscalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-vnet-proven.cfg")
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	for _, path := range windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		for _, call := range p.Calls {
			if call.Meta.Attrs.NoGenerate || call.Meta.Attrs.AutomaticHelper {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-vnet-proven.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdSessionConfigUsesSnapshotIsolation(t *testing.T) {
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-session.cfg")
	if cfg.VM.KeepState {
		t.Fatal("AFD session config must keep vm.keep_state disabled so each request reloads the Nyx root snapshot")
	}
}

func TestWindowsAfdPrivateConfigStaysQueryOnly(t *testing.T) {
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-private.cfg")
	want := []string{
		"NtDeviceIoControlFile$afd_query_recv_tcp",
		"NtDeviceIoControlFile$afd_query_recv_accept",
		"NtDeviceIoControlFile$afd_get_remote_address_tcp",
		"NtDeviceIoControlFile$afd_get_context_tcp",
		"NtDeviceIoControlFile$afd_address_list_query_udp",
		"NtDeviceIoControlFile$afd_routing_interface_query_udp",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("private AFD enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	for _, name := range cfg.EnabledSyscalls {
		if strings.Contains(name, "event_select") ||
			strings.Contains(name, "enum_network_events") ||
			strings.Contains(name, "poll") {
			t.Fatalf("private AFD config should keep %s seed-only", name)
		}
	}
}

func TestWindowsAfdPrivateConfigForcesGenerationInterleave(t *testing.T) {
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-private.cfg")
	if cfg.Experimental.ForceGenerateEveryN != 2 {
		t.Fatalf("private AFD force_generate_every_n=%d, want 2",
			cfg.Experimental.ForceGenerateEveryN)
	}
}

func TestWindowsAfdPrivateConfigCoversSeedSyscalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-private.cfg")
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	for _, path := range windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		for _, call := range p.Calls {
			if call.Meta.Attrs.NoGenerate || call.Meta.Attrs.AutomaticHelper {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-private.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
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
		p := target.GenSampleProg(meta, rand.NewSource(1), target.DefaultChoiceTable())
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

func TestDescribeExecProgramReportsWindowsVNetUse(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	serialized, err := os.ReadFile(filepath.Join("..", "..", "sys", "windows", "test", "nyx_vnet_ipv4_tcp_syn.txt"))
	if err != nil {
		t.Fatalf("read vnet seed: %v", err)
	}
	p, err := target.Deserialize(serialized, prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	execData, err := p.SerializeForExec()
	if err != nil {
		t.Fatalf("SerializeForExec: %v", err)
	}
	got := describeExecProgram(execData)
	if !strings.Contains(got, "call0=syz_emit_ethernet$windows") {
		t.Fatalf("program summary missing vnet call0: %q", got)
	}
	if !strings.Contains(got, "vnet=1") {
		t.Fatalf("program summary missing vnet marker: %q", got)
	}
}

func TestStandaloneProgramFileLoadsWindowsVNetSeed(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	seedPath := filepath.Join("..", "..", "sys", "windows", "test", "nyx_vnet_ipv4_tcp_syn.txt")
	p, bootstrap, label, err := standaloneBaseProgram(target, "NtQuerySystemInformation", 1, seedPath)
	if err != nil {
		t.Fatalf("standaloneBaseProgram: %v", err)
	}
	if bootstrap {
		t.Fatal("standalone program file should not be treated as bootstrap")
	}
	if label != seedPath {
		t.Fatalf("label=%q, want %q", label, seedPath)
	}
	serialized := string(p.Serialize())
	for _, want := range []string{
		"syz_emit_ethernet$windows(",
		"syz_extract_tcp_res$windows_synack(",
	} {
		if !strings.Contains(serialized, want) {
			t.Fatalf("standalone program file missing %q:\n%s", want, serialized)
		}
	}
	execData, err := p.SerializeForExec()
	if err != nil {
		t.Fatalf("SerializeForExec: %v", err)
	}
	got := describeExecProgram(execData)
	if !strings.Contains(got, "call0=syz_emit_ethernet$windows") ||
		!strings.Contains(got, "vnet=1") {
		t.Fatalf("vnet standalone program summary mismatch: %q", got)
	}
	enabled := standaloneEnabledCallsForProgram(target, p)
	for _, name := range []string{
		"syz_emit_ethernet$windows",
		"syz_extract_tcp_res$windows_synack",
	} {
		if !enabled[target.SyscallMap[name]] {
			t.Fatalf("standalone program enabled calls missing %s", name)
		}
	}
}

func TestStandaloneStagedProgramFilesLoadWindowsVNetSeeds(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	tests := []struct {
		path string
		want []string
	}{
		{
			path: filepath.Join("..", "..", "sys", "windows", "test", "nyx_afd_listener_vnet_syn_tapmac_any_stage1.txt"),
			want: []string{
				"listen$inet_tcp(",
				"syz_emit_ethernet$windows(",
			},
		},
		{
			path: filepath.Join("..", "..", "sys", "windows", "test", "nyx_afd_listener_vnet_arp_syn_tapmac_any_bind_any_stage1.txt"),
			want: []string{
				"listen$inet_tcp(",
				"@arp=",
				"syz_emit_ethernet$windows(",
			},
		},
		{
			path: filepath.Join("..", "..", "sys", "windows", "test", "nyx_vnet_extract_tcp_cache_stage2.txt"),
			want: []string{
				"syz_extract_tcp_res$windows_synack(",
			},
		},
	}
	for _, test := range tests {
		p, bootstrap, label, err := standaloneBaseProgram(target, "NtQuerySystemInformation", 1, test.path)
		if err != nil {
			t.Fatalf("standaloneBaseProgram(%s): %v", test.path, err)
		}
		if bootstrap {
			t.Fatalf("%s should not be treated as bootstrap", test.path)
		}
		if label != test.path {
			t.Fatalf("label=%q, want %q", label, test.path)
		}
		serialized := string(p.Serialize())
		for _, want := range test.want {
			if !strings.Contains(serialized, want) {
				t.Fatalf("%s missing %q:\n%s", test.path, want, serialized)
			}
		}
		execData, err := p.SerializeForExec()
		if err != nil {
			t.Fatalf("SerializeForExec(%s): %v", test.path, err)
		}
		if !strings.Contains(describeExecProgram(execData), "vnet=1") {
			t.Fatalf("%s should be marked as a vnet standalone program", test.path)
		}
	}
}

func TestStandaloneStagedVNetModeIsHostDelayed(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(data)
	for _, want := range []string{
		"standalone-staged-program",
		"standalone-stage-delay-ms",
		"runStandaloneStaged",
		"standalone staged host sleep before stage2",
		"guest is not stepped",
		"time.Sleep(time.Duration(stageDelayMs) * time.Millisecond)",
		"--standalone-staged-program requires --standalone-program",
		"standalone staged exec program %s",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("main.go is missing staged vnet standalone support %q", want)
		}
	}
}

func TestStandaloneStagedVNetModeSupportsGuestIdle(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(data)
	for _, want := range []string{
		"nyxKindIdle",
		"type nyxIdleMeta struct",
		"func (vm *nyxVM) executeIdle",
		"packNyxPayload(nyxKindIdle",
		"standalone-stage-idle-ms",
		"standalone staged guest idle before stage2",
		"standalone staged guest idle finished",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("main.go is missing staged guest idle support %q", want)
		}
	}
}

func TestNyxModeLoopSupportsIdlePayload(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "executor", "executor.cc"))
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	src := string(data)
	for _, want := range []string{
		"SYZ_NYX_KIND_IDLE",
		"nyx_idle_meta_t",
		"if (sleep_ms != 0)",
		"nyx idle begin sleep_ms=%u",
		"Sleep(sleep_ms)",
		"nyx idle kept guest state sleep_ms=%u",
		"nyx idle result dumped sleep_ms=%u bytes=%u",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("executor.cc is missing Nyx idle support %q", want)
		}
	}
	body := extractFunctionBody(t, src, "int nyx_mode_loop")
	idle := strings.Index(body, "if (header->kind == SYZ_NYX_KIND_IDLE)")
	exec := strings.Index(body, "if (header->kind != SYZ_NYX_KIND_EXEC)")
	if idle == -1 || exec == -1 || exec <= idle {
		t.Fatal("failed to locate Nyx idle block")
	}
	idleBlock := body[idle:exec]
	if strings.Contains(idleBlock, "HYPERCALL_KAFL_REQUEST_RELOAD") {
		t.Fatal("Nyx idle payload must preserve guest state for staged standalone programs")
	}
}

func TestStandaloneStagedVNetModeCanKeepGuestState(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(data)
	body := extractFunctionBody(t, src, "func runStandaloneStaged")
	for _, want := range []string{
		"keepState:    keepState",
		"standalone staged guest idle before stage2",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("runStandaloneStaged is missing configurable keep-state support %q", want)
		}
	}
}

func TestStandaloneExecProgramReplayFlagsAreWired(t *testing.T) {
	mainData, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	mainSrc := string(mainData)
	for _, want := range []string{
		"standalone-exec-program",
		"standalone-staged-exec-program",
		"runStandaloneExec(",
		"runStandaloneExecStaged(",
	} {
		if !strings.Contains(mainSrc, want) {
			t.Fatalf("runner standalone exec replay support missing %q", want)
		}
	}
	reorder := extractFunctionBody(t, mainSrc, "func reorderArgsForFlags")
	for _, want := range []string{
		"-standalone-exec-program",
		"-standalone-staged-exec-program",
		"--standalone-exec-program",
		"--standalone-staged-exec-program",
	} {
		if !strings.Contains(reorder, want) {
			t.Fatalf("runner arg reordering missing %q", want)
		}
	}

	scriptPath := filepath.Join("..", "..", "..", "guest-vm", "run-nyx-fullchain.sh")
	scriptData, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	scriptSrc := string(scriptData)
	for _, want := range []string{
		"--standalone-exec-program",
		"--standalone-staged-exec-program",
		"standalone_exec_program",
		"standalone_staged_exec_program",
	} {
		if !strings.Contains(scriptSrc, want) {
			t.Fatalf("run-nyx-fullchain standalone exec replay support missing %q", want)
		}
	}
}

func TestRunnerHandshakeUsesTimeoutAndSlowTraceArtifact(t *testing.T) {
	mainData, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	mainSrc := string(mainData)
	if !strings.Contains(mainSrc, "func (vm *nyxVM) executeHandshake(payload []byte, requestID int64)") {
		t.Fatal("executeHandshake should take the request id used for trace attribution")
	}
	executeHandshake := extractFunctionBody(t, mainSrc, "func (vm *nyxVM) executeHandshake")
	for _, want := range []string{
		"vm.traceReqID = requestID",
		"deadline := time.Now().Add(vm.execWaitTimeout())",
		"runQemuWithTimeout(remaining)",
		"handshake_step_timeout",
		"recordHprintfTrace(requestID)",
	} {
		if !strings.Contains(executeHandshake, want) {
			t.Fatalf("executeHandshake missing %q", want)
		}
	}

	ensureHandshake := extractFunctionBody(t, mainSrc, "func (r *runner) ensureHandshake")
	for _, want := range []string{
		"handshake_request_begin",
		"executeHandshake(packNyxPayload(nyxKindHandshake, nil, packFlatbuffer(msg)), req.Id)",
		"handshake_error",
		`r.maybeDumpSlowTrace(req, "runner handshake"`,
		"handshake_end",
	} {
		if !strings.Contains(ensureHandshake, want) {
			t.Fatalf("ensureHandshake missing %q", want)
		}
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

func TestNyxModeLoopReloadsExecByDefaultUnlessKeepStateRequested(t *testing.T) {
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
		finish := strings.Index(block, "nyx_finish_exec_payload(meta, msg->num_calls())")
		if finish == -1 {
			t.Fatalf("%s: exec finish helper not found", label)
		}
		log := strings.Index(block, "nyx_hprintf(\"nyx result dumped request=%lld bytes=%u\\n\"")
		if log == -1 {
			t.Fatalf("%s: result-dumped log not found", label)
		}
		if !(dump < finish && finish < log) {
			t.Fatalf("%s: expected dump < finish < result-log, got dump=%d finish=%d log=%d",
				label, dump, finish, log)
		}
	}
	helper := extractFunctionBody(t, src, "static void nyx_finish_exec_payload")
	for _, want := range []string{
		"meta->flags & SYZ_NYX_EXEC_KEEP_STATE",
		"nyx result kept guest state request=%lld calls=%u flags=0x%x",
		"nyx result requesting reload request=%lld calls=%u flags=0x%x",
		"nyx_hypercall(HYPERCALL_KAFL_REQUEST_RELOAD, 0);",
	} {
		if !strings.Contains(helper, want) {
			t.Fatalf("exec finish helper missing %q", want)
		}
	}
	keep := strings.Index(helper, "nyx result kept guest state")
	reload := strings.Index(helper, "nyx_hypercall(HYPERCALL_KAFL_REQUEST_RELOAD, 0);")
	if keep == -1 || reload == -1 || keep > reload {
		t.Fatalf("keep-state branch must return before default reload, keep=%d reload=%d", keep, reload)
	}

	mainData, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	mainSrc := string(mainData)
	for _, want := range []string{
		"nyxExecKeepState",
		"meta.Flags |= nyxExecKeepState",
		"keep-state",
		"standalone-keep-state",
	} {
		if !strings.Contains(mainSrc, want) {
			t.Fatalf("runner keep-state protocol missing %q", want)
		}
	}
	if strings.Contains(mainSrc, "execProgramIsMultiCallWindowsVNet") &&
		strings.Contains(mainSrc, "meta.Flags |= nyxExecKeepState") {
		// The protocol is selected by runner mode, not by syscall names.
		metaSet := strings.Index(mainSrc, "meta.Flags |= nyxExecKeepState")
		vnetCheck := strings.LastIndex(mainSrc[:metaSet], "execProgramIsMultiCallWindowsVNet")
		if vnetCheck != -1 && metaSet-vnetCheck < 400 {
			t.Fatalf("keep-state protocol should not be selected by nearby vnet syscall-name checks")
		}
	}

	if strings.Contains(src, "nyx result skipped request reload request=%lld calls=%u") {
		t.Fatal("executor must use explicit keep-state/reload logs, not unconditional skip logs")
	}
	unconditionalReloads := strings.Count(src, "nyx_hypercall(HYPERCALL_KAFL_REQUEST_RELOAD, 0);")
	if unconditionalReloads != 1 {
		t.Fatalf("expected exactly one default exec reload path, got %d reload calls", unconditionalReloads)
	}

	if strings.Contains(src, "runner restarts between vnet requests") {
		t.Fatal("executor tests must not encode a vnet-specific reload policy")
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

	genericStart := strings.LastIndex(src, "auto result = finish_output(")
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
	for _, needle := range []string{
		"is_windows_nyx_vnet_call(call)",
		"execute_call_vnet_no_acquire",
		"execute_call_vnet_done",
	} {
		if !strings.Contains(body, needle) {
			t.Fatalf("execute_call should run Windows vnet helpers outside Nyx ACQUIRE, missing %q", needle)
		}
	}
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

func TestWindowsExecutorLogsScheduleHandoff(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	body := extractFunctionBody(t, string(data), "thread_t* schedule_call")
	wantOrder := []string{
		"schedule_pre_idle_wait",
		"event_timedwait(&th->idle, idle_timeout_ms)",
		"schedule_post_idle_wait",
		"schedule_pre_done_reset",
		"event_reset(&th->done);",
		"schedule_post_done_reset",
		"th->handoff_seq++;",
		"schedule_handoff_seq",
		"schedule_pre_idle_reset",
		"event_reset(&th->idle);",
		"schedule_post_idle_reset",
		"schedule_pre_ready_set",
		"event_set(&th->ready);",
		"schedule_post_ready_set",
		"running++;",
		"schedule_running_incremented",
	}
	last := -1
	for _, needle := range wantOrder {
		idx := strings.Index(body, needle)
		if idx == -1 {
			t.Fatalf("schedule_call missing handoff breadcrumb %q", needle)
		}
		if idx <= last {
			t.Fatalf("schedule_call breadcrumb %q is out of order", needle)
		}
		last = idx
	}
	if !strings.Contains(body, "event_isset(&th->ready)") ||
		!strings.Contains(body, "event_isset(&th->done)") ||
		!strings.Contains(body, "th->executing") ||
		!strings.Contains(body, "running") ||
		!strings.Contains(body, "th->worker_tid") ||
		!strings.Contains(body, "th->worker_wait_seq") ||
		!strings.Contains(body, "event_isset(&th->idle)") {
		t.Fatal("schedule_call handoff logs should include ready/done/idle/executing/running state")
	}
}

func TestWindowsExecutorLogsWorkerHandoffWaits(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	src := string(data)
	threadCreate := extractFunctionBody(t, src, "void thread_create")
	for _, needle := range []string{
		"th->handoff_seq = 0;",
		"th->worker_tid = 0;",
		"th->worker_wait_seq = 0;",
		"th->call_index = -1;",
		"th->call_num = -1;",
		"event_init(&th->idle);",
	} {
		if !strings.Contains(threadCreate, needle) {
			t.Fatalf("thread_create missing initialization %q", needle)
		}
	}
	worker := extractFunctionBody(t, src, "void* worker_thread")
	for _, needle := range []string{
		"th->worker_tid = GetCurrentThreadId();",
		"worker_thread_started",
		"th->worker_wait_seq = th->handoff_seq;",
		"event_set(&th->idle);",
		"worker_wait_ready_begin",
		"event_wait(&th->ready);",
		"worker_ready_seen",
	} {
		if !strings.Contains(worker, needle) {
			t.Fatalf("worker_thread missing handoff wait breadcrumb %q", needle)
		}
	}
	if strings.Index(worker, "worker_wait_ready_begin") > strings.Index(worker, "event_wait(&th->ready);") {
		t.Fatal("worker should log wait begin before blocking on ready")
	}
	if strings.Index(worker, "event_set(&th->idle);") > strings.Index(worker, "event_wait(&th->ready);") {
		t.Fatal("worker should mark itself idle before blocking on ready")
	}
	if strings.Index(worker, "event_wait(&th->ready);") > strings.Index(worker, "worker_ready_seen") {
		t.Fatal("worker should log ready seen after the ready wait returns")
	}
	execOne := extractFunctionBody(t, src, "void execute_one()")
	for _, needle := range []string{
		"wait_call_done_begin",
		"event_timedwait(&th->done, timeout_ms)",
		"wait_call_done_result",
	} {
		if !strings.Contains(execOne, needle) {
			t.Fatalf("execute_one missing immediate wait breadcrumb %q", needle)
		}
	}
	if strings.Index(execOne, "wait_call_done_begin") >
		strings.Index(execOne, "event_timedwait(&th->done, timeout_ms)") {
		t.Fatal("execute_one should log before waiting for a scheduled call")
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

func TestWindowsNetInjectionStubsFailFast(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "common_windows.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read common_windows.h: %v", err)
	}
	src := string(data)
	for _, needle := range []string{
		"#include <winioctl.h>",
		"initialize_windows_net_injection",
		"SYZ_WINDOWS_NET_INJECTION_DEVICE",
		"SYZ_WINDOWS_NET_INJECTION_BACKGROUND_READER",
		"SYZ_WINDOWS_NET_INJECTION_REFRESH_UNICAST",
		"SYZ_WINDOWS_NET_INJECTION_STATIC_NEIGHBOR",
		"SYZ_WINDOWS_NET_INJECTION_FIREWALL_ALLOW",
		"SYZ_WINDOWS_NET_INJECTION_PRE_SNAPSHOT_SETTLE_MS",
		"SYZ_WINDOWS_NET_INJECTION_POST_WRITE_SETTLE_MS",
		"SYZ_WINDOWS_NET_INJECTION_READ_ATTEMPTS",
		"GetEnvironmentVariableA(SYZ_WINDOWS_NET_INJECTION_DEVICE_ENV",
		"GetEnvironmentVariableA(SYZ_WINDOWS_NET_INJECTION_BACKGROUND_READER_ENV",
		"GetEnvironmentVariableA(SYZ_WINDOWS_NET_INJECTION_REFRESH_UNICAST_ENV",
		"GetEnvironmentVariableA(SYZ_WINDOWS_NET_INJECTION_STATIC_NEIGHBOR_ENV",
		"GetEnvironmentVariableA(SYZ_WINDOWS_NET_INJECTION_FIREWALL_ALLOW_ENV",
		"windows_net_injection_env_dword(SYZ_WINDOWS_NET_INJECTION_PRE_SNAPSHOT_SETTLE_MS_ENV, 30000)",
		"windows_net_injection_env_dword(SYZ_WINDOWS_NET_INJECTION_POST_WRITE_SETTLE_MS_ENV, 30000)",
		"windows_net_injection_env_dword(SYZ_WINDOWS_NET_INJECTION_READ_ATTEMPTS_ENV",
		"CreateFileA(device_path, GENERIC_READ | GENERIC_WRITE",
		"FILE_FLAG_OVERLAPPED",
		"SYZ_WINDOWS_TAP_IOCTL_SET_MEDIA_STATUS",
		"DeviceIoControl(windows_net_injection, SYZ_WINDOWS_TAP_IOCTL_SET_MEDIA_STATUS",
		"set windows TAP media status connected",
		"failed to set windows TAP media status",
		"SYZ_WINDOWS_NET_INJECTION_IO_TIMEOUT_MS",
		"SYZ_WINDOWS_NET_INJECTION_READ_POLL_MS",
		"SYZ_WINDOWS_NET_INJECTION_BACKGROUND_READ_POLL_MS",
		"SYZ_WINDOWS_NET_INJECTION_MAX_FRAME_SIZE",
		"SYZ_WINDOWS_NET_INJECTION_MAX_READ_ATTEMPTS",
		"SYZ_WINDOWS_NET_INJECTION_READ_TIMEOUT",
		"#include <winsock2.h>",
		"#include <ws2tcpip.h>",
		"#include <netioapi.h>",
		"static char windows_net_injection_write_buffer[4096]",
		"static volatile LONG windows_net_injection_background_reader_enabled",
		"static volatile LONG windows_net_injection_refresh_unicast_enabled",
		"static volatile LONG windows_net_injection_static_neighbor_enabled",
		"static volatile LONG windows_net_injection_cached_tcp_valid",
		"static DWORD windows_net_injection_target_ifindex_cache",
		"static char windows_net_injection_target_adapter_name[64]",
		"windows_net_injection_parse_device_adapter_name(device_path, windows_net_injection_target_adapter_name",
		"windows_net_injection_target_ifindex",
		"windows_net_injection_adapter_name_matches",
		"_stricmp(adapter->AdapterName, windows_net_injection_target_adapter_name)",
		"windows_net_injection_log_neighbor_ipv4_table_for_index",
		"GetIpNetTable2(AF_INET",
		"CreateIpNetEntry2(&row)",
		"SetIpNetEntry2(&row)",
		"row.State = NlnsPermanent",
		"windows net injection static neighbor enabled",
		"windows net injection static-neighbor",
		"windows net state %s neighbor ifindex=%lu addr=172.20.0.187",
		"static long windows_net_injection_write",
		"static DWORD WINAPI windows_net_injection_background_reader",
		"static bool windows_net_injection_parse_tcp_frame",
		"memcpy(windows_net_injection_write_buffer, data, length)",
		"WriteFile(windows_net_injection, windows_net_injection_write_buffer",
		"WriteFile(windows_net_injection",
		"ReadFile(windows_net_injection",
		"WaitForSingleObject(ov.hEvent, SYZ_WINDOWS_NET_INJECTION_IO_TIMEOUT_MS)",
		"SYZ_WINDOWS_NET_INJECTION_READ_ATTEMPTS",
		"CancelIoEx(windows_net_injection, &ov)",
		"GetOverlappedResult(windows_net_injection, &ov, &written, FALSE)",
		"GetOverlappedResult(windows_net_injection, &ov, &read, FALSE)",
		"windows net injection write begin handle=0x%p event=0x%p length=%u buffer=0x%p",
		"windows net injection write issued ok=%u err=%u written=%u",
		"windows net injection write overlapped result ok=%u err=%u written=%u",
		"windows net injection post-write settle begin ms=%lu",
		"windows net injection post-write settle end ms=%lu",
		"windows_net_injection_log_frame_summary",
		"windows net injection %s eth dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x type=0x%04x length=%zu",
		"windows net injection %s ipv4 src=%u.%u.%u.%u dst=%u.%u.%u.%u proto=%u total_len=%u ihl=%u csum=0x%04x verify=0x%04x",
		"windows net injection %s tcp src_port=%u dst_port=%u flags=0x%02x seq=0x%x ack=0x%x data_off=%u csum=0x%04x verify=0x%04x",
		"windows_net_checksum_finish",
		"windows net injection wrote frame length=%u",
		"windows net injection extracted tcp seq=0x%x ack=0x%x",
		"windows net injection extracted cached tcp seq=0x%x ack=0x%x",
		"windows net injection extract complete source=%s",
		"windows net injection cached tcp frame seq=0x%x ack=0x%x length=%ld",
		"windows net injection tcp cache miss",
		"windows net injection read begin handle=0x%p event=0x%p length=%u buffer=0x%p",
		"windows net injection read issued ok=%u err=%u read=%u",
		"windows net injection read overlapped result ok=%u err=%u read=%u",
		"windows net injection read cancel issued ok=%u err=%u",
		"windows net injection read post-cancel result ok=%u err=%u read=%u",
		"windows net injection write timed out",
		"windows net injection read timed out",
		"windows net injection read found no tcp response after attempts=%d",
		"windows net injection %s non-tcp ipv4 frame",
		"windows_net_load_be16",
		"windows_net_load_be32",
		"SYZ_WINDOWS_NET_INJECTION_ETH_P_IP",
		"SYZ_WINDOWS_NET_INJECTION_IPPROTO_TCP",
		"SYZ_WINDOWS_NET_INJECTION_LOCAL_IPV4",
		"SYZ_WINDOWS_NET_INJECTION_PEER_IPV4",
		"SYZ_WINDOWS_NET_INJECTION_LOCAL_IPV4_MASK",
		"SYZ_WINDOWS_NET_INJECTION_LOCAL_TCP_PORT",
		"SYZ_WINDOWS_NET_INJECTION_PEER_TCP_PORT",
		"SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_SYN",
		"SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_ACK",
		"windows_net_injection_try_configure_local_ipv4",
		"windows_net_injection_local_ipv4_present",
		"windows_net_injection_log_ip_interface_for_index",
		"windows_net_injection_log_unicast_ipv4_table",
		"windows_net_injection_log_adapter_addresses",
		"windows_net_injection_log_unicast_ipv4_entry",
		"windows_net_injection_refresh_unicast_ipv4_entry",
		"ConvertInterfaceIndexToLuid((NET_IFINDEX)ifindex, &luid)",
		"GetIpInterfaceEntry(&row)",
		"GetUnicastIpAddressTable(AF_INET, &table)",
		"GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX",
		"GetUnicastIpAddressEntry(&row)",
		"InitializeUnicastIpAddressEntry(&row)",
		"SetUnicastIpAddressEntry(&row)",
		"windows_net_injection_log_ip_tcp_statistics",
		"GetTcpStatisticsEx(&tcp_stats, AF_INET)",
		"GetIpStatisticsEx(&ip_stats, AF_INET)",
		"windows net state %s tcp-stats active=%lu passive=%lu attemptfails=%lu estabresets=%lu insegs=%lu outsegs=%lu retrans=%lu inerrs=%lu outrsts=%lu numconns=%lu",
		"windows net state %s ip-stats inrecv=%lu hdrerrs=%lu addrerrs=%lu unknownproto=%lu discarded=%lu delivered=%lu outreq=%lu routingdisc=%lu outdisc=%lu outerrs=%lu noreasm=%lu",
		"CoCreateInstance(__uuidof(NetFwPolicy2)",
		"CoCreateInstance(__uuidof(NetFwRule)",
		"windows_net_injection_allow_firewall_tcp_inbound",
		"windows net injection firewall allow enabled",
		"windows net injection firewall-allow rule name=",
		"scope=local-port-only",
		"rule->put_Protocol(NET_FW_IP_PROTOCOL_TCP)",
		"rule->put_LocalPorts(ports)",
		"rule->put_Direction(NET_FW_RULE_DIR_IN)",
		"rule->put_Action(NET_FW_ACTION_ALLOW)",
		"rules->Add(rule)",
		"windows_net_injection_log_peer_route",
		"windows_net_injection_ipv4_prefix_contains",
		"GetIpForwardTable2(AF_INET, &table)",
		"windows net state %s peer-route-row ifindex=%lu route-ifindex=%lu dest=%u.%u.%u.%u/%u peer-match=%u on-ifindex=%u default=%u",
		"FreeMibTable(table)",
		"AddIPAddress(local_addr, local_mask, ifindex",
		"windows net injection local ipv4 add ifindex=%lu status=%lu nte_context=%lu nte_instance=%lu",
		"windows net state %s adapter ifindex=%lu luid=0x%llx",
		"windows net state %s adapter-unicast ifindex=%lu addr=%u.%u.%u.%u prefix=%u",
		"windows net state %s unicast-entry ifindex=%lu addr=172.20.0.170",
		"windows net injection refresh unicast enabled",
		"windows net injection refresh-unicast %s ifindex=%lu set-status=%lu",
		"windows net injection pre-snapshot settle begin ms=%lu",
		"windows net injection pre-snapshot settle end ms=%lu",
		"windows_net_injection_log_guest_net_state(\"after-settle\")",
		"windows net state %s ip-interface ifindex=%lu connected=%u mtu=%lu metric=%lu",
		"windows net state %s unicast ifindex=%lu addr=%u.%u.%u.%u prefix=%u",
		"windows net state %s unicast 172.20.0.0/24 not found",
		"if (windows_net_injection_local_ipv4_present())",
		"windows net injection local ipv4 already present",
		"windows net injection local ipv4 target adapter not found name=%s",
		"GetIfTable(NULL, &if_table_size, TRUE)",
		"GetIpAddrTable(NULL, &ip_table_size, TRUE)",
		"windows_net_injection_log_extended_tcp_table",
		"GetExtendedTcpTable(NULL, &owner_table_size, TRUE, AF_INET",
		"TCP_TABLE_OWNER_PID_ALL",
		"PMIB_TCPTABLE_OWNER_PID",
		"MIB_TCPROW_OWNER_PID* row",
		"windows_net_injection_tcp_state_name",
		"MIB_TCP_STATE_SYN_RCVD",
		"windows net state %s extended-tcp local=%u.%u.%u.%u:%u remote=%u.%u.%u.%u:%u state=%lu(%s) pid=%lu target=%u listener=%u",
		"windows net state %s extended-tcp target 172.20.0.170:20000->172.20.0.187:40000 state=%lu(%s) pid=%lu",
		"windows net state %s extended-tcp target 172.20.0.170:20000->172.20.0.187:40000 not found",
		"GetTcpTable(NULL, &table_size, TRUE)",
		"windows_net_injection_log_guest_net_state",
		"windows net state %s tap ifindex=%lu oper=%lu admin=%lu in_octets=%lu in_ucast=%lu out_octets=%lu out_ucast=%lu",
		"windows net state %s ip ifindex=%lu addr=%u.%u.%u.%u mask=%u.%u.%u.%u type=0x%x",
		"windows net state %s ip 172.20.0.0/24 not found",
		"windows net state %s tcp local=%u.%u.%u.%u:%u remote=%u.%u.%u.%u:%u state=%lu pid=%lu",
		"windows net state %s tcp local-port=%u not found",
		"FILE_SHARE_READ | FILE_SHARE_WRITE",
		"#define windows_nyx_log(...) nyx_hprintf(__VA_ARGS__)",
		"windows net injection backend is not configured",
		"windows net injection device path is too long",
		"windows net injection background reader enabled",
		"windows net injection background reader started handle=0x%p",
		"failed to open windows net injection device",
		"windows_net_injection_try_configure_local_ipv4();",
		"static intptr_t SYSCALLAPI syz_emit_ethernet",
		"static intptr_t SYSCALLAPI syz_extract_tcp_res",
		"windows_net_injection == INVALID_HANDLE_VALUE",
		"initialize_windows_net_injection();",
	} {
		if !strings.Contains(src, needle) {
			t.Fatalf("common_windows.h is missing %q", needle)
		}
	}
	sandbox := extractFunctionBody(t, src, "static int do_sandbox_none(void)")
	initCall := strings.Index(sandbox, "initialize_windows_net_injection();")
	loopCall := strings.Index(sandbox, "loop();")
	if initCall == -1 || loopCall == -1 {
		t.Fatal("do_sandbox_none should initialize Windows net injection before entering loop")
	}
	if loopCall < initCall {
		t.Fatal("Windows net injection initialization appears after executor loop")
	}
	executorPath, err := os.ReadFile(filepath.Join("..", "..", "executor", "executor.cc"))
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	nyxLoop := extractFunctionBody(t, string(executorPath), "static int nyx_mode_loop")
	initCall = strings.Index(nyxLoop, "initialize_windows_net_injection();")
	payloadLoop := strings.Index(nyxLoop, "for (;;) {")
	if initCall == -1 {
		t.Fatal("Windows Nyx executor should initialize net injection before entering the payload loop")
	}
	if payloadLoop == -1 || payloadLoop < initCall {
		t.Fatal("Windows Nyx net injection initialization appears after the payload loop")
	}
	configure := extractFunctionBody(t, src, "static void windows_net_injection_try_configure_local_ipv4()")
	if !strings.Contains(configure, "DWORD ifindex = windows_net_injection_target_ifindex();") {
		t.Fatal("Windows net injection should configure IPv4 only on the adapter selected from the opened TAP device GUID")
	}
	if strings.Contains(configure, "GetIfTable(") ||
		strings.Contains(configure, "windows_net_injection_is_target_mac(row->bPhysAddr") {
		t.Fatal("Windows net injection must not configure every GetIfTable row that reuses the TAP MAC")
	}
	netState := extractFunctionBody(t, src, "static void windows_net_injection_log_guest_net_state")
	if !strings.Contains(netState, "DWORD target_ifindex = windows_net_injection_target_ifindex();") ||
		!strings.Contains(netState, "row->dwIndex != target_ifindex") {
		t.Fatal("Windows net state diagnostics should scope per-ifindex checks to the opened TAP adapter")
	}
	if strings.Contains(netState, "windows_net_injection_log_firewall_policy(label)") ||
		strings.Contains(netState, "windows_net_injection_log_firewall_policy2(label)") {
		t.Fatal("per-write Windows net state diagnostics should not run heavyweight firewall policy probes")
	}
	backendStart := strings.Index(src, "#if SYZ_NET_INJECTION && (SYZ_EXECUTOR || __NR_syz_emit_ethernet || __NR_syz_extract_tcp_res || SYZ_REPEAT)")
	if backendStart == -1 {
		t.Fatal("Windows net injection backend must be gated by SYZ_NET_INJECTION")
	}
	stubMarker := "\n#else\n\n#if SYZ_EXECUTOR || __NR_syz_emit_ethernet"
	stubStartRel := strings.Index(src[backendStart:], stubMarker)
	if stubStartRel == -1 {
		t.Fatal("Windows net injection backend should have non-injection fail-fast stubs")
	}
	backendSrc := src[backendStart : backendStart+stubStartRel]
	stubSrc := src[backendStart+stubStartRel:]
	emit := extractFunctionBody(t, backendSrc, "intptr_t SYSCALLAPI syz_emit_ethernet")
	extract := extractFunctionBody(t, backendSrc, "intptr_t SYSCALLAPI syz_extract_tcp_res")
	parseTCP := extractFunctionBody(t, src, "static bool windows_net_injection_parse_tcp_frame")
	if strings.Contains(src, "static long syz_emit_ethernet(volatile long") ||
		strings.Contains(src, "static long syz_extract_tcp_res(volatile long") {
		t.Fatal("Windows vnet pseudo-syscalls must use intptr_t syscall_t-compatible arguments")
	}
	if strings.Contains(emit+extract, "Sleep(") &&
		!strings.Contains(src, "SYZ_WINDOWS_NET_INJECTION_POST_WRITE_SETTLE_MS_ENV") {
		t.Fatal("Windows net injection stubs must not block waiting for backend traffic unless a gated diagnostic settle is enabled")
	}
	if !strings.Contains(emit, "a0 <= 0 || a0 > SYZ_WINDOWS_NET_INJECTION_MAX_FRAME_SIZE") {
		t.Fatal("syz_emit_ethernet should reject invalid or oversized frames")
	}
	if strings.Contains(emit, "debug_dump_data(") {
		t.Fatal("syz_emit_ethernet should not dump the guest frame before writing it to TAP")
	}
	if !strings.Contains(emit, "return windows_net_injection_write((const void*)(uintptr_t)a1, (DWORD)a0)") {
		t.Fatal("syz_emit_ethernet should write frames through the configured backend")
	}
	stubEmit := extractFunctionBody(t, stubSrc, "intptr_t SYSCALLAPI syz_emit_ethernet")
	stubExtract := extractFunctionBody(t, stubSrc, "intptr_t SYSCALLAPI syz_extract_tcp_res")
	if strings.Contains(stubEmit+stubExtract, "windows_net_injection_write") ||
		strings.Contains(stubEmit+stubExtract, "windows_net_injection_read") ||
		strings.Contains(stubEmit+stubExtract, "Sleep(") {
		t.Fatal("non-injection Windows vnet stubs must fail fast without backend I/O")
	}
	if !strings.Contains(stubEmit, "return -1;") {
		t.Fatal("non-injection syz_emit_ethernet stub should fail fast")
	}
	if !strings.Contains(stubExtract, "NONFAILING(memset((void*)(uintptr_t)a0, 0, sizeof(windows_tcp_resources)))") ||
		!strings.Contains(stubExtract, "return -1;") {
		t.Fatal("non-injection syz_extract_tcp_res stub should clear output resources and fail fast")
	}
	if !strings.Contains(extract, "windows_net_injection_read(data, sizeof(data))") {
		t.Fatal("syz_extract_tcp_res should read a bounded frame from the configured backend")
	}
	if !strings.Contains(extract, "rv == SYZ_WINDOWS_NET_INJECTION_READ_TIMEOUT") {
		t.Fatal("syz_extract_tcp_res should continue bounded reads after an empty TAP poll")
	}
	if !strings.Contains(extract, "InterlockedCompareExchange(&windows_net_injection_cached_tcp_valid, 0, 1)") {
		t.Fatal("syz_extract_tcp_res should consume cached TCP results without waiting when the background reader is enabled")
	}
	if strings.Contains(extract, `windows_net_injection_log_guest_net_state("after-extract-read")`) ||
		strings.Contains(extract, `windows_net_injection_log_guest_net_state("after-extract-cached")`) {
		t.Fatal("syz_extract_tcp_res should not run full guest net-state diagnostics after successful TCP extraction")
	}
	for _, needle := range []string{
		"read_attempts = SYZ_WINDOWS_NET_INJECTION_READ_ATTEMPTS",
		"attempt < read_attempts",
		"SYZ_WINDOWS_NET_INJECTION_MAX_READ_ATTEMPTS",
	} {
		if !strings.Contains(extract, needle) {
			t.Fatalf("syz_extract_tcp_res should filter non-target frames across bounded read attempts, missing %q", needle)
		}
	}
	for _, needle := range []string{
		`windows_nyx_log("opened windows net injection device %s\n"`,
		`windows_nyx_log("set windows TAP media status connected\n")`,
		`windows_net_injection_log_guest_net_state("after-open")`,
		`windows_net_injection_log_guest_net_state("before-write")`,
		`windows_nyx_log("windows net injection write begin handle=0x%p event=0x%p length=%u buffer=0x%p\n"`,
		`windows_nyx_log("windows net injection write issued ok=%u err=%u written=%u\n"`,
		`windows_net_injection_log_frame_summary("tx", windows_net_injection_write_buffer, length)`,
		`windows_nyx_log("windows net injection wrote frame length=%u\n"`,
		`windows_net_injection_log_guest_net_state("after-write")`,
		`windows_net_injection_log_guest_net_state("before-extract")`,
		`windows_nyx_log("windows net injection read begin handle=0x%p event=0x%p length=%u buffer=0x%p\n"`,
		`windows_nyx_log("windows net injection read issued ok=%u err=%u read=%u\n"`,
		`windows_nyx_log("windows net injection read cancel issued ok=%u err=%u\n"`,
		`windows_nyx_log("windows net injection read post-cancel result ok=%u err=%u read=%u\n"`,
		`windows_nyx_log("windows net injection read frame length=%u\n"`,
		`windows_net_injection_log_frame_summary("rx", (const char*)data, read)`,
		`windows_nyx_log("windows net injection extracted tcp seq=0x%x ack=0x%x\n"`,
		`windows_nyx_log("windows net injection extracted cached tcp seq=0x%x ack=0x%x\n"`,
		`windows_net_injection_log_extract_complete("read")`,
		`windows_net_injection_log_extract_complete("cached")`,
		`windows_nyx_log("windows net injection read timed out\n")`,
		`windows_nyx_log("windows net injection read found no tcp response after attempts=%d\n"`,
	} {
		if !strings.Contains(src, needle) {
			t.Fatalf("Windows net injection should mirror proof-critical status to Nyx hprintf: missing %q", needle)
		}
	}
	for _, needle := range []string{
		"eth_type != SYZ_WINDOWS_NET_INJECTION_ETH_P_IP",
		"version != 4",
		"ip[9] != SYZ_WINDOWS_NET_INJECTION_IPPROTO_TCP",
		"src_ip != SYZ_WINDOWS_NET_INJECTION_LOCAL_IPV4",
		"dst_ip != SYZ_WINDOWS_NET_INJECTION_PEER_IPV4",
		"src_port != SYZ_WINDOWS_NET_INJECTION_LOCAL_TCP_PORT",
		"dst_port != SYZ_WINDOWS_NET_INJECTION_PEER_TCP_PORT",
		"SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_SYN | SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_ACK",
		"windows net injection %s non-target tcp",
		"windows_net_load_be32(tcp + 4)",
		"windows_net_load_be32(tcp + 8)",
	} {
		if !strings.Contains(parseTCP, needle) {
			t.Fatalf("windows_net_injection_parse_tcp_frame is missing %q", needle)
		}
	}
	for _, needle := range []string{
		"((windows_tcp_resources*)(uintptr_t)a0)->seq = windows_net_host_to_be32(seq)",
		"((windows_tcp_resources*)(uintptr_t)a0)->ack = windows_net_host_to_be32(ack)",
	} {
		if !strings.Contains(extract, needle) {
			t.Fatalf("syz_extract_tcp_res is missing %q", needle)
		}
	}
	zeroOut := strings.Index(extract, "memset((void*)(uintptr_t)a0, 0, sizeof(windows_tcp_resources))")
	missingBackend := strings.Index(extract, "windows_net_injection == INVALID_HANDLE_VALUE")
	if zeroOut == -1 {
		t.Fatal("syz_extract_tcp_res should clear output resources before returning")
	}
	if missingBackend == -1 {
		t.Fatal("syz_extract_tcp_res should check for a configured backend")
	}
	if missingBackend < zeroOut {
		t.Fatal("syz_extract_tcp_res should clear output resources before the missing-backend return")
	}
}

func TestWindowsNyxExecutorBuildEnablesNetInjection(t *testing.T) {
	path := filepath.Join("..", "build-nyx-windows-executor.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read build-nyx-windows-executor.sh: %v", err)
	}
	for _, needle := range []string{
		"-DSYZ_NET_INJECTION=1",
		"-liphlpapi",
		"-ladvapi32",
		"-lole32",
		"-loleaut32",
		"-luuid",
	} {
		if !strings.Contains(string(data), needle) {
			t.Fatalf("Windows Nyx executor build should include %q for vnet pseudo-syscalls", needle)
		}
	}
}

func TestWindowsSocketStateWrappersLogWinsockErrors(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	src := string(data)
	for _, needle := range []string{
		"static void windows_log_sockaddr_state",
		"static void windows_log_getsockname_state",
		"static int windows_wsa_error_to_errno",
		"WSAEADDRNOTAVAIL",
		"return EADDRNOTAVAIL;",
		"WSASetLastError(0)",
		"WSAGetLastError()",
		"getsockname(s, (struct sockaddr*)&storage, &len)",
		"windows socket state %s socket=0x%llx family=AF_INET addr=%u.%u.%u.%u port=%u namelen=%d",
		"windows_log_sockaddr_state(\"bind input\"",
		"windows socket state bind failed socket=0x%llx wsa=%d errno=%d",
		"windows socket state bind ok socket=0x%llx",
		"windows_log_getsockname_state(\"listen before\"",
		"windows socket state listen failed socket=0x%llx backlog=%lld wsa=%d errno=%d",
		"windows socket state listen ok socket=0x%llx backlog=%lld",
	} {
		if !strings.Contains(src, needle) {
			t.Fatalf("executor.cc is missing Windows socket diagnostic %q", needle)
		}
	}
	bindBody := extractFunctionBody(t, src, "static intptr_t SYSCALLAPI windows_bind_state")
	if strings.Index(bindBody, "windows_log_sockaddr_state(\"bind input\"") >
		strings.Index(bindBody, "bind(socket, name, (int)namelen)") {
		t.Fatal("windows_bind_state should log the sockaddr before bind")
	}
	listenBody := extractFunctionBody(t, src, "static intptr_t SYSCALLAPI windows_listen_state")
	if strings.Index(listenBody, "windows_log_getsockname_state(\"listen before\"") >
		strings.Index(listenBody, "listen(socket, (int)backlog)") {
		t.Fatal("windows_listen_state should log getsockname before listen")
	}
}

package main

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

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

func loadWindowsNyxConfig(t *testing.T, path string) struct {
	EnabledSyscalls  []string `json:"enable_syscalls"`
	NoMutateSyscalls []string `json:"no_mutate_syscalls"`
	Experimental     struct {
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
		Experimental     struct {
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
	cfg := loadWindowsNyxConfig(t, "windows-nyx-none.cfg")
	if len(cfg.EnabledSyscalls) == 0 {
		t.Fatalf("windows nyx config %s has no enable_syscalls", "windows-nyx-none.cfg")
	}
	return cfg.EnabledSyscalls
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
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, name := range loadWindowsNyxConfigSyscalls(t) {
		if _, ok := table[name]; !ok {
			t.Fatalf("windows nyx config syscall %q missing from sparse Nyx table", name)
		}
		if target.SyscallMap[name] == nil {
			t.Fatalf("windows nyx config syscall %q missing from windows/amd64 target", name)
		}
	}
}

func TestWindowsAutomaticHelpersPresentInEnabledSet(t *testing.T) {
	requireWindowsHelpersEnabled(t, "windows-nyx-none.cfg",
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
	assertResource("socket$inet_tcp", -1, "SOCKET_TCP")
	assertResource("socket$inet_udp", -1, "SOCKET_UDP")
	assertResource("socket$accept_tcp", -1, "SOCKET_ACCEPT")
	assertResource("socket$listener_tcp", -1, "SOCKET_LISTENER")
	assertResource("socket$connected_tcp", -1, "SOCKET_CONNECTED")
	assertResource("listen$inet_tcp", 0, "SOCKET_LISTENER")
	assertResource("accept$inet_tcp", 0, "SOCKET_LISTENER")
	assertResource("accept$inet_tcp", -1, "SOCKET_ACCEPT")
	assertResource("connect$inet_tcp", 0, "SOCKET_CONNECTED")
	assertResource("send$inet_tcp", 0, "SOCKET_CONNECTED")
	assertResource("recv$inet_tcp", 0, "SOCKET_CONNECTED")
	assertResource("AcceptEx$inet_tcp", 0, "SOCKET_LISTENER")
	assertResource("AcceptEx$inet_tcp", 1, "SOCKET_ACCEPT")
	assertResource("WSARecvEx$inet_accept", 0, "SOCKET_ACCEPT")
	assertResource("TransmitFile$inet_accept", 0, "SOCKET_ACCEPT")
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
	assertResource("NtFsControlFile", 0, "FILE_HANDLE")
	assertResource("TransmitFile$inet_accept", 1, "FILE_HANDLE")
}

func TestWindowsNyxNetworkConfigSyscallsPresentInSparseTable(t *testing.T) {
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-network-none.cfg")
	if len(cfg.EnabledSyscalls) == 0 {
		t.Fatalf("windows nyx network config has no enable_syscalls")
	}
	for _, name := range cfg.EnabledSyscalls {
		if _, ok := table[name]; !ok {
			t.Fatalf("windows nyx network config syscall %q missing from sparse Nyx table", name)
		}
		if target.SyscallMap[name] == nil {
			t.Fatalf("windows nyx network config syscall %q missing from windows/amd64 target", name)
		}
	}
	requireWindowsHelpersEnabled(t, "windows-nyx-network-none.cfg",
		[]string{"WSAStartup", "WSACleanup", "socket$inet_udp", "socket$accept_tcp", "socket$listener_tcp", "socket$connected_tcp", "closesocket$any"})
}

func TestWindowsNyxAfdConfigSyscallsPresentInSparseTable(t *testing.T) {
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-none.cfg")
	if len(cfg.EnabledSyscalls) == 0 {
		t.Fatalf("windows nyx afd config has no enable_syscalls")
	}
	for _, name := range cfg.EnabledSyscalls {
		if _, ok := table[name]; !ok {
			t.Fatalf("windows nyx afd config syscall %q missing from sparse Nyx table", name)
		}
		if target.SyscallMap[name] == nil {
			t.Fatalf("windows nyx afd config syscall %q missing from windows/amd64 target", name)
		}
	}
	requireWindowsHelpersEnabled(t, "windows-nyx-afd-none.cfg",
		[]string{"WSAStartup", "WSACleanup", "socket$accept_tcp", "socket$listener_tcp", "socket$connected_tcp", "closesocket$any"})
	enabledCalls := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		enabledCalls[target.SyscallMap[name]] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabledCalls)
	for _, name := range []string{"bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "connect$inet_tcp", "CreateFileA"} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("windows nyx afd config did not transitively enable %q", name)
		}
	}
}

func TestWindowsNyxAfdSessionConfigSyscallsPresentInSparseTable(t *testing.T) {
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-session-none.cfg")
	if len(cfg.EnabledSyscalls) == 0 {
		t.Fatalf("windows nyx afd-session config has no enable_syscalls")
	}
	for _, name := range cfg.EnabledSyscalls {
		if _, ok := table[name]; !ok {
			t.Fatalf("windows nyx afd-session config syscall %q missing from sparse Nyx table", name)
		}
		if target.SyscallMap[name] == nil {
			t.Fatalf("windows nyx afd-session config syscall %q missing from windows/amd64 target", name)
		}
	}
	requireWindowsHelpersEnabled(t, "windows-nyx-afd-session-none.cfg",
		[]string{"WSAStartup", "WSACleanup", "socket$accept_tcp", "socket$listener_tcp", "socket$connected_tcp", "closesocket$any"})
	enabledCalls := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		enabledCalls[target.SyscallMap[name]] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabledCalls)
	for _, name := range []string{"bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "connect$inet_tcp"} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("windows nyx afd-session config did not transitively enable %q", name)
		}
	}
}

func TestWindowsNyxAfdAcceptRaceConfigUsesFocusedSeedPrefixes(t *testing.T) {
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-accept-race-none.cfg")
	if cfg.Experimental.SeedPrefix != "nyx_afd_accept_" {
		t.Fatalf("accept-race seed_prefix=%q, want %q", cfg.Experimental.SeedPrefix, "nyx_afd_accept_")
	}
	if cfg.Experimental.BorrowingSeedPrefix != "nyx_afd_accept_" {
		t.Fatalf("accept-race borrowing_seed_prefix=%q, want %q", cfg.Experimental.BorrowingSeedPrefix, "nyx_afd_accept_")
	}
	if cfg.Experimental.WindowsTargetProfile != "afd_accept_race" {
		t.Fatalf("accept-race windows_target_profile=%q, want %q", cfg.Experimental.WindowsTargetProfile, "afd_accept_race")
	}
}

func TestWindowsNyxAfdTransmitConfigUsesFocusedSeedPrefixes(t *testing.T) {
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-transmit-none.cfg")
	if cfg.Experimental.SeedPrefix != "nyx_afd_accept_transmit" {
		t.Fatalf("transmit seed_prefix=%q, want %q", cfg.Experimental.SeedPrefix, "nyx_afd_accept_transmit")
	}
	if cfg.Experimental.BorrowingSeedPrefix != "nyx_afd_accept_transmit" {
		t.Fatalf("transmit borrowing_seed_prefix=%q, want %q", cfg.Experimental.BorrowingSeedPrefix, "nyx_afd_accept_transmit")
	}
	if cfg.Experimental.WindowsTargetProfile != "afd_transmit" {
		t.Fatalf("transmit windows_target_profile=%q, want %q", cfg.Experimental.WindowsTargetProfile, "afd_transmit")
	}
	want := map[string]bool{
		"TransmitFile$inet_accept":   true,
		"WSARecvEx$inet_accept":      true,
		"getsockopt$int_accept":      true,
		"ioctlsocket$fionbio_accept": true,
		"send$inet_accept":           true,
		"recv$inet_accept":           true,
	}
	for _, call := range cfg.EnabledSyscalls {
		delete(want, call)
	}
	if len(want) != 0 {
		t.Fatalf("transmit config missing enabled syscalls: %+v", want)
	}
}

func TestWindowsNyxFsctlConfigSyscallsPresentInSparseTable(t *testing.T) {
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-fsctl-none.cfg")
	if len(cfg.EnabledSyscalls) == 0 {
		t.Fatalf("windows nyx fsctl config has no enable_syscalls")
	}
	for _, name := range cfg.EnabledSyscalls {
		if _, ok := table[name]; !ok {
			t.Fatalf("windows nyx fsctl config syscall %q missing from sparse Nyx table", name)
		}
		if target.SyscallMap[name] == nil {
			t.Fatalf("windows nyx fsctl config syscall %q missing from windows/amd64 target", name)
		}
	}
	requireWindowsHelpersEnabled(t, "windows-nyx-fsctl-none.cfg",
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
			t.Fatalf("windows nyx fsctl config did not transitively enable %q", name)
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

func TestStandaloneNtFsControlFileProgramUsesHandleCreator(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, name := range []string{"NtFsControlFile", "NtReadFile", "NtWriteFile"} {
		meta := target.SyscallMap[name]
		if meta == nil {
			t.Fatalf("%s missing from windows/amd64 target", name)
		}
		p, bootstrap, err := standaloneProgram(target, meta, 1)
		if err != nil {
			t.Fatalf("standaloneProgram(%s): %v", name, err)
		}
		if !bootstrap {
			t.Fatalf("%s should use deterministic bootstrap program", name)
		}
		serialized := string(p.Serialize())
		if !strings.Contains(serialized, name+"(") {
			t.Fatalf("generated program does not contain %s:\n%s", name, serialized)
		}
		if !strings.Contains(serialized, "CreateFileA(") {
			t.Fatalf("generated program does not contain CreateFileA handle creator for %s:\n%s", name, serialized)
		}
	}
}

func TestStandaloneWinsockProgramsUseSocketBootstrap(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, name := range []string{
		"socket$inet_tcp",
		"socket$listener_tcp",
		"socket$connected_tcp",
		"socket$inet_udp",
		"socket$accept_tcp",
		"bind$inet_tcp",
		"bind$inet_udp",
		"listen$inet_tcp",
		"connect$inet_tcp",
		"connect$inet_udp",
		"accept$inet_tcp",
		"send$inet_tcp",
		"send$inet_udp",
		"send$inet_accept",
		"recv$inet_tcp",
		"recv$inet_udp",
		"recv$inet_accept",
		"ioctlsocket$fionbio_tcp",
		"ioctlsocket$fionbio_udp",
		"ioctlsocket$fionbio_accept",
		"AcceptEx$inet_tcp",
		"WSARecvEx$inet_accept",
		"TransmitFile$inet_accept",
		"setsockopt$int_tcp",
		"setsockopt$int_udp",
		"setsockopt$int_accept",
		"getsockopt$int_tcp",
		"getsockopt$int_udp",
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
		if !bootstrap {
			t.Fatalf("%s should use deterministic bootstrap program", name)
		}
		serialized := string(p.Serialize())
		if !strings.Contains(serialized, "WSAStartup(") {
			t.Fatalf("generated program does not contain WSAStartup for %s:\n%s", name, serialized)
		}
		hasTypedSocketCreator := strings.Contains(serialized, "socket$inet_tcp(") ||
			strings.Contains(serialized, "socket$listener_tcp(") ||
			strings.Contains(serialized, "socket$connected_tcp(") ||
			strings.Contains(serialized, "socket$inet_udp(") ||
			strings.Contains(serialized, "socket$accept_tcp(")
		if !hasTypedSocketCreator {
			t.Fatalf("generated program does not contain a typed socket creator for %s:\n%s", name, serialized)
		}
		if !strings.Contains(serialized, "closesocket$any(") {
			t.Fatalf("generated program does not contain closesocket$any for %s:\n%s", name, serialized)
		}
		if (name == "accept$inet_tcp" || name == "recv$inet_accept" || name == "recv$inet_tcp" ||
			name == "recv$inet_udp" || name == "ioctlsocket$fionbio_tcp" ||
			name == "ioctlsocket$fionbio_udp" || name == "ioctlsocket$fionbio_accept") &&
			!strings.Contains(serialized, "ioctlsocket$fionbio_") {
			t.Fatalf("generated program does not contain nonblocking ioctlsocket variant for %s:\n%s", name, serialized)
		}
		if (name == "connect$inet_tcp" || name == "send$inet_tcp" || name == "send$inet_accept" ||
			name == "recv$inet_tcp" || name == "recv$inet_accept" || name == "accept$inet_tcp") &&
			(!strings.Contains(serialized, "socket$listener_tcp(") ||
				!strings.Contains(serialized, "socket$connected_tcp(")) {
			t.Fatalf("generated program does not contain both listener/connected sockets for %s:\n%s", name, serialized)
		}
		if (name == "connect$inet_tcp" || name == "send$inet_tcp" || name == "send$inet_accept" ||
			name == "recv$inet_tcp" || name == "recv$inet_accept" || name == "accept$inet_tcp") &&
			!strings.Contains(serialized, "bind$inet_tcp(") {
			t.Fatalf("generated program does not contain bind$inet_tcp for %s:\n%s", name, serialized)
		}
		if (name == "connect$inet_tcp" || name == "send$inet_tcp" || name == "send$inet_accept" ||
			name == "recv$inet_tcp" || name == "recv$inet_accept" || name == "accept$inet_tcp") &&
			!strings.Contains(serialized, "listen$inet_tcp(") {
			t.Fatalf("generated program does not contain listen$inet_tcp for %s:\n%s", name, serialized)
		}
		if (name == "recv$inet_tcp" || name == "recv$inet_accept") &&
			!strings.Contains(serialized, "send$inet_tcp(") {
			if !strings.Contains(serialized, "send$inet_accept(") {
				t.Fatalf("generated program does not contain peer send bootstrap for %s:\n%s", name, serialized)
			}
		}
		if name == "recv$inet_udp" && !strings.Contains(serialized, "send$inet_udp(") {
			t.Fatalf("generated program does not contain UDP peer send bootstrap for %s:\n%s", name, serialized)
		}
		if name == "recv$inet_tcp" {
			sendIdx := strings.Index(serialized, "send$inet_accept(")
			recvIdx := strings.Index(serialized, "recv$inet_tcp(")
			if sendIdx == -1 || recvIdx == -1 || sendIdx > recvIdx {
				t.Fatalf("generated program does not send before recv for %s:\n%s", name, serialized)
			}
		}
		if name == "recv$inet_accept" {
			sendIdx := strings.Index(serialized, "send$inet_tcp(")
			recvIdx := strings.Index(serialized, "recv$inet_accept(")
			if sendIdx == -1 || recvIdx == -1 || sendIdx > recvIdx {
				t.Fatalf("generated program does not send before recv for %s:\n%s", name, serialized)
			}
		}
		if name == "recv$inet_udp" {
			sendIdx := strings.Index(serialized, "send$inet_udp(")
			recvIdx := strings.Index(serialized, "recv$inet_udp(")
			if sendIdx == -1 || recvIdx == -1 || sendIdx > recvIdx {
				t.Fatalf("generated program does not send before recv for %s:\n%s", name, serialized)
			}
		}
		if name == "WSARecvEx$inet_accept" {
			sendIdx := strings.Index(serialized, "send$inet_tcp(")
			recvIdx := strings.Index(serialized, "WSARecvEx$inet_accept(")
			if sendIdx == -1 || recvIdx == -1 || sendIdx > recvIdx {
				t.Fatalf("generated program does not send before recv for %s:\n%s", name, serialized)
			}
		}
		if name == "send$inet_tcp" {
			connectIdx := strings.Index(serialized, "connect$inet_tcp(")
			sendIdx := strings.Index(serialized, "send$inet_tcp(")
			closeIdx := strings.Index(serialized, "closesocket$any(r1)")
			if connectIdx == -1 || sendIdx == -1 || connectIdx > sendIdx {
				t.Fatalf("generated program does not connect before send for %s:\n%s", name, serialized)
			}
			if closeIdx == -1 || sendIdx > closeIdx {
				t.Fatalf("generated program closes connected socket before send for %s:\n%s", name, serialized)
			}
		}
		if name == "send$inet_accept" {
			acceptIdx := strings.Index(serialized, "accept$inet_tcp(")
			sendIdx := strings.Index(serialized, "send$inet_accept(")
			closeIdx := strings.Index(serialized, "closesocket$any(r2)")
			if acceptIdx == -1 || sendIdx == -1 || acceptIdx > sendIdx {
				t.Fatalf("generated program does not accept before send for %s:\n%s", name, serialized)
			}
			if closeIdx == -1 || sendIdx > closeIdx {
				t.Fatalf("generated program closes accept socket before send for %s:\n%s", name, serialized)
			}
		}
		if name == "TransmitFile$inet_accept" {
			acceptIdx := strings.Index(serialized, "accept$inet_tcp(")
			writeIdx := strings.Index(serialized, "WriteFile(")
			txIdx := strings.Index(serialized, "TransmitFile$inet_accept(")
			closeIdx := strings.Index(serialized, "CloseHandle(r3)")
			if acceptIdx == -1 || writeIdx == -1 || txIdx == -1 || acceptIdx > txIdx || writeIdx > txIdx {
				t.Fatalf("generated program does not prepare accept session/file payload before transmit for %s:\n%s", name, serialized)
			}
			if closeIdx == -1 || txIdx > closeIdx {
				t.Fatalf("generated program closes file before transmit for %s:\n%s", name, serialized)
			}
		}
		if name == "setsockopt$int_accept" {
			acceptIdx := strings.Index(serialized, "accept$inet_tcp(")
			optIdx := strings.Index(serialized, "setsockopt$int_accept(")
			if acceptIdx == -1 || optIdx == -1 || acceptIdx > optIdx {
				t.Fatalf("generated program does not accept before setsockopt for %s:\n%s", name, serialized)
			}
		}
		if name == "getsockopt$int_accept" {
			acceptIdx := strings.Index(serialized, "accept$inet_tcp(")
			optIdx := strings.Index(serialized, "getsockopt$int_accept(")
			if acceptIdx == -1 || optIdx == -1 || acceptIdx > optIdx {
				t.Fatalf("generated program does not accept before getsockopt for %s:\n%s", name, serialized)
			}
		}
		if (name == "AcceptEx$inet_tcp" || name == "WSARecvEx$inet_accept" || name == "TransmitFile$inet_accept") &&
			!strings.Contains(serialized, "accept$inet_tcp(") && !strings.Contains(serialized, "AcceptEx$inet_tcp(") {
			t.Fatalf("generated program does not contain accept path for %s:\n%s", name, serialized)
		}
		if name == "socket$listener_tcp" && !strings.Contains(serialized, "socket$listener_tcp(") {
			t.Fatalf("generated program does not contain socket$listener_tcp for %s:\n%s", name, serialized)
		}
		if name == "socket$connected_tcp" && !strings.Contains(serialized, "socket$connected_tcp(") {
			t.Fatalf("generated program does not contain socket$connected_tcp for %s:\n%s", name, serialized)
		}
		if name == "TransmitFile$inet_accept" {
			if !strings.Contains(serialized, "CreateFileA(") || !strings.Contains(serialized, "WriteFile(") {
				t.Fatalf("generated program does not contain file bootstrap for %s:\n%s", name, serialized)
			}
		}
	}
}

func TestStandaloneWinsockBuilderHelpersStayWired(t *testing.T) {
	path := filepath.Join("main.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(data)
	tests := []struct {
		caseName string
		want     []string
	}{
		{
			caseName: "send$inet_tcp",
			want:     []string{"bootstrapTCPAcceptedSessionWithClientConnectedPeerSend(", "bootstrapCloseAcceptSessionSockets()"},
		},
		{
			caseName: "send$inet_accept",
			want:     []string{"bootstrapTCPAcceptedSessionWithClientAcceptPeerSend(", "bootstrapCloseAcceptSessionSockets()"},
		},
		{
			caseName: "recv$inet_tcp",
			want:     []string{"bootstrapTCPAcceptedSessionWithClientAcceptPeerSend(", "bootstrapCloseAcceptSessionSockets()"},
		},
		{
			caseName: "recv$inet_accept",
			want:     []string{"bootstrapTCPAcceptedSessionWithClientConnectedPeerSend(", "bootstrapCloseAcceptSessionSockets()"},
		},
		{
			caseName: "WSARecvEx$inet_accept",
			want:     []string{"bootstrapTCPAcceptedSessionWithClientConnectedPeerSend(", "bootstrapCloseAcceptSessionSockets()"},
		},
		{
			caseName: "TransmitFile$inet_accept",
			want:     []string{"bootstrapTCPAcceptedSessionWithClient(", "bootstrapFilePayload()", "bootstrapCloseAcceptSessionSockets()"},
		},
		{
			caseName: "connect$inet_udp",
			want:     []string{"bootstrapUDPConnectedSession(", "bootstrapClose(\"r0\")"},
		},
		{
			caseName: "send$inet_udp",
			want:     []string{"bootstrapUDPConnectedSession(", "bootstrapClose(\"r0\")"},
		},
		{
			caseName: "recv$inet_udp",
			want:     []string{"bootstrapUDPBoundReceiverWithPeerSend(", "bootstrapClose(\"r1\")", "bootstrapClose(\"r0\")"},
		},
		{
			caseName: "AcceptEx$inet_tcp",
			want:     []string{"bootstrapTCPAcceptExSessionWithClient(", "bootstrapCloseAcceptSessionSockets()"},
		},
		{
			caseName: "accept$inet_tcp",
			want:     []string{"bootstrapTCPAcceptedSessionWithClient(", "bootstrapTCPListenerNonblocking()", "bootstrapCloseAcceptSessionSockets()"},
		},
		{
			caseName: "ioctlsocket$fionbio_accept",
			want:     []string{"bootstrapTCPAcceptedSessionWithClient(", "bootstrapTCPListenerNonblocking()", "bootstrapCloseAcceptSessionSockets()"},
		},
		{
			caseName: "setsockopt$int_accept",
			want:     []string{"bootstrapTCPAcceptedSessionWithClient(", "bootstrapCloseAcceptSessionSockets()"},
		},
		{
			caseName: "getsockopt$int_accept",
			want:     []string{"bootstrapTCPAcceptedSessionWithClient(", "bootstrapCloseAcceptSessionSockets()"},
		},
	}
	for _, test := range tests {
		body := extractCaseBody(t, src, test.caseName)
		for _, want := range test.want {
			if !strings.Contains(body, want) {
				t.Fatalf("%s case does not use expected builder %q:\n%s", test.caseName, want, body)
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

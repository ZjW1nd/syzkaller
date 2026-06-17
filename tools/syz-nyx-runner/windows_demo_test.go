package main

import (
	"encoding/json"
	"fmt"
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

	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
)

func skipLegacyAfdWinsockArchived(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(filepath.Join("..", "..", "sys", "windows", "archive", "afd-winsock", "socket_nyx.txt")); err == nil {
		t.Skip("legacy AFD Winsock surface is archived")
	}
}

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
		Debug        bool   `json:"debug"`
	} `json:"vm"`
	Experimental struct {
		SeedPrefix            string   `json:"seed_prefix"`
		SeedExcludePrefixes   string   `json:"seed_exclude_prefixes"`
		BorrowingSeedPrefix   string   `json:"borrowing_seed_prefix"`
		WindowsTargetProfile  string   `json:"windows_target_profile"`
		MaxCallsPerProg       int      `json:"max_calls_per_prog"`
		ForceGenerateEveryN   int      `json:"force_generate_every_n"`
		NoGenerateSyscalls    []string `json:"no_generate_syscalls"`
		DisableCollide        bool     `json:"disable_collide"`
		CorpusFuzzWeightRules []struct {
			Calls  []string `json:"calls"`
			Weight float64  `json:"weight"`
		} `json:"corpus_fuzz_weight_rules"`
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
			Debug        bool   `json:"debug"`
		} `json:"vm"`
		Experimental struct {
			SeedPrefix            string   `json:"seed_prefix"`
			SeedExcludePrefixes   string   `json:"seed_exclude_prefixes"`
			BorrowingSeedPrefix   string   `json:"borrowing_seed_prefix"`
			WindowsTargetProfile  string   `json:"windows_target_profile"`
			MaxCallsPerProg       int      `json:"max_calls_per_prog"`
			ForceGenerateEveryN   int      `json:"force_generate_every_n"`
			NoGenerateSyscalls    []string `json:"no_generate_syscalls"`
			DisableCollide        bool     `json:"disable_collide"`
			CorpusFuzzWeightRules []struct {
				Calls  []string `json:"calls"`
				Weight float64  `json:"weight"`
			} `json:"corpus_fuzz_weight_rules"`
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

func windowsSeedPrefixMatchesExcept(t *testing.T, prefixes, excludePrefixes string) []string {
	t.Helper()
	matches := windowsSeedPrefixMatches(t, prefixes)
	excludes := splitWindowsSeedPrefixes(excludePrefixes)
	if len(excludes) == 0 {
		return matches
	}
	var filtered []string
	for _, match := range matches {
		name := filepath.Base(match)
		excluded := false
		for _, prefix := range excludes {
			if strings.HasPrefix(name, prefix) {
				excluded = true
				break
			}
		}
		if !excluded {
			filtered = append(filtered, match)
		}
	}
	return filtered
}

func splitWindowsSeedPrefixes(prefixes string) []string {
	var split []string
	for _, prefix := range strings.Split(prefixes, ",") {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" {
			split = append(split, prefix)
		}
	}
	return split
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
	skipLegacyAfdWinsockArchived(t)
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
	skipLegacyAfdWinsockArchived(t)
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

func TestWindowsAFDSocketStateTransitionsUseStateWrappers(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	path := filepath.Join("..", "..", "executor", "syscalls_windows_nyx_demo.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read demo syscall table: %v", err)
	}
	src := string(data)
	for _, needle := range []string{
		`call_t{"bind$inet_tcp", 0, {}, (syscall_t)windows_bind_state}`,
		`call_t{"bind$inet_udp", 0, {}, (syscall_t)windows_bind_state}`,
		`call_t{"bind$connectex_tcp", 0, {}, (syscall_t)windows_bind_state}`,
		`call_t{"listen$inet_tcp", 0, {}, (syscall_t)windows_listen_state}`,
		`call_t{"ConnectEx$inet_tcp_pending", 0, {}, (syscall_t)windows_connect_ex_state}`,
		`call_t{"setsockopt$update_connect_context", 0, {}, (syscall_t)windows_update_connect_context_state}`,
	} {
		if !strings.Contains(src, needle) {
			t.Fatalf("sparse executor table is missing state-wrapper mapping %q", needle)
		}
	}
}

func TestWindowsAFDDirectStateIoctlsUseStateWrapper(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "syscalls_windows_nyx_demo.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read demo syscall table: %v", err)
	}
	src := string(data)
	for _, name := range []string{
		"NtDeviceIoControlFile$afd_bind_tcp",
		"NtDeviceIoControlFile$afd_bind_tcp_nonblock",
		"NtDeviceIoControlFile$afd_bind_udp",
		"NtDeviceIoControlFile$afd_bind_udp_nonblock",
		"NtDeviceIoControlFile$afd_connect_tcp",
		"NtDeviceIoControlFile$afd_connect_tcp_nonblock",
		"NtDeviceIoControlFile$afd_connect_udp",
		"NtDeviceIoControlFile$afd_connect_udp_nonblock",
		"NtDeviceIoControlFile$afd_connectex_tcp",
		"NtDeviceIoControlFile$afd_connectex_tcp_nonblock",
		"NtDeviceIoControlFile$afd_connectex_udp",
		"NtDeviceIoControlFile$afd_connectex_udp_nonblock",
		"NtDeviceIoControlFile$afd_super_connect_tcp",
		"NtDeviceIoControlFile$afd_super_connect_tcp_nonblock",
		"NtDeviceIoControlFile$afd_super_connect_tli",
		"NtDeviceIoControlFile$afd_super_disconnect_tcp",
		"NtDeviceIoControlFile$afd_super_disconnect_tcp_nonblock",
		"NtDeviceIoControlFile$afd_super_disconnect_accept",
		"NtDeviceIoControlFile$afd_super_disconnect_accept_nonblock",
		"NtDeviceIoControlFile$afd_start_listen_tcp",
		"NtDeviceIoControlFile$afd_start_listen_tcp_nonblock",
		"NtDeviceIoControlFile$afd_start_listen_tcp_delayed",
		"NtDeviceIoControlFile$afd_start_listen_tcp_delayed_nonblock",
		"NtDeviceIoControlFile$afd_defer_accept_requeue_tcp",
		"NtDeviceIoControlFile$afd_defer_accept_requeue_tcp_nonblock",
		"NtDeviceIoControlFile$afd_wait_for_listen_pending_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_pending_tcp_nonblock",
		"NtDeviceIoControlFile$afd_wait_for_listen_lifo_pending_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_lifo_pending_tcp_nonblock",
		"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_created",
		"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_bound",
		"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_listening",
		"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_connected",
		"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_accepted",
		"NtDeviceIoControlFile$afd_set_information_nonblock_udp_created",
		"NtDeviceIoControlFile$afd_set_information_nonblock_udp_bound",
		"NtDeviceIoControlFile$afd_set_information_nonblock_udp_peered",
		"NtDeviceIoControlFile$afd_set_context_tcp",
		"NtDeviceIoControlFile$afd_set_context_udp",
		"NtDeviceIoControlFile$afd_set_send_connect_data_tcp",
		"NtDeviceIoControlFile$afd_set_send_connect_options_tcp",
		"NtDeviceIoControlFile$afd_set_send_disconnect_data_tcp",
		"NtDeviceIoControlFile$afd_set_send_disconnect_options_tcp",
		"NtDeviceIoControlFile$afd_set_receive_connect_data_length_tcp",
		"NtDeviceIoControlFile$afd_set_receive_connect_options_length_tcp",
		"NtDeviceIoControlFile$afd_set_receive_disconnect_data_length_tcp",
		"NtDeviceIoControlFile$afd_set_receive_disconnect_options_length_tcp",
		"NtDeviceIoControlFile$afd_set_send_connect_data_udp",
		"NtDeviceIoControlFile$afd_set_send_connect_options_udp",
		"NtDeviceIoControlFile$afd_set_send_disconnect_data_udp",
		"NtDeviceIoControlFile$afd_set_send_disconnect_options_udp",
		"NtDeviceIoControlFile$afd_set_receive_connect_data_length_udp",
		"NtDeviceIoControlFile$afd_set_receive_connect_options_length_udp",
		"NtDeviceIoControlFile$afd_set_receive_disconnect_data_length_udp",
		"NtDeviceIoControlFile$afd_set_receive_disconnect_options_length_udp",
		"NtDeviceIoControlFile$afd_partial_disconnect_tcp",
		"NtDeviceIoControlFile$afd_receive_message_udp_bound_nonblock",
		"NtDeviceIoControlFile$afd_receive_message_udp_peer_nonblock",
		"NtDeviceIoControlFile$afd_send_message_tcp",
		"NtDeviceIoControlFile$afd_send_message_tcp_nonblock",
		"NtDeviceIoControlFile$afd_send_message_accept",
		"NtDeviceIoControlFile$afd_send_message_accept_nonblock",
		"NtDeviceIoControlFile$afd_send_message_udp_bound",
		"NtDeviceIoControlFile$afd_send_message_udp_bound_nonblock",
		"NtDeviceIoControlFile$afd_send_message_udp_peer",
		"NtDeviceIoControlFile$afd_send_message_udp_peer_nonblock",
		"NtDeviceIoControlFile$afd_unconnect_udp",
		"NtDeviceIoControlFile$afd_unbind_tcp",
		"NtDeviceIoControlFile$afd_unbind_udp",
		"NtDeviceIoControlFile$afd_tli_type1_nobuf",
		"NtDeviceIoControlFile$afd_tli_type2_nobuf",
		"NtDeviceIoControlFile$afd_tli_type3_nobuf",
		"NtDeviceIoControlFile$afd_tli_type1_inbuf",
		"NtDeviceIoControlFile$afd_tli_type2_inbuf",
		"NtDeviceIoControlFile$afd_tli_type3_inbuf",
		"NtDeviceIoControlFile$afd_tli_type1_outbuf",
		"NtDeviceIoControlFile$afd_tli_type2_outbuf",
		"NtDeviceIoControlFile$afd_tli_type3_outbuf",
		"NtDeviceIoControlFile$afd_tli_set_qos",
		"NtDeviceIoControlFile$afd_tli_associate_qos",
		"NtDeviceIoControlFile$afd_tli_isb_query",
		"NtDeviceIoControlFile$afd_tli_isb_set",
		"NtDeviceIoControlFile$afd_tli_type3_nobuf_pending",
		"NtDeviceIoControlFile$afd_set_qos_tcp",
		"NtDeviceIoControlFile$afd_set_qos_udp",
		"NtDeviceIoControlFile$afd_set_qos_tli",
		"NtDeviceIoControlFile$afd_get_qos_tcp_set",
		"NtDeviceIoControlFile$afd_get_qos_udp_set",
		"NtDeviceIoControlFile$afd_get_qos_tli",
		"NtDeviceIoControlFile$afd_validate_group_tcp",
		"NtDeviceIoControlFile$afd_validate_group_udp",
		"NtDeviceIoControlFile$afd_validate_group_recheck_tcp",
		"NtDeviceIoControlFile$afd_validate_group_recheck_udp",
		"NtDeviceIoControlFile$afd_san_fast_cement_endpoint",
		"NtDeviceIoControlFile$afd_san_fast_set_events",
		"NtDeviceIoControlFile$afd_san_fast_reset_events",
		"NtDeviceIoControlFile$afd_san_connect_handler",
		"NtDeviceIoControlFile$afd_san_fast_complete_accept",
		"NtDeviceIoControlFile$afd_san_fast_complete_request",
		"NtDeviceIoControlFile$afd_san_fast_complete_io",
		"NtDeviceIoControlFile$afd_san_fast_refresh_endpoint",
		"NtDeviceIoControlFile$afd_san_fast_transfer_ctx",
		"NtDeviceIoControlFile$afd_san_acquire_context",
		"NtDeviceIoControlFile$afd_san_fast_get_service_pid",
		"NtDeviceIoControlFile$afd_san_fast_set_service_process",
		"NtDeviceIoControlFile$afd_san_fast_provider_change",
		"NtDeviceIoControlFile$afd_san_fast_unknown_1210b",
		"NtDeviceIoControlFile$afd_san_addr_list_change",
		"NtDeviceIoControlFile$afd_sqm",
		"NtDeviceIoControlFile$afd_socket_transfer_begin",
		"NtDeviceIoControlFile$afd_socket_transfer_end",
		"NtDeviceIoControlFile$afd_notify_sock_register",
		"NtDeviceIoControlFile$afd_notify_sock_drain",
	} {
		needle := fmt.Sprintf(`call_t{"%s", 0, {}, (syscall_t)windows_nt_device_io_control_file_state}`, name)
		if !strings.Contains(src, needle) {
			t.Fatalf("sparse executor table is missing direct AFD state-wrapper mapping %q", needle)
		}
	}
	for _, name := range []string{
		"NtDeviceIoControlFile$afd_accept_tcp",
		"NtDeviceIoControlFile$afd_accept_tcp_nonblock",
		"NtDeviceIoControlFile$afd_super_accept_tcp",
		"NtDeviceIoControlFile$afd_super_accept_tcp_nonblock",
	} {
		needle := fmt.Sprintf(`call_t{"%s", 0, {}, (syscall_t)windows_nt_device_io_control_file_input_handle8_state}`, name)
		if !strings.Contains(src, needle) {
			t.Fatalf("sparse executor table is missing direct AFD input-handle state-wrapper mapping %q", needle)
		}
	}
	for _, name := range []string{
		"NtDeviceIoControlFile$afd_connect_tcp_to_listener",
		"NtDeviceIoControlFile$afd_connect_tcp_to_listener_nonblock",
		"NtDeviceIoControlFile$afd_connect_tcp_to_delayed_listener",
		"NtDeviceIoControlFile$afd_connect_tcp_to_delayed_listener_nonblock",
	} {
		needle := fmt.Sprintf(`call_t{"%s", 0, {}, (syscall_t)windows_nt_device_io_control_file_input_handle16_state}`, name)
		if !strings.Contains(src, needle) {
			t.Fatalf("sparse executor table is missing direct AFD input-handle16 state-wrapper mapping %q", needle)
		}
	}
	for _, name := range []string{
		"NtDeviceIoControlFile$afd_wait_for_listen_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_tcp_nonblock",
		"NtDeviceIoControlFile$afd_wait_for_listen_delayed_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_delayed_tcp_nonblock",
		"NtDeviceIoControlFile$afd_wait_for_listen_lifo_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_lifo_tcp_nonblock",
	} {
		needle := fmt.Sprintf(`call_t{"%s", 0, {}, (syscall_t)windows_nt_device_io_control_file_output_int32_state}`, name)
		if !strings.Contains(src, needle) {
			t.Fatalf("sparse executor table is missing direct AFD output-int32 state-wrapper mapping %q", needle)
		}
	}
}

func TestWindowsAFDNonIoctlEntriesUseNativeWrappers(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "syscalls_windows_nyx_demo.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read demo syscall table: %v", err)
	}
	src := string(data)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	prefixToNative := map[string]string{
		"NtCreateFile$afd_":            "NtCreateFile",
		"NtReadFile$afd_":              "NtReadFile",
		"NtWriteFile$afd_":             "NtWriteFile",
		"GetKernelObjectSecurity$afd_": "GetKernelObjectSecurity",
		"SetKernelObjectSecurity$afd_": "SetKernelObjectSecurity",
		"CloseHandle$afd_":             "CloseHandle",
	}
	for _, call := range target.Syscalls {
		if call == nil {
			continue
		}
		for prefix, native := range prefixToNative {
			if !strings.HasPrefix(call.Name, prefix) {
				continue
			}
			needle := fmt.Sprintf(`call_t{"%s", 0, {}, (syscall_t)%s}`, call.Name, native)
			if !strings.Contains(src, needle) {
				t.Fatalf("sparse executor table is missing AFD native mapping %q", needle)
			}
		}
	}
}

func TestWindowsNyxServiceTableMatchesTargetIDs(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
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
	skipLegacyAfdWinsockArchived(t)
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
	assertResource("ioctlsocket$fionbio_listener", 0, "SOCKET_TCP_LISTENING")
	assertResource("ioctlsocket$fionbio_listener", -1, "SOCKET_TCP_LISTENING_NONBLOCK")
	assertResource("accept$inet_tcp_nonblock", 0, "SOCKET_TCP_LISTENING_NONBLOCK")
	assertResource("accept$inet_tcp_nonblock", -1, "SOCKET_TCP_ACCEPTED_NONBLOCK")
	assertResource("connect$inet_tcp", 0, "SOCKET_TCP_CREATED")
	assertResource("connect$inet_tcp", -1, "SOCKET_TCP_CONNECTED")
	assertResource("DisconnectEx$inet_tcp_reuse", 0, "SOCKET_TCP_CONNECTED")
	assertResource("DisconnectEx$inet_tcp_reuse", -1, "SOCKET_TCP_DISCONNECT_REUSE_PENDING")
	assertResource("CreateIoCompletionPort$disconnect_reuse_pending", 0, "SOCKET_TCP_DISCONNECT_REUSE_PENDING")
	assertResource("WSAGetOverlappedResult$disconnect_reuse_pending", 0, "SOCKET_TCP_DISCONNECT_REUSE_PENDING")
	assertResource("WSAGetOverlappedResult$disconnect_reuse_pending", -1, "SOCKET_TCP_DISCONNECTED_REUSABLE")
	assertResource("ConnectEx$inet_tcp_reuse", 0, "SOCKET_TCP_DISCONNECTED_REUSABLE")
	assertResource("ConnectEx$inet_tcp_reuse", -1, "SOCKET_TCP_CONNECTING")
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
	assertResource("WSASendTo$udp_bound", 0, "SOCKET_UDP_BOUND")
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
	assertResource("setsockopt$update_connect_context", 0, "SOCKET_TCP_CONNECTING")
	assertResource("setsockopt$update_connect_context", -1, "SOCKET_TCP_CONNECTED")
	assertResource("DisconnectEx$inet_tcp", 0, "SOCKET_TCP_CONNECTED")
	assertResource("WSARecvEx$inet_accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("send$inet_accept_updated", 0, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("recv$inet_accept_updated", 0, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("setsockopt$int_accept_updated", 0, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("getsockopt$int_accept_updated", 0, "SOCKET_TCP_ACCEPTED_UPDATED")
	assertResource("TransmitFile$inet_accept", 0, "SOCKET_TCP_ACCEPTED")
	assertResource("TransmitPackets$inet_accept", 0, "SOCKET_ACCEPT")
	assertResource("TransmitFile$inet_accept_nonblock", 0, "SOCKET_TCP_ACCEPTED_NONBLOCK")
	assertResource("TransmitPackets$inet_accept_nonblock", 0, "SOCKET_TCP_ACCEPTED_NONBLOCK")
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
	skipLegacyAfdWinsockArchived(t)
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
	assertResource("CreateFileA$afd_transmit", -1, "AFD_TRANSMIT_FILE_HANDLE")
	assertResource("CreateFile2", -1, "FILE_HANDLE")
	assertResource("ReadFile", 0, "FILE_HANDLE")
	assertResource("WriteFile", 0, "FILE_HANDLE")
	assertResource("WriteFile$afd_transmit", 0, "AFD_TRANSMIT_FILE_HANDLE")
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
	assertResource("TransmitFile$inet_accept_nonblock", 1, "AFD_TRANSMIT_FILE_HANDLE")
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
	cfgPaths := []string{
		"windows-nyx-afd-session.cfg",
		"windows-nyx-afd-rio.cfg",
		"windows-nyx-afd-tli.cfg",
		"windows-nyx-afd-private.cfg",
	}
	indexed := make(map[string]bool, len(cfgPaths))
	for _, cfgPath := range cfgPaths {
		indexed[cfgPath] = true
	}
	matches, err := filepath.Glob("windows-nyx-afd*.cfg")
	if err != nil {
		t.Fatalf("glob AFD configs: %v", err)
	}
	for _, path := range matches {
		base := filepath.Base(path)
		if !indexed[base] {
			t.Fatalf("AFD config %s is missing from TestWindowsAfdFocusedConfigs", base)
		}
	}
	for _, cfgPath := range cfgPaths {
		cfgPath := cfgPath
		t.Run(cfgPath, func(t *testing.T) {
			cfg := loadWindowsNyxConfig(t, cfgPath)
			if cfg.VM.ModuleRanges != "ntoskrnl.exe:required,ntfs.sys,afd.sys,win32k*.sys" {
				t.Fatalf("%s module_ranges=%q", cfgPath, cfg.VM.ModuleRanges)
			}
			if cfg.Experimental.SeedPrefix == "" {
				t.Fatalf("%s missing experimental.seed_prefix", cfgPath)
			}
			if matches := windowsSeedPrefixMatchesExcept(t, cfg.Experimental.SeedPrefix,
				cfg.Experimental.SeedExcludePrefixes); len(matches) == 0 {
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

func TestWindowsAfdTransmitSeedHelpersPresentInSparseTable(t *testing.T) {
	table := loadDemoSyscallTable(t)
	for _, name := range []string{
		"CreateFileA$afd_transmit",
		"WriteFile$afd_transmit",
		"NtDeviceIoControlFile$afd_transmit_file_accept_nonblock",
		"NtDeviceIoControlFile$afd_transmit_packets_accept_nonblock",
	} {
		if _, ok := table[name]; !ok {
			t.Fatalf("AFD transmit seed helper %q missing from sparse Nyx table", name)
		}
	}
}

func TestWindowsAfdSessionEnablesStableSurfaceAndAvoidsKnownRiskyPaths(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-session.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("formal AFD session should disable generic collide while async collide stability is unresolved")
	}
	if cfg.Experimental.ForceGenerateEveryN != 2 {
		t.Fatalf("formal AFD session force_generate_every_n=%d, want 2 to avoid resource-centric no-candidate stalls",
			cfg.Experimental.ForceGenerateEveryN)
	}
	formalSeedExcludes := splitWindowsSeedPrefixes(cfg.Experimental.SeedExcludePrefixes)
	for _, prefix := range []string{
		"nyx_afd_acceptex_vnet_",
		"nyx_afd_async_accept_",
		"nyx_afd_private_event_select_nonblock",
		"nyx_afd_private_enum_events_nonblock",
		"nyx_afd_private_poll_accept_nonblock",
		"nyx_afd_private_event_nonblock",
		"nyx_afd_private_accept_immediate",
		"nyx_afd_select_nonblock",
		"nyx_afd_accept_data",
		"nyx_afd_public_event_nonblock_tcp",
		"nyx_afd_udp_peer_nonblock_receive",
		"nyx_afd_transmit_nonblock",
	} {
		if !slices.Contains(formalSeedExcludes, prefix) {
			t.Fatalf("formal AFD session should exclude seed prefix %q", prefix)
		}
		for _, path := range windowsSeedPrefixMatchesExcept(t, cfg.Experimental.SeedPrefix,
			cfg.Experimental.SeedExcludePrefixes) {
			if strings.HasPrefix(filepath.Base(path), prefix) {
				t.Fatalf("formal AFD session still selects excluded seed %s", filepath.Base(path))
			}
		}
	}
	for _, path := range windowsSeedPrefixMatchesExcept(t, cfg.Experimental.SeedPrefix,
		cfg.Experimental.SeedExcludePrefixes) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(data), "NtDeviceIoControlFile$afd_poll_accept_nonblock") {
			t.Fatalf("formal AFD session should not select private poll seed %s; it bugchecked the Nyx guest",
				filepath.Base(path))
		}
		if strings.Contains(string(data), "NtDeviceIoControlFile$afd_event_select_accept_nonblock") ||
			strings.Contains(string(data), "NtDeviceIoControlFile$afd_enum_network_events_accept_nonblock") {
			t.Fatalf("formal AFD session should not select private accepted-event seed %s; it hanged the Nyx guest",
				filepath.Base(path))
		}
		if strings.Contains(string(data), "select$afd_accept_nonblock") {
			t.Fatalf("formal AFD session should not select accepted-chain select seed %s; it bugchecked the Nyx guest",
				filepath.Base(path))
		}
		for _, slowCall := range []string{
			"NtDeviceIoControlFile$afd_query_handles_accept",
			"NtDeviceIoControlFile$afd_get_qos_accept",
			"recv$inet_accept_nonblock",
			"WSARecv$accept_nonblock",
			"WSASend$accept",
			"WSAEventSelect$tcp_nonblock",
			"WSAEnumNetworkEvents$tcp_nonblock",
		} {
			if strings.Contains(string(data), slowCall) {
				t.Fatalf("formal AFD session should not select slow accepted-chain seed %s containing %s",
					filepath.Base(path), slowCall)
			}
		}
	}
	wantWeighted := []string{
		"AcceptEx$inet_tcp_pending",
		"CreateIoCompletionPort$accept_pending",
		"WSAGetOverlappedResult$accept_pending",
		"GetQueuedCompletionStatus$socket",
		"GetAcceptExSockaddrs$inet_tcp",
		"setsockopt$update_accept_context",
		"send$inet_accept_updated",
		"recv$inet_accept_updated",
		"setsockopt$int_accept_updated",
		"getsockopt$int_accept_updated",
	}
	foundAcceptExWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight != 0 {
			continue
		}
		hasAll := true
		for _, name := range wantWeighted {
			if !slices.Contains(rule.Calls, name) {
				hasAll = false
				break
			}
		}
		if hasAll {
			foundAcceptExWeight = true
			break
		}
	}
	if !foundAcceptExWeight {
		t.Fatalf("formal AFD session should exclude AcceptEx/update-context corpus from ordinary fuzz mutation")
	}
	wantConnectExWeighted := []string{
		"bind$connectex_tcp",
		"ConnectEx$inet_tcp_pending",
		"CreateIoCompletionPort$connect_pending",
		"WSAGetOverlappedResult$connect_pending",
		"GetQueuedCompletionStatus$socket",
		"setsockopt$update_connect_context",
	}
	foundConnectExWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight != 0 {
			continue
		}
		hasAll := true
		for _, name := range wantConnectExWeighted {
			if !slices.Contains(rule.Calls, name) {
				hasAll = false
				break
			}
		}
		if hasAll {
			foundConnectExWeight = true
			break
		}
	}
	if !foundConnectExWeight {
		t.Fatalf("formal AFD session should keep ConnectEx M4 corpus out of ordinary fuzz mutation")
	}
	wantUDPBoundWeighted := []string{
		"NtDeviceIoControlFile$afd_address_list_query_udp",
		"NtDeviceIoControlFile$afd_query_handles_udp",
		"NtDeviceIoControlFile$afd_get_qos_udp",
		"NtDeviceIoControlFile$afd_noop_udp",
	}
	foundUDPBoundWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight != 0 {
			continue
		}
		hasAll := true
		for _, name := range wantUDPBoundWeighted {
			if !slices.Contains(rule.Calls, name) {
				hasAll = false
				break
			}
		}
		if hasAll {
			foundUDPBoundWeight = true
			break
		}
	}
	if !foundUDPBoundWeight {
		t.Fatalf("formal AFD session should keep UDP-bound private IOCTL corpus out of ordinary fuzz mutation")
	}
	wantUDPPeerWeighted := []string{
		"send$inet_udp",
		"ioctlsocket$fionbio_udp_peer",
		"recvfrom$udp_connected_nonblock",
		"setsockopt$int_udp",
		"WSAIoctl$sio_routing_interface_query",
		"NtDeviceIoControlFile$afd_query_handles_udp_peer",
		"NtDeviceIoControlFile$afd_routing_interface_query_udp",
	}
	foundUDPSendToWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight != 0 {
			continue
		}
		hasAll := true
		for _, name := range wantUDPPeerWeighted {
			if !slices.Contains(rule.Calls, name) {
				hasAll = false
				break
			}
		}
		if hasAll {
			foundUDPSendToWeight = true
			break
		}
	}
	if !foundUDPSendToWeight {
		t.Fatalf("formal AFD session should keep UDP peer risky corpus out of ordinary fuzz mutation")
	}
	wantTCPConnectedWeighted := []string{
		"NtDeviceIoControlFile$afd_query_recv_tcp",
		"NtDeviceIoControlFile$afd_query_handles_tcp",
		"NtDeviceIoControlFile$afd_get_remote_address_tcp",
		"NtDeviceIoControlFile$afd_set_context_tcp",
		"NtDeviceIoControlFile$afd_get_context_tcp",
		"NtDeviceIoControlFile$afd_get_qos_tcp",
		"NtDeviceIoControlFile$afd_noop_tcp",
	}
	foundTCPConnectedWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight != 0 {
			continue
		}
		hasAll := true
		for _, name := range wantTCPConnectedWeighted {
			if !slices.Contains(rule.Calls, name) {
				hasAll = false
				break
			}
		}
		if hasAll {
			foundTCPConnectedWeight = true
			break
		}
	}
	if !foundTCPConnectedWeight {
		t.Fatalf("formal AFD session should keep TCP connected private IOCTL corpus out of ordinary fuzz mutation")
	}
	foundTransmitWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight == 0 &&
			slices.Contains(rule.Calls, "TransmitFile$inet_accept_nonblock") &&
			slices.Contains(rule.Calls, "TransmitPackets$inet_accept_nonblock") &&
			slices.Contains(rule.Calls, "WriteFile$afd_transmit") {
			foundTransmitWeight = true
			break
		}
	}
	if !foundTransmitWeight {
		t.Fatalf("formal AFD session should keep transmit corpus out of ordinary fuzz mutation")
	}
	wantShutdownWeighted := []string{
		"shutdown$tcp",
		"shutdown$tcp_rd",
		"shutdown$tcp_wr",
		"shutdown$accept",
		"shutdown$accept_rd",
		"shutdown$accept_wr",
	}
	foundShutdownWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight != 0 {
			continue
		}
		hasAll := true
		for _, name := range wantShutdownWeighted {
			if !slices.Contains(rule.Calls, name) {
				hasAll = false
				break
			}
		}
		if hasAll {
			foundShutdownWeight = true
			break
		}
	}
	if !foundShutdownWeight {
		t.Fatalf("formal AFD session should keep shutdown lifecycle corpus out of ordinary fuzz mutation")
	}
	wantAcceptedChainWeighted := []string{
		"select$afd_accept_nonblock",
		"WSAEventSelect$tcp_nonblock",
		"WSAEnumNetworkEvents$tcp_nonblock",
		"NtDeviceIoControlFile$afd_event_select_accept_nonblock",
		"NtDeviceIoControlFile$afd_enum_network_events_accept_nonblock",
		"NtDeviceIoControlFile$afd_poll_accept_nonblock",
		"NtDeviceIoControlFile$afd_query_handles_accept",
		"NtDeviceIoControlFile$afd_get_qos_accept",
		"NtDeviceIoControlFile$afd_noop_accept",
	}
	foundAcceptedChainWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight != 0 {
			continue
		}
		hasAll := true
		for _, name := range wantAcceptedChainWeighted {
			if !slices.Contains(rule.Calls, name) {
				hasAll = false
				break
			}
		}
		if hasAll {
			foundAcceptedChainWeight = true
			break
		}
	}
	if !foundAcceptedChainWeight {
		t.Fatalf("formal AFD session should keep accepted-socket event/private IOCTL corpus out of ordinary fuzz mutation")
	}
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
	}

	wantEnabled := []string{
		"sendto$udp_bound",
		"connect$inet_udp",
		"send$inet_udp",
		"sendto$udp_connected",
		"WSASendTo$udp",
		"WSASendTo$udp_bound",
		"ioctlsocket$fionbio_udp_bound",
		"recv$inet_udp_nonblock",
		"recvfrom$udp_bound_nonblock",
		"recvfrom$udp_connected_nonblock",
		"WSARecvFrom$udp_nonblock",
		"WSARecvMsg$udp_nonblock",
		"NtDeviceIoControlFile$afd_address_list_query_udp",
		"NtDeviceIoControlFile$afd_routing_interface_query_udp",
		"NtDeviceIoControlFile$afd_query_handles_udp",
		"NtDeviceIoControlFile$afd_query_handles_udp_peer",
		"NtDeviceIoControlFile$afd_get_qos_udp",
		"NtDeviceIoControlFile$afd_noop_udp",
		"WSAIoctl$sio_address_list_query",
		"WSAIoctl$sio_routing_interface_query",
		"WSAIoctl$sio_get_interface_list",
		"ioctlsocket$fionbio_tcp_created",
		"connect$inet_tcp_nonblock",
		"send$inet_tcp",
		"ioctlsocket$fionbio_tcp_connected",
		"recv$inet_tcp_nonblock",
		"WSASend$tcp",
		"WSARecv$tcp_nonblock",
		"shutdown$tcp",
		"shutdown$tcp_rd",
		"shutdown$tcp_wr",
		"closesocket$tcp_shutdown_rd",
		"closesocket$tcp_shutdown_wr",
		"NtDeviceIoControlFile$afd_query_recv_tcp",
		"NtDeviceIoControlFile$afd_query_handles_tcp",
		"NtDeviceIoControlFile$afd_get_remote_address_tcp",
		"NtDeviceIoControlFile$afd_set_context_tcp",
		"NtDeviceIoControlFile$afd_get_context_tcp",
		"NtDeviceIoControlFile$afd_get_qos_tcp",
		"NtDeviceIoControlFile$afd_noop_tcp",
		"WSAIoctl$sio_keepalive_vals",
		"WSAIoctl$sio_get_extension_function_pointer",
		"bind$connectex_tcp",
		"ConnectEx$inet_tcp_pending",
		"CreateIoCompletionPort$connect_pending",
		"WSAGetOverlappedResult$connect_pending",
		"GetQueuedCompletionStatus$socket",
		"setsockopt$update_connect_context",
		"ioctlsocket$fionbio_listener",
		"accept$inet_tcp_nonblock",
		"send$inet_accept",
		"recv$inet_accept_nonblock",
		"WSASend$accept",
		"WSARecv$accept_nonblock",
		"shutdown$accept",
		"shutdown$accept_rd",
		"shutdown$accept_wr",
		"AcceptEx$inet_tcp_pending",
		"CreateIoCompletionPort$accept_pending",
		"WSAGetOverlappedResult$accept_pending",
		"GetAcceptExSockaddrs$inet_tcp",
		"setsockopt$update_accept_context",
		"send$inet_accept_updated",
		"recv$inet_accept_updated",
		"setsockopt$int_accept_updated",
		"getsockopt$int_accept_updated",
		"WriteFile$afd_transmit",
		"TransmitFile$inet_accept_nonblock",
		"TransmitPackets$inet_accept_nonblock",
		"WSAEventSelect$tcp_nonblock",
		"WSAEnumNetworkEvents$tcp_nonblock",
		"select$afd_accept_nonblock",
		"NtDeviceIoControlFile$afd_event_select_accept_nonblock",
		"NtDeviceIoControlFile$afd_enum_network_events_accept_nonblock",
		"NtDeviceIoControlFile$afd_poll_accept_nonblock",
		"getsockname$accept",
		"getpeername$accept",
		"NtDeviceIoControlFile$afd_query_handles_accept",
		"NtDeviceIoControlFile$afd_get_qos_accept",
		"NtDeviceIoControlFile$afd_noop_accept",
		"setsockopt$int_accept",
		"getsockopt$int_accept",
		"WSARecvEx$inet_accept_nonblock",
	}
	for _, name := range wantEnabled {
		if !slices.Contains(cfg.EnabledSyscalls, name) {
			t.Fatalf("AFD session config should enable stable syscall %q", name)
		}
	}

	riskyPaths := []string{
		"connect$inet_tcp",
		"recv$inet_tcp",
		"WSARecv$tcp",
		"WSARecv$tcp_pending",
		"WSASend$tcp_pending",
		"WSAEventSelect$tcp",
		"WSAEnumNetworkEvents$tcp",
		"WNet*",
		"ConnectEx$inet_tcp",
		"ConnectEx$inet_tcp_reuse",
		"DisconnectEx$inet_tcp*",
		"recv$inet_udp",
		"recvfrom$udp_bound",
		"recvfrom$udp_connected",
		"WSARecvFrom$udp",
		"WSARecvMsg$udp",
		"WSAIoctl$sio_udp_connreset",
		"select$afd_basic",
		"NtDeviceIoControlFile$afd_event_select_accept",
		"NtDeviceIoControlFile$afd_enum_network_events_accept",
		"NtDeviceIoControlFile$afd_poll_accept",
		"accept$inet_tcp",
		"ioctlsocket$fionbio_accept",
		"ioctlsocket$fionbio_accept_nonblock",
		"recv$inet_accept",
		"WSARecv$accept",
		"WSARecvEx$inet_accept",
		"WSASend$accept_pending",
		"WSARecv$accept_pending",
		"WSAEventSelect$accept",
		"WSAEnumNetworkEvents$accept",
		"WSAEventSelect$accept_nonblock",
		"WSAEnumNetworkEvents$accept_nonblock",
		"NtDeviceIoControlFile$afd_query_recv_accept",
		"CreateIoCompletionPort$socket",
		"CreateIoCompletionPort$accept_recv_pending",
		"CreateIoCompletionPort$accept_send_pending",
		"CreateIoCompletionPort$tcp_*_pending",
		"WSAGetOverlappedResult$socket",
		"WSAGetOverlappedResult$accept_recv_pending",
		"WSAGetOverlappedResult$accept_send_pending",
		"WSAGetOverlappedResult$tcp_*_pending",
		"CancelIoEx$socket",
		"CancelIoEx$accept*",
		"CancelIoEx$connect_pending",
		"CancelIoEx$tcp_*_pending",
		"CancelIo$socket",
		"CancelIo$accept*",
		"CancelIo$connect_pending",
		"CancelIo$tcp_*_pending",
		"closesocket$any",
		"closesocket$accept*",
		"closesocket$connect_pending",
		"closesocket$tcp_*_pending",
		"AcceptEx$inet_tcp",
		"CreatePipe$anon",
		"CreateRemoteThreadEx",
		"AddFontMemResourceEx",
		"TransmitPackets$inet_accept",
		"TransmitFile$inet_accept",
	}
	directForbidden := append([]string{
		"socket$connected_tcp",
		"socket$connected_udp",
		"ioctlsocket$fionbio_tcp",
		"socket$accept_tcp",
	}, riskyPaths...)
	for _, name := range cfg.EnabledSyscalls {
		for _, pattern := range directForbidden {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("AFD session directly enables risky syscall %q via pattern %q",
					name, pattern)
			}
		}
	}
	for _, name := range []string{
		"WSAIoctl$sio_udp_connreset",
		"ioctlsocket$fionbio_tcp",
		"ioctlsocket$fionbio_udp_peer",
		"ConnectEx$inet_tcp",
		"ConnectEx$inet_tcp_reuse",
		"CreateRemoteThreadEx",
	} {
		if !slices.Contains(cfg.DisabledSyscalls, name) {
			t.Fatalf("AFD session should keep %q disabled in formal configs", name)
		}
	}

	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	expanded := make(map[*prog.Syscall]bool, len(syscalls))
	for _, id := range syscalls {
		meta := target.Syscalls[id]
		expanded[meta] = true
		name := meta.Name
		for _, pattern := range riskyPaths {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("AFD session leaves risky syscall %q enabled via pattern %q",
					name, pattern)
			}
		}
	}
	if call := target.SyscallMap["WriteFile"]; call != nil && expanded[call] {
		t.Fatalf("AFD session should not enable generic WriteFile; use WriteFile$afd_transmit for transmit seeds")
	}
	noDirect, err := mgrconfig.ParseNoGenerateSyscalls(target, cfg.Experimental.NoGenerateSyscalls)
	if err != nil {
		t.Fatalf("ParseNoGenerateSyscalls: %v", err)
	}
	ct := target.BuildChoiceTableWithNoDirectCalls(nil, expanded, noDirect)
	for _, name := range []string{
		"send$inet_udp",
		"WSARecvMsg$udp_nonblock",
		"recv$inet_udp_nonblock",
		"recvfrom$udp_bound_nonblock",
		"WSARecvFrom$udp_nonblock",
		"NtDeviceIoControlFile$afd_address_list_query_udp",
		"NtDeviceIoControlFile$afd_query_handles_udp",
		"NtDeviceIoControlFile$afd_get_qos_udp",
		"NtDeviceIoControlFile$afd_noop_udp",
		"recvfrom$udp_connected_nonblock",
		"setsockopt$int_udp",
		"getsockname$udp",
		"getpeername$udp",
		"WSAIoctl$sio_routing_interface_query",
		"NtDeviceIoControlFile$afd_query_handles_udp_peer",
		"NtDeviceIoControlFile$afd_routing_interface_query_udp",
		"ioctlsocket$fionbio_tcp_connected",
		"NtDeviceIoControlFile$afd_query_recv_tcp",
		"NtDeviceIoControlFile$afd_query_handles_tcp",
		"NtDeviceIoControlFile$afd_get_remote_address_tcp",
		"NtDeviceIoControlFile$afd_set_context_tcp",
		"NtDeviceIoControlFile$afd_get_context_tcp",
		"NtDeviceIoControlFile$afd_get_qos_tcp",
		"NtDeviceIoControlFile$afd_noop_tcp",
		"ioctlsocket$fionbio_listener",
		"select$afd_accept_nonblock",
		"WSAEventSelect$tcp_nonblock",
		"WSAEnumNetworkEvents$tcp_nonblock",
		"NtDeviceIoControlFile$afd_event_select_accept_nonblock",
		"NtDeviceIoControlFile$afd_enum_network_events_accept_nonblock",
		"NtDeviceIoControlFile$afd_poll_accept_nonblock",
		"NtDeviceIoControlFile$afd_query_handles_accept",
		"NtDeviceIoControlFile$afd_get_qos_accept",
		"NtDeviceIoControlFile$afd_noop_accept",
		"CreateIoCompletionPort$accept_pending",
		"WSAGetOverlappedResult$accept_pending",
		"GetAcceptExSockaddrs$inet_tcp",
		"WSARecvEx$inet_accept_nonblock",
		"TransmitFile$inet_accept_nonblock",
		"TransmitPackets$inet_accept_nonblock",
		"WriteFile$afd_transmit",
		"send$inet_accept_updated",
		"recv$inet_accept_updated",
		"setsockopt$int_accept_updated",
		"getsockopt$int_accept_updated",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing formal no-generate syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("%s should stay enabled in formal AFD session", name)
		}
		if !call.Attrs.NoGenerate && !ct.Generatable(call.ID) {
			t.Fatalf("%s should stay available for seeds/resource construction", name)
		}
		if ct.DirectlyGeneratable(call.ID) {
			t.Fatalf("%s should not be a formal fresh/insertion generation root", name)
		}
	}
	for _, name := range []string{
		"sendto$udp_bound",
		"ioctlsocket$fionbio_udp_bound",
		"sendto$udp_connected",
		"WSASendTo$udp",
		"WSASendTo$udp_bound",
		"getsockname$tcp",
		"getpeername$tcp",
		"setsockopt$int_tcp",
		"getsockopt$int_tcp",
		"send$inet_tcp",
		"recv$inet_tcp_nonblock",
		"WSASend$tcp",
		"WSARecv$tcp_nonblock",
		"WSAIoctl$sio_keepalive_vals",
		"WSAIoctl$sio_get_extension_function_pointer",
		"bind$connectex_tcp",
		"ConnectEx$inet_tcp_pending",
		"CreateIoCompletionPort$connect_pending",
		"WSAGetOverlappedResult$connect_pending",
		"GetQueuedCompletionStatus$socket",
		"setsockopt$update_connect_context",
		"connect$inet_tcp_nonblock",
		"accept$inet_tcp_nonblock",
		"send$inet_accept",
		"recv$inet_accept_nonblock",
		"WSASend$accept",
		"WSARecv$accept_nonblock",
		"getsockname$accept",
		"getpeername$accept",
		"setsockopt$int_accept",
		"getsockopt$int_accept",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing formal direct-generation syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("%s should stay enabled in formal AFD session", name)
		}
		if noDirect[call.ID] || !ct.DirectlyGeneratable(call.ID) {
			t.Fatalf("%s should be available as a formal fresh/insertion generation root", name)
		}
	}
	scheduledFresh := 0
	var lastFresh *prog.Prog
	for seed := int64(1); seed <= 4096; seed++ {
		p := target.Generate(rand.New(rand.NewSource(seed)), cfg.Experimental.MaxCallsPerProg, ct)
		lastFresh = p
		if target.RuntimePolicy.ShouldScheduleProgram == nil ||
			target.RuntimePolicy.ShouldScheduleProgram("gen", p) {
			scheduledFresh++
			if scheduledFresh >= 8 {
				break
			}
		}
	}
	if scheduledFresh == 0 {
		t.Fatalf("formal AFD fresh generation never produced a schedulable program; last program:\n%s",
			lastFresh.Serialize())
	}
	for _, name := range []string{
		"recv$inet_udp_nonblock",
		"recvfrom$udp_bound_nonblock",
		"WSARecvFrom$udp_nonblock",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing formal UDP nonblock receive syscall %q", name)
		}
		p := target.GenSampleProg(call, rand.NewSource(1), ct)
		serialized := string(p.Serialize())
		if target.RuntimePolicy.ShouldScheduleProgram != nil &&
			target.RuntimePolicy.ShouldScheduleProgram("gen", p) &&
			!strings.Contains(serialized, "ioctlsocket$fionbio_udp_bound(") {
			t.Fatalf("%s formal sample scheduled without UDP FIONBIO constructor:\n%s", name, serialized)
		}
	}
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight != 0 {
			continue
		}
		for _, name := range []string{
			"sendto$udp_bound",
			"ioctlsocket$fionbio_udp_bound",
			"sendto$udp_connected",
			"WSASendTo$udp",
			"WSASendTo$udp_bound",
			"ioctlsocket$fionbio_tcp_connected",
			"send$inet_tcp",
			"recv$inet_tcp_nonblock",
			"WSASend$tcp",
			"WSARecv$tcp_nonblock",
			"ioctlsocket$fionbio_listener",
			"connect$inet_tcp_nonblock",
			"accept$inet_tcp_nonblock",
			"send$inet_accept",
			"recv$inet_accept_nonblock",
			"WSASend$accept",
			"WSARecv$accept_nonblock",
		} {
			for _, pattern := range rule.Calls {
				if mgrconfig.MatchSyscall(name, pattern) {
					t.Fatalf("formal AFD zero-weight rule %v still suppresses stable generation/mutation call %s",
						rule.Calls, name)
				}
			}
		}
	}
	foundAcceptedRecvExWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight == 0 && slices.Contains(rule.Calls, "WSARecvEx$inet_accept_nonblock") {
			foundAcceptedRecvExWeight = true
			break
		}
	}
	if !foundAcceptedRecvExWeight {
		t.Fatalf("formal AFD session should keep accepted WSARecvEx out of ordinary fuzz mutation")
	}
	foundKeepaliveWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight == 0 &&
			slices.Contains(rule.Calls, "WSAIoctl$sio_keepalive_vals") &&
			slices.Contains(rule.Calls, "WSAIoctl$sio_get_extension_function_pointer") {
			foundKeepaliveWeight = true
			break
		}
	}
	if !foundKeepaliveWeight {
		t.Fatalf("formal AFD session should keep keepalive/extension WSAIoctl corpus out of ordinary fuzz mutation")
	}
	foundUDPGetNameWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight == 0 &&
			slices.Contains(rule.Calls, "getsockname$udp") &&
			slices.Contains(rule.Calls, "getpeername$udp") {
			foundUDPGetNameWeight = true
			break
		}
	}
	if !foundUDPGetNameWeight {
		t.Fatalf("formal AFD session should keep UDP getsockname/getpeername corpus out of ordinary fuzz mutation")
	}
	foundUDPNonblockReceiveWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight == 0 &&
			slices.Contains(rule.Calls, "recv$inet_udp_nonblock") &&
			slices.Contains(rule.Calls, "recvfrom$udp_bound_nonblock") &&
			slices.Contains(rule.Calls, "WSARecvFrom$udp_nonblock") &&
			slices.Contains(rule.Calls, "WSARecvMsg$udp_nonblock") {
			foundUDPNonblockReceiveWeight = true
			break
		}
	}
	if !foundUDPNonblockReceiveWeight {
		t.Fatalf("formal AFD session should keep UDP nonblock receive paths out of ordinary fuzz mutation")
	}
	for _, name := range []string{
		"AcceptEx$inet_tcp_pending",
		"CreateIoCompletionPort$accept_pending",
		"WSAGetOverlappedResult$accept_pending",
		"GetAcceptExSockaddrs$inet_tcp",
		"setsockopt$update_accept_context",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing formal accept-updated seed-only syscall %q", name)
		}
		if !call.Attrs.NoMinimize {
			t.Fatalf("%s should stay no_minimize in formal AFD session", name)
		}
		if !call.Attrs.NoGenerate && !noDirect[call.ID] {
			t.Fatalf("%s should be blocked from formal fresh/insertion generation by syscall attrs or config", name)
		}
		if ct.DirectlyGeneratable(call.ID) {
			t.Fatalf("%s should not be a formal fresh/insertion generation root", name)
		}
	}
	for _, name := range []string{
		"connect$inet_tcp_nonblock",
		"accept$inet_tcp_nonblock",
		"WSARecvEx$inet_accept_nonblock",
		"select$afd_accept_nonblock",
		"TransmitFile$inet_accept_nonblock",
		"TransmitPackets$inet_accept_nonblock",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing formal nonblocking accepted-chain syscall %q", name)
		}
		if !call.Attrs.NoMinimize {
			t.Fatalf("%s should stay no_minimize so formal seeds are not reduced to a bare accept chain", name)
		}
	}
	for _, name := range []string{
		"getsockname$accept",
		"getpeername$accept",
		"setsockopt$int_accept",
		"getsockopt$int_accept",
		"NtDeviceIoControlFile$afd_query_handles_accept",
		"NtDeviceIoControlFile$afd_get_qos_accept",
		"NtDeviceIoControlFile$afd_noop_accept",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing formal accepted-socket syscall %q", name)
		}
		p := target.GenSampleProg(call, rand.NewSource(1), ct)
		serialized := string(p.Serialize())
		if strings.Contains(serialized, "socket$accept_tcp(") {
			t.Fatalf("%s formal sample uses raw accept helper instead of accept$inet_tcp_nonblock chain:\n%s",
				name, serialized)
		}
		if target.RuntimePolicy.ShouldScheduleProgram != nil &&
			target.RuntimePolicy.ShouldScheduleProgram("gen", p) &&
			!strings.Contains(serialized, "connect$inet_tcp_nonblock(") &&
			!strings.Contains(serialized, "connect$inet_tcp(") {
			t.Fatalf("%s formal sample scheduled accepted socket without peer connect:\n%s",
				name, serialized)
		}
	}
	for _, name := range []string{
		"send$inet_tcp",
		"WSASend$tcp",
		"getsockname$tcp",
		"getpeername$tcp",
		"setsockopt$int_tcp",
		"getsockopt$int_tcp",
		"WSAIoctl$sio_keepalive_vals",
		"WSAIoctl$sio_get_extension_function_pointer",
		"NtDeviceIoControlFile$afd_query_recv_tcp",
		"NtDeviceIoControlFile$afd_query_handles_tcp",
		"NtDeviceIoControlFile$afd_get_remote_address_tcp",
		"NtDeviceIoControlFile$afd_set_context_tcp",
		"NtDeviceIoControlFile$afd_get_context_tcp",
		"NtDeviceIoControlFile$afd_get_qos_tcp",
		"NtDeviceIoControlFile$afd_noop_tcp",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing formal TCP-connected syscall %q", name)
		}
		p := target.GenSampleProg(call, rand.NewSource(1), ct)
		serialized := string(p.Serialize())
		if strings.Contains(serialized, "socket$connected_tcp(") {
			t.Fatalf("%s formal sample uses raw connected helper instead of connect$inet_tcp_nonblock chain:\n%s",
				name, serialized)
		}
	}
	for _, name := range []string{
		"ioctlsocket$fionbio_udp_bound",
		"recv$inet_udp_nonblock",
		"recvfrom$udp_bound_nonblock",
		"WSARecvFrom$udp_nonblock",
		"NtDeviceIoControlFile$afd_address_list_query_udp",
		"NtDeviceIoControlFile$afd_query_handles_udp",
		"NtDeviceIoControlFile$afd_get_qos_udp",
		"NtDeviceIoControlFile$afd_noop_udp",
		"WSAIoctl$sio_address_list_query",
		"WSAIoctl$sio_get_interface_list",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing formal UDP-bound syscall %q", name)
		}
		for seed := int64(1); seed <= 100; seed++ {
			p := target.GenSampleProg(call, rand.NewSource(seed), ct)
			serialized := string(p.Serialize())
			for _, forbidden := range []string{
				"socket$inet_tcp(",
				"listen$inet_tcp(",
				"accept$inet_tcp",
				"connect$inet_tcp",
				"ioctlsocket$fionbio_listener(",
				"ioctlsocket$fionbio_tcp",
			} {
				if strings.Contains(serialized, forbidden) {
					t.Fatalf("%s formal sample uses TCP resource chain for UDP bound with seed %d:\n%s",
						name, seed, serialized)
				}
			}
		}
	}
	for _, name := range []string{
		"send$inet_udp",
		"sendto$udp_connected",
		"WSASendTo$udp",
		"recvfrom$udp_connected_nonblock",
		"getpeername$udp",
		"WSAIoctl$sio_routing_interface_query",
		"NtDeviceIoControlFile$afd_query_handles_udp_peer",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing formal UDP-peer syscall %q", name)
		}
		for seed := int64(1); seed <= 100; seed++ {
			p := target.GenSampleProg(call, rand.NewSource(seed), ct)
			serialized := string(p.Serialize())
			for _, forbidden := range []string{
				"listen$inet_tcp(",
				"accept$inet_tcp",
				"connect$inet_tcp",
				"ioctlsocket$fionbio_listener(",
				"ioctlsocket$fionbio_tcp",
			} {
				if strings.Contains(serialized, forbidden) {
					t.Fatalf("%s formal sample uses TCP resource chain for UDP peer with seed %d:\n%s",
						name, seed, serialized)
				}
			}
		}
	}
	for _, name := range []string{
		"shutdown$tcp",
		"shutdown$tcp_rd",
		"shutdown$tcp_wr",
		"shutdown$accept",
		"shutdown$accept_rd",
		"shutdown$accept_wr",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing formal shutdown-state syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("%s should stay enabled in formal AFD session", name)
		}
		if !noDirect[call.ID] {
			t.Fatalf("%s should stay out of direct formal generation and enter through lifecycle seeds", name)
		}
		if ct.DirectlyGeneratable(call.ID) {
			t.Fatalf("%s should not be a formal fresh/insertion generation root", name)
		}
	}
	if call := target.SyscallMap["getpeername$udp"]; call == nil {
		t.Fatalf("missing formal UDP peer name syscall")
	} else if call.Attrs.NoGenerate || !call.Attrs.NoMinimize {
		t.Fatalf("getpeername$udp should remain triageable but no_minimize in formal AFD session")
	}
	for _, name := range []string{
		"send$inet_accept_updated",
		"recv$inet_accept_updated",
		"setsockopt$int_accept_updated",
		"getsockopt$int_accept_updated",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing accept-updated consumer syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("%s should be available only for the formal accept-updated seed", name)
		}
		if ct.DirectlyGeneratable(call.ID) {
			t.Fatalf("%s should stay out of formal fresh/insertion generation", name)
		}
	}
	foundAcceptUpdatedSeed := false
	for _, path := range windowsSeedPrefixMatchesExcept(t, cfg.Experimental.SeedPrefix,
		cfg.Experimental.SeedExcludePrefixes) {
		if strings.HasPrefix(filepath.Base(path), "nyx_afd_accept_updated") {
			foundAcceptUpdatedSeed = true
		}
	}
	if !foundAcceptUpdatedSeed {
		t.Fatalf("formal AFD session should include the validated accept-updated seed")
	}
	acceptExIOCPSeed := filepath.Join("..", "..", "sys", "windows", "test",
		"nyx_afd_acceptex_iocp_local_update.txt")
	data, err := os.ReadFile(acceptExIOCPSeed)
	if err != nil {
		t.Fatalf("read AcceptEx IOCP formal seed: %v", err)
	}
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize AcceptEx IOCP formal seed: %v", err)
	}
	filterCfg := &mgrconfig.Config{
		DisabledSyscalls: cfg.DisabledSyscalls,
		Derived: mgrconfig.Derived{
			Target:          target,
			NoGenerateCalls: noDirect,
		},
	}
	filtered := manager.FilterCandidatesForConfig([]fuzzer.Candidate{{
		Prog:  p,
		Flags: fuzzer.ProgMinimized,
	}}, expanded, filterCfg, true)
	if len(filtered.Candidates) != 1 {
		t.Fatalf("got %d filtered AcceptEx IOCP candidates, want 1", len(filtered.Candidates))
	}
	filteredText := string(filtered.Candidates[0].Prog.Serialize())
	for _, want := range []string{
		"AcceptEx$inet_tcp_pending(",
		"CreateIoCompletionPort$accept_pending(",
		"WSAGetOverlappedResult$accept_pending(",
		"GetQueuedCompletionStatus$socket(",
		"GetAcceptExSockaddrs$inet_tcp(",
		"setsockopt$update_accept_context(",
		"recv$inet_accept_updated(",
	} {
		if !strings.Contains(filteredText, want) {
			t.Fatalf("formal AcceptEx IOCP seed lost %q after filtering:\n%s", want, filteredText)
		}
	}
	for _, forbidden := range []string{
		"CancelIoEx$accept_pending(",
		"CancelIo$accept_pending(",
		"closesocket$accept_pending(",
		"syz_emit_ethernet$windows(",
		"syz_extract_tcp_res$windows",
	} {
		if strings.Contains(filteredText, forbidden) {
			t.Fatalf("formal AcceptEx IOCP seed contains forbidden call %q:\n%s", forbidden, filteredText)
		}
	}
	for _, name := range []string{
		"nyx_afd_public_event_nonblock_tcp.txt",
		"nyx_exp_afd_public_event_nonblock_tcp.txt",
	} {
		path := filepath.Join("..", "..", "sys", "windows", "test", name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		serialized := string(p.Serialize())
		if strings.Contains(serialized, "send$inet_accept(") {
			t.Fatalf("%s must not combine tcp_nonblock event-select/enum with accepted-side send; it bugchecked the Nyx guest:\n%s",
				name, serialized)
		}
		for _, want := range []string{
			"WSAEventSelect$tcp_nonblock",
			"WSAEnumNetworkEvents$tcp_nonblock",
		} {
			if !strings.Contains(serialized, want+"(") {
				t.Fatalf("%s should keep %s coverage in the formal seed:\n%s",
					name, want, serialized)
			}
		}
	}
}

func TestWindowsAfdVNetProvenConfigSeedsStayNarrow(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
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
	skipLegacyAfdWinsockArchived(t)
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-vnet-proven.cfg")
	if cfg.Experimental.ForceGenerateEveryN != 2 {
		t.Fatalf("vnet proven force_generate_every_n=%d, want 2",
			cfg.Experimental.ForceGenerateEveryN)
	}
}

func TestWindowsAfdVNetProvenConfigCoversSeedSyscalls(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
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

func TestWindowsAfdAcceptExIOCPConfigKeepsProofSeedsIsolated(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-acceptex-iocp.cfg")
	if cfg.Experimental.SeedPrefix != "nyx_afd_acceptex_vnet_" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("AcceptEx IOCP seed_prefix=%q borrowing_seed_prefix=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if cfg.Experimental.MaxCallsPerProg < 16 {
		t.Fatalf("AcceptEx IOCP max_calls_per_prog=%d, want at least 16 for sockaddrs/update seed",
			cfg.Experimental.MaxCallsPerProg)
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("AcceptEx IOCP config should disable collide while vnet/helper mutation is unsafe")
	}
	if cfg.VM.KeepState {
		t.Fatal("AcceptEx IOCP config should reload between requests")
	}

	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	var gotSeeds []string
	for _, match := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(match))
	}
	wantSeeds := []string{
		"nyx_afd_acceptex_vnet_cancel.txt",
		"nyx_afd_acceptex_vnet_iocp.txt",
		"nyx_afd_acceptex_vnet_sockaddrs.txt",
	}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("AcceptEx IOCP seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}

	proofOnly := []string{
		"AcceptEx$inet_tcp_pending",
		"CreateIoCompletionPort$accept_pending",
		"WSAGetOverlappedResult$accept_pending",
		"GetQueuedCompletionStatus$socket",
		"GetAcceptExSockaddrs$inet_tcp",
		"setsockopt$update_accept_context",
		"recv$inet_accept_updated",
		"CancelIoEx$accept_pending",
		"CancelIo$accept_pending",
		"closesocket$accept_pending",
		"syz_emit_ethernet$windows",
		"syz_extract_tcp_res$windows_synack",
	}
	noGenerate := make(map[string]bool)
	for _, name := range cfg.Experimental.NoGenerateSyscalls {
		noGenerate[name] = true
	}
	for _, name := range proofOnly {
		if !noGenerate[name] {
			t.Fatalf("AcceptEx IOCP proof call %s should be listed in no_generate_syscalls", name)
		}
	}
	zeroWeight := make(map[string]bool)
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight != 0 {
			continue
		}
		for _, name := range rule.Calls {
			zeroWeight[name] = true
		}
	}
	for _, name := range proofOnly {
		if !zeroWeight[name] {
			t.Fatalf("AcceptEx IOCP proof call %s should have corpus fuzz weight 0", name)
		}
	}

	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	expandedNames := make(map[string]bool, len(syscalls))
	expanded := make(map[*prog.Syscall]bool, len(syscalls))
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		expandedNames[name] = true
		expanded[target.Syscalls[id]] = true
		for _, pattern := range []string{
			"ConnectEx$inet_tcp*",
			"DisconnectEx$inet_tcp*",
			"AcceptEx$inet_tcp",
			"WSARecv$accept*",
			"WSASend$accept*",
			"CreateIoCompletionPort$connect*",
			"CreateIoCompletionPort$tcp_*",
			"WSAGetOverlappedResult$connect*",
			"WSAGetOverlappedResult$tcp_*",
			"CancelIoEx$connect*",
			"CancelIoEx$tcp_*",
			"CancelIo$connect*",
			"CancelIo$tcp_*",
			"closesocket$connect*",
			"closesocket$tcp_*",
			"TransmitPackets$inet_accept*",
			"TransmitFile$inet_accept*",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("AcceptEx IOCP config leaves risky expanded syscall %q enabled via %q",
					name, pattern)
			}
		}
	}
	for _, name := range proofOnly {
		if !expandedNames[name] {
			t.Fatalf("AcceptEx IOCP config must keep proof call %s enabled for seed replay", name)
		}
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		for _, call := range p.Calls {
			if !expandedNames[call.Meta.Name] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-acceptex-iocp.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdAcceptExCancelConfig(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-acceptex-cancel.cfg")
	want := []string{
		"bind$inet_tcp",
		"listen$inet_tcp",
		"AcceptEx$inet_tcp_pending",
		"CreateIoCompletionPort$accept_pending",
		"CancelIoEx$accept_pending",
		"CancelIo$accept_pending",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("AcceptEx cancel enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_exp_afd_acceptex_iocp_cancel" ||
		cfg.Experimental.BorrowingSeedPrefix != "nyx_exp_afd_acceptex_iocp_cancel" {
		t.Fatalf("AcceptEx cancel seed prefixes are wrong: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if strings.HasPrefix(cfg.Experimental.SeedPrefix, "nyx_afd_") {
		t.Fatalf("AcceptEx cancel focused seed %q would be visible to the formal AFD session",
			cfg.Experimental.SeedPrefix)
	}
	if cfg.Experimental.MaxCallsPerProg < 8 {
		t.Fatalf("AcceptEx cancel max_calls_per_prog=%d, want at least 8",
			cfg.Experimental.MaxCallsPerProg)
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("AcceptEx cancel config should disable collide while pending cleanup is isolated")
	}
	if cfg.VM.KeepState {
		t.Fatal("AcceptEx cancel config must reload between requests")
	}

	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{
		"nyx_exp_afd_acceptex_iocp_cancel.txt",
	}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("AcceptEx cancel seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}

	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	expandedNames := make(map[string]bool, len(syscalls))
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		expandedNames[name] = true
		for _, pattern := range []string{
			"connect$inet_tcp*",
			"ConnectEx$inet_tcp*",
			"DisconnectEx$inet_tcp*",
			"AcceptEx$inet_tcp",
			"GetAcceptExSockaddrs$inet_tcp",
			"setsockopt$update_accept_context",
			"recv$inet_accept*",
			"send$inet_accept*",
			"WSARecv$accept*",
			"WSASend$accept*",
			"CreateIoCompletionPort$socket",
			"CreateIoCompletionPort$connect*",
			"CreateIoCompletionPort$tcp_*",
			"CreateIoCompletionPort$accept_recv_pending",
			"CreateIoCompletionPort$accept_send_pending",
			"WSAGetOverlappedResult$*",
			"GetQueuedCompletionStatus$socket",
			"CancelIoEx$connect*",
			"CancelIoEx$tcp_*",
			"CancelIoEx$accept_recv_pending",
			"CancelIoEx$accept_send_pending",
			"CancelIo$connect*",
			"CancelIo$tcp_*",
			"CancelIo$accept_recv_pending",
			"CancelIo$accept_send_pending",
			"closesocket$accept_pending",
			"closesocket$connect*",
			"closesocket$tcp_*",
			"closesocket$accept_recv_pending",
			"closesocket$accept_send_pending",
			"syz_emit_ethernet$windows",
			"syz_extract_tcp_res$windows*",
			"WSAEventSelect$*",
			"WSAEnumNetworkEvents$*",
			"select$afd*",
			"NtDeviceIoControlFile$afd_event_select_accept*",
			"NtDeviceIoControlFile$afd_enum_network_events_accept*",
			"NtDeviceIoControlFile$afd_poll_accept*",
			"TransmitPackets$inet_accept*",
			"TransmitFile$inet_accept*",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("AcceptEx cancel config leaves risky expanded syscall %q enabled via %q",
					name, pattern)
			}
		}
	}
	for _, name := range want {
		if !expandedNames[name] {
			t.Fatalf("AcceptEx cancel config must keep %s enabled for seed replay", name)
		}
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		serialized := string(data)
		for _, want := range []string{
			"AcceptEx$inet_tcp_pending(",
			"CreateIoCompletionPort$accept_pending(",
			"CancelIoEx$accept_pending(",
		} {
			if !strings.Contains(serialized, want) {
				t.Fatalf("AcceptEx cancel seed %s missing %q:\n%s",
					filepath.Base(path), want, serialized)
			}
		}
		for _, forbidden := range []string{
			"CancelIo$accept_pending(",
			"closesocket$accept_pending(",
			"WSAGetOverlappedResult$accept_pending(",
			"GetQueuedCompletionStatus$socket(",
			"GetAcceptExSockaddrs$inet_tcp(",
			"setsockopt$update_accept_context(",
			"syz_emit_ethernet$windows(",
			"syz_extract_tcp_res$windows",
		} {
			if strings.Contains(serialized, forbidden) {
				t.Fatalf("AcceptEx cancel seed %s contains completion/vnet call %q:\n%s",
					filepath.Base(path), forbidden, serialized)
			}
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		if target.RuntimePolicy.ShouldScheduleProgram != nil &&
			!target.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
			t.Fatalf("%s is rejected by the AFD runtime scheduler", filepath.Base(path))
		}
		for _, call := range p.Calls {
			if call.Meta.Attrs.AutomaticHelper {
				continue
			}
			if cfg.Experimental.BorrowingSeedPrefix != "" &&
				call.Meta.Attrs.NoGenerate && !target.GenerateNoGenerateCalls[call.Meta.ID] {
				t.Fatalf("%s uses no_generate syscall %s without an AFD profile generation override",
					filepath.Base(path), call.Meta.Name)
			}
			if !expandedNames[call.Meta.Name] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-acceptex-cancel.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdAcceptExUpdateConfig(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-acceptex-update.cfg")
	want := []string{
		"bind$inet_tcp",
		"listen$inet_tcp",
		"ioctlsocket$fionbio_tcp_created",
		"connect$inet_tcp_nonblock",
		"AcceptEx$inet_tcp_pending",
		"CreateIoCompletionPort$accept_pending",
		"WSAGetOverlappedResult$accept_pending",
		"GetQueuedCompletionStatus$socket",
		"GetAcceptExSockaddrs$inet_tcp",
		"setsockopt$update_accept_context",
		"send$inet_tcp",
		"recv$inet_accept_updated",
		"syz_emit_ethernet$windows",
		"syz_extract_tcp_res$windows_synack",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("AcceptEx update enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_exp_afd_acceptex_iocp_local_update,nyx_afd_acceptex_vnet_iocp,nyx_afd_acceptex_vnet_sockaddrs" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("AcceptEx update seed prefixes are wrong: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if cfg.Experimental.MaxCallsPerProg < 17 {
		t.Fatalf("AcceptEx update max_calls_per_prog=%d, want at least 17",
			cfg.Experimental.MaxCallsPerProg)
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("AcceptEx update config should disable collide while local/vnet completion paths are isolated")
	}
	if cfg.VM.KeepState {
		t.Fatal("AcceptEx update config must reload between requests")
	}
	for _, name := range []string{
		"syz_emit_ethernet$windows",
		"syz_extract_tcp_res$windows_synack",
	} {
		if !slices.Contains(cfg.Experimental.NoGenerateSyscalls, name) {
			t.Fatalf("AcceptEx update should keep vnet helper %q seed-only, no_generate_syscalls=%v",
				name, cfg.Experimental.NoGenerateSyscalls)
		}
	}
	zeroWeight := make(map[string]bool)
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight != 0 {
			continue
		}
		for _, name := range rule.Calls {
			zeroWeight[name] = true
		}
	}
	for _, name := range []string{
		"syz_emit_ethernet$windows",
		"syz_extract_tcp_res$windows_synack",
	} {
		if !zeroWeight[name] {
			t.Fatalf("AcceptEx update vnet helper %s should have corpus fuzz weight 0", name)
		}
	}

	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{
		"nyx_afd_acceptex_vnet_iocp.txt",
		"nyx_afd_acceptex_vnet_sockaddrs.txt",
		"nyx_exp_afd_acceptex_iocp_local_update.txt",
	}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("AcceptEx update seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}

	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	expandedNames := make(map[string]bool, len(syscalls))
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		expandedNames[name] = true
		for _, pattern := range []string{
			"connect$inet_tcp",
			"ConnectEx$inet_tcp*",
			"DisconnectEx$inet_tcp*",
			"AcceptEx$inet_tcp",
			"recv$inet_accept",
			"recv$inet_accept_nonblock",
			"send$inet_accept*",
			"WSARecv$accept*",
			"WSASend$accept*",
			"CreateIoCompletionPort$socket",
			"CreateIoCompletionPort$connect*",
			"CreateIoCompletionPort$tcp_*",
			"CreateIoCompletionPort$accept_recv_pending",
			"CreateIoCompletionPort$accept_send_pending",
			"WSAGetOverlappedResult$socket",
			"WSAGetOverlappedResult$connect*",
			"WSAGetOverlappedResult$tcp_*",
			"WSAGetOverlappedResult$accept_recv_pending",
			"WSAGetOverlappedResult$accept_send_pending",
			"CancelIoEx$*",
			"CancelIo$*",
			"closesocket$*",
			"WSAEventSelect$*",
			"WSAEnumNetworkEvents$*",
			"select$afd*",
			"NtDeviceIoControlFile$afd_event_select_accept*",
			"NtDeviceIoControlFile$afd_enum_network_events_accept*",
			"NtDeviceIoControlFile$afd_poll_accept*",
			"TransmitPackets$inet_accept*",
			"TransmitFile$inet_accept*",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("AcceptEx update config leaves risky expanded syscall %q enabled via %q",
					name, pattern)
			}
		}
	}
	for _, name := range want {
		if !expandedNames[name] {
			t.Fatalf("AcceptEx update config must keep %s enabled for seed replay", name)
		}
	}
	gqcs := target.SyscallMap["GetQueuedCompletionStatus$socket"]
	if gqcs == nil {
		t.Fatal("missing GetQueuedCompletionStatus$socket")
	}
	timeout, ok := gqcs.Args[4].Type.(*prog.ConstType)
	if !ok || timeout.Val != 0 {
		t.Fatalf("GetQueuedCompletionStatus$socket timeout type=%v, want const[0]",
			gqcs.Args[4].Type)
	}
	iocp := target.SyscallMap["CreateIoCompletionPort$accept_pending"]
	if iocp == nil {
		t.Fatal("missing CreateIoCompletionPort$accept_pending")
	}
	completionKey, ok := iocp.Args[2].Type.(*prog.ConstType)
	if !ok || completionKey.Val != 0xafd {
		t.Fatalf("CreateIoCompletionPort$accept_pending CompletionKey type=%v, want const[0xafd]",
			iocp.Args[2].Type)
	}
	threads, ok := iocp.Args[3].Type.(*prog.ConstType)
	if !ok || threads.Val != 0 {
		t.Fatalf("CreateIoCompletionPort$accept_pending NumberOfConcurrentThreads type=%v, want const[0]",
			iocp.Args[3].Type)
	}
	result := target.SyscallMap["WSAGetOverlappedResult$accept_pending"]
	if result == nil {
		t.Fatal("missing WSAGetOverlappedResult$accept_pending")
	}
	fwait, ok := result.Args[3].Type.(*prog.ConstType)
	if !ok || fwait.Val != 0 {
		t.Fatalf("WSAGetOverlappedResult$accept_pending fWait type=%v, want const[0]",
			result.Args[3].Type)
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		serialized := string(data)
		for _, forbidden := range []string{
			"CancelIoEx$accept_pending(",
			"CancelIo$accept_pending(",
			"closesocket$accept_pending(",
			"ConnectEx$",
			"DisconnectEx$",
		} {
			if strings.Contains(serialized, forbidden) {
				t.Fatalf("AcceptEx update seed %s contains forbidden call %q:\n%s",
					filepath.Base(path), forbidden, serialized)
			}
		}
		for _, want := range []string{
			"AcceptEx$inet_tcp_pending(",
			"CreateIoCompletionPort$accept_pending(",
			"WSAGetOverlappedResult$accept_pending(",
			"GetQueuedCompletionStatus$socket(",
			"setsockopt$update_accept_context(",
			"recv$inet_accept_updated(",
		} {
			if !strings.Contains(serialized, want) {
				t.Fatalf("AcceptEx update seed %s missing %q:\n%s",
					filepath.Base(path), want, serialized)
			}
		}
		if strings.Contains(filepath.Base(path), "local_update") {
			for _, want := range []string{
				"connect$inet_tcp_nonblock(",
				"send$inet_tcp(",
			} {
				if !strings.Contains(serialized, want) {
					t.Fatalf("AcceptEx local update seed missing %q:\n%s", want, serialized)
				}
			}
			for _, forbidden := range []string{
				"syz_emit_ethernet$windows(",
				"syz_extract_tcp_res$windows",
			} {
				if strings.Contains(serialized, forbidden) {
					t.Fatalf("AcceptEx local update seed contains vnet call %q:\n%s",
						forbidden, serialized)
				}
			}
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		if target.RuntimePolicy.ShouldScheduleProgram != nil &&
			!target.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
			t.Fatalf("%s is rejected by the AFD runtime scheduler", filepath.Base(path))
		}
		for _, call := range p.Calls {
			if call.Meta.Attrs.AutomaticHelper {
				continue
			}
			if !expandedNames[call.Meta.Name] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-acceptex-update.cfg",
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
	if cfg.VM.Debug {
		t.Fatal("AFD session config must keep vm.debug disabled for formal fuzzing")
	}
}

func TestWindowsAfdSessionKeepsPrivateEventPollSeedOnly(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-session.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	syscallIDs, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls,
		cfg.DisabledSyscalls, mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	noDirect, err := mgrconfig.ParseNoGenerateSyscalls(target, cfg.Experimental.NoGenerateSyscalls)
	if err != nil {
		t.Fatalf("ParseNoGenerateSyscalls: %v", err)
	}
	enabled := make(map[*prog.Syscall]bool, len(syscallIDs))
	for _, id := range syscallIDs {
		enabled[target.Syscalls[id]] = true
	}
	privateEventCalls := []string{
		"NtDeviceIoControlFile$afd_event_select_accept_nonblock",
		"NtDeviceIoControlFile$afd_enum_network_events_accept_nonblock",
		"NtDeviceIoControlFile$afd_poll_accept_nonblock",
	}
	for _, name := range privateEventCalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing private event/poll syscall %q", name)
		}
		if !call.Attrs.NoGenerate || !call.Attrs.NoMinimize {
			t.Fatalf("%s should remain seed-only in formal AFD session", name)
		}
		if !enabled[call] {
			t.Fatalf("%s should stay enabled so focused private event/poll profiles can exercise it", name)
		}
		if !noDirect[call.ID] {
			t.Fatalf("%s should stay out of formal fresh/insertion generation", name)
		}
	}
	formalSeedPaths := make(map[string]string)
	for _, path := range windowsSeedPrefixMatchesExcept(t, cfg.Experimental.SeedPrefix,
		cfg.Experimental.SeedExcludePrefixes) {
		formalSeedPaths[filepath.Base(path)] = path
	}
	for _, seedName := range []string{
		"nyx_afd_private_event_nonblock.txt",
		"nyx_afd_private_event_select_nonblock.txt",
		"nyx_afd_private_enum_events_nonblock.txt",
		"nyx_afd_private_poll_accept_nonblock.txt",
		"nyx_afd_private_accept_immediate.txt",
	} {
		if path := formalSeedPaths[seedName]; path != "" {
			t.Fatalf("formal AFD session should exclude private poll seed %s", seedName)
		}
	}
}

func TestWindowsAfdSessionFormalSeedsUseNonblockingAcceptScaffolds(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-session.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	syscallIDs, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls,
		cfg.DisabledSyscalls, mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	noDirect, err := mgrconfig.ParseNoGenerateSyscalls(target, cfg.Experimental.NoGenerateSyscalls)
	if err != nil {
		t.Fatalf("ParseNoGenerateSyscalls: %v", err)
	}
	enabled := make(map[*prog.Syscall]bool, len(syscallIDs))
	for _, id := range syscallIDs {
		enabled[target.Syscalls[id]] = true
	}
	filterCfg := &mgrconfig.Config{
		DisabledSyscalls: cfg.DisabledSyscalls,
		Derived: mgrconfig.Derived{
			Target:          target,
			NoGenerateCalls: noDirect,
		},
	}
	wantSeeds := map[string][]string{
		"nyx_afd_accept_lifecycle.txt": {
			"getsockname$tcp",
			"getpeername$tcp",
			"getsockname$accept",
			"getpeername$accept",
			"shutdown$tcp_wr",
			"shutdown$accept_rd",
			"closesocket$tcp_shutdown_wr",
			"closesocket$tcp_shutdown_rd",
		},
		"nyx_afd_accept_shutdown_typed.txt": {
			"shutdown$tcp_rd",
			"shutdown$accept_wr",
			"closesocket$tcp_shutdown_rd",
			"closesocket$tcp_shutdown_wr",
		},
		"nyx_afd_accept_option.txt": {
			"setsockopt$int_accept",
			"getsockopt$int_accept",
			"WSARecvEx$inet_accept_nonblock",
		},
		"nyx_afd_wsaioctl_tcp.txt": {
			"WSAIoctl$sio_keepalive_vals",
			"WSAIoctl$sio_get_extension_function_pointer",
		},
		"nyx_afd_tcp_connected_data.txt": {
			"send$inet_tcp",
			"WSASend$tcp",
			"ioctlsocket$fionbio_tcp_connected",
			"recv$inet_tcp_nonblock",
			"WSARecv$tcp_nonblock",
		},
		"nyx_afd_connectex_iocp_local_update.txt": {
			"bind$connectex_tcp",
			"ConnectEx$inet_tcp_pending",
			"CreateIoCompletionPort$connect_pending",
			"WSAGetOverlappedResult$connect_pending",
			"GetQueuedCompletionStatus$socket",
			"setsockopt$update_connect_context",
			"send$inet_tcp",
			"getsockname$tcp",
			"getpeername$tcp",
		},
	}
	for seedName, wantCalls := range wantSeeds {
		path := filepath.Join("..", "..", "sys", "windows", "test", seedName)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", seedName, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", seedName, err)
		}
		serialized := string(p.Serialize())
		for _, forbidden := range []string{
			"socket$listener_tcp(",
			"socket$connected_tcp(",
			"socket$accept_tcp(",
			"connect$inet_tcp(",
			"accept$inet_tcp(",
			"recv$inet_accept(",
			"WSARecv$accept(",
			"WSARecvEx$inet_accept(",
			"select$afd_basic(",
			"select$afd_accept_nonblock(",
			"ioctlsocket$fionbio_accept(",
			"closesocket$any(",
			"WSAIoctl$sio_udp_connreset(",
		} {
			if strings.Contains(serialized, forbidden) {
				t.Fatalf("%s uses stale formal seed call %q:\n%s", seedName, forbidden, serialized)
			}
		}
		filtered := manager.FilterCandidatesForConfig([]fuzzer.Candidate{{
			Prog:  p,
			Flags: fuzzer.ProgMinimized,
		}}, enabled, filterCfg, true)
		if len(filtered.Candidates) != 1 {
			t.Fatalf("got %d filtered candidates for %s, want 1", len(filtered.Candidates), seedName)
		}
		filteredText := string(filtered.Candidates[0].Prog.Serialize())
		for _, name := range wantCalls {
			if !strings.Contains(filteredText, name+"(") {
				t.Fatalf("%s lost %s after formal filtering:\n%s", seedName, name, filteredText)
			}
		}
	}
}

func TestWindowsAfdSessionIncludesSplitTransmitNonblockSeeds(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-session.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	syscallIDs, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls,
		cfg.DisabledSyscalls, mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	enabled := make(map[*prog.Syscall]bool, len(syscallIDs))
	for _, id := range syscallIDs {
		enabled[target.Syscalls[id]] = true
	}
	filterCfg := &mgrconfig.Config{
		DisabledSyscalls: cfg.DisabledSyscalls,
		Derived: mgrconfig.Derived{
			Target: target,
		},
	}

	allTransmitCalls := []string{
		"WriteFile$afd_transmit",
		"TransmitFile$inet_accept_nonblock",
		"TransmitPackets$inet_accept_nonblock",
	}
	for _, name := range allTransmitCalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing formal transmit syscall %q", name)
		}
		if !enabled[call] {
			t.Fatalf("%s should be enabled in formal AFD session", name)
		}
	}

	wantSeeds := map[string][]string{
		"nyx_afd_transmit_packets_nonblock.txt": {
			"TransmitPackets$inet_accept_nonblock",
		},
	}
	seenSeeds := make(map[string]bool)
	for _, path := range windowsSeedPrefixMatchesExcept(t, cfg.Experimental.SeedPrefix,
		cfg.Experimental.SeedExcludePrefixes) {
		base := filepath.Base(path)
		if base == "nyx_afd_transmit_nonblock.txt" {
			t.Fatalf("formal AFD session should exclude %s; it bugchecked the Nyx guest during candidate deflake",
				base)
		}
		wantCalls, ok := wantSeeds[base]
		if !ok {
			continue
		}
		seenSeeds[base] = true
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		serialized := string(p.Serialize())
		for _, forbidden := range []string{
			"TransmitFile$inet_accept(",
			"TransmitPackets$inet_accept(",
			"connect$inet_tcp(",
			"accept$inet_tcp(",
			"socket$accept_tcp(",
			"CreatePipe$anon(",
			"AddFontMemResourceEx(",
			"WriteFile(",
		} {
			if strings.Contains(serialized, forbidden) {
				t.Fatalf("formal transmit seed %s uses risky call %q:\n%s",
					base, forbidden, serialized)
			}
		}
		if strings.Contains(serialized, "TransmitFile$inet_accept_nonblock(") &&
			strings.Contains(serialized, "TransmitPackets$inet_accept_nonblock(") {
			t.Fatalf("formal transmit seed %s should not combine TransmitFile and TransmitPackets:\n%s",
				base, serialized)
		}
		filtered := manager.FilterCandidatesForConfig([]fuzzer.Candidate{{
			Prog:  p,
			Flags: fuzzer.ProgMinimized,
		}}, enabled, filterCfg, true)
		if len(filtered.Candidates) != 1 {
			t.Fatalf("got %d filtered transmit seed candidates for %s, want 1",
				len(filtered.Candidates), base)
		}
		filteredText := string(filtered.Candidates[0].Prog.Serialize())
		for _, name := range wantCalls {
			if !strings.Contains(filteredText, name+"(") {
				t.Fatalf("formal transmit seed %s lost %s after config filtering:\n%s",
					base, name, filteredText)
			}
			if name == "CreateFileA$afd_transmit" {
				call := target.SyscallMap[name]
				if call == nil {
					t.Fatalf("missing formal transmit helper %q", name)
				}
				if !target.CallIsAutomaticHelper(call) {
					t.Fatalf("%s should be an automatic helper in formal AFD session", name)
				}
			}
		}
		for _, name := range allTransmitCalls {
			if slices.Contains(wantCalls, name) {
				continue
			}
			if strings.Contains(filteredText, name+"(") {
				t.Fatalf("formal transmit seed %s unexpectedly contains %s after filtering:\n%s",
					base, name, filteredText)
			}
		}
	}
	for name := range wantSeeds {
		if !seenSeeds[name] {
			t.Fatalf("formal AFD session should include split transmit seed %s", name)
		}
	}
}

func TestWindowsTransmitPacketsArgumentsStayBounded(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, name := range []string{
		"TransmitPackets$inet_accept",
		"TransmitPackets$inet_accept_nonblock",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		sendSize, ok := call.Args[3].Type.(*prog.ConstType)
		if !ok {
			t.Fatalf("%s nSendSize type is %T, want *prog.ConstType", name, call.Args[3].Type)
		}
		if sendSize.Val != 0 {
			t.Fatalf("%s nSendSize=%#x, want 0", name, sendSize.Val)
		}
		flags, ok := call.Args[5].Type.(*prog.ConstType)
		if !ok {
			t.Fatalf("%s dwFlags type is %T, want *prog.ConstType", name, call.Args[5].Type)
		}
		if flags.Val != 0 {
			t.Fatalf("%s dwFlags=%#x, want 0", name, flags.Val)
		}
	}
}

func TestWindowsWSAStartupVersionStaysWinsock2(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	call := target.SyscallMap["WSAStartup"]
	if call == nil {
		t.Fatal("missing WSAStartup")
	}
	version, ok := call.Args[0].Type.(*prog.ConstType)
	if !ok {
		t.Fatalf("WSAStartup version type is %T, want *prog.ConstType", call.Args[0].Type)
	}
	if version.Val != 0x202 {
		t.Fatalf("WSAStartup version=%#x, want 0x202", version.Val)
	}
}

func TestWindowsWSABufferPayloadsStayBounded(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, tc := range []struct {
		callName string
		argIndex int
	}{
		{"WSASendTo$udp", 1},
		{"WSASend$tcp", 1},
		{"WSARecv$tcp_nonblock", 1},
	} {
		call := target.SyscallMap[tc.callName]
		if call == nil {
			t.Fatalf("missing syscall %q", tc.callName)
		}
		if tc.argIndex >= len(call.Args) {
			t.Fatalf("%s missing arg %d", tc.callName, tc.argIndex)
		}
		ptr, ok := call.Args[tc.argIndex].Type.(*prog.PtrType)
		if !ok {
			t.Fatalf("%s arg %d type is %T, want *prog.PtrType",
				tc.callName, tc.argIndex, call.Args[tc.argIndex].Type)
		}
		buffers, ok := ptr.Elem.(*prog.ArrayType)
		if !ok {
			t.Fatalf("%s arg %d elem is %T, want *prog.ArrayType",
				tc.callName, tc.argIndex, ptr.Elem)
		}
		wsabuf, ok := buffers.Elem.(*prog.StructType)
		if !ok {
			t.Fatalf("%s buffer elem is %T, want *prog.StructType",
				tc.callName, buffers.Elem)
		}
		var payload prog.Type
		for _, field := range wsabuf.Fields {
			if field.Name != "buf" {
				continue
			}
			bufPtr, ok := field.Type.(*prog.PtrType)
			if !ok {
				t.Fatalf("%s WSABUF.buf type is %T, want *prog.PtrType",
					tc.callName, field.Type)
			}
			payload = bufPtr.Elem
			break
		}
		if payload == nil {
			t.Fatalf("%s WSABUF has no buf field", tc.callName)
		}
		switch payload := payload.(type) {
		case *prog.ArrayType:
			if payload.Kind != prog.ArrayRangeLen || payload.RangeBegin != 0 || payload.RangeEnd != 256 {
				t.Fatalf("%s WSABUF payload array range=%d:%d kind=%v, want 0:256 range",
					tc.callName, payload.RangeBegin, payload.RangeEnd, payload.Kind)
			}
		case *prog.BufferType:
			if payload.Kind != prog.BufferBlobRange || payload.RangeBegin != 0 || payload.RangeEnd != 256 {
				t.Fatalf("%s WSABUF payload buffer range=%d:%d kind=%v, want 0:256 range",
					tc.callName, payload.RangeBegin, payload.RangeEnd, payload.Kind)
			}
		default:
			t.Fatalf("%s WSABUF.buf elem is %T, want bounded array/buffer",
				tc.callName, payload)
		}
	}
}

func TestWindowsAfdSessionIncludesRecvMsgNonblockSeed(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-session.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	var seedPath string
	for _, path := range windowsSeedPrefixMatchesExcept(t, cfg.Experimental.SeedPrefix,
		cfg.Experimental.SeedExcludePrefixes) {
		if filepath.Base(path) == "nyx_afd_recvmsg_nonblock.txt" {
			seedPath = path
			break
		}
	}
	if seedPath == "" {
		t.Fatal("formal AFD session should include the nonblocking recvmsg seed")
	}
	data, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("read %s: %v", seedPath, err)
	}
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize %s: %v", seedPath, err)
	}
	serialized := string(p.Serialize())
	for _, forbidden := range []string{
		"WSARecvMsg$udp(",
		"recv$inet_udp(",
		"recvfrom$udp_bound(",
		"socket$connected_udp(",
		"WSAIoctl$sio_udp_connreset(",
	} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("formal recvmsg seed %s uses risky call %q:\n%s",
				filepath.Base(seedPath), forbidden, serialized)
		}
	}
	syscallIDs, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls,
		cfg.DisabledSyscalls, mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	noDirect, err := mgrconfig.ParseNoGenerateSyscalls(target, cfg.Experimental.NoGenerateSyscalls)
	if err != nil {
		t.Fatalf("ParseNoGenerateSyscalls: %v", err)
	}
	enabled := make(map[*prog.Syscall]bool, len(syscallIDs))
	for _, id := range syscallIDs {
		enabled[target.Syscalls[id]] = true
	}
	filterCfg := &mgrconfig.Config{
		DisabledSyscalls: cfg.DisabledSyscalls,
		Derived: mgrconfig.Derived{
			Target:          target,
			NoGenerateCalls: noDirect,
		},
	}
	filtered := manager.FilterCandidatesForConfig([]fuzzer.Candidate{{
		Prog:  p,
		Flags: fuzzer.ProgMinimized,
	}}, enabled, filterCfg, true)
	if len(filtered.Candidates) != 1 {
		t.Fatalf("got %d filtered recvmsg seed candidates, want 1", len(filtered.Candidates))
	}
	filteredText := string(filtered.Candidates[0].Prog.Serialize())
	recvmsg := target.SyscallMap["WSARecvMsg$udp_nonblock"]
	if recvmsg == nil {
		t.Fatal("missing WSARecvMsg$udp_nonblock")
	}
	if !enabled[recvmsg] {
		t.Fatal("WSARecvMsg$udp_nonblock should stay enabled in formal AFD session")
	}
	if !noDirect[recvmsg.ID] {
		t.Fatal("WSARecvMsg$udp_nonblock should stay out of formal fresh generation")
	}
	if !strings.Contains(filteredText, "WSARecvMsg$udp_nonblock(") {
		t.Fatalf("formal recvmsg seed lost WSARecvMsg$udp_nonblock after config filtering:\n%s",
			filteredText)
	}
}

func TestWindowsAfdSessionIncludesPrivateReadonlyQuerySeeds(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-session.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	syscallIDs, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls,
		cfg.DisabledSyscalls, mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	noDirect, err := mgrconfig.ParseNoGenerateSyscalls(target, cfg.Experimental.NoGenerateSyscalls)
	if err != nil {
		t.Fatalf("ParseNoGenerateSyscalls: %v", err)
	}
	enabled := make(map[*prog.Syscall]bool, len(syscallIDs))
	for _, id := range syscallIDs {
		enabled[target.Syscalls[id]] = true
	}
	filterCfg := &mgrconfig.Config{
		DisabledSyscalls: cfg.DisabledSyscalls,
		Derived: mgrconfig.Derived{
			Target:          target,
			NoGenerateCalls: noDirect,
		},
	}
	for _, tc := range []struct {
		seedName string
		want     []string
	}{
		{
			seedName: "nyx_afd_private_tcp_query_nonblock.txt",
			want: []string{
				"NtDeviceIoControlFile$afd_query_recv_tcp",
				"NtDeviceIoControlFile$afd_query_handles_tcp",
				"NtDeviceIoControlFile$afd_get_remote_address_tcp",
				"NtDeviceIoControlFile$afd_get_context_tcp",
				"NtDeviceIoControlFile$afd_get_qos_tcp",
				"NtDeviceIoControlFile$afd_noop_tcp",
			},
		},
		{
			seedName: "nyx_afd_private_udp_query_nonblock.txt",
			want: []string{
				"WSAIoctl$sio_address_list_query",
				"WSAIoctl$sio_get_interface_list",
				"NtDeviceIoControlFile$afd_address_list_query_udp",
				"NtDeviceIoControlFile$afd_query_handles_udp",
				"NtDeviceIoControlFile$afd_get_qos_udp",
				"NtDeviceIoControlFile$afd_noop_udp",
				"WSAIoctl$sio_routing_interface_query",
				"NtDeviceIoControlFile$afd_routing_interface_query_udp",
				"NtDeviceIoControlFile$afd_query_handles_udp_peer",
			},
		},
	} {
		var seedPath string
		for _, path := range windowsSeedPrefixMatchesExcept(t, cfg.Experimental.SeedPrefix,
			cfg.Experimental.SeedExcludePrefixes) {
			if filepath.Base(path) == tc.seedName {
				seedPath = path
				break
			}
		}
		if seedPath == "" {
			t.Fatalf("formal AFD session should include %s", tc.seedName)
		}
		data, err := os.ReadFile(seedPath)
		if err != nil {
			t.Fatalf("read %s: %v", seedPath, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", seedPath, err)
		}
		serialized := string(p.Serialize())
		for _, forbidden := range []string{
			"connect$inet_tcp(",
			"accept$inet_tcp(",
			"socket$bound_udp(",
			"socket$connected_udp(",
			"socket$accept_tcp(",
			"closesocket$any(",
			"NtDeviceIoControlFile$afd_query_recv_accept(",
			"NtDeviceIoControlFile$afd_event_select_accept",
			"NtDeviceIoControlFile$afd_enum_network_events_accept",
			"NtDeviceIoControlFile$afd_poll_accept",
		} {
			if strings.Contains(serialized, forbidden) {
				t.Fatalf("%s uses formal-risky scaffold %q:\n%s",
					tc.seedName, forbidden, serialized)
			}
		}
		filtered := manager.FilterCandidatesForConfig([]fuzzer.Candidate{{
			Prog:  p,
			Flags: fuzzer.ProgMinimized,
		}}, enabled, filterCfg, true)
		if len(filtered.Candidates) != 1 {
			t.Fatalf("got %d filtered private readonly seed candidates for %s, want 1",
				len(filtered.Candidates), tc.seedName)
		}
		filteredText := string(filtered.Candidates[0].Prog.Serialize())
		for _, name := range tc.want {
			call := target.SyscallMap[name]
			if call == nil {
				t.Fatalf("missing private readonly syscall %q", name)
			}
			if !enabled[call] {
				t.Fatalf("%s should stay enabled in formal AFD session", name)
			}
			if !call.Attrs.NoGenerate && !noDirect[call.ID] {
				t.Fatalf("%s should stay out of formal fresh generation", name)
			}
			if !strings.Contains(filteredText, name+"(") {
				t.Fatalf("%s lost %s after formal filtering:\n%s",
					tc.seedName, name, filteredText)
			}
		}
	}
}

func TestWindowsAfdSessionIncludesUdpLifecycleSeed(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-session.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	syscallIDs, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls,
		cfg.DisabledSyscalls, mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	noDirect, err := mgrconfig.ParseNoGenerateSyscalls(target, cfg.Experimental.NoGenerateSyscalls)
	if err != nil {
		t.Fatalf("ParseNoGenerateSyscalls: %v", err)
	}
	enabled := make(map[*prog.Syscall]bool, len(syscallIDs))
	for _, id := range syscallIDs {
		enabled[target.Syscalls[id]] = true
	}
	filterCfg := &mgrconfig.Config{
		DisabledSyscalls: cfg.DisabledSyscalls,
		Derived: mgrconfig.Derived{
			Target:          target,
			NoGenerateCalls: noDirect,
		},
	}
	seedPath := filepath.Join("..", "..", "sys", "windows", "test", "nyx_afd_udp_lifecycle.txt")
	data, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("read %s: %v", seedPath, err)
	}
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize %s: %v", seedPath, err)
	}
	filtered := manager.FilterCandidatesForConfig([]fuzzer.Candidate{{
		Prog:  p,
		Flags: fuzzer.ProgMinimized,
	}}, enabled, filterCfg, true)
	if len(filtered.Candidates) != 1 {
		t.Fatalf("got %d filtered UDP lifecycle seed candidates, want 1", len(filtered.Candidates))
	}
	filteredText := string(filtered.Candidates[0].Prog.Serialize())
	for _, want := range []string{
		"socket$inet_udp(",
		"bind$inet_udp(",
		"connect$inet_udp(",
		"getsockname$udp(",
		"getpeername$udp(",
	} {
		if !strings.Contains(filteredText, want) {
			t.Fatalf("formal UDP lifecycle seed lost %s after filtering:\n%s", want, filteredText)
		}
	}
	for _, forbidden := range []string{
		"socket$connected_udp(",
		"socket$bound_udp(",
		"getpeername$udp(r0, 0x0, 0x0)",
	} {
		if strings.Contains(filteredText, forbidden) {
			t.Fatalf("formal UDP lifecycle seed uses stale/risky shape %q:\n%s", forbidden, filteredText)
		}
	}
}

func TestWindowsAfdSessionIncludesUdpDataSeeds(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-session.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	syscallIDs, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls,
		cfg.DisabledSyscalls, mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	noDirect, err := mgrconfig.ParseNoGenerateSyscalls(target, cfg.Experimental.NoGenerateSyscalls)
	if err != nil {
		t.Fatalf("ParseNoGenerateSyscalls: %v", err)
	}
	enabled := make(map[*prog.Syscall]bool, len(syscallIDs))
	for _, id := range syscallIDs {
		enabled[target.Syscalls[id]] = true
	}
	filterCfg := &mgrconfig.Config{
		DisabledSyscalls: cfg.DisabledSyscalls,
		Derived: mgrconfig.Derived{
			Target:          target,
			NoGenerateCalls: noDirect,
		},
	}
	wantSeeds := map[string][]string{
		"nyx_afd_udp_data.txt": {
			"send$inet_udp(",
			"recv$inet_udp_nonblock(",
			"ioctlsocket$fionbio_udp(",
		},
		"nyx_afd_udp_sendrecv_families.txt": {
			"send$inet_udp(",
			"sendto$udp_connected(",
			"WSASendTo$udp(",
			"WSASendTo$udp_bound(",
			"sendto$udp_bound(",
		},
	}
	for seedName, wantCalls := range wantSeeds {
		seedPath := filepath.Join("..", "..", "sys", "windows", "test", seedName)
		data, err := os.ReadFile(seedPath)
		if err != nil {
			t.Fatalf("read %s: %v", seedPath, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", seedPath, err)
		}
		filtered := manager.FilterCandidatesForConfig([]fuzzer.Candidate{{
			Prog:  p,
			Flags: fuzzer.ProgMinimized,
		}}, enabled, filterCfg, true)
		if len(filtered.Candidates) != 1 {
			t.Fatalf("got %d filtered candidates for %s, want 1", len(filtered.Candidates), seedName)
		}
		filteredText := string(filtered.Candidates[0].Prog.Serialize())
		for _, want := range append([]string{
			"socket$inet_udp(",
			"bind$inet_udp(",
			"connect$inet_udp(",
		}, wantCalls...) {
			if !strings.Contains(filteredText, want) {
				t.Fatalf("%s lost %s after formal filtering:\n%s", seedName, want, filteredText)
			}
		}
		for _, forbidden := range []string{
			"socket$connected_udp(",
			"socket$bound_udp(",
			"recv$inet_udp(",
			"recvfrom$udp_bound(",
			"recvfrom$udp_connected(",
			"WSARecvFrom$udp(",
		} {
			if strings.Contains(filteredText, forbidden) {
				t.Fatalf("%s uses stale/blocking UDP shape %q:\n%s", seedName, forbidden, filteredText)
			}
		}
	}
}

func TestWindowsAfdPrivateConfigCoversEndpointState(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-private.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	want := []string{
		"NtCreateFile$afd_tcp_endpoint",
		"NtCreateFile$afd_udp_endpoint",
		"NtDeviceIoControlFile$afd_bind_tcp",
		"NtDeviceIoControlFile$afd_bind_tcp_nonblock",
		"NtDeviceIoControlFile$afd_bind_udp",
		"NtDeviceIoControlFile$afd_bind_udp_nonblock",
		"NtDeviceIoControlFile$afd_connect_tcp",
		"NtDeviceIoControlFile$afd_connect_tcp_nonblock",
		"NtDeviceIoControlFile$afd_connect_tcp_to_listener",
		"NtDeviceIoControlFile$afd_connect_tcp_to_listener_nonblock",
		"NtDeviceIoControlFile$afd_connect_tcp_to_delayed_listener",
		"NtDeviceIoControlFile$afd_connect_tcp_to_delayed_listener_nonblock",
		"NtDeviceIoControlFile$afd_connect_udp",
		"NtDeviceIoControlFile$afd_connect_udp_nonblock",
		"NtDeviceIoControlFile$afd_start_listen_tcp",
		"NtDeviceIoControlFile$afd_start_listen_tcp_nonblock",
		"NtDeviceIoControlFile$afd_start_listen_tcp_delayed",
		"NtDeviceIoControlFile$afd_start_listen_tcp_delayed_nonblock",
		"NtDeviceIoControlFile$afd_wait_for_listen_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_tcp_nonblock",
		"NtDeviceIoControlFile$afd_wait_for_listen_delayed_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_delayed_tcp_nonblock",
		"NtDeviceIoControlFile$afd_wait_for_listen_lifo_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_lifo_tcp_nonblock",
		"NtDeviceIoControlFile$afd_wait_for_listen_pending_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_pending_tcp_nonblock",
		"NtDeviceIoControlFile$afd_wait_for_listen_lifo_pending_tcp",
		"NtDeviceIoControlFile$afd_wait_for_listen_lifo_pending_tcp_nonblock",
		"NtDeviceIoControlFile$afd_accept_tcp",
		"NtDeviceIoControlFile$afd_accept_tcp_nonblock",
		"NtDeviceIoControlFile$afd_super_accept_tcp",
		"NtDeviceIoControlFile$afd_super_accept_tcp_nonblock",
		"NtDeviceIoControlFile$afd_defer_accept_requeue_tcp",
		"NtDeviceIoControlFile$afd_defer_accept_requeue_tcp_nonblock",
		"NtDeviceIoControlFile$afd_defer_accept_reject_tcp",
		"NtDeviceIoControlFile$afd_defer_accept_reject_tcp_nonblock",
		"NtDeviceIoControlFile$afd_get_unaccepted_connect_data_tcp",
		"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_created",
		"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_bound",
		"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_accepted",
		"NtDeviceIoControlFile$afd_set_information_nonblock_udp_created",
		"NtDeviceIoControlFile$afd_set_information_nonblock_udp_bound",
		"NtDeviceIoControlFile$afd_set_information_nonblock_udp_peered",
		"NtDeviceIoControlFile$afd_get_information_tcp",
		"NtDeviceIoControlFile$afd_get_information_udp",
		"NtDeviceIoControlFile$afd_get_address_tcp",
		"NtDeviceIoControlFile$afd_get_address_udp",
		"NtDeviceIoControlFile$afd_query_recv_tcp",
		"NtDeviceIoControlFile$afd_query_handles_tcp",
		"NtDeviceIoControlFile$afd_query_handles_udp",
		"NtDeviceIoControlFile$afd_get_remote_address_tcp",
		"NtDeviceIoControlFile$afd_set_context_tcp",
		"NtDeviceIoControlFile$afd_set_context_udp",
		"NtDeviceIoControlFile$afd_get_context_tcp",
		"NtDeviceIoControlFile$afd_get_context_udp",
		"NtDeviceIoControlFile$afd_set_send_connect_data_tcp",
		"NtDeviceIoControlFile$afd_set_send_connect_options_tcp",
		"NtDeviceIoControlFile$afd_set_send_disconnect_data_tcp",
		"NtDeviceIoControlFile$afd_set_send_disconnect_options_tcp",
		"NtDeviceIoControlFile$afd_set_receive_connect_data_length_tcp",
		"NtDeviceIoControlFile$afd_set_receive_connect_options_length_tcp",
		"NtDeviceIoControlFile$afd_set_receive_disconnect_data_length_tcp",
		"NtDeviceIoControlFile$afd_set_receive_disconnect_options_length_tcp",
		"NtDeviceIoControlFile$afd_get_receive_connect_data_tcp",
		"NtDeviceIoControlFile$afd_get_receive_connect_options_tcp",
		"NtDeviceIoControlFile$afd_get_receive_disconnect_data_tcp",
		"NtDeviceIoControlFile$afd_get_receive_disconnect_options_tcp",
		"NtDeviceIoControlFile$afd_set_send_connect_data_udp",
		"NtDeviceIoControlFile$afd_set_send_connect_options_udp",
		"NtDeviceIoControlFile$afd_set_send_disconnect_data_udp",
		"NtDeviceIoControlFile$afd_set_send_disconnect_options_udp",
		"NtDeviceIoControlFile$afd_set_receive_connect_data_length_udp",
		"NtDeviceIoControlFile$afd_set_receive_connect_options_length_udp",
		"NtDeviceIoControlFile$afd_set_receive_disconnect_data_length_udp",
		"NtDeviceIoControlFile$afd_set_receive_disconnect_options_length_udp",
		"NtDeviceIoControlFile$afd_get_receive_connect_data_udp",
		"NtDeviceIoControlFile$afd_get_receive_connect_options_udp",
		"NtDeviceIoControlFile$afd_get_receive_disconnect_data_udp",
		"NtDeviceIoControlFile$afd_get_receive_disconnect_options_udp",
		"NtDeviceIoControlFile$afd_set_returned_receive_connect_data_length_tcp",
		"NtDeviceIoControlFile$afd_set_returned_receive_connect_options_length_tcp",
		"NtDeviceIoControlFile$afd_set_returned_receive_disconnect_data_length_tcp",
		"NtDeviceIoControlFile$afd_set_returned_receive_disconnect_options_length_tcp",
		"NtDeviceIoControlFile$afd_get_returned_receive_connect_data_length_tcp",
		"NtDeviceIoControlFile$afd_get_returned_receive_connect_options_length_tcp",
		"NtDeviceIoControlFile$afd_get_returned_receive_disconnect_data_length_tcp",
		"NtDeviceIoControlFile$afd_get_returned_receive_disconnect_options_length_tcp",
		"NtDeviceIoControlFile$afd_get_qos_tcp",
		"NtDeviceIoControlFile$afd_get_qos_udp",
		"NtDeviceIoControlFile$afd_noop_tcp",
		"NtDeviceIoControlFile$afd_noop_accept_pending",
		"NtDeviceIoControlFile$afd_noop_accept_pending_nonblock",
		"NtDeviceIoControlFile$afd_noop_udp",
		"NtDeviceIoControlFile$afd_address_list_query_udp",
		"NtDeviceIoControlFile$afd_routing_interface_query_udp",
		"NtDeviceIoControlFile$afd_address_list_change_udp_nonblock",
		"NtDeviceIoControlFile$afd_routing_interface_change_udp_nonblock",
		"NtDeviceIoControlFile$afd_send_udp_peer",
		"NtDeviceIoControlFile$afd_send_udp_peer_nonblock",
		"NtDeviceIoControlFile$afd_send_datagram_udp_bound",
		"NtDeviceIoControlFile$afd_send_datagram_udp_bound_nonblock",
		"NtDeviceIoControlFile$afd_receive_datagram_udp_bound_nonblock",
		"NtDeviceIoControlFile$afd_receive_datagram_udp_peer_nonblock",
		"NtDeviceIoControlFile$afd_send_accept",
		"NtDeviceIoControlFile$afd_send_accept_nonblock",
		"NtDeviceIoControlFile$afd_receive_accept_nonblock",
		"NtDeviceIoControlFile$afd_transmit_file_tcp_nonblock",
		"NtDeviceIoControlFile$afd_transmit_file_accept_nonblock",
		"NtDeviceIoControlFile$afd_transmit_packets_tcp_nonblock",
		"NtDeviceIoControlFile$afd_transmit_packets_accept_nonblock",
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
	if cfg.Experimental.SeedPrefix != "nyx_afd_private_core_" ||
		cfg.Experimental.BorrowingSeedPrefix != "nyx_afd_private_core_" {
		t.Fatalf("private AFD seed prefixes are too broad: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if cfg.VM.KeepState {
		t.Fatal("private AFD config must reload between requests for core query isolation")
	}

	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	forbidden := []string{
		"WSAStartup",
		"socket$inet_*",
		"connect$inet_tcp",
		"connect$inet_tcp_nonblock",
		"recv$inet_tcp",
		"WSARecv$tcp",
		"ioctlsocket$fionbio_*",
		"setsockopt$int_*",
		"getsockopt$int_*",
		"getsockname$*",
		"getpeername$*",
		"WSAIoctl$sio_*",
		"WSAEventSelect$tcp",
		"WSAEnumNetworkEvents$tcp",
		"ConnectEx$inet_tcp*",
		"DisconnectEx$inet_tcp*",
		"recv$inet_udp",
		"recvfrom$udp_bound",
		"recvfrom$udp_connected",
		"WSARecvFrom$udp",
		"WSARecvMsg$udp",
		"accept$inet_tcp",
		"socket$accept_tcp",
		"recv$inet_accept",
		"WSARecv$accept",
		"WSARecvEx$inet_accept",
		"CreateIoCompletionPort$*",
		"GetQueuedCompletionStatus$socket",
		"WSAGetOverlappedResult$*",
		"CancelIoEx$*",
		"CancelIo$*",
		"AcceptEx$inet_tcp*",
		"TransmitPackets$inet_accept",
		"TransmitFile$inet_accept",
	}
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		for _, pattern := range forbidden {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("private AFD config leaves risky expanded syscall %q enabled via %q",
					name, pattern)
			}
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
	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{
		"nyx_afd_private_core_endpoint_tcp.txt",
		"nyx_afd_private_core_endpoint_udp.txt",
		"nyx_afd_private_core_listen_accept.txt",
		"nyx_afd_private_core_readonly.txt",
	}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("private AFD core seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		for _, call := range p.Calls {
			if call.Meta.Name == "connect$inet_tcp" ||
				call.Meta.Name == "accept$inet_tcp" ||
				call.Meta.Name == "socket$accept_tcp" ||
				strings.HasPrefix(call.Meta.Name, "recv$inet_accept") ||
				strings.HasPrefix(call.Meta.Name, "WSARecv$accept") ||
				strings.HasPrefix(call.Meta.Name, "WSARecvEx$inet_accept") {
				t.Fatalf("%s uses non-core private scaffold %s",
					filepath.Base(path), call.Meta.Name)
			}
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

func TestWindowsAfdPrivateAcceptConfigUsesNonblockingAcceptOnly(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-private-accept.cfg")
	want := []string{
		"ioctlsocket$fionbio_listener",
		"ioctlsocket$fionbio_tcp_created",
		"connect$inet_tcp_nonblock",
		"accept$inet_tcp_nonblock",
		"NtDeviceIoControlFile$afd_query_recv_accept",
		"NtDeviceIoControlFile$afd_query_handles_accept",
		"NtDeviceIoControlFile$afd_get_qos_accept",
		"NtDeviceIoControlFile$afd_noop_accept",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("private accept AFD enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_afd_private_accept_immediate" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("private accept AFD seed prefixes are too broad: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if cfg.Experimental.ForceGenerateEveryN != 1 {
		t.Fatalf("private accept AFD force_generate_every_n=%d, want 1",
			cfg.Experimental.ForceGenerateEveryN)
	}
	if cfg.VM.KeepState {
		t.Fatal("private accept AFD config should reload between requests while isolating accept IOCTLs")
	}
	for _, name := range cfg.EnabledSyscalls {
		for _, pattern := range []string{
			"socket$accept_tcp",
			"WSAEventSelect$accept",
			"WSAEnumNetworkEvents$accept",
			"NtDeviceIoControlFile$afd_event_select_accept*",
			"NtDeviceIoControlFile$afd_enum_network_events_accept*",
			"NtDeviceIoControlFile$afd_poll_accept*",
			"CreateIoCompletionPort$accept*",
			"AcceptEx$inet_tcp*",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("private accept AFD config directly enables risky syscall %q via %q",
					name, pattern)
			}
		}
	}
}

func TestWindowsAfdPrivateAcceptConfigCoversSeedSyscalls(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-private-accept.cfg")
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
			for _, forbidden := range []string{
				"connect$inet_tcp",
				"accept$inet_tcp",
				"socket$accept_tcp",
			} {
				if call.Meta.Name == forbidden {
					t.Fatalf("%s uses blocking accept scaffold %s",
						filepath.Base(path), call.Meta.Name)
				}
			}
			if call.Meta.Attrs.NoGenerate || call.Meta.Attrs.AutomaticHelper {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-private-accept.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdAcceptUpdatedConfigStaysFocused(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-accept-updated.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	want := []string{
		"ioctlsocket$fionbio_tcp_created",
		"connect$inet_tcp_nonblock",
		"AcceptEx$inet_tcp_pending",
		"CreateIoCompletionPort$accept_pending",
		"WSAGetOverlappedResult$accept_pending",
		"GetQueuedCompletionStatus$socket",
		"setsockopt$update_accept_context",
		"send$inet_tcp",
		"send$inet_accept_updated",
		"recv$inet_accept_updated",
		"setsockopt$int_accept_updated",
		"getsockopt$int_accept_updated",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("accept-updated AFD enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_exp_afd_accept_updated" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("accept-updated AFD seed should stay regular-seed-only: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if cfg.Experimental.MaxCallsPerProg < 18 {
		t.Fatalf("accept-updated AFD max_calls_per_prog=%d, want at least 18 for full AcceptEx/update-context seed",
			cfg.Experimental.MaxCallsPerProg)
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("accept-updated AFD config should disable collide while testing AcceptEx/update context")
	}
	if cfg.VM.KeepState {
		t.Fatal("accept-updated AFD config should reload between requests")
	}
	noDirect, err := mgrconfig.ParseNoGenerateSyscalls(target, cfg.Experimental.NoGenerateSyscalls)
	if err != nil {
		t.Fatalf("ParseNoGenerateSyscalls: %v", err)
	}
	for _, name := range []string{
		"AcceptEx$inet_tcp_pending",
		"CreateIoCompletionPort$accept_pending",
		"WSAGetOverlappedResult$accept_pending",
		"setsockopt$update_accept_context",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing accept-updated syscall %q", name)
		}
		if !call.Attrs.NoMinimize {
			t.Fatalf("%s must stay no_minimize in the accept-updated focused profile", name)
		}
		if !call.Attrs.NoGenerate && !noDirect[call.ID] {
			t.Fatalf("%s must stay config-blocked until direct update-context generation no longer causes reload/handshake slow", name)
		}
	}
	for _, name := range []string{
		"send$inet_accept_updated",
		"recv$inet_accept_updated",
		"setsockopt$int_accept_updated",
		"getsockopt$int_accept_updated",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing accept-updated consumer syscall %q", name)
		}
		if call.Attrs.NoGenerate || !call.Attrs.NoMinimize {
			t.Fatalf("%s must stay triageable but no_minimize in the accept-updated focused profile", name)
		}
	}
	for _, name := range cfg.EnabledSyscalls {
		for _, pattern := range []string{
			"socket$listener_tcp",
			"bind$connectex_tcp",
			"ConnectEx$inet_tcp*",
			"DisconnectEx$inet_tcp*",
			"ioctlsocket$fionbio_listener",
			"connect$inet_tcp",
			"accept$inet_tcp",
			"WSAEventSelect$accept*",
			"WSAEnumNetworkEvents$accept*",
			"NtDeviceIoControlFile$afd_*accept*",
			"CreateIoCompletionPort$accept_recv_pending",
			"CreateIoCompletionPort$accept_send_pending",
			"WSAGetOverlappedResult$accept_recv_pending",
			"WSAGetOverlappedResult$accept_send_pending",
			"CancelIoEx$accept*",
			"CancelIo$accept*",
			"closesocket$*",
			"TransmitPackets$inet_accept",
			"TransmitFile$inet_accept",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("accept-updated AFD config directly enables risky syscall %q via %q",
					name, pattern)
			}
		}
	}
	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	expandedNames := make(map[string]bool, len(syscalls))
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		expandedNames[name] = true
		for _, pattern := range []string{
			"socket$listener_tcp",
			"bind$connectex_tcp",
			"ConnectEx$inet_tcp*",
			"DisconnectEx$inet_tcp*",
			"ioctlsocket$fionbio_listener",
			"AcceptEx$inet_tcp",
			"GetAcceptExSockaddrs$inet_tcp",
			"closesocket$*",
			"CreateIoCompletionPort$socket",
			"CreateIoCompletionPort$connect_pending",
			"CreateIoCompletionPort$accept_recv_pending",
			"CreateIoCompletionPort$accept_send_pending",
			"CreateIoCompletionPort$tcp_recv_pending",
			"CreateIoCompletionPort$tcp_send_pending",
			"WSAGetOverlappedResult$socket",
			"WSAGetOverlappedResult$connect_pending",
			"WSAGetOverlappedResult$accept_recv_pending",
			"WSAGetOverlappedResult$accept_send_pending",
			"WSAGetOverlappedResult$tcp_recv_pending",
			"WSAGetOverlappedResult$tcp_send_pending",
			"CancelIoEx$*",
			"CancelIo$*",
			"TransmitPackets$inet_accept",
			"TransmitFile$inet_accept",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("accept-updated AFD config leaves risky expanded syscall %q enabled via %q",
					name, pattern)
			}
		}
	}
	for _, name := range []string{
		"socket$accept_tcp",
		"AcceptEx$inet_tcp_pending",
		"CreateIoCompletionPort$accept_pending",
		"WSAGetOverlappedResult$accept_pending",
		"GetQueuedCompletionStatus$socket",
		"setsockopt$update_accept_context",
	} {
		if !expandedNames[name] {
			t.Fatalf("accept-updated AFD config must keep %s enabled for the AcceptEx/update-context path", name)
		}
	}
	expanded := make(map[*prog.Syscall]bool, len(syscalls))
	for _, id := range syscalls {
		expanded[target.Syscalls[id]] = true
	}
	for _, path := range windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		p, err := target.Deserialize(data, prog.Strict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		serialized := string(p.Serialize())
		for _, pattern := range []string{
			"socket$listener_tcp(",
			"ioctlsocket$fionbio_listener(",
		} {
			if strings.Contains(serialized, pattern) {
				t.Fatalf("%s must use the real bind/listen resource chain, got %s in:\n%s",
					filepath.Base(path), pattern, serialized)
			}
		}
		if target.RuntimePolicy.ShouldScheduleProgram != nil &&
			!target.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
			t.Fatalf("%s is rejected by the AFD runtime scheduler", filepath.Base(path))
		}
		for _, call := range p.Calls {
			for _, pattern := range []string{
				"closesocket$*",
				"CreateIoCompletionPort$connect_pending",
				"CreateIoCompletionPort$accept_recv_pending",
				"CreateIoCompletionPort$accept_send_pending",
				"CreateIoCompletionPort$tcp_recv_pending",
				"CreateIoCompletionPort$tcp_send_pending",
				"WSAGetOverlappedResult$connect_pending",
				"WSAGetOverlappedResult$accept_recv_pending",
				"WSAGetOverlappedResult$accept_send_pending",
				"WSAGetOverlappedResult$tcp_recv_pending",
				"WSAGetOverlappedResult$tcp_send_pending",
				"CancelIoEx$*",
				"CancelIo$*",
				"TransmitPackets$inet_accept",
				"TransmitFile$inet_accept",
			} {
				if mgrconfig.MatchSyscall(call.Meta.Name, pattern) {
					t.Fatalf("%s uses risky lifecycle syscall %s",
						filepath.Base(path), call.Meta.Name)
				}
			}
			if cfg.Experimental.BorrowingSeedPrefix != "" && call.Meta.Attrs.NoGenerate {
				t.Fatalf("%s uses no_generate syscall %s and cannot be used as a borrowing seed",
					filepath.Base(path), call.Meta.Name)
			}
			if call.Meta.Attrs.NoGenerate || target.CallIsAutomaticHelper(call.Meta) {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-accept-updated.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdPrivateEventConfigKeepsEventPollSeedOnly(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-private-event.cfg")
	want := []string{
		"ioctlsocket$fionbio_listener",
		"ioctlsocket$fionbio_tcp_created",
		"connect$inet_tcp_nonblock",
		"accept$inet_tcp_nonblock",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("private AFD event enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_afd_private_event_nonblock" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("private AFD event seed prefixes are too broad: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if cfg.Experimental.ForceGenerateEveryN != 1 {
		t.Fatalf("private AFD event force_generate_every_n=%d, want 1",
			cfg.Experimental.ForceGenerateEveryN)
	}
	if cfg.VM.KeepState {
		t.Fatal("private AFD event config must reload between requests while isolating event/poll IOCTLs")
	}
	for _, name := range cfg.EnabledSyscalls {
		for _, pattern := range []string{
			"connect$inet_tcp",
			"accept$inet_tcp",
			"socket$accept_tcp",
			"ioctlsocket$fionbio_accept_nonblock",
			"NtDeviceIoControlFile$afd_event_select_accept_nonblock",
			"NtDeviceIoControlFile$afd_enum_network_events_accept_nonblock",
			"NtDeviceIoControlFile$afd_poll_accept_nonblock",
			"CreateIoCompletionPort$accept*",
			"AcceptEx$inet_tcp*",
			"TransmitPackets$inet_accept",
			"TransmitFile$inet_accept",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("private AFD event config directly enables risky syscall %q via %q",
					name, pattern)
			}
		}
	}
}

func TestWindowsAfdPrivateEventConfigCoversSeedSyscalls(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-private-event.cfg")
	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{"nyx_afd_private_event_nonblock.txt"}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("private AFD event seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		for _, call := range p.Calls {
			for _, forbidden := range []string{
				"connect$inet_tcp",
				"accept$inet_tcp",
				"socket$accept_tcp",
			} {
				if call.Meta.Name == forbidden {
					t.Fatalf("%s uses blocking accept scaffold %s",
						filepath.Base(path), call.Meta.Name)
				}
			}
			if call.Meta.Attrs.AutomaticHelper {
				continue
			}
			if call.Meta.Attrs.NoGenerate && !slices.Contains(cfg.EnabledSyscalls, call.Meta.Name) {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-private-event.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdPublicEventConfigUsesNonblockingEvents(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-public-event.cfg")
	want := []string{
		"ioctlsocket$fionbio_listener",
		"ioctlsocket$fionbio_tcp_created",
		"connect$inet_tcp_nonblock",
		"ioctlsocket$fionbio_tcp_connected",
		"accept$inet_tcp_nonblock",
		"send$inet_tcp",
		"send$inet_accept",
		"WSAEventSelect$tcp_nonblock",
		"WSAEnumNetworkEvents$tcp_nonblock",
		"WSAEventSelect$accept_nonblock",
		"WSAEnumNetworkEvents$accept_nonblock",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("public AFD event enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_exp_afd_public_event_nonblock" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("public AFD event seed prefixes are too broad: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("public AFD event focused config should disable collide while async collide stability is unresolved")
	}
	if cfg.VM.KeepState {
		t.Fatal("public AFD event config must reload between requests while isolating event state")
	}
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, name := range []string{
		"WSAEventSelect$tcp_nonblock",
		"WSAEnumNetworkEvents$tcp_nonblock",
		"WSAEventSelect$accept_nonblock",
		"WSAEnumNetworkEvents$accept_nonblock",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing public event syscall %q", name)
		}
		if call.Attrs.NoGenerate {
			t.Fatalf("%s should be generatable in the focused nonblocking event profile", name)
		}
	}
	for _, name := range cfg.EnabledSyscalls {
		for _, pattern := range []string{
			"socket$connected_tcp",
			"connect$inet_tcp",
			"accept$inet_tcp",
			"socket$accept_tcp",
			"WSAEventSelect$tcp",
			"WSAEnumNetworkEvents$tcp",
			"WSAEventSelect$accept",
			"WSAEnumNetworkEvents$accept",
			"WNet*",
			"ioctlsocket$fionbio_accept_nonblock",
			"CreateIoCompletionPort$accept*",
			"AcceptEx$inet_tcp*",
			"TransmitPackets$inet_accept",
			"TransmitFile$inet_accept",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("public AFD event config directly enables risky syscall %q via %q",
					name, pattern)
			}
		}
	}
}

func TestWindowsAfdPublicEventConfigCoversSeedSyscalls(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-public-event.cfg")
	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{
		"nyx_exp_afd_public_event_nonblock_accept.txt",
		"nyx_exp_afd_public_event_nonblock_tcp.txt",
	}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("public AFD event seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	for _, id := range syscalls {
		if mgrconfig.MatchSyscall(target.Syscalls[id].Name, "WNet*") {
			t.Fatalf("public AFD event config leaves non-AFD syscall %q enabled",
				target.Syscalls[id].Name)
		}
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		for _, call := range p.Calls {
			for _, forbidden := range []string{
				"connect$inet_tcp",
				"accept$inet_tcp",
				"socket$accept_tcp",
				"socket$connected_tcp",
				"WSAEventSelect$tcp",
				"WSAEnumNetworkEvents$tcp",
				"WSAEventSelect$accept",
				"WSAEnumNetworkEvents$accept",
			} {
				if call.Meta.Name == forbidden {
					t.Fatalf("%s uses blocked public event scaffold %s",
						filepath.Base(path), call.Meta.Name)
				}
			}
			if call.Meta.Attrs.AutomaticHelper {
				continue
			}
			if call.Meta.Attrs.NoGenerate && !slices.Contains(cfg.EnabledSyscalls, call.Meta.Name) {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-public-event.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdTransmitConfigStaysNonblocking(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-transmit.cfg")
	want := []string{
		"NtCreateFile$afd_tcp_endpoint",
		"NtDeviceIoControlFile$afd_bind_tcp",
		"NtDeviceIoControlFile$afd_start_listen_tcp",
		"NtDeviceIoControlFile$afd_connect_tcp_to_listener",
		"NtDeviceIoControlFile$afd_wait_for_listen_tcp",
		"NtDeviceIoControlFile$afd_accept_tcp",
		"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_accepted",
		"WriteFile$afd_transmit",
		"NtDeviceIoControlFile$afd_transmit_file_accept_nonblock",
		"NtDeviceIoControlFile$afd_transmit_packets_accept_nonblock",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("AFD transmit enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_exp_afd_transmit_nonblock" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("AFD transmit seed prefixes are wrong: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if strings.HasPrefix(cfg.Experimental.SeedPrefix, "nyx_afd_") {
		t.Fatalf("AFD transmit focused seed %q would be visible to the formal AFD session",
			cfg.Experimental.SeedPrefix)
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("AFD transmit focused config should keep collide disabled while validating direct AFD transmit paths")
	}
	if cfg.VM.KeepState {
		t.Fatal("AFD transmit config must reload between requests")
	}

	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	expandedNames := make(map[string]bool, len(syscalls))
	expanded := make(map[*prog.Syscall]bool, len(syscalls))
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		expandedNames[name] = true
		expanded[target.Syscalls[id]] = true
		for _, pattern := range []string{
			"WSAStartup",
			"WSACleanup",
			"socket$inet_*",
			"bind$inet_*",
			"listen$inet_tcp",
			"connect$inet_tcp*",
			"accept$inet_tcp*",
			"ioctlsocket$fionbio_*",
			"socket$accept_tcp",
			"socket$connected_tcp",
			"AcceptEx$inet_tcp*",
			"ConnectEx$inet_tcp*",
			"DisconnectEx$inet_tcp*",
			"CreateIoCompletionPort$*",
			"GetQueuedCompletionStatus$socket",
			"WSAGetOverlappedResult$*",
			"CancelIoEx$*",
			"CancelIo$*",
			"closesocket$*",
			"CreatePipe$anon",
			"AddFontMemResourceEx",
			"TransmitPackets$inet_accept*",
			"TransmitFile$inet_accept*",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("AFD transmit leaves risky syscall %q enabled via pattern %q",
					name, pattern)
			}
		}
	}
	if expandedNames["WriteFile"] {
		t.Fatalf("AFD transmit should not enable generic WriteFile; use WriteFile$afd_transmit")
	}
	for _, name := range []string{
		"WriteFile$afd_transmit",
		"NtDeviceIoControlFile$afd_transmit_file_accept_nonblock",
		"NtDeviceIoControlFile$afd_transmit_packets_accept_nonblock",
	} {
		if !expandedNames[name] {
			t.Fatalf("AFD transmit config must keep %s enabled", name)
		}
	}
}

func TestWindowsAfdTransmitConfigCoversSeedSyscalls(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-transmit.cfg")
	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{"nyx_exp_afd_transmit_nonblock.txt"}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("AFD transmit seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		serialized := string(data)
		for _, name := range []string{
			"WSAStartup(",
			"WSACleanup(",
			"socket$inet_",
			"bind$inet_",
			"listen$inet_tcp(",
			"connect$inet_tcp(",
			"accept$inet_tcp(",
			"ioctlsocket$fionbio_",
			"socket$accept_tcp(",
			"socket$connected_tcp(",
			"TransmitFile$inet_accept",
			"TransmitPackets$inet_accept",
			"CreatePipe$anon(",
			"AddFontMemResourceEx(",
			"WriteFile(",
			"closesocket$",
		} {
			if strings.Contains(serialized, name) {
				t.Fatalf("AFD transmit seed %s contains risky call %q:\n%s",
					filepath.Base(path), name, serialized)
			}
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		for _, call := range p.Calls {
			if call.Meta.Attrs.NoGenerate || target.CallIsAutomaticHelper(call.Meta) {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-transmit.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdRioConfigStaysRioOnly(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-rio.cfg")
	want := []string{
		"NtCreateFile$afd_rio_registration_domain",
		"NtCreateFile$afd_rio_tcp_endpoint",
		"NtDeviceIoControlFile$afd_rio_create_cq",
		"NtDeviceIoControlFile$afd_rio_notify_cq",
		"NtDeviceIoControlFile$afd_rio_register_buffer",
		"NtDeviceIoControlFile$afd_rio_resize_cq",
		"NtDeviceIoControlFile$afd_rio_destroy_cq",
		"NtDeviceIoControlFile$afd_rio_deregister_buffer",
		"NtDeviceIoControlFile$afd_rio_create_rqpair",
		"NtDeviceIoControlFile$afd_rio_flush_send",
		"NtDeviceIoControlFile$afd_rio_flush_receive",
		"NtDeviceIoControlFile$afd_rio_resize_rqpair",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("AFD RIO enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_exp_afd_rio_" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("AFD RIO seed prefixes are wrong: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("AFD RIO focused config should keep collide disabled while validating Fast I/O reachability")
	}
	if cfg.VM.KeepState {
		t.Fatal("AFD RIO config must reload between requests")
	}

	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	expandedNames := make(map[string]bool, len(syscalls))
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		expandedNames[name] = true
		for _, pattern := range []string{
			"WSAStartup",
			"WSACleanup",
			"socket$inet_*",
			"bind$inet_*",
			"listen$inet_tcp",
			"connect$inet_tcp*",
			"accept$inet_tcp*",
			"ioctlsocket$fionbio_*",
			"AcceptEx$inet_tcp*",
			"ConnectEx$inet_tcp*",
			"DisconnectEx$inet_tcp*",
			"TransmitPackets$inet_accept*",
			"TransmitFile$inet_accept*",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("AFD RIO leaves risky syscall %q enabled via pattern %q",
					name, pattern)
			}
		}
	}
	for _, name := range []string{
		"NtCreateFile$afd_rio_registration_domain",
		"NtDeviceIoControlFile$afd_rio_create_cq",
		"NtDeviceIoControlFile$afd_rio_register_buffer",
	} {
		if !expandedNames[name] {
			t.Fatalf("AFD RIO config must keep %s enabled", name)
		}
	}
}

func TestWindowsAfdRioConfigCoversSeedSyscalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-rio.cfg")
	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{"nyx_exp_afd_rio_rd.txt"}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("AFD RIO seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		serialized := string(data)
		for _, name := range []string{
			"WSAStartup(",
			"WSACleanup(",
			"socket$inet_",
			"bind$inet_",
			"listen$inet_tcp(",
			"connect$inet_tcp(",
			"accept$inet_tcp(",
			"ioctlsocket$fionbio_",
			"TransmitFile$inet_accept",
			"TransmitPackets$inet_accept",
		} {
			if strings.Contains(serialized, name) {
				t.Fatalf("AFD RIO seed %s contains risky call %q:\n%s",
					filepath.Base(path), name, serialized)
			}
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		for _, call := range p.Calls {
			if call.Meta.Attrs.NoGenerate || target.CallIsAutomaticHelper(call.Meta) {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-rio.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdTliConfigStaysTliOnly(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-tli.cfg")
	want := []string{
		"NtCreateFile$afd_tli_tcp_endpoint",
		"NtDeviceIoControlFile$afd_tli_type1_nobuf",
		"NtDeviceIoControlFile$afd_tli_type2_nobuf",
		"NtDeviceIoControlFile$afd_tli_type3_nobuf",
		"NtDeviceIoControlFile$afd_tli_type1_inbuf",
		"NtDeviceIoControlFile$afd_tli_type2_inbuf",
		"NtDeviceIoControlFile$afd_tli_type3_inbuf",
		"NtDeviceIoControlFile$afd_tli_type1_outbuf",
		"NtDeviceIoControlFile$afd_tli_type2_outbuf",
		"NtDeviceIoControlFile$afd_tli_type3_outbuf",
		"NtDeviceIoControlFile$afd_tli_set_qos",
		"NtDeviceIoControlFile$afd_tli_associate_qos",
		"NtDeviceIoControlFile$afd_tli_isb_query",
		"NtDeviceIoControlFile$afd_tli_isb_set",
		"NtDeviceIoControlFile$afd_tli_type3_nobuf_pending",
		"CancelIoEx$afd_tli_pending",
		"CancelIo$afd_tli_pending",
		"CloseHandle$afd_tli_pending",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("AFD TLI enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_exp_afd_tli_" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("AFD TLI seed prefixes are wrong: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("AFD TLI focused config should keep collide disabled while validating endpoint gate reachability")
	}
	if cfg.VM.KeepState {
		t.Fatal("AFD TLI config must reload between requests")
	}

	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	expandedNames := make(map[string]bool, len(syscalls))
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		expandedNames[name] = true
		for _, pattern := range []string{
			"WSAStartup",
			"WSACleanup",
			"socket$inet_*",
			"bind$inet_*",
			"listen$inet_tcp",
			"connect$inet_tcp*",
			"accept$inet_tcp*",
			"ioctlsocket$fionbio_*",
			"AcceptEx$inet_tcp*",
			"ConnectEx$inet_tcp*",
			"DisconnectEx$inet_tcp*",
			"TransmitPackets$inet_accept*",
			"TransmitFile$inet_accept*",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("AFD TLI leaves risky syscall %q enabled via pattern %q",
					name, pattern)
			}
		}
	}
	for _, name := range []string{
		"NtCreateFile$afd_tli_tcp_endpoint",
		"NtDeviceIoControlFile$afd_tli_type3_nobuf",
		"NtDeviceIoControlFile$afd_tli_set_qos",
	} {
		if !expandedNames[name] {
			t.Fatalf("AFD TLI config must keep %s enabled", name)
		}
	}
}

func TestWindowsAfdTliConfigCoversSeedSyscalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-tli.cfg")
	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{"nyx_exp_afd_tli_nobuf.txt"}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("AFD TLI seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		serialized := string(data)
		for _, name := range []string{
			"WSAStartup(",
			"WSACleanup(",
			"socket$inet_",
			"bind$inet_",
			"listen$inet_tcp(",
			"connect$inet_tcp(",
			"accept$inet_tcp(",
			"ioctlsocket$fionbio_",
			"TransmitFile$inet_accept",
			"TransmitPackets$inet_accept",
		} {
			if strings.Contains(serialized, name) {
				t.Fatalf("AFD TLI seed %s contains risky call %q:\n%s",
					filepath.Base(path), name, serialized)
			}
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		for _, call := range p.Calls {
			if call.Meta.Attrs.NoGenerate || target.CallIsAutomaticHelper(call.Meta) {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-tli.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdSelectConfigStaysNonblocking(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-select.cfg")
	want := []string{
		"ioctlsocket$fionbio_listener",
		"ioctlsocket$fionbio_tcp_created",
		"connect$inet_tcp_nonblock",
		"accept$inet_tcp_nonblock",
		"select$afd_accept_nonblock",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("AFD select enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_exp_afd_select_nonblock" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("AFD select seed prefixes are wrong: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if strings.HasPrefix(cfg.Experimental.SeedPrefix, "nyx_afd_") {
		t.Fatalf("AFD select focused seed %q would be visible to the formal AFD session",
			cfg.Experimental.SeedPrefix)
	}
	if cfg.Experimental.ForceGenerateEveryN != 1 {
		t.Fatalf("AFD select force_generate_every_n=%d, want 1",
			cfg.Experimental.ForceGenerateEveryN)
	}
	if cfg.VM.KeepState {
		t.Fatal("AFD select config must reload between requests")
	}

	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		for _, pattern := range []string{
			"connect$inet_tcp",
			"accept$inet_tcp",
			"socket$accept_tcp",
			"select$afd_basic",
			"ioctlsocket$fionbio_accept_nonblock",
			"CreateIoCompletionPort$accept*",
			"AcceptEx$inet_tcp*",
			"TransmitPackets$inet_accept",
			"TransmitFile$inet_accept",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("AFD select leaves risky syscall %q enabled via pattern %q",
					name, pattern)
			}
		}
	}
}

func TestWindowsAfdSelectConfigCoversSeedSyscalls(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-select.cfg")
	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{"nyx_exp_afd_select_nonblock.txt"}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("AFD select seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		for _, call := range p.Calls {
			for _, forbidden := range []string{
				"connect$inet_tcp",
				"accept$inet_tcp",
				"socket$accept_tcp",
				"select$afd_basic",
			} {
				if call.Meta.Name == forbidden {
					t.Fatalf("%s uses risky scaffold %s",
						filepath.Base(path), call.Meta.Name)
				}
			}
			if call.Meta.Attrs.AutomaticHelper {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-select.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdRecvMsgConfigStaysNonblocking(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-recvmsg.cfg")
	want := []string{
		"connect$inet_udp",
		"send$inet_udp",
		"ioctlsocket$fionbio_udp_bound",
		"WSARecvMsg$udp_nonblock",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("AFD recvmsg enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_exp_afd_recvmsg_nonblock" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("AFD recvmsg seed prefixes are wrong: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if strings.HasPrefix(cfg.Experimental.SeedPrefix, "nyx_afd_") {
		t.Fatalf("AFD recvmsg focused seed %q would be visible to the formal AFD session",
			cfg.Experimental.SeedPrefix)
	}
	if cfg.Experimental.ForceGenerateEveryN != 1 {
		t.Fatalf("AFD recvmsg force_generate_every_n=%d, want 1",
			cfg.Experimental.ForceGenerateEveryN)
	}
	for _, name := range []string{"send$inet_udp", "WSARecvMsg$udp_nonblock"} {
		if !slices.Contains(cfg.Experimental.NoGenerateSyscalls, name) {
			t.Fatalf("AFD recvmsg should keep %s seed-only, got no_generate=%v",
				name, cfg.Experimental.NoGenerateSyscalls)
		}
	}
	foundSeedWeightZero := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight == 0 &&
			slices.Contains(rule.Calls, "send$inet_udp") &&
			slices.Contains(rule.Calls, "WSARecvMsg$udp_nonblock") {
			foundSeedWeightZero = true
			break
		}
	}
	if !foundSeedWeightZero {
		t.Fatal("AFD recvmsg should keep the send/recvmsg seed out of ordinary corpus mutation")
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("AFD recvmsg config must disable collide while the seed-only shape is evaluated")
	}
	if cfg.VM.KeepState {
		t.Fatal("AFD recvmsg config must reload between requests")
	}

	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		for _, pattern := range []string{
			"socket$connected_udp",
			"recv$inet_udp",
			"recvfrom$udp_bound",
			"recvfrom$udp_connected",
			"WSARecvFrom$udp",
			"WSARecvMsg$udp",
			"WSAIoctl$sio_udp_connreset",
			"connect$inet_tcp",
			"accept$inet_tcp",
			"socket$accept_tcp",
			"ConnectEx$inet_tcp*",
			"DisconnectEx$inet_tcp*",
			"AcceptEx$inet_tcp*",
			"CreateIoCompletionPort$*",
			"WSAGetOverlappedResult$*",
			"CancelIoEx$*",
			"CancelIo$*",
			"closesocket$*",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("AFD recvmsg leaves risky syscall %q enabled via pattern %q",
					name, pattern)
			}
		}
	}
}

func TestWindowsAfdRecvMsgConfigCoversSeedSyscalls(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-recvmsg.cfg")
	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{"nyx_exp_afd_recvmsg_nonblock.txt"}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("AFD recvmsg seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		serialized := string(data)
		for _, forbidden := range []string{
			"WSARecvMsg$udp(",
			"WSARecvFrom$udp(",
			"recvfrom$udp_bound(",
			"recv$inet_udp(",
			"socket$connected_udp(",
			"WSAIoctl$sio_udp_connreset(",
		} {
			if strings.Contains(serialized, forbidden) {
				t.Fatalf("AFD recvmsg seed %s contains risky call %q:\n%s",
					filepath.Base(path), forbidden, serialized)
			}
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		for _, call := range p.Calls {
			if call.Meta.Attrs.AutomaticHelper {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-recvmsg.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdWSAIoctlConfigStaysLowRisk(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	for _, tc := range []struct {
		cfgPath        string
		seedPrefix     string
		disableCollide bool
		want           []string
	}{
		{
			cfgPath:    "windows-nyx-afd-wsaioctl.cfg",
			seedPrefix: "nyx_afd_wsaioctl_lowrisk",
			want: []string{
				"bind$inet_udp",
				"WSAIoctl$sio_get_interface_list",
				"WSAIoctl$sio_udp_connreset",
			},
		},
		{
			cfgPath:    "windows-nyx-afd-wsaioctl-interface.cfg",
			seedPrefix: "nyx_afd_wsaioctl_interface",
			want: []string{
				"bind$inet_udp",
				"WSAIoctl$sio_get_interface_list",
			},
		},
		{
			cfgPath:        "windows-nyx-afd-wsaioctl-interface-udp-mix.cfg",
			seedPrefix:     "nyx_exp_afd_wsaioctl_interface_udp_mix",
			disableCollide: true,
			want: []string{
				"bind$inet_udp",
				"connect$inet_udp",
				"WSASendTo$udp",
				"getpeername$udp",
				"WSAIoctl$sio_keepalive_vals",
				"WSAIoctl$sio_get_interface_list",
			},
		},
		{
			cfgPath:    "windows-nyx-afd-wsaioctl-interface-udp-interface-first.cfg",
			seedPrefix: "nyx_exp_afd_wsaioctl_interface_udp_interface_first",
			want: []string{
				"bind$inet_udp",
				"connect$inet_udp",
				"WSASendTo$udp",
				"getpeername$udp",
				"WSAIoctl$sio_keepalive_vals",
				"WSAIoctl$sio_get_interface_list",
			},
		},
		{
			cfgPath:    "windows-nyx-afd-wsaioctl-interface-udp-no-keepalive.cfg",
			seedPrefix: "nyx_exp_afd_wsaioctl_interface_udp_no_keepalive",
			want: []string{
				"bind$inet_udp",
				"connect$inet_udp",
				"WSASendTo$udp",
				"getpeername$udp",
				"WSAIoctl$sio_get_interface_list",
			},
		},
		{
			cfgPath:    "windows-nyx-afd-wsaioctl-interface-udp-no-getpeername.cfg",
			seedPrefix: "nyx_exp_afd_wsaioctl_interface_udp_no_getpeername",
			want: []string{
				"bind$inet_udp",
				"connect$inet_udp",
				"WSASendTo$udp",
				"WSAIoctl$sio_keepalive_vals",
				"WSAIoctl$sio_get_interface_list",
			},
		},
		{
			cfgPath:        "windows-nyx-afd-wsaioctl-udp-connreset.cfg",
			seedPrefix:     "nyx_afd_wsaioctl_udp_connreset",
			disableCollide: true,
			want: []string{
				"bind$inet_udp",
				"WSAIoctl$sio_udp_connreset",
			},
		},
	} {
		tc := tc
		t.Run(tc.cfgPath, func(t *testing.T) {
			cfg := loadWindowsNyxConfig(t, tc.cfgPath)
			if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("WSAIoctl AFD enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
					strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(tc.want, "\n"))
			}
			if cfg.Experimental.SeedPrefix != tc.seedPrefix ||
				cfg.Experimental.BorrowingSeedPrefix != "" {
				t.Fatalf("WSAIoctl AFD seed prefixes are too broad: seed=%q borrowing=%q",
					cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
			}
			if cfg.Experimental.DisableCollide != tc.disableCollide {
				t.Fatalf("disable_collide=%v, want %v", cfg.Experimental.DisableCollide, tc.disableCollide)
			}
			if cfg.VM.KeepState {
				t.Fatal("WSAIoctl AFD config should reload between requests while isolating low-risk IOCTLs")
			}

			for _, name := range cfg.EnabledSyscalls {
				if strings.Contains(name, "_CHANGE") {
					t.Fatalf("WSAIoctl AFD config directly enables blocking change notification syscall %q", name)
				}
				for _, pattern := range []string{
					"ConnectEx$inet_tcp*",
					"DisconnectEx$inet_tcp*",
					"AcceptEx$inet_tcp*",
					"CreateIoCompletionPort$*",
					"WSAGetOverlappedResult$*",
					"CancelIoEx$*",
					"CancelIo$*",
					"NtDeviceIoControlFile$afd_event_select_accept*",
					"NtDeviceIoControlFile$afd_enum_network_events_accept*",
					"NtDeviceIoControlFile$afd_poll_accept*",
				} {
					if mgrconfig.MatchSyscall(name, pattern) {
						t.Fatalf("WSAIoctl AFD config directly enables risky syscall %q via %q",
							name, pattern)
					}
				}
			}
		})
	}
}

func TestWindowsAfdWSAIoctlConfigCoversSeedSyscalls(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for _, cfgPath := range []string{
		"windows-nyx-afd-wsaioctl.cfg",
		"windows-nyx-afd-wsaioctl-interface.cfg",
		"windows-nyx-afd-wsaioctl-interface-udp-interface-first.cfg",
		"windows-nyx-afd-wsaioctl-interface-udp-no-getpeername.cfg",
		"windows-nyx-afd-wsaioctl-interface-udp-no-keepalive.cfg",
		"windows-nyx-afd-wsaioctl-interface-udp-mix.cfg",
		"windows-nyx-afd-wsaioctl-udp-connreset.cfg",
	} {
		cfgPath := cfgPath
		t.Run(cfgPath, func(t *testing.T) {
			cfg := loadWindowsNyxConfig(t, cfgPath)
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
					if strings.Contains(call.Meta.Name, "_CHANGE") ||
						strings.HasPrefix(call.Meta.Name, "ConnectEx$") ||
						strings.HasPrefix(call.Meta.Name, "AcceptEx$") {
						t.Fatalf("%s uses risky WSAIoctl scaffold %s",
							filepath.Base(path), call.Meta.Name)
					}
					if call.Meta.Attrs.NoGenerate || call.Meta.Attrs.AutomaticHelper {
						continue
					}
					if !expanded[call.Meta] {
						t.Fatalf("%s uses %s, which is not enabled by %s",
							filepath.Base(path), call.Meta.Name, cfgPath)
					}
				}
			}
		})
	}
}

func TestWindowsAfdAsyncConfigAvoidsDisconnectExGeneration(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-async.cfg")
	for _, name := range []string{
		"DisconnectEx$inet_tcp",
		"DisconnectEx$inet_tcp_reuse",
		"CreateIoCompletionPort$disconnect_reuse_pending",
		"WSAGetOverlappedResult$disconnect_reuse_pending",
		"ConnectEx$inet_tcp_reuse",
	} {
		if slices.Contains(cfg.EnabledSyscalls, name) {
			t.Fatalf("async config should not generate unstable reuse root %q", name)
		}
	}
}

func TestWindowsAfdConnectExIOCPConfig(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-connectex-iocp.cfg")
	want := []string{
		"bind$inet_tcp",
		"listen$inet_tcp",
		"bind$connectex_tcp",
		"ConnectEx$inet_tcp_pending",
		"CreateIoCompletionPort$connect_pending",
		"WSAGetOverlappedResult$connect_pending",
		"GetQueuedCompletionStatus$socket",
		"closesocket$connect_pending",
		"setsockopt$update_connect_context",
		"send$inet_tcp",
		"getsockname$tcp",
		"getpeername$tcp",
		"syz_emit_ethernet$windows",
		"syz_extract_tcp_res$windows",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConnectEx IOCP enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_exp_afd_connectex_iocp_" ||
		cfg.Experimental.SeedExcludePrefixes != "nyx_exp_afd_connectex_iocp_cancel,nyx_exp_afd_connectex_iocp_vnet_update" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("ConnectEx IOCP seed prefixes are wrong: seed=%q exclude=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.SeedExcludePrefixes,
			cfg.Experimental.BorrowingSeedPrefix)
	}
	if strings.HasPrefix(cfg.Experimental.SeedPrefix, "nyx_afd_") {
		t.Fatalf("ConnectEx IOCP focused seed %q would be visible to the formal AFD session",
			cfg.Experimental.SeedPrefix)
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("ConnectEx IOCP config should disable collide until the focused flow is stable")
	}
	if cfg.Experimental.ForceGenerateEveryN != 0 {
		t.Fatalf("ConnectEx IOCP force_generate_every_n=%d, want 0 while fresh ConnectEx generation is state-gated",
			cfg.Experimental.ForceGenerateEveryN)
	}
	for _, name := range []string{
		"syz_emit_ethernet$windows",
		"syz_extract_tcp_res$windows",
	} {
		if !slices.Contains(cfg.Experimental.NoGenerateSyscalls, name) {
			t.Fatalf("ConnectEx IOCP should keep unstable vnet helper %q seed-only, no_generate_syscalls=%v",
				name, cfg.Experimental.NoGenerateSyscalls)
		}
	}
	foundVNetSeedWeightZero := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight == 0 &&
			slices.Contains(rule.Calls, "syz_emit_ethernet$windows") &&
			slices.Contains(rule.Calls, "syz_extract_tcp_res$windows") {
			foundVNetSeedWeightZero = true
			break
		}
	}
	if !foundVNetSeedWeightZero {
		t.Fatal("ConnectEx IOCP should keep vnet completion seeds out of ordinary corpus mutation")
	}
	if cfg.VM.KeepState {
		t.Fatal("ConnectEx IOCP config must reload between requests")
	}
	gqcs := target.SyscallMap["GetQueuedCompletionStatus$socket"]
	if gqcs == nil {
		t.Fatal("missing GetQueuedCompletionStatus$socket")
	}
	timeout, ok := gqcs.Args[4].Type.(*prog.ConstType)
	if !ok || timeout.Val != 0 {
		t.Fatalf("GetQueuedCompletionStatus$socket timeout type=%v, want const[0]",
			gqcs.Args[4].Type)
	}
	iocp := target.SyscallMap["CreateIoCompletionPort$connect_pending"]
	if iocp == nil {
		t.Fatal("missing CreateIoCompletionPort$connect_pending")
	}
	completionKey, ok := iocp.Args[2].Type.(*prog.ConstType)
	if !ok || completionKey.Val != 0xafd {
		t.Fatalf("CreateIoCompletionPort$connect_pending CompletionKey type=%v, want const[0xafd]",
			iocp.Args[2].Type)
	}
	threads, ok := iocp.Args[3].Type.(*prog.ConstType)
	if !ok || threads.Val != 0 {
		t.Fatalf("CreateIoCompletionPort$connect_pending NumberOfConcurrentThreads type=%v, want const[0]",
			iocp.Args[3].Type)
	}

	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	expanded := make(map[*prog.Syscall]bool, len(syscalls))
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		expanded[target.Syscalls[id]] = true
		for _, pattern := range []string{
			"connect$inet_tcp*",
			"ConnectEx$inet_tcp",
			"ConnectEx$inet_tcp_reuse",
			"DisconnectEx$inet_tcp*",
			"AcceptEx$inet_tcp*",
			"GetAcceptExSockaddrs$inet_tcp",
			"CreateIoCompletionPort$socket",
			"CreateIoCompletionPort$accept*",
			"CreateIoCompletionPort$tcp_recv_pending",
			"CreateIoCompletionPort$tcp_send_pending",
			"WSAGetOverlappedResult$socket",
			"WSAGetOverlappedResult$accept*",
			"WSAGetOverlappedResult$tcp_recv_pending",
			"WSAGetOverlappedResult$tcp_send_pending",
			"CancelIoEx$socket",
			"CancelIoEx$accept*",
			"CancelIoEx$tcp_*_pending",
			"CancelIoEx$connect_pending",
			"CancelIo$socket",
			"CancelIo$accept*",
			"CancelIo$tcp_*_pending",
			"CancelIo$connect_pending",
			"WSAEventSelect$*",
			"WSAEnumNetworkEvents$*",
			"select$afd*",
			"NtDeviceIoControlFile$afd_event_select_accept*",
			"NtDeviceIoControlFile$afd_enum_network_events_accept*",
			"NtDeviceIoControlFile$afd_poll_accept*",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("ConnectEx IOCP leaves risky syscall %q enabled via pattern %q",
					name, pattern)
			}
		}
	}
	for _, name := range []string{
		"ConnectEx$inet_tcp_pending",
		"CreateIoCompletionPort$connect_pending",
		"WSAGetOverlappedResult$connect_pending",
		"GetQueuedCompletionStatus$socket",
		"setsockopt$update_connect_context",
		"send$inet_tcp",
		"getsockname$tcp",
		"getpeername$tcp",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing ConnectEx IOCP syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("ConnectEx IOCP expanded set missing %s", name)
		}
	}
}

func TestWindowsAfdPendingIOConfig(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-pending-io.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	want := []string{
		"bind$inet_tcp",
		"listen$inet_tcp",
		"ioctlsocket$fionbio_listener",
		"ioctlsocket$fionbio_tcp_created",
		"ioctlsocket$fionbio_tcp_connected",
		"connect$inet_tcp_nonblock",
		"accept$inet_tcp_nonblock",
		"send$inet_accept",
		"WSARecv$tcp_pending",
		"CreateIoCompletionPort$tcp_recv_pending",
		"WSAGetOverlappedResult$tcp_recv_pending",
		"GetQueuedCompletionStatus$socket",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("pending-IO AFD enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_exp_afd_pending_io_" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("pending-IO seed prefixes are wrong: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if strings.HasPrefix(cfg.Experimental.SeedPrefix, "nyx_afd_") {
		t.Fatalf("pending-IO focused seed %q would be visible to the formal AFD session",
			cfg.Experimental.SeedPrefix)
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("pending-IO config should disable collide until focused flow is stable")
	}
	if cfg.Experimental.MaxCallsPerProg != 15 {
		t.Fatalf("pending-IO max_calls_per_prog=%d, want exactly 15 for local listener proof seeds",
			cfg.Experimental.MaxCallsPerProg)
	}
	proofOnly := []string{
		"WSARecv$tcp_pending",
		"CreateIoCompletionPort$tcp_recv_pending",
		"WSAGetOverlappedResult$tcp_recv_pending",
		"GetQueuedCompletionStatus$socket",
	}
	for _, name := range proofOnly {
		if !slices.Contains(cfg.Experimental.NoGenerateSyscalls, name) {
			t.Fatalf("pending-IO proof call %s should be listed in no_generate_syscalls: %v",
				name, cfg.Experimental.NoGenerateSyscalls)
		}
	}
	zeroWeight := make(map[string]bool)
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight != 0 {
			continue
		}
		for _, name := range rule.Calls {
			zeroWeight[name] = true
		}
	}
	for _, name := range proofOnly {
		if !zeroWeight[name] {
			t.Fatalf("pending-IO proof call %s should have corpus fuzz weight 0", name)
		}
	}
	for _, name := range []string{
		"WSARecv$tcp_pending",
		"CreateIoCompletionPort$tcp_recv_pending",
		"WSAGetOverlappedResult$tcp_recv_pending",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing pending-IO syscall %q", name)
		}
		if !call.Attrs.NoGenerate || !call.Attrs.NoMinimize {
			t.Fatalf("%s should stay proof/seed-only and no_minimize after focused smoke failure", name)
		}
	}
	for _, name := range []string{
		"WSASend$tcp_pending",
		"WSASend$accept_pending",
	} {
		call := target.SyscallMap[name]
		flags, ok := call.Args[4].Type.(*prog.ConstType)
		if !ok || flags.Val != 0 {
			t.Fatalf("%s flags type=%v, want const[0]", name, call.Args[4].Type)
		}
		routine, ok := call.Args[6].Type.(*prog.ConstType)
		if !ok || routine.Val != 0 {
			t.Fatalf("%s completion routine type=%v, want const[0]", name, call.Args[6].Type)
		}
	}
	for _, name := range []string{
		"WSARecv$tcp_pending",
		"WSARecv$accept_pending",
	} {
		call := target.SyscallMap[name]
		routine, ok := call.Args[6].Type.(*prog.ConstType)
		if !ok || routine.Val != 0 {
			t.Fatalf("%s completion routine type=%v, want const[0]", name, call.Args[6].Type)
		}
	}
	for _, name := range []string{
		"CreateIoCompletionPort$tcp_recv_pending",
		"CreateIoCompletionPort$accept_recv_pending",
	} {
		call := target.SyscallMap[name]
		completionKey, ok := call.Args[2].Type.(*prog.ConstType)
		if !ok || completionKey.Val != 0xafd {
			t.Fatalf("%s CompletionKey type=%v, want const[0xafd]", name, call.Args[2].Type)
		}
		threads, ok := call.Args[3].Type.(*prog.ConstType)
		if !ok || threads.Val != 0 {
			t.Fatalf("%s NumberOfConcurrentThreads type=%v, want const[0]", name, call.Args[3].Type)
		}
	}
	for _, name := range []string{
		"WSAGetOverlappedResult$tcp_recv_pending",
		"WSAGetOverlappedResult$accept_recv_pending",
	} {
		call := target.SyscallMap[name]
		fwait, ok := call.Args[3].Type.(*prog.ConstType)
		if !ok || fwait.Val != 0 {
			t.Fatalf("%s fWait type=%v, want const[0]", name, call.Args[3].Type)
		}
	}
	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	expanded := make(map[*prog.Syscall]bool, len(syscalls))
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		expanded[target.Syscalls[id]] = true
		for _, pattern := range []string{
			"ConnectEx$inet_tcp*",
			"DisconnectEx$inet_tcp*",
			"AcceptEx$inet_tcp*",
			"setsockopt$update_accept_context",
			"setsockopt$update_connect_context",
			"WSAEventSelect$*",
			"WSAEnumNetworkEvents$*",
			"WSASend$*_pending",
			"CancelIoEx$*_recv_pending",
			"CancelIoEx$*_send_pending",
			"CancelIo$*_recv_pending",
			"CancelIo$*_send_pending",
			"closesocket$*_recv_pending",
			"closesocket$*_send_pending",
			"select$afd*",
			"NtDeviceIoControlFile$afd_event_select_accept*",
			"NtDeviceIoControlFile$afd_enum_network_events_accept*",
			"NtDeviceIoControlFile$afd_poll_accept*",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("pending-IO config leaves unrelated risky syscall %q enabled via pattern %q",
					name, pattern)
			}
		}
	}
	for _, name := range want {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing pending-IO syscall %q", name)
		}
		if !expanded[call] && !slices.Contains(cfg.EnabledSyscalls, name) {
			t.Fatalf("pending-IO expanded set missing %s", name)
		}
	}
	noDirect, err := mgrconfig.ParseNoGenerateSyscalls(target, cfg.Experimental.NoGenerateSyscalls)
	if err != nil {
		t.Fatalf("ParseNoGenerateSyscalls: %v", err)
	}
	ct := target.BuildChoiceTableWithNoDirectCalls(nil, expanded, noDirect)
	for _, name := range proofOnly {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing pending-IO proof syscall %q", name)
		}
		if ct.DirectlyGeneratable(call.ID) {
			t.Fatalf("%s should not be directly generated by pending-IO proof cfg", name)
		}
	}
}

func TestWindowsAfdPendingIOConfigCoversSeedSyscalls(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-pending-io.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{
		"nyx_exp_afd_pending_io_tcp_recv_iocp.txt",
	}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("pending-IO seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		serialized := string(data)
		for _, forbidden := range []string{
			"AcceptEx$",
			"ConnectEx$",
			"DisconnectEx$",
			"WSAEventSelect$",
			"WSAEnumNetworkEvents$",
			"NtDeviceIoControlFile$afd_poll_accept",
		} {
			if strings.Contains(serialized, forbidden) {
				t.Fatalf("pending-IO seed %s contains forbidden call %q:\n%s",
					filepath.Base(path), forbidden, serialized)
			}
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		if target.RuntimePolicy.ShouldScheduleProgram != nil &&
			!target.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
			t.Fatalf("%s is rejected by the AFD runtime scheduler", filepath.Base(path))
		}
		for _, call := range p.Calls {
			if call.Meta.Attrs.AutomaticHelper {
				continue
			}
			if call.Meta.Attrs.NoGenerate && !slices.Contains(cfg.EnabledSyscalls, call.Meta.Name) {
				t.Fatalf("%s uses no_generate syscall %s that is not explicitly enabled",
					filepath.Base(path), call.Meta.Name)
			}
			if !expanded[call.Meta] && !slices.Contains(cfg.EnabledSyscalls, call.Meta.Name) {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-pending-io.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsAfdConnectExIOCPConfigCoversSeedSyscalls(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-connectex-iocp.cfg")
	matches := windowsSeedPrefixMatchesExcept(t, cfg.Experimental.SeedPrefix,
		cfg.Experimental.SeedExcludePrefixes)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{
		"nyx_exp_afd_connectex_iocp_local_update.txt",
	}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("ConnectEx IOCP seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	proofSeeds := windowsSeedPrefixMatches(t, cfg.Experimental.SeedExcludePrefixes)
	gotProofSeeds := make([]string, 0, len(proofSeeds))
	for _, path := range proofSeeds {
		gotProofSeeds = append(gotProofSeeds, filepath.Base(path))
	}
	wantProofSeeds := []string{
		"nyx_exp_afd_connectex_iocp_cancel.txt",
		"nyx_exp_afd_connectex_iocp_vnet_update.txt",
	}
	if strings.Join(gotProofSeeds, "\n") != strings.Join(wantProofSeeds, "\n") {
		t.Fatalf("ConnectEx IOCP proof seed mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotProofSeeds, "\n"), strings.Join(wantProofSeeds, "\n"))
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		serialized := string(data)
		for _, forbidden := range []string{
			"AcceptEx$",
			"DisconnectEx$",
			"ConnectEx$inet_tcp_reuse",
			"WSAEventSelect$",
			"WSAEnumNetworkEvents$",
			"NtDeviceIoControlFile$afd_poll_accept",
		} {
			if strings.Contains(serialized, forbidden) {
				t.Fatalf("ConnectEx IOCP seed %s contains forbidden call %q:\n%s",
					filepath.Base(path), forbidden, serialized)
			}
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		for _, call := range p.Calls {
			if call.Meta.Attrs.AutomaticHelper {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-connectex-iocp.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
		if strings.Contains(filepath.Base(path), "vnet_update") {
			for _, want := range []string{
				"WSAGetOverlappedResult$connect_pending(",
				"GetQueuedCompletionStatus$socket(",
				"setsockopt$update_connect_context(",
				"send$inet_tcp(",
				"syz_extract_tcp_res$windows(",
				"0x4e20",
				"0x9c40",
			} {
				if !strings.Contains(serialized, want) {
					t.Fatalf("ConnectEx vnet update seed missing %q:\n%s", want, serialized)
				}
			}
			for _, oldPort := range []string{"0x4e22", "0x4e23"} {
				if strings.Contains(serialized, oldPort) {
					t.Fatalf("ConnectEx vnet update seed uses stale TCP port %s:\n%s",
						oldPort, serialized)
				}
			}
		}
		if strings.Contains(filepath.Base(path), "local_update") {
			for _, want := range []string{
				"listen$inet_tcp(",
				"WSAGetOverlappedResult$connect_pending(",
				"GetQueuedCompletionStatus$socket(",
				"setsockopt$update_connect_context(",
				"send$inet_tcp(",
			} {
				if !strings.Contains(serialized, want) {
					t.Fatalf("ConnectEx local update seed missing %q:\n%s", want, serialized)
				}
			}
			for _, forbidden := range []string{
				"syz_emit_ethernet$windows(",
				"syz_extract_tcp_res$windows(",
				"closesocket$",
			} {
				if strings.Contains(serialized, forbidden) {
					t.Fatalf("ConnectEx local update seed contains non-local/finalizer call %q:\n%s",
						forbidden, serialized)
				}
			}
		}
	}
	for _, path := range proofSeeds {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read proof seed %s: %v", path, err)
		}
		serialized := string(data)
		if _, err := target.Deserialize(data, prog.NonStrict); err != nil {
			t.Fatalf("deserialize proof seed %s: %v", path, err)
		}
		if strings.Contains(filepath.Base(path), "cancel") {
			for _, want := range []string{
				"CancelIoEx$connect_pending(",
			} {
				if !strings.Contains(serialized, want) {
					t.Fatalf("ConnectEx cancel proof seed %s missing %q:\n%s",
						filepath.Base(path), want, serialized)
				}
			}
			for _, forbidden := range []string{
				"CancelIo$connect_pending(",
				"closesocket$connect_pending(",
				"WSAGetOverlappedResult$connect_pending(",
				"GetQueuedCompletionStatus$socket(",
				"setsockopt$update_connect_context(",
			} {
				if strings.Contains(serialized, forbidden) {
					t.Fatalf("ConnectEx cancel proof seed %s contains completion/update call %q:\n%s",
						filepath.Base(path), forbidden, serialized)
				}
			}
			continue
		}
		for _, want := range []string{
			"WSAGetOverlappedResult$connect_pending(",
			"GetQueuedCompletionStatus$socket(",
			"setsockopt$update_connect_context(",
			"send$inet_tcp(",
		} {
			if !strings.Contains(serialized, want) {
				t.Fatalf("ConnectEx update proof seed %s missing %q:\n%s",
					filepath.Base(path), want, serialized)
			}
		}
	}
}

func TestWindowsAfdDisconnectExReuseConfig(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-disconnectex-reuse.cfg")
	want := []string{
		"bind$inet_tcp",
		"listen$inet_tcp",
		"bind$connectex_tcp",
		"connect$inet_tcp",
		"accept$inet_tcp",
		"closesocket$any",
		"ConnectEx$inet_tcp_pending",
		"DisconnectEx$inet_tcp_reuse",
		"CreateIoCompletionPort$disconnect_reuse_pending",
		"WSAGetOverlappedResult$disconnect_reuse_pending",
		"ConnectEx$inet_tcp_reuse",
		"CreateIoCompletionPort$connect_pending",
		"WSAGetOverlappedResult$connect_pending",
		"GetQueuedCompletionStatus$socket",
		"setsockopt$update_connect_context",
	}
	if strings.Join(cfg.EnabledSyscalls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("DisconnectEx reuse enabled syscalls mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(cfg.EnabledSyscalls, "\n"), strings.Join(want, "\n"))
	}
	if cfg.Experimental.SeedPrefix != "nyx_exp_afd_disconnectex_reuse" ||
		cfg.Experimental.BorrowingSeedPrefix != "" {
		t.Fatalf("DisconnectEx reuse seed prefixes are wrong: seed=%q borrowing=%q",
			cfg.Experimental.SeedPrefix, cfg.Experimental.BorrowingSeedPrefix)
	}
	if strings.HasPrefix(cfg.Experimental.SeedPrefix, "nyx_afd_") {
		t.Fatalf("DisconnectEx reuse focused seed %q would be visible to the formal AFD session",
			cfg.Experimental.SeedPrefix)
	}
	if !cfg.Experimental.DisableCollide {
		t.Fatal("DisconnectEx reuse config should disable collide until the focused flow is stable")
	}
	if cfg.Experimental.MaxCallsPerProg != 22 {
		t.Fatalf("DisconnectEx reuse max_calls_per_prog=%d, want 22", cfg.Experimental.MaxCallsPerProg)
	}
	if cfg.VM.KeepState {
		t.Fatal("DisconnectEx reuse config must reload between requests")
	}
	for _, name := range []string{"connect$inet_tcp", "accept$inet_tcp"} {
		if !slices.Contains(cfg.Experimental.NoGenerateSyscalls, name) {
			t.Fatalf("DisconnectEx reuse blocking scaffold %s must be no-direct: %v",
				name, cfg.Experimental.NoGenerateSyscalls)
		}
	}
	foundZeroWeight := false
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		if rule.Weight != 0 {
			continue
		}
		if slices.Contains(rule.Calls, "connect$inet_tcp") {
			foundZeroWeight = true
			break
		}
	}
	if !foundZeroWeight {
		t.Fatalf("DisconnectEx reuse config must zero-weight blocking scaffold corpus fuzz rules: %+v",
			cfg.Experimental.CorpusFuzzWeightRules)
	}
	noDirect, err := mgrconfig.ParseNoGenerateSyscalls(target, cfg.Experimental.NoGenerateSyscalls)
	if err != nil {
		t.Fatalf("ParseNoGenerateSyscalls: %v", err)
	}
	for _, tc := range []struct {
		name  string
		index int
	}{
		{"DisconnectEx$inet_tcp_reuse", 1},
	} {
		call := target.SyscallMap[tc.name]
		if call == nil {
			t.Fatalf("missing %s", tc.name)
		}
		ptr, ok := call.Args[tc.index].Type.(*prog.PtrType)
		if !ok {
			t.Fatalf("%s overlapped type=%v, want ptr[inout, OVERLAPPED]",
				tc.name, call.Args[tc.index].Type)
		}
		st, ok := ptr.Elem.(*prog.StructType)
		if !ok || st.Name() != "OVERLAPPED" {
			t.Fatalf("%s overlapped elem=%v, want OVERLAPPED", tc.name, ptr.Elem)
		}
	}

	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	expandedNames := make(map[string]bool, len(syscalls))
	expanded := make(map[*prog.Syscall]bool, len(syscalls))
	for _, id := range syscalls {
		name := target.Syscalls[id].Name
		expandedNames[name] = true
		expanded[target.Syscalls[id]] = true
		for _, pattern := range []string{
			"socket$accept_tcp",
			"socket$connected_tcp",
			"ioctlsocket$fionbio_listener",
			"ioctlsocket$fionbio_tcp_created",
			"connect$inet_tcp_nonblock",
			"accept$inet_tcp_nonblock",
			"send$inet_tcp",
			"recv$inet_tcp",
			"ConnectEx$inet_tcp",
			"DisconnectEx$inet_tcp",
			"AcceptEx$inet_tcp*",
			"CreateIoCompletionPort$socket",
			"CreateIoCompletionPort$accept*",
			"CreateIoCompletionPort$tcp_recv_pending",
			"CreateIoCompletionPort$tcp_send_pending",
			"WSAGetOverlappedResult$socket",
			"WSAGetOverlappedResult$accept*",
			"WSAGetOverlappedResult$tcp_recv_pending",
			"WSAGetOverlappedResult$tcp_send_pending",
			"CancelIoEx$*",
			"CancelIo$*",
			"closesocket$accept_pending",
			"closesocket$accept_recv_pending",
			"closesocket$accept_send_pending",
			"closesocket$connect_pending",
			"closesocket$tcp_recv_pending",
			"closesocket$tcp_send_pending",
			"WSAEventSelect$*",
			"WSAEnumNetworkEvents$*",
			"select$afd*",
			"NtDeviceIoControlFile$afd_event_select_accept*",
			"NtDeviceIoControlFile$afd_enum_network_events_accept*",
			"NtDeviceIoControlFile$afd_poll_accept*",
			"TransmitFile$inet_accept*",
			"TransmitPackets$inet_accept*",
		} {
			if mgrconfig.MatchSyscall(name, pattern) {
				t.Fatalf("DisconnectEx reuse config leaves risky syscall %q enabled via pattern %q",
					name, pattern)
			}
		}
	}
	for _, name := range want {
		if !expandedNames[name] {
			t.Fatalf("DisconnectEx reuse config must keep %s enabled", name)
		}
	}
	ct := target.BuildChoiceTableWithNoDirectCalls(nil, expanded, noDirect)
	for _, name := range []string{"connect$inet_tcp", "accept$inet_tcp"} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing %s", name)
		}
		if ct.DirectlyGeneratable(call.ID) {
			t.Fatalf("%s should be enabled for seeds but not directly generated", name)
		}
	}
}

func TestWindowsAfdDisconnectExReuseConfigCoversSeedSyscalls(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	cfg := loadWindowsNyxConfig(t, "windows-nyx-afd-disconnectex-reuse.cfg")
	target, err = target.ApplyTargetProfile(target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	matches := windowsSeedPrefixMatches(t, cfg.Experimental.SeedPrefix)
	gotSeeds := make([]string, 0, len(matches))
	for _, path := range matches {
		gotSeeds = append(gotSeeds, filepath.Base(path))
	}
	wantSeeds := []string{
		"nyx_exp_afd_disconnectex_reuse.txt",
		"nyx_exp_afd_disconnectex_reuse_connectex_peerclose.txt",
	}
	if strings.Join(gotSeeds, "\n") != strings.Join(wantSeeds, "\n") {
		t.Fatalf("DisconnectEx reuse seed set mismatch:\ngot:\n%s\nwant:\n%s",
			strings.Join(gotSeeds, "\n"), strings.Join(wantSeeds, "\n"))
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("unknown enabled syscall %q", name)
		}
		enabled[call] = true
	}
	expanded, _ := target.TransitivelyEnabledCalls(enabled)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		serialized := string(data)
		for _, forbidden := range []string{
			"socket$accept_tcp(",
			"ioctlsocket$fionbio_listener(",
			"ioctlsocket$fionbio_tcp_created(",
			"connect$inet_tcp_nonblock(",
			"accept$inet_tcp_nonblock(",
			"ConnectEx$inet_tcp(",
			"DisconnectEx$inet_tcp(",
			"AcceptEx$",
			"CancelIo",
			"WSAEventSelect$",
			"WSAEnumNetworkEvents$",
			"select$afd",
			"NtDeviceIoControlFile$afd_",
			"TransmitFile$",
			"TransmitPackets$",
			"closesocket$accept_pending",
			"closesocket$connect_pending",
			"closesocket$tcp_",
		} {
			if strings.Contains(serialized, forbidden) {
				t.Fatalf("DisconnectEx reuse seed %s contains forbidden call %q:\n%s",
					filepath.Base(path), forbidden, serialized)
			}
		}
		for _, want := range []string{
			"socket$inet_tcp(",
			"accept$inet_tcp(",
			"closesocket$any(",
			"DisconnectEx$inet_tcp_reuse(",
			"CreateIoCompletionPort$disconnect_reuse_pending(",
			"WSAGetOverlappedResult$disconnect_reuse_pending(",
			"ConnectEx$inet_tcp_reuse(",
			"CreateIoCompletionPort$connect_pending(",
			"WSAGetOverlappedResult$connect_pending(",
			"GetQueuedCompletionStatus$socket(",
			"setsockopt$update_connect_context(",
		} {
			if !strings.Contains(serialized, want) {
				t.Fatalf("DisconnectEx reuse seed %s missing %q:\n%s",
					filepath.Base(path), want, serialized)
			}
		}
		switch filepath.Base(path) {
		case "nyx_exp_afd_disconnectex_reuse_connectex_peerclose.txt":
			for _, want := range []string{
				"bind$connectex_tcp(",
				"ConnectEx$inet_tcp_pending(",
			} {
				if !strings.Contains(serialized, want) {
					t.Fatalf("ConnectEx-driven DisconnectEx reuse seed %s missing %q:\n%s",
						filepath.Base(path), want, serialized)
				}
			}
			if strings.Contains(serialized, "connect$inet_tcp(") {
				t.Fatalf("ConnectEx-driven DisconnectEx reuse seed uses blocking connect:\n%s", serialized)
			}
		default:
			if !strings.Contains(serialized, "connect$inet_tcp(") {
				t.Fatalf("blocking DisconnectEx reuse seed %s missing connect$inet_tcp:\n%s",
					filepath.Base(path), serialized)
			}
			if strings.Contains(serialized, "ConnectEx$inet_tcp_pending(") {
				t.Fatalf("blocking DisconnectEx reuse seed %s contains ConnectEx pending:\n%s",
					filepath.Base(path), serialized)
			}
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			t.Fatalf("deserialize %s: %v", path, err)
		}
		if target.RuntimePolicy.ShouldScheduleProgram != nil &&
			!target.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
			t.Fatalf("%s is rejected by the AFD runtime scheduler", filepath.Base(path))
		}
		for _, call := range p.Calls {
			if call.Meta.Attrs.AutomaticHelper {
				continue
			}
			if !expanded[call.Meta] {
				t.Fatalf("%s uses %s, which is not enabled by windows-nyx-afd-disconnectex-reuse.cfg",
					filepath.Base(path), call.Meta.Name)
			}
		}
	}
}

func TestWindowsDemoExecEncodingUsesTargetIDs(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
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
	skipLegacyAfdWinsockArchived(t)
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
		"setsockopt$update_connect_context":           true,
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
		"setsockopt$update_connect_context",
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
	skipLegacyAfdWinsockArchived(t)
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
	skipLegacyAfdWinsockArchived(t)
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

func TestStandaloneProgramCanApplyWindowsTargetProfile(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
	path := filepath.Join(t.TempDir(), "afd_accept_get_qos.txt")
	text := []byte(`WSAStartup(0x202, &(0x7f0000000000)=0x0)
r0 = socket$accept_tcp(0x2, 0x1, 0x6)
NtDeviceIoControlFile$afd_get_qos_accept(r0, 0x0, 0x0, 0x0, &(0x7f0000000100)={@Status=0x0, 0x0}, 0x12098, 0x0, 0x0, &(0x7f0000000140), 0x58)
`)
	if err := os.WriteFile(path, text, 0o644); err != nil {
		t.Fatal(err)
	}
	profiled, err := standaloneTarget("afd")
	if err != nil {
		t.Fatalf("standaloneTarget(afd): %v", err)
	}
	p, bootstrap, label, err := standaloneBaseProgram(profiled, "", 0, path)
	if err != nil {
		t.Fatalf("standaloneBaseProgram with afd profile: %v", err)
	}
	if bootstrap {
		t.Fatal("profiled file program should not be treated as bootstrap")
	}
	if label != path {
		t.Fatalf("label=%q, want %q", label, path)
	}
	if !standaloneProgramContainsCall(p, "NtDeviceIoControlFile$afd_get_qos_accept") {
		t.Fatalf("profiled standalone program missing afd_get_qos_accept:\n%s", p.Serialize())
	}
	if _, err := p.SerializeForExec(); err != nil {
		t.Fatalf("SerializeForExec profiled AFD standalone program: %v", err)
	}
	if _, err := standaloneTarget("missing"); err == nil {
		t.Fatal("standaloneTarget accepted missing profile")
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
		"standalone-no-cover",
		"standalone-fixed-repeat",
		"runStandaloneExec(",
		"runStandaloneExecStaged(",
		"standalone fixed-repeat program",
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
		if os.IsNotExist(err) {
			t.Skipf("run-nyx-fullchain.sh is outside this test environment: %v", err)
		}
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	scriptSrc := string(scriptData)
	for _, want := range []string{
		"--standalone-exec-program",
		"--standalone-staged-exec-program",
		"standalone_exec_program",
		"standalone_staged_exec_program",
		"standalone_no_cover",
		"standalone_fixed_repeat",
	} {
		if !strings.Contains(scriptSrc, want) {
			t.Fatalf("run-nyx-fullchain standalone exec replay support missing %q", want)
		}
	}
}

func TestFullchainManagerReplayDiagnosticsAreWired(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "..", "guest-vm", "run-nyx-fullchain.sh")
	scriptData, err := os.ReadFile(scriptPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("run-nyx-fullchain.sh is outside this test environment: %v", err)
		}
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	scriptSrc := string(scriptData)
	for _, want := range []string{
		"--candidate-run-repeat",
		"candidate_run_repeat",
		"-candidate_run_repeat",
		"--manager-request-history-dir",
		"MANAGER_REQUEST_HISTORY_DIR",
		"SYZ_MANAGER_REQUEST_HISTORY_DIR",
		"resolve_output_paths",
		`MANAGER_LOG="$study_dir/manager.log"`,
		`RUNNER_LOG="$study_dir/runner.log"`,
		`STATS_OUTPUT="$study_dir/stats.csv"`,
		`STATS_DIR="$study_dir/stats"`,
	} {
		if !strings.Contains(scriptSrc, want) {
			t.Fatalf("run-nyx-fullchain manager replay diagnostics missing %q", want)
		}
	}
}

func TestFullchainBincoverEnablesRawCover(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "..", "guest-vm", "run-nyx-fullchain.sh")
	scriptData, err := os.ReadFile(scriptPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("run-nyx-fullchain.sh is outside this test environment: %v", err)
		}
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	scriptSrc := string(scriptData)
	for _, want := range []string{
		`"$manager_workdir_from_env" != "1" && "$collect_bincover" != "1"`,
		`jq_filter="$jq_filter | .raw_cover = true"`,
		`--collect-bincover requires syz-manager mode`,
		`reference/how-to-check-coverage/guest-afd.sys.i64`,
		`reference/afd.sys.i64 is not the guest VM afd.sys IDB`,
	} {
		if !strings.Contains(scriptSrc, want) {
			t.Fatalf("run-nyx-fullchain bincover config materialization missing %q", want)
		}
	}
}

func TestFullchainNyxMemoryOverrideIsWired(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "..", "guest-vm", "run-nyx-fullchain.sh")
	scriptData, err := os.ReadFile(scriptPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("run-nyx-fullchain.sh is outside this test environment: %v", err)
		}
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	scriptSrc := string(scriptData)
	for _, want := range []string{
		`NYX_MEMORY="${NYX_MEMORY:-4096}"`,
		`jq_filter="$jq_filter | .vm.memory = (\$vm_memory | tonumber)"`,
		`--arg vm_memory "$NYX_MEMORY"`,
		`--memory "$NYX_MEMORY"`,
		`Using manager config copy with memory`,
	} {
		if !strings.Contains(scriptSrc, want) {
			t.Fatalf("run-nyx-fullchain memory override missing %q", want)
		}
	}
}

func TestFullchainBuildSkipEnvironmentDefaultsAreWired(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "..", "guest-vm", "run-nyx-fullchain.sh")
	scriptData, err := os.ReadFile(scriptPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("run-nyx-fullchain.sh is outside this test environment: %v", err)
		}
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	scriptSrc := string(scriptData)
	for _, want := range []string{
		`keep_overlay="${KEEP_OVERLAY:-0}"`,
		`keep_workdir="${KEEP_WORKDIR:-0}"`,
		`skip_host_build="${SKIP_HOST_BUILD:-0}"`,
		`skip_executor_build="${SKIP_EXECUTOR_BUILD:-0}"`,
		`skip_guest_prepare="${SKIP_GUEST_PREPARE:-0}"`,
		`collect_stats="${COLLECT_STATS:-0}"`,
	} {
		if !strings.Contains(scriptSrc, want) {
			t.Fatalf("run-nyx-fullchain build-skip env default missing %q", want)
		}
	}
}

func TestFullchainPersistsSlowTraceArtifacts(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "..", "guest-vm", "run-nyx-fullchain.sh")
	scriptData, err := os.ReadFile(scriptPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("run-nyx-fullchain.sh is outside this test environment: %v", err)
		}
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	scriptSrc := string(scriptData)
	for _, want := range []string{
		`SLOW_TRACE_DIR="${SLOW_TRACE_DIR:-}"`,
		`SLOW_TRACE_DIR="$(dirname "$MANAGER_LOG")/slow-traces"`,
		`SYZ_NYX_SLOW_TRACE_DIR="$SLOW_TRACE_DIR"`,
		`SYZ_NYX_SLOW_TRACE_THRESHOLD_MS="$SLOW_TRACE_THRESHOLD_MS"`,
		`SYZ_NYX_SLOW_TRACE_MAX_EVENTS="$SLOW_TRACE_MAX_EVENTS"`,
		`--slow-trace-dir "$SLOW_TRACE_DIR"`,
		`--slow-trace-threshold-ms "$SLOW_TRACE_THRESHOLD_MS"`,
		`--slow-trace-max-events "$SLOW_TRACE_MAX_EVENTS"`,
	} {
		if !strings.Contains(scriptSrc, want) {
			t.Fatalf("run-nyx-fullchain slow trace persistence missing %q", want)
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

func TestRunnerSuccessPathLogsAreDebugOnly(t *testing.T) {
	mainData, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	mainSrc := string(mainData)

	executeHandshake := extractFunctionBody(t, mainSrc, "func (vm *nyxVM) executeHandshake")
	for _, want := range []string{
		`vm.debugLogf("runner handshake ack observed`,
	} {
		if !strings.Contains(executeHandshake, want) {
			t.Fatalf("executeHandshake should gate success log with debugLogf: missing %q", want)
		}
	}
	for _, bad := range []string{
		`log.Logf(0, "runner handshake ack observed`,
	} {
		if strings.Contains(executeHandshake, bad) {
			t.Fatalf("executeHandshake should not emit high-frequency success log by default: %q", bad)
		}
	}

	executeRequest := extractFunctionBody(t, mainSrc, "func (vm *nyxVM) executeRequest")
	for _, want := range []string{
		`vm.debugLogf("runner exec result observed before step=%d"`,
		`vm.debugLogf("runner exec observed exec_done at step=%d but result file is not present yet"`,
	} {
		if !strings.Contains(executeRequest, want) {
			t.Fatalf("executeRequest should gate success log with debugLogf: missing %q", want)
		}
	}
	for _, bad := range []string{
		`log.Logf(0, "runner exec result observed before step=%d"`,
		`log.Logf(0, "runner exec observed exec_done at step=%d but result file is not present yet"`,
	} {
		if strings.Contains(executeRequest, bad) {
			t.Fatalf("executeRequest should not emit high-frequency success log by default: %q", bad)
		}
	}

	ensureHandshake := extractFunctionBody(t, mainSrc, "func (r *runner) ensureHandshake")
	for _, want := range []string{
		`r.vm.debugLogf("runner sending handshake`,
		`r.vm.debugLogf("runner handshake complete"`,
	} {
		if !strings.Contains(ensureHandshake, want) {
			t.Fatalf("ensureHandshake should gate success log with debugLogf: missing %q", want)
		}
	}
	for _, bad := range []string{
		`log.Logf(0, "runner sending handshake`,
		`log.Logf(0, "runner handshake complete"`,
	} {
		if strings.Contains(ensureHandshake, bad) {
			t.Fatalf("ensureHandshake should not emit high-frequency success log by default: %q", bad)
		}
	}

	handle := extractFunctionBody(t, mainSrc, "func (r *runner) executeRequestOnce")
	for _, want := range []string{
		`r.vm.debugLogf("%s request:`,
		`r.vm.debugLogf("%s program:`,
		"if r.vm.debug {\n\t\t\t\tlogModuleCoverage",
		"if r.vm.debug {\n\t\t\tlogCallFeedback",
		`r.vm.debugLogf("%s complete:`,
		`log.Logf(0, "%s complete:`,
	} {
		if !strings.Contains(handle, want) {
			t.Fatalf("executeRequestOnce log gating missing %q", want)
		}
	}
	for _, bad := range []string{
		`log.Logf(0, "%s request:`,
		`log.Logf(0, "%s program:`,
	} {
		if strings.Contains(handle, bad) {
			t.Fatalf("executeRequestOnce should not emit high-frequency success log by default: %q", bad)
		}
	}

	loop := extractFunctionBody(t, mainSrc, "func (r *runner) loop")
	for _, want := range []string{
		`r.vm.debugLogf("runner received ExecRequest`,
		`r.vm.debugLogf("runner received StateRequest"`,
		`r.vm.debugLogf("runner received SignalUpdate"`,
		`r.vm.debugLogf("runner received CorpusTriaged"`,
	} {
		if !strings.Contains(loop, want) {
			t.Fatalf("runner loop should gate message receive log with debugLogf: missing %q", want)
		}
	}

	if !strings.Contains(mainSrc, `log.Logf(0, "runner slow trace saved:`) {
		t.Fatal("slow trace artifact path must remain visible in default logs")
	}
}

func TestRunnerDoesNotDrainReloadBeforeNextPayload(t *testing.T) {
	mainData, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	mainSrc := string(mainData)
	if strings.Contains(mainSrc, "drainExecReload") ||
		strings.Contains(mainSrc, "reload_drain") {
		t.Fatal("runner should not release QEMU to drain reload before writing the next payload")
	}
	executeRequest := extractFunctionBody(t, mainSrc, "func (vm *nyxVM) executeRequest")
	for _, bad := range []string{
		"drainReload bool",
		"drain_reload",
	} {
		if strings.Contains(executeRequest, bad) {
			t.Fatalf("executeRequest should not contain post-result reload drain construct %q", bad)
		}
	}
	handle := extractFunctionBody(t, mainSrc, "func (r *runner) executeRequestOnce")
	if !strings.Contains(handle, "The pending root reload is consumed by the next payload release") {
		t.Fatal("executeRequestOnce should document that reload is deferred until the next payload is written")
	}
}

func TestStandaloneGenericProgramsReceiveTransitiveScaffold(t *testing.T) {
	skipLegacyAfdWinsockArchived(t)
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
			name: "setsockopt$update_connect_context",
			want: []string{"WSAStartup(", "socket$inet_tcp(", "ConnectEx$inet_tcp_pending(", "WSAGetOverlappedResult$connect_pending(", "GetQueuedCompletionStatus$socket(", "setsockopt$update_connect_context("},
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
			test.name == "setsockopt$update_connect_context" ||
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
		"windows_yield_until_event(&th->idle, kWindowsWorkerIdleYields,",
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
	if strings.Contains(body, "event_timedwait(&th->idle") {
		t.Fatal("schedule_call should not use a guest-timer-based idle wait")
	}
	if !strings.Contains(body, "kWindowsWorkerIdleWaitMs") {
		t.Fatal("schedule_call should pass the worker idle time budget")
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

func TestWindowsExecutorWorkerIdleWaitIsBounded(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	helper := extractFunctionBody(t, string(data), "static int windows_yield_until_event")
	for _, needle := range []string{
		"uint64 deadline_ms = current_time_ms() + max_wait_ms;",
		"for (uint64 i = 0; i < max_yields; i++)",
		"event_isset(ev)",
		"current_time_ms() >= deadline_ms",
		"SwitchToThread()",
		"Sleep(0)",
	} {
		if !strings.Contains(helper, needle) {
			t.Fatalf("windows_yield_until_event missing bounded-yield construct %q", needle)
		}
	}
	if strings.Contains(helper, "event_timedwait") ||
		strings.Contains(helper, "WaitForSingleObject") {
		t.Fatal("windows_yield_until_event should not use a blocking guest wait")
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
		"thread_start(worker_thread, th);",
		"thread_create_pre_idle_wait",
		"windows_yield_until_event(&th->idle, kWindowsWorkerIdleYields,",
		"thread_create_post_idle_wait",
		"event_set(&th->done);",
	} {
		if !strings.Contains(threadCreate, needle) {
			t.Fatalf("thread_create missing initialization %q", needle)
		}
	}
	if strings.Index(threadCreate, "thread_start(worker_thread, th);") >
		strings.Index(threadCreate, "event_set(&th->done);") {
		t.Fatal("Windows thread_create should start the worker before marking it done")
	}
	if strings.Index(threadCreate, "thread_create_pre_idle_wait") >
		strings.Index(threadCreate, "thread_create_post_idle_wait") {
		t.Fatal("thread_create should log idle wait begin before idle wait result")
	}
	if !strings.Contains(threadCreate, "kWindowsWorkerIdleWaitMs") {
		t.Fatal("thread_create should pass the worker idle time budget")
	}
	if strings.Index(threadCreate, "thread_create_post_idle_wait") >
		strings.Index(threadCreate, "event_set(&th->done);") {
		t.Fatal("thread_create should wait for the worker idle breadcrumb before marking done")
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
		"bool is_syn = (flags & (SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_SYN | SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_ACK)) == SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_SYN",
		"bool is_synack = (flags & (SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_SYN | SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_ACK)) == (SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_SYN | SYZ_WINDOWS_NET_INJECTION_TCP_FLAG_ACK)",
		"(!is_syn && !is_synack)",
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
	skipLegacyAfdWinsockArchived(t)
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

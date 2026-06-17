package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys" // trigger register.go init()
)

type sparseEntry struct {
	macro string
	name  string
}

type serviceEntry struct {
	kind        string
	macro       string
	targetName  string
	serviceName string
	number      string
}

type windowsNyxConfig struct {
	EnabledSyscalls []string `json:"enable_syscalls"`
}

func main() {
	write := flag.Bool("w", false, "rewrite executor/syscalls_windows_nyx_demo.h with current windows/amd64 target IDs")
	flag.Parse()

	t, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERR:", err)
		os.Exit(1)
	}
	sparse, err := readSparseEntries("executor/syscalls_windows_nyx_demo.h")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERR:", err)
		os.Exit(1)
	}
	services, err := readServiceEntries("executor/windows_service_26200.h")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERR:", err)
		os.Exit(1)
	}
	if *write {
		kept, removed, err := rewriteSparseTable(t, services, "executor/syscalls_windows_nyx_demo.h")
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERR:", err)
			os.Exit(1)
		}
		fmt.Printf("Rewrote executor/syscalls_windows_nyx_demo.h: kept=%d removed_stale=%d\n", kept, removed)
		return
	}
	enabledUnmapped, err := enabledUnmappedCalls(t, sparse, "tools/syz-nyx-runner/windows-nyx-test.cfg")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERR:", err)
		os.Exit(1)
	}
	fmt.Printf("Windows target syscalls: %d\n", len(t.Syscalls))
	fmt.Printf("Nyx executable entries: %d\n", len(sparse))
	fmt.Printf("NT service-number entries: %d\n", countServiceKind(services, "ntos"))
	fmt.Printf("win32k service-number entries: %d\n", countServiceKind(services, "win32k"))
	fmt.Printf("Enabled but unmapped calls: %d\n", len(enabledUnmapped))
	for _, name := range enabledUnmapped {
		fmt.Printf("  UNMAPPED enabled syscall: %s\n", name)
	}
	for _, entry := range sparse {
		if s := t.SyscallMap[entry.name]; s != nil {
			fmt.Printf("#define %-32s %d\n", entry.macro, s.ID)
		} else {
			fmt.Printf("// MISSING: %s %s\n", entry.macro, entry.name)
		}
	}
	for _, entry := range services {
		if s := t.SyscallMap[entry.targetName]; s == nil {
			fmt.Printf("// SERVICE MISSING: %s %s %s\n", entry.kind, entry.macro, entry.targetName)
		}
	}
}

func readSparseEntries(path string) ([]sparseEntry, error) {
	table, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`syscalls\[(W32_[A-Z0-9_]+)\]\s*=\s*call_t\{\"([^\"]+)\"`)
	var entries []sparseEntry
	for _, match := range re.FindAllSubmatch(table, -1) {
		entries = append(entries, sparseEntry{
			macro: string(match[1]),
			name:  string(match[2]),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].macro < entries[j].macro })
	return entries, nil
}

func rewriteSparseTable(target *prog.Target, services []serviceEntry, path string) (int, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	src := string(data)
	stmtRe := regexp.MustCompile(`(?ms)^\s*syscalls\[(W32_[A-Z0-9_]+)\]\s*=\s*call_t\{"([^"]+)".*?;\n`)
	matches := stmtRe.FindAllStringSubmatchIndex(src, -1)
	if len(matches) == 0 {
		return 0, 0, fmt.Errorf("no sparse syscall assignment statements found in %s", path)
	}
	var out strings.Builder
	macroIDs := make(map[string]int)
	last := 0
	kept, removed := 0, 0
	for _, match := range matches {
		out.WriteString(src[last:match[0]])
		stmt := src[match[0]:match[1]]
		macro := src[match[2]:match[3]]
		name := src[match[4]:match[5]]
		meta := target.SyscallMap[name]
		if meta == nil {
			removed++
		} else {
			macroIDs[macro] = meta.ID
			out.WriteString(stmt)
			kept++
		}
		last = match[1]
	}
	out.WriteString(src[last:])
	src = out.String()

	for _, entry := range services {
		meta := target.SyscallMap[entry.targetName]
		if meta == nil {
			return 0, 0, fmt.Errorf("service entry target %q missing from windows/amd64 target", entry.targetName)
		}
		macroIDs[entry.macro] = meta.ID
	}

	include := `#include "windows_service_26200.h"`
	includeAt := strings.Index(src, include)
	if includeAt == -1 {
		return 0, 0, fmt.Errorf("%s marker not found in %s", include, path)
	}
	before := src[:includeAt]
	after := src[includeAt:]
	defineRe := regexp.MustCompile(`(?m)^#define\s+W32_[A-Z0-9_]+\s+\d+\n`)
	before = defineRe.ReplaceAllString(before, "")

	macros := make([]string, 0, len(macroIDs))
	for macro := range macroIDs {
		macros = append(macros, macro)
	}
	sort.Strings(macros)
	var defs strings.Builder
	for _, macro := range macros {
		fmt.Fprintf(&defs, "#define %-32s %d\n", macro, macroIDs[macro])
	}

	rewritten := strings.TrimRight(before, "\n") + "\n" + defs.String() + after
	if rewritten == string(data) {
		return kept, removed, nil
	}
	if err := os.WriteFile(path, []byte(rewritten), 0644); err != nil {
		return 0, 0, err
	}
	return kept, removed, nil
}

func readServiceEntries(path string) ([]serviceEntry, error) {
	table, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`X\((ntos|win32k),\s*(W32_[A-Z0-9_]+),\s*"([^"]+)",\s*"([^"]+)",\s*([0-9]+)\)`)
	var entries []serviceEntry
	for _, match := range re.FindAllSubmatch(table, -1) {
		entries = append(entries, serviceEntry{
			kind:        string(match[1]),
			macro:       string(match[2]),
			targetName:  string(match[3]),
			serviceName: string(match[4]),
			number:      string(match[5]),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].targetName < entries[j].targetName })
	return entries, nil
}

func countServiceKind(entries []serviceEntry, kind string) int {
	count := 0
	for _, entry := range entries {
		if entry.kind == kind {
			count++
		}
	}
	return count
}

func enabledUnmappedCalls(target *prog.Target, sparse []sparseEntry, cfgPath string) ([]string, error) {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}
	var cfg windowsNyxConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	sparseNames := make(map[string]bool)
	for _, entry := range sparse {
		sparseNames[entry.name] = true
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, name := range cfg.EnabledSyscalls {
		call := target.SyscallMap[name]
		if call == nil {
			return nil, fmt.Errorf("enabled syscall %q missing from target", name)
		}
		enabled[call] = true
	}
	expanded, disabled := target.TransitivelyEnabledCalls(enabled)
	if len(disabled) != 0 {
		return nil, fmt.Errorf("disabled after expansion: %v", disabled)
	}
	var unmapped []string
	for call := range expanded {
		if !sparseNames[call.Name] {
			unmapped = append(unmapped, call.Name)
		}
	}
	sort.Strings(unmapped)
	return unmapped, nil
}

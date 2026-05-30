package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"

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

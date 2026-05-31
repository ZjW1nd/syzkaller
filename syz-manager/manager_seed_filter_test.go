package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestCollideEnabledForConfig(t *testing.T) {
	if !collideEnabledForConfig(nil) {
		t.Fatal("nil config should default to collide enabled")
	}
	cfg := &mgrconfig.Config{
		Experimental: mgrconfig.Experimental{},
		Derived: mgrconfig.Derived{
			TargetOS: "windows",
			VMLess:   true,
		},
	}
	if !collideEnabledForConfig(cfg) {
		t.Fatal("windows vmless should default to collide enabled")
	}
	cfg.Experimental.WindowsVMLessCollide = true
	if !collideEnabledForConfig(cfg) {
		t.Fatal("windows vmless compatibility option should keep collide enabled")
	}
	cfg.TargetOS = "linux"
	cfg.Experimental.WindowsVMLessCollide = false
	if !collideEnabledForConfig(cfg) {
		t.Fatal("non-windows targets should keep collide enabled")
	}
}

func TestLoadBorrowingSeedsFiltersByPrefix(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	seedDir := filepath.Join(dir, "sys", "windows", "test")
	if err := os.MkdirAll(seedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	good := []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
		"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
		"connect$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e33, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"send$inet_tcp(r0, 'ping', 0x4, 0x0)\n")
	if err := os.WriteFile(filepath.Join(seedDir, "nyx_afd_sample.txt"), good, 0o644); err != nil {
		t.Fatal(err)
	}
	other := []byte("test$manual(0x1)\n")
	if err := os.WriteFile(filepath.Join(seedDir, "other.txt"), other, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &mgrconfig.Config{
		Syzkaller: dir,
		Experimental: mgrconfig.Experimental{
			BorrowingSeedPrefix: "nyx_afd_",
		},
		Derived: mgrconfig.Derived{
			TargetOS: "windows",
			Target:   target,
		},
	}
	progs := manager.LoadBorrowingSeeds(cfg)
	if len(progs) != 1 {
		t.Fatalf("got %d borrowing seeds, want 1", len(progs))
	}
	if got := string(progs[0].Serialize()); got == "" {
		t.Fatal("loaded borrowing seed serialized to empty program")
	}
	parsed, err := manager.ParseSeed(target, good)
	if err != nil {
		t.Fatal(err)
	}
	if string(progs[0].Serialize()) != string(parsed.Serialize()) {
		t.Fatalf("loaded borrowing seed mismatch:\n%s\nwant:\n%s", progs[0].Serialize(), parsed.Serialize())
	}
}

func TestLoadBorrowingSeedsSkipsNoGenerateCalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	seedDir := filepath.Join(dir, "sys", "windows", "test")
	if err := os.MkdirAll(seedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stable := []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
		"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
		"connect$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e33, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"send$inet_tcp(r0, 'ping', 0x4, 0x0)\n")
	if err := os.WriteFile(filepath.Join(seedDir, "nyx_afd_stable.txt"), stable, 0o644); err != nil {
		t.Fatal(err)
	}
	seedOnly := []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
		"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n" +
		"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"listen$inet_tcp(r0, 0x1)\n" +
		"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
		"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n" +
		"r3 = WSACreateEvent()\n" +
		"WSAEventSelect$accept(r2, r3, 0x3f)\n" +
		"WSAEnumNetworkEvents$accept(r2, r3, &(0x7f0000000280))\n")
	if err := os.WriteFile(filepath.Join(seedDir, "nyx_afd_seed_only.txt"), seedOnly, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &mgrconfig.Config{
		Syzkaller: dir,
		Experimental: mgrconfig.Experimental{
			BorrowingSeedPrefix: "nyx_afd_",
		},
		Derived: mgrconfig.Derived{
			TargetOS: "windows",
			Target:   target,
		},
	}
	progs := manager.LoadBorrowingSeeds(cfg)
	if len(progs) != 1 {
		t.Fatalf("got %d borrowing seeds, want 1", len(progs))
	}
	got := string(progs[0].Serialize())
	if !strings.Contains(got, "send$inet_tcp") {
		t.Fatalf("stable borrowing seed was not loaded:\n%s", got)
	}
	if strings.Contains(got, "WSAEventSelect$accept") || strings.Contains(got, "WSAEnumNetworkEvents$accept") {
		t.Fatalf("seed-only async calls leaked into borrowing corpus:\n%s", got)
	}
}

func TestLoadSeedsFiltersRegularSeedsByPrefix(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	seedDir := filepath.Join(dir, "sys", "windows", "test")
	if err := os.MkdirAll(seedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	good := []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
		"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n" +
		"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e33, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"listen$inet_tcp(r0, 0x1)\n" +
		"r1 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n" +
		"recv$inet_accept(r1, &(0x7f00000001a0)='\\x00'/64, 0x40, 0x0)\n")
	if err := os.WriteFile(filepath.Join(seedDir, "nyx_afd_accept_sample.txt"), good, 0o644); err != nil {
		t.Fatal(err)
	}
	other := []byte("r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n" +
		"NtFsControlFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)='\\x00'/128, 0x9c040, &(0x7f0000000200)='\\x00'/512, 0x200)\n")
	if err := os.WriteFile(filepath.Join(seedDir, "nyx_ntfs_sample.txt"), other, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := mgrconfig.DefaultValues()
	cfg.Syzkaller = dir
	cfg.Workdir = t.TempDir()
	cfg.Experimental.SeedPrefix = "nyx_afd_accept_"
	cfg.Derived.TargetOS = "windows"
	cfg.Derived.Target = target

	info, err := manager.LoadSeeds(cfg, true)
	if err != nil {
		t.Fatalf("LoadSeeds: %v", err)
	}
	if len(info.Candidates) != 1 {
		t.Fatalf("got %d regular seeds, want 1", len(info.Candidates))
	}
	got := string(info.Candidates[0].Prog.Serialize())
	if !strings.Contains(got, "recv$inet_accept") {
		t.Fatalf("filtered regular seed mismatch:\n%s", got)
	}
}

func TestFilterCandidatesKeepsNoGenerateSeedCalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p := parseSeedProgram(t, target, []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
		"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
		"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
		"listen$inet_tcp(r0, 0x1)\n"+
		"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
		"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
		"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
		"r3 = WSACreateEvent()\n"+
		"WSAEventSelect$accept(r2, r3, 0x3f)\n"+
		"WSAEnumNetworkEvents$accept(r2, r3, &(0x7f0000000280))\n"))
	enabled := enabledWithoutNoGenerate(p)
	filtered := manager.FilterCandidates([]fuzzer.Candidate{{
		Prog:  p,
		Flags: fuzzer.ProgMinimized,
	}}, enabled, true)
	if len(filtered.Candidates) != 1 {
		t.Fatalf("got %d filtered candidates, want 1", len(filtered.Candidates))
	}
	if len(filtered.ModifiedHashes) != 0 {
		t.Fatalf("seed-only calls should not make regular seeds look modified")
	}
	got := string(filtered.Candidates[0].Prog.Serialize())
	if !strings.Contains(got, "WSAEventSelect$accept") ||
		!strings.Contains(got, "WSAEnumNetworkEvents$accept") {
		t.Fatalf("seed-only async calls were filtered out of regular seed:\n%s", got)
	}
}

func TestFilterCandidatesFiltersNoGenerateCorpusCalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p := parseSeedProgram(t, target, []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
		"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
		"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
		"listen$inet_tcp(r0, 0x1)\n"+
		"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
		"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
		"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
		"r3 = WSACreateEvent()\n"+
		"WSAEventSelect$accept(r2, r3, 0x3f)\n"+
		"WSAEnumNetworkEvents$accept(r2, r3, &(0x7f0000000280))\n"))
	enabled := enabledWithoutNoGenerate(p)
	filtered := manager.FilterCandidates([]fuzzer.Candidate{{
		Prog:  p,
		Flags: fuzzer.ProgFromCorpus | fuzzer.ProgMinimized,
	}}, enabled, true)
	if len(filtered.Candidates) != 1 {
		t.Fatalf("got %d filtered candidates, want 1", len(filtered.Candidates))
	}
	if len(filtered.ModifiedHashes) != 1 {
		t.Fatalf("got %d modified hashes, want 1", len(filtered.ModifiedHashes))
	}
	got := string(filtered.Candidates[0].Prog.Serialize())
	if strings.Contains(got, "WSAEventSelect$accept") ||
		strings.Contains(got, "WSAEnumNetworkEvents$accept") {
		t.Fatalf("seed-only async calls leaked into corpus candidate:\n%s", got)
	}
}

func TestWindowsAFDAsyncConfigKeepsSeedOnlyCallsInSeeds(t *testing.T) {
	cfg, err := mgrconfig.LoadPartialFile(filepath.Join("..", "tools", "syz-nyx-runner", "windows-nyx-afd-async.cfg"))
	if err != nil {
		t.Fatalf("LoadPartialFile: %v", err)
	}
	cfg.Syzkaller = ".."
	cfg.Workdir = t.TempDir()
	cfg.Target, err = cfg.Target.ApplyTargetProfile(cfg.Target, cfg.Experimental.WindowsTargetProfile)
	if err != nil {
		t.Fatalf("ApplyTargetProfile: %v", err)
	}
	cfg.Syscalls, err = mgrconfig.ParseEnabledSyscalls(cfg.Target, cfg.EnabledSyscalls,
		cfg.DisabledSyscalls, mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	info, err := manager.LoadSeeds(cfg, true)
	if err != nil {
		t.Fatalf("LoadSeeds: %v", err)
	}
	enabled := make(map[*prog.Syscall]bool, len(cfg.Syscalls))
	for _, id := range cfg.Syscalls {
		enabled[cfg.Target.Syscalls[id]] = true
	}
	filtered := manager.FilterCandidates(info.Candidates, enabled, true)
	if len(filtered.Candidates) == 0 {
		t.Fatal("async focused config produced no seed candidates")
	}
	if len(filtered.ModifiedHashes) != 0 {
		t.Fatalf("async seed candidates were unexpectedly modified: %v", filtered.ModifiedHashes)
	}
	for _, candidate := range filtered.Candidates {
		if !progContainsNoGenerate(candidate.Prog) {
			t.Fatalf("async seed candidate lost seed-only calls:\n%s", candidate.Prog.Serialize())
		}
	}
}

func parseSeedProgram(t *testing.T, target *prog.Target, data []byte) *prog.Prog {
	t.Helper()
	p, err := manager.ParseSeed(target, data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func enabledWithoutNoGenerate(p *prog.Prog) map[*prog.Syscall]bool {
	enabled := make(map[*prog.Syscall]bool)
	for _, call := range p.Calls {
		if !call.Meta.Attrs.NoGenerate {
			enabled[call.Meta] = true
		}
	}
	return enabled
}

func progContainsNoGenerate(p *prog.Prog) bool {
	for _, call := range p.Calls {
		if call.Meta.Attrs.NoGenerate {
			return true
		}
	}
	return false
}

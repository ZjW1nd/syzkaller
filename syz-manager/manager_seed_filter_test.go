package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if collideEnabledForConfig(cfg) {
		t.Fatal("windows vmless should default to collide disabled")
	}
	cfg.Experimental.WindowsVMLessCollide = true
	if !collideEnabledForConfig(cfg) {
		t.Fatal("windows vmless collide opt-in should enable collide")
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
	progs := loadBorrowingSeeds(cfg)
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

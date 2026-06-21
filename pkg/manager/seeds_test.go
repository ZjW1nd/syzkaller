// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"reflect"
	"testing"

	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/prog"
)

func TestRequires(t *testing.T) {
	{
		requires := parseRequires([]byte("# requires: manual arch=amd64"))
		if !checkArch(requires, "amd64") {
			t.Fatalf("amd64 does not pass check")
		}
		if checkArch(requires, "riscv64") {
			t.Fatalf("riscv64 passes check")
		}
	}
	{
		requires := parseRequires([]byte("# requires: -arch=arm64 manual -arch=riscv64"))
		if !checkArch(requires, "amd64") {
			t.Fatalf("amd64 does not pass check")
		}
		if checkArch(requires, "riscv64") {
			t.Fatalf("riscv64 passes check")
		}
	}
}

func TestSplitSeedPrefixes(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{in: "", want: nil},
		{in: "smoke_", want: []string{"smoke_"}},
		{in: "socket_recv, file_open_", want: []string{
			"socket_recv",
			"file_open_",
		}},
		{in: " socket_wsarecv,, file_cancel ", want: []string{
			"socket_wsarecv",
			"file_cancel",
		}},
	}
	for _, test := range tests {
		if got := splitSeedPrefixes(test.in); !reflect.DeepEqual(got, test.want) {
			t.Fatalf("splitSeedPrefixes(%q)=%v, want %v", test.in, got, test.want)
		}
	}
}

func TestSeedMatchesAnyPrefix(t *testing.T) {
	prefixes := splitSeedPrefixes("socket_recv,file_open_")
	for _, name := range []string{
		"socket_recv.txt",
		"socket_recv_nonblock.txt",
		"file_open_read.txt",
	} {
		if !seedMatchesAnyPrefix(name, prefixes) {
			t.Fatalf("%s should match %v", name, prefixes)
		}
	}
	for _, name := range []string{
		"socket_connect.txt",
		"pipe_open_read.txt",
	} {
		if seedMatchesAnyPrefix(name, prefixes) {
			t.Fatalf("%s should not match %v", name, prefixes)
		}
	}
}

func TestFilterCandidatesCountsSeedOrigin(t *testing.T) {
	candidates := []fuzzer.Candidate{
		{Prog: &prog.Prog{}, Flags: fuzzer.ProgFromSeed | fuzzer.ProgMinimized},
		{Prog: &prog.Prog{}},
	}
	filtered := FilterCandidates(candidates, map[*prog.Syscall]bool{}, false)
	if filtered.SeedCount != 1 {
		t.Fatalf("SeedCount=%d, want 1", filtered.SeedCount)
	}
	if len(filtered.Candidates) != len(candidates) {
		t.Fatalf("kept %d candidates, want %d", len(filtered.Candidates), len(candidates))
	}
	if filtered.Candidates[0].Flags&fuzzer.ProgFromSeed == 0 {
		t.Fatal("seed candidate lost ProgFromSeed")
	}
	if filtered.Candidates[1].Flags&fuzzer.ProgFromSeed != 0 {
		t.Fatal("ordinary candidate was counted as seed")
	}
}

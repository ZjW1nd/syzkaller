package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
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
	cfg.Experimental.DisableCollide = true
	if collideEnabledForConfig(cfg) {
		t.Fatal("disable_collide should disable collide")
	}
}

func TestModeCandidateRunIsRegistered(t *testing.T) {
	for _, mode := range modes {
		if mode == ModeCandidateRun {
			if !mode.LoadCorpus {
				t.Fatal("candidate-run mode must load corpus seeds")
			}
			return
		}
	}
	t.Fatal("candidate-run mode is not registered")
}

func TestCandidateRunSourceRunsCandidatesOnceAndStops(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	first := parseSeedProgram(t, target, []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"))
	second := parseSeedProgram(t, target, []byte("WSACleanup()\n"))

	finished := make(chan error, 1)
	src := &candidateRunSource{
		candidates: []fuzzer.Candidate{
			{Prog: first},
			{Prog: second},
		},
		finish: func(err error) {
			finished <- err
		},
	}

	req1 := src.Next()
	req2 := src.Next()
	if req1 == nil || req2 == nil {
		t.Fatalf("candidate-run returned nil before exhausting candidates: %v %v", req1, req2)
	}
	if req1.Prog != first || req2.Prog != second {
		t.Fatal("candidate-run did not preserve candidate order")
	}
	if req1.Origin != "candidate-run" || req2.Origin != "candidate-run" {
		t.Fatalf("origins = %q/%q, want candidate-run", req1.Origin, req2.Origin)
	}
	wantFlags := flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover
	if req1.ExecOpts.ExecFlags&wantFlags != wantFlags ||
		req2.ExecOpts.ExecFlags&wantFlags != wantFlags {
		t.Fatalf("candidate-run requests flags = %v/%v, want at least %v",
			req1.ExecOpts.ExecFlags, req2.ExecOpts.ExecFlags, wantFlags)
	}
	if got := src.Next(); got != nil {
		t.Fatalf("candidate-run produced extra request after candidates: %v", got)
	}

	req2.Done(&queue.Result{Status: queue.Success})
	assertNoCandidateRunFinish(t, finished)
	req1.Done(&queue.Result{Status: queue.Success})
	assertCandidateRunFinish(t, finished, "")
}

func TestCandidateRunSourceRepeatsCandidatesDeterministically(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	first := parseSeedProgram(t, target, []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"))
	second := parseSeedProgram(t, target, []byte("WSACleanup()\n"))

	finished := make(chan error, 1)
	src := &candidateRunSource{
		candidates: []fuzzer.Candidate{
			{Prog: first},
			{Prog: second},
		},
		repeat: 2,
		finish: func(err error) {
			finished <- err
		},
	}

	var requests []*queue.Request
	for i := 0; i < 4; i++ {
		req := src.Next()
		if req == nil {
			t.Fatalf("candidate-run returned nil at request %d", i+1)
		}
		requests = append(requests, req)
	}
	if got := src.Next(); got != nil {
		t.Fatalf("candidate-run produced extra request after repeats: %v", got)
	}
	for i, want := range []*prog.Prog{first, second, first, second} {
		if requests[i].Prog != want {
			t.Fatalf("request %d program=%p, want %p", i+1, requests[i].Prog, want)
		}
	}

	for _, req := range requests[:3] {
		req.Done(&queue.Result{Status: queue.Success})
	}
	assertNoCandidateRunFinish(t, finished)
	requests[3].Done(&queue.Result{Status: queue.Success})
	assertCandidateRunFinish(t, finished, "")
}

func TestCandidateRunSourceStopsAtLimit(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	first := parseSeedProgram(t, target, []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"))
	second := parseSeedProgram(t, target, []byte("WSACleanup()\n"))
	third := parseSeedProgram(t, target, []byte("VirtualAlloc(0x200000000000, 0x1000, 0x3000, 0x40)\n"))

	finished := make(chan error, 1)
	src := &candidateRunSource{
		candidates: []fuzzer.Candidate{
			{Prog: first},
			{Prog: second},
			{Prog: third},
		},
		limit: 2,
		finish: func(err error) {
			finished <- err
		},
	}

	req1 := src.Next()
	req2 := src.Next()
	if req1 == nil || req2 == nil {
		t.Fatalf("candidate-run returned nil before limit: %v %v", req1, req2)
	}
	if got := src.Next(); got != nil {
		t.Fatalf("candidate-run produced request after limit: %v", got)
	}
	req1.Done(&queue.Result{Status: queue.Success})
	assertNoCandidateRunFinish(t, finished)
	req2.Done(&queue.Result{Status: queue.Success})
	assertCandidateRunFinish(t, finished, "")
}

func TestCandidateRunSourceStopsOnFailure(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p := parseSeedProgram(t, target, []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"))

	finished := make(chan error, 1)
	src := &candidateRunSource{
		candidates: []fuzzer.Candidate{{Prog: p}},
		finish: func(err error) {
			finished <- err
		},
	}
	req := src.Next()
	if req == nil {
		t.Fatal("candidate-run returned nil")
	}
	req.Done(&queue.Result{Status: queue.Hanged})
	err = assertCandidateRunFinish(t, finished, "candidate 1 finished with status Hanged")
	if err == nil {
		t.Fatal("candidate-run failure should report an error")
	}
}

func TestLimitFocusedCandidates(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	first := parseSeedProgram(t, target, []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"))
	second := parseSeedProgram(t, target, []byte("WSACleanup()\n"))
	candidates := []fuzzer.Candidate{{Prog: first}, {Prog: second}}

	if got := limitFocusedCandidates(candidates, 0); len(got) != 2 {
		t.Fatalf("limit 0 returned %d candidates, want all", len(got))
	}
	limited := limitFocusedCandidates(candidates, 1)
	if len(limited) != 1 || limited[0].Prog != first {
		t.Fatalf("limit 1 returned %+v, want first candidate only", limited)
	}
	if got := limitFocusedCandidates(candidates, 3); len(got) != 2 {
		t.Fatalf("limit above size returned %d candidates, want all", len(got))
	}
}

func TestFocusedFuzzingGateEnabled(t *testing.T) {
	tests := []struct {
		name             string
		candidateLimit   int
		corpusMin        int
		candidateSaveMin int
		genMin           int
		collideMin       int
		want             bool
	}{
		{name: "disabled", want: false},
		{name: "candidate limit", candidateLimit: 1, want: true},
		{name: "corpus minimum", corpusMin: 1, want: true},
		{name: "candidate save minimum", candidateSaveMin: 1, want: true},
		{name: "generation minimum", genMin: 1, want: true},
		{name: "collide minimum", collideMin: 1, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := focusedFuzzingGateEnabled(test.candidateLimit, test.corpusMin,
				test.candidateSaveMin, test.genMin, test.collideMin); got != test.want {
				t.Fatalf("focusedFuzzingGateEnabled(%d, %d, %d, %d, %d) = %v, want %v",
					test.candidateLimit, test.corpusMin, test.candidateSaveMin, test.genMin,
					test.collideMin, got, test.want)
			}
		})
	}
}

func TestFocusedFuzzingGateDoneRequiresCorpusMinimum(t *testing.T) {
	done, err := focusedFuzzingGateDone(focusedFuzzingGateStats{CorpusPrograms: 1}, focusedFuzzingGateConfig{
		CorpusMin: 2,
	})
	if !done {
		t.Fatal("focused gate should finish once candidate triage drained")
	}
	if err == nil || !strings.Contains(err.Error(), "corpus=1, want at least 2") {
		t.Fatalf("focused gate error = %v, want corpus minimum failure", err)
	}
	done, err = focusedFuzzingGateDone(focusedFuzzingGateStats{CorpusPrograms: 2}, focusedFuzzingGateConfig{
		CorpusMin: 2,
	})
	if !done || err != nil {
		t.Fatalf("focused gate with enough corpus = (%v, %v), want done without error", done, err)
	}
	done, err = focusedFuzzingGateDone(focusedFuzzingGateStats{}, focusedFuzzingGateConfig{})
	if !done || err != nil {
		t.Fatalf("focused gate without corpus minimum = (%v, %v), want done without error", done, err)
	}
}

func TestFocusedFuzzingGateDoneRequiresCandidateSaves(t *testing.T) {
	done, err := focusedFuzzingGateDone(focusedFuzzingGateStats{
		CorpusPrograms: 3,
		CandidateSaves: 1,
	}, focusedFuzzingGateConfig{
		CorpusMin:        1,
		CandidateSaveMin: 2,
	})
	if !done {
		t.Fatal("focused gate should finish once candidate triage drained")
	}
	if err == nil || !strings.Contains(err.Error(), "candidate_saves=1, want at least 2") {
		t.Fatalf("focused gate error = %v, want candidate save minimum failure", err)
	}
	done, err = focusedFuzzingGateDone(focusedFuzzingGateStats{
		CorpusPrograms: 3,
		CandidateSaves: 2,
	}, focusedFuzzingGateConfig{
		CorpusMin:        1,
		CandidateSaveMin: 2,
	})
	if !done || err != nil {
		t.Fatalf("focused gate with enough candidate saves = (%v, %v), want done without error", done, err)
	}
}

func TestFocusedFuzzingGateWaitsForGenerationAndCollideMinimums(t *testing.T) {
	cfg := focusedFuzzingGateConfig{
		CorpusMin:        1,
		CandidateSaveMin: 1,
		GenMin:           1,
		CollideMin:       1,
	}
	done, err := focusedFuzzingGateDone(focusedFuzzingGateStats{
		CorpusPrograms: 1,
		CandidateSaves: 1,
	}, cfg)
	if done || err != nil {
		t.Fatalf("focused gate before gen/collide = (%v, %v), want continue", done, err)
	}
	done, err = focusedFuzzingGateDone(focusedFuzzingGateStats{
		CorpusPrograms: 1,
		CandidateSaves: 1,
		ExecFuzz:       1,
		ExecRegular:    1,
	}, cfg)
	if done || err != nil {
		t.Fatalf("focused gate before collide = (%v, %v), want continue", done, err)
	}
	done, err = focusedFuzzingGateDone(focusedFuzzingGateStats{
		CorpusPrograms: 1,
		CandidateSaves: 1,
		ExecGen:        1,
		ExecRegular:    1,
		ExecCollide:    1,
	}, cfg)
	if !done || err != nil {
		t.Fatalf("focused gate with gen/collide minimums = (%v, %v), want done without error", done, err)
	}
}

func TestFocusedFuzzingGateWaitsBeforeFailingMinimums(t *testing.T) {
	cfg := focusedFuzzingGateConfig{
		CorpusMin: 2,
		GenMin:    1,
	}
	done, err := focusedFuzzingGateDone(focusedFuzzingGateStats{
		CorpusPrograms: 1,
	}, cfg)
	if done || err != nil {
		t.Fatalf("focused gate before required gen = (%v, %v), want continue", done, err)
	}
	done, err = focusedFuzzingGateDone(focusedFuzzingGateStats{
		CorpusPrograms: 1,
		ExecRegular:    1,
	}, cfg)
	if !done || err == nil || !strings.Contains(err.Error(), "corpus=1, want at least 2") {
		t.Fatalf("focused gate after required gen = (%v, %v), want corpus failure", done, err)
	}
}

func TestFocusedCandidateSaveTrackerCountsDistinctCandidateTraces(t *testing.T) {
	mgr := &Manager{}
	mgr.recordFocusedCorpusSave(fuzzer.CorpusSaveEvent{
		Origin: "candidate", TraceID: "candidate-1", CallName: "recv$inet_accept",
	})
	mgr.recordFocusedCorpusSave(fuzzer.CorpusSaveEvent{
		Origin: "candidate", TraceID: "candidate-1", CallName: "accept$inet_tcp",
	})
	mgr.recordFocusedCorpusSave(fuzzer.CorpusSaveEvent{
		Origin: "candidate", TraceID: "candidate-2", CallName: "WSARecv$accept",
	})
	mgr.recordFocusedCorpusSave(fuzzer.CorpusSaveEvent{
		Origin: "collide:triage", TraceID: "collide-1", CallName: "WSARecv$accept",
	})
	mgr.recordFocusedCorpusSave(fuzzer.CorpusSaveEvent{
		Origin: "candidate", CallName: "ioctlsocket$fionbio_accept",
	})
	if got := mgr.focusedCandidateCorpusSaveCount(); got != 2 {
		t.Fatalf("focused candidate save count=%d, want distinct candidate traces only", got)
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

func TestLoadBorrowingSeedsSkipsDisabledCalls(t *testing.T) {
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
		"r0 = socket$connected_udp(0x2, 0x2, 0x11)\n" +
		"connect$inet_udp(r0, &(0x7f0000000100)={0x2, 0x4e33, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"send$inet_udp(r0, 'ping', 0x4, 0x0)\n")
	if err := os.WriteFile(filepath.Join(seedDir, "nyx_afd_allowed.txt"), good, 0o644); err != nil {
		t.Fatal(err)
	}
	disabled := []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
		"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n" +
		"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e33, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"listen$inet_tcp(r0, 0x1)\n" +
		"accept$inet_tcp(r0, 0x0, 0x0)\n")
	if err := os.WriteFile(filepath.Join(seedDir, "nyx_afd_disabled.txt"), disabled, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &mgrconfig.Config{
		Syzkaller:        dir,
		DisabledSyscalls: []string{"accept$inet_tcp"},
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
		t.Fatalf("got %d borrowing seeds, want only the allowed seed", len(progs))
	}
	if strings.Contains(string(progs[0].Serialize()), "accept$inet_tcp") {
		t.Fatalf("disabled borrowing seed was loaded:\n%s", progs[0].Serialize())
	}
}

func TestLoadBorrowingSeedsSkipsCallsNotEnabledByConfig(t *testing.T) {
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
		"r0 = socket$connected_udp(0x2, 0x2, 0x11)\n" +
		"connect$inet_udp(r0, &(0x7f0000000100)={0x2, 0x4e33, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"send$inet_udp(r0, 'ping', 0x4, 0x0)\n")
	if err := os.WriteFile(filepath.Join(seedDir, "nyx_afd_allowed.txt"), good, 0o644); err != nil {
		t.Fatal(err)
	}
	notEnabled := []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
		"r0 = socket$connected_udp(0x2, 0x2, 0x11)\n" +
		"connect$inet_udp(r0, &(0x7f0000000100)={0x2, 0x4e34, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"WSAIoctl$sio_get_interface_list(r0, 0x4004747f, 0x0, 0x0, &(0x7f0000000180)=[{}], 0x130, &(0x7f0000000300), 0x0, 0x0)\n")
	if err := os.WriteFile(filepath.Join(seedDir, "nyx_afd_not_enabled.txt"), notEnabled, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &mgrconfig.Config{
		Syzkaller: dir,
		EnabledSyscalls: []string{
			"WSAStartup",
			"socket$connected_udp",
			"connect$inet_udp",
			"send$inet_udp",
		},
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
		t.Fatalf("got %d borrowing seeds, want only the enabled seed", len(progs))
	}
	got := string(progs[0].Serialize())
	if !strings.Contains(got, "send$inet_udp") {
		t.Fatalf("enabled borrowing seed was not loaded:\n%s", got)
	}
	if strings.Contains(got, "WSAIoctl$sio_get_interface_list") {
		t.Fatalf("non-enabled borrowing seed was loaded:\n%s", got)
	}
}

func assertNoCandidateRunFinish(t *testing.T, finished <-chan error) {
	t.Helper()
	select {
	case err := <-finished:
		t.Fatalf("candidate-run finished too early: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
}

func assertCandidateRunFinish(t *testing.T, finished <-chan error, wantErrSubstring string) error {
	t.Helper()
	select {
	case err := <-finished:
		if wantErrSubstring == "" {
			if err != nil {
				t.Fatalf("candidate-run finished with error: %v", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), wantErrSubstring) {
			t.Fatalf("candidate-run error = %v, want substring %q", err, wantErrSubstring)
		}
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for candidate-run finish")
		return nil
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

func TestFilterCandidatesForConfigDropsDisabledSeedCalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p := parseSeedProgram(t, target, []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
		"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
		"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
		"listen$inet_tcp(r0, 0x1)\n"+
		"accept$inet_tcp(r0, 0x0, 0x0)\n"+
		"r1 = socket$connected_udp(0x2, 0x2, 0x11)\n"+
		"connect$inet_udp(r1, &(0x7f0000000120)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
		"send$inet_udp(r1, 'ping', 0x4, 0x0)\n"))
	enabled := enabledWithoutNoGenerate(p)
	cfg := &mgrconfig.Config{
		DisabledSyscalls: []string{"accept$inet_tcp"},
		Derived: mgrconfig.Derived{
			Target: target,
		},
	}

	filtered := manager.FilterCandidatesForConfig([]fuzzer.Candidate{{
		Prog:  p,
		Flags: fuzzer.ProgMinimized,
	}}, enabled, cfg, true)
	if len(filtered.Candidates) != 1 {
		t.Fatalf("got %d filtered candidates, want 1", len(filtered.Candidates))
	}
	if len(filtered.ModifiedHashes) != 1 {
		t.Fatalf("got %d modified hashes, want 1", len(filtered.ModifiedHashes))
	}
	got := string(filtered.Candidates[0].Prog.Serialize())
	if strings.Contains(got, "accept$inet_tcp") {
		t.Fatalf("disabled seed call leaked through config-aware filter:\n%s", got)
	}
	if !strings.Contains(got, "send$inet_udp") {
		t.Fatalf("unrelated enabled call was filtered out:\n%s", got)
	}
}

func TestFilterCandidatesKeepsAutomaticHelperSeedCalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p := parseSeedProgram(t, target, []byte("WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
		"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
		"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
		"listen$inet_tcp(r0, 0x1)\n"+
		"recv$inet_accept(r0, &(0x7f00000001a0)='\\x00'/64, 0x40, 0x0)\n"))
	enabled := enabledWithoutSeedScaffold(p)
	filtered := manager.FilterCandidates([]fuzzer.Candidate{{
		Prog:  p,
		Flags: fuzzer.ProgMinimized,
	}}, enabled, true)
	if len(filtered.Candidates) != 1 {
		t.Fatalf("got %d filtered candidates, want 1", len(filtered.Candidates))
	}
	if len(filtered.ModifiedHashes) != 0 {
		t.Fatalf("automatic helper calls should not make regular seeds look modified")
	}
	got := string(filtered.Candidates[0].Prog.Serialize())
	if !strings.Contains(got, "WSAStartup") {
		t.Fatalf("automatic helper was filtered out of regular seed:\n%s", got)
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

func enabledWithoutSeedScaffold(p *prog.Prog) map[*prog.Syscall]bool {
	enabled := make(map[*prog.Syscall]bool)
	for _, call := range p.Calls {
		if !call.Meta.Attrs.NoGenerate && !call.Meta.Attrs.AutomaticHelper {
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

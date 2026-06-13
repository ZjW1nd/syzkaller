// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
)

func TestNormalizePrios(t *testing.T) {
	prios := [][]int32{
		{2, 2, 2},
		{1, 2, 4},
		{1, 2, 0},
	}
	want := [][]int32{
		{10, 10, 10},
		{4, 8, 17},
		{10, 20, 0},
	}
	t.Logf("had:  %+v", prios)
	normalizePrios(prios, len(prios))
	if !reflect.DeepEqual(prios, want) {
		t.Logf("got:  %+v", prios)
		t.Errorf("want: %+v", want)
	}
}

// Test static priorities assigned based on argument direction.
func TestStaticPriorities(t *testing.T) {
	target := initTargetTest(t, "linux", "amd64")
	rs := rand.NewSource(0)
	// The test is probabilistic and needs some sensible number of iterations to succeed.
	// If it fails try to increase the number a bit.
	const iters = 200000
	// The first call is the one that creates a resource and the rest are calls that can use that resource.
	tests := [][]string{
		{"open", "read", "write", "mmap"},
		{"socket", "listen", "setsockopt"},
	}
	ct := target.DefaultChoiceTable()
	r := rand.New(rs)
	for _, syscalls := range tests {
		// Counts the number of times a call is chosen after a call that creates a resource (referenceCall).
		counter := make(map[string]int)
		referenceCall := syscalls[0]
		for _, call := range syscalls {
			count := 0
			for range iters {
				chosenCall := target.Syscalls[ct.choose(r, target.SyscallMap[call].ID)].Name
				if call == referenceCall {
					counter[chosenCall]++
				} else if chosenCall == referenceCall {
					count++
				}
			}
			if call == referenceCall {
				continue
			}
			// Checks that prio[callCreatesRes][callUsesRes] > prio[callUsesRes][callCreatesRes]
			if count >= counter[call] {
				t.Fatalf("too high priority for %s -> %s: %d vs %s -> %s: %d",
					call, referenceCall, count, referenceCall, call, counter[call])
			}
		}
	}
}

func TestPrioDeterminism(t *testing.T) {
	if testutil.RaceEnabled {
		t.Skip("skipping in race mode, too slow")
	}
	target, rs, iters := initTest(t)
	ct := target.DefaultChoiceTable()
	var corpus []*Prog
	for range 100 {
		corpus = append(corpus, target.Generate(rs, 10, ct))
	}
	ct0 := target.BuildChoiceTable(corpus, nil)
	ct1 := target.BuildChoiceTable(corpus, nil)
	if !reflect.DeepEqual(ct0.runs, ct1.runs) {
		t.Fatal("non-deterministic ChoiceTable")
	}
	for i := range iters {
		seed := rs.Int63()
		call0 := ct0.choose(rand.New(rand.NewSource(seed)), -1)
		call1 := ct1.choose(rand.New(rand.NewSource(seed)), -1)
		if call0 != call1 {
			t.Fatalf("seed=%v iter=%v call=%v/%v", seed, i, call0, call1)
		}
	}
}

func BenchmarkBuildChoiceTable(b *testing.B) {
	target, cleanup := initBench(b)
	defer cleanup()
	for range b.N {
		target.BuildChoiceTable(nil, nil)
	}
}

func TestAutomaticHelperDeprioritizedInChoiceTable(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	clone := *target
	clone.Helpers.DeprioritizeAutomaticHelpers = true

	enabled := map[*Syscall]bool{
		clone.SyscallMap["test$automatic"]:        true,
		clone.SyscallMap["test$automatic_helper"]: true,
		clone.SyscallMap["test$manual"]:           true,
	}
	ctBase := target.BuildChoiceTable(nil, enabled)
	ctDeprio := clone.BuildChoiceTable(nil, enabled)

	if len(ctDeprio.biasCalls) != 2 {
		t.Fatalf("got %d bias calls, want 2", len(ctDeprio.biasCalls))
	}
	for _, call := range ctDeprio.biasCalls {
		if call.Name == "test$automatic_helper" {
			t.Fatalf("automatic helper should not appear in bias calls: %+v", ctDeprio.biasCalls)
		}
	}

	const iters = 50000
	baseHelper := 0
	deprioHelper := 0
	rBase := rand.New(rand.NewSource(0))
	rDeprio := rand.New(rand.NewSource(0))
	for range iters {
		if target.Syscalls[ctBase.choose(rBase, -1)].Name == "test$automatic_helper" {
			baseHelper++
		}
		if clone.Syscalls[ctDeprio.choose(rDeprio, -1)].Name == "test$automatic_helper" {
			deprioHelper++
		}
	}
	if deprioHelper >= baseHelper/2 {
		t.Fatalf("automatic helper still chosen too often: base=%d deprio=%d", baseHelper, deprioHelper)
	}
}

func TestAutomaticHelperBiasIsIgnoredDuringGeneration(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	clone := *target
	clone.Helpers.DeprioritizeAutomaticHelpers = true
	clone.Helpers.AvoidAutomaticHelperBias = true
	enabled := map[*Syscall]bool{
		clone.SyscallMap["test$manual"]:           true,
		clone.SyscallMap["test$automatic_helper"]: true,
	}
	ct := clone.BuildChoiceTable(nil, enabled)
	p, err := clone.Deserialize([]byte("test$automatic_helper(0x0)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	s := newState(&clone, ct, nil)
	r := newRand(&clone, rand.NewSource(0))
	for range 100 {
		calls := r.generateCall(s, p, 1)
		if len(calls) == 0 {
			t.Fatal("generateCall returned no calls")
		}
		last := calls[len(calls)-1]
		if last.Meta.Name != "test$manual" {
			t.Fatalf("helper-biased generation picked %q, want test$manual", last.Meta.Name)
		}
	}
}

func TestAutomaticHelpersCanBeExcludedFromTopLevelGeneration(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	clone := *target
	clone.Helpers.NoGenerateAutomaticHelpers = true

	helper := clone.SyscallMap["test$automatic_helper"]
	manual := clone.SyscallMap["test$manual"]
	enabled := map[*Syscall]bool{
		helper: true,
		manual: true,
	}
	corpus, err := clone.Deserialize([]byte("test$automatic_helper(0x0)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	ct := clone.BuildChoiceTable([]*Prog{corpus}, enabled)
	if !ct.Generatable(helper.ID) {
		t.Fatal("automatic helper should remain enabled for constructor use")
	}
	if ct.DirectlyGeneratable(helper.ID) {
		t.Fatal("automatic helper should not be a direct top-level generation choice")
	}
	if !ct.DirectlyGeneratable(manual.ID) {
		t.Fatal("manual syscall should remain a direct top-level generation choice")
	}

	r := rand.New(rand.NewSource(0))
	for range 1000 {
		if got := clone.Syscalls[ct.choose(r, helper.ID)].Name; got != "test$manual" {
			t.Fatalf("helper-biased choice picked %q, want test$manual", got)
		}
	}
}

func TestNoDirectCallsStayAvailableAsResourceConstructors(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	helper := target.SyscallMap["test$automatic_helper"]
	manual := target.SyscallMap["test$manual"]
	enabled := map[*Syscall]bool{
		helper: true,
		manual: true,
	}
	corpus, err := target.Deserialize([]byte("test$automatic_helper(0x0)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	ct := target.BuildChoiceTableWithNoDirectCalls([]*Prog{corpus}, enabled, map[int]bool{
		helper.ID: true,
	})
	if !ct.Generatable(helper.ID) {
		t.Fatal("no-direct syscall should remain enabled for constructor use")
	}
	if ct.DirectlyGeneratable(helper.ID) {
		t.Fatal("no-direct syscall should not be a direct top-level generation choice")
	}
	if !ct.DirectlyGeneratable(manual.ID) {
		t.Fatal("manual syscall should remain a direct top-level generation choice")
	}

	r := rand.New(rand.NewSource(0))
	for range 1000 {
		if got := target.Syscalls[ct.choose(r, helper.ID)].Name; got != "test$manual" {
			t.Fatalf("no-direct biased choice picked %q, want test$manual", got)
		}
	}
}

func TestGenerationBiasCallHookOverridesRandomInsertionBias(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	clone := *target
	clone.Bias.SelectGenerationBiasCall = func(_ *Prog, insertionPoint int) int {
		if insertionPoint == 0 {
			return -1
		}
		return insertionPoint - 1
	}
	clone.Bias.AdjustCallPriority = func(src, dst *Syscall, weight int32) int32 {
		if src.Name != "test$manual" {
			return weight
		}
		if dst.Name == "test$automatic" {
			return 1000
		}
		return 0
	}
	enabled := map[*Syscall]bool{
		clone.SyscallMap["test$automatic"]: true,
		clone.SyscallMap["test$manual"]:    true,
	}
	ct := clone.BuildChoiceTable(nil, enabled)
	p, err := clone.Deserialize([]byte("test$automatic(0x0)\ntest$manual(0x1)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	s := newState(&clone, ct, nil)
	for _, c := range p.Calls {
		s.analyze(c)
	}
	r := newRand(&clone, rand.NewSource(0))
	calls := r.generateCall(s, p, len(p.Calls))
	if len(calls) == 0 {
		t.Fatal("generateCall returned no calls")
	}
	last := calls[len(calls)-1]
	if last.Meta.Name != "test$automatic" {
		t.Fatalf("generation bias hook picked %q, want test$automatic", last.Meta.Name)
	}
}

func TestGenerationBiasCallHookCanSuppressPrefixBias(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	clone := *target
	clone.Helpers.DeprioritizeAutomaticHelpers = true
	clone.Bias.SelectGenerationBiasCall = func(_ *Prog, insertionPoint int) int {
		if insertionPoint == 0 {
			return -1
		}
		return NoGenerationBiasCall
	}
	clone.Bias.AdjustCallPriority = func(src, dst *Syscall, weight int32) int32 {
		switch src.Name {
		case "test$automatic_helper":
			if dst.Name == "test$automatic_helper" {
				return 1000
			}
			return 0
		case "test$manual":
			if dst.Name == "test$manual" {
				return 1000
			}
			return 0
		default:
			return weight
		}
	}
	enabled := map[*Syscall]bool{
		clone.SyscallMap["test$automatic_helper"]: true,
		clone.SyscallMap["test$manual"]:           true,
	}
	ct := clone.BuildChoiceTable(nil, enabled)
	p, err := clone.Deserialize([]byte("test$automatic_helper(0x0)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	s := newState(&clone, ct, nil)
	for _, c := range p.Calls {
		s.analyze(c)
	}
	r := newRand(&clone, rand.NewSource(0))
	calls := r.generateCall(s, p, len(p.Calls))
	if len(calls) == 0 {
		t.Fatal("generateCall returned no calls")
	}
	last := calls[len(calls)-1]
	if last.Meta.Name != "test$manual" {
		t.Fatalf("generation bias suppression picked %q, want test$manual", last.Meta.Name)
	}
}

func TestBiasCallFilterOverridesGlobalBiasPool(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	clone := *target
	clone.Bias.FilterBiasCalls = func(calls []*Syscall) []*Syscall {
		var filtered []*Syscall
		for _, c := range calls {
			if c.Name == "test$manual" {
				filtered = append(filtered, c)
			}
		}
		return filtered
	}
	clone.Bias.AdjustCallPriority = func(src, dst *Syscall, weight int32) int32 {
		if src.Name != "test$manual" {
			return weight
		}
		if dst.Name == "test$manual" {
			return 1000
		}
		return 0
	}
	enabled := map[*Syscall]bool{
		clone.SyscallMap["test$automatic"]: true,
		clone.SyscallMap["test$manual"]:    true,
	}
	ct := clone.BuildChoiceTable(nil, enabled)
	r := rand.New(rand.NewSource(0))
	for range 100 {
		idx := ct.choose(r, -1)
		if clone.Syscalls[idx].Name != "test$manual" {
			t.Fatalf("filtered global bias pool still selected %q", clone.Syscalls[idx].Name)
		}
	}
}

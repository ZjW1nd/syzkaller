// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAssignRandomAsync(t *testing.T) {
	tests := []struct {
		os    string
		arch  string
		orig  string
		check func(*Prog) bool
	}{
		{
			"linux", "amd64",
			`r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
write(r0, &AUTO="01010101", 0x4)
read(r0, &AUTO=""/4, 0x4)
close(r0)
`,
			func(p *Prog) bool {
				return !p.Calls[0].Props.Async
			},
		},
		{
			"linux", "amd64",
			`r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
nanosleep(&AUTO={0x0,0x4C4B40}, &AUTO={0,0})
write(r0, &AUTO="01010101", 0x4)
read(r0, &AUTO=""/4, 0x4)
close(r0)
`,
			func(p *Prog) bool {
				return !p.Calls[0].Props.Async || !p.Calls[1].Props.Async
			},
		},
		{
			"linux", "amd64",
			`r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
r1 = dup(r0)
r2 = dup(r1)
r3 = dup(r2)
r4 = dup(r3)
`,
			func(p *Prog) bool {
				for _, call := range p.Calls[0 : len(p.Calls)-1] {
					if call.Props.Async {
						return false
					}
				}
				return true
			},
		},
	}
	_, rs, iters := initTest(t)
	r := rand.New(rs)
	anyAsync := false
	for _, test := range tests {
		target, err := GetTarget(test.os, test.arch)
		if err != nil {
			t.Fatal(err)
		}
		p, err := target.Deserialize([]byte(test.orig), Strict)
		if err != nil {
			t.Fatal(err)
		}
		for range iters {
			collided := AssignRandomAsync(p, r)
			if !test.check(collided) {
				t.Fatalf("bad async assignment:\n%s", collided.Serialize())
			}
			for _, call := range collided.Calls {
				anyAsync = anyAsync || call.Props.Async
			}
		}
	}
	if !anyAsync {
		t.Fatalf("not a single async was assigned")
	}
}

func TestDoubleExecCollide(t *testing.T) {
	tests := []struct {
		os         string
		arch       string
		orig       string
		duplicated string
		shouldFail bool
	}{
		{
			"linux", "amd64",
			`r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
r1 = dup(r0)
r2 = dup(r1)
r3 = dup(r2)
r4 = dup(r2)
r5 = dup(r3)
`,
			`r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='./file1\x00', 0x42, 0x1ff)
r1 = dup(r0)
r2 = dup(r1)
r3 = dup(r2)
dup(r2)
dup(r3)
openat(0xffffffffffffff9c, &(0x7f0000000040)='./file1\x00', 0x42, 0x1ff)
dup(r0)
dup(r1)
dup(r2)
dup(r2)
dup(r3)
`,
			false,
		},
	}
	_, rs, iters := initTest(t)
	r := rand.New(rs)
	for _, test := range tests {
		target, err := GetTarget(test.os, test.arch)
		if err != nil {
			t.Fatal(err)
		}
		p, err := target.Deserialize([]byte(test.orig), Strict)
		if err != nil {
			t.Fatal(err)
		}
		for range iters {
			collided, err := DoubleExecCollide(p, r)
			if test.shouldFail && err == nil {
				t.Fatalf("expected to fail, but it hasn't")
			} else if !test.shouldFail && err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if test.duplicated != "" {
				woProps := collided.Clone()
				for _, c := range woProps.Calls {
					c.Props = CallProps{}
				}
				serialized := string(woProps.Serialize())
				if serialized != test.duplicated {
					t.Fatalf("expected:%s\ngot:%s", test.duplicated, serialized)
				}
			}
			// TODO: also test the `async` assignment.
		}
	}
}

func TestDupCallCollide(t *testing.T) {
	tests := []struct {
		os   string
		arch string
		orig string
		rets []string
	}{
		{
			"linux", "amd64",
			`r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
r1 = dup(r0)
r2 = dup(r1)
dup(r2)
`,
			[]string{
				`r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='./file1\x00', 0x42, 0x1ff)
dup(r0) (async)
r1 = dup(r0)
r2 = dup(r1)
dup(r2)
`,
				`r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='./file1\x00', 0x42, 0x1ff)
r1 = dup(r0)
r2 = dup(r1)
dup(r2) (async)
dup(r2)
`,
			},
		},
	}
	_, rs, iters := initTest(t)
	// Let's save resources -- we don't need that many for these small tests.
	iters = min(iters, 100)
	r := rand.New(rs)
	for _, test := range tests {
		target, err := GetTarget(test.os, test.arch)
		if err != nil {
			t.Fatal(err)
		}
		p, err := target.Deserialize([]byte(test.orig), Strict)
		if err != nil {
			t.Fatal(err)
		}
		detected := map[string]struct{}{}
		for range iters {
			collided, err := DupCallCollide(p, r)
			assert.NoError(t, err)
			detected[string(collided.Serialize())] = struct{}{}
		}
		for _, variant := range test.rets {
			_, exists := detected[variant]
			assert.True(t, exists)
		}
	}
}

func TestAvoidAutomaticHelperAsync(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	clone.Helpers.AvoidCollidingAutomaticHelpers = true
	p, err := clone.Deserialize([]byte(
		"test$automatic_helper(0x0)\n"+
			"test$manual(0x1)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(0))
	for range 100 {
		collided := AssignRandomAsync(p, r)
		for _, call := range collided.Calls {
			if call.Meta.Name == "test$automatic_helper" && call.Props.Async {
				t.Fatalf("automatic helper became async:\n%s", collided.Serialize())
			}
		}
	}
	for range 100 {
		collided, err := DupCallCollide(p, r)
		assert.NoError(t, err)
		for _, call := range collided.Calls {
			if call.Meta.Name == "test$automatic_helper" && call.Props.Async {
				t.Fatalf("duplicated automatic helper became async:\n%s", collided.Serialize())
			}
		}
	}
	for range 20 {
		collided, err := DoubleExecCollide(p, r)
		assert.NoError(t, err)
		manualAsync := false
		for _, call := range collided.Calls {
			if call.Meta.Name == "test$automatic_helper" && call.Props.Async {
				t.Fatalf("double-exec automatic helper became async:\n%s", collided.Serialize())
			}
			if call.Meta.Name == "test$manual" && call.Props.Async {
				manualAsync = true
			}
		}
		if !manualAsync {
			t.Fatalf("double-exec did not keep any target call async:\n%s", collided.Serialize())
		}
	}
}

func TestDupCallCollidePrefersHigherRelevance(t *testing.T) {
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	clone.CallRelevanceScore = func(call *Syscall) int {
		if call.Name == "test$manual" {
			return 3
		}
		return 1
	}
	p, err := clone.Deserialize([]byte(
		"test$automatic(0x0)\n"+
			"test$manual(0x1)\n"+
			"test$automatic(0x2)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(0))
	for range 20 {
		collided, err := DupCallCollide(p, r)
		assert.NoError(t, err)
		manualAsync := 0
		automaticAsync := 0
		for _, call := range collided.Calls {
			if !call.Props.Async {
				continue
			}
			switch call.Meta.Name {
			case "test$manual":
				manualAsync++
			case "test$automatic":
				automaticAsync++
			}
		}
		if manualAsync == 0 || automaticAsync != 0 {
			t.Fatalf("expected only higher-relevance call to be duplicated async:\n%s", collided.Serialize())
		}
	}
}

func TestDoubleExecCollideMarksHigherRelevanceAsync(t *testing.T) {
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	clone.CallRelevanceScore = func(call *Syscall) int {
		if call.Name == "test$manual" {
			return 3
		}
		return 1
	}
	p, err := clone.Deserialize([]byte(
		"test$automatic(0x0)\n"+
			"test$manual(0x1)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(0))
	collided, err := DoubleExecCollide(p, r)
	assert.NoError(t, err)
	manualAsync := 0
	automaticAsync := 0
	for _, call := range collided.Calls {
		if !call.Props.Async {
			continue
		}
		switch call.Meta.Name {
		case "test$manual":
			manualAsync++
		case "test$automatic":
			automaticAsync++
		}
	}
	if manualAsync == 0 {
		t.Fatalf("expected higher-relevance call to become async:\n%s", collided.Serialize())
	}
	if automaticAsync != 0 {
		t.Fatalf("did not expect lower-relevance call to become async when higher-relevance exists:\n%s", collided.Serialize())
	}
}

func TestAssignRandomRerunPrefersHigherRelevance(t *testing.T) {
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	clone.CallRelevanceScore = func(call *Syscall) int {
		if call.Name == "test$manual" {
			return 3
		}
		return 1
	}
	p, err := clone.Deserialize([]byte(
		"test$automatic(0x0) (async)\n"+
			"test$automatic(0x1)\n"+
			"test$manual(0x2) (async)\n"+
			"test$automatic(0x3)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(0))
	seenPreferred := false
	for range 200 {
		collided := p.Clone()
		AssignRandomRerun(collided, r)
		if collided.Calls[0].Props.Rerun != 0 {
			t.Fatalf("lower-relevance async call unexpectedly received rerun:\n%s", collided.Serialize())
		}
		if collided.Calls[2].Props.Rerun != 0 {
			seenPreferred = true
			if collided.Calls[3].Props.Rerun != collided.Calls[2].Props.Rerun {
				t.Fatalf("rerun pair not propagated to the following call:\n%s", collided.Serialize())
			}
		}
	}
	if !seenPreferred {
		t.Fatal("higher-relevance async call never received rerun")
	}
}

func TestAssignRandomRerunSkipsLowRelevancePrograms(t *testing.T) {
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	clone.CallRelevanceScore = func(call *Syscall) int {
		if call.Name == "test$manual" {
			return 2
		}
		return 1
	}
	clone.MinimumCollideCallRelevance = 3
	p, err := clone.Deserialize([]byte(
		"test$manual(0x0) (async)\n"+
			"test$automatic(0x1)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(0))
	for range 50 {
		collided := p.Clone()
		AssignRandomRerun(collided, r)
		if collided.Calls[0].Props.Rerun != 0 || collided.Calls[1].Props.Rerun != 0 {
			t.Fatalf("low-relevance program unexpectedly received rerun:\n%s", collided.Serialize())
		}
	}
}

func TestAssignRandomAsyncPrefersHigherRelevance(t *testing.T) {
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	clone.CallRelevanceScore = func(call *Syscall) int {
		if call.Name == "test$manual" {
			return 3
		}
		return 1
	}
	p, err := clone.Deserialize([]byte(
		"test$automatic(0x0)\n"+
			"test$manual(0x1)\n"+
			"test$automatic(0x2)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(0))
	for range 20 {
		collided := AssignRandomAsync(p, r)
		manualAsync := 0
		automaticAsync := 0
		for _, call := range collided.Calls {
			if !call.Props.Async {
				continue
			}
			switch call.Meta.Name {
			case "test$manual":
				manualAsync++
			case "test$automatic":
				automaticAsync++
			}
		}
		if manualAsync == 0 || automaticAsync != 0 {
			t.Fatalf("expected only higher-relevance call to become async:\n%s", collided.Serialize())
		}
	}
}

func TestAssignRandomAsyncSkipsLowRelevancePrograms(t *testing.T) {
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	clone.CallRelevanceScore = func(call *Syscall) int {
		if call.Name == "test$manual" {
			return 2
		}
		return 1
	}
	clone.MinimumCollideCallRelevance = 3
	p, err := clone.Deserialize([]byte(
		"test$automatic(0x0)\n"+
			"test$manual(0x1)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(0))
	collided := AssignRandomAsync(p, r)
	for _, call := range collided.Calls {
		if call.Props.Async {
			t.Fatalf("expected no async assignment for low-relevance-only program:\n%s", collided.Serialize())
		}
	}
}

func TestCollideUsesTargetSelectedIndices(t *testing.T) {
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	clone.SelectCollideCallIndices = func(calls []*Call) ([]int, bool) {
		if len(calls) < 3 {
			return nil, false
		}
		return []int{1}, false
	}
	p, err := clone.Deserialize([]byte(
		"test$automatic(0x0)\n"+
			"test$manual(0x1)\n"+
			"test$automatic(0x2)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	seenSelectedAsync := false
	for seed := int64(0); seed < 64; seed++ {
		collided := AssignRandomAsync(p, rand.New(rand.NewSource(seed)))
		if collided.Calls[0].Props.Async {
			t.Fatalf("unexpected async on unselected call:\n%s", collided.Serialize())
		}
		if collided.Calls[2].Props.Async {
			t.Fatalf("unexpected async on trailing unselected call:\n%s", collided.Serialize())
		}
		if collided.Calls[1].Props.Async {
			seenSelectedAsync = true
			break
		}
	}
	if !seenSelectedAsync {
		t.Fatal("selected collide call never became async across sampled seeds")
	}
	rerunProg := p.Clone()
	rerunProg.Calls[1].Props.Async = true
	AssignRandomRerun(rerunProg, rand.New(rand.NewSource(1)))
	if rerunProg.Calls[0].Props.Rerun != 0 {
		t.Fatalf("unselected call unexpectedly received rerun:\n%s", rerunProg.Serialize())
	}
}

func TestCollideUsesTargetAsyncGuard(t *testing.T) {
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	clone.SelectCollideCallIndices = func(calls []*Call) ([]int, bool) {
		return []int{0}, false
	}
	clone.AllowAsyncCollideCall = func(calls []*Call, idx int) bool {
		return false
	}
	p, err := clone.Deserialize([]byte(
		"test$manual(0x0)\n"+
			"test$automatic(0x1)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	collided := AssignRandomAsync(p, rand.New(rand.NewSource(0)))
	for _, call := range collided.Calls {
		if call.Props.Async {
			t.Fatalf("target-blocked call became async:\n%s", collided.Serialize())
		}
	}
	if _, err := DupCallCollide(p, rand.New(rand.NewSource(0))); err == nil {
		t.Fatal("expected duplicate-collide to reject target-blocked calls")
	}
	if _, err := DoubleExecCollide(p, rand.New(rand.NewSource(0))); err == nil {
		t.Fatal("expected double-exec collide to reject target-blocked calls")
	}

	withProps, err := clone.Deserialize([]byte(
		"test$manual(0x0) (async, rerun: 32)\n"+
			"test$automatic(0x1) (rerun: 32)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	sanitized, changed := SanitizeCollidePropsForTarget(withProps)
	if !changed {
		t.Fatal("expected sanitizer to clear target-blocked async props")
	}
	for _, call := range sanitized.Calls {
		if call.Props.Async || call.Props.Rerun != 0 {
			t.Fatalf("sanitizer left target-blocked collide props:\n%s", sanitized.Serialize())
		}
	}
	if withProps.Calls[0].Props.Async == false || withProps.Calls[0].Props.Rerun == 0 {
		t.Fatal("sanitizer mutated the original program")
	}
}

func TestCollidePreservesTargetRequiredAsync(t *testing.T) {
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	clone.SelectCollideCallIndices = func(calls []*Call) ([]int, bool) {
		return []int{1}, false
	}
	clone.AllowAsyncCollideCall = func(calls []*Call, idx int) bool {
		return idx != 0
	}
	clone.CallRequiresAsync = func(calls []*Call, idx int) bool {
		return idx == 0
	}
	p, err := clone.Deserialize([]byte(
		"test$manual(0x0) (async)\n"+
			"test$automatic(0x1)\n"+
			"test$manual(0x2)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		collided := AssignRandomAsync(p, rand.New(rand.NewSource(0)))
		if !collided.Calls[0].Props.Async {
			t.Fatalf("required-async call was made synchronous:\n%s", collided.Serialize())
		}
	}

	withProps, err := clone.Deserialize([]byte(
		"test$manual(0x0) (rerun: 32)\n"+
			"test$automatic(0x1) (rerun: 32)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	sanitized, changed := SanitizeCollidePropsForTarget(withProps)
	if !changed {
		t.Fatal("expected sanitizer to restore required async and clear illegal rerun")
	}
	if !sanitized.Calls[0].Props.Async || sanitized.Calls[0].Props.Rerun != 0 {
		t.Fatalf("sanitizer did not preserve required async safely:\n%s", sanitized.Serialize())
	}
}

func TestDupCallCollideSkipsLowRelevancePrograms(t *testing.T) {
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	clone.CallRelevanceScore = func(call *Syscall) int {
		if call.Name == "test$manual" {
			return 2
		}
		return 1
	}
	clone.MinimumCollideCallRelevance = 3
	p, err := clone.Deserialize([]byte(
		"test$automatic(0x0)\n"+
			"test$manual(0x1)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(0))
	if _, err := DupCallCollide(p, r); err == nil {
		t.Fatal("expected duplicate-collide to reject low-relevance-only program")
	}
}

func TestDoubleExecCollideSkipsLowRelevancePrograms(t *testing.T) {
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	clone.CallRelevanceScore = func(call *Syscall) int {
		if call.Name == "test$manual" {
			return 2
		}
		return 1
	}
	clone.MinimumCollideCallRelevance = 3
	p, err := clone.Deserialize([]byte(
		"test$automatic(0x0)\n"+
			"test$manual(0x1)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(0))
	if _, err := DoubleExecCollide(p, r); err == nil {
		t.Fatal("expected double-exec collide to reject low-relevance-only program")
	}
}

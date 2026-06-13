package windows_test

import (
	"math/rand"
	"os"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestWindowsStatePolicyUsesGenericResourceHooks(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if target.CallRelevanceScore == nil {
		t.Fatal("windows target did not set CallRelevanceScore")
	}
	if target.TriageCallScore == nil {
		t.Fatal("windows target did not set TriageCallScore")
	}
	if target.ResourceUseScore == nil {
		t.Fatal("windows target did not set ResourceUseScore")
	}
	if target.ResourceReuseScore == nil {
		t.Fatal("windows target did not set ResourceReuseScore")
	}
	if target.CorpusResourceScore == nil {
		t.Fatal("windows target did not set CorpusResourceScore")
	}
	if target.PreferResourceCentricBorrowing == nil {
		t.Fatal("windows target did not set PreferResourceCentricBorrowing")
	}
	if target.SelectResourceCtor == nil {
		t.Fatal("windows target did not set SelectResourceCtor")
	}
	if target.SelectCollideCallIndices == nil {
		t.Fatal("windows target did not set SelectCollideCallIndices")
	}
	if target.ExpandEnabledCalls == nil {
		t.Fatal("windows target did not set ExpandEnabledCalls")
	}

	deep := target.SyscallMap["TransmitPackets$inet_accept"]
	setup := target.SyscallMap["listen$inet_tcp"]
	helper := target.SyscallMap["socket$accept_tcp"]
	if deep == nil || setup == nil || helper == nil {
		t.Fatalf("missing policy test syscall: deep=%v setup=%v helper=%v", deep, setup, helper)
	}
	if target.CallRelevance(deep) <= target.CallRelevance(setup) {
		t.Fatalf("deep call relevance=%d setup relevance=%d",
			target.CallRelevance(deep), target.CallRelevance(setup))
	}
	if target.CallRelevance(helper) >= 0 {
		t.Fatalf("helper relevance=%d, want negative", target.CallRelevance(helper))
	}
	if target.ResourceUseScore(deep) <= target.ResourceUseScore(setup) {
		t.Fatalf("deep resource score=%d setup resource score=%d",
			target.ResourceUseScore(deep), target.ResourceUseScore(setup))
	}
}

func TestWindowsStatePolicyExpandsResourceConstructors(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	root := target.SyscallMap["WSARecv$accept"]
	if root == nil {
		t.Fatal("missing WSARecv$accept")
	}
	expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{
		root: true,
	})
	for _, name := range []string{
		"WSARecv$accept",
		"socket$inet_tcp",
		"bind$inet_tcp",
		"listen$inet_tcp",
		"accept$inet_tcp",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("resource constructor closure missing %q", name)
		}
	}
	startup := target.SyscallMap["WSAStartup"]
	if startup == nil {
		t.Fatal("missing syscall \"WSAStartup\"")
	}
	if !expanded[startup] {
		t.Fatal("Winsock resource constructor closure did not add WSAStartup scaffold")
	}
	for _, name := range []string{"closesocket$any"} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if expanded[call] {
			t.Fatalf("resource constructor closure should not add name-only scaffold %q", name)
		}
	}
}

func TestWindowsAFDTargetProfileKeepsDefaultTargetClean(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if target.ApplyTargetProfile == nil {
		t.Fatal("windows target did not set ApplyTargetProfile")
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	if profiled == target {
		t.Fatal("AFD target profile should clone the shared target")
	}
	if target.MinimumTriageCallRelevance != 0 || target.MinimumCollideCallRelevance != 0 {
		t.Fatalf("default target was modified: triage=%d collide=%d",
			target.MinimumTriageCallRelevance, target.MinimumCollideCallRelevance)
	}
	if profiled.MinimumHintsCallRelevance != 4 ||
		profiled.MinimumTriageCallRelevance != 4 ||
		profiled.MinimumCollideCallRelevance != 4 ||
		profiled.MinimumMutationCallRelevance != 4 {
		t.Fatalf("bad AFD profile thresholds: hints=%d triage=%d collide=%d mutation=%d",
			profiled.MinimumHintsCallRelevance,
			profiled.MinimumTriageCallRelevance,
			profiled.MinimumCollideCallRelevance,
			profiled.MinimumMutationCallRelevance)
	}
	if profiled.CallEligibleForTriage(profiled.SyscallMap["Sleep"]) {
		t.Fatal("AFD profile should not triage shallow calls")
	}
	if !profiled.CallEligibleForTriage(profiled.SyscallMap["WSARecv$accept"]) {
		t.Fatal("AFD profile should triage deep resource consumers")
	}
	if !profiled.CallEligibleForTriage(profiled.SyscallMap["ConnectEx$inet_tcp"]) {
		t.Fatal("AFD profile should triage deep public resource state transitions")
	}
	if target.Bias.SelectGeneratedCall == nil || profiled.Bias.SelectGeneratedCall == nil {
		t.Fatal("windows targets should keep the generic Winsock startup generation hook")
	}
	if profiled.Bias.FilterBiasCalls != nil ||
		profiled.Bias.SelectGenerationBiasCall != nil {
		t.Fatal("AFD profile must not install AFD-specific generation bias hooks")
	}
	if profiled.RuntimePolicy.PreferCollideProgram == nil ||
		profiled.RuntimePolicy.ShouldScheduleImmediateCollide == nil ||
		profiled.RuntimePolicy.ShouldForceTriageCall == nil ||
		profiled.RuntimePolicy.ShouldSkipTriageProgram == nil ||
		profiled.RuntimePolicy.ShouldPersistStableTriageCall == nil {
		t.Fatal("AFD profile did not set generic focused runtime policy hooks")
	}
}

func TestWindowsAFDTargetProfileKeepsAcceptExUpdatedSeedOnly(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	for _, name := range []string{
		"AcceptEx$inet_tcp_pending",
		"setsockopt$update_accept_context",
	} {
		call := profiled.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !call.Attrs.NoGenerate || !call.Attrs.NoMinimize {
			t.Fatalf("%s should stay seed-only under the AFD profile", name)
		}
	}
	for _, name := range []string{
		"send$inet_accept_updated",
		"recv$inet_accept_updated",
		"setsockopt$int_accept_updated",
		"getsockopt$int_accept_updated",
	} {
		call := profiled.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if call.Attrs.NoGenerate || !call.Attrs.NoMinimize {
			t.Fatalf("%s should stay triageable but no_minimize under the AFD profile", name)
		}
	}
}

func TestWindowsAFDTargetProfilePrefersDeepCollideCalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p, err := profiled.Deserialize([]byte(
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = bind$inet_tcp(r0, &(0x7f0000000000)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = listen$inet_tcp(r1, 0x1)\n"+
			"r3 = accept$inet_tcp(r2, 0x0, 0x0)\n"+
			"WSARecv$accept(r3, &(0x7f0000000100)=[{0x40, &(0x7f0000000180)='\\x00'/64}], 0x1, &(0x7f0000000200), &(0x7f0000000240)=0x0, 0x0, 0x0)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	idx, blocked := profiled.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("focused collide selection unexpectedly blocked deep program")
	}
	deepIdx := idx[len(idx)-1]
	if p.Calls[deepIdx].Meta.Name != "WSARecv$accept" {
		t.Fatalf("collide indices=%v, want WSARecv$accept as deepest owner", idx)
	}
	if !profiled.RuntimePolicy.PreferCollideProgram(p) {
		t.Fatal("focused profile did not prefer deep resource program for collide")
	}
	if !profiled.RuntimePolicy.ShouldScheduleImmediateCollide(p, deepIdx) {
		t.Fatal("focused profile did not request immediate collide for deep owner")
	}
	if !profiled.RuntimePolicy.ShouldForceTriageCall("candidate", p, deepIdx) {
		t.Fatal("focused profile did not force candidate triage for deep owner")
	}
	if !profiled.RuntimePolicy.ShouldPersistStableTriageCall("candidate", p, deepIdx) {
		t.Fatal("focused profile did not persist stable candidate triage for deep owner")
	}
	shallow, err := profiled.Deserialize([]byte(
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000000)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize shallow: %v", err)
	}
	_, blocked = profiled.SelectCollideCallIndices(shallow.Calls)
	if !blocked {
		t.Fatal("focused collide selection should block setup-only program")
	}
	if profiled.RuntimePolicy.PreferCollideProgram(shallow) {
		t.Fatal("focused profile should not prefer setup-only program for collide")
	}
	if profiled.RuntimePolicy.ShouldForceTriageCall("candidate", shallow, 0) {
		t.Fatal("focused profile should not force candidate triage for shallow setup")
	}
}

func TestWindowsAFDTargetProfileSkipsDeepDefaultResourceProgram(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p, err := profiled.Deserialize([]byte(
		"WSARecv$accept(0xffffffffffffffff, &(0x7f0000000100)=[{0x40, &(0x7f0000000180)='\\x00'/64}], 0x1, &(0x7f0000000200), &(0x7f0000000240)=0x0, 0x0, 0x0)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if profiled.RuntimePolicy.PreferCollideProgram(p) {
		t.Fatal("focused profile should not prefer a deep call backed only by a default resource")
	}
	if profiled.RuntimePolicy.ShouldScheduleImmediateCollide(p, 0) {
		t.Fatal("focused profile should not collide a deep call backed only by a default resource")
	}
	if profiled.RuntimePolicy.ShouldForceTriageCall("candidate", p, 0) {
		t.Fatal("focused profile should not force triage for a default-resource deep call")
	}
	if !profiled.RuntimePolicy.ShouldSkipTriageProgram("candidate", p) {
		t.Fatal("focused profile should skip default-resource deep calls")
	}
}

func TestWindowsAFDTargetProfileRejectsBrokenPrivateResourceLineage(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p, err := profiled.Deserialize([]byte(
		"r0 = connect$inet_udp(0xffffffffffffffff, 0x0, 0x0)\n"+
			"NtDeviceIoControlFile$afd_routing_interface_query_udp(r0, 0x0, 0x0, 0x0, &(0x7f0000000000)={@Status=0x0, 0x0}, 0x120ab, &(0x7f0000000040)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000080), 0x10)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if profiled.RuntimePolicy.ShouldScheduleProgram("collide:fuzz", p) {
		t.Fatalf("focused profile scheduled broken resource lineage:\n%s", p.Serialize())
	}
	if profiled.RuntimePolicy.PreferCollideProgram(p) {
		t.Fatal("focused profile should not prefer broken private resource lineage")
	}
	if profiled.RuntimePolicy.ShouldForceTriageCall("collide:fuzz", p, 1) {
		t.Fatal("focused profile should not force triage for broken private resource lineage")
	}
}

func TestWindowsAFDTargetProfileRejectsMixedBrokenResourceLineage(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p, err := profiled.Deserialize([]byte(
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = bind$inet_tcp(r0, &(0x7f0000000000)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = listen$inet_tcp(r1, 0x1)\n"+
			"r3 = accept$inet_tcp(r2, 0x0, 0x0)\n"+
			"NtDeviceIoControlFile$afd_event_select_accept(r3, 0x0, 0x0, 0x0, &(0x7f0000000100)={@Status=0x0, 0x0}, 0x12087, &(0x7f0000000140)={0x0, 0x3ff, 0x0}, 0x10, 0x0, 0x0)\n"+
			"r4 = bind$inet_tcp(0xffffffffffffffff, 0x0, 0x0)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if !profiled.RuntimePolicy.PreferCollideProgram(p) {
		t.Fatal("test program should still contain a valid focused owner")
	}
	if profiled.RuntimePolicy.ShouldScheduleProgram("collide:fuzz", p) {
		t.Fatalf("focused profile scheduled program with mixed broken lineage:\n%s", p.Serialize())
	}
}

func TestWindowsAFDTargetProfilePrefersSameLineageCollidePair(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p, err := profiled.Deserialize([]byte(
		"r0 = socket$accept_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r2 = bind$inet_tcp(r1, &(0x7f0000000000)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r3 = listen$inet_tcp(r2, 0x1)\n"+
			"r4 = accept$inet_tcp(r3, 0x0, 0x0)\n"+
			"WSARecv$accept(r4, &(0x7f0000000100)=[{0x40, &(0x7f0000000180)='\\x00'/64}], 0x1, &(0x7f0000000200), &(0x7f0000000240)=0x0, 0x0, 0x0)\n"+
			"WSASend$accept(r4, &(0x7f0000000300)=[{0x4, &(0x7f0000000380)='pong'}], 0x1, &(0x7f0000000400), 0x0, 0x0, 0x0)\n"+
			"r5 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r6 = connect$inet_tcp(r5, &(0x7f0000000500)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"WSARecv$tcp(r6, &(0x7f0000000600)=[{0x20, &(0x7f0000000680)='\\x00'/32}], 0x1, &(0x7f0000000700), &(0x7f0000000740)=0x0, 0x0, 0x0)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	idx, blocked := profiled.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("focused collide selection unexpectedly blocked same-lineage program")
	}
	if len(idx) != 1 || p.Calls[idx[0]].Meta.Name != "WSARecv$accept" {
		t.Fatalf("collide indices=%v, want first accepted-socket deep pair", idx)
	}
	collided := prog.AssignRandomAsync(p, rand.New(rand.NewSource(0)))
	for i, call := range collided.Calls {
		if call.Meta.Name == "WSARecv$accept" {
			if !call.Props.Async {
				t.Fatalf("same-lineage recv was not marked async:\n%s", collided.Serialize())
			}
			if i+1 >= len(collided.Calls) || collided.Calls[i+1].Meta.Name != "WSASend$accept" {
				t.Fatalf("same-lineage recv is not followed by send:\n%s", collided.Serialize())
			}
			return
		}
		if call.Props.Async {
			t.Fatalf("unexpected async on non-selected call %s:\n%s", call.Meta.Name, collided.Serialize())
		}
	}
	t.Fatal("generated program is missing WSARecv$accept")
}

func TestWindowsAFDTargetProfileScoresCorpusResourcesByLineage(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	corpusProg, err := profiled.Deserialize([]byte(
		"r0 = socket$accept_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r2 = bind$inet_tcp(r1, &(0x7f0000000000)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r3 = listen$inet_tcp(r2, 0x1)\n"+
			"r4 = accept$inet_tcp(r3, 0x0, 0x0)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	current := profiled.SyscallMap["recv$inet_accept"]
	deep := windowsPolicyTestCallReturn(t, corpusProg, "accept$inet_tcp")
	compat := windowsPolicyTestCallReturn(t, corpusProg, "socket$accept_tcp")
	deepScore := profiled.CorpusResourceScore(current, deep, nil, 0, corpusProg)
	compatScore := profiled.CorpusResourceScore(current, compat, nil, 0, corpusProg)
	if deepScore <= compatScore {
		t.Fatalf("corpus score: deep=%d compat=%d", deepScore, compatScore)
	}
}

func TestWindowsAFDTargetProfileSkipsSeedOnlyTriagePrograms(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	seedOnly := profiled.SyscallMap["WSAEventSelect$tcp"]
	creator := profiled.SyscallMap["ConnectEx$inet_tcp"]
	if seedOnly == nil || creator == nil {
		t.Fatalf("missing policy test syscall: seedOnly=%v creator=%v", seedOnly, creator)
	}
	seedOnlyProg := &prog.Prog{Target: profiled, Calls: []*prog.Call{{Meta: seedOnly}}}
	if !profiled.RuntimePolicy.ShouldSkipTriageProgram("candidate", seedOnlyProg) {
		t.Fatal("focused profile should skip triage for seed-only programs")
	}
	creatorProg, err := profiled.Deserialize([]byte(
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = bind$connectex_tcp(r0, &(0x7f0000000000)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"ConnectEx$inet_tcp(r1, &(0x7f0000000100)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='', 0x0, &(0x7f0000000240), 0x0)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize creator: %v", err)
	}
	if profiled.RuntimePolicy.ShouldSkipTriageProgram("candidate", creatorProg) {
		t.Fatal("focused profile should triage regular public resource calls")
	}
	if !profiled.RuntimePolicy.ShouldForceTriageCall("candidate", creatorProg, 2) {
		t.Fatal("focused profile should force triage for deep public state transitions")
	}
	scaffold := profiled.SyscallMap["listen$inet_tcp"]
	if scaffold == nil {
		t.Fatal("missing listen$inet_tcp")
	}
	scaffoldProg := &prog.Prog{Target: profiled, Calls: []*prog.Call{{Meta: scaffold}}}
	if profiled.RuntimePolicy.ShouldForceTriageCall("candidate", scaffoldProg, 0) {
		t.Fatal("focused profile should not force triage for shallow scaffold transitions")
	}
}

func TestWindowsAFDTargetProfileKeepsVNetReceiveSeedForTriage(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	data, err := os.ReadFile("test/nyx_afd_accept_vnet_recv.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	p, err := profiled.Deserialize(data, prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if profiled.RuntimePolicy.ShouldSkipTriageProgram("candidate", p) {
		t.Fatal("focused profile should not skip vnet receive seeds with deep corpus owners")
	}
}

func TestWindowsAFDTargetProfileSchedulesVNetReceiveSeedCandidate(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	data, err := os.ReadFile("test/nyx_afd_accept_vnet_recv.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	p, err := profiled.Deserialize(data, prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if !profiled.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
		t.Fatal("focused profile should schedule vnet receive seed candidates")
	}
}

func windowsPolicyTestCallReturn(t *testing.T, p *prog.Prog, callName string) *prog.ResultArg {
	t.Helper()
	for _, call := range p.Calls {
		if call.Meta == nil || call.Meta.Name != callName {
			continue
		}
		if call.Ret == nil {
			t.Fatalf("%s has no return resource", callName)
		}
		return call.Ret
	}
	t.Fatalf("program is missing %s", callName)
	return nil
}

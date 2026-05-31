package windows_test

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestWindowsStatePolicyHooksPreferDeepAFDCalls(t *testing.T) {
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
	if target.SelectResourceCtor == nil {
		t.Fatal("windows target did not set SelectResourceCtor")
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

func TestWindowsStatePolicyExpandsAFDDeepCallScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	root := target.SyscallMap["TransmitPackets$inet_accept"]
	if root == nil {
		t.Fatal("missing TransmitPackets$inet_accept")
	}
	expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{
		root: true,
	})
	for _, name := range []string{
		"TransmitPackets$inet_accept",
		"WSAStartup",
		"socket$inet_tcp",
		"bind$inet_tcp",
		"listen$inet_tcp",
		"accept$inet_tcp",
		"connect$inet_tcp",
		"closesocket$any",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("expanded AFD scaffold missing %q", name)
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
		profiled.MinimumCollideCallRelevance != 5 ||
		profiled.MinimumMutationCallRelevance != 4 {
		t.Fatalf("bad AFD profile thresholds: hints=%d triage=%d collide=%d mutation=%d",
			profiled.MinimumHintsCallRelevance,
			profiled.MinimumTriageCallRelevance,
			profiled.MinimumCollideCallRelevance,
			profiled.MinimumMutationCallRelevance)
	}
	if profiled.CallRelevance(profiled.SyscallMap["Sleep"]) != 1 {
		t.Fatalf("AFD profile should score unclassified calls below focused thresholds")
	}
	if profiled.CallEligibleForTriage(profiled.SyscallMap["Sleep"]) {
		t.Fatal("AFD profile should not triage unclassified calls")
	}
	if profiled.SelectCollideCallIndices == nil {
		t.Fatal("AFD profile did not set SelectCollideCallIndices")
	}
	if profiled.RuntimePolicy.PreferCollideProgram == nil ||
		profiled.RuntimePolicy.ShouldScheduleImmediateCollide == nil ||
		profiled.RuntimePolicy.ShouldForceTriageCall == nil ||
		profiled.RuntimePolicy.ShouldSkipTriageProgram == nil ||
		profiled.RuntimePolicy.ShouldPersistStableTriageCall == nil {
		t.Fatal("AFD profile did not set runtime policy hooks")
	}
	if profiled.CorpusResourceScore == nil || profiled.PreferResourceCentricBorrowing == nil {
		t.Fatal("AFD profile did not set corpus resource policy hooks")
	}
	if profiled.Bias.FilterBiasCalls == nil ||
		profiled.Bias.SelectGenerationBiasCall == nil ||
		profiled.Bias.SelectGeneratedCall == nil {
		t.Fatal("AFD profile did not set generation bias hooks")
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
	p := &prog.Prog{
		Target: profiled,
		Calls: []*prog.Call{
			{Meta: profiled.SyscallMap["bind$inet_tcp"]},
			{Meta: profiled.SyscallMap["WSAIoctl$sio_keepalive_vals"]},
			{Meta: profiled.SyscallMap["WSARecv$accept"]},
			{Meta: profiled.SyscallMap["socket$accept_tcp"]},
		},
	}
	idx, blocked := profiled.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("AFD collide selection unexpectedly blocked deep program")
	}
	if len(idx) != 1 || idx[0] != 2 {
		t.Fatalf("AFD collide indices=%v, want [2]", idx)
	}
	if !profiled.RuntimePolicy.PreferCollideProgram(p) {
		t.Fatal("AFD profile did not prefer deep AFD program for collide")
	}
	if !profiled.RuntimePolicy.ShouldScheduleImmediateCollide(p, 2) {
		t.Fatal("AFD profile did not request immediate collide for deep accept recv")
	}
	shallow := &prog.Prog{
		Target: profiled,
		Calls:  []*prog.Call{{Meta: profiled.SyscallMap["bind$inet_tcp"]}},
	}
	_, blocked = profiled.SelectCollideCallIndices(shallow.Calls)
	if !blocked {
		t.Fatal("AFD collide selection should block helper/setup-only program")
	}
	if profiled.RuntimePolicy.PreferCollideProgram(shallow) {
		t.Fatal("AFD profile should not prefer setup-only program for collide")
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
		t.Fatal("AFD collide selection unexpectedly blocked same-lineage program")
	}
	if len(idx) != 1 || p.Calls[idx[0]].Meta.Name != "WSARecv$accept" {
		t.Fatalf("AFD collide indices=%v, want first accepted-socket deep pair", idx)
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
			for seed := int64(0); seed < 64; seed++ {
				rerunProg := collided.Clone()
				prog.AssignRandomRerun(rerunProg, rand.New(rand.NewSource(seed)))
				if rerunProg.Calls[i].Props.Rerun != 0 &&
					rerunProg.Calls[i+1].Props.Rerun == rerunProg.Calls[i].Props.Rerun {
					return
				}
			}
			t.Fatalf("rerun was never assigned to same-lineage pair:\n%s", collided.Serialize())
		}
		if call.Props.Async {
			t.Fatalf("unexpected async on non-selected call %s:\n%s", call.Meta.Name, collided.Serialize())
		}
	}
	t.Fatal("generated program is missing WSARecv$accept")
}

func TestWindowsAFDTargetProfileFiltersGenerationBiasToDeepCalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	helper := profiled.SyscallMap["socket$accept_tcp"]
	setup := profiled.SyscallMap["listen$inet_tcp"]
	deepAccept := profiled.SyscallMap["WSARecv$accept"]
	deepUDP := profiled.SyscallMap["sendto$udp_connected"]
	if helper == nil || setup == nil || deepAccept == nil || deepUDP == nil {
		t.Fatalf("missing policy test call: helper=%v setup=%v deepAccept=%v deepUDP=%v",
			helper, setup, deepAccept, deepUDP)
	}
	filtered := profiled.Bias.FilterBiasCalls([]*prog.Syscall{helper, setup, deepAccept, deepUDP})
	if len(filtered) != 2 || filtered[0] != deepAccept || filtered[1] != deepUDP {
		t.Fatalf("filtered bias calls=%v, want deep accept + deep udp", windowsTestCallNames(filtered))
	}
}

func TestWindowsAFDTargetProfileSelectsDeepGenerationBiasCall(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	p := &prog.Prog{
		Target: profiled,
		Calls: []*prog.Call{
			{Meta: profiled.SyscallMap["bind$inet_tcp"]},
			{Meta: profiled.SyscallMap["sendto$udp_connected"]},
			{Meta: profiled.SyscallMap["WSARecv$accept"]},
			{Meta: profiled.SyscallMap["socket$accept_tcp"]},
		},
	}
	if got := profiled.Bias.SelectGenerationBiasCall(p, len(p.Calls)); got != 2 {
		t.Fatalf("SelectGenerationBiasCall=%d, want deep accept index 2", got)
	}
	shallow := &prog.Prog{
		Target: profiled,
		Calls: []*prog.Call{
			{Meta: profiled.SyscallMap["bind$inet_tcp"]},
			{Meta: profiled.SyscallMap["listen$inet_tcp"]},
			{Meta: profiled.SyscallMap["socket$accept_tcp"]},
		},
	}
	if got := profiled.Bias.SelectGenerationBiasCall(shallow, len(shallow.Calls)); got != prog.NoGenerationBiasCall {
		t.Fatalf("shallow SelectGenerationBiasCall=%d, want NoGenerationBiasCall", got)
	}
}

func TestWindowsAFDTargetProfileContinuesDeepGenerationLineage(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	tests := []struct {
		bias string
		want string
	}{
		{bias: "recv$inet_accept", want: "send$inet_accept"},
		{bias: "send$inet_tcp", want: "recv$inet_tcp"},
		{bias: "recvfrom$udp_connected", want: "sendto$udp_connected"},
		{bias: "DisconnectEx$inet_tcp_reuse", want: "ConnectEx$inet_tcp_reuse"},
	}
	for _, test := range tests {
		bias := profiled.SyscallMap[test.bias]
		want := profiled.SyscallMap[test.want]
		if bias == nil || want == nil {
			t.Fatalf("missing policy test call: bias=%v want=%v", bias, want)
		}
		ct := profiled.BuildChoiceTable(nil, map[*prog.Syscall]bool{
			bias: true,
			want: true,
		})
		p := &prog.Prog{
			Target: profiled,
			Calls:  []*prog.Call{{Meta: bias}},
		}
		got := profiled.Bias.SelectGeneratedCall(p, len(p.Calls), bias.ID, ct)
		if got != want.ID {
			t.Fatalf("%s continuation=%q, want %q", test.bias, profiled.Syscalls[got].Name, test.want)
		}
	}
}

func TestWindowsAFDTargetProfileScoresCorpusResourcesBySocketState(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	tests := []struct {
		name       string
		program    string
		current    string
		deepCall   string
		compatCall string
	}{
		{
			name: "accepted socket",
			program: "r0 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r2 = bind$inet_tcp(r1, &(0x7f0000000000)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r3 = listen$inet_tcp(r2, 0x1)\n" +
				"r4 = accept$inet_tcp(r3, 0x0, 0x0)\n",
			current:    "recv$inet_accept",
			deepCall:   "accept$inet_tcp",
			compatCall: "socket$accept_tcp",
		},
		{
			name: "udp peer",
			program: "r0 = socket$connected_udp(0x2, 0x2, 0x11)\n" +
				"r1 = socket$inet_udp(0x2, 0x2, 0x11)\n" +
				"r2 = connect$inet_udp(r1, &(0x7f0000000000)={0x2, 0x4e23, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n",
			current:    "sendto$udp_connected",
			deepCall:   "connect$inet_udp",
			compatCall: "socket$connected_udp",
		},
		{
			name: "connectex reuse",
			program: "r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r2 = connect$inet_tcp(r1, &(0x7f0000000000)={0x2, 0x4e24, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r3 = DisconnectEx$inet_tcp_reuse(r2, 0x0, 0x2, 0x0)\n",
			current:    "ConnectEx$inet_tcp_reuse",
			deepCall:   "DisconnectEx$inet_tcp_reuse",
			compatCall: "socket$connected_tcp",
		},
	}
	for _, test := range tests {
		corpusProg, err := profiled.Deserialize([]byte(test.program), prog.NonStrict)
		if err != nil {
			t.Fatalf("%s Deserialize: %v", test.name, err)
		}
		current := profiled.SyscallMap[test.current]
		if current == nil {
			t.Fatalf("missing syscall %q", test.current)
		}
		deep := windowsPolicyTestCallReturn(t, corpusProg, test.deepCall)
		compat := windowsPolicyTestCallReturn(t, corpusProg, test.compatCall)
		deepScore := profiled.CorpusResourceScore(current, deep, nil, 0, corpusProg)
		compatScore := profiled.CorpusResourceScore(current, compat, nil, 0, corpusProg)
		if deepScore <= compatScore {
			t.Fatalf("%s corpus score: deep=%d compat=%d", test.name, deepScore, compatScore)
		}
	}
}

func TestWindowsAFDTargetProfilePrefersCorpusBorrowingForDeepConsumers(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	for _, name := range []string{
		"recv$inet_accept",
		"sendto$udp_connected",
		"CancelIoEx$connect_pending",
	} {
		call := profiled.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !profiled.PreferResourceCentricBorrowing(call) {
			t.Fatalf("AFD profile should prefer corpus borrowing for %s", name)
		}
	}
	for _, name := range []string{
		"bind$inet_tcp",
		"listen$inet_tcp",
		"socket$accept_tcp",
	} {
		call := profiled.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if profiled.PreferResourceCentricBorrowing(call) {
			t.Fatalf("AFD profile should not prefer corpus borrowing for shallow setup %s", name)
		}
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
	if !seedOnly.Attrs.NoGenerate {
		t.Fatal("WSAEventSelect$tcp should be seed-only")
	}
	if creator.Attrs.NoGenerate {
		t.Fatal("ConnectEx$inet_tcp should remain generatable")
	}
	seedOnlyProg := &prog.Prog{Target: profiled, Calls: []*prog.Call{{Meta: seedOnly}}}
	if !profiled.RuntimePolicy.ShouldSkipTriageProgram("candidate", seedOnlyProg) {
		t.Fatal("AFD profile should skip triage for programs containing no_generate calls")
	}
	creatorProg := &prog.Prog{Target: profiled, Calls: []*prog.Call{{Meta: creator}}}
	if profiled.RuntimePolicy.ShouldSkipTriageProgram("candidate", creatorProg) {
		t.Fatal("AFD profile should triage regular public AFD calls")
	}
}

func windowsTestCallNames(calls []*prog.Syscall) []string {
	names := make([]string, 0, len(calls))
	for _, call := range calls {
		if call != nil {
			names = append(names, call.Name)
		}
	}
	return names
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

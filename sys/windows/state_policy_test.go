package windows_test

import (
	"math/rand"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestWindowsStatePolicyUsesGenericResourceHooks(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
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

	deep := target.SyscallMap["TransmitPackets$inet_accept_nonblock"]
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
	windowsSkipLegacyAfdWinsockArchived(t)
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
	windowsSkipLegacyAfdWinsockArchived(t)
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
	if !profiled.CallEligibleForTriage(profiled.SyscallMap["NtDeviceIoControlFile$afd_bind_tcp"]) {
		t.Fatal("AFD profile should triage direct AFD endpoint state transitions")
	}
	bind := profiled.SyscallMap["NtDeviceIoControlFile$afd_bind_tcp"]
	getAddr := profiled.SyscallMap["NtDeviceIoControlFile$afd_get_address_tcp"]
	if profiled.TriageRelevance(bind) != profiled.TriageRelevance(getAddr) {
		t.Fatalf("AFD direct surface should use flat triage relevance: bind=%d get_address=%d",
			profiled.TriageRelevance(bind), profiled.TriageRelevance(getAddr))
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

func TestWindowsAFDTargetProfileAllowsFocusedAcceptExWithoutMutatingSyscallAttrs(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	call := profiled.SyscallMap["AcceptEx$inet_tcp_pending"]
	if call == nil {
		t.Fatal("missing syscall \"AcceptEx$inet_tcp_pending\"")
	}
	if !call.Attrs.NoGenerate || !call.Attrs.NoMinimize {
		t.Fatal("AcceptEx$inet_tcp_pending should keep no_generate/no_minimize syscall attrs")
	}
	ct := profiled.BuildChoiceTable(nil, map[*prog.Syscall]bool{call: true})
	if !ct.Generatable(call.ID) {
		t.Fatal("AFD profile should allow focused generation of AcceptEx$inet_tcp_pending")
	}
	helper := target.SyscallMap["WSAStartup"]
	baseCT := target.BuildChoiceTable(nil, map[*prog.Syscall]bool{
		target.SyscallMap["AcceptEx$inet_tcp_pending"]: true,
		helper: true,
	})
	if baseCT.Generatable(target.SyscallMap["AcceptEx$inet_tcp_pending"].ID) {
		t.Fatal("AFD profile generation override leaked into the base target")
	}
	for _, name := range []string{
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

func TestWindowsAFDTargetProfileGeneratesAcceptExCancelNoGenerateOverrides(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	enabled := map[*prog.Syscall]bool{}
	for _, name := range []string{
		"WSAStartup",
		"socket$inet_tcp",
		"bind$inet_tcp",
		"listen$inet_tcp",
		"socket$accept_tcp",
		"AcceptEx$inet_tcp_pending",
		"CreateIoCompletionPort$accept_pending",
		"CancelIoEx$accept_pending",
		"CancelIo$accept_pending",
		"closesocket$accept_pending",
	} {
		call := profiled.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		enabled[call] = true
	}
	ct := profiled.BuildChoiceTable(nil, enabled)
	for _, name := range []string{
		"AcceptEx$inet_tcp_pending",
		"CreateIoCompletionPort$accept_pending",
		"CancelIoEx$accept_pending",
		"CancelIo$accept_pending",
		"closesocket$accept_pending",
	} {
		call := profiled.SyscallMap[name]
		if !call.Attrs.NoGenerate || profiled.CallNoGenerate(call) {
			t.Fatalf("%s should keep syscall no_generate attrs but be profile-generatable", name)
		}
		if !ct.Generatable(call.ID) {
			t.Fatalf("%s is not generatable in the AFD profile cancel choice table", name)
		}
	}
	for seed := int64(0); seed < 128; seed++ {
		p := profiled.Generate(rand.New(rand.NewSource(seed)), 10, ct)
		if p == nil || len(p.Calls) == 0 {
			t.Fatalf("seed %d generated empty program", seed)
		}
	}
}

func TestWindowsAFDTargetProfileGeneratesDirectListenAcceptSeed(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	for _, name := range []string{
		"NtDeviceIoControlFile$afd_connect_tcp_to_listener",
		"NtDeviceIoControlFile$afd_wait_for_listen_tcp",
		"NtDeviceIoControlFile$afd_accept_tcp",
		"NtDeviceIoControlFile$afd_get_unaccepted_connect_data_tcp",
		"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_accepted",
		"NtDeviceIoControlFile$afd_send_accept_nonblock",
	} {
		call := profiled.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !call.Attrs.NoGenerate || profiled.CallNoGenerate(call) {
			t.Fatalf("%s should keep syscall no_generate attrs but be profile-generatable", name)
		}
	}
	data, err := os.ReadFile("test/nyx_afd_private_core_listen_accept.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	p, err := profiled.Deserialize(data, prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	for _, call := range p.Calls {
		if call.Meta != nil && profiled.CallNoGenerate(call.Meta) {
			t.Fatalf("AFD private listen/accept seed still contains effective no_generate call %s", call.Meta.Name)
		}
	}
}

func TestWindowsAFDPrivateIoctlResourceSimulation(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	ctor := profiled.SyscallMap["NtCreateFile$afd_tli_tcp_endpoint"]
	if ctor == nil {
		t.Fatal("missing NtCreateFile$afd_tli_tcp_endpoint")
	}
	if !ctor.Attrs.NoGenerate || profiled.CallNoGenerate(ctor) {
		t.Fatal("TLI endpoint ctor should keep no_generate attrs but be profile-generatable")
	}
	enabled := make(map[*prog.Syscall]bool)
	var ioctls []*prog.Syscall
	for _, call := range profiled.Syscalls {
		if call == nil || call.Attrs.Disabled {
			continue
		}
		enabled[call] = true
		if strings.HasPrefix(call.Name, "NtDeviceIoControlFile$afd_") {
			ioctls = append(ioctls, call)
		}
	}
	sort.Slice(ioctls, func(i, j int) bool {
		return ioctls[i].Name < ioctls[j].Name
	})
	if len(ioctls) == 0 {
		t.Fatal("no AFD private ioctl syscalls found")
	}
	for _, call := range ioctls {
		t.Run(call.Name, func(t *testing.T) {
			if call.Attrs.NoGenerate && profiled.CallNoGenerate(call) {
				t.Fatalf("AFD profile did not allow focused generation")
			}
			sim, err := profiled.SimulateCallResourceUse(call, enabled)
			if err != nil {
				t.Fatalf("SimulateCallResourceUse: %v", err)
			}
			if !sim.Valid() {
				t.Fatalf("resource simulation failed:\n%s",
					windowsFormatResourceSimulationFailures(sim.Failures()))
			}
		})
	}
}

func TestWindowsAFDPrivateNonIoctlResourceSimulation(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	enabled := make(map[*prog.Syscall]bool)
	var calls []*prog.Syscall
	for _, call := range profiled.Syscalls {
		if call == nil || call.Attrs.Disabled {
			continue
		}
		enabled[call] = true
		if strings.HasPrefix(call.Name, "NtCreateFile$afd_") ||
			strings.HasPrefix(call.Name, "NtReadFile$afd_") ||
			strings.HasPrefix(call.Name, "NtWriteFile$afd_") ||
			strings.HasPrefix(call.Name, "NtCancelIoFileEx$afd_") ||
			strings.HasPrefix(call.Name, "GetKernelObjectSecurity$afd_") ||
			strings.HasPrefix(call.Name, "SetKernelObjectSecurity$afd_") ||
			strings.HasPrefix(call.Name, "CloseHandle$afd_") {
			calls = append(calls, call)
		}
	}
	sort.Slice(calls, func(i, j int) bool {
		return calls[i].Name < calls[j].Name
	})
	if len(calls) == 0 {
		t.Fatal("no AFD private non-ioctl syscalls found")
	}
	for _, call := range calls {
		t.Run(call.Name, func(t *testing.T) {
			sim, err := profiled.SimulateCallResourceUse(call, enabled)
			if err != nil {
				t.Fatalf("SimulateCallResourceUse: %v", err)
			}
			if !sim.Valid() {
				t.Fatalf("resource simulation failed:\n%s",
					windowsFormatResourceSimulationFailures(sim.Failures()))
			}
		})
	}
}

func TestWindowsAFDTliUsesDedicatedEndpointResource(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, call := range profiled.Syscalls {
		if call != nil && !call.Attrs.Disabled {
			enabled[call] = true
		}
	}
	for _, name := range []string{
		"NtDeviceIoControlFile$afd_tli_type3_nobuf",
		"NtDeviceIoControlFile$afd_tli_set_qos",
		"NtDeviceIoControlFile$afd_tli_type3_nobuf_pending",
	} {
		call := profiled.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		fileHandle, ok := call.Args[0].Type.(*prog.ResourceType)
		if !ok {
			t.Fatalf("%s FileHandle has type %T, want resource", name, call.Args[0].Type)
		}
		if got := fileHandle.Desc.Name; got != "AFD_TLI_ENDPOINT" {
			t.Fatalf("%s FileHandle resource=%s, want AFD_TLI_ENDPOINT", name, got)
		}
		sim, err := profiled.SimulateCallResourceUse(call, enabled)
		if err != nil {
			t.Fatalf("%s SimulateCallResourceUse: %v", name, err)
		}
		if !sim.Valid() {
			t.Fatalf("%s resource simulation failed:\n%s",
				name, windowsFormatResourceSimulationFailures(sim.Failures()))
		}
	}
}

func windowsFormatResourceSimulationFailures(failures []prog.ResourceSimulationFailure) string {
	var b strings.Builder
	for _, failure := range failures {
		b.WriteString(failure.String())
		b.WriteByte('\n')
	}
	return b.String()
}

func TestWindowsAFDTargetProfileTriagesAcceptExCancelNoGenerateOverrides(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	data, err := os.ReadFile("test/nyx_exp_afd_acceptex_iocp_cancel.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	p, err := profiled.Deserialize(data, prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if profiled.RuntimePolicy.ShouldSkipTriageProgram == nil ||
		profiled.RuntimePolicy.ShouldForceTriageCall == nil {
		t.Fatal("AFD profile missing focused triage hooks")
	}
	if profiled.RuntimePolicy.ShouldSkipTriageProgram("candidate", p) {
		t.Fatalf("AFD profile should triage the AcceptEx cancel seed:\n%s", p.Serialize())
	}
	for idx, call := range p.Calls {
		if call.Meta == nil || call.Meta.Name != "AcceptEx$inet_tcp_pending" {
			continue
		}
		if !profiled.RuntimePolicy.ShouldForceTriageCall("candidate", p, idx) {
			t.Fatalf("AFD profile should force triage for %s in AcceptEx cancel seed", call.Meta.Name)
		}
		return
	}
	t.Fatal("AcceptEx cancel seed did not contain AcceptEx$inet_tcp_pending")
}

func TestWindowsAFDTargetProfilePrefersDeepCollideCalls(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
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
	windowsSkipLegacyAfdWinsockArchived(t)
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

func TestWindowsAFDTargetProfileRejectsUDPNonblockReceiveWithoutFionbio(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	broken, err := profiled.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n"+
			"r1 = bind$inet_udp(r0, &(0x7f0000000100)={0x2, 0x4e22, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"recv$inet_udp_nonblock(r1, &(0x7f0000000200)=\"\"/64, 0x40, 0x0)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize broken: %v", err)
	}
	if profiled.RuntimePolicy.ShouldScheduleProgram("gen", broken) {
		t.Fatalf("focused profile scheduled UDP nonblock receive without FIONBIO:\n%s",
			broken.Serialize())
	}
}

func TestWindowsAFDTargetProfileRejectsMixedSocketFamilies(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	broken, err := profiled.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n"+
			"r1 = bind$inet_udp(r0, &(0x7f0000000100)={0x2, 0x4e25, 0x7f000001}, 0x10)\n"+
			"connect$inet_tcp_nonblock(r1, &(0x7f0000000200)={0x2, 0x4e20, 0x7}, 0x10)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize broken: %v", err)
	}
	if profiled.RuntimePolicy.ShouldScheduleProgram("fuzz", broken) {
		t.Fatalf("focused profile scheduled mixed UDP/TCP socket lineage:\n%s",
			broken.Serialize())
	}

	valid, err := profiled.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n"+
			"r1 = bind$inet_udp(r0, &(0x7f0000000100)={0x2, 0x4e25, 0x7f000001}, 0x10)\n"+
			"WSASendTo$udp_bound(r1, &(0x7f0000000080)=[{0x4, &(0x7f0000000180)='ping'}], 0x1, &(0x7f0000000200), 0x0, &(0x7f0000000240)={0x2, 0x4e22, 0x7f000001}, 0x10, 0x0, 0x0)\n"),
		prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize valid: %v", err)
	}
	if !profiled.RuntimePolicy.ShouldScheduleProgram("fuzz", valid) {
		t.Fatalf("focused profile rejected valid UDP send lineage:\n%s",
			valid.Serialize())
	}
}

func TestWindowsAFDTargetProfileRejectsMixedAFDEndpointFamilies(t *testing.T) {
	profiled := windowsPolicyTestAFDTarget(t)
	broken := windowsPolicyTestDeserialize(t, profiled,
		"NtCreateFile$afd_tcp_endpoint(&(0x7f0000000000)=<r0=>0xffffffffffffffff, 0xc0100000, &(0x7f00000000c0)={0x30, 0x0, 0x0, &(0x7f0000000080)={0x16, 0x18, 0x0, &(0x7f0000000040)}}, &(0x7f0000000100)={@Status=0x7f, 0x75f}, 0x0, 0x0, 0x3, 0x3, 0x0, &(0x7f0000000140), 0x34)\n"+
			"r1 = NtDeviceIoControlFile$afd_bind_tcp_listener(r0, 0x0, 0x0, 0x0, &(0x7f0000000180)={@Status=0x8001, 0x80000000}, 0x12003, &(0x7f00000001c0), 0x14, &(0x7f0000000200), 0x10)\n"+
			"r2 = NtDeviceIoControlFile$afd_start_listen_tcp(r1, 0x0, 0x0, 0x0, &(0x7f0000000240)={@Status=0xf, 0x5}, 0x1200b, &(0x7f0000000280)={0x0, '\\x00', 0x8}, 0xc, 0x0, 0x0)\n"+
			"r3 = NtDeviceIoControlFile$afd_set_information_nonblock_tcp_listening(r2, 0x0, 0x0, 0x0, &(0x7f00000002c0)={@Status=0x8, 0x6}, 0x1203b, &(0x7f0000000300)={0x2, 0x0, 0x1}, 0x10, 0x0, 0x0)\n"+
			"r4 = NtDeviceIoControlFile$afd_set_information_nonblock_udp_bound(r3, 0x0, 0x0, 0x0, &(0x7f0000000340)={@Status=0x2, 0x8}, 0x1203b, &(0x7f0000000380)={0x2, 0x0, 0x1}, 0x10, 0x0, 0x0)\n"+
			"NtDeviceIoControlFile$afd_receive_datagram_udp_bound_nonblock(r4, 0x0, 0x0, 0x0, &(0x7f00000003c0)={@Pointer=0x7fff, 0x9}, 0x1201b, &(0x7f00000004c0)={&(0x7f0000000440)=[{0x4, &(0x7f0000000400)='ping'}], 0x1, 0x2, {&(0x7f0000000480)={0x2, 0x4e22, 0x7f000001}}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, &(0x7f0000000500)={0x2, 0x4e23, 0x7f000001}}}, 0x48, 0x0, 0x0)\n")
	if profiled.RuntimePolicy.ShouldScheduleProgram("fuzz", broken) {
		t.Fatalf("focused profile scheduled mixed TCP/UDP AFD endpoint lineage:\n%s", broken.Serialize())
	}

	valid := windowsPolicyTestDeserialize(t, profiled,
		"NtCreateFile$afd_udp_endpoint(&(0x7f0000000000)=<r0=>0xffffffffffffffff, 0xc0100000, &(0x7f00000000c0)={0x30, 0x0, 0x0, &(0x7f0000000080)={0x16, 0x18, 0x0, &(0x7f0000000040)}}, &(0x7f0000000100)={@Pointer=0x7, 0x7a85bf3b}, 0x0, 0x0, 0x3, 0x3, 0x0, &(0x7f0000000140), 0x34)\n"+
			"r1 = NtDeviceIoControlFile$afd_bind_udp(r0, 0x0, 0x0, 0x0, &(0x7f0000000180)={@Status=0x7, 0xfff}, 0x12003, &(0x7f00000001c0)={0x1}, 0x14, &(0x7f0000000200), 0x10)\n"+
			"r2 = NtDeviceIoControlFile$afd_set_information_nonblock_udp_bound(r1, 0x0, 0x0, 0x0, &(0x7f0000000240)={@Status=0x2, 0x8}, 0x1203b, &(0x7f0000000280)={0x2, 0x0, 0x1}, 0x10, 0x0, 0x0)\n"+
			"NtDeviceIoControlFile$afd_receive_datagram_udp_bound_nonblock(r2, 0x0, 0x0, 0x0, &(0x7f00000002c0)={@Pointer=0x7fff, 0x9}, 0x1201b, &(0x7f00000003c0)={&(0x7f0000000340)=[{0x4, &(0x7f0000000300)='pong'}], 0x1, 0x2, {&(0x7f0000000380)={0x2, 0x4e22, 0x7f000001}}}, 0x48, 0x0, 0x0)\n")
	if !profiled.RuntimePolicy.ShouldScheduleProgram("fuzz", valid) {
		t.Fatalf("focused profile rejected valid UDP AFD nonblock receive lineage:\n%s", valid.Serialize())
	}
}

func TestWindowsAFDTargetProfileRejectsMismatchedAFDReturnedSequence(t *testing.T) {
	profiled := windowsPolicyTestAFDTarget(t)
	broken := windowsPolicyTestDeserialize(t, profiled,
		"NtCreateFile$afd_tcp_endpoint(&(0x7f0000000000)=<r0=>0xffffffffffffffff, 0xc0100000, &(0x7f00000000c0)={0x30, 0x0, 0x0, &(0x7f0000000080)={0x16, 0x18, 0x0, &(0x7f0000000040)}}, &(0x7f0000000100)={@Status=0x7f, 0x75f}, 0x0, 0x0, 0x3, 0x3, 0x0, &(0x7f0000000140), 0x34)\n"+
			"r1 = NtDeviceIoControlFile$afd_bind_tcp(r0, 0x0, 0x0, 0x0, &(0x7f0000000180)={@Status=0x8001, 0x80000000}, 0x12003, &(0x7f00000001c0), 0x14, &(0x7f0000000200), 0x10)\n"+
			"NtCreateFile$afd_tcp_endpoint(&(0x7f0000000280)=<r2=>0xffffffffffffffff, 0xc0100000, &(0x7f0000000340)={0x30, 0x0, 0x0, &(0x7f0000000300)={0x16, 0x18, 0x0, &(0x7f00000002c0)}}, &(0x7f0000000380)={@Pointer=0x9, 0x40}, 0x0, 0x0, 0x3, 0x3, 0x0, &(0x7f00000003c0), 0x34)\n"+
			"r3 = NtDeviceIoControlFile$afd_bind_tcp_listener(r2, 0x0, 0x0, 0x0, &(0x7f0000000400)={@Status=0x3, 0x5}, 0x12003, &(0x7f0000000440), 0x14, &(0x7f0000000480), 0x10)\n"+
			"r4 = NtDeviceIoControlFile$afd_start_listen_tcp(r3, 0x0, 0x0, 0x0, &(0x7f00000004c0)={@Status=0x1, 0x21}, 0x1200b, &(0x7f0000000500)={0x0, '\\x00', 0x6}, 0xc, 0x0, 0x0)\n"+
			"r5 = NtDeviceIoControlFile$afd_connect_tcp_to_listener(r1, 0x0, 0x0, 0x0, &(0x7f0000000240)={@Pointer=0x1, 0x9}, 0x12007, &(0x7f0000000540)={0x0, '\\x00', 0x0, r4}, 0x28, &(0x7f0000000580), 0x10)\n"+
			"r6 = NtDeviceIoControlFile$afd_wait_for_listen_tcp(r5, 0x0, 0x0, 0x0, &(0x7f00000005c0)={@Status=0x1, 0x6}, 0x1200c, 0x0, 0x0, &(0x7f0000000600)={<r7=>0x0}, 0x14)\n"+
			"NtCreateFile$afd_tcp_endpoint(&(0x7f0000000680)=<r8=>0xffffffffffffffff, 0xc0100000, &(0x7f0000000740)={0x30, 0x0, 0x0, &(0x7f0000000700)={0x16, 0x18, 0x0, &(0x7f00000006c0)}}, &(0x7f0000000780)={@Pointer=0xffff, 0x5}, 0x0, 0x0, 0x3, 0x3, 0x0, &(0x7f00000007c0), 0x34)\n"+
			"r9 = NtDeviceIoControlFile$afd_bind_tcp(r8, 0x0, 0x0, 0x0, &(0x7f0000000800)={@Status=0x8}, 0x12003, &(0x7f0000000840)={0x3}, 0x14, &(0x7f0000000880), 0x10)\n"+
			"NtCreateFile$afd_tcp_endpoint(&(0x7f0000000900)=<r10=>0xffffffffffffffff, 0xc0100000, &(0x7f00000009c0)={0x30, 0x0, 0x0, &(0x7f0000000980)={0x16, 0x18, 0x0, &(0x7f0000000940)}}, &(0x7f0000000a00)={@Status=0x40, 0x8}, 0x0, 0x0, 0x3, 0x3, 0x0, &(0x7f0000000a40), 0x34)\n"+
			"r11 = NtDeviceIoControlFile$afd_bind_tcp_listener(r10, 0x0, 0x0, 0x0, &(0x7f0000000a80)={@Status=0x67e, 0x3}, 0x12003, &(0x7f0000000ac0), 0x14, &(0x7f0000000b00), 0x10)\n"+
			"r12 = NtDeviceIoControlFile$afd_start_listen_tcp(r11, 0x0, 0x0, 0x0, &(0x7f0000000b40)={@Status, 0xc4b7}, 0x1200b, &(0x7f0000000b80)={0x0, '\\x00', 0x2}, 0xc, 0x0, 0x0)\n"+
			"r13 = NtDeviceIoControlFile$afd_connect_tcp_to_listener(r9, 0x0, 0x0, 0x0, &(0x7f00000008c0)={@Status=0x1, 0x30}, 0x12007, &(0x7f0000000bc0)={0x0, '\\x00', 0x0, r12}, 0x28, &(0x7f0000000c00), 0x10)\n"+
			"NtDeviceIoControlFile$afd_wait_for_listen_lifo_tcp(r13, 0x0, 0x0, 0x0, &(0x7f0000000c40)={@Pointer=0x3, 0x500000000000000}, 0x12090, 0x0, 0x0, &(0x7f0000000c80)={<r14=>0x0}, 0x14)\n"+
			"NtDeviceIoControlFile$afd_get_unaccepted_connect_data_tcp(r6, 0x0, 0x0, 0x0, &(0x7f0000000640)={@Status=0x1, 0x7}, 0x120a7, &(0x7f0000000cc0)={r14}, 0xc, &(0x7f0000000d00), 0xc)\n")
	if profiled.RuntimePolicy.ShouldScheduleProgram("fuzz", broken) {
		t.Fatalf("focused profile scheduled returned handle/sequence mismatch:\n%s", broken.Serialize())
	}

	data, err := os.ReadFile("test/nyx_afd_private_core_listen_accept.txt")
	if err != nil {
		t.Fatalf("read core seed: %v", err)
	}
	valid := windowsPolicyTestDeserialize(t, profiled, string(data))
	if !profiled.RuntimePolicy.ShouldScheduleProgram("candidate", valid) {
		t.Fatalf("focused profile rejected matching returned handle/sequence seed:\n%s", valid.Serialize())
	}
}

func TestWindowsAFDTargetProfileRejectsBrokenPrivateResourceLineage(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
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
			"NtDeviceIoControlFile$afd_routing_interface_query_udp(r0, 0x0, 0x0, 0x0, &(0x7f0000000000)={@Status=0x0, 0x0}, 0x120ab, &(0x7f0000000040)={0x1, 0x10, 0x2, {0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}}, 0x18, &(0x7f0000000080), 0x14)\n"),
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
	windowsSkipLegacyAfdWinsockArchived(t)
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
	windowsSkipLegacyAfdWinsockArchived(t)
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
	windowsSkipLegacyAfdWinsockArchived(t)
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
	windowsSkipLegacyAfdWinsockArchived(t)
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
	windowsSkipLegacyAfdWinsockArchived(t)
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
	windowsSkipLegacyAfdWinsockArchived(t)
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

func TestWindowsAFDSemanticStateAcceptsConnectExIOCPUpdateChain(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	p := windowsPolicyTestDeserialize(t, profiled,
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r1, 0x1)\n"+
			"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r3 = bind$connectex_tcp(r2, &(0x7f0000000140)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n"+
			"r5 = CreateIoCompletionPort$connect_pending(r4, 0x0, 0xafd, 0x0)\n"+
			"WSAGetOverlappedResult$connect_pending(r4, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n"+
			"GetQueuedCompletionStatus$socket(r5, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n"+
			"r6 = setsockopt$update_connect_context(r4, 0xffff, 0x7010, 0x0, 0x0)\n"+
			"send$inet_tcp(r6, &(0x7f0000000480)='ok', 0x2, 0x0)\n")
	st := prog.BuildSemanticState(p, len(p.Calls))
	if !st.Valid() {
		t.Fatalf("valid ConnectEx IOCP chain rejected by semantic model: %+v\n%s",
			st.Violations, p.Serialize())
	}
	if !profiled.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
		t.Fatalf("valid ConnectEx IOCP chain rejected by runtime policy:\n%s", p.Serialize())
	}
	seenUpdated := false
	for _, facts := range st.Resources {
		if facts["connect_context_updated"] {
			seenUpdated = true
			break
		}
	}
	if !seenUpdated {
		t.Fatal("semantic state did not record SO_UPDATE_CONNECT_CONTEXT transition")
	}
}

func TestWindowsAFDSemanticStateAcceptsConnectExFocusedSeeds(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	for _, seed := range []string{
		"test/nyx_exp_afd_connectex_iocp_cancel.txt",
		"test/nyx_exp_afd_connectex_iocp_local_update.txt",
	} {
		t.Run(seed, func(t *testing.T) {
			data, err := os.ReadFile(seed)
			if err != nil {
				t.Fatalf("read seed: %v", err)
			}
			p := windowsPolicyTestDeserialize(t, profiled, string(data))
			if st := prog.BuildSemanticState(p, len(p.Calls)); !st.Valid() {
				t.Fatalf("focused ConnectEx seed rejected by semantic model: %+v\n%s",
					st.Violations, p.Serialize())
			}
			if !profiled.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
				t.Fatalf("focused ConnectEx seed rejected by runtime policy:\n%s", p.Serialize())
			}
		})
	}
}

func TestWindowsAFDSemanticStateAcceptsAcceptOptionSeed(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	data, err := os.ReadFile("test/nyx_afd_accept_option.txt")
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	p := windowsPolicyTestDeserialize(t, profiled, string(data))
	if st := prog.BuildSemanticState(p, len(p.Calls)); !st.Valid() {
		t.Fatalf("accept option seed rejected by semantic model: %+v\n%s",
			st.Violations, p.Serialize())
	}
	if !profiled.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
		t.Fatalf("accept option seed rejected by runtime policy:\n%s", p.Serialize())
	}
}

func TestWindowsAFDSemanticStateRejectsAcceptedSocketUseWithoutPeer(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	p := windowsPolicyTestDeserialize(t, profiled,
		"WSAStartup(0x202, &(0x7f0000000000)=0x8)\n"+
			"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001}, 0x10)\n"+
			"listen$inet_tcp(r1, 0x1)\n"+
			"r2 = accept$inet_tcp_nonblock(r1, 0x0, &(0x7f0000000140)=0x39)\n"+
			"getsockopt$int_accept(r2, 0xffff, 0x700c, &(0x7f0000000080), &(0x7f00000000c0)=0x4)\n")
	if st := prog.BuildSemanticState(p, len(p.Calls)); st.Valid() {
		t.Fatalf("semantic model accepted peerless accepted socket use:\n%s", p.Serialize())
	}
	if profiled.RuntimePolicy.ShouldScheduleProgram("fuzz", p) {
		t.Fatalf("runtime policy scheduled peerless accepted socket use:\n%s", p.Serialize())
	}
}

func TestWindowsAFDSemanticStateRejectsTCPConnectWithoutLocalListener(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	p := windowsPolicyTestDeserialize(t, profiled,
		"WSAStartup(0x202, &(0x7f0000000000))\n"+
			"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001}, 0x10)\n"+
			"connect$inet_tcp_nonblock(r0, &(0x7f00000000c0)={0x2, 0x4e32, 0x90}, 0x10)\n"+
			"r1 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp_nonblock(r1, &(0x7f0000000080)={0x2, 0x4e21}, 0x10)\n")
	if st := prog.BuildSemanticState(p, len(p.Calls)); st.Valid() {
		t.Fatalf("semantic model accepted peerless TCP connect chain:\n%s", p.Serialize())
	}
	if profiled.RuntimePolicy.ShouldScheduleProgram("fuzz", p) {
		t.Fatalf("runtime policy scheduled peerless TCP connect chain:\n%s", p.Serialize())
	}
}

func TestWindowsAFDSemanticStateAcceptsAcceptExUpdateChain(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	p := windowsPolicyTestDeserialize(t, profiled,
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = listen$inet_tcp(r1, 0x1)\n"+
			"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n"+
			"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n"+
			"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n"+
			"r7 = CreateIoCompletionPort$accept_pending(r6, 0x0, 0xafd, 0x0)\n"+
			"WSAGetOverlappedResult$accept_pending(r6, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n"+
			"GetQueuedCompletionStatus$socket(r7, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n"+
			"GetAcceptExSockaddrs$inet_tcp(&(0x7f0000000200), 0x0, 0x20, 0x20, &(0x7f0000000500), &(0x7f0000000540), &(0x7f0000000580), &(0x7f00000005c0))\n"+
			"r8 = setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000600)=r2, 0x8)\n"+
			"send$inet_accept_updated(r8, &(0x7f0000000680)='ok', 0x2, 0x0)\n")
	st := prog.BuildSemanticState(p, len(p.Calls))
	if !st.Valid() {
		t.Fatalf("valid AcceptEx update chain rejected by semantic model: %+v\n%s",
			st.Violations, p.Serialize())
	}
	seenUpdated := false
	for _, facts := range st.Resources {
		if facts["accept_context_updated"] {
			seenUpdated = true
			break
		}
	}
	if !seenUpdated {
		t.Fatal("semantic state did not record SO_UPDATE_ACCEPT_CONTEXT transition")
	}
}

func TestWindowsAFDSemanticStateAcceptsAcceptExFocusedSeeds(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	for _, seed := range []string{
		"test/nyx_exp_afd_accept_updated.txt",
		"test/nyx_exp_afd_acceptex_iocp_cancel.txt",
		"test/nyx_exp_afd_acceptex_iocp_local_update.txt",
		"test/nyx_afd_acceptex_vnet_cancel.txt",
		"test/nyx_afd_acceptex_vnet_iocp.txt",
		"test/nyx_afd_acceptex_vnet_sockaddrs.txt",
	} {
		t.Run(seed, func(t *testing.T) {
			data, err := os.ReadFile(seed)
			if err != nil {
				t.Fatalf("read seed: %v", err)
			}
			p := windowsPolicyTestDeserialize(t, profiled, string(data))
			if st := prog.BuildSemanticState(p, len(p.Calls)); !st.Valid() {
				t.Fatalf("focused AcceptEx seed rejected by semantic model: %+v\n%s",
					st.Violations, p.Serialize())
			}
			if !profiled.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
				t.Fatalf("focused AcceptEx seed rejected by runtime policy:\n%s", p.Serialize())
			}
		})
	}
}

func TestWindowsAFDSemanticStateRejectsUnsafePendingCancelCleanup(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	prefix := "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
		"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e34, 0x7f000001, '\\x00'/8}, 0x10)\n" +
		"r2 = listen$inet_tcp(r1, 0x1)\n" +
		"r3 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
		"r4 = AcceptEx$inet_tcp_pending(r2, r3, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
		"CreateIoCompletionPort$accept_pending(r4, 0x0, 0xafd, 0x0)\n" +
		"CancelIoEx$accept_pending(r4, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n"

	validCancel := windowsPolicyTestDeserialize(t, profiled, prefix)
	if st := prog.BuildSemanticState(validCancel, len(validCancel.Calls)); !st.Valid() {
		t.Fatalf("single pending cancel should be a terminal focused path: %+v\n%s",
			st.Violations, validCancel.Serialize())
	}
	if !profiled.RuntimePolicy.ShouldScheduleProgram("candidate", validCancel) {
		t.Fatalf("single pending cancel rejected by runtime policy:\n%s", validCancel.Serialize())
	}

	for name, suffix := range map[string]string{
		"duplicate cancel":   "CancelIo$accept_pending(r4)\n",
		"close after cancel": "closesocket$accept_pending(r4)\n",
	} {
		t.Run(name, func(t *testing.T) {
			p := windowsPolicyTestDeserialize(t, profiled, prefix+suffix)
			if st := prog.BuildSemanticState(p, len(p.Calls)); st.Valid() {
				t.Fatalf("unsafe pending cancel cleanup accepted:\n%s", p.Serialize())
			}
			if profiled.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
				t.Fatalf("unsafe pending cancel cleanup scheduled:\n%s", p.Serialize())
			}
		})
	}
}

func TestWindowsAFDSemanticStateAcceptsSendRecvPendingChains(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	tests := []struct {
		name string
		prog string
	}{
		{
			name: "tcp send iocp completion",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e40, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = ioctlsocket$fionbio_tcp_created(r2, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"r4 = connect$inet_tcp_nonblock(r3, &(0x7f0000000180)={0x2, 0x4e40, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = WSASend$tcp_pending(r4, &(0x7f0000000200)=[{0x4, &(0x7f0000000280)='ping'}], 0x1, &(0x7f0000000300), 0x0, &(0x7f0000000340)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
				"r6 = CreateIoCompletionPort$tcp_send_pending(r5, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$tcp_send_pending(r5, &(0x7f0000000340)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000400), 0x0, &(0x7f0000000440)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r6, &(0x7f0000000480), &(0x7f00000004c0), &(0x7f0000000500), 0x0)\n",
		},
		{
			name: "tcp recv iocp completion",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e41, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = ioctlsocket$fionbio_listener(r1, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000180)=0x1)\n" +
				"r5 = connect$inet_tcp_nonblock(r4, &(0x7f00000001c0)={0x2, 0x4e41, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r6 = ioctlsocket$fionbio_tcp_connected(r5, 0x8004667e, &(0x7f0000000200)=0x1)\n" +
				"r7 = accept$inet_tcp_nonblock(r2, &(0x7f0000000240)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000280)=0x10)\n" +
				"send$inet_accept(r7, &(0x7f00000002c0)='from-accept', 0xb, 0x0)\n" +
				"r8 = WSARecv$tcp_pending(r6, &(0x7f0000000340)=[{0x40, &(0x7f00000003c0)='\\x00'/64}], 0x1, &(0x7f0000000440), &(0x7f0000000480)=0x0, &(0x7f00000004c0)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
				"r9 = CreateIoCompletionPort$tcp_recv_pending(r8, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$tcp_recv_pending(r8, &(0x7f00000004c0)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000540), 0x0, &(0x7f0000000580)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r9, &(0x7f00000005c0), &(0x7f0000000600), &(0x7f0000000640), 0x0)\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := windowsPolicyTestDeserialize(t, profiled, test.prog)
			if st := prog.BuildSemanticState(p, len(p.Calls)); !st.Valid() {
				t.Fatalf("valid pending send/recv chain rejected by semantic model: %+v\n%s",
					st.Violations, p.Serialize())
			}
		})
	}
}

func TestWindowsAFDSemanticStateAcceptsPendingIOFocusedSeeds(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	for _, seed := range []string{
		"test/nyx_exp_afd_pending_io_tcp_recv_iocp.txt",
	} {
		t.Run(seed, func(t *testing.T) {
			data, err := os.ReadFile(seed)
			if err != nil {
				t.Fatalf("read seed: %v", err)
			}
			p := windowsPolicyTestDeserialize(t, profiled, string(data))
			if st := prog.BuildSemanticState(p, len(p.Calls)); !st.Valid() {
				t.Fatalf("focused pending-IO seed rejected by semantic model: %+v\n%s",
					st.Violations, p.Serialize())
			}
			if !profiled.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
				t.Fatalf("focused pending-IO seed rejected by runtime policy:\n%s", p.Serialize())
			}
		})
	}
}

func TestWindowsAFDSemanticStateAcceptsEventPollFocusedSeeds(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	for _, seed := range []string{
		"test/nyx_afd_public_event_nonblock_tcp.txt",
		"test/nyx_afd_private_event_select_nonblock.txt",
		"test/nyx_afd_private_enum_events_nonblock.txt",
		"test/nyx_afd_private_poll_accept_nonblock.txt",
	} {
		t.Run(seed, func(t *testing.T) {
			data, err := os.ReadFile(seed)
			if err != nil {
				t.Fatalf("read seed: %v", err)
			}
			p := windowsPolicyTestDeserialize(t, profiled, string(data))
			if st := prog.BuildSemanticState(p, len(p.Calls)); !st.Valid() {
				t.Fatalf("focused event/poll seed rejected by semantic model: %+v\n%s",
					st.Violations, p.Serialize())
			}
			if !profiled.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
				t.Fatalf("focused event/poll seed rejected by runtime policy:\n%s", p.Serialize())
			}
		})
	}
}

func TestWindowsAFDSemanticStateRejectsBadEventPollChains(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	prefix := "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
		"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"listen$inet_tcp(r1, 0x1)\n" +
		"r2 = ioctlsocket$fionbio_listener(r1, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
		"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
		"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000180)=0x1)\n" +
		"connect$inet_tcp_nonblock(r4, &(0x7f00000001c0)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"r5 = accept$inet_tcp_nonblock(r2, &(0x7f0000000200)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000240)=0x10)\n"
	tests := []struct {
		name string
		prog string
	}{
		{
			name: "private enum without select",
			prog: prefix +
				"NtDeviceIoControlFile$afd_enum_network_events_accept_nonblock(r5, 0x0, 0x0, 0x0, &(0x7f0000000300)={@Status=0x0, 0x0}, 0x1208b, 0x0, 0x0, &(0x7f0000000340), 0x38)\n",
		},
		{
			name: "private select without events",
			prog: prefix +
				"NtDeviceIoControlFile$afd_event_select_accept_nonblock(r5, 0x0, 0x0, 0x0, &(0x7f0000000280)={@Status=0x0, 0x0}, 0x12087, &(0x7f00000002c0)={0x0, 0x0, 0x0}, 0x10, 0x0, 0x0)\n",
		},
		{
			name: "private poll null output",
			prog: prefix +
				"NtDeviceIoControlFile$afd_poll_accept_nonblock(r5, 0x0, 0x0, 0x0, &(0x7f0000000280)={@Status=0x0, 0x0}, 0x12024, &(0x7f00000002c0)={{@QuadPart=0x0}, 0x1, 0x0, [0, 0, 0], [{r5, 0x3f, 0x0}]}, 0x20, 0x0, 0x0)\n",
		},
		{
			name: "private poll different socket",
			prog: prefix +
				"r6 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"NtDeviceIoControlFile$afd_poll_accept_nonblock(r5, 0x0, 0x0, 0x0, &(0x7f0000000280)={@Status=0x0, 0x0}, 0x12024, &(0x7f00000002c0)={{@QuadPart=0x0}, 0x1, 0x0, [0, 0, 0], [{r6, 0x3f, 0x0}]}, 0x20, &(0x7f0000000340)={{@QuadPart=0x0}, 0x1, 0x0, [0, 0, 0], [{r5, 0x0, 0x0}]}, 0x20)\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := windowsPolicyTestDeserialize(t, profiled, test.prog)
			if st := prog.BuildSemanticState(p, len(p.Calls)); st.Valid() {
				t.Fatalf("bad event/poll chain accepted by semantic model:\n%s", p.Serialize())
			}
		})
	}
}

func TestWindowsAFDSemanticStateRejectsBadSendRecvPendingChains(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	tests := []struct {
		name string
		prog string
	}{
		{
			name: "pending recv without completion",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = ioctlsocket$fionbio_tcp_created(r0, 0x8004667e, &(0x7f0000000100)=0x1)\n" +
				"r2 = connect$inet_tcp_nonblock(r1, &(0x7f0000000140)={0x2, 0x4e42, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"WSARecv$tcp_pending(r2, &(0x7f0000000200)=[{0x40, &(0x7f0000000280)='\\x00'/64}], 0x1, &(0x7f0000000300), &(0x7f0000000340)=0x0, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n",
		},
		{
			name: "recv completion without peer send driver",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = ioctlsocket$fionbio_tcp_created(r0, 0x8004667e, &(0x7f0000000100)=0x1)\n" +
				"r2 = connect$inet_tcp_nonblock(r1, &(0x7f0000000140)={0x2, 0x4e4b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r3 = WSARecv$tcp_pending(r2, &(0x7f0000000200)=[{0x40, &(0x7f0000000280)='\\x00'/64}], 0x1, &(0x7f0000000300), &(0x7f0000000340)=0x0, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
				"r4 = CreateIoCompletionPort$tcp_recv_pending(r3, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$tcp_recv_pending(r3, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000400), 0x0, &(0x7f0000000440)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r4, &(0x7f0000000480), &(0x7f00000004c0), &(0x7f0000000500), 0x0)\n",
		},
		{
			name: "canceled send without close",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = ioctlsocket$fionbio_tcp_created(r0, 0x8004667e, &(0x7f0000000100)=0x1)\n" +
				"r2 = connect$inet_tcp_nonblock(r1, &(0x7f0000000140)={0x2, 0x4e43, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r3 = WSASend$tcp_pending(r2, &(0x7f0000000200)=[{0x4, &(0x7f0000000280)='ping'}], 0x1, &(0x7f0000000300), 0x0, &(0x7f0000000340)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
				"CancelIoEx$tcp_send_pending(r3, &(0x7f0000000340)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "canceled send close cleanup",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = ioctlsocket$fionbio_tcp_created(r0, 0x8004667e, &(0x7f0000000100)=0x1)\n" +
				"r2 = connect$inet_tcp_nonblock(r1, &(0x7f0000000140)={0x2, 0x4e4a, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r3 = WSASend$tcp_pending(r2, &(0x7f0000000200)=[{0x4, &(0x7f0000000280)='ping'}], 0x1, &(0x7f0000000300), 0x0, &(0x7f0000000340)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
				"CancelIoEx$tcp_send_pending(r3, &(0x7f0000000340)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CancelIo$tcp_send_pending(r3)\n" +
				"closesocket$tcp_send_pending(r3)\n",
		},
		{
			name: "result after cancel",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = ioctlsocket$fionbio_tcp_created(r0, 0x8004667e, &(0x7f0000000100)=0x1)\n" +
				"r2 = connect$inet_tcp_nonblock(r1, &(0x7f0000000140)={0x2, 0x4e44, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r3 = WSASend$tcp_pending(r2, &(0x7f0000000200)=[{0x4, &(0x7f0000000280)='ping'}], 0x1, &(0x7f0000000300), 0x0, &(0x7f0000000340)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
				"CancelIoEx$tcp_send_pending(r3, &(0x7f0000000340)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"WSAGetOverlappedResult$tcp_send_pending(r3, &(0x7f0000000340)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000400), 0x0, &(0x7f0000000440)=0x0)\n" +
				"closesocket$tcp_send_pending(r3)\n",
		},
		{
			name: "different overlapped",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = ioctlsocket$fionbio_tcp_created(r0, 0x8004667e, &(0x7f0000000100)=0x1)\n" +
				"r2 = connect$inet_tcp_nonblock(r1, &(0x7f0000000140)={0x2, 0x4e45, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r3 = WSARecv$tcp_pending(r2, &(0x7f0000000200)=[{0x40, &(0x7f0000000280)='\\x00'/64}], 0x1, &(0x7f0000000300), &(0x7f0000000340)=0x0, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
				"WSAGetOverlappedResult$tcp_recv_pending(r3, &(0x7f0000000480)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000400), 0x0, &(0x7f0000000440)=0x0)\n",
		},
		{
			name: "fwait result",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = ioctlsocket$fionbio_tcp_created(r0, 0x8004667e, &(0x7f0000000100)=0x1)\n" +
				"r2 = connect$inet_tcp_nonblock(r1, &(0x7f0000000140)={0x2, 0x4e46, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r3 = WSARecv$tcp_pending(r2, &(0x7f0000000200)=[{0x40, &(0x7f0000000280)='\\x00'/64}], 0x1, &(0x7f0000000300), &(0x7f0000000340)=0x0, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n" +
				"WSAGetOverlappedResult$tcp_recv_pending(r3, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000400), 0x1, &(0x7f0000000440)=0x0)\n",
		},
		{
			name: "send non-zero flags",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = ioctlsocket$fionbio_tcp_created(r0, 0x8004667e, &(0x7f0000000100)=0x1)\n" +
				"r2 = connect$inet_tcp_nonblock(r1, &(0x7f0000000140)={0x2, 0x4e47, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"WSASend$tcp_pending(r2, &(0x7f0000000200)=[{0x4, &(0x7f0000000280)='ping'}], 0x1, &(0x7f0000000300), 0x1, &(0x7f0000000340)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n",
		},
		{
			name: "recv non-zero flags",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = ioctlsocket$fionbio_tcp_created(r0, 0x8004667e, &(0x7f0000000100)=0x1)\n" +
				"r2 = connect$inet_tcp_nonblock(r1, &(0x7f0000000140)={0x2, 0x4e48, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"WSARecv$tcp_pending(r2, &(0x7f0000000200)=[{0x40, &(0x7f0000000280)='\\x00'/64}], 0x1, &(0x7f0000000300), &(0x7f0000000340)=0x1, &(0x7f0000000380)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n",
		},
		{
			name: "completion routine",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = ioctlsocket$fionbio_tcp_created(r0, 0x8004667e, &(0x7f0000000100)=0x1)\n" +
				"r2 = connect$inet_tcp_nonblock(r1, &(0x7f0000000140)={0x2, 0x4e49, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"WSASend$tcp_pending(r2, &(0x7f0000000200)=[{0x4, &(0x7f0000000280)='ping'}], 0x1, &(0x7f0000000300), 0x0, &(0x7f0000000340)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380)=0x1)\n",
		},
		{
			name: "default socket",
			prog: "WSASend$tcp_pending(0xffffffffffffffff, &(0x7f0000000200)=[{0x4, &(0x7f0000000280)='ping'}], 0x1, &(0x7f0000000300), 0x0, &(0x7f0000000340)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0)\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := windowsPolicyTestDeserialize(t, profiled, test.prog)
			if st := prog.BuildSemanticState(p, len(p.Calls)); st.Valid() {
				t.Fatalf("bad pending send/recv chain accepted by semantic model:\n%s", p.Serialize())
			}
		})
	}
}

func TestWindowsAFDSemanticStateRejectsBadAcceptExChains(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	tests := []struct {
		name string
		prog string
	}{
		{
			name: "update before completion",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = AcceptEx$inet_tcp_pending(r2, r3, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"setsockopt$update_accept_context(r4, 0xffff, 0x700b, &(0x7f0000000380)=r2, 0x8)\n",
		},
		{
			name: "different listener",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = bind$inet_tcp(r3, &(0x7f0000000140)={0x2, 0x4e33, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = listen$inet_tcp(r4, 0x1)\n" +
				"r6 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r7 = ioctlsocket$fionbio_tcp_created(r6, 0x8004667e, &(0x7f0000000180)=0x1)\n" +
				"connect$inet_tcp_nonblock(r7, &(0x7f00000001c0)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r8 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r9 = AcceptEx$inet_tcp_pending(r2, r8, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"setsockopt$update_accept_context(r9, 0xffff, 0x700b, &(0x7f0000000380)=r5, 0x8)\n",
		},
		{
			name: "invalid address lengths",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"AcceptEx$inet_tcp_pending(r2, r3, &(0x7f0000000200)='\\x00'/32, 0x0, 0x10, 0x10, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "default accept socket",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"AcceptEx$inet_tcp_pending(r2, 0xffffffffffffffff, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "default accept-updated resource",
			prog: "send$inet_accept_updated(0xffffffffffffffff, &(0x7f0000000400)='ok', 0x2, 0x0)\n",
		},
		{
			name: "update after cancel",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CancelIoEx$accept_pending(r6, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000380)=r2, 0x8)\n",
		},
		{
			name: "result after cancel",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = AcceptEx$inet_tcp_pending(r2, r3, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CancelIoEx$accept_pending(r4, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"WSAGetOverlappedResult$accept_pending(r4, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"closesocket$accept_pending(r4)\n",
		},
		{
			name: "gqcs after cancel",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = AcceptEx$inet_tcp_pending(r2, r3, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r5 = CreateIoCompletionPort$accept_pending(r4, 0x0, 0xafd, 0x0)\n" +
				"CancelIoEx$accept_pending(r4, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"GetQueuedCompletionStatus$socket(r5, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"closesocket$accept_pending(r4)\n",
		},
		{
			name: "cancel after completion",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = AcceptEx$inet_tcp_pending(r2, r3, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r5 = CreateIoCompletionPort$accept_pending(r4, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r4, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r5, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"CancelIoEx$accept_pending(r4, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"closesocket$accept_pending(r4)\n",
		},
		{
			name: "unrelated syscall before acceptex chain",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"SetThreadToken(&(0x7f0000000900), 0x0)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000380)=r2, 0x8)\n",
		},
		{
			name: "unrelated syscall inside acceptex chain",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"GetProcessHeaps(0x56, &(0x7f0000000040))\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000380)=r2, 0x8)\n",
		},
		{
			name: "non-zero result overlapped",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r7 = CreateIoCompletionPort$accept_pending(r6, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r6, &(0x7f0000000300)={0x0, 0x101, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r7, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n",
		},
		{
			name: "non-zero result flags",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r7 = CreateIoCompletionPort$accept_pending(r6, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r6, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x9)\n" +
				"GetQueuedCompletionStatus$socket(r7, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n",
		},
		{
			name: "null gqcs overlapped output",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r7 = CreateIoCompletionPort$accept_pending(r6, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r6, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r7, &(0x7f0000000400), &(0x7f0000000440), 0x0, 0x0)\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n",
		},
		{
			name: "accept-updated recv non-zero flags",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"r5 = connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r6 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r7 = AcceptEx$inet_tcp_pending(r2, r6, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r8 = CreateIoCompletionPort$accept_pending(r7, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r7, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r8, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"r9 = setsockopt$update_accept_context(r7, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n" +
				"send$inet_tcp(r5, &(0x7f0000000680)='afd-acceptex-local-iocp', 0x18, 0x0)\n" +
				"recv$inet_accept_updated(r9, &(0x7f0000000780)='\\x00'/64, 0x40, 0x3)\n",
		},
		{
			name: "mutable iocp threads",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CreateIoCompletionPort$accept_pending(r6, 0x0, 0xafd, 0x3)\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000380)=r2, 0x8)\n",
		},
		{
			name: "mutable iocp key",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CreateIoCompletionPort$accept_pending(r6, 0x0, 0x0, 0x0)\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000380)=r2, 0x8)\n",
		},
		{
			name: "default local driver connect",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"connect$inet_tcp_nonblock(0xffffffffffffffff, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r3 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = AcceptEx$inet_tcp_pending(r2, r3, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r5 = CreateIoCompletionPort$accept_pending(r4, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r4, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r5, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"setsockopt$update_accept_context(r4, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n",
		},
		{
			name: "default fionbio local driver connect",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = ioctlsocket$fionbio_tcp_created(0xffffffffffffffff, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r3, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r4 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r5 = AcceptEx$inet_tcp_pending(r2, r4, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r6 = CreateIoCompletionPort$accept_pending(r5, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r5, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r6, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"setsockopt$update_accept_context(r5, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n",
		},
		{
			name: "plain socket nonblock local driver connect",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"connect$inet_tcp_nonblock(r3, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r4 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r5 = AcceptEx$inet_tcp_pending(r2, r4, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r6 = CreateIoCompletionPort$accept_pending(r5, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r5, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r6, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"setsockopt$update_accept_context(r5, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n",
		},
		{
			name: "completed accept without update or close",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r7 = CreateIoCompletionPort$accept_pending(r6, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r6, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r7, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n",
		},
		{
			name: "accept update without overlapped result",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r7 = CreateIoCompletionPort$accept_pending(r6, 0x0, 0xafd, 0x0)\n" +
				"GetQueuedCompletionStatus$socket(r7, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n",
		},
		{
			name: "accept update without iocp completion",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CreateIoCompletionPort$accept_pending(r6, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r6, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n",
		},
		{
			name: "accept sockaddrs before completion fences",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"GetAcceptExSockaddrs$inet_tcp(&(0x7f0000000200), 0x0, 0x20, 0x20, &(0x7f0000000500), &(0x7f0000000540), &(0x7f0000000580), &(0x7f00000005c0))\n",
		},
		{
			name: "accept sockaddrs with different output buffer",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r7 = CreateIoCompletionPort$accept_pending(r6, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r6, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r7, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"GetAcceptExSockaddrs$inet_tcp(&(0x7f0000000500), 0x0, 0x20, 0x20, &(0x7f0000000580), &(0x7f00000005c0), &(0x7f0000000600), &(0x7f0000000640))\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000680)=r2, 0x8)\n",
		},
		{
			name: "tcp send before accept update",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"r5 = connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r6 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r7 = AcceptEx$inet_tcp_pending(r2, r6, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CreateIoCompletionPort$accept_pending(r7, 0x0, 0xafd, 0x0)\n" +
				"send$inet_tcp(r5, &(0x7f0000000680)='afd-acceptex-local-iocp', 0x18, 0x0)\n",
		},
		{
			name: "tcp send before accept issue",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"send$inet_tcp(0xffffffffffffffff, &(0x7f0000000040)='afd-acceptex-local-iocp', 0x18, 0x0)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r7 = CreateIoCompletionPort$accept_pending(r6, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r6, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r7, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n",
		},
		{
			name: "default tcp send after accept update",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r5 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r6 = AcceptEx$inet_tcp_pending(r2, r5, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r7 = CreateIoCompletionPort$accept_pending(r6, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r6, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r7, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"setsockopt$update_accept_context(r6, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n" +
				"send$inet_tcp(0xffffffffffffffff, &(0x7f0000000680)='afd-acceptex-local-iocp', 0x18, 0x0)\n",
		},
		{
			name: "tcp send non-zero flags after accept update",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"r5 = connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r6 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r7 = AcceptEx$inet_tcp_pending(r2, r6, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r8 = CreateIoCompletionPort$accept_pending(r7, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r7, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r8, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"setsockopt$update_accept_context(r7, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n" +
				"send$inet_tcp(r5, &(0x7f0000000680)='afd-acceptex-local-iocp', 0x18, 0x3)\n",
		},
		{
			name: "tcp send oversized after accept update",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = listen$inet_tcp(r1, 0x1)\n" +
				"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r4 = ioctlsocket$fionbio_tcp_created(r3, 0x8004667e, &(0x7f0000000140)=0x1)\n" +
				"r5 = connect$inet_tcp_nonblock(r4, &(0x7f0000000180)={0x2, 0x4e32, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r6 = socket$accept_tcp(0x2, 0x1, 0x6)\n" +
				"r7 = AcceptEx$inet_tcp_pending(r2, r6, &(0x7f0000000200)='\\x00'/96, 0x0, 0x20, 0x20, &(0x7f0000000280), &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r8 = CreateIoCompletionPort$accept_pending(r7, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$accept_pending(r7, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r8, &(0x7f0000000400), &(0x7f0000000440), &(0x7f0000000480), 0x0)\n" +
				"setsockopt$update_accept_context(r7, 0xffff, 0x700b, &(0x7f0000000500)=r2, 0x8)\n" +
				"send$inet_tcp(r5, &(0x7f0000000680)='afd-acceptex-local-iocp', 0x101, 0x0)\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := windowsPolicyTestDeserialize(t, profiled, test.prog)
			if st := prog.BuildSemanticState(p, len(p.Calls)); st.Valid() {
				t.Fatalf("bad AcceptEx chain accepted by semantic model:\n%s", p.Serialize())
			}
		})
	}
}

func TestWindowsAFDSemanticStateRejectsBadConnectExChains(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	tests := []struct {
		name string
		prog string
	}{
		{
			name: "unbound connectex",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "connectex bind from default socket",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = bind$connectex_tcp(0xffffffffffffffff, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r1 = ConnectEx$inet_tcp_pending(r0, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r2 = CreateIoCompletionPort$connect_pending(r1, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r1, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r2, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n",
		},
		{
			name: "listener bind from default socket",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = bind$inet_tcp(0xffffffffffffffff, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r0, 0x1)\n" +
				"r1 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r2 = bind$connectex_tcp(r1, &(0x7f0000000140)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r3 = ConnectEx$inet_tcp_pending(r2, &(0x7f0000000180)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CreateIoCompletionPort$connect_pending(r3, 0x0, 0xafd, 0x0)\n",
		},
		{
			name: "connectex without matching listener",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000140)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CreateIoCompletionPort$connect_pending(r2, 0x0, 0xafd, 0x0)\n",
		},
		{
			name: "connectex listener address mismatch",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000140)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000180)={0x2, 0x4e20, 0x7f000003, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CreateIoCompletionPort$connect_pending(r4, 0x0, 0xafd, 0x0)\n",
		},
		{
			name: "connectex bind without sockaddr",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, 0x0, 0x0)\n" +
				"ConnectEx$inet_tcp_pending(r3, &(0x7f0000000180)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "connectex invalid send buffer pointer",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000140)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"ConnectEx$inet_tcp_pending(r3, &(0x7f0000000180)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, 0xfffffffffffffffe, 0x0, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "connectex low send buffer pointer",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000120)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"ConnectEx$inet_tcp_pending(r3, &(0x7f0000000140)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000040)=\"0fdb7e39a05cca3a095643f9ae2bed65be46b1ee9341b5454dfa230ea6a7\", 0x1e, &(0x7f00000001c0), &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "connectex low bytes-sent pointer",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000120)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"ConnectEx$inet_tcp_pending(r3, &(0x7f0000000140)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000180)='cx', 0x2, &(0x7f0000000040), &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "null overlapped",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), 0x0)\n",
		},
		{
			name: "non-zero connectex overlapped",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000140)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"ConnectEx$inet_tcp_pending(r3, &(0x7f0000000180)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x2, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "connectex overlapped output token reused",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000140), 0x10)\n" +
				"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000180)={0x2, 0x4e20, 0x7f000001}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts, <r5=>0x0})\n" +
				"OpenPrinterA(&(0x7f0000000040)=0x6, &(0x7f0000000080)=r5, &(0x7f00000000c0)=0x7fffffff)\n" +
				"CreateIoCompletionPort$connect_pending(r4, 0x0, 0xafd, 0x0)\n",
		},
		{
			name: "unrelated syscall before connectex chain",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e2f, 0x7f000001}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"OpenProcessToken(0x0, 0x400, &(0x7f0000000500))\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000140), 0x10)\n" +
				"ConnectEx$inet_tcp_pending(r3, &(0x7f0000000180)={0x2, 0x4e2f, 0x7f000001}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "unrelated syscall during connectex chain",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e2f, 0x7f000001}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000140), 0x10)\n" +
				"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000180)={0x2, 0x4e2f, 0x7f000001}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"OpenPrinterA(&(0x7f0000000040)=0x6, &(0x7f0000000080)=0x0, &(0x7f00000000c0)=0x7fffffff)\n" +
				"CreateIoCompletionPort$connect_pending(r4, 0x0, 0xafd, 0x0)\n",
		},
		{
			name: "pending without observed completion",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "duplicate cancel request",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CancelIoEx$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CancelIo$connect_pending(r2)\n",
		},
		{
			name: "canceled connectex without close pending",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e2f, 0x7f000001}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000140), 0x10)\n" +
				"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000180)={0x2, 0x4e2f, 0x7f000001}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r5 = CreateIoCompletionPort$connect_pending(r4, 0x0, 0xafd, 0x0)\n" +
				"CancelIoEx$connect_pending(r4, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"WSAGetOverlappedResult$connect_pending(r4, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"CancelIo$connect_pending(r4)\n" +
				"GetQueuedCompletionStatus$socket(r5, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n" +
				"closesocket$any(r1)\n",
		},
		{
			name: "close pending before completion",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"closesocket$connect_pending(r2)\n",
		},
		{
			name: "different result overlapped",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"WSAGetOverlappedResult$connect_pending(r2, &(0x7f0000000300)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n",
		},
		{
			name: "non-zero result overlapped",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000140)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000180)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"WSAGetOverlappedResult$connect_pending(r4, &(0x7f0000000280)={0x0, 0x2, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x0, &(0x7f00000003c0)=0x0)\n",
		},
		{
			name: "overlapped result waits on connectex",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"WSAGetOverlappedResult$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000380), 0x1, &(0x7f00000003c0)=0x0)\n",
		},
		{
			name: "overlapped result low output pointer",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000140)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000180)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"WSAGetOverlappedResult$connect_pending(r4, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000080), 0x0, &(0x7f0000000340)=0x0)\n",
		},
		{
			name: "gqcs without iocp",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"GetQueuedCompletionStatus$socket(0x0, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n",
		},
		{
			name: "gqcs low output pointer",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000140)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000180)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r5 = CreateIoCompletionPort$connect_pending(r4, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r4, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r5, &(0x7f0000000080), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n",
		},
		{
			name: "connect pending iocp without pending socket",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CreateIoCompletionPort$connect_pending(0xffffffffffffffff, 0x0, 0xafd, 0x0)\n" +
				"CancelIoEx$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"WSAGetOverlappedResult$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"closesocket$connect_pending(r2)\n",
		},
		{
			name: "duplicate connect pending iocp association",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CreateIoCompletionPort$connect_pending(r2, 0x0, 0xafd, 0x0)\n" +
				"CreateIoCompletionPort$connect_pending(r2, 0x0, 0xafd, 0x0)\n" +
				"CancelIoEx$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"WSAGetOverlappedResult$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"closesocket$connect_pending(r2)\n",
		},
		{
			name: "gqcs after CancelIo without CancelIoEx",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r3 = CreateIoCompletionPort$connect_pending(r2, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"CancelIo$connect_pending(r2)\n" +
				"GetQueuedCompletionStatus$socket(r3, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n" +
				"closesocket$connect_pending(r2)\n",
		},
		{
			name: "overlapped result after CancelIoEx",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CancelIoEx$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"WSAGetOverlappedResult$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"closesocket$connect_pending(r2)\n",
		},
		{
			name: "gqcs after CancelIoEx",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r3 = CreateIoCompletionPort$connect_pending(r2, 0x0, 0xafd, 0x0)\n" +
				"CancelIoEx$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"GetQueuedCompletionStatus$socket(r3, &(0x7f0000000300), &(0x7f0000000340), &(0x7f0000000380), 0x0)\n" +
				"closesocket$connect_pending(r2)\n",
		},
		{
			name: "cancel after gqcs completion",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r3 = CreateIoCompletionPort$connect_pending(r2, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r3, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n" +
				"CancelIoEx$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"closesocket$connect_pending(r2)\n",
		},
		{
			name: "update before completion",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"setsockopt$update_connect_context(r2, 0xffff, 0x7010, 0x0, 0x0)\n",
		},
		{
			name: "update after gqcs without overlapped result",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r3 = CreateIoCompletionPort$connect_pending(r2, 0x0, 0xafd, 0x0)\n" +
				"GetQueuedCompletionStatus$socket(r3, &(0x7f0000000300), &(0x7f0000000340), &(0x7f0000000380), 0x0)\n" +
				"setsockopt$update_connect_context(r2, 0xffff, 0x7010, 0x0, 0x0)\n",
		},
		{
			name: "update after overlapped result without gqcs",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CreateIoCompletionPort$connect_pending(r2, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"setsockopt$update_connect_context(r2, 0xffff, 0x7010, 0x0, 0x0)\n",
		},
		{
			name: "direct connected use before update",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"send$inet_tcp(r2, &(0x7f0000000300)='bad', 0x3, 0x0)\n",
		},
		{
			name: "default connected use in connectex program",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r3 = CreateIoCompletionPort$connect_pending(r2, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r3, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n" +
				"send$inet_tcp(0xffffffffffffffff, &(0x7f0000000480)='bad', 0x3, 0x0)\n",
		},
		{
			name: "update after cancel",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$connectex_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r2 = ConnectEx$inet_tcp_pending(r1, &(0x7f0000000180)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000200)='cx', 0x2, &(0x7f0000000240), &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"CancelIoEx$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"WSAGetOverlappedResult$connect_pending(r2, &(0x7f0000000280)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"setsockopt$update_connect_context(r2, 0xffff, 0x7010, 0x0, 0x0)\n",
		},
		{
			name: "post update getpeername low length pointer",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000120)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000140)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000180)='cx', 0x2, &(0x7f00000001c0), &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r5 = CreateIoCompletionPort$connect_pending(r4, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r4, &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r5, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n" +
				"r6 = setsockopt$update_connect_context(r4, 0xffff, 0x7010, 0x0, 0x0)\n" +
				"send$inet_tcp(r6, &(0x7f0000000480)='afd-connectex-local', 0x13, 0x0)\n" +
				"getsockname$tcp(r6, &(0x7f0000000580), &(0x7f00000005c0)=0x10)\n" +
				"getpeername$tcp(r6, &(0x7f0000000600), &(0x7f0000000040)=0x10)\n",
		},
		{
			name: "post update getpeername low output pointer",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000120)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000140)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000180)='cx', 0x2, &(0x7f00000001c0), &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r5 = CreateIoCompletionPort$connect_pending(r4, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r4, &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r5, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n" +
				"r6 = setsockopt$update_connect_context(r4, 0xffff, 0x7010, 0x0, 0x0)\n" +
				"send$inet_tcp(r6, &(0x7f0000000480)='afd-connectex-local', 0x13, 0x0)\n" +
				"getsockname$tcp(r6, &(0x7f0000000580), &(0x7f00000005c0)=0x10)\n" +
				"getpeername$tcp(r6, &(0x7f0000000080), &(0x7f0000000640)=0x10)\n",
		},
		{
			name: "post update send non-zero flags",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000120)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000140)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000180)='cx', 0x2, &(0x7f00000001c0), &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r5 = CreateIoCompletionPort$connect_pending(r4, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r4, &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r5, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n" +
				"r6 = setsockopt$update_connect_context(r4, 0xffff, 0x7010, 0x0, 0x0)\n" +
				"send$inet_tcp(r6, &(0x7f0000000480)='afd-connectex-local', 0x13, 0x8000)\n",
		},
		{
			name: "post update send null buffer",
			prog: "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
				"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"listen$inet_tcp(r1, 0x1)\n" +
				"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
				"r3 = bind$connectex_tcp(r2, &(0x7f0000000120)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
				"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000140)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000180)='cx', 0x2, &(0x7f00000001c0), &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r5 = CreateIoCompletionPort$connect_pending(r4, 0x0, 0xafd, 0x0)\n" +
				"WSAGetOverlappedResult$connect_pending(r4, &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
				"GetQueuedCompletionStatus$socket(r5, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n" +
				"r6 = setsockopt$update_connect_context(r4, 0xffff, 0x7010, 0x0, 0x0)\n" +
				"send$inet_tcp(r6, 0x0, 0x0, 0x0)\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := windowsPolicyTestDeserialize(t, profiled, test.prog)
			if st := prog.BuildSemanticState(p, len(p.Calls)); st.Valid() {
				t.Fatalf("semantic model accepted bad ConnectEx chain:\n%s", p.Serialize())
			}
			if profiled.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
				t.Fatalf("runtime policy scheduled bad ConnectEx chain:\n%s", p.Serialize())
			}
		})
	}
}

func TestWindowsAFDSemanticStateAcceptsDisconnectExReuseChain(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	p := windowsPolicyTestDeserialize(t, profiled,
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = listen$inet_tcp(r1, 0x1)\n"+
			"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n"+
			"r4 = connect$inet_tcp(r3, &(0x7f0000000140)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r5 = accept$inet_tcp(r2, 0x0, 0x0)\n"+
			"closesocket$any(r5)\n"+
			"r6 = DisconnectEx$inet_tcp_reuse(r4, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x2, 0x0)\n"+
			"r7 = CreateIoCompletionPort$disconnect_reuse_pending(r6, 0x0, 0xafd, 0x0)\n"+
			"GetQueuedCompletionStatus$socket(r7, &(0x7f0000000280), &(0x7f00000002c0), &(0x7f0000000300), 0x0)\n"+
			"r8 = WSAGetOverlappedResult$disconnect_reuse_pending(r6, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000340), 0x0, &(0x7f0000000380)=0x0)\n"+
			"r9 = ConnectEx$inet_tcp_reuse(r8, &(0x7f00000003c0)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000400)='dx', 0x2, &(0x7f0000000440), &(0x7f0000000480)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n"+
			"r10 = CreateIoCompletionPort$connect_pending(r9, 0x0, 0xafd, 0x0)\n"+
			"WSAGetOverlappedResult$connect_pending(r9, &(0x7f0000000480)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000580), 0x0, &(0x7f00000005c0)=0x0)\n"+
			"GetQueuedCompletionStatus$socket(r10, &(0x7f0000000600), &(0x7f0000000640), &(0x7f0000000680), 0x0)\n"+
			"setsockopt$update_connect_context(r9, 0xffff, 0x7010, 0x0, 0x0)\n")
	if st := prog.BuildSemanticState(p, len(p.Calls)); !st.Valid() {
		t.Fatalf("valid DisconnectEx reuse chain rejected by semantic model: %+v\n%s",
			st.Violations, p.Serialize())
	}
	if !profiled.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
		t.Fatalf("valid DisconnectEx reuse chain rejected by runtime policy:\n%s", p.Serialize())
	}
}

func TestWindowsAFDSemanticStateAcceptsDisconnectExReuseConnectExPeerCloseSeed(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	data, err := os.ReadFile("test/nyx_exp_afd_disconnectex_reuse_connectex_peerclose.txt")
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	p := windowsPolicyTestDeserialize(t, profiled, string(data))
	if st := prog.BuildSemanticState(p, len(p.Calls)); !st.Valid() {
		t.Fatalf("valid ConnectEx-driven DisconnectEx reuse seed rejected by semantic model: %+v\n%s",
			st.Violations, p.Serialize())
	}
	if !profiled.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
		t.Fatalf("valid ConnectEx-driven DisconnectEx reuse seed rejected by runtime policy:\n%s", p.Serialize())
	}
}

func TestWindowsAFDSemanticStateRejectsBadDisconnectExReuseChains(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	prefix := "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
		"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"r2 = listen$inet_tcp(r1, 0x1)\n" +
		"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
		"r4 = connect$inet_tcp(r3, &(0x7f0000000140)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"r9 = accept$inet_tcp(r2, 0x0, 0x0)\n" +
		"closesocket$any(r9)\n"
	prefixNoPeerClose := "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
		"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"r2 = listen$inet_tcp(r1, 0x1)\n" +
		"r3 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
		"r4 = connect$inet_tcp(r3, &(0x7f0000000140)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"accept$inet_tcp(r2, 0x0, 0x0)\n"
	prefixConnectExNoPeerClose := "WSAStartup(0x202, &(0x7f0000000000)=0x0)\n" +
		"r0 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
		"r1 = bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e2d, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"listen$inet_tcp(r1, 0x1)\n" +
		"r2 = socket$inet_tcp(0x2, 0x1, 0x6)\n" +
		"r3 = bind$connectex_tcp(r2, &(0x7f0000000120)={0x2, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n" +
		"r4 = ConnectEx$inet_tcp_pending(r3, &(0x7f0000000140)={0x2, 0x4e2d, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000180)='cx', 0x2, &(0x7f00000001c0), &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
		"r5 = CreateIoCompletionPort$connect_pending(r4, 0x0, 0xafd, 0x0)\n" +
		"WSAGetOverlappedResult$connect_pending(r4, &(0x7f0000000200)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000300), 0x0, &(0x7f0000000340)=0x0)\n" +
		"GetQueuedCompletionStatus$socket(r5, &(0x7f0000000380), &(0x7f00000003c0), &(0x7f0000000400), 0x0)\n" +
		"r6 = setsockopt$update_connect_context(r4, 0xffff, 0x7010, 0x0, 0x0)\n"
	tests := []struct {
		name string
		prog string
	}{
		{
			name: "disconnectex reuse without peer close",
			prog: prefixNoPeerClose +
				"DisconnectEx$inet_tcp_reuse(r4, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x2, 0x0)\n",
		},
		{
			name: "connectex updated disconnectex reuse without peer close",
			prog: prefixConnectExNoPeerClose +
				"DisconnectEx$inet_tcp_reuse(r6, &(0x7f0000000480)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x2, 0x0)\n",
		},
		{
			name: "reuse without disconnectex",
			prog: prefix +
				"ConnectEx$inet_tcp_reuse(r4, &(0x7f0000000180)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f00000001c0)='dx', 0x2, &(0x7f0000000200), &(0x7f0000000240)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "disconnectex reuse with bad flags",
			prog: prefix +
				"DisconnectEx$inet_tcp_reuse(r4, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x0, 0x0)\n",
		},
		{
			name: "disconnectex reuse with bad reserved",
			prog: prefix +
				"DisconnectEx$inet_tcp_reuse(r4, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x2, 0x1)\n",
		},
		{
			name: "disconnectex reuse with null overlapped",
			prog: prefix +
				"DisconnectEx$inet_tcp_reuse(r4, 0x0, 0x2, 0x0)\n",
		},
		{
			name: "connectex reuse before disconnect completion",
			prog: prefix +
				"r5 = DisconnectEx$inet_tcp_reuse(r4, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x2, 0x0)\n" +
				"ConnectEx$inet_tcp_reuse(r5, &(0x7f00000003c0)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000400)='dx', 0x2, &(0x7f0000000440), &(0x7f0000000480)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "connectex reuse with null overlapped",
			prog: prefix +
				"r5 = DisconnectEx$inet_tcp_reuse(r4, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x2, 0x0)\n" +
				"r6 = WSAGetOverlappedResult$disconnect_reuse_pending(r5, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000340), 0x0, &(0x7f0000000380)=0x0)\n" +
				"ConnectEx$inet_tcp_reuse(r6, &(0x7f00000003c0)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000400)='dx', 0x2, &(0x7f0000000440), 0x0)\n",
		},
		{
			name: "connectex reuse without send buffer",
			prog: prefix +
				"r5 = DisconnectEx$inet_tcp_reuse(r4, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x2, 0x0)\n" +
				"r6 = WSAGetOverlappedResult$disconnect_reuse_pending(r5, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000340), 0x0, &(0x7f0000000380)=0x0)\n" +
				"ConnectEx$inet_tcp_reuse(r6, &(0x7f00000003c0)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, 0x0, 0x0, &(0x7f0000000440), &(0x7f0000000480)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n",
		},
		{
			name: "update before completion",
			prog: prefix +
				"r5 = DisconnectEx$inet_tcp_reuse(r4, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x2, 0x0)\n" +
				"r6 = WSAGetOverlappedResult$disconnect_reuse_pending(r5, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000340), 0x0, &(0x7f0000000380)=0x0)\n" +
				"r7 = ConnectEx$inet_tcp_reuse(r6, &(0x7f00000003c0)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000400)='dx', 0x2, &(0x7f0000000440), &(0x7f0000000480)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"setsockopt$update_connect_context(r7, 0xffff, 0x7010, 0x0, 0x0)\n",
		},
		{
			name: "connectex reuse completion without update",
			prog: prefix +
				"r5 = DisconnectEx$inet_tcp_reuse(r4, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, 0x2, 0x0)\n" +
				"r6 = WSAGetOverlappedResult$disconnect_reuse_pending(r5, &(0x7f0000000180)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0}, &(0x7f0000000340), 0x0, &(0x7f0000000380)=0x0)\n" +
				"r7 = ConnectEx$inet_tcp_reuse(r6, &(0x7f00000003c0)={0x2, 0x4e2b, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10, &(0x7f0000000400)='d', 0x1, &(0x7f0000000440), &(0x7f0000000480)={0x0, 0x0, @Parts={0x0, 0x0}, 0x0})\n" +
				"r8 = CreateIoCompletionPort$connect_pending(r7, 0x0, 0xafd, 0x0)\n" +
				"GetQueuedCompletionStatus$socket(r8, &(0x7f0000000600), &(0x7f0000000640), &(0x7f0000000680), 0x0)\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := windowsPolicyTestDeserialize(t, profiled, test.prog)
			if st := prog.BuildSemanticState(p, len(p.Calls)); st.Valid() {
				t.Fatalf("bad DisconnectEx reuse chain accepted by semantic model:\n%s", p.Serialize())
			}
			if profiled.RuntimePolicy.ShouldScheduleProgram("candidate", p) {
				t.Fatalf("bad DisconnectEx reuse chain scheduled:\n%s", p.Serialize())
			}
		})
	}
}

func TestWindowsAFDConnectExUpdateContextType(t *testing.T) {
	windowsSkipLegacyAfdWinsockArchived(t)
	profiled := windowsPolicyTestAFDTarget(t)
	call := profiled.SyscallMap["setsockopt$update_connect_context"]
	if call == nil {
		t.Fatal("missing setsockopt$update_connect_context")
	}
	if call.Attrs.NoGenerate || !call.Attrs.NoMinimize {
		t.Fatal("ConnectEx update-context transition should be generatable but no_minimize")
	}
	if len(call.Args) == 0 {
		t.Fatal("setsockopt$update_connect_context has no args")
	}
	argType, ok := call.Args[0].Type.(*prog.ResourceType)
	if !ok || argType.Desc == nil || argType.Desc.Name != "SOCKET_TCP_CONNECTING" {
		t.Fatalf("update context input type=%v, want SOCKET_TCP_CONNECTING", call.Args[0].Type)
	}
	retType, ok := call.Ret.(*prog.ResourceType)
	if !ok || retType.Desc == nil || retType.Desc.Name != "SOCKET_TCP_CONNECTED" {
		t.Fatalf("update context return type=%v, want SOCKET_TCP_CONNECTED", call.Ret)
	}
}

func windowsPolicyTestAFDTarget(t *testing.T) *prog.Target {
	t.Helper()
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	profiled, err := target.ApplyTargetProfile(target, "afd")
	if err != nil {
		t.Fatalf("ApplyTargetProfile(afd): %v", err)
	}
	return profiled
}

func windowsPolicyTestDeserialize(t *testing.T, target *prog.Target, serialized string) *prog.Prog {
	t.Helper()
	p, err := target.Deserialize([]byte(serialized), prog.NonStrict)
	if err != nil {
		t.Fatalf("Deserialize: %v\ndata:\n%s", err, serialized)
	}
	return p
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

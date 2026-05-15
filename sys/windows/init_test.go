package windows_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestInitTargetMarksWindowsHelpers(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if target.ConfigureProfile == nil {
		t.Fatal("windows target did not install ConfigureProfile hook")
	}
	if !target.Helpers.DeprioritizeAutomaticHelpers {
		t.Fatal("windows target did not enable helper deprioritization")
	}
	if !target.Helpers.AvoidCollidingAutomaticHelpers {
		t.Fatal("windows target did not avoid colliding automatic helpers")
	}
	if !target.Helpers.SkipHintsForAutomaticHelpers {
		t.Fatal("windows target did not skip helper hints jobs")
	}
	if !target.Helpers.NoMutateAutomaticHelpers {
		t.Fatal("windows target did not auto-protect helper syscalls from direct mutation")
	}
	if !target.Helpers.SkipCorpusForAutomaticHelpers {
		t.Fatal("windows target did not skip helper-owned corpus persistence")
	}
	if !target.Helpers.SkipTriageForAutomaticHelpers {
		t.Fatal("windows target did not skip helper-owned triage jobs")
	}
	if !target.Helpers.AvoidAutomaticHelperBias {
		t.Fatal("windows target did not avoid helper bias during call generation")
	}
	if target.Bias.SelectGenerationBiasCall == nil {
		t.Fatal("windows target did not install generation bias selection hook")
	}
	if target.Bias.FilterBiasCalls == nil {
		t.Fatal("windows target did not install bias call filtering hook")
	}
	if target.SelectCollideCallIndices == nil {
		t.Fatal("windows target did not install collide call selection hook")
	}
	if target.SelectResourceCtor == nil {
		t.Fatal("windows target did not install resource constructor selection hook")
	}
	if target.MinimumHintsCallRelevance != 3 {
		t.Fatalf("windows target got MinimumHintsCallRelevance=%d, want 3", target.MinimumHintsCallRelevance)
	}
	if target.MinimumTriageCallRelevance != 3 {
		t.Fatalf("windows target got MinimumTriageCallRelevance=%d, want 3", target.MinimumTriageCallRelevance)
	}
	if target.MinimumCollideCallRelevance != 3 {
		t.Fatalf("windows target got MinimumCollideCallRelevance=%d, want 3", target.MinimumCollideCallRelevance)
	}
	if target.MinimumMutationCallRelevance != 3 {
		t.Fatalf("windows target got MinimumMutationCallRelevance=%d, want 3", target.MinimumMutationCallRelevance)
	}
	if target.Bias.MinimumGenerationBiasCallRelevance != 3 {
		t.Fatalf("windows target got MinimumGenerationBiasCallRelevance=%d, want 3", target.Bias.MinimumGenerationBiasCallRelevance)
	}
	for _, name := range []string{
		"CloseHandle", "CreateFileA", "CreateFile2", "VirtualAlloc",
		"WSAStartup", "WSACleanup",
		"socket$inet_tcp", "socket$inet_udp", "socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp",
		"closesocket$any",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !target.CallIsAutomaticHelper(call) {
			t.Fatalf("syscall %q is not classified as AutomaticHelper", name)
		}
	}
}

func TestWindowsConfigureProfileClonesPolicyBehavior(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	afd := target.Clone()
	if err := afd.ConfigureProfile(afd, "afd"); err != nil {
		t.Fatalf("ConfigureProfile(afd): %v", err)
	}
	fsctl := target.Clone()
	if err := fsctl.ConfigureProfile(fsctl, "fsctl"); err != nil {
		t.Fatalf("ConfigureProfile(fsctl): %v", err)
	}
	orig := target.SyscallMap["NtFsControlFile"]
	if orig == nil {
		t.Fatal("missing NtFsControlFile")
	}
	send := target.SyscallMap["send$inet_accept"]
	if send == nil {
		t.Fatal("missing send$inet_accept")
	}
	if afd.CallRelevance(orig) >= 0 {
		t.Fatalf("afd profile should suppress NtFsControlFile, got relevance %d", afd.CallRelevance(orig))
	}
	if fsctl.CallRelevance(send) >= 0 {
		t.Fatalf("fsctl profile should suppress network send path, got relevance %d", fsctl.CallRelevance(send))
	}
	if target.CallRelevance(orig) < 0 || target.CallRelevance(send) < 0 {
		t.Fatal("profile application polluted the shared default windows target")
	}
}

func TestWindowsAcceptRaceProfilePrioritizesDeepAcceptSideCalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	send := acceptRace.SyscallMap["send$inet_accept"]
	getsockopt := acceptRace.SyscallMap["getsockopt$int_accept"]
	ioctl := acceptRace.SyscallMap["ioctlsocket$fionbio_accept"]
	wsaRecv := acceptRace.SyscallMap["WSARecvEx$inet_accept"]
	transmit := acceptRace.SyscallMap["TransmitFile$inet_accept"]
	bind := acceptRace.SyscallMap["bind$inet_tcp"]
	listen := acceptRace.SyscallMap["listen$inet_tcp"]
	connect := acceptRace.SyscallMap["connect$inet_tcp"]
	if send == nil || getsockopt == nil || ioctl == nil || wsaRecv == nil ||
		transmit == nil || bind == nil || listen == nil || connect == nil {
		t.Fatal("missing accept-race profile syscalls")
	}
	if acceptRace.TriageRelevance(send) <= acceptRace.TriageRelevance(bind) {
		t.Fatalf("send$inet_accept triage score=%d, bind$inet_tcp=%d",
			acceptRace.TriageRelevance(send), acceptRace.TriageRelevance(bind))
	}
	if acceptRace.TriageRelevance(getsockopt) <= acceptRace.TriageRelevance(listen) {
		t.Fatalf("getsockopt$int_accept triage score=%d, listen$inet_tcp=%d",
			acceptRace.TriageRelevance(getsockopt), acceptRace.TriageRelevance(listen))
	}
	if acceptRace.TriageRelevance(send) <= acceptRace.TriageRelevance(connect) {
		t.Fatalf("send$inet_accept triage score=%d, connect$inet_tcp=%d",
			acceptRace.TriageRelevance(send), acceptRace.TriageRelevance(connect))
	}
	if acceptRace.TriageRelevance(wsaRecv) <= acceptRace.TriageRelevance(send) {
		t.Fatalf("WSARecvEx$inet_accept triage score=%d, send$inet_accept=%d",
			acceptRace.TriageRelevance(wsaRecv), acceptRace.TriageRelevance(send))
	}
	if acceptRace.TriageRelevance(getsockopt) <= acceptRace.TriageRelevance(send) {
		t.Fatalf("getsockopt$int_accept triage score=%d, send$inet_accept=%d",
			acceptRace.TriageRelevance(getsockopt), acceptRace.TriageRelevance(send))
	}
	if acceptRace.TriageRelevance(ioctl) <= acceptRace.TriageRelevance(send) {
		t.Fatalf("ioctlsocket$fionbio_accept triage score=%d, send$inet_accept=%d",
			acceptRace.TriageRelevance(ioctl), acceptRace.TriageRelevance(send))
	}
	if acceptRace.TriageRelevance(ioctl) <= acceptRace.TriageRelevance(getsockopt) {
		t.Fatalf("ioctlsocket$fionbio_accept triage score=%d, getsockopt$int_accept=%d",
			acceptRace.TriageRelevance(ioctl), acceptRace.TriageRelevance(getsockopt))
	}
	if acceptRace.RuntimePolicy.ShouldScheduleImmediateCollide == nil {
		t.Fatal("accept-race profile did not install immediate collide hook")
	}
	p := &prog.Prog{Target: acceptRace, Calls: []*prog.Call{{Meta: send}, {Meta: wsaRecv}, {Meta: getsockopt}, {Meta: ioctl}, {Meta: transmit}}}
	for idx := 1; idx <= 4; idx++ {
		if !acceptRace.RuntimePolicy.ShouldScheduleImmediateCollide(p, idx) {
			t.Fatalf("accept-race profile should request immediate collide for %s", p.Calls[idx].Meta.Name)
		}
	}
	if acceptRace.RuntimePolicy.ShouldScheduleImmediateCollide(p, 0) {
		t.Fatalf("accept-race profile should not request immediate collide for %s", p.Calls[0].Meta.Name)
	}
}

func TestWindowsTransmitProfilePrioritizesTransmitAcceptSideCalls(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	transmitProfile := target.Clone()
	if err := transmitProfile.ConfigureProfile(transmitProfile, "afd_transmit"); err != nil {
		t.Fatalf("ConfigureProfile(afd_transmit): %v", err)
	}
	send := transmitProfile.SyscallMap["send$inet_accept"]
	getsockopt := transmitProfile.SyscallMap["getsockopt$int_accept"]
	ioctl := transmitProfile.SyscallMap["ioctlsocket$fionbio_accept"]
	wsaRecv := transmitProfile.SyscallMap["WSARecvEx$inet_accept"]
	transmit := transmitProfile.SyscallMap["TransmitFile$inet_accept"]
	if send == nil || getsockopt == nil || ioctl == nil || wsaRecv == nil || transmit == nil {
		t.Fatal("missing transmit profile syscalls")
	}
	if transmitProfile.TriageRelevance(transmit) <= transmitProfile.TriageRelevance(send) {
		t.Fatalf("TransmitFile$inet_accept triage score=%d, send$inet_accept=%d",
			transmitProfile.TriageRelevance(transmit), transmitProfile.TriageRelevance(send))
	}
	if transmitProfile.TriageRelevance(transmit) <= transmitProfile.TriageRelevance(getsockopt) {
		t.Fatalf("TransmitFile$inet_accept triage score=%d, getsockopt$int_accept=%d",
			transmitProfile.TriageRelevance(transmit), transmitProfile.TriageRelevance(getsockopt))
	}
	if transmitProfile.TriageRelevance(transmit) <= transmitProfile.TriageRelevance(ioctl) {
		t.Fatalf("TransmitFile$inet_accept triage score=%d, ioctlsocket$fionbio_accept=%d",
			transmitProfile.TriageRelevance(transmit), transmitProfile.TriageRelevance(ioctl))
	}
	if transmitProfile.TriageRelevance(transmit) <= transmitProfile.TriageRelevance(wsaRecv) {
		t.Fatalf("TransmitFile$inet_accept triage score=%d, WSARecvEx$inet_accept=%d",
			transmitProfile.TriageRelevance(transmit), transmitProfile.TriageRelevance(wsaRecv))
	}
	if transmitProfile.TriageRelevance(ioctl) <= transmitProfile.TriageRelevance(getsockopt) {
		t.Fatalf("ioctlsocket$fionbio_accept triage score=%d, getsockopt$int_accept=%d",
			transmitProfile.TriageRelevance(ioctl), transmitProfile.TriageRelevance(getsockopt))
	}
	if transmitProfile.RuntimePolicy.ShouldPersistStableTriageCall == nil {
		t.Fatal("transmit profile did not install stable-triage persistence hook")
	}
	p := &prog.Prog{Target: transmitProfile, Calls: []*prog.Call{{Meta: transmit}}}
	if !transmitProfile.RuntimePolicy.ShouldPersistStableTriageCall("candidate", p, 0) {
		t.Fatal("transmit profile should retain stable candidate TransmitFile owners")
	}
	if transmitProfile.RuntimePolicy.ShouldPersistStableTriageCall("collide:triage", p, 0) {
		t.Fatal("transmit profile should not apply stable persistence outside candidate origin")
	}
}

func TestWindowsExpandEnabledCallsForNetworkAndFileTargets(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if target.ExpandEnabledCalls == nil {
		t.Fatal("windows target did not set ExpandEnabledCalls")
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["TransmitFile$inet_accept"]: true,
	}
	expanded := target.ExpandEnabledCalls(target, enabled)
	for _, name := range []string{
		"VirtualAlloc",
		"TransmitFile$inet_accept",
		"WSAStartup", "WSACleanup", "socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp", "closesocket$any",
		"CreateFileA", "CreateFile2", "CloseHandle",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("expanded enabled calls are missing %q", name)
		}
	}
}

func TestWindowsAcceptRaceProfileDoesNotExpandTransmitFileIntoNtFsctlPath(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	ids, err := mgrconfig.ParseEnabledSyscalls(acceptRace,
		[]string{"send$inet_accept", "recv$inet_accept", "WSARecvEx$inet_accept",
			"getsockopt$int_accept", "ioctlsocket$fionbio_accept", "TransmitFile$inet_accept"},
		nil, mgrconfig.ManualDescriptions)
	if err != nil {
		t.Fatalf("ParseEnabledSyscalls: %v", err)
	}
	enabled := make(map[*prog.Syscall]bool)
	for _, id := range ids {
		enabled[acceptRace.Syscalls[id]] = true
	}
	for _, name := range []string{"NtFsControlFile", "NtReadFile", "NtWriteFile"} {
		call := acceptRace.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if enabled[call] {
			t.Fatalf("accept-race profile unexpectedly expanded %q into focused enabled set", name)
		}
	}
	for _, name := range []string{"CreateFileA", "CreateFile2", "CloseHandle", "WriteFile", "TransmitFile$inet_accept"} {
		call := acceptRace.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !enabled[call] {
			t.Fatalf("accept-race profile did not expand required file scaffold %q", name)
		}
	}
}

func TestWindowsExpandEnabledCallsAddsAcceptScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["WSARecvEx$inet_accept"]: true,
	}
	expanded := target.ExpandEnabledCalls(target, enabled)
	for _, name := range []string{
		"VirtualAlloc",
		"WSARecvEx$inet_accept",
		"WSAStartup", "WSACleanup", "socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp", "closesocket$any",
		"bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "connect$inet_tcp",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("expanded enabled calls are missing %q", name)
		}
	}
}

func TestWindowsExpandEnabledCallsAddsPeerTrafficAndFilePayloadScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	tests := []struct {
		root string
		want []string
	}{
		{
			root: "recv$inet_tcp",
			want: []string{"send$inet_accept", "socket$listener_tcp", "listen$inet_tcp", "accept$inet_tcp"},
		},
		{
			root: "WSARecvEx$inet_accept",
			want: []string{"send$inet_tcp"},
		},
		{
			root: "recv$inet_udp",
			want: []string{"send$inet_udp"},
		},
		{
			root: "TransmitFile$inet_accept",
			want: []string{"WriteFile"},
		},
	}
	for _, test := range tests {
		expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{
			target.SyscallMap[test.root]: true,
		})
		for _, name := range append([]string{test.root}, test.want...) {
			call := target.SyscallMap[name]
			if call == nil {
				t.Fatalf("missing syscall %q", name)
			}
			if !expanded[call] {
				t.Fatalf("%s expansion is missing %q", test.root, name)
			}
		}
	}
}

func TestWindowsExpandEnabledCallsAddsTCPAndUDPConnectScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	tests := []struct {
		root string
		want []string
	}{
		{
			root: "setsockopt$int_tcp",
			want: []string{"WSAStartup", "WSACleanup", "socket$connected_tcp", "closesocket$any", "connect$inet_tcp"},
		},
		{
			root: "getsockopt$int_udp",
			want: []string{"WSAStartup", "WSACleanup", "socket$inet_udp", "closesocket$any", "connect$inet_udp"},
		},
	}
	for _, test := range tests {
		expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{
			target.SyscallMap[test.root]: true,
		})
		for _, name := range append([]string{test.root}, test.want...) {
			call := target.SyscallMap[name]
			if call == nil {
				t.Fatalf("missing syscall %q", name)
			}
			if !expanded[call] {
				t.Fatalf("%s expansion is missing %q", test.root, name)
			}
		}
	}
}

func TestWindowsExpandEnabledCallsAddsAcceptSideOptionScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	tests := []struct {
		root string
		want []string
	}{
		{
			root: "ioctlsocket$fionbio_accept",
			want: []string{
				"WSAStartup", "WSACleanup", "closesocket$any",
				"socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp",
				"bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "connect$inet_tcp",
			},
		},
		{
			root: "getsockopt$int_accept",
			want: []string{
				"WSAStartup", "WSACleanup", "closesocket$any",
				"socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp",
				"bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "connect$inet_tcp",
			},
		},
	}
	for _, test := range tests {
		expanded := target.ExpandEnabledCalls(target, map[*prog.Syscall]bool{
			target.SyscallMap[test.root]: true,
		})
		for _, name := range append([]string{test.root}, test.want...) {
			call := target.SyscallMap[name]
			if call == nil {
				t.Fatalf("missing syscall %q", name)
			}
			if !expanded[call] {
				t.Fatalf("%s expansion is missing %q", test.root, name)
			}
		}
	}
}

func TestWindowsExpandEnabledCallsAddsFileScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["FlushFileBuffers"]: true,
	}
	expanded := target.ExpandEnabledCalls(target, enabled)
	for _, name := range []string{
		"VirtualAlloc",
		"FlushFileBuffers",
		"CreateFileA", "CreateFile2", "CloseHandle",
		"NtReadFile", "NtWriteFile", "NtFsControlFile",
	} {
		call := target.SyscallMap[name]
		if call == nil {
			t.Fatalf("missing syscall %q", name)
		}
		if !expanded[call] {
			t.Fatalf("expanded enabled calls are missing %q", name)
		}
	}
}

func TestWindowsCallStageScoreOrdering(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	score := target.CallRelevanceScore
	if score == nil {
		t.Fatal("windows target did not set CallRelevanceScore")
	}
	connect := target.SyscallMap["connect$inet_tcp"]
	send := target.SyscallMap["send$inet_tcp"]
	transmit := target.SyscallMap["TransmitFile$inet_accept"]
	fsctl := target.SyscallMap["NtFsControlFile"]
	if connect == nil || send == nil || transmit == nil || fsctl == nil {
		t.Fatal("missing expected windows syscalls for score ordering test")
	}
	if !(score(connect) < score(send) && score(send) < score(transmit) && score(send) < score(fsctl)) {
		t.Fatalf("unexpected windows call stage ordering: connect=%d send=%d transmit=%d fsctl=%d",
			score(connect), score(send), score(transmit), score(fsctl))
	}
}

func TestWindowsCallStageScoreUsesResourceRoles(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	score := target.CallRelevanceScore
	if score == nil {
		t.Fatal("windows target did not set CallRelevanceScore")
	}
	listener := target.SyscallMap["listen$inet_tcp"]
	connected := target.SyscallMap["connect$inet_tcp"]
	accept := target.SyscallMap["accept$inet_tcp"]
	file := target.SyscallMap["ReadFile"]
	if listener == nil || connected == nil || accept == nil || file == nil {
		t.Fatal("missing expected windows syscalls for resource-role score test")
	}
	if !(score(listener) >= 2 && score(connected) >= 2 && score(accept) > score(connected)) {
		t.Fatalf("unexpected resource-role score ordering: listener=%d connected=%d accept=%d",
			score(listener), score(connected), score(accept))
	}
	if score(file) < 3 {
		t.Fatalf("expected file-handle consumer to get deep score, got %d", score(file))
	}
}

func TestWindowsNetworkCallPairBias(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["listen$inet_tcp"]:            true,
		target.SyscallMap["accept$inet_tcp"]:            true,
		target.SyscallMap["connect$inet_tcp"]:           true,
		target.SyscallMap["send$inet_tcp"]:              true,
		target.SyscallMap["send$inet_accept"]:           true,
		target.SyscallMap["TransmitFile$inet_accept"]:   true,
		target.SyscallMap["NtQuerySystemInformation"]:   true,
		target.SyscallMap["setsockopt$int_tcp"]:         true,
		target.SyscallMap["getsockopt$int_accept"]:      true,
		target.SyscallMap["ioctlsocket$fionbio_accept"]: true,
	}
	prios, generatable := target.CalculatePriorities(nil, enabled)
	for call := range enabled {
		if !generatable[call] {
			t.Fatalf("expected %s to remain generatable", call.Name)
		}
	}
	assertGreater := func(src, dst, other string) {
		t.Helper()
		srcCall := target.SyscallMap[src]
		dstCall := target.SyscallMap[dst]
		otherCall := target.SyscallMap[other]
		if srcCall == nil || dstCall == nil || otherCall == nil {
			t.Fatalf("missing call in bias assertion: %s %s %s", src, dst, other)
		}
		if prios[srcCall.ID][dstCall.ID] <= prios[srcCall.ID][otherCall.ID] {
			t.Fatalf("expected %s -> %s to outrank %s -> %s, got %d <= %d",
				src, dst, src, other, prios[srcCall.ID][dstCall.ID], prios[srcCall.ID][otherCall.ID])
		}
	}
	assertGreater("listen$inet_tcp", "accept$inet_tcp", "NtQuerySystemInformation")
	assertGreater("connect$inet_tcp", "send$inet_tcp", "NtQuerySystemInformation")
	assertGreater("accept$inet_tcp", "TransmitFile$inet_accept", "NtQuerySystemInformation")
	assertGreater("accept$inet_tcp", "getsockopt$int_accept", "NtQuerySystemInformation")
	assertGreater("accept$inet_tcp", "ioctlsocket$fionbio_accept", "NtQuerySystemInformation")
}

func TestWindowsSelectGenerationBiasCallPrefersDeepestScoredCall(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_tcp(r1, 'abcd', 0x4, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := target.Bias.SelectGenerationBiasCall(p, len(p.Calls))
	if idx != len(p.Calls)-1 {
		t.Fatalf("generation bias hook selected call index %d, want %d", idx, len(p.Calls)-1)
	}
	if p.Calls[idx].Meta.Name != "send$inet_tcp" {
		t.Fatalf("generation bias hook selected %q, want send$inet_tcp", p.Calls[idx].Meta.Name)
	}
}

func TestWindowsSelectGeneratedCallPrefersAcceptSessionDataPath(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["send$inet_accept"]:         true,
		target.SyscallMap["recv$inet_accept"]:         true,
		target.SyscallMap["WSARecvEx$inet_accept"]:    true,
		target.SyscallMap["TransmitFile$inet_accept"]: true,
		target.SyscallMap["getsockopt$int_accept"]:    true,
		target.SyscallMap["NtQuerySystemInformation"]: true,
	}
	ct := target.BuildChoiceTable(nil, enabled)
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'main', 0x4, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := target.Bias.SelectGeneratedCall(p, len(p.Calls), p.Calls[len(p.Calls)-1].Meta.ID, ct)
	if idx < 0 {
		t.Fatal("windows target did not select a generated call for accept session")
	}
	name := target.Syscalls[idx].Name
	switch name {
	case "recv$inet_accept":
	default:
		t.Fatalf("unexpected generated call %q for accept session, want recv$inet_accept continuation", name)
	}
}

func TestWindowsSelectGeneratedCallPrefersFileSessionOps(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["NtFsControlFile"]:          true,
		target.SyscallMap["NtWriteFile"]:              true,
		target.SyscallMap["NtReadFile"]:               true,
		target.SyscallMap["WriteFile"]:                true,
		target.SyscallMap["FlushFileBuffers"]:         true,
		target.SyscallMap["NtQuerySystemInformation"]: true,
	}
	ct := target.BuildChoiceTable(nil, enabled)
	p, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"NtFsControlFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000300)='\\x00'/128, 0x9c040, &(0x7f0000000400)='\\x00'/512, 0x200)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := target.Bias.SelectGeneratedCall(p, len(p.Calls), p.Calls[len(p.Calls)-1].Meta.ID, ct)
	if idx < 0 {
		t.Fatal("windows target did not select a generated call for file session")
	}
	name := target.Syscalls[idx].Name
	switch name {
	case "NtWriteFile", "NtReadFile":
	default:
		t.Fatalf("unexpected generated call %q for file session, want NT file continuation", name)
	}
}

func TestWindowsSelectGeneratedCallUsesTwoStepAcceptContinuation(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["recv$inet_accept"]:           true,
		target.SyscallMap["getsockopt$int_accept"]:      true,
		target.SyscallMap["ioctlsocket$fionbio_accept"]: true,
	}
	ct := target.BuildChoiceTable(nil, enabled)
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'main', 0x4, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := target.Bias.SelectGeneratedCall(p, len(p.Calls), p.Calls[len(p.Calls)-1].Meta.ID, ct)
	if idx < 0 {
		t.Fatal("windows target did not select a generated call for two-step accept session")
	}
	if got := target.Syscalls[idx].Name; got != "recv$inet_accept" {
		t.Fatalf("unexpected generated call %q, want recv$inet_accept", got)
	}
}

func TestWindowsAcceptRaceSelectGeneratedCallPrefersDeeperAcceptContinuation(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	enabled := map[*prog.Syscall]bool{
		acceptRace.SyscallMap["recv$inet_accept"]:           true,
		acceptRace.SyscallMap["WSARecvEx$inet_accept"]:      true,
		acceptRace.SyscallMap["getsockopt$int_accept"]:      true,
		acceptRace.SyscallMap["ioctlsocket$fionbio_accept"]: true,
	}
	ct := acceptRace.BuildChoiceTable(nil, enabled)
	p, err := acceptRace.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'main', 0x4, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := acceptRace.Bias.SelectGeneratedCall(p, len(p.Calls), p.Calls[len(p.Calls)-1].Meta.ID, ct)
	if idx < 0 {
		t.Fatal("accept-race target did not select a generated call for two-step accept session")
	}
	got := acceptRace.Syscalls[idx].Name
	switch got {
	case "WSARecvEx$inet_accept":
	default:
		t.Fatalf("unexpected generated call %q, want deeper accept-race continuation", got)
	}
}

func TestWindowsAcceptRaceSelectGeneratedCallPrefersDeepAcceptOptionAfterSendRecv(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	enabled := map[*prog.Syscall]bool{
		acceptRace.SyscallMap["WSARecvEx$inet_accept"]:      true,
		acceptRace.SyscallMap["getsockopt$int_accept"]:      true,
		acceptRace.SyscallMap["ioctlsocket$fionbio_accept"]: true,
	}
	ct := acceptRace.BuildChoiceTable(nil, enabled)
	p, err := acceptRace.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'main', 0x4, 0x0)\n"+
			"recv$inet_accept(r2, &(0x7f00000001a0)='\\x00'/64, 0x40, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := acceptRace.Bias.SelectGeneratedCall(p, len(p.Calls), p.Calls[len(p.Calls)-1].Meta.ID, ct)
	if idx < 0 {
		t.Fatal("accept-race target did not select a generated call for send/recv accept session")
	}
	got := acceptRace.Syscalls[idx].Name
	switch got {
	case "WSARecvEx$inet_accept", "getsockopt$int_accept", "ioctlsocket$fionbio_accept":
	default:
		t.Fatalf("unexpected generated call %q, want deep accept-side option/data continuation", got)
	}
}

func TestWindowsAcceptRaceSelectGeneratedCallExtendsWSARecvIntoAcceptOptions(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	enabled := map[*prog.Syscall]bool{
		acceptRace.SyscallMap["getsockopt$int_accept"]:      true,
		acceptRace.SyscallMap["ioctlsocket$fionbio_accept"]: true,
		acceptRace.SyscallMap["send$inet_accept"]:           true,
	}
	ct := acceptRace.BuildChoiceTable(nil, enabled)
	p, err := acceptRace.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'main', 0x4, 0x0)\n"+
			"WSARecvEx$inet_accept(r2, &(0x7f00000001a0)=0x0, 0x40, &(0x7f00000001e0)=0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := acceptRace.Bias.SelectGeneratedCall(p, len(p.Calls), p.Calls[len(p.Calls)-1].Meta.ID, ct)
	if idx < 0 {
		t.Fatal("accept-race target did not select a generated call after WSARecvEx")
	}
	got := acceptRace.Syscalls[idx].Name
	switch got {
	case "ioctlsocket$fionbio_accept":
	default:
		t.Fatalf("unexpected generated call %q, want ioctlsocket$fionbio_accept continuation after WSARecvEx", got)
	}
}

func TestWindowsAcceptRaceSelectGeneratedCallCanContinueIntoTransmitFile(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	enabled := map[*prog.Syscall]bool{
		acceptRace.SyscallMap["TransmitFile$inet_accept"]:   true,
		acceptRace.SyscallMap["getsockopt$int_accept"]:      true,
		acceptRace.SyscallMap["ioctlsocket$fionbio_accept"]: true,
	}
	ct := acceptRace.BuildChoiceTable(nil, enabled)
	p, err := acceptRace.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"WSARecvEx$inet_accept(r2, &(0x7f00000001a0)=0x0, 0x40, &(0x7f00000001e0)=0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := acceptRace.Bias.SelectGeneratedCall(p, len(p.Calls), p.Calls[len(p.Calls)-1].Meta.ID, ct)
	if idx < 0 {
		t.Fatal("accept-race target did not select a generated call after WSARecvEx")
	}
	got := acceptRace.Syscalls[idx].Name
	switch got {
	case "TransmitFile$inet_accept", "ioctlsocket$fionbio_accept", "getsockopt$int_accept":
	default:
		t.Fatalf("unexpected generated call %q, want deep accept-side continuation after WSARecvEx", got)
	}
}

func TestWindowsAcceptRaceSelectGeneratedCallExtendsTransmitFileIntoAcceptOptions(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	enabled := map[*prog.Syscall]bool{
		acceptRace.SyscallMap["getsockopt$int_accept"]:      true,
		acceptRace.SyscallMap["ioctlsocket$fionbio_accept"]: true,
		acceptRace.SyscallMap["send$inet_accept"]:           true,
	}
	ct := acceptRace.BuildChoiceTable(nil, enabled)
	p, err := acceptRace.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"r3 = CreateFileA(&(0x7f0000000200)='./nyx-txfile\\x00', 0xffffffff, 0x7, 0x0, 0x2, 0x80, 0xffffffffffffffff)\n"+
			"WriteFile(r3, &(0x7f0000000240)='abcd', 0x4, &(0x7f0000000280)=0x0, 0x0)\n"+
			"TransmitFile$inet_accept(r2, r3, 0x4, 0x0, 0x0, 0x0, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := acceptRace.Bias.SelectGeneratedCall(p, len(p.Calls), p.Calls[len(p.Calls)-1].Meta.ID, ct)
	if idx < 0 {
		t.Fatal("accept-race target did not select a generated call after TransmitFile")
	}
	got := acceptRace.Syscalls[idx].Name
	switch got {
	case "ioctlsocket$fionbio_accept", "getsockopt$int_accept", "send$inet_accept":
	default:
		t.Fatalf("unexpected generated call %q, want deep accept-side continuation after TransmitFile", got)
	}
}

func TestWindowsSelectGeneratedCallUsesTwoStepFileContinuation(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["NtFsControlFile"]:  true,
		target.SyscallMap["FlushFileBuffers"]: true,
	}
	ct := target.BuildChoiceTable(nil, enabled)
	p, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"NtFsControlFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000300)='\\x00'/128, 0x9c040, &(0x7f0000000400)='\\x00'/512, 0x200)\n"+
			"NtWriteFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000500)='abcd', 0x4, 0x0, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := target.Bias.SelectGeneratedCall(p, len(p.Calls), p.Calls[len(p.Calls)-1].Meta.ID, ct)
	if idx < 0 {
		t.Fatal("windows target did not select a generated call for two-step file session")
	}
	if got := target.Syscalls[idx].Name; got != "NtFsControlFile" {
		t.Fatalf("unexpected generated call %q, want NtFsControlFile", got)
	}
}

func TestWindowsSelectGeneratedCallUsesTwoStepUdpContinuation(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["recv$inet_udp"]:           true,
		target.SyscallMap["getsockopt$int_udp"]:      true,
		target.SyscallMap["ioctlsocket$fionbio_udp"]: true,
	}
	ct := target.BuildChoiceTable(nil, enabled)
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n"+
			"connect$inet_udp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_udp(r0, 'abcd', 0x4, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := target.Bias.SelectGeneratedCall(p, len(p.Calls), p.Calls[len(p.Calls)-1].Meta.ID, ct)
	if idx < 0 {
		t.Fatal("windows target did not select a generated call for two-step udp session")
	}
	if got := target.Syscalls[idx].Name; got != "recv$inet_udp" {
		t.Fatalf("unexpected generated call %q, want recv$inet_udp", got)
	}
}

func TestWindowsSelectGeneratedCallUsesAcceptContinuationPastHelperTail(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["recv$inet_accept"]:           true,
		target.SyscallMap["getsockopt$int_accept"]:      true,
		target.SyscallMap["ioctlsocket$fionbio_accept"]: true,
	}
	ct := target.BuildChoiceTable(nil, enabled)
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'main', 0x4, 0x0)\n"+
			"closesocket$any(r1)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := target.Bias.SelectGeneratedCall(p, len(p.Calls), p.Calls[len(p.Calls)-1].Meta.ID, ct)
	if idx < 0 {
		t.Fatal("windows target did not select a generated call past helper tail")
	}
	if got := target.Syscalls[idx].Name; got != "recv$inet_accept" {
		t.Fatalf("unexpected generated call %q, want recv$inet_accept", got)
	}
}

func TestWindowsSelectGeneratedCallUsesTcpContinuationPastHelperTail(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["recv$inet_tcp"]:           true,
		target.SyscallMap["getsockopt$int_tcp"]:      true,
		target.SyscallMap["ioctlsocket$fionbio_tcp"]: true,
	}
	ct := target.BuildChoiceTable(nil, enabled)
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_tcp(r0, 'abcd', 0x4, 0x0)\n"+
			"closesocket$any(r0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	idx := target.Bias.SelectGeneratedCall(p, len(p.Calls), p.Calls[len(p.Calls)-1].Meta.ID, ct)
	if idx < 0 {
		t.Fatal("windows target did not select a generated call past tcp helper tail")
	}
	if got := target.Syscalls[idx].Name; got != "recv$inet_tcp" {
		t.Fatalf("unexpected generated call %q, want recv$inet_tcp", got)
	}
}

func TestWindowsSelectCollideCallIndicesPrefersDeepestRaceFamily(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'abcd', 0x4, 0x0)\n"+
			"recv$inet_accept(r2, &(0x7f00000001a0)='\\x00'/64, 0x40, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := target.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("windows collide selector unexpectedly blocked deep accept-side program")
	}
	if len(indices) == 0 {
		t.Fatal("windows collide selector returned no indices")
	}
	for _, idx := range indices {
		name := p.Calls[idx].Meta.Name
		if name != "send$inet_accept" && name != "recv$inet_accept" {
			t.Fatalf("collide selector chose shallow/off-family call %q at index %d", name, idx)
		}
	}
}

func TestWindowsSelectCollideCallIndicesBlocksShallowPrograms(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"listen$inet_tcp(r0, 0x1)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize shallow program: %v", err)
	}
	indices, blocked := target.SelectCollideCallIndices(p.Calls)
	if !blocked {
		t.Fatalf("expected shallow program to be blocked, got indices=%v", indices)
	}
}

func TestWindowsSelectCollideCallIndicesPrefersSharedResourceRoot(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"r3 = socket$accept_tcp(0x2, 0x1, 0x6)\n"+
			"send$inet_accept(r3, 'side', 0x4, 0x0)\n"+
			"send$inet_accept(r2, 'main', 0x4, 0x0)\n"+
			"recv$inet_accept(r2, &(0x7f00000001a0)='\\x00'/64, 0x40, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := target.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("windows collide selector unexpectedly blocked accept-root test program")
	}
	if len(indices) == 0 {
		t.Fatal("windows collide selector returned no indices")
	}
	for _, idx := range indices {
		name := p.Calls[idx].Meta.Name
		if name != "send$inet_accept" && name != "recv$inet_accept" {
			t.Fatalf("collide selector chose off-family call %q at index %d", name, idx)
		}
		if idx == 8 {
			t.Fatalf("collide selector kept accept-side call on unrelated socket root at index %d", idx)
		}
	}
}

func TestWindowsSelectCollideCallIndicesPrefersAcceptDataPathOverSocketOptions(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"getsockopt$int_accept(r2, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"+
			"r3 = CreateFileA(&(0x7f0000000300)='./nyx-txfile\\x00', 0xffffffff, 0x7, 0x0, 0x2, 0x80, 0xffffffffffffffff)\n"+
			"WriteFile(r3, &(0x7f0000000340)='abcd', 0x4, &(0x7f0000000380)=0x0, 0x0)\n"+
			"TransmitFile$inet_accept(r2, r3, 0x4, 0x0, 0x0, 0x0, 0x0)\n"+
			"send$inet_accept(r2, 'main', 0x4, 0x0)\n"+
			"recv$inet_accept(r2, &(0x7f00000001a0)='\\x00'/64, 0x40, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := target.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("windows collide selector unexpectedly blocked accept-path priority test program")
	}
	if len(indices) == 0 {
		t.Fatal("windows collide selector returned no indices")
	}
	for _, idx := range indices {
		name := p.Calls[idx].Meta.Name
		if name != "send$inet_accept" && name != "recv$inet_accept" {
			t.Fatalf("collide selector preferred %q, want accept-side data path call", name)
		}
	}
}

func TestWindowsSelectCollideCallIndicesPrefersNtFileDataPath(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"FlushFileBuffers(r0)\n"+
			"ReadFile(r0, &(0x7f0000000100)='\\x00'/64, 0x40, &(0x7f0000000140)=0x0, 0x0)\n"+
			"NtWriteFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000200)='abcd', 0x4, 0x0, 0x0)\n"+
			"NtFsControlFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000300)='\\x00'/128, 0x9c040, &(0x7f0000000400)='\\x00'/512, 0x200)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := target.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("windows collide selector unexpectedly blocked file-path priority test program")
	}
	if len(indices) == 0 {
		t.Fatal("windows collide selector returned no indices")
	}
	for _, idx := range indices {
		name := p.Calls[idx].Meta.Name
		if name != "NtFsControlFile" && name != "NtWriteFile" {
			t.Fatalf("collide selector preferred %q, want fsctl/write file data-path on file path", name)
		}
	}
}

func TestWindowsSelectCollideCallIndicesFollowsAcceptContinuationTemplate(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'abcd', 0x4, 0x0)\n"+
			"recv$inet_accept(r2, &(0x7f00000001a0)='\\x00'/64, 0x40, 0x0)\n"+
			"getsockopt$int_accept(r2, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := target.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("windows collide selector unexpectedly blocked accept continuation template test")
	}
	if len(indices) != 2 {
		t.Fatalf("expected collide selector to focus two-call template, got %v", indices)
	}
	got := map[string]bool{}
	for _, idx := range indices {
		got[p.Calls[idx].Meta.Name] = true
	}
	if !got["send$inet_accept"] || !got["recv$inet_accept"] || got["getsockopt$int_accept"] {
		t.Fatalf("collide selector did not follow accept send/recv template, got %+v", got)
	}
}

func TestWindowsSelectCollideCallIndicesFollowsTcpContinuationTemplate(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_tcp(r0, 'abcd', 0x4, 0x0)\n"+
			"recv$inet_tcp(r0, &(0x7f00000001a0)='\\x00'/64, 0x40, 0x0)\n"+
			"getsockopt$int_tcp(r0, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := target.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("windows collide selector unexpectedly blocked tcp continuation template test")
	}
	if len(indices) != 2 {
		t.Fatalf("expected collide selector to focus tcp two-call template, got %v", indices)
	}
	got := map[string]bool{}
	for _, idx := range indices {
		got[p.Calls[idx].Meta.Name] = true
	}
	if !got["send$inet_tcp"] || !got["recv$inet_tcp"] || got["getsockopt$int_tcp"] {
		t.Fatalf("collide selector did not follow tcp send/recv template, got %+v", got)
	}
}

func TestWindowsSelectCollideCallIndicesFollowsAcceptOptionDataTemplate(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"getsockopt$int_accept(r2, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"+
			"send$inet_accept(r2, 'abcd', 0x4, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := target.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("windows collide selector unexpectedly blocked accept option/data template test")
	}
	if len(indices) != 2 {
		t.Fatalf("expected collide selector to focus accept option/data two-call template, got %v", indices)
	}
	got := map[string]bool{}
	for _, idx := range indices {
		got[p.Calls[idx].Meta.Name] = true
	}
	if !got["getsockopt$int_accept"] || !got["send$inet_accept"] {
		t.Fatalf("collide selector did not follow accept option/data template, got %+v", got)
	}
}

func TestWindowsAcceptRaceSelectCollideCallIndicesPrefersWSARecvAccept(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	p, err := acceptRace.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'abcd', 0x4, 0x0)\n"+
			"WSARecvEx$inet_accept(r2, &(0x7f00000001a0)=0x0, 0x40, &(0x7f00000001e0)=0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := acceptRace.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("accept-race collide selector unexpectedly blocked WSARecv accept program")
	}
	if len(indices) == 0 {
		t.Fatal("accept-race collide selector returned no indices")
	}
	got := map[string]bool{}
	for _, idx := range indices {
		got[p.Calls[idx].Meta.Name] = true
	}
	if !got["send$inet_accept"] || !got["WSARecvEx$inet_accept"] {
		t.Fatalf("accept-race collide selector did not follow WSARecv accept template, got %+v", got)
	}
}

func TestWindowsAcceptRaceSelectCollideCallIndicesFollowsDeepAcceptOptionTemplate(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	p, err := acceptRace.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"ioctlsocket$fionbio_accept(r2, 0x8004667e, &(0x7f0000000200)=0x1)\n"+
			"WSARecvEx$inet_accept(r2, &(0x7f00000001a0)=0x0, 0x40, &(0x7f00000001e0)=0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := acceptRace.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("accept-race collide selector unexpectedly blocked deep accept option/data test")
	}
	if len(indices) != 2 {
		t.Fatalf("expected accept-race collide selector to focus two-call deep template, got %v", indices)
	}
	got := map[string]bool{}
	for _, idx := range indices {
		got[p.Calls[idx].Meta.Name] = true
	}
	if !got["ioctlsocket$fionbio_accept"] || !got["WSARecvEx$inet_accept"] {
		t.Fatalf("accept-race collide selector did not follow deep accept option/data template, got %+v", got)
	}
}

func TestWindowsAcceptRaceSelectCollideCallIndicesFollowsWSARecvOptionTemplate(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	acceptRace := target.Clone()
	if err := acceptRace.ConfigureProfile(acceptRace, "afd_accept_race"); err != nil {
		t.Fatalf("ConfigureProfile(afd_accept_race): %v", err)
	}
	p, err := acceptRace.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"WSARecvEx$inet_accept(r2, &(0x7f00000001a0)=0x0, 0x40, &(0x7f00000001e0)=0x0)\n"+
			"getsockopt$int_accept(r2, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := acceptRace.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("accept-race collide selector unexpectedly blocked WSARecv/option test")
	}
	if len(indices) != 2 {
		t.Fatalf("expected accept-race collide selector to focus WSARecv/option template, got %v", indices)
	}
	got := map[string]bool{}
	for _, idx := range indices {
		got[p.Calls[idx].Meta.Name] = true
	}
	if !got["WSARecvEx$inet_accept"] || !got["getsockopt$int_accept"] {
		t.Fatalf("accept-race collide selector did not follow WSARecv/getsockopt template, got %+v", got)
	}
}

func TestWindowsSelectCollideCallIndicesFollowsTcpOptionDataTemplate(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"getsockopt$int_tcp(r0, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"+
			"send$inet_tcp(r0, 'abcd', 0x4, 0x0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := target.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("windows collide selector unexpectedly blocked tcp option/data template test")
	}
	if len(indices) != 2 {
		t.Fatalf("expected collide selector to focus tcp option/data two-call template, got %v", indices)
	}
	got := map[string]bool{}
	for _, idx := range indices {
		got[p.Calls[idx].Meta.Name] = true
	}
	if !got["getsockopt$int_tcp"] || !got["send$inet_tcp"] {
		t.Fatalf("collide selector did not follow tcp option/data template, got %+v", got)
	}
}

func TestWindowsSelectCollideCallIndicesFollowsUdpContinuationTemplate(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n"+
			"connect$inet_udp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_udp(r0, 'abcd', 0x4, 0x0)\n"+
			"recv$inet_udp(r0, &(0x7f00000001a0)='\\x00'/64, 0x40, 0x0)\n"+
			"getsockopt$int_udp(r0, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := target.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("windows collide selector unexpectedly blocked udp continuation template test")
	}
	if len(indices) != 2 {
		t.Fatalf("expected collide selector to focus udp two-call template, got %v", indices)
	}
	got := map[string]bool{}
	for _, idx := range indices {
		got[p.Calls[idx].Meta.Name] = true
	}
	if !got["send$inet_udp"] || !got["recv$inet_udp"] || got["getsockopt$int_udp"] {
		t.Fatalf("collide selector did not follow udp send/recv template, got %+v", got)
	}
}

func TestWindowsSelectCollideCallIndicesFollowsFsctlContinuationTemplate(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"NtFsControlFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000300)='\\x00'/128, 0x9c040, &(0x7f0000000400)='\\x00'/512, 0x200)\n"+
			"NtWriteFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000500)='abcd', 0x4, 0x0, 0x0)\n"+
			"FlushFileBuffers(r0)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize program: %v", err)
	}
	indices, blocked := target.SelectCollideCallIndices(p.Calls)
	if blocked {
		t.Fatal("windows collide selector unexpectedly blocked fsctl continuation template test")
	}
	if len(indices) != 2 {
		t.Fatalf("expected collide selector to focus fsctl two-call template, got %v", indices)
	}
	got := map[string]bool{}
	for _, idx := range indices {
		got[p.Calls[idx].Meta.Name] = true
	}
	if !got["NtFsControlFile"] || !got["NtWriteFile"] || got["FlushFileBuffers"] {
		t.Fatalf("collide selector did not follow fsctl write template, got %+v", got)
	}
}

func TestWindowsSelectGenerationBiasCallSuppressesShallowPrefixBias(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(
		"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize shallow program: %v", err)
	}
	idx := target.Bias.SelectGenerationBiasCall(p, len(p.Calls))
	if idx != prog.NoGenerationBiasCall {
		t.Fatalf("generation bias hook selected %d, want NoGenerationBiasCall", idx)
	}
}

func TestWindowsFilterBiasCallsPrefersDeeperStateTargets(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	input := []*prog.Syscall{
		target.SyscallMap["listen$inet_tcp"],
		target.SyscallMap["connect$inet_tcp"],
		target.SyscallMap["send$inet_tcp"],
		target.SyscallMap["TransmitFile$inet_accept"],
		target.SyscallMap["CreateFileA"],
	}
	filtered := target.Bias.FilterBiasCalls(input)
	if len(filtered) == 0 {
		t.Fatal("windows filter bias calls returned empty set")
	}
	for _, call := range filtered {
		if call.Name != "TransmitFile$inet_accept" {
			t.Fatalf("windows bias filter kept %q, want only deepest call", call.Name)
		}
	}
}

func TestWindowsAFDSessionSeedsParse(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("test")
	if err != nil {
		t.Fatalf("ReadDir(test): %v", err)
	}
	parsed := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) < len("nyx_afd_.txt") || name[:8] != "nyx_afd_" || filepath.Ext(name) != ".txt" {
			continue
		}
		data, err := os.ReadFile(filepath.Join("test", name))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}
		p, err := manager.ParseSeed(target, data)
		if err != nil {
			t.Fatalf("ParseSeed(%s): %v", name, err)
		}
		if p == nil || len(p.Calls) == 0 {
			t.Fatalf("ParseSeed(%s) returned empty program", name)
		}
		parsed++
	}
	if parsed == 0 {
		t.Fatal("did not find any nyx_afd_*.txt windows session seeds")
	}
}

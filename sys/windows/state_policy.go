// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package windows

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
)

const windowsTargetProfileAFD = "afd"

func applyWindowsTargetProfile(target *prog.Target, profile string) (*prog.Target, error) {
	if target == nil {
		return nil, fmt.Errorf("windows target profile %q requires a target", profile)
	}
	switch profile {
	case "", "default":
		return target, nil
	case windowsTargetProfileAFD:
		clone := target.Clone()
		windowsAFDAllowProfileGenerationPrefix(clone, "NtDeviceIoControlFile$afd_")
		windowsAFDAllowProfileGeneration(clone,
			"NtCreateFile$afd_tli_tcp_endpoint",
			"AcceptEx$inet_tcp_pending",
			"CreateIoCompletionPort$accept_pending",
			"CancelIoEx$accept_pending",
			"CancelIo$accept_pending",
			"closesocket$accept_pending",
		)
		clone.MinimumHintsCallRelevance = 4
		clone.MinimumTriageCallRelevance = 4
		clone.MinimumCollideCallRelevance = 4
		clone.MinimumMutationCallRelevance = 4
		clone.Bias.MinimumGenerationBiasCallRelevance = 3
		clone.SelectCollideCallIndices = func(calls []*prog.Call) ([]int, bool) {
			return prog.SelectResourceLineageCollideCallIndices(clone, calls)
		}
		clone.SemanticStateModel = windowsAFDSemanticStateModel
		clone.RuntimePolicy = windowsRuntimePolicy(
			prog.FocusedResourceRuntimePolicy(clone, clone.MinimumCollideCallRelevance))
		return clone, nil
	default:
		return nil, fmt.Errorf("unknown windows target profile %q", profile)
	}
}

func windowsAFDAllowProfileGenerationPrefix(target *prog.Target, prefix string) {
	for _, call := range target.Syscalls {
		if call != nil && strings.HasPrefix(call.Name, prefix) {
			windowsAFDAllowProfileGeneration(target, call.Name)
		}
	}
}

func windowsAFDAllowProfileGeneration(target *prog.Target, names ...string) {
	for _, name := range names {
		if call := target.SyscallMap[name]; call != nil {
			if target.GenerateNoGenerateCalls == nil {
				target.GenerateNoGenerateCalls = make(map[int]bool)
			}
			target.GenerateNoGenerateCalls[call.ID] = true
		}
	}
}

func configureWindowsHelpers(target *prog.Target) {
	target.Helpers.DeprioritizeAutomaticHelpers = true
	target.Helpers.NoGenerateAutomaticHelpers = true
	target.Helpers.AvoidCollidingAutomaticHelpers = true
	target.Helpers.SkipHintsForAutomaticHelpers = true
	target.Helpers.NoMutateAutomaticHelpers = true
	target.Helpers.SkipCorpusForAutomaticHelpers = true
	target.Helpers.SkipTriageForAutomaticHelpers = true
	target.Helpers.AvoidAutomaticHelperBias = true
}

func windowsCallRelevanceScore(call *prog.Syscall) int {
	return prog.ResourceDepthCallScore(nil, call)
}

func expandWindowsEnabledCalls(target *prog.Target, enabled map[*prog.Syscall]bool) map[*prog.Syscall]bool {
	expanded := prog.ExpandEnabledResourceCtors(target, enabled)
	if windowsProgramNeedsWSAStartup(expanded) {
		if startup := target.SyscallMap["WSAStartup"]; startup != nil {
			expanded[startup] = true
		}
	}
	return expanded
}

func windowsSelectGeneratedCall(p *prog.Prog, insertionPoint int, biasCall int, ct *prog.ChoiceTable) int {
	if p == nil || p.Target == nil || insertionPoint != 0 {
		return -1
	}
	startup := p.Target.SyscallMap["WSAStartup"]
	if startup == nil || !ct.Generatable(startup.ID) {
		return -1
	}
	return startup.ID
}

func windowsRuntimePolicy(base prog.RuntimePolicy) prog.RuntimePolicy {
	prev := base.ShouldScheduleProgram
	base.ShouldScheduleProgram = func(origin string, p *prog.Prog) bool {
		if !windowsHasValidWinsockStartupOrder(p) {
			return false
		}
		if !windowsHasCompatibleSocketResourceFamilies(p) {
			return false
		}
		if !windowsHasValidAFDNonblockState(p) {
			return false
		}
		st := prog.BuildSemanticState(p, len(p.Calls))
		if !st.Valid() {
			return false
		}
		if windowsSemanticHasCompletedConnectEx(st) {
			return true
		}
		if windowsSemanticHasResolvedAcceptEx(st) {
			return true
		}
		if windowsSemanticHasResolvedSendRecvPending(st) {
			return true
		}
		if prev != nil {
			return prev(origin, p)
		}
		return true
	}
	return base
}

func windowsHasValidAFDNonblockState(p *prog.Prog) bool {
	if p == nil {
		return true
	}
	for idx, call := range p.Calls {
		if call == nil || call.Meta == nil || !windowsCallNeedsUDPBoundNonblock(call.Meta.Name) {
			continue
		}
		if len(call.Args) == 0 {
			return false
		}
		sock, ok := call.Args[0].(*prog.ResultArg)
		if !ok || sock.Res == nil {
			return false
		}
		producer := prog.ResourceProducer(sock.Res, p, idx)
		if producer == nil || producer.Name != "ioctlsocket$fionbio_udp_bound" {
			return false
		}
	}
	return true
}

func windowsHasCompatibleSocketResourceFamilies(p *prog.Prog) bool {
	if p == nil {
		return true
	}
	for _, call := range p.Calls {
		if call == nil {
			continue
		}
		compatible := true
		prog.ForeachArg(call, func(arg prog.Arg, ctx *prog.ArgCtx) {
			if !compatible || arg.Dir() == prog.DirOut {
				return
			}
			res, ok := arg.(*prog.ResultArg)
			if !ok || res.Res == nil {
				return
			}
			wantType, ok := res.Type().(*prog.ResourceType)
			if !ok || wantType.Desc == nil {
				return
			}
			gotType, ok := res.Res.Type().(*prog.ResourceType)
			if !ok || gotType.Desc == nil {
				return
			}
			wantFamily := windowsSocketResourceFamily(wantType.Desc.Name)
			gotFamily := windowsSocketResourceFamily(gotType.Desc.Name)
			if wantFamily == "" || gotFamily == "" || wantFamily == gotFamily {
				return
			}
			compatible = false
			ctx.Stop = true
		})
		if !compatible {
			return false
		}
	}
	return true
}

func windowsSocketResourceFamily(name string) string {
	switch {
	case strings.HasPrefix(name, "SOCKET_TCP"),
		name == "SOCKET_LISTENER",
		name == "SOCKET_CONNECTED",
		name == "SOCKET_ACCEPT":
		return "tcp"
	case strings.HasPrefix(name, "SOCKET_UDP"):
		return "udp"
	default:
		return ""
	}
}

func windowsCallNeedsUDPBoundNonblock(name string) bool {
	switch name {
	case "recv$inet_udp_nonblock",
		"recvfrom$udp_bound_nonblock",
		"WSARecvFrom$udp_nonblock",
		"WSARecvMsg$udp_nonblock":
		return true
	default:
		return false
	}
}

func windowsProgramNeedsWSAStartup(calls map[*prog.Syscall]bool) bool {
	for call := range calls {
		if windowsCallNeedsWSAStartup(call) {
			return true
		}
	}
	return false
}

func windowsHasValidWinsockStartupOrder(p *prog.Prog) bool {
	if p == nil {
		return true
	}
	started := false
	for idx, call := range p.Calls {
		if call == nil || call.Meta == nil {
			continue
		}
		if call.Meta.Name == "WSAStartup" {
			if started || idx != 0 {
				return false
			}
			started = true
			continue
		}
		if windowsCallNeedsWSAStartup(call.Meta) && !started {
			return false
		}
	}
	return true
}

func windowsCallNeedsWSAStartup(call *prog.Syscall) bool {
	if call == nil {
		return false
	}
	switch call.Name {
	case "WSAStartup", "WSACleanup":
		return false
	}
	if strings.HasPrefix(call.Name, "WSA") || strings.HasPrefix(call.Name, "socket$") {
		return true
	}
	needsStartup := false
	prog.ForeachCallType(call, func(typ prog.Type, ctx *prog.TypeCtx) {
		res, ok := typ.(*prog.ResourceType)
		if !ok {
			return
		}
		if strings.Contains(res.Desc.Name, "SOCKET") || strings.HasPrefix(res.Desc.Name, "WSA") {
			needsStartup = true
			ctx.Stop = true
		}
	})
	return needsStartup
}

// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestResourceCtors(t *testing.T) {
	if testing.Short() && testutil.RaceEnabled {
		t.Skip("too slow")
	}
	testEachTarget(t, func(t *testing.T, target *Target) {
		for _, res := range target.Resources {
			if len(target.calcResourceCtors(res, true)) == 0 && !strings.HasPrefix(res.Name, "ANY") &&
				res.Name != "disabled_resource" {
				t.Errorf("resource %v can't be created", res.Name)
			}
		}
	})
}

func TestTransitivelyEnabledCalls(t *testing.T) {
	testEachTarget(t, func(t *testing.T, target *Target) {
		calls := make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			if c.Attrs.Disabled {
				continue
			}
			calls[c] = true
		}
		enabled, disabled := target.TransitivelyEnabledCalls(calls)
		for c, ok := range enabled {
			if !ok {
				t.Fatalf("syscalls %v is false in enabled map", c.Name)
			}
		}
		if target.OS == "test" {
			for c := range enabled {
				if c.CallName == "unsupported" {
					t.Errorf("call %v is not disabled", c.Name)
				}
			}
			for c, reason := range disabled {
				if c.CallName != "unsupported" {
					t.Errorf("call %v is disabled: %v", c.Name, reason)
				}
			}
		} else {
			if len(enabled) != len(calls) {
				t.Errorf("some calls are disabled: %v/%v", len(enabled), len(calls))
			}
			for c, reason := range disabled {
				t.Errorf("disabled %v: %v", c.Name, reason)
			}
		}
	})
}

func TestTransitivelyEnabledCallsLinux(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	calls := make(map[*Syscall]bool)
	for _, c := range target.Syscalls {
		if c.Attrs.Disabled {
			continue
		}
		calls[c] = true
	}
	delete(calls, target.SyscallMap["epoll_create"])
	if trans, disabled := target.TransitivelyEnabledCalls(calls); len(disabled) != 0 || len(trans) != len(calls) {
		t.Fatalf("still must be able to create epoll fd with epoll_create1")
	}
	delete(calls, target.SyscallMap["epoll_create1"])
	trans, disabled := target.TransitivelyEnabledCalls(calls)
	if len(calls)-8 != len(trans) ||
		trans[target.SyscallMap["epoll_ctl$EPOLL_CTL_ADD"]] ||
		trans[target.SyscallMap["epoll_ctl$EPOLL_CTL_MOD"]] ||
		trans[target.SyscallMap["epoll_ctl$EPOLL_CTL_DEL"]] ||
		trans[target.SyscallMap["epoll_wait"]] ||
		trans[target.SyscallMap["epoll_pwait"]] ||
		trans[target.SyscallMap["epoll_pwait2"]] ||
		trans[target.SyscallMap["kcmp$KCMP_EPOLL_TFD"]] ||
		trans[target.SyscallMap["syz_io_uring_submit$IORING_OP_EPOLL_CTL"]] {
		t.Fatalf("epoll fd is not disabled")
	}
	if len(disabled) != 8 {
		t.Fatalf("disabled %v syscalls, want 8", len(disabled))
	}
	for c, reason := range disabled {
		if !strings.Contains(reason, "fd_epoll [epoll_create epoll_create1]") {
			t.Fatalf("%v: wrong disable reason: %v", c.Name, reason)
		}
	}
}

func TestTransitivelyEnabledAutoCalls(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	calls := make(map[*Syscall]bool)
	for _, c := range target.Syscalls {
		if c.Attrs.Automatic || c.Attrs.AutomaticHelper {
			calls[c] = true
		}
	}
	_, disabled := target.TransitivelyEnabledCalls(calls)
	for c, reason := range disabled {
		t.Errorf("disabled call %v: %v", c.Name, reason)
	}
}

func TestGetInputResources(t *testing.T) {
	expectedRequiredResources := map[string]bool{
		"required_res1": false,
		"required_res2": false,
	}

	t.Parallel()
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}

	resources := target.getInputResources(target.SyscallMap["test$optional_res"])
	for _, resource := range resources {
		if _, ok := expectedRequiredResources[resource.Name]; ok {
			expectedRequiredResources[resource.Name] = true
		} else {
			t.Fatalf(" unexpected %v", resource.Name)
		}
	}
	for expectedRes, found := range expectedRequiredResources {
		if !found {
			t.Fatalf(" missing %v", expectedRes)
		}
	}
}

func TestClockGettime(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	calls := make(map[*Syscall]bool)
	for _, c := range target.Syscalls {
		calls[c] = true
	}
	// Removal of clock_gettime should disable all calls that accept timespec/timeval.
	delete(calls, target.SyscallMap["clock_gettime"])
	trans, disabled := target.TransitivelyEnabledCalls(calls)
	if len(trans)+10 > len(calls) || len(trans)+len(disabled) != len(calls) || len(trans) == 0 {
		t.Fatalf("clock_gettime did not disable enough calls: before %v, after %v, disabled %v",
			len(calls), len(trans), len(disabled))
	}
}

func TestCreateResourceRotation(t *testing.T) {
	target, rs, _ := initTest(t)
	allCalls := make(map[*Syscall]bool)
	for _, call := range target.Syscalls {
		allCalls[call] = true
	}
	rotator := MakeRotator(target, allCalls, rand.New(rs))
	testCreateResource(t, target, rotator.Select(), rs)
}

func TestCreateResourceHalf(t *testing.T) {
	target, rs, _ := initTest(t)
	r := rand.New(rs)
	var halfCalls map[*Syscall]bool
	for len(halfCalls) == 0 {
		halfCalls = make(map[*Syscall]bool)
		for _, call := range target.Syscalls {
			if r.Intn(10) == 0 {
				halfCalls[call] = true
			}
		}
		halfCalls, _ = target.TransitivelyEnabledCalls(halfCalls)
	}
	testCreateResource(t, target, halfCalls, rs)
}

func testCreateResource(t *testing.T, target *Target, calls map[*Syscall]bool, rs rand.Source) {
	r := newRand(target, rs)
	r.inGenerateResource = true
	ct := target.BuildChoiceTable(nil, calls)
	for call := range calls {
		if call.Attrs.Disabled {
			continue
		}
		t.Logf("testing call %v", call.Name)
		ForeachCallType(call, func(typ Type, ctx *TypeCtx) {
			if res, ok := typ.(*ResourceType); ok && ctx.Dir != DirOut {
				s := newState(target, ct, nil)
				arg, calls := r.createResource(s, res, DirIn)
				if arg == nil && !ctx.Optional {
					t.Fatalf("failed to create resource %v", res.Name())
				}
				if arg != nil && len(calls) == 0 {
					t.Fatalf("created resource %v, but got no calls", res.Name())
				}
			}
		})
	}
}

func TestPreferPreciseResources(t *testing.T) {
	target, rs, _ := initRandomTargetTest(t, "test", "64")
	r := newRand(target, rs)
	counts := map[string]int{}
	for range 2000 {
		s := newState(target, target.DefaultChoiceTable(), nil)
		calls := r.generateParticularCall(s,
			target.SyscallMap["test$consume_subtype_of_common"])
		for _, call := range calls {
			if call.Meta.Name == "test$consume_subtype_of_common" {
				continue
			}
			counts[call.Meta.Name]++
		}
	}
	assert.Greater(t, counts["test$produce_common"], 70)
	assert.Greater(t, counts["test$also_produce_common"], 70)
	assert.Greater(t, counts["test$produce_subtype_of_common"], 1000)
}

func TestWindowsResourceCentricPrefersNonHelperUsers(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	helperOnly, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./helper-only\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"CloseHandle(r0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize helper-only program: %v", err)
	}
	targeted, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"NtFsControlFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)='\\x00'/128, 0x9c040, &(0x7f0000000200)='\\x00'/512, 0x200)\n"+
			"CloseHandle(r0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize targeted program: %v", err)
	}
	meta := target.SyscallMap["NtFsControlFile"]
	if meta == nil {
		t.Fatal("NtFsControlFile is missing from windows target")
	}
	handleType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("NtFsControlFile arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	s := newState(target, target.DefaultChoiceTable(), []*Prog{helperOnly, targeted})
	arg, calls := r.resourceCentric(s, handleType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return a HANDLE resource")
	}
	found := false
	for _, call := range calls {
		if call.Meta.Name == "NtFsControlFile" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("resourceCentric selected helper-only slice, want a slice that reaches NtFsControlFile:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsResourceCentricPrefersDeeperSocketStates(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	shallow, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"closesocket$any(r1)\n"+
			"closesocket$any(r0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize shallow socket program: %v", err)
	}
	deep, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_tcp(r1, 'abcd', 0x4, 0x0)\n"+
			"closesocket$any(r1)\n"+
			"closesocket$any(r0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize deep socket program: %v", err)
	}
	meta := target.SyscallMap["send$inet_tcp"]
	if meta == nil {
		t.Fatal("send$inet_tcp is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("send$inet_tcp arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	s := newState(target, target.DefaultChoiceTable(), []*Prog{shallow, deep})
	arg, calls := r.resourceCentric(s, socketType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return a connected socket resource")
	}
	found := false
	for _, call := range calls {
		if call.Meta.Name == "send$inet_tcp" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("resourceCentric selected shallow connected-socket slice, want a slice that reaches send$inet_tcp:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsResourceCentricPrefersAcceptDataPathSlice(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	shallow, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"closesocket$any(r2)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize shallow accept program: %v", err)
	}
	deep, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'abcd', 0x4, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize deep accept program: %v", err)
	}
	meta := target.SyscallMap["recv$inet_accept"]
	if meta == nil {
		t.Fatal("recv$inet_accept is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("recv$inet_accept arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	s := newState(target, target.DefaultChoiceTable(), []*Prog{shallow, deep})
	arg, calls := r.resourceCentric(s, socketType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return an accept socket resource")
	}
	found := false
	for _, call := range calls {
		if call.Meta.Name == "send$inet_accept" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("resourceCentric selected shallow accept slice, want a slice that reaches send$inet_accept:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsResourceCentricPrefersAcceptSendRecvOverOptionOnlySlice(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	optionOnly, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"getsockopt$int_accept(r2, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize option-only accept program: %v", err)
	}
	dataPath, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'abcd', 0x4, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize data-path accept program: %v", err)
	}
	meta := target.SyscallMap["recv$inet_accept"]
	if meta == nil {
		t.Fatal("recv$inet_accept is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("recv$inet_accept arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	s := newState(target, target.DefaultChoiceTable(), []*Prog{optionOnly, dataPath})
	arg, calls := r.resourceCentric(s, socketType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return an accept socket resource")
	}
	foundSend := false
	foundOnlyOption := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "send$inet_accept":
			foundSend = true
		case "getsockopt$int_accept":
			foundOnlyOption = true
		}
	}
	if !foundSend || foundOnlyOption {
		t.Fatalf("resourceCentric did not prefer the accept data-path slice over option-only slice:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsResourceCentricPrefersAcceptOptionSliceForOptionCalls(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	optionOnly, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"getsockopt$int_accept(r2, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize option-only accept program: %v", err)
	}
	dataPath, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'abcd', 0x4, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize data-path accept program: %v", err)
	}
	meta := target.SyscallMap["getsockopt$int_accept"]
	if meta == nil {
		t.Fatal("getsockopt$int_accept is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("getsockopt$int_accept arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	s := newState(target, target.DefaultChoiceTable(), []*Prog{optionOnly, dataPath})
	arg, calls := r.resourceCentric(s, socketType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return an accept socket resource")
	}
	foundOption := false
	foundSend := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "getsockopt$int_accept":
			foundOption = true
		case "send$inet_accept":
			foundSend = true
		}
	}
	if !foundOption || foundSend {
		t.Fatalf("resourceCentric did not prefer the accept option-only slice for getsockopt:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsResourceCentricPrefersTcpSendSliceForRecvCalls(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	optionOnly, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"getsockopt$int_tcp(r0, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize option-only tcp program: %v", err)
	}
	dataPath, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_tcp(r0, 'abcd', 0x4, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize data-path tcp program: %v", err)
	}
	meta := target.SyscallMap["recv$inet_tcp"]
	if meta == nil {
		t.Fatal("recv$inet_tcp is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("recv$inet_tcp arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	s := newState(target, target.DefaultChoiceTable(), []*Prog{optionOnly, dataPath})
	arg, calls := r.resourceCentric(s, socketType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return a connected tcp resource")
	}
	foundSend := false
	foundOption := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "send$inet_tcp":
			foundSend = true
		case "getsockopt$int_tcp":
			foundOption = true
		}
	}
	if !foundSend || foundOption {
		t.Fatalf("resourceCentric did not prefer the tcp data-path slice for recv$inet_tcp:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsResourceCentricPrefersTcpOptionSliceForOptionCalls(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	optionOnly, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"getsockopt$int_tcp(r0, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize option-only tcp program: %v", err)
	}
	dataPath, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_tcp(r0, 'abcd', 0x4, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize data-path tcp program: %v", err)
	}
	meta := target.SyscallMap["getsockopt$int_tcp"]
	if meta == nil {
		t.Fatal("getsockopt$int_tcp is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("getsockopt$int_tcp arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	s := newState(target, target.DefaultChoiceTable(), []*Prog{optionOnly, dataPath})
	arg, calls := r.resourceCentric(s, socketType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return a connected tcp resource")
	}
	foundOption := false
	foundSend := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "getsockopt$int_tcp":
			foundOption = true
		case "send$inet_tcp":
			foundSend = true
		}
	}
	if !foundOption || foundSend {
		t.Fatalf("resourceCentric did not prefer the tcp option-only slice for getsockopt:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsResourceCentricPrefersUdpSendSliceForRecvCalls(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	optionOnly, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n"+
			"connect$inet_udp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"getsockopt$int_udp(r0, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize option-only udp program: %v", err)
	}
	dataPath, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n"+
			"connect$inet_udp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_udp(r0, 'abcd', 0x4, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize data-path udp program: %v", err)
	}
	meta := target.SyscallMap["recv$inet_udp"]
	if meta == nil {
		t.Fatal("recv$inet_udp is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("recv$inet_udp arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	s := newState(target, target.DefaultChoiceTable(), []*Prog{optionOnly, dataPath})
	arg, calls := r.resourceCentric(s, socketType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return a udp socket resource")
	}
	foundSend := false
	foundOption := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "send$inet_udp":
			foundSend = true
		case "getsockopt$int_udp":
			foundOption = true
		}
	}
	if !foundSend || foundOption {
		t.Fatalf("resourceCentric did not prefer the udp data-path slice for recv$inet_udp:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsResourceCentricPrefersUdpOptionSliceForOptionCalls(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	optionOnly, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n"+
			"connect$inet_udp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"getsockopt$int_udp(r0, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize option-only udp program: %v", err)
	}
	dataPath, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n"+
			"connect$inet_udp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_udp(r0, 'abcd', 0x4, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize data-path udp program: %v", err)
	}
	meta := target.SyscallMap["getsockopt$int_udp"]
	if meta == nil {
		t.Fatal("getsockopt$int_udp is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("getsockopt$int_udp arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	s := newState(target, target.DefaultChoiceTable(), []*Prog{optionOnly, dataPath})
	arg, calls := r.resourceCentric(s, socketType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return a udp socket resource")
	}
	foundOption := false
	foundSend := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "getsockopt$int_udp":
			foundOption = true
		case "send$inet_udp":
			foundSend = true
		}
	}
	if !foundOption || foundSend {
		t.Fatalf("resourceCentric did not prefer the udp option-only slice for getsockopt:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsResourceCentricFollowsAcceptContinuationTemplate(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	sendSlice, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'abcd', 0x4, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize send accept slice: %v", err)
	}
	wsaRecvSlice, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"WSARecvEx$inet_accept(r2, &(0x7f00000001a0)='\\x00'/64, 0x40, &(0x7f0000000200)=0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize WSARecvEx accept slice: %v", err)
	}
	contextProg, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'ctx', 0x3, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize context accept program: %v", err)
	}
	meta := target.SyscallMap["recv$inet_accept"]
	if meta == nil {
		t.Fatal("recv$inet_accept is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("recv$inet_accept arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	r.currentProg = contextProg
	r.currentInsertionPoint = len(contextProg.Calls)
	s := newState(target, target.DefaultChoiceTable(), []*Prog{sendSlice, wsaRecvSlice})
	arg, calls := r.resourceCentric(s, socketType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return an accept socket resource")
	}
	foundSend := false
	foundWSARecv := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "send$inet_accept":
			foundSend = true
		case "WSARecvEx$inet_accept":
			foundWSARecv = true
		}
	}
	if !foundSend || foundWSARecv {
		t.Fatalf("resourceCentric did not follow the accept send->recv continuation template:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsResourceCentricFollowsTcpContinuationTemplate(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	sendSlice, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_tcp(r0, 'abcd', 0x4, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize send tcp slice: %v", err)
	}
	optionSlice, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"getsockopt$int_tcp(r0, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize option tcp slice: %v", err)
	}
	contextProg, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_tcp(r0, 'ctx', 0x3, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize context tcp program: %v", err)
	}
	meta := target.SyscallMap["recv$inet_tcp"]
	if meta == nil {
		t.Fatal("recv$inet_tcp is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("recv$inet_tcp arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	r.currentProg = contextProg
	r.currentInsertionPoint = len(contextProg.Calls)
	s := newState(target, target.DefaultChoiceTable(), []*Prog{sendSlice, optionSlice})
	arg, calls := r.resourceCentric(s, socketType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return a connected tcp resource")
	}
	foundSend := false
	foundOption := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "send$inet_tcp":
			foundSend = true
		case "getsockopt$int_tcp":
			foundOption = true
		}
	}
	if !foundSend || foundOption {
		t.Fatalf("resourceCentric did not follow the tcp send->recv continuation template:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsResourceCentricFollowsUdpContinuationTemplate(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	sendSlice, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n"+
			"connect$inet_udp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_udp(r0, 'abcd', 0x4, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize send udp slice: %v", err)
	}
	optionSlice, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n"+
			"connect$inet_udp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"getsockopt$int_udp(r0, 0x1, 0x1, &(0x7f0000000200)=0x0, &(0x7f0000000240)=0x4)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize option udp slice: %v", err)
	}
	contextProg, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$inet_udp(0x2, 0x2, 0x11)\n"+
			"connect$inet_udp(r0, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_udp(r0, 'ctx', 0x3, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize context udp program: %v", err)
	}
	meta := target.SyscallMap["recv$inet_udp"]
	if meta == nil {
		t.Fatal("recv$inet_udp is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("recv$inet_udp arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	r.currentProg = contextProg
	r.currentInsertionPoint = len(contextProg.Calls)
	s := newState(target, target.DefaultChoiceTable(), []*Prog{sendSlice, optionSlice})
	arg, calls := r.resourceCentric(s, socketType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return a udp socket resource")
	}
	foundSend := false
	foundOption := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "send$inet_udp":
			foundSend = true
		case "getsockopt$int_udp":
			foundOption = true
		}
	}
	if !foundSend || foundOption {
		t.Fatalf("resourceCentric did not follow the udp send->recv continuation template:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsResourceCentricFollowsFsctlWriteContinuationTemplate(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	writeSlice, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-nt\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"NtWriteFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)='abcd', 0x4, 0x0, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize write file slice: %v", err)
	}
	flushSlice, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-file\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"FlushFileBuffers(r0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize flush file slice: %v", err)
	}
	contextProg, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"NtFsControlFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000300)='\\x00'/128, 0x9c040, &(0x7f0000000400)='\\x00'/512, 0x200)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize context file program: %v", err)
	}
	meta := target.SyscallMap["NtWriteFile"]
	if meta == nil {
		t.Fatal("NtWriteFile is missing from windows target")
	}
	handleType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("NtWriteFile arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	r.currentProg = contextProg
	r.currentInsertionPoint = len(contextProg.Calls)
	s := newState(target, target.DefaultChoiceTable(), []*Prog{writeSlice, flushSlice})
	arg, calls := r.resourceCentric(s, handleType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return a file handle")
	}
	foundWrite := false
	foundFlush := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "NtWriteFile":
			foundWrite = true
		case "FlushFileBuffers":
			foundFlush = true
		}
	}
	if !foundWrite || foundFlush {
		t.Fatalf("resourceCentric did not follow the fsctl->write continuation template:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsPreferResourceCentricBorrowingBeforeExistingResource(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	currentProg, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize current program: %v", err)
	}
	corpusProg, err := target.Deserialize([]byte(
		"WSAStartup(0x202, &(0x7f0000000000)=0x0)\n"+
			"r0 = socket$listener_tcp(0x2, 0x1, 0x6)\n"+
			"bind$inet_tcp(r0, &(0x7f0000000100)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"listen$inet_tcp(r0, 0x1)\n"+
			"r1 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r1, &(0x7f0000000120)={0x2, 0x4e20, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"r2 = accept$inet_tcp(r0, &(0x7f0000000140)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000180)=0x10)\n"+
			"send$inet_accept(r2, 'ctx', 0x3, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize corpus program: %v", err)
	}
	meta := target.SyscallMap["recv$inet_accept"]
	if meta == nil {
		t.Fatal("recv$inet_accept is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("recv$inet_accept arg0 has unexpected type %T", meta.Args[0].Type)
	}
	s := analyze(target.DefaultChoiceTable(), []*Prog{corpusProg}, currentProg, nil)
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	r.currentProg = currentProg
	r.currentInsertionPoint = len(currentProg.Calls)
	arg, calls := socketType.generate(r, s, DirIn)
	if arg == nil {
		t.Fatal("resource generation returned nil")
	}
	if len(calls) == 0 {
		t.Fatal("expected corpus-guided resource borrowing to insert calls before recv$inet_accept")
	}
	foundSend := false
	for _, call := range calls {
		if call.Meta.Name == "send$inet_accept" {
			foundSend = true
			break
		}
	}
	if !foundSend {
		t.Fatalf("borrowed slice did not carry the expected accept send path:\n%s",
			string((&Prog{Target: target, Calls: calls}).Serialize()))
	}
}

func TestWindowsCreateResourcePrefersSessionConstructors(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	meta := target.SyscallMap["recv$inet_accept"]
	if meta == nil {
		t.Fatal("recv$inet_accept is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("recv$inet_accept arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	ct := target.BuildChoiceTable(nil, nil)
	s := newState(target, ct, nil)
	arg, calls := socketType.generate(r, s, DirIn)
	if arg == nil {
		t.Fatal("createResource returned nil for SOCKET_ACCEPT")
	}
	foundAccept := false
	for _, call := range calls {
		if call.Meta.Name == "accept$inet_tcp" {
			foundAccept = true
			break
		}
	}
	if !foundAccept {
		t.Fatal("createResource did not choose accept$inet_tcp session constructor")
	}
}

func TestWindowsResourceCentricPrefersFsctlSliceForFsctlCalls(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	shallow, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-file\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"FlushFileBuffers(r0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize shallow file program: %v", err)
	}
	deep, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-fsctl\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"NtFsControlFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)='\\x00'/128, 0x9c040, &(0x7f0000000200)='\\x00'/512, 0x200)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize deep file program: %v", err)
	}
	meta := target.SyscallMap["NtFsControlFile"]
	if meta == nil {
		t.Fatal("NtFsControlFile is missing from windows target")
	}
	handleType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("NtFsControlFile arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	s := newState(target, target.DefaultChoiceTable(), []*Prog{shallow, deep})
	arg, calls := r.resourceCentric(s, handleType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return a file handle")
	}
	foundFsctl := false
	foundOnlyFlush := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "NtFsControlFile":
			foundFsctl = true
		case "FlushFileBuffers":
			foundOnlyFlush = true
		}
	}
	if !foundFsctl || foundOnlyFlush {
		t.Fatal("resourceCentric did not prefer the FSCTL slice for NtFsControlFile")
	}
}

func TestWindowsResourceCentricPrefersNtReadWriteSliceForNtReadFileCalls(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	shallow, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-file\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"ReadFile(r0, &(0x7f0000000100)='\\x00'/64, 0x40, &(0x7f0000000140)=0x0, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize shallow file program: %v", err)
	}
	deep, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-nt\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"NtReadFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)='\\x00'/64, 0x40, 0x0, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize deep file program: %v", err)
	}
	meta := target.SyscallMap["NtReadFile"]
	if meta == nil {
		t.Fatal("NtReadFile is missing from windows target")
	}
	handleType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("NtReadFile arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	s := newState(target, target.DefaultChoiceTable(), []*Prog{shallow, deep})
	arg, calls := r.resourceCentric(s, handleType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return a file handle")
	}
	foundNtRead := false
	foundReadFile := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "NtReadFile":
			foundNtRead = true
		case "ReadFile":
			foundReadFile = true
		}
	}
	if !foundNtRead || foundReadFile {
		t.Fatal("resourceCentric did not prefer the NT read slice for NtReadFile")
	}
}

func TestWindowsResourceCentricPrefersNtWriteSliceForNtWriteFileCalls(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	shallow, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-file\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"WriteFile(r0, &(0x7f0000000100)='abcd', 0x4, &(0x7f0000000140)=0x0, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize shallow file program: %v", err)
	}
	deep, err := target.Deserialize([]byte(
		"r0 = CreateFileA(&(0x7f0000000000)='./nyx-nt\\x00', 0xffffffff, 0x7, 0x0, 0x4, 0x80, 0xffffffffffffffff)\n"+
			"NtWriteFile(r0, 0xffffffffffffffff, 0x0, 0x0, &(0x7f0000000100)='abcd', 0x4, 0x0, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize deep file program: %v", err)
	}
	meta := target.SyscallMap["NtWriteFile"]
	if meta == nil {
		t.Fatal("NtWriteFile is missing from windows target")
	}
	handleType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("NtWriteFile arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	s := newState(target, target.DefaultChoiceTable(), []*Prog{shallow, deep})
	arg, calls := r.resourceCentric(s, handleType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric did not return a file handle")
	}
	foundNtWrite := false
	foundWriteFile := false
	for _, call := range calls {
		switch call.Meta.Name {
		case "NtWriteFile":
			foundNtWrite = true
		case "WriteFile":
			foundWriteFile = true
		}
	}
	if !foundNtWrite || foundWriteFile {
		t.Fatal("resourceCentric did not prefer the NT write slice for NtWriteFile")
	}
}


func TestWindowsExistingResourcePrefersDeeperSocketStates(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
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
			"r2 = socket$connected_tcp(0x2, 0x1, 0x6)\n"+
			"connect$inet_tcp(r2, &(0x7f0000000140)={0x2, 0x4e21, 0x7f000001, [0, 0, 0, 0, 0, 0, 0, 0]}, 0x10)\n"+
			"send$inet_tcp(r2, 'abcd', 0x4, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize socket state program: %v", err)
	}
	meta := target.SyscallMap["send$inet_tcp"]
	if meta == nil {
		t.Fatal("send$inet_tcp is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("send$inet_tcp arg0 has unexpected type %T", meta.Args[0].Type)
	}
	s := analyze(target.DefaultChoiceTable(), nil, p, nil)
	r := newRand(target, rand.NewSource(0))
	best := 0
	for range 200 {
		arg := r.existingResource(s, socketType, DirIn)
		if arg == nil {
			t.Fatal("existingResource did not return a connected socket resource")
		}
		res := arg.(*ResultArg).Res
		score := s.resourceScores[res]
		if score > best {
			best = score
		}
		if score >= 3 {
			return
		}
	}
	t.Fatalf("existingResource never preferred a deep connected socket resource, best score=%d", best)
}

func TestWindowsExistingResourcePrefersAcceptSessionRootForAcceptCalls(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
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
			"send$inet_accept(r2, 'abcd', 0x4, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize accept session program: %v", err)
	}
	meta := target.SyscallMap["recv$inet_accept"]
	if meta == nil {
		t.Fatal("recv$inet_accept is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("recv$inet_accept arg0 has unexpected type %T", meta.Args[0].Type)
	}
	s := analyze(target.DefaultChoiceTable(), nil, p, nil)
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	for range 100 {
		arg := r.existingResource(s, socketType, DirIn)
		if arg == nil {
			t.Fatal("existingResource did not return an accept socket resource")
		}
		res := arg.(*ResultArg).Res
		if res != nil && res.Type().Name() == "SOCKET_ACCEPT" {
			return
		}
	}
	t.Fatal("existingResource never preferred the accepted-socket session root for recv$inet_accept")
}

func TestWindowsExistingResourcePrefersMostRecentAcceptSessionRoot(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
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
			"send$inet_accept(r2, 'one', 0x3, 0x0)\n"+
			"r3 = accept$inet_tcp(r0, &(0x7f0000000240)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000280)=0x10)\n"+
			"send$inet_accept(r3, 'two', 0x3, 0x0)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize accept session program: %v", err)
	}
	meta := target.SyscallMap["recv$inet_accept"]
	if meta == nil {
		t.Fatal("recv$inet_accept is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("recv$inet_accept arg0 has unexpected type %T", meta.Args[0].Type)
	}
	s := analyze(target.DefaultChoiceTable(), nil, p, nil)
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	r.currentProg = p
	r.currentInsertionPoint = len(p.Calls)
	var lastAccept *ResultArg
	ForeachArg(p.Calls[len(p.Calls)-1], func(arg Arg, _ *ArgCtx) {
		if res, ok := arg.(*ResultArg); ok && res.Res != nil && res.Res.Type().Name() == "SOCKET_ACCEPT" {
			lastAccept = res.Res
		}
	})
	if lastAccept == nil {
		t.Fatal("failed to capture most recent accept-session root")
	}
	for range 100 {
		arg := r.existingResource(s, socketType, DirIn)
		if arg == nil {
			t.Fatal("existingResource did not return an accept socket resource")
		}
		if arg.(*ResultArg).Res == lastAccept {
			return
		}
	}
	t.Fatal("existingResource never preferred the most recent accept-session root")
}

func TestWindowsExistingResourcePrefersDataPathRootOverFreshShallowRoot(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("windows", "amd64")
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
			"send$inet_accept(r2, 'old', 0x3, 0x0)\n"+
			"r3 = accept$inet_tcp(r0, &(0x7f0000000240)={0x0, 0x0, 0x0, [0, 0, 0, 0, 0, 0, 0, 0]}, &(0x7f0000000280)=0x10)\n"), NonStrict)
	if err != nil {
		t.Fatalf("deserialize accept session program: %v", err)
	}
	meta := target.SyscallMap["recv$inet_accept"]
	if meta == nil {
		t.Fatal("recv$inet_accept is missing from windows target")
	}
	socketType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("recv$inet_accept arg0 has unexpected type %T", meta.Args[0].Type)
	}
	s := analyze(target.DefaultChoiceTable(), nil, p, nil)
	r := newRand(target, rand.NewSource(0))
	r.currentMeta = meta
	r.currentProg = p
	r.currentInsertionPoint = len(p.Calls)
	var oldAccept, freshAccept *ResultArg
	ForeachArg(p.Calls[7], func(arg Arg, _ *ArgCtx) {
		if res, ok := arg.(*ResultArg); ok && res.Res != nil && res.Res.Type().Name() == "SOCKET_ACCEPT" {
			oldAccept = res.Res
		}
	})
	ForeachArg(p.Calls[8], func(arg Arg, _ *ArgCtx) {
		if res, ok := arg.(*ResultArg); ok && res.Dir() == DirOut && res.Type().Name() == "SOCKET_ACCEPT" {
			freshAccept = res
		}
	})
	if oldAccept == nil || freshAccept == nil {
		t.Fatal("failed to capture old/fresh accept roots")
	}
	for range 100 {
		arg := r.existingResource(s, socketType, DirIn)
		if arg == nil {
			t.Fatal("existingResource did not return an accept socket resource")
		}
		switch arg.(*ResultArg).Res {
		case oldAccept:
			return
		case freshAccept:
			t.Fatal("existingResource preferred fresh shallow accept root over old data-path root")
		}
	}
	t.Fatal("existingResource never preferred the established accept data-path root")
}

func TestResourceCentricUsesCorpusResourceScoreHook(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	clone := *target
	prog1, err := clone.Deserialize([]byte(
		"r0 = test$produce_common()\n"+
			"test$consume_common(r0)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	prog2, err := clone.Deserialize([]byte(
		"r0 = test$also_produce_common()\n"+
			"test$consume_common(r0)\n"), Strict)
	if err != nil {
		t.Fatal(err)
	}
	var preferred *ResultArg
	ForeachArg(prog2.Calls[0], func(arg Arg, _ *ArgCtx) {
		if res, ok := arg.(*ResultArg); ok && res.Dir() == DirOut {
			preferred = res
		}
	})
	if preferred == nil {
		t.Fatal("failed to capture preferred corpus resource root")
	}
	clone.CorpusResourceScore = func(current *Syscall, candidate *ResultArg, _ *Prog, _ int, _ *Prog) int {
		if current != nil && current.Name == "test$consume_common" && candidate == preferred {
			return 10
		}
		return 0
	}
	meta := clone.SyscallMap["test$consume_common"]
	if meta == nil {
		t.Fatal("test$consume_common is missing")
	}
	resType, ok := meta.Args[0].Type.(*ResourceType)
	if !ok {
		t.Fatalf("test$consume_common arg0 has unexpected type %T", meta.Args[0].Type)
	}
	r := newRand(&clone, rand.NewSource(0))
	r.currentMeta = meta
	s := newState(&clone, clone.DefaultChoiceTable(), []*Prog{prog1, prog2})
	arg, calls := r.resourceCentric(s, resType, DirIn)
	if arg == nil {
		t.Fatal("resourceCentric returned nil")
	}
	foundPreferredProducer := false
	for _, call := range calls {
		if call.Meta.Name == "test$also_produce_common" {
			foundPreferredProducer = true
		}
	}
	if !foundPreferredProducer {
		t.Fatalf("resourceCentric did not follow CorpusResourceScore hook:\n%s",
			string((&Prog{Target: &clone, Calls: calls}).Serialize()))
	}
}

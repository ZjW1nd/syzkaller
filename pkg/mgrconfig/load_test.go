// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"testing"
	"time"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEnabledSyscalls(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	tests := []struct {
		name   string
		mode   DescriptionsMode
		enable []string
		// TODO: add disable tests as well.
		expectEnabled  []string
		expectDisabled []string
	}{
		{
			name:           "wildcard, no snapshot",
			mode:           ManualDescriptions,
			enable:         []string{"test"},
			expectDisabled: []string{"test$snapshot_only"},
		},
		{
			name:          "wildcard, snapshot",
			mode:          ManualDescriptions | SnapshotDescriptions,
			enable:        []string{"test"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:          "no wildcard, no snapshot",
			mode:          ManualDescriptions,
			enable:        []string{"test$snapshot_only"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:          "no wildcard, snapshot",
			mode:          ManualDescriptions | SnapshotDescriptions,
			enable:        []string{"test$snapshot_only"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:   "automatic allowed",
			mode:   ManualDescriptions | AutoDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic",
				"test$automatic_helper",
				"test$manual",
			},
		},
		{
			name:   "manual only",
			mode:   ManualDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic_helper",
				"test$manual",
			},
			expectDisabled: []string{
				"test$automatic",
			},
		},
		{
			name:   "auto only",
			mode:   AutoDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic",
				"test$automatic_helper",
			},
			expectDisabled: []string{
				"test$manual",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ids, err := ParseEnabledSyscalls(target, test.enable,
				nil, test.mode)
			require.NoError(t, err)
			for _, enabled := range test.expectEnabled {
				assert.Contains(t, ids, target.SyscallMap[enabled].ID)
			}
			for _, disabled := range test.expectDisabled {
				assert.NotContains(t, ids, target.SyscallMap[disabled].ID)
			}
		})
	}
}

func TestParseEnabledSyscallsExpandsWindowsHelpers(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	require.NoError(t, err)

	ids, err := ParseEnabledSyscalls(target,
		[]string{"NtDeviceIoControlFile$afd_transmit_file_accept_nonblock"}, nil, ManualDescriptions)
	require.NoError(t, err)

	want := []string{
		"NtDeviceIoControlFile$afd_transmit_file_accept_nonblock",
		"NtCreateFile$afd_tcp_endpoint",
		"NtDeviceIoControlFile$afd_bind_tcp",
		"NtDeviceIoControlFile$afd_start_listen_tcp",
		"NtDeviceIoControlFile$afd_connect_tcp_to_listener",
		"NtDeviceIoControlFile$afd_wait_for_listen_tcp",
		"NtDeviceIoControlFile$afd_accept_tcp",
		"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_accepted",
		"CreateFileA$afd_transmit",
	}
	for _, name := range want {
		assert.Contains(t, ids, target.SyscallMap[name].ID, "expected %s to be auto-enabled", name)
	}
}

func TestParseEnabledSyscallsDisabledOverridesExpansion(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	require.NoError(t, err)

	ids, err := ParseEnabledSyscalls(target,
		[]string{"NtDeviceIoControlFile$afd_transmit_file_accept_nonblock"},
		[]string{"CreateFileA$afd_transmit", "NtCreateFile$afd_tcp_endpoint"},
		ManualDescriptions)
	require.NoError(t, err)

	assert.NotContains(t, ids, target.SyscallMap["CreateFileA$afd_transmit"].ID)
	assert.NotContains(t, ids, target.SyscallMap["NtCreateFile$afd_tcp_endpoint"].ID)
	assert.Contains(t, ids, target.SyscallMap["NtDeviceIoControlFile$afd_transmit_file_accept_nonblock"].ID)
}

func TestParseEnabledSyscallsExpandsWindowsAcceptAndUDPScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	require.NoError(t, err)

	ids, err := ParseEnabledSyscalls(target,
		[]string{"NtDeviceIoControlFile$afd_receive_accept_nonblock", "NtDeviceIoControlFile$afd_send_udp_peer_nonblock"},
		nil, ManualDescriptions)
	require.NoError(t, err)

	want := []string{
		"NtDeviceIoControlFile$afd_receive_accept_nonblock",
		"NtDeviceIoControlFile$afd_send_udp_peer_nonblock",
		"NtCreateFile$afd_tcp_endpoint",
		"NtDeviceIoControlFile$afd_bind_tcp",
		"NtDeviceIoControlFile$afd_start_listen_tcp",
		"NtDeviceIoControlFile$afd_connect_tcp_to_listener",
		"NtDeviceIoControlFile$afd_wait_for_listen_tcp",
		"NtDeviceIoControlFile$afd_accept_tcp",
		"NtDeviceIoControlFile$afd_set_information_nonblock_tcp_accepted",
		"NtCreateFile$afd_udp_endpoint",
		"NtDeviceIoControlFile$afd_bind_udp",
		"NtDeviceIoControlFile$afd_set_information_nonblock_udp_bound",
		"NtDeviceIoControlFile$afd_connect_udp_nonblock",
	}
	for _, name := range want {
		assert.Contains(t, ids, target.SyscallMap[name].ID, "expected %s to be auto-enabled", name)
	}
}

func TestParseEnabledSyscallsExpandsWindowsAfdFocusedTargets(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	require.NoError(t, err)

	ids, err := ParseEnabledSyscalls(target,
		[]string{"NtDeviceIoControlFile$afd_transmit_file_accept_nonblock"},
		nil, ManualDescriptions)
	require.NoError(t, err)

	want := []string{
		"NtDeviceIoControlFile$afd_transmit_file_accept_nonblock",
		"NtCreateFile$afd_tcp_endpoint",
		"NtDeviceIoControlFile$afd_bind_tcp",
		"NtDeviceIoControlFile$afd_start_listen_tcp",
		"NtDeviceIoControlFile$afd_connect_tcp_to_listener",
		"NtDeviceIoControlFile$afd_wait_for_listen_tcp",
		"NtDeviceIoControlFile$afd_accept_tcp",
		"CreateFileA$afd_transmit",
	}
	for _, name := range want {
		assert.Contains(t, ids, target.SyscallMap[name].ID, "expected %s to be auto-enabled", name)
	}
}

func TestParseEnabledSyscallsExpandsWindowsFsctlFocusedTargets(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	require.NoError(t, err)

	ids, err := ParseEnabledSyscalls(target,
		[]string{"NtFsControlFile"},
		nil, ManualDescriptions)
	require.NoError(t, err)

	want := []string{
		"NtFsControlFile",
		"CreateFileA",
	}
	for _, name := range want {
		assert.Contains(t, ids, target.SyscallMap[name].ID, "expected %s to be auto-enabled", name)
	}
}

func TestSetTargetsUsesSharedWindowsTarget(t *testing.T) {
	cfg := DefaultValues()
	cfg.RawTarget = "windows/amd64"
	cfg.Workdir = t.TempDir()
	cfg.Syzkaller = "."
	cfg.Type = "none"

	err := SetTargets(cfg)
	require.NoError(t, err)
	require.NotNil(t, cfg.Target)

	global, err := prog.GetTarget("windows", "amd64")
	require.NoError(t, err)
	require.Same(t, global, cfg.Target)
}

func TestExperimentalForceGenerateEveryNIsPreserved(t *testing.T) {
	cfg := DefaultValues()
	cfg.RawTarget = "windows/amd64"
	cfg.Workdir = t.TempDir()
	cfg.Syzkaller = "."
	cfg.Type = "none"
	cfg.Experimental.ForceGenerateEveryN = 3

	err := SetTargets(cfg)
	require.NoError(t, err)
	assert.Equal(t, 3, cfg.Experimental.ForceGenerateEveryN)
}

func TestExperimentalNoGenerateSyscallsAreValidated(t *testing.T) {
	cfg := DefaultValues()
	cfg.RawTarget = "windows/amd64"
	cfg.Workdir = t.TempDir()
	cfg.Syzkaller = "."
	cfg.Type = "none"
	cfg.Experimental.NoGenerateSyscalls = []string{
		"NtDeviceIoControlFile$afd_receive_datagram_udp_bound_nonblock",
		"NtDeviceIoControlFile$afd_accept_tcp_nonblock",
	}

	require.NoError(t, SetTargets(cfg))
	noGenerate, err := ParseNoGenerateSyscalls(cfg.Target, cfg.Experimental.NoGenerateSyscalls)
	require.NoError(t, err)
	assert.True(t, noGenerate[cfg.Target.SyscallMap["NtDeviceIoControlFile$afd_receive_datagram_udp_bound_nonblock"].ID])
	assert.True(t, noGenerate[cfg.Target.SyscallMap["NtDeviceIoControlFile$afd_accept_tcp_nonblock"].ID])

	cfg = DefaultValues()
	cfg.RawTarget = "windows/amd64"
	cfg.Workdir = t.TempDir()
	cfg.Syzkaller = "."
	cfg.Type = "none"
	cfg.Experimental.NoGenerateSyscalls = []string{"DefinitelyMissingSyscall"}
	require.NoError(t, SetTargets(cfg))
	_, err = ParseNoGenerateSyscalls(cfg.Target, cfg.Experimental.NoGenerateSyscalls)
	require.ErrorContains(t, err, "unknown no_generate syscall")
}

func TestExperimentalCorpusFuzzWeightRulesAreValidated(t *testing.T) {
	makeConfig := func() *Config {
		cfg := DefaultValues()
		cfg.RawTarget = "windows/amd64"
		cfg.Workdir = t.TempDir()
		cfg.Syzkaller = "."
		cfg.Type = "none"
		return cfg
	}

	cfg := makeConfig()
	cfg.Experimental.CorpusFuzzWeightRules = []CorpusFuzzWeightRule{
		{
			Calls:  []string{"WSAStartup", "AcceptEx*"},
			Weight: 0.25,
		},
	}
	require.NoError(t, SetTargets(cfg))
	require.NoError(t, cfg.completeCorpusFuzzWeightRules())

	cfg = makeConfig()
	cfg.Experimental.CorpusFuzzWeightRules = []CorpusFuzzWeightRule{{Calls: []string{"WSAStartup"}, Weight: -0.1}}
	require.NoError(t, SetTargets(cfg))
	require.ErrorContains(t, cfg.completeCorpusFuzzWeightRules(), "weight must be non-negative")

	cfg = makeConfig()
	cfg.Experimental.CorpusFuzzWeightRules = []CorpusFuzzWeightRule{{Weight: 0.25}}
	require.NoError(t, SetTargets(cfg))
	require.ErrorContains(t, cfg.completeCorpusFuzzWeightRules(), "calls must not be empty")

	cfg = makeConfig()
	cfg.Experimental.CorpusFuzzWeightRules = []CorpusFuzzWeightRule{
		{
			Calls:  []string{"DefinitelyMissingSyscall"},
			Weight: 0.25,
		},
	}
	require.NoError(t, SetTargets(cfg))
	require.ErrorContains(t, cfg.completeCorpusFuzzWeightRules(), "unknown syscall pattern")
}

func TestLoadDataAppliesWindowsAFDTargetProfile(t *testing.T) {
	data := []byte(`{
		"name": "windows-afd-profile",
		"target": "windows/amd64",
		"http": "127.0.0.1:0",
		"workdir": "` + t.TempDir() + `",
		"syzkaller": ".",
		"type": "none",
		"reproduce": false,
		"execprog_bin_on_target": "C:\\syzkaller\\syz-execprog.exe",
		"executor_bin_on_target": "C:\\syzkaller\\syz-executor.exe",
		"experimental": {
			"windows_target_profile": "afd"
		}
	}`)
	cfg, err := LoadData(data)
	require.NoError(t, err)
	require.NotNil(t, cfg.Target)
	assert.Equal(t, 4, cfg.Target.MinimumTriageCallRelevance)
	assert.Equal(t, 4, cfg.Target.MinimumCollideCallRelevance)
	require.NotNil(t, cfg.Target.RuntimePolicy.ShouldScheduleImmediateCollide)

	global, err := prog.GetTarget("windows", "amd64")
	require.NoError(t, err)
	require.NotSame(t, global, cfg.Target)
	assert.Equal(t, 0, global.MinimumTriageCallRelevance)
	assert.Equal(t, 0, global.MinimumCollideCallRelevance)
}

func TestLoadDataRejectsUnknownWindowsTargetProfile(t *testing.T) {
	data := []byte(`{
		"name": "windows-bad-profile",
		"target": "windows/amd64",
		"http": "127.0.0.1:0",
		"workdir": "` + t.TempDir() + `",
		"syzkaller": ".",
		"type": "none",
		"reproduce": false,
		"execprog_bin_on_target": "C:\\syzkaller\\syz-execprog.exe",
		"executor_bin_on_target": "C:\\syzkaller\\syz-executor.exe",
		"experimental": {
			"windows_target_profile": "missing"
		}
	}`)
	_, err := LoadData(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown windows target profile")
}

func TestLoadDataOverridesVMRunningTime(t *testing.T) {
	data := []byte(`{
		"name": "windows-timeout-override",
		"target": "windows/amd64",
		"http": "127.0.0.1:0",
		"workdir": "` + t.TempDir() + `",
		"syzkaller": ".",
		"type": "none",
		"reproduce": false,
		"vm_running_time": "720h",
		"execprog_bin_on_target": "C:\\syzkaller\\syz-execprog.exe",
		"executor_bin_on_target": "C:\\syzkaller\\syz-executor.exe"
	}`)
	cfg, err := LoadData(data)
	require.NoError(t, err)
	assert.Equal(t, 720*time.Hour, cfg.Timeouts.VMRunningTime)
}

func TestLoadDataRejectsBadVMRunningTime(t *testing.T) {
	data := []byte(`{
		"name": "windows-timeout-override",
		"target": "windows/amd64",
		"http": "127.0.0.1:0",
		"workdir": "` + t.TempDir() + `",
		"syzkaller": ".",
		"type": "none",
		"reproduce": false,
		"vm_running_time": "0s",
		"execprog_bin_on_target": "C:\\syzkaller\\syz-execprog.exe",
		"executor_bin_on_target": "C:\\syzkaller\\syz-executor.exe"
	}`)
	_, err := LoadData(data)
	require.ErrorContains(t, err, "vm_running_time")
}

func TestLoadWindowsNyxAFDPrivateConfig(t *testing.T) {
	cfg, err := LoadFile("../../tools/syz-nyx-runner/windows-nyx-afd-private.cfg")
	require.NoError(t, err)
	assert.Equal(t, 720*time.Hour, cfg.Timeouts.VMRunningTime)
	assert.True(t, cfg.Experimental.DisableCollide)
	require.NotEmpty(t, cfg.Experimental.NoGenerateSyscalls)
	require.NotEmpty(t, cfg.NoGenerateCalls)
	require.NotEmpty(t, cfg.Experimental.CorpusFuzzWeightRules)
	for _, rule := range cfg.Experimental.CorpusFuzzWeightRules {
		assert.Zero(t, rule.Weight)
	}
}

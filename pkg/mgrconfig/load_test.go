// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"testing"

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

	ids, err := ParseEnabledSyscalls(target, []string{"TransmitFile$inet_accept"}, nil, ManualDescriptions)
	require.NoError(t, err)

	want := []string{
		"VirtualAlloc",
		"TransmitFile$inet_accept",
		"WSAStartup",
		"WSACleanup",
		"socket$listener_tcp",
		"socket$connected_tcp",
		"socket$accept_tcp",
		"bind$inet_tcp",
		"listen$inet_tcp",
		"accept$inet_tcp",
		"connect$inet_tcp",
		"closesocket$any",
		"CreateFileA",
		"CreateFile2",
		"CloseHandle",
		"WriteFile",
	}
	for _, name := range want {
		assert.Contains(t, ids, target.SyscallMap[name].ID, "expected %s to be auto-enabled", name)
	}
}

func TestParseEnabledSyscallsDisabledOverridesExpansion(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	require.NoError(t, err)

	ids, err := ParseEnabledSyscalls(target,
		[]string{"TransmitFile$inet_accept"},
		[]string{"CreateFileA", "WSAStartup"},
		ManualDescriptions)
	require.NoError(t, err)

	assert.NotContains(t, ids, target.SyscallMap["CreateFileA"].ID)
	assert.NotContains(t, ids, target.SyscallMap["WSAStartup"].ID)
	assert.Contains(t, ids, target.SyscallMap["TransmitFile$inet_accept"].ID)
}

func TestParseEnabledSyscallsExpandsWindowsAcceptAndUDPScaffold(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	require.NoError(t, err)

	ids, err := ParseEnabledSyscalls(target,
		[]string{"WSARecvEx$inet_accept", "send$inet_udp"},
		nil, ManualDescriptions)
	require.NoError(t, err)

	want := []string{
		"WSARecvEx$inet_accept",
		"send$inet_udp",
		"WSAStartup", "WSACleanup", "closesocket$any",
		"socket$listener_tcp", "socket$connected_tcp", "socket$accept_tcp",
		"bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "connect$inet_tcp",
		"send$inet_tcp",
		"socket$inet_udp", "connect$inet_udp",
	}
	for _, name := range want {
		assert.Contains(t, ids, target.SyscallMap[name].ID, "expected %s to be auto-enabled", name)
	}
}

func TestParseEnabledSyscallsExpandsWindowsAfdFocusedTargets(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	require.NoError(t, err)

	ids, err := ParseEnabledSyscalls(target,
		[]string{"TransmitFile$inet_accept"},
		nil, ManualDescriptions)
	require.NoError(t, err)

	want := []string{
		"WSAStartup", "WSACleanup", "closesocket$any",
		"socket$listener_tcp",
		"socket$connected_tcp",
		"socket$accept_tcp",
		"bind$inet_tcp", "listen$inet_tcp", "accept$inet_tcp", "connect$inet_tcp",
		"CreateFileA", "CreateFile2", "CloseHandle", "WriteFile",
		"TransmitFile$inet_accept",
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
		"VirtualAlloc",
		"NtFsControlFile",
		"CreateFileA", "CreateFile2", "CloseHandle",
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

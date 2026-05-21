// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsMinidumpPath(t *testing.T) {
	rep := &report.Report{Report: []byte("header\r\n dump file: /tmp/crash.dmp\r\nfooter\r\n")}

	assert.Equal(t, "/tmp/crash.dmp", windowsMinidumpPath(rep))
}

func TestCopyWindowsMinidump(t *testing.T) {
	source := filepath.Join(t.TempDir(), "crash.dmp")
	require.NoError(t, os.WriteFile(source, []byte("MINIDUMP"), 0o644))

	copyPath, err := copyWindowsMinidump(source)
	require.NoError(t, err)
	defer os.Remove(copyPath)

	assert.Equal(t, ".dmp", filepath.Ext(copyPath))
	data, err := os.ReadFile(copyPath)
	require.NoError(t, err)
	assert.Equal(t, []byte("MINIDUMP"), data)
}

func TestShouldCollectWindowsMinidump(t *testing.T) {
	mgr := &Manager{
		cfg:       &mgrconfig.Config{},
		sysTarget: targets.Get(targets.Windows, targets.AMD64),
	}
	rep := &report.Report{Report: []byte("SYZ-NYX-WINDOWS-CRASH: WINDOWS BUGCHECK\n" +
		"dump file: /tmp/crash.dmp\n")}

	assert.True(t, mgr.shouldCollectMemoryDump(rep))
}

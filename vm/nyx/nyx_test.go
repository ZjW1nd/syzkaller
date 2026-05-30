// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package nyx

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/syzkaller/vm/vmimpl"
)

func TestManagerEndpoint(t *testing.T) {
	inst := &instance{
		pool: &Pool{cfg: &Config{Host: "127.0.0.1"}},
	}
	host, port, err := inst.managerEndpoint("syz-executor runner 3 10.0.2.2 50001")
	if err != nil {
		t.Fatalf("managerEndpoint failed: %v", err)
	}
	if host != "10.0.2.2" || port != "50001" {
		t.Fatalf("bad endpoint: host=%q port=%q", host, port)
	}

	inst.forwardPort = 50002
	host, port, err = inst.managerEndpoint("unexpected command")
	if err != nil {
		t.Fatalf("managerEndpoint fallback failed: %v", err)
	}
	if host != "127.0.0.1" || port != "50002" {
		t.Fatalf("bad fallback endpoint: host=%q port=%q", host, port)
	}
}

func TestRunnerArgs(t *testing.T) {
	inst := &instance{
		pool: &Pool{
			env: &vmimpl.Env{
				Workdir: "/mgr/work",
				Debug:   true,
			},
			cfg: &Config{
				Runner:                 "/bin/syz-nyx-runner",
				Qemu:                   "/bin/qemu-system-x86_64",
				Workdir:                "/nyx/{{INDEX}}",
				Image:                  "/images/{{INDEX}}.qcow2",
				Memory:                 4096,
				PayloadSize:            4 << 20,
				BitmapSize:             1 << 20,
				HardTimeout:            "5m",
				ModuleRanges:           "ntoskrnl.exe:required,afd.sys",
				QemuArgs:               []string{"-serial", "file:{{WORKDIR}}/serial.log"},
				WindowsMinidump:        true,
				WindowsMinidumpTimeout: 90,
			},
		},
		index:   2,
		workdir: "/inst/work",
	}

	args, err := inst.runnerArgs("10.0.2.2", "50001")
	if err != nil {
		t.Fatalf("runnerArgs failed: %v", err)
	}
	want := []string{
		"2", "10.0.2.2", "50001",
		"--workdir", "/nyx/2",
		"--qemu-path", "/bin/qemu-system-x86_64",
		"--image", "/images/2.qcow2",
		"--memory", "4096",
		"--payload-size", "4194304",
		"--bitmap-size", "1048576",
		"--hard-timeout", "5m",
		"--module-ranges", "ntoskrnl.exe:required,afd.sys",
		"--debug",
		"--windows-minidump",
		"--windows-minidump-timeout", "90",
		"--qemu-arg", "-serial",
		"--qemu-arg", "file:/inst/work/serial.log",
	}
	if !slices.Equal(args, want) {
		t.Fatalf("bad args:\n got: %s\nwant: %s", strings.Join(args, " "), strings.Join(want, " "))
	}
}

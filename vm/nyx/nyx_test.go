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
				KeepState:              true,
				SlowTraceDir:           "/logs/{{INDEX}}/slow",
				SlowTraceThresholdMS:   1234,
				SlowTraceMaxEvents:     5678,
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
		"--keep-state",
		"--slow-trace-dir", "/logs/2/slow",
		"--slow-trace-threshold-ms", "1234",
		"--slow-trace-max-events", "5678",
		"--qemu-arg", "-serial",
		"--qemu-arg", "file:/inst/work/serial.log",
	}
	if !slices.Equal(args, want) {
		t.Fatalf("bad args:\n got: %s\nwant: %s", strings.Join(args, " "), strings.Join(want, " "))
	}
}

func TestStandaloneRunnerArgsFromExecprogCommand(t *testing.T) {
	inst := &instance{
		pool: &Pool{
			env: &vmimpl.Env{
				Workdir: "/mgr/work",
			},
			cfg: &Config{
				Qemu:                    "/bin/qemu-system-x86_64",
				Workdir:                 "/nyx/{{INDEX}}",
				ModuleRanges:            "afd.sys:required",
				StandaloneTargetProfile: "afd",
			},
		},
		index:   5,
		workdir: "/inst/work",
	}

	args, err := inst.runnerArgsForCommand("/host/syz-execprog.exe -executor=C:\\syzkaller\\syz-executor.exe -arch=amd64 -sandbox=none -procs=1 -repeat=0 -threaded=false -collide=false /tmp/repro.syz")
	if err != nil {
		t.Fatalf("runnerArgsForCommand failed: %v", err)
	}
	want := []string{
		"5",
		"--standalone",
		"--standalone-program", "/tmp/repro.syz",
		"--standalone-threaded=false",
		"--standalone-keep-state=false",
		"--standalone-fixed-repeat",
		"--standalone-rounds", "0",
		"--standalone-no-cover",
		"--standalone-target-profile", "afd",
		"--workdir", "/nyx/5",
		"--qemu-path", "/bin/qemu-system-x86_64",
		"--module-ranges", "afd.sys:required",
	}
	if !slices.Equal(args, want) {
		t.Fatalf("bad standalone args:\n got: %s\nwant: %s", strings.Join(args, " "), strings.Join(want, " "))
	}
}

func TestParseExecprogCommand(t *testing.T) {
	cmd, err := parseExecprogCommand("strace -f /bin/syz-execprog -executor=/bin/syz-executor -threaded=true -cover=1 -repeat=3 /tmp/prog")
	if err != nil {
		t.Fatalf("parseExecprogCommand failed: %v", err)
	}
	if cmd.program != "/tmp/prog" || !cmd.threaded || !cmd.collectCover || cmd.repeat != 3 {
		t.Fatalf("bad parsed command: %+v", cmd)
	}
}

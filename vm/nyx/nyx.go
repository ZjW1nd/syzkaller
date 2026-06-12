// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package nyx runs qemu-nyx through syz-nyx-runner as a syzkaller VM backend.
package nyx

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	var _ vmimpl.Infoer = (*instance)(nil)
	vmimpl.Register("nyx", vmimpl.Type{
		Ctor:       ctor,
		Overcommit: true,
	})
}

type Config struct {
	Count                  int      `json:"count"`
	Runner                 string   `json:"runner"`
	Qemu                   string   `json:"qemu"`
	Workdir                string   `json:"workdir"`
	Image                  string   `json:"image"`
	Memory                 int      `json:"memory"`
	PayloadSize            int      `json:"payload_size"`
	BitmapSize             int      `json:"bitmap_size"`
	HardTimeout            string   `json:"hard_timeout"`
	ModuleRanges           string   `json:"module_ranges"`
	QemuArgs               []string `json:"qemu_args"`
	Debug                  bool     `json:"debug"`
	Host                   string   `json:"host"`
	RunnerLog              string   `json:"runner_log"`
	SlowTraceDir           string   `json:"slow_trace_dir"`
	SlowTraceThresholdMS   int      `json:"slow_trace_threshold_ms"`
	SlowTraceMaxEvents     int      `json:"slow_trace_max_events"`
	WindowsMinidump        bool     `json:"windows_minidump"`
	WindowsMinidumpTimeout int      `json:"windows_minidump_timeout"`
	KeepState              bool     `json:"keep_state"`
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	pool        *Pool
	index       int
	workdir     string
	closed      chan bool
	closeOnce   sync.Once
	mu          sync.Mutex
	cmd         *exec.Cmd
	runnerLog   *os.File
	forwardPort int
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count:                  1,
		Runner:                 filepath.Join(".", "bin", "syz-nyx-runner"),
		Memory:                 2048,
		PayloadSize:            0,
		BitmapSize:             0,
		HardTimeout:            "3m",
		Host:                   "127.0.0.1",
		WindowsMinidump:        true,
		WindowsMinidumpTimeout: 120,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse nyx vm config: %w", err)
	}
	applyEnvOverrides(cfg, env)
	if cfg.Count <= 0 {
		return nil, fmt.Errorf("invalid config param count: %v", cfg.Count)
	}
	if cfg.Runner == "" {
		return nil, fmt.Errorf("config param runner is empty")
	}
	if cfg.Qemu == "" {
		return nil, fmt.Errorf("config param qemu is empty")
	}
	if _, err := time.ParseDuration(cfg.HardTimeout); err != nil {
		return nil, fmt.Errorf("bad hard_timeout %q: %w", cfg.HardTimeout, err)
	}
	return &Pool{env: env, cfg: cfg}, nil
}

func applyEnvOverrides(cfg *Config, env *vmimpl.Env) {
	if value := os.Getenv("SYZ_NYX_RUNNER"); value != "" {
		cfg.Runner = value
	}
	if value := os.Getenv("SYZ_NYX_QEMU_PATH"); value != "" {
		cfg.Qemu = value
	}
	if value := os.Getenv("SYZ_NYX_WORKDIR"); value != "" {
		cfg.Workdir = value
	}
	if value := os.Getenv("SYZ_NYX_IMAGE"); value != "" {
		cfg.Image = value
	}
	if value := os.Getenv("SYZ_NYX_RUNNER_LOG"); value != "" {
		cfg.RunnerLog = value
	}
	if value := os.Getenv("SYZ_NYX_SLOW_TRACE_DIR"); value != "" {
		cfg.SlowTraceDir = value
	}
	if value := os.Getenv("SYZ_NYX_SLOW_TRACE_THRESHOLD_MS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			cfg.SlowTraceThresholdMS = parsed
		}
	}
	if value := os.Getenv("SYZ_NYX_SLOW_TRACE_MAX_EVENTS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			cfg.SlowTraceMaxEvents = parsed
		}
	}
	if value := os.Getenv("SYZ_NYX_PAYLOAD_SIZE"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			cfg.PayloadSize = parsed
		}
	}
	if value := os.Getenv("SYZ_NYX_BITMAP_SIZE"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			cfg.BitmapSize = parsed
		}
	}
	if value := os.Getenv("SYZ_NYX_MEMORY_MB"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			cfg.Memory = parsed
		}
	}
	if value := os.Getenv("SYZ_NYX_MODULE_RANGES"); value != "" {
		cfg.ModuleRanges = value
	}
	if value := os.Getenv("SYZ_NYX_HARD_TIMEOUT"); value != "" {
		cfg.HardTimeout = value
	}
	if value := os.Getenv("SYZ_NYX_WINDOWS_MINIDUMP_TIMEOUT"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			cfg.WindowsMinidumpTimeout = parsed
		}
	}
	if env.Image != "" && cfg.Image == "" {
		cfg.Image = env.Image
	}
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(_ context.Context, workdir string, index int) (vmimpl.Instance, error) {
	return &instance{
		pool:    pool,
		index:   index,
		workdir: workdir,
		closed:  make(chan bool),
	}, nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	return hostSrc, nil
}

func (inst *instance) Forward(port int) (string, error) {
	if port == 0 {
		return "", fmt.Errorf("nyx: Forward port is zero")
	}
	inst.forwardPort = port
	return fmt.Sprintf("%s:%d", inst.pool.cfg.Host, port), nil
}

func (inst *instance) Run(ctx context.Context, command string) (<-chan vmimpl.Chunk, <-chan error, error) {
	host, port, err := inst.managerEndpoint(command)
	if err != nil {
		return nil, nil, err
	}
	args, err := inst.runnerArgs(host, port)
	if err != nil {
		return nil, nil, err
	}
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	cmd := osutil.CommandContext(ctx, inst.pool.cfg.Runner, args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe

	var tee io.Writer
	if inst.pool.cfg.RunnerLog != "" {
		runnerLog := inst.expand(inst.pool.cfg.RunnerLog)
		if err := os.MkdirAll(filepath.Dir(runnerLog), 0o755); err != nil {
			wpipe.Close()
			rpipe.Close()
			return nil, nil, err
		}
		logFile, err := os.OpenFile(runnerLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			wpipe.Close()
			rpipe.Close()
			return nil, nil, err
		}
		inst.mu.Lock()
		if inst.runnerLog != nil {
			_ = inst.runnerLog.Close()
		}
		inst.runnerLog = logFile
		inst.mu.Unlock()
		tee = logFile
	}
	merger := vmimpl.NewOutputMerger(tee)
	merger.Add("syz-nyx-runner", vmimpl.OutputConsole, rpipe)

	if err := cmd.Start(); err != nil {
		wpipe.Close()
		rpipe.Close()
		merger.Wait()
		return nil, nil, err
	}
	wpipe.Close()
	inst.mu.Lock()
	inst.cmd = cmd
	inst.mu.Unlock()

	scale := inst.pool.env.Timeouts.Scale
	if scale <= 0 {
		scale = time.Second
	}
	return vmimpl.Multiplex(ctx, cmd, merger, vmimpl.MultiplexConfig{
		Close: inst.closed,
		Debug: inst.pool.env.Debug || inst.pool.cfg.Debug,
		Scale: scale,
	})
}

func (inst *instance) managerEndpoint(command string) (string, string, error) {
	fields := strings.Fields(command)
	for i := 0; i+3 < len(fields); i++ {
		if fields[i] == "runner" {
			return fields[i+2], fields[i+3], nil
		}
	}
	if inst.forwardPort != 0 {
		return inst.pool.cfg.Host, strconv.Itoa(inst.forwardPort), nil
	}
	return "", "", fmt.Errorf("nyx: failed to parse manager endpoint from command %q", command)
}

func (inst *instance) runnerArgs(host, port string) ([]string, error) {
	cfg := inst.pool.cfg
	workdir := inst.expand(cfg.Workdir)
	if workdir == "" {
		workdir = filepath.Join(inst.pool.env.Workdir, "nyx")
	}
	args := []string{
		strconv.Itoa(inst.index),
		host,
		port,
		"--workdir", workdir,
		"--qemu-path", inst.expand(cfg.Qemu),
	}
	if image := inst.expand(cfg.Image); image != "" {
		args = append(args, "--image", image)
	}
	if cfg.Memory > 0 {
		args = append(args, "--memory", strconv.Itoa(cfg.Memory))
	}
	if cfg.PayloadSize > 0 {
		args = append(args, "--payload-size", strconv.Itoa(cfg.PayloadSize))
	}
	if cfg.BitmapSize > 0 {
		args = append(args, "--bitmap-size", strconv.Itoa(cfg.BitmapSize))
	}
	if cfg.HardTimeout != "" {
		args = append(args, "--hard-timeout", cfg.HardTimeout)
	}
	if cfg.ModuleRanges != "" {
		args = append(args, "--module-ranges", cfg.ModuleRanges)
	}
	if cfg.Debug || inst.pool.env.Debug {
		args = append(args, "--debug")
	}
	if cfg.WindowsMinidump {
		args = append(args, "--windows-minidump")
		if cfg.WindowsMinidumpTimeout > 0 {
			args = append(args, "--windows-minidump-timeout", strconv.Itoa(cfg.WindowsMinidumpTimeout))
		}
	}
	if cfg.KeepState {
		args = append(args, "--keep-state")
	}
	if cfg.SlowTraceDir != "" {
		args = append(args, "--slow-trace-dir", inst.expand(cfg.SlowTraceDir))
	}
	if cfg.SlowTraceThresholdMS > 0 {
		args = append(args, "--slow-trace-threshold-ms", strconv.Itoa(cfg.SlowTraceThresholdMS))
	}
	if cfg.SlowTraceMaxEvents > 0 {
		args = append(args, "--slow-trace-max-events", strconv.Itoa(cfg.SlowTraceMaxEvents))
	}
	for _, arg := range cfg.QemuArgs {
		args = append(args, "--qemu-arg", inst.expand(arg))
	}
	return args, nil
}

func (inst *instance) expand(value string) string {
	cfg := inst.pool.cfg
	nyxWorkdir := cfg.Workdir
	if nyxWorkdir == "" {
		nyxWorkdir = filepath.Join(inst.pool.env.Workdir, "nyx")
	}
	repl := strings.NewReplacer(
		"{{INDEX}}", strconv.Itoa(inst.index),
		"{{WORKDIR}}", inst.workdir,
		"{{NYX_WORKDIR}}", nyxWorkdir,
	)
	return repl.Replace(value)
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}

func (inst *instance) Info() ([]byte, error) {
	args, err := inst.runnerArgs(inst.pool.cfg.Host, strconv.Itoa(inst.forwardPort))
	if err != nil {
		return nil, err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "nyx runner: %s\n", inst.pool.cfg.Runner)
	fmt.Fprintf(&sb, "nyx runner args: %s\n", strings.Join(args, " "))
	return []byte(sb.String()), nil
}

func (inst *instance) Close() error {
	inst.closeOnce.Do(func() {
		close(inst.closed)
	})
	inst.mu.Lock()
	cmd := inst.cmd
	logFile := inst.runnerLog
	inst.cmd = nil
	inst.runnerLog = nil
	inst.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	if logFile != nil {
		return logFile.Close()
	}
	return nil
}

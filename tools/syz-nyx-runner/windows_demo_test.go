package main

import (
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
)

func extractFunctionBody(t *testing.T, src, signature string) string {
	t.Helper()
	start := strings.LastIndex(src, signature)
	if start == -1 {
		t.Fatalf("%s not found in executor.cc", signature)
	}
	openRel := strings.Index(src[start:], "{")
	if openRel == -1 {
		t.Fatalf("opening brace for %s not found", signature)
	}
	bodyStart := start + openRel + 1
	depth := 1
	for i := bodyStart; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[bodyStart:i]
			}
		}
	}
	t.Fatalf("closing brace for %s not found", signature)
	return ""
}

func loadDemoSyscallTable(t *testing.T) map[string]int {
	t.Helper()
	path := filepath.Join("..", "..", "executor", "syscalls_windows_nyx_demo.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read demo syscall table: %v", err)
	}
	src := string(data)
	defines := make(map[string]int)
	defineRe := regexp.MustCompile(`#define\s+(W32_[A-Z0-9_]+)\s+(\d+)`)
	for _, match := range defineRe.FindAllStringSubmatch(src, -1) {
		id, err := strconv.Atoi(match[2])
		if err != nil {
			t.Fatalf("parse syscall ID %q: %v", match[2], err)
		}
		defines[match[1]] = id
	}
	re := regexp.MustCompile(`syscalls\[(W32_[A-Z0-9_]+|\d+)\]\s*=\s*call_t\{\"([^\"]+)\"`)
	matches := re.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatalf("no demo syscall entries found in %s", path)
	}
	table := make(map[string]int, len(matches))
	for _, match := range matches {
		id, err := strconv.Atoi(match[1])
		if err != nil {
			var ok bool
			id, ok = defines[match[1]]
			if !ok {
				t.Fatalf("unknown syscall macro %q in %s", match[1], path)
			}
		}
		table[match[2]] = id
	}
	return table
}

func TestWindowsDemoSyscallTableMatchesTargetIDs(t *testing.T) {
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for name, wantID := range table {
		meta := target.SyscallMap[name]
		if meta == nil {
			t.Fatalf("demo syscall %q missing from windows/amd64 target", name)
		}
		if meta.ID != wantID {
			t.Fatalf("demo syscall %q has target ID %d, want %d", name, meta.ID, wantID)
		}
	}
}

func TestWindowsDemoExecEncodingUsesTargetIDs(t *testing.T) {
	table := loadDemoSyscallTable(t)
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	for name, wantID := range table {
		meta := target.SyscallMap[name]
		ct := target.BuildChoiceTable(nil, map[*prog.Syscall]bool{meta: true})
		p := target.GenSampleProg(meta, rand.NewSource(1), ct)
		execData, err := p.SerializeForExec()
		if err != nil {
			t.Fatalf("SerializeForExec(%s): %v", name, err)
		}
		decoded, err := target.DeserializeExec(execData, nil)
		if err != nil {
			t.Fatalf("DeserializeExec(%s): %v", name, err)
		}
		if len(decoded.Calls) != 1 {
			t.Fatalf("decoded %s into %d calls, want 1", name, len(decoded.Calls))
		}
		if decoded.Calls[0].Meta == nil {
			t.Fatalf("decoded %s call has nil metadata", name)
		}
		if got := decoded.Calls[0].Meta.ID; got != wantID {
			t.Fatalf("decoded %s with target ID %d, want %d", name, got, wantID)
		}
	}
}

func TestStandaloneBootstrapProgramForNtQuerySystemInformation(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	meta := target.SyscallMap["NtQuerySystemInformation"]
	if meta == nil {
		t.Fatal("NtQuerySystemInformation missing from windows/amd64 target")
	}
	p, bootstrap, err := standaloneProgram(target, meta, 1)
	if err != nil {
		t.Fatalf("standaloneProgram: %v", err)
	}
	if !bootstrap {
		t.Fatal("NtQuerySystemInformation should use deterministic bootstrap program")
	}
	wantCalls := []struct {
		name  string
		async bool
	}{
		{"VirtualAlloc", false},
		{"NtQuerySystemInformation", false},
		{"NtQueryTimerResolution", false},
		{"NtQuerySystemTime", false},
		{"NtQueryPerformanceCounter", false},
		{"NtDelayExecution", true},
		{"CloseHandle", true},
		{"NtYieldExecution", true},
		{"NtFlushWriteBuffer", true},
	}
	if len(p.Calls) != len(wantCalls) {
		t.Fatalf("bootstrap program has %d calls, want %d", len(p.Calls), len(wantCalls))
	}
	for i, want := range wantCalls {
		if got := p.Calls[i].Meta.Name; got != want.name {
			t.Fatalf("bootstrap call[%d] = %q, want %q", i, got, want.name)
		}
		if got := p.Calls[i].Props.Async; got != want.async {
			t.Fatalf("bootstrap call[%d] async=%v, want %v", i, got, want.async)
		}
	}
	serialized := string(p.Serialize())
	if !strings.Contains(serialized, "NtQuerySystemInformation(") ||
		!strings.Contains(serialized, "NtDelayExecution(") ||
		!strings.Contains(serialized, "0xfffffffffff85ee0") ||
		!strings.Contains(serialized, "NtFlushWriteBuffer() (async)") {
		t.Fatalf("unexpected bootstrap program:\n%s", serialized)
	}
	execData, err := p.SerializeForExec()
	if err != nil {
		t.Fatalf("SerializeForExec: %v", err)
	}
	decoded, err := target.DeserializeExec(execData, nil)
	if err != nil {
		t.Fatalf("DeserializeExec: %v", err)
	}
	if len(decoded.Calls) != len(wantCalls) {
		t.Fatalf("decoded bootstrap program into %d calls, want %d", len(decoded.Calls), len(wantCalls))
	}
	for i, want := range wantCalls {
		if decoded.Calls[i].Meta == nil || decoded.Calls[i].Meta.Name != want.name {
			t.Fatalf("decoded bootstrap call[%d] mismatch: got %#v want %q", i, decoded.Calls[i].Meta, want.name)
		}
	}
}

func TestStandaloneBootstrapProgramFitsReferenceNyxPayload(t *testing.T) {
	target, err := prog.GetTarget("windows", "amd64")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	meta := target.SyscallMap["NtQuerySystemInformation"]
	if meta == nil {
		t.Fatal("NtQuerySystemInformation missing from windows/amd64 target")
	}
	p, bootstrap, err := standaloneProgram(target, meta, 1)
	if err != nil {
		t.Fatalf("standaloneProgram: %v", err)
	}
	if !bootstrap {
		t.Fatal("NtQuerySystemInformation should use deterministic bootstrap program")
	}
	execData, err := p.SerializeForExec()
	if err != nil {
		t.Fatalf("SerializeForExec: %v", err)
	}
	const (
		oldSmokePayload  = 4096
		referencePayload = 131072
	)
	if got := len(execData) + 4; got > oldSmokePayload {
		t.Logf("bootstrap exec payload=%d exceeds smoke-sized Nyx buffer=%d", got, oldSmokePayload)
	} else {
		t.Fatalf("bootstrap exec payload=%d unexpectedly fits smoke-sized Nyx buffer=%d", got, oldSmokePayload)
	}
	if got := len(execData) + 4; got > referencePayload {
		t.Fatalf("bootstrap exec payload=%d exceeds reference Nyx payload=%d", got, referencePayload)
	}
}

func TestExecutorInitializesInputDataBeforeNyxPreview(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	src := string(data)
	start := strings.Index(src, "parse_execute(req);")
	if start == -1 {
		t.Fatal("parse_execute(req) block not found in executor.cc")
	}
	endRel := strings.Index(src[start:], "uint64_t exec_start = current_time_ms();")
	if endRel == -1 {
		t.Fatal("Nyx exec block end not found in executor.cc")
	}
	block := src[start : start+endRel]
	assign := strings.Index(block, "input_data =")
	if assign == -1 {
		t.Fatal("input_data assignment not found before Nyx execution")
	}
	preview := strings.Index(block, "nyx_log_exec_preview(")
	if preview == -1 {
		t.Fatal("nyx_log_exec_preview call not found in Nyx execution block")
	}
	if assign > preview {
		t.Fatalf("input_data is assigned after nyx_log_exec_preview (assign=%d preview=%d)", assign, preview)
	}
}

func TestNyxModeLoopInitializesCoverageAfterHandshake(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	src := string(data)
	start := strings.Index(src, "if (header->kind == SYZ_NYX_KIND_HANDSHAKE) {")
	if start == -1 {
		t.Fatal("Nyx handshake block not found in executor.cc")
	}
	endRel := strings.Index(src[start:], "have_handshake = true;")
	if endRel == -1 {
		t.Fatal("Nyx handshake block end not found in executor.cc")
	}
	block := src[start : start+endRel]
	parseIdx := strings.Index(block, "parse_handshake(hs);")
	if parseIdx == -1 {
		t.Fatal("parse_handshake(hs) not found in Nyx handshake block")
	}
	setupIdx := strings.Index(block, "setup_coverage();")
	if setupIdx == -1 {
		t.Fatal("setup_coverage() not found in Nyx handshake block")
	}
	if setupIdx < parseIdx {
		t.Fatal("setup_coverage() appears before parse_handshake(hs) in Nyx handshake block")
	}
}

func TestNyxModeLoopLogsBeforeHandshakeDecode(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	src := string(data)
	start := strings.Index(src, "const uint8_t* body = payload->data + sizeof(*header);")
	if start == -1 {
		t.Fatal("Nyx payload body setup not found in executor.cc")
	}
	endRel := strings.Index(src[start:], "hs = {")
	if endRel == -1 {
		t.Fatal("Nyx handshake assignment block not found in executor.cc")
	}
	block := src[start : start+endRel]
	headerLog := strings.Index(block, "nyx_hprintf(\"nyx payload header kind=%u body=%u total=%d\\n\"")
	if headerLog == -1 {
		t.Fatal("Nyx payload header log not found before handshake decode")
	}
	bodyLog := strings.Index(block, "nyx_hprintf(\"nyx handshake body ready body=%u total=%d\\n\"")
	if bodyLog == -1 {
		t.Fatal("Nyx handshake body-ready log not found before handshake decode")
	}
	rootLog := strings.Index(block, "nyx_hprintf(\"nyx handshake root parsed body=%u\\n\"")
	if rootLog == -1 {
		t.Fatal("Nyx handshake root-parsed log not found before handshake decode")
	}
	rootCall := strings.Index(block, "flatbuffers::GetRoot<rpc::SnapshotHandshake>(body)")
	if rootCall == -1 {
		t.Fatal("Nyx handshake flatbuffers GetRoot call not found")
	}
	if rootLog < rootCall {
		t.Fatal("Nyx handshake root-parsed log appears before GetRoot call")
	}
}

func assertNoNyxLoggingBetweenAcquireAndRelease(t *testing.T, src string) {
	t.Helper()
	const acquireNeedle = "nyx_hypercall(HYPERCALL_KAFL_ACQUIRE,"
	const releaseNeedle = "nyx_hypercall(HYPERCALL_KAFL_RELEASE, 0);"
	found := 0
	for start := 0; start < len(src); {
		acquireRel := strings.Index(src[start:], acquireNeedle)
		if acquireRel == -1 {
			break
		}
		acquire := start + acquireRel
		releaseRel := strings.Index(src[acquire:], releaseNeedle)
		if releaseRel == -1 {
			t.Fatal("Nyx RELEASE hypercall not found after ACQUIRE")
		}
		window := src[acquire : acquire+releaseRel]
		if strings.Contains(window, "nyx_hprintf(") || strings.Contains(window, "nyx_log_exec_stage(") {
			t.Fatal("executor contains Nyx logging between ACQUIRE and RELEASE")
		}
		found++
		start = acquire + releaseRel + len(releaseNeedle)
	}
	if found == 0 {
		t.Fatal("Nyx ACQUIRE hypercall not found in executor.cc")
	}
}

func TestExecutorAvoidsNyxHprintfBetweenAcquireAndRelease(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	assertNoNyxLoggingBetweenAcquireAndRelease(t, string(data))
}

func TestExecutePathsAvoidNyxHprintf(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor.cc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor.cc: %v", err)
	}
	src := string(data)
	body := extractFunctionBody(t, src, "void execute_call(thread_t* th)")
	assertNoNyxLoggingBetweenAcquireAndRelease(t, body)
	if !strings.Contains(body, "GetCurrentThreadId()") {
		t.Fatal("execute_call ACQUIRE path does not capture the current thread ID")
	}
	if !strings.Contains(body, "__readgsqword(0x30)") {
		t.Fatal("execute_call ACQUIRE path does not capture the thread TEB")
	}
	release := strings.Index(body, "nyx_hypercall(HYPERCALL_KAFL_RELEASE, 0);")
	if release == -1 {
		t.Fatal("execute_call RELEASE hypercall not found")
	}
	if strings.Contains(body[release:], "HYPERCALL_KAFL_SYZ_COV_DUMP") {
		t.Fatal("execute_call should rely on RELEASE handling for per-call coverage dump")
	}
}

func TestWindowsExecutorPrefaultsDataSegment(t *testing.T) {
	path := filepath.Join("..", "..", "executor", "executor_windows.h")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read executor_windows.h: %v", err)
	}
	src := string(data)
	virtualAlloc := strings.Index(src, "VirtualAlloc(data, data_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)")
	if virtualAlloc == -1 {
		t.Fatal("VirtualAlloc data segment mapping not found in executor_windows.h")
	}
	prefault := strings.Index(src, "for (size_t i = 0; i < data_size; i += SYZ_PAGE_SIZE)")
	if prefault == -1 {
		t.Fatal("data segment prefault loop not found in executor_windows.h")
	}
	if prefault < virtualAlloc {
		t.Fatal("data segment prefault loop appears before VirtualAlloc mapping")
	}
}

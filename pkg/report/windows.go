// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"strings"

	"github.com/google/syzkaller/pkg/report/crash"
)

type windows struct {
	*config
}

func ctorWindows(cfg *config) (reporterImpl, []string, error) {
	return &windows{config: cfg}, nil, nil
}

var windowsCrashMarkers = []string{
	"SYZ-NYX-WINDOWS-CRASH:",
	"WINDOWS BUGCHECK DIRECT DUMP IO",
	"WINDOWS BUGCHECK",
	"KVM_EXIT_KAFL_PANIC_EXTENDED",
	"KVM_EXIT_KAFL_PANIC",
	"nyx crash:",
}

func (ctx *windows) ContainsCrash(output []byte) bool {
	return windowsCrashPos(output) != -1
}

func (ctx *windows) Parse(output []byte) *Report {
	pos := windowsCrashPos(output)
	if pos == -1 {
		return nil
	}
	start := lineStart(output, pos)
	end := windowsCrashEnd(output[pos:])
	if end == -1 {
		end = len(output)
	} else {
		end += pos
	}
	title := windowsCrashTitle(output[pos:lineEnd(output, pos)])
	rep := output[start:end]
	return &Report{
		Title:    title,
		Type:     crash.UnknownType,
		Report:   rep,
		StartPos: start,
		EndPos:   end,
		SkipPos:  end,
		Panicked: true,
	}
}

func (ctx *windows) Symbolize(rep *Report) error {
	return nil
}

func windowsCrashPos(output []byte) int {
	pos := -1
	for _, marker := range windowsCrashMarkers {
		cur := bytes.Index(output, []byte(marker))
		if cur != -1 && (pos == -1 || cur < pos) {
			pos = cur
		}
	}
	return pos
}

func windowsCrashEnd(output []byte) int {
	endMarker := []byte("END SYZ-NYX-WINDOWS-CRASH")
	pos := bytes.Index(output, endMarker)
	if pos == -1 {
		return -1
	}
	return lineEnd(output, pos)
}

func windowsCrashTitle(line []byte) string {
	text := strings.TrimSpace(string(line))
	if strings.HasPrefix(text, "SYZ-NYX-WINDOWS-CRASH:") {
		title := strings.TrimSpace(strings.TrimPrefix(text, "SYZ-NYX-WINDOWS-CRASH:"))
		if title != "" {
			return title
		}
	}
	if strings.Contains(text, "WINDOWS BUGCHECK DIRECT DUMP IO") {
		return "WINDOWS BUGCHECK DIRECT DUMP IO"
	}
	if strings.Contains(text, "WINDOWS BUGCHECK") {
		return "WINDOWS BUGCHECK"
	}
	if strings.Contains(text, "KVM_EXIT_KAFL_PANIC_EXTENDED") {
		return "KVM_EXIT_KAFL_PANIC_EXTENDED"
	}
	if strings.Contains(text, "KVM_EXIT_KAFL_PANIC") {
		return "KVM_EXIT_KAFL_PANIC"
	}
	if strings.HasPrefix(text, "nyx crash:") {
		title := strings.TrimSpace(strings.TrimPrefix(text, "nyx crash:"))
		if title != "" {
			return title
		}
	}
	return "WINDOWS BUGCHECK"
}

func lineStart(output []byte, pos int) int {
	if pos <= 0 {
		return 0
	}
	if start := bytes.LastIndexByte(output[:pos], '\n'); start != -1 {
		return start + 1
	}
	return 0
}

func lineEnd(output []byte, pos int) int {
	if pos < 0 {
		return 0
	}
	if end := bytes.IndexByte(output[pos:], '\n'); end != -1 {
		return pos + end + 1
	}
	return len(output)
}

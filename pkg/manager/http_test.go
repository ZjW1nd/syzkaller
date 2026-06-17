// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func TestHttpTemplates(t *testing.T) {
	for i, typ := range templTypes {
		t.Run(fmt.Sprintf("%v_%T", i, typ.data), func(t *testing.T) {
			data := testutil.RandValue(t, typ.data)
			if err := typ.templ.Execute(io.Discard, data); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBinCoverRaw(t *testing.T) {
	base := uint64(0xfffff80010000000)
	serv := newBinCoverTestServer(t, base, 0x100)
	corp := corpus.NewCorpus(context.Background())
	p := testProg(t)
	corp.Save(corpus.NewInput{
		Prog:     p,
		Call:     0,
		Signal:   signal.FromRaw([]uint64{1}, 0),
		Cover:    []uint64{base + 0x10},
		RawCover: []uint64{base + 0x10, base + 0x20, base + 0x200},
	})
	serv.Corpus.Store(corp)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/bincover/raw?module=afd.sys", nil)
	serv.httpBinCoverRaw(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("httpBinCoverRaw status=%d body=%s", w.Code, w.Body.String())
	}
	var resp binCoverRawResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(resp.Offsets, ","), "0x10,0x20"; got != want {
		t.Fatalf("offsets=%v want %v", got, want)
	}
	if !resp.RawCoverComplete {
		t.Fatal("expected complete raw cover")
	}
	if got, want := len(resp.Unmapped), 1; got != want {
		t.Fatalf("unmapped=%d want %d", got, want)
	}
}

func TestBinCoverRawNormalizesRawCoverPCs(t *testing.T) {
	base := uint64(0xfffff80010000000)
	serv := newBinCoverTestServer(t, base, 0x100)
	serv.Cfg.SysTarget = targets.Get(targets.Linux, targets.AMD64)
	corp := corpus.NewCorpus(context.Background())
	corp.Save(corpus.NewInput{
		Prog:     testProg(t),
		Call:     0,
		Signal:   signal.FromRaw([]uint64{1}, 0),
		RawCover: []uint64{base + 0x15, base + 0x25, base + 0x205},
	})
	serv.Corpus.Store(corp)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/bincover/raw?module=afd.sys", nil)
	serv.httpBinCoverRaw(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("httpBinCoverRaw status=%d body=%s", w.Code, w.Body.String())
	}
	var resp binCoverRawResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(resp.Offsets, ","), "0x10,0x20"; got != want {
		t.Fatalf("offsets=%v want %v", got, want)
	}
	if got, want := len(resp.Unmapped), 1; got != want {
		t.Fatalf("unmapped=%d want %d", got, want)
	}
}

func TestBinCoverRawFallsBackToCover(t *testing.T) {
	base := uint64(0xfffff80010000000)
	serv := newBinCoverTestServer(t, base, 0x100)
	corp := corpus.NewCorpus(context.Background())
	corp.Save(corpus.NewInput{
		Prog:   testProg(t),
		Call:   0,
		Signal: signal.FromRaw([]uint64{1}, 0),
		Cover:  []uint64{base + 0x30, base + 0x200},
	})
	serv.Corpus.Store(corp)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/bincover/raw?module=afd.sys", nil)
	serv.httpBinCoverRaw(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("httpBinCoverRaw status=%d body=%s", w.Code, w.Body.String())
	}
	var resp binCoverRawResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(resp.Offsets, ","), "0x30"; got != want {
		t.Fatalf("offsets=%v want %v", got, want)
	}
	if resp.RawCoverComplete {
		t.Fatal("fallback cover must mark raw cover incomplete")
	}
	if got, want := resp.SourceItems, 1; got != want {
		t.Fatalf("source_items=%d want %d", got, want)
	}
	if got, want := resp.SourceUpdates, 1; got != want {
		t.Fatalf("source_updates=%d want %d", got, want)
	}
}

func TestBinCoverUploadAndLighthouse(t *testing.T) {
	serv := &HTTPServer{Cfg: &mgrconfig.Config{Name: "test"}}
	payload := BinCoverageSnapshot{
		Tool: "test-tool",
		Module: BinCoverageModule{
			Name:             "afd.sys",
			CoveredBlocks:    1,
			TotalBlocks:      2,
			CoveredFunctions: 1,
			TotalFunctions:   1,
		},
		Functions: []BinCoverageFunction{{
			Name:          "AfdFunc",
			StartOffset:   0x10,
			EndOffset:     0x40,
			CoveredBlocks: 1,
			TotalBlocks:   2,
		}},
		Pseudocode: []BinCoverageFunctionCode{{
			Name: "AfdFunc",
			Lines: []BinCoverageLine{{
				Line:  1,
				Text:  "return 0;",
				State: "covered",
			}},
		}},
		CoveredOffsets: []uint64{0x20, 0x10, 0x20},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/bincover/upload", bytes.NewReader(data))
	serv.httpBinCoverUpload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("httpBinCoverUpload status=%d body=%s", w.Code, w.Body.String())
	}
	if snapshot := serv.BinCover.Load(); snapshot == nil || len(snapshot.CoveredOffsets) != 2 {
		t.Fatalf("bad stored snapshot: %#v", snapshot)
	} else if got, want := snapshot.Pseudocode[0].File, "afd.sys/AfdFunc.pseudo.c"; got != want {
		t.Fatalf("pseudocode file=%q want %q", got, want)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/bincover/lighthouse?module=afd.sys", nil)
	serv.httpBinCoverLighthouse(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("httpBinCoverLighthouse status=%d body=%s", w.Code, w.Body.String())
	}
	if got, want := w.Body.String(), "afd.sys+10\nafd.sys+20\n"; got != want {
		t.Fatalf("lighthouse body=%q want %q", got, want)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/cover?module=afd.sys&function=AfdFunc", nil)
	serv.httpCover(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("httpCover function status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "return 0;") {
		t.Fatalf("function page does not contain pseudocode: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/bincover?module=afd.sys", nil)
	serv.httpBinCover(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("httpBinCover status=%d body=%s", w.Code, w.Body.String())
	}
	if got, want := w.Header().Get("Location"), "/cover?module=afd.sys"; got != want {
		t.Fatalf("bincover redirect=%q want %q", got, want)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/cover?module=afd.sys", nil)
	serv.httpCover(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("httpCover status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		"href='/cover?module=afd.sys'",
		`href="/bincover/raw?module=afd.sys"`,
		`href="/bincover/lighthouse?module=afd.sys"`,
		`href="/bincover?json=1&amp;module=afd.sys"`,
		`href="/cover?module=afd.sys&amp;function=AfdFunc"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("cover page missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "binary coverage") || strings.Contains(body, ".pseudo.c") {
		t.Fatalf("cover page contains legacy binary/source UI text: %s", body)
	}
}

func TestBinCoverModuleCoverPage(t *testing.T) {
	serv := &HTTPServer{Cfg: &mgrconfig.Config{Name: "test"}}
	snapshot := &BinCoverageSnapshot{
		Tool: "test-tool",
		Module: BinCoverageModule{
			Name:             "afd.sys",
			CoveredBlocks:    1,
			TotalBlocks:      2,
			CoveredFunctions: 1,
			TotalFunctions:   1,
		},
		Functions: []BinCoverageFunction{{
			Name:          "AfdFunc",
			StartOffset:   0x10,
			EndOffset:     0x40,
			CoveredBlocks: 1,
			TotalBlocks:   2,
		}},
		Pseudocode: []BinCoverageFunctionCode{{
			Name: "AfdFunc",
			File: "afd.sys/AfdFunc.pseudo.c",
			Lines: []BinCoverageLine{
				{Line: 1, Text: "covered_line();", State: "covered", Offsets: []uint64{0x10}},
				{Line: 2, Text: "uncovered_line();", State: "uncovered"},
			},
		}},
	}
	normalizeBinCoverageSnapshot(snapshot)
	serv.BinCover.Store(snapshot)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/cover?module=afd.sys", nil)
	serv.httpCover(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("httpCover status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		"AfdFunc",
		`href="/cover?module=afd.sys&amp;function=AfdFunc"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("module cover page missing %q: %s", want, body)
		}
	}
	for _, unwanted := range []string{
		"afd.sys/AfdFunc.pseudo.c",
		"covered_line();",
		"uncovered_line();",
	} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("module cover page contains unwanted source text %q: %s", unwanted, body)
		}
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/cover?module=afd.sys&function=AfdFunc", nil)
	serv.httpCover(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("httpCover function status=%d body=%s", w.Code, w.Body.String())
	}
	body = w.Body.String()
	for _, want := range []string{
		"AfdFunc",
		"covered_line();",
		"uncovered_line();",
		"class=\"covered\"",
		"class=\"uncovered\"",
		"0x10",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("module cover page missing %q: %s", want, body)
		}
	}
}

func TestCoverRedirectsToBinaryModuleWhenNativeCoverDisabled(t *testing.T) {
	serv := &HTTPServer{Cfg: &mgrconfig.Config{Name: "test"}}
	snapshot := &BinCoverageSnapshot{
		Module: BinCoverageModule{Name: "afd.sys"},
	}
	normalizeBinCoverageSnapshot(snapshot)
	serv.BinCover.Store(snapshot)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/cover", nil)
	serv.httpCover(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("httpCover status=%d body=%s", w.Code, w.Body.String())
	}
	if got, want := w.Header().Get("Location"), "/cover?module=afd.sys"; got != want {
		t.Fatalf("redirect=%q want %q", got, want)
	}
}

func TestBareCoverRedirectsToBinaryModule(t *testing.T) {
	serv := &HTTPServer{Cfg: &mgrconfig.Config{Name: "test", Cover: true}}
	snapshot := &BinCoverageSnapshot{
		Module: BinCoverageModule{Name: "afd.sys"},
	}
	normalizeBinCoverageSnapshot(snapshot)
	serv.BinCover.Store(snapshot)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/cover", nil)
	serv.httpCover(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("httpCover status=%d body=%s", w.Code, w.Body.String())
	}
	if got, want := w.Header().Get("Location"), "/cover?module=afd.sys"; got != want {
		t.Fatalf("redirect=%q want %q", got, want)
	}
}

func newBinCoverTestServer(t *testing.T, base, size uint64) *HTTPServer {
	t.Helper()
	target := targets.Get(targets.TestOS, targets.TestArch64)
	cfg := &mgrconfig.Config{Name: "test", RawCover: true}
	cfg.SysTarget = target
	serv := &HTTPServer{Cfg: cfg}
	serv.Cover.Store(&CoverageInfo{Modules: []*vminfo.KernelModule{{
		Name: "afd.sys",
		Addr: base,
		Size: size,
		Path: `C:\Windows\System32\drivers\afd.sys`,
	}}})
	return serv
}

func testProg(t *testing.T) *prog.Prog {
	t.Helper()
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["test$manual"]: true,
	}
	ct := target.BuildChoiceTable(nil, enabled)
	return target.Generate(rand.NewSource(0), 1, ct)
}

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
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/bincover/lighthouse", nil)
	serv.httpBinCoverLighthouse(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("httpBinCoverLighthouse status=%d body=%s", w.Code, w.Body.String())
	}
	if got, want := w.Body.String(), "afd.sys+10\nafd.sys+20\n"; got != want {
		t.Fatalf("lighthouse body=%q want %q", got, want)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/bincover/function?name=AfdFunc", nil)
	serv.httpBinCoverFunction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("httpBinCoverFunction status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "return 0;") {
		t.Fatalf("function page does not contain pseudocode: %s", w.Body.String())
	}
}

func newBinCoverTestServer(t *testing.T, base, size uint64) *HTTPServer {
	t.Helper()
	serv := &HTTPServer{Cfg: &mgrconfig.Config{Name: "test", RawCover: true}}
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

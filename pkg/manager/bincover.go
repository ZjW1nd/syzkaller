// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxBinCoverUpload = 64 << 20

type BinCoverageSnapshot struct {
	Tool           string                    `json:"tool,omitempty"`
	UpdatedAt      time.Time                 `json:"updated_at,omitempty"`
	ReceivedAt     time.Time                 `json:"received_at,omitempty"`
	Module         BinCoverageModule         `json:"module"`
	Functions      []BinCoverageFunction     `json:"functions,omitempty"`
	Pseudocode     []BinCoverageFunctionCode `json:"pseudocode,omitempty"`
	CoveredOffsets []uint64                  `json:"covered_offsets,omitempty"`
	Lighthouse     []string                  `json:"lighthouse,omitempty"`
	Unmapped       []uint64                  `json:"unmapped,omitempty"`
}

type BinCoverageModule struct {
	Name             string `json:"name"`
	Path             string `json:"path,omitempty"`
	Base             uint64 `json:"base,omitempty"`
	Size             uint64 `json:"size,omitempty"`
	CoveredBlocks    int    `json:"covered_blocks,omitempty"`
	TotalBlocks      int    `json:"total_blocks,omitempty"`
	CoveredFunctions int    `json:"covered_functions,omitempty"`
	TotalFunctions   int    `json:"total_functions,omitempty"`
}

func (mod BinCoverageModule) BlockPercent() string {
	return binCoverPercent(mod.CoveredBlocks, mod.TotalBlocks)
}

func (mod BinCoverageModule) FunctionPercent() string {
	return binCoverPercent(mod.CoveredFunctions, mod.TotalFunctions)
}

type BinCoverageFunction struct {
	Name          string `json:"name"`
	File          string `json:"file,omitempty"`
	StartOffset   uint64 `json:"start_offset"`
	EndOffset     uint64 `json:"end_offset"`
	CoveredBlocks int    `json:"covered_blocks"`
	TotalBlocks   int    `json:"total_blocks"`
}

func (fn BinCoverageFunction) BlockPercent() string {
	return binCoverPercent(fn.CoveredBlocks, fn.TotalBlocks)
}

func (fn BinCoverageFunction) StartHex() string {
	return fmt.Sprintf("0x%x", fn.StartOffset)
}

func (fn BinCoverageFunction) EndHex() string {
	return fmt.Sprintf("0x%x", fn.EndOffset)
}

type BinCoverageFunctionCode struct {
	Name  string            `json:"name"`
	File  string            `json:"file,omitempty"`
	Lines []BinCoverageLine `json:"lines"`
}

type BinCoverageLine struct {
	Line    int      `json:"line"`
	Text    string   `json:"text"`
	State   string   `json:"state"`
	Offsets []uint64 `json:"offsets,omitempty"`
}

type UIBinCoverPage struct {
	UIPageHeader
	Snapshot      *BinCoverageSnapshot
	Functions     []BinCoverageFunction
	LighthouseURL string
	JSONURL       string
	RawURL        string
}

type UIBinCoverFunctionPage struct {
	UIPageHeader
	Snapshot *BinCoverageSnapshot
	Function BinCoverageFunction
	Name     string
	Lines    []BinCoverageLine
}

type UIBinCoverSourcePage struct {
	UIPageHeader
	Snapshot      *BinCoverageSnapshot
	Module        string
	Files         []binCoverageFile
	SelectedFile  string
	Functions     []BinCoverageFunctionCode
	LighthouseURL string
	JSONURL       string
	RawURL        string
}

type binCoverageFile struct {
	Name      string
	Functions int
	Covered   int
	Total     int
}

func (file binCoverageFile) Percent() string {
	return binCoverPercent(file.Covered, file.Total)
}

type binCoverRawResponse struct {
	GeneratedAt      time.Time         `json:"generated_at"`
	Module           binCoverRawModule `json:"module"`
	PCs              []string          `json:"pcs"`
	Offsets          []string          `json:"offsets"`
	RawCoverComplete bool              `json:"raw_cover_complete"`
	SourceItems      int               `json:"source_items"`
	SourceUpdates    int               `json:"source_updates"`
	Unmapped         []string          `json:"unmapped,omitempty"`
}

type binCoverRawModule struct {
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
	Base string `json:"base"`
	Size string `json:"size"`
}

func (serv *HTTPServer) httpBinCover(w http.ResponseWriter, r *http.Request) {
	moduleName := strings.TrimSpace(r.FormValue("module"))
	snapshot := serv.BinCover.Load()
	if snapshot != nil && moduleName != "" && !snapshot.matchesModule(moduleName) {
		http.Error(w, "binary coverage for requested module is not ready", http.StatusNotFound)
		return
	}
	if r.URL.Path == "/bincover" && r.FormValue("json") == "" {
		if snapshot != nil && snapshot.Module.Name != "" {
			http.Redirect(w, r, binCoverModuleURL("/cover", snapshot.Module.Name), http.StatusFound)
			return
		}
		if moduleName != "" {
			http.Redirect(w, r, binCoverModuleURL("/cover", moduleName), http.StatusFound)
			return
		}
	}
	if r.FormValue("json") != "" {
		w.Header().Set("Content-Type", ctApplicationJSON)
		if snapshot == nil {
			snapshot = &BinCoverageSnapshot{}
		}
		if err := json.NewEncoder(w).Encode(snapshot); err != nil {
			http.Error(w, fmt.Sprintf("failed to encode binary coverage: %v", err), http.StatusInternalServerError)
		}
		return
	}
	header := serv.pageHeader(r, "coverage")
	if snapshot != nil {
		header.setBinCoverModule(snapshot.Module.Name)
	} else {
		header.setBinCoverModule(moduleName)
	}
	data := UIBinCoverPage{
		UIPageHeader: header,
		Snapshot:     snapshot,
	}
	if snapshot != nil {
		data.Functions = snapshot.uiFunctions()
		data.LighthouseURL = binCoverModuleURL("/bincover/lighthouse", snapshot.Module.Name)
		data.JSONURL = binCoverModuleURL("/bincover", snapshot.Module.Name, "json", "1")
		data.RawURL = binCoverModuleURL("/bincover/raw", snapshot.Module.Name)
	}
	executeTemplate(w, binCoverTemplate, data)
}

func (serv *HTTPServer) httpBinCoverSource(w http.ResponseWriter, r *http.Request) {
	moduleName := strings.TrimSpace(r.FormValue("module"))
	if moduleName == "" {
		if snapshot := serv.BinCover.Load(); snapshot != nil && snapshot.Module.Name != "" {
			http.Redirect(w, r, binCoverModuleURL("/cover", snapshot.Module.Name, "file", r.FormValue("file")),
				http.StatusFound)
			return
		}
		http.Error(w, "missing module parameter", http.StatusBadRequest)
		return
	}
	snapshot, status, msg := serv.binCoverSnapshotForModule(moduleName)
	if snapshot == nil {
		http.Error(w, msg, status)
		return
	}
	selected := r.FormValue("file")
	files := snapshot.pseudocodeFiles()
	if selected == "" && len(files) != 0 {
		selected = files[0].Name
	}
	header := serv.pageHeader(r, "coverage "+snapshot.Module.Name)
	header.setBinCoverModule(snapshot.Module.Name)
	data := UIBinCoverSourcePage{
		UIPageHeader:  header,
		Snapshot:      snapshot,
		Module:        snapshot.Module.Name,
		Files:         files,
		SelectedFile:  selected,
		Functions:     snapshot.pseudocodeForFile(selected),
		LighthouseURL: binCoverModuleURL("/bincover/lighthouse", snapshot.Module.Name),
		JSONURL:       binCoverModuleURL("/bincover", snapshot.Module.Name, "json", "1"),
		RawURL:        binCoverModuleURL("/bincover/raw", snapshot.Module.Name),
	}
	executeTemplate(w, binCoverSourceTemplate, data)
}

func (serv *HTTPServer) httpBinCoverFunction(w http.ResponseWriter, r *http.Request) {
	moduleName := strings.TrimSpace(r.FormValue("module"))
	snapshot, status, msg := serv.binCoverSnapshotForModule(moduleName)
	if snapshot == nil {
		http.Error(w, msg, status)
		return
	}
	name := r.FormValue("function")
	if name == "" {
		name = r.FormValue("name")
	}
	if name == "" {
		http.Error(w, "missing function name", http.StatusBadRequest)
		return
	}
	fn, ok := snapshot.findFunction(name)
	if !ok {
		http.Error(w, "unknown function", http.StatusNotFound)
		return
	}
	lines := snapshot.findPseudocode(name)
	header := serv.pageHeader(r, name)
	header.setBinCoverModule(snapshot.Module.Name)
	data := UIBinCoverFunctionPage{
		UIPageHeader: header,
		Snapshot:     snapshot,
		Function:     fn,
		Name:         name,
		Lines:        lines,
	}
	executeTemplate(w, binCoverFuncTemplate, data)
}

func (serv *HTTPServer) httpBinCoverLighthouse(w http.ResponseWriter, r *http.Request) {
	snapshot, status, msg := serv.binCoverSnapshotForModule(strings.TrimSpace(r.FormValue("module")))
	if snapshot == nil {
		http.Error(w, msg, status)
		return
	}
	lines := snapshot.lighthouseLines()
	if len(lines) == 0 {
		http.Error(w, "binary coverage has no lighthouse data", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", ctTextPlain)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", snapshot.Module.Name+"_coverage_modoff.txt"))
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
}

func (serv *HTTPServer) binCoverSnapshotForModule(moduleName string) (*BinCoverageSnapshot, int, string) {
	snapshot := serv.BinCover.Load()
	if snapshot == nil {
		return nil, http.StatusNotFound, "binary coverage is not ready"
	}
	if moduleName != "" && !snapshot.matchesModule(moduleName) {
		return nil, http.StatusNotFound, "binary coverage for requested module is not ready"
	}
	return snapshot, http.StatusOK, ""
}

func (serv *HTTPServer) httpBinCoverUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST method supported", http.StatusMethodNotAllowed)
		return
	}
	var snapshot BinCoverageSnapshot
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBinCoverUpload))
	if err := dec.Decode(&snapshot); err != nil {
		http.Error(w, fmt.Sprintf("failed to decode binary coverage: %v", err), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(snapshot.Module.Name) == "" {
		http.Error(w, "missing module name", http.StatusBadRequest)
		return
	}
	normalizeBinCoverageSnapshot(&snapshot)
	serv.BinCover.Store(&snapshot)
	w.Header().Set("Content-Type", ctApplicationJSON)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"ok":          true,
		"received_at": snapshot.ReceivedAt,
	}); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode upload response: %v", err), http.StatusInternalServerError)
	}
}

func (serv *HTTPServer) httpBinCoverRaw(w http.ResponseWriter, r *http.Request) {
	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
		return
	}
	coverInfo := serv.Cover.Load()
	if coverInfo == nil {
		http.Error(w, "coverage is not ready, please try again later after fuzzer started", http.StatusInternalServerError)
		return
	}
	moduleName := r.FormValue("module")
	if moduleName == "" {
		http.Error(w, "missing module parameter", http.StatusBadRequest)
		return
	}
	module, ok := findBinCoverModule(coverInfo, moduleName)
	if !ok {
		http.Error(w, "unknown module", http.StatusNotFound)
		return
	}

	pcs := make(map[uint64]struct{})
	unmapped := make(map[uint64]struct{})
	rawComplete := serv.Cfg != nil && serv.Cfg.RawCover
	sourceItems := 0
	sourceUpdates := 0
	for _, item := range corpus.Items() {
		sourceItems++
		usedRaw := false
		for updateID := range item.Updates {
			raw := item.Updates[updateID].RawCover
			if len(raw) == 0 {
				rawComplete = false
				continue
			}
			sourceUpdates++
			usedRaw = true
			binCoverAddPCs(raw, module.Addr, module.Size, pcs, unmapped)
		}
		if !usedRaw {
			rawComplete = false
			if len(item.Cover) != 0 {
				sourceUpdates++
			}
			binCoverAddPCs(item.Cover, module.Addr, module.Size, pcs, unmapped)
		}
	}

	raw := binCoverSortedKeys(pcs)
	resp := binCoverRawResponse{
		GeneratedAt:      time.Now().UTC(),
		Module:           binCoverRawModuleFromKernel(module),
		RawCoverComplete: rawComplete,
		SourceItems:      sourceItems,
		SourceUpdates:    sourceUpdates,
	}
	for _, pc := range raw {
		resp.PCs = append(resp.PCs, fmt.Sprintf("0x%x", pc))
		resp.Offsets = append(resp.Offsets, fmt.Sprintf("0x%x", pc-module.Addr))
	}
	for _, pc := range binCoverSortedKeys(unmapped) {
		if len(resp.Unmapped) >= 128 {
			break
		}
		resp.Unmapped = append(resp.Unmapped, fmt.Sprintf("0x%x", pc))
	}
	w.Header().Set("Content-Type", ctApplicationJSON)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode binary raw coverage: %v", err), http.StatusInternalServerError)
	}
}

func normalizeBinCoverageSnapshot(snapshot *BinCoverageSnapshot) {
	now := time.Now().UTC()
	snapshot.ReceivedAt = now
	if snapshot.UpdatedAt.IsZero() {
		snapshot.UpdatedAt = now
	}
	snapshot.Module.Name = strings.TrimSpace(snapshot.Module.Name)
	sort.Slice(snapshot.Functions, func(i, j int) bool {
		if snapshot.Functions[i].StartOffset != snapshot.Functions[j].StartOffset {
			return snapshot.Functions[i].StartOffset < snapshot.Functions[j].StartOffset
		}
		return snapshot.Functions[i].Name < snapshot.Functions[j].Name
	})
	for index := range snapshot.Functions {
		fn := &snapshot.Functions[index]
		fn.File = strings.TrimSpace(fn.File)
		if fn.File == "" {
			fn.File = binCoverVirtualFile(snapshot.Module.Name, fn.Name)
		}
	}
	for codeIndex := range snapshot.Pseudocode {
		code := &snapshot.Pseudocode[codeIndex]
		code.File = strings.TrimSpace(code.File)
		if code.File == "" {
			code.File = binCoverVirtualFile(snapshot.Module.Name, code.Name)
		}
		for lineIndex := range snapshot.Pseudocode[codeIndex].Lines {
			line := &snapshot.Pseudocode[codeIndex].Lines[lineIndex]
			switch line.State {
			case "covered", "partial", "uncovered", "unknown":
			default:
				line.State = "unknown"
			}
			sort.Slice(line.Offsets, func(i, j int) bool {
				return line.Offsets[i] < line.Offsets[j]
			})
			line.Offsets = dedupSortedUint64(line.Offsets)
		}
	}
	sort.Slice(snapshot.Pseudocode, func(i, j int) bool {
		if snapshot.Pseudocode[i].File != snapshot.Pseudocode[j].File {
			return snapshot.Pseudocode[i].File < snapshot.Pseudocode[j].File
		}
		return snapshot.Pseudocode[i].Name < snapshot.Pseudocode[j].Name
	})
	sort.Slice(snapshot.CoveredOffsets, func(i, j int) bool {
		return snapshot.CoveredOffsets[i] < snapshot.CoveredOffsets[j]
	})
	snapshot.CoveredOffsets = dedupSortedUint64(snapshot.CoveredOffsets)
	sort.Strings(snapshot.Lighthouse)
	snapshot.Lighthouse = dedupSortedStrings(snapshot.Lighthouse)
}

func (header *UIPageHeader) setBinCoverModule(moduleName string) {
	moduleName = strings.TrimSpace(moduleName)
	if moduleName == "" {
		return
	}
	header.CoverURL = binCoverModuleURL("/cover", moduleName)
	header.BinCoverURL = binCoverModuleURL("/bincover", moduleName)
}

func (snapshot *BinCoverageSnapshot) uiFunctions() []BinCoverageFunction {
	functions := append([]BinCoverageFunction(nil), snapshot.Functions...)
	sort.SliceStable(functions, func(i, j int) bool {
		if functions[i].CoveredBlocks != functions[j].CoveredBlocks {
			return functions[i].CoveredBlocks > functions[j].CoveredBlocks
		}
		if functions[i].TotalBlocks != functions[j].TotalBlocks {
			return functions[i].TotalBlocks > functions[j].TotalBlocks
		}
		if functions[i].Name != functions[j].Name {
			return functions[i].Name < functions[j].Name
		}
		return functions[i].StartOffset < functions[j].StartOffset
	})
	return functions
}

func (snapshot *BinCoverageSnapshot) matchesModule(moduleName string) bool {
	moduleName = strings.TrimSpace(moduleName)
	if moduleName == "" {
		return true
	}
	return strings.EqualFold(snapshot.Module.Name, moduleName) ||
		strings.EqualFold(binCoverBaseName(snapshot.Module.Path), moduleName)
}

func (snapshot *BinCoverageSnapshot) UpdatedAtLocal() string {
	return binCoverLocalTime(snapshot.UpdatedAt)
}

func (snapshot *BinCoverageSnapshot) ReceivedAtLocal() string {
	return binCoverLocalTime(snapshot.ReceivedAt)
}

func binCoverLocalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04:05 -0700")
}

func binCoverModuleURL(path, moduleName string, params ...string) string {
	values := url.Values{}
	moduleName = strings.TrimSpace(moduleName)
	if moduleName != "" {
		values.Set("module", moduleName)
	}
	for i := 0; i+1 < len(params); i += 2 {
		if params[i+1] != "" {
			values.Set(params[i], params[i+1])
		}
	}
	if len(values) == 0 {
		return path
	}
	return path + "?" + values.Encode()
}

func (snapshot *BinCoverageSnapshot) findFunction(name string) (BinCoverageFunction, bool) {
	for _, fn := range snapshot.Functions {
		if fn.Name == name {
			return fn, true
		}
	}
	return BinCoverageFunction{}, false
}

func (snapshot *BinCoverageSnapshot) findPseudocode(name string) []BinCoverageLine {
	for _, code := range snapshot.Pseudocode {
		if code.Name == name {
			return code.Lines
		}
	}
	return nil
}

func (snapshot *BinCoverageSnapshot) pseudocodeFiles() []binCoverageFile {
	files := make(map[string]*binCoverageFile)
	for _, code := range snapshot.Pseudocode {
		fileName := code.File
		if fileName == "" {
			fileName = binCoverVirtualFile(snapshot.Module.Name, code.Name)
		}
		file := files[fileName]
		if file == nil {
			file = &binCoverageFile{Name: fileName}
			files[fileName] = file
		}
		file.Functions++
		for _, line := range code.Lines {
			switch line.State {
			case "covered", "partial":
				file.Covered++
				file.Total++
			case "uncovered":
				file.Total++
			}
		}
	}
	ret := make([]binCoverageFile, 0, len(files))
	for _, file := range files {
		ret = append(ret, *file)
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i].Name < ret[j].Name
	})
	return ret
}

func (snapshot *BinCoverageSnapshot) pseudocodeForFile(file string) []BinCoverageFunctionCode {
	var ret []BinCoverageFunctionCode
	for _, code := range snapshot.Pseudocode {
		fileName := code.File
		if fileName == "" {
			fileName = binCoverVirtualFile(snapshot.Module.Name, code.Name)
		}
		if fileName == file {
			ret = append(ret, code)
		}
	}
	return ret
}

func (snapshot *BinCoverageSnapshot) lighthouseLines() []string {
	if len(snapshot.Lighthouse) != 0 {
		return append([]string(nil), snapshot.Lighthouse...)
	}
	if snapshot.Module.Name == "" || len(snapshot.CoveredOffsets) == 0 {
		return nil
	}
	lines := make([]string, 0, len(snapshot.CoveredOffsets))
	for _, off := range snapshot.CoveredOffsets {
		lines = append(lines, fmt.Sprintf("%s+%x", snapshot.Module.Name, off))
	}
	return lines
}

func binCoverVirtualFile(moduleName, functionName string) string {
	moduleName = strings.TrimSpace(moduleName)
	if moduleName == "" {
		moduleName = "binary"
	}
	functionName = strings.TrimSpace(functionName)
	if functionName == "" {
		functionName = "unknown"
	}
	return moduleName + "/" + functionName + ".pseudo.c"
}

func findBinCoverModule(coverInfo *CoverageInfo, name string) (*binCoverKernelModule, bool) {
	if coverInfo == nil {
		return nil, false
	}
	name = strings.TrimSpace(name)
	for _, module := range coverInfo.Modules {
		if module == nil {
			continue
		}
		if strings.EqualFold(module.Name, name) || strings.EqualFold(binCoverBaseName(module.Path), name) {
			return &binCoverKernelModule{
				Name: module.Name,
				Path: module.Path,
				Addr: module.Addr,
				Size: module.Size,
			}, true
		}
	}
	return nil, false
}

type binCoverKernelModule struct {
	Name string
	Path string
	Addr uint64
	Size uint64
}

func binCoverRawModuleFromKernel(module *binCoverKernelModule) binCoverRawModule {
	return binCoverRawModule{
		Name: module.Name,
		Path: module.Path,
		Base: fmt.Sprintf("0x%x", module.Addr),
		Size: fmt.Sprintf("0x%x", module.Size),
	}
}

func binCoverBaseName(path string) string {
	return filepath.Base(strings.ReplaceAll(path, `\`, `/`))
}

func binCoverAddPCs(raw []uint64, base, size uint64, pcs, unmapped map[uint64]struct{}) {
	for _, pc := range raw {
		if size != 0 && pc >= base && pc-base < size {
			pcs[pc] = struct{}{}
			continue
		}
		unmapped[pc] = struct{}{}
	}
}

func binCoverSortedKeys(m map[uint64]struct{}) []uint64 {
	ret := make([]uint64, 0, len(m))
	for value := range m {
		ret = append(ret, value)
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i] < ret[j]
	})
	return ret
}

func dedupSortedUint64(values []uint64) []uint64 {
	if len(values) == 0 {
		return nil
	}
	n := 1
	for i := 1; i < len(values); i++ {
		if values[i] == values[n-1] {
			continue
		}
		values[n] = values[i]
		n++
	}
	return values[:n]
}

func dedupSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	n := 1
	for i := 1; i < len(values); i++ {
		if values[i] == values[n-1] {
			continue
		}
		values[n] = values[i]
		n++
	}
	return values[:n]
}

func binCoverPercent(covered, total int) string {
	if total == 0 {
		return "---"
	}
	return fmt.Sprintf("%.1f%%", float64(covered)*100.0/float64(total))
}

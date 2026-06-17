// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"cmp"
	"fmt"
	"maps"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/hash"
)

// Target describes target OS/arch pair.
type Target struct {
	OS         string
	Arch       string
	Revision   string // unique hash representing revision of the descriptions
	PtrSize    uint64
	PageSize   uint64
	NumPages   uint64
	DataOffset uint64
	BigEndian  bool

	Syscalls  []*Syscall
	Resources []*ResourceDesc
	Consts    []ConstValue
	Flags     []FlagDesc
	Types     []Type

	// MakeDataMmap creates calls that mmaps target data memory range.
	MakeDataMmap func() []*Call

	// Neutralize neutralizes harmful calls by transforming them into non-harmful ones
	// (e.g. an ioctl that turns off console output is turned into ioctl that turns on output).
	// fixStructure determines whether it's allowed to make structural changes (e.g. add or
	// remove arguments). It is helpful e.g. when we do neutralization while iterating over the
	// arguments.
	Neutralize func(c *Call, fixStructure bool) error

	// AnnotateCall annotates a syscall invocation in C reproducers.
	// The returned string will be placed inside a comment except for the
	// empty string which will omit the comment.
	AnnotateCall func(c ExecCall) string

	// SpecialTypes allows target to do custom generation/mutation for some struct's and union's.
	// Map key is struct/union name for which custom generation/mutation is required.
	// Map value is custom generation/mutation function that will be called
	// for the corresponding type. g is helper object that allows generate random numbers,
	// allocate memory, etc. typ is the struct/union type. old is the old value of the struct/union
	// for mutation, or nil for generation. The function returns a new value of the struct/union,
	// and optionally any calls that need to be inserted before the arg reference.
	SpecialTypes map[string]func(g *Gen, typ Type, dir Dir, old Arg) (Arg, []*Call)

	// Resources that play auxiliary role, but widely used throughout all syscalls (e.g. pid/uid).
	AuxResources map[string]bool

	// Helpers groups target-specific helper/syscall-scaffold handling knobs.
	Helpers HelperPolicy
	// Bias groups target-specific generation/bias/template steering hooks.
	Bias BiasPolicy
	// RuntimePolicy groups runtime pipeline steering hooks that are consumed outside
	// pure prog semantics (triage/corpus/collide scheduling).
	RuntimePolicy RuntimePolicy
	// SemanticStateModel optionally analyzes a program prefix into target-specific
	// semantic facts. Generic targets leave this unset.
	SemanticStateModel SemanticStateModel
	// ApplyTargetProfile returns a target instance with named target-specific policy
	// knobs applied. Implementations should clone before mutating profile state.
	ApplyTargetProfile func(target *Target, profile string) (*Target, error)
	// SelectCollideCallIndices lets a target choose which calls in a program should be treated
	// as the primary race/collide targets. It returns preferred call indices plus a flag that
	// blocks generic collide transforms when the target considers the whole program too shallow.
	SelectCollideCallIndices func(calls []*Call) ([]int, bool)
	// ResourceUseScore returns how valuable a particular syscall is as a consumer of an
	// existing resource for future reuse decisions. Higher scores mean the resource has
	// already reached a deeper or more interesting state.
	ResourceUseScore func(call *Syscall) int
	// ResourceReuseScore prioritizes one existing resource root over another for the syscall
	// currently being generated. Higher values mean the resource is a better fit for continuing
	// the current state/session.
	ResourceReuseScore func(current *Syscall, candidate *ResultArg, p *Prog, insertionPoint int) int
	// CorpusResourceScore lets a target prioritize one corpus-derived resource root over another
	// when resourceCentric borrows an initialization slice from corpus programs.
	CorpusResourceScore func(current *Syscall, candidate *ResultArg, p *Prog, insertionPoint int, corpusProg *Prog) int
	// PreferResourceCentricBorrowing lets a target request trying resourceCentric corpus borrowing
	// before in-program existingResource reuse for the syscall currently being generated.
	PreferResourceCentricBorrowing func(current *Syscall) bool
	// SelectResourceCtor lets a target override which constructor syscall should be used to
	// synthesize a new resource of the requested kind.
	SelectResourceCtor func(current *Syscall, resourceType string, ctors []ResourceCtor) *Syscall
	// CallRelevanceScore returns how relevant a syscall is as an owning call for triage/corpus
	// focus. Higher scores mean the syscall represents a deeper or more target-relevant state.
	CallRelevanceScore func(call *Syscall) int
	// TriageCallScore lets a target prefer one owning syscall over another specifically for
	// triage/corpus ownership decisions. When unset, triage falls back to CallRelevanceScore.
	TriageCallScore func(call *Syscall) int
	// ExpandEnabledCalls can automatically add helper/constructor syscalls to the enabled set
	// before choice-table building and transitive resource checks.
	ExpandEnabledCalls func(target *Target, enabled map[*Syscall]bool) map[*Syscall]bool
	// GenerateNoGenerateCalls lets target profiles generate selected no_generate calls without
	// mutating the shared syscall metadata.
	GenerateNoGenerateCalls map[int]bool
	// MinimumHintsCallRelevance skips comparison-driven hints jobs for calls below the
	// configured relevance threshold when CallRelevanceScore is available.
	MinimumHintsCallRelevance int
	// MinimumTriageCallRelevance skips triage creation for calls below the configured
	// relevance threshold when CallRelevanceScore is available.
	MinimumTriageCallRelevance int
	// MinimumCollideCallRelevance skips collide-style concurrency transforms when a program
	// does not contain any call that reaches the configured relevance threshold.
	MinimumCollideCallRelevance int
	// MinimumMutationCallRelevance skips selecting calls below the configured relevance
	// threshold as direct mutateArg targets when CallRelevanceScore is available.
	MinimumMutationCallRelevance int
	// Additional special invalid pointer values besides NULL to use.
	SpecialPointers []uint64

	// Special file name length that can provoke bugs (e.g. PATH_MAX).
	SpecialFileLenghts []int

	// Filled by prog package:
	SyscallMap map[string]*Syscall
	ConstMap   map[string]uint64
	FlagsMap   map[string][]string

	// ObserveTemplateHook is an optional callback for target-level policy code to report when
	// a local interaction template materially influenced a choice (generation, corpus borrowing,
	// collide selection, etc.). The payload should be a short stable identifier.
	ObserveTemplateHook func(name string)

	init        sync.Once
	fillArch    func(target *Target)
	initArch    func(target *Target)
	resourceMap map[string]*ResourceDesc
	// Maps resource name to a list of calls that can create the resource.
	resourceCtors map[string][]ResourceCtor
	any           anyTypes

	// The default ChoiceTable is used only by tests and utilities, so we initialize it lazily.
	defaultOnce        sync.Once
	defaultChoiceTable *ChoiceTable

	kFuzzTestID int
}

type HelperPolicy struct {
	// AutomaticHelperPredicate lets a target classify helper/syscall-scaffold calls without
	// mutating the underlying shared syscall descriptions. When unset, CallIsAutomaticHelper
	// falls back to SyscallAttrs.AutomaticHelper.
	AutomaticHelperPredicate func(call *Syscall) bool

	// DeprioritizeAutomaticHelpers reduces the chance of selecting syscalls marked with
	// AutomaticHelper as top-level exploration targets. Helper syscalls remain generatable
	// and are still available as resource constructors.
	DeprioritizeAutomaticHelpers bool
	// NoGenerateAutomaticHelpers removes AutomaticHelper syscalls from ordinary top-level
	// choice-table selection. They remain enabled for resource construction, and target
	// hooks can still insert required scaffolding explicitly.
	NoGenerateAutomaticHelpers bool
	// AvoidCollidingAutomaticHelpers avoids marking AutomaticHelper syscalls async in the
	// generic collide transforms when possible. This keeps helper/resource-constructor calls
	// stable while still allowing deeper target calls to be perturbed concurrently.
	AvoidCollidingAutomaticHelpers bool
	// SkipHintsForAutomaticHelpers skips comparison-driven hints jobs for syscalls marked
	// AutomaticHelper. This keeps compare-guided mutations focused on deeper target calls
	// instead of resource-construction helpers.
	SkipHintsForAutomaticHelpers bool
	// NoMutateAutomaticHelpers adds AutomaticHelper syscalls to the "do not mutate directly"
	// set. These helpers can still be inserted/generated as constructors, but their own
	// arguments are not used as primary mutation targets.
	NoMutateAutomaticHelpers bool
	// SkipCorpusForAutomaticHelpers skips persisting AutomaticHelper calls as owning corpus
	// entries. The full program can still be retained through deeper target calls that gain
	// stable signal, but helper-only coverage will not dominate the corpus.
	SkipCorpusForAutomaticHelpers bool
	// SkipTriageForAutomaticHelpers skips creating triage jobs for helper-owned new signal.
	// The signal still contributes to global max-signal accounting, but we avoid spending
	// deflake/minimize/post-process budget on helper-only coverage.
	SkipTriageForAutomaticHelpers bool
	// AvoidAutomaticHelperBias causes call generation to ignore helper syscalls as the biasing
	// context for the next top-level call choice. This helps programs transition from setup
	// scaffolding into deeper target operations more quickly.
	AvoidAutomaticHelperBias bool
}

type BiasPolicy struct {
	// SelectGenerationBiasCall lets a target select which existing call in the current program
	// prefix should be used as the bias context for the next generated top-level call.
	// It receives the whole program plus the insertion point and returns the index of the call
	// to use as bias, `NoGenerationBiasCall` to explicitly suppress prefix bias, or -1 to fall
	// back to the generic random-prefix behavior.
	SelectGenerationBiasCall func(p *Prog, insertionPoint int) int
	// SelectGeneratedCall lets a target override the next top-level generated syscall choice
	// after bias computation but before the generic choice table lookup. It returns a syscall
	// ID to force, or -1 to fall back to the generic choice table.
	SelectGeneratedCall func(p *Prog, insertionPoint int, biasCall int, ct *ChoiceTable) int
	// GenerationTemplateScore lets a target recognize when the current program prefix already
	// matches a small local interaction template for the specified syscall. Higher scores mean
	// the target is more confident that the template should be continued consistently in other
	// heuristics such as corpus slice selection.
	GenerationTemplateScore func(p *Prog, insertionPoint int, call *Syscall) int
	// FilterBiasCalls lets a target narrow the global bias-call pool used when there is no
	// explicit prefix-bias source. Returning nil or an empty slice keeps the original pool.
	FilterBiasCalls func(calls []*Syscall) []*Syscall
	// AdjustCallPriority allows a target to modify the pairwise call-choice weight used by
	// the choice table. It is applied after the generic static/dynamic priority calculation.
	AdjustCallPriority func(src, dst *Syscall, weight int32) int32
	// MinimumGenerationBiasCallRelevance skips using calls below the configured relevance
	// threshold as prefix-bias sources for future call generation when SelectGenerationBiasCall
	// consults CallRelevanceScore.
	MinimumGenerationBiasCallRelevance int
}

type RuntimePolicy struct {
	// TriageDiagnostics requests detailed triage/corpus-save logs for focused
	// runs where gate scripts or stats tools need to attribute owners precisely.
	TriageDiagnostics bool
	// PreferCollideProgram lets a target request a higher collide probability for programs that
	// already match a target-specific local interaction template.
	PreferCollideProgram func(p *Prog) bool
	// ShouldScheduleProgram lets a target reject generated or mutated programs before they enter
	// the executor queues. Focused modes use this to keep broken resource lineages out of the
	// steady-state fuzz stream while leaving ordinary targets unrestricted.
	ShouldScheduleProgram func(origin string, p *Prog) bool
	// ShouldScheduleImmediateCollide lets a target request an immediate one-off collide attempt
	// after a triaged program is stabilized and persisted. This is intended for focused targets
	// where deeper owners are rare and should be raced promptly rather than waiting to be drawn
	// later from the regular gen/fuzz stream.
	ShouldScheduleImmediateCollide func(p *Prog, call int) bool
	// ShouldForceTriageCall lets a target request triage for a specific call/origin even when
	// the execution did not contribute new global max-signal. This is intended for narrowly
	// focused flows such as collide:triage where preserving deep owners can matter more than
	// strict global novelty.
	ShouldForceTriageCall func(origin string, p *Prog, call int) bool
	// ShouldSkipTriageProgram lets a target treat a program as execute-only: its signal can
	// still update the global max-signal, but it should not enter deflake/minimize/corpus work.
	ShouldSkipTriageProgram func(origin string, p *Prog) bool
	// ShouldPersistStableTriageCall lets a target request corpus persistence for a triaged call
	// even when newStableSignal is empty, provided the call still has non-empty stableSignal.
	// This is intended for focused modes where a stable deep owner is useful for future mutation
	// and collide scheduling even if its stable signal is no longer globally novel.
	ShouldPersistStableTriageCall func(origin string, p *Prog, call int) bool
}

const NoGenerationBiasCall = -2

func (target *Target) CallRelevance(call *Syscall) int {
	if target == nil || target.CallRelevanceScore == nil {
		return 0
	}
	return target.CallRelevanceScore(call)
}

func (target *Target) TriageRelevance(call *Syscall) int {
	if target == nil || call == nil {
		return 0
	}
	if target.TriageCallScore != nil {
		return target.TriageCallScore(call)
	}
	return target.CallRelevance(call)
}

func (target *Target) CallPassesRelevanceThreshold(call *Syscall, minScore int) bool {
	score := target.CallRelevance(call)
	if score < 0 {
		return false
	}
	return score == 0 || minScore <= 0 || score >= minScore
}

func (target *Target) CallIsAutomaticHelper(call *Syscall) bool {
	if target == nil || call == nil {
		return false
	}
	if target.Helpers.AutomaticHelperPredicate != nil {
		return target.Helpers.AutomaticHelperPredicate(call)
	}
	return call.Attrs.AutomaticHelper
}

func (target *Target) CallEligibleForHints(call *Syscall) bool {
	if target == nil || call == nil {
		return false
	}
	if target.Helpers.SkipHintsForAutomaticHelpers && target.CallIsAutomaticHelper(call) {
		return false
	}
	return target.CallPassesRelevanceThreshold(call, target.MinimumHintsCallRelevance)
}

func (target *Target) CallEligibleForTriage(call *Syscall) bool {
	if target == nil || call == nil {
		return false
	}
	if target.Helpers.SkipTriageForAutomaticHelpers && target.CallIsAutomaticHelper(call) {
		return false
	}
	return target.CallPassesRelevanceThreshold(call, target.MinimumTriageCallRelevance)
}

func (target *Target) CallEligibleForMutation(call *Syscall) bool {
	if target == nil || call == nil {
		return false
	}
	if target.Helpers.NoMutateAutomaticHelpers && target.CallIsAutomaticHelper(call) {
		return false
	}
	return target.CallPassesRelevanceThreshold(call, target.MinimumMutationCallRelevance)
}

func (target *Target) CallEligibleForGenerationBias(call *Syscall) bool {
	if target == nil || call == nil {
		return false
	}
	if target.CallNoGenerate(call) {
		return false
	}
	if target.Helpers.AvoidAutomaticHelperBias && target.CallIsAutomaticHelper(call) {
		return false
	}
	return target.CallPassesRelevanceThreshold(call, target.Bias.MinimumGenerationBiasCallRelevance)
}

func (target *Target) CallNoGenerate(call *Syscall) bool {
	if call == nil {
		return false
	}
	return call.Attrs.NoGenerate && (target == nil || !target.GenerateNoGenerateCalls[call.ID])
}

func (target *Target) CallEligibleForCollide(call *Syscall) bool {
	if target == nil || call == nil {
		return false
	}
	if target.Helpers.AvoidCollidingAutomaticHelpers && target.CallIsAutomaticHelper(call) {
		return false
	}
	return target.CallPassesRelevanceThreshold(call, target.MinimumCollideCallRelevance)
}

func (target *Target) bestRelevanceCallIndices(calls []*Call, minScore int, skipHelpers bool) ([]int, bool) {
	bestScore := 0
	hasScored := false
	var preferred []int
	for i, call := range calls {
		if call == nil || call.Meta == nil {
			continue
		}
		if skipHelpers && target != nil && target.Helpers.AvoidCollidingAutomaticHelpers && target.CallIsAutomaticHelper(call.Meta) {
			continue
		}
		score := target.CallRelevance(call.Meta)
		if score > 0 {
			hasScored = true
		}
		if score > bestScore {
			bestScore = score
			preferred = preferred[:0]
		}
		if score == bestScore {
			preferred = append(preferred, i)
		}
	}
	if hasScored && minScore > 0 && bestScore < minScore {
		return nil, true
	}
	if len(preferred) != 0 && bestScore > 0 {
		return preferred, false
	}
	return nil, false
}

func (target *Target) SelectBestRelevanceCallIndex(calls []*Call, minScore int, skipHelpers bool) (int, bool) {
	indices, thresholdBlocked := target.bestRelevanceCallIndices(calls, minScore, skipHelpers)
	if len(indices) == 0 {
		return -1, thresholdBlocked
	}
	return indices[len(indices)-1], thresholdBlocked
}

const maxSpecialPointers = 16

var targets = make(map[string]*Target)

func RegisterTarget(target *Target, fill, init func(target *Target)) {
	key := target.OS + "/" + target.Arch
	if targets[key] != nil {
		panic(fmt.Sprintf("duplicate target %v", key))
	}
	target.fillArch = fill
	target.initArch = init
	targets[key] = target
}

func GetTarget(OS, arch string) (*Target, error) {
	key := OS + "/" + arch
	target := targets[key]
	if target == nil {
		var supported []string
		for _, t := range targets {
			supported = append(supported, fmt.Sprintf("%v/%v", t.OS, t.Arch))
		}
		slices.Sort(supported)
		return nil, fmt.Errorf("unknown target: %v (supported: %v) did you run `make generate`?", key, supported)
	}
	target.init.Do(target.lazyInit)
	return target, nil
}

func AllTargets() []*Target {
	var res []*Target
	for _, target := range targets {
		target.init.Do(target.lazyInit)
		res = append(res, target)
	}
	slices.SortFunc(res, func(a, b *Target) int {
		if a.OS != b.OS {
			return cmp.Compare(a.OS, b.OS)
		}
		return cmp.Compare(a.Arch, b.Arch)
	})
	return res
}

// Extend extends a target with a new set of syscalls, types, and resources.
// It is assumed that all new syscalls, types, and resources do not conflict
// with those already present in the target.
func (target *Target) Extend(syscalls []*Syscall, types []Type, resources []*ResourceDesc) {
	target.Syscalls = append(target.Syscalls, syscalls...)
	target.Types = append(target.Types, types...)
	target.Resources = append(target.Resources, resources...)
	// Updates the system call map and restores any links.
	target.initTarget()
}

func (target *Target) lazyInit() {
	target.Neutralize = func(c *Call, fixStructure bool) error { return nil }
	target.AnnotateCall = func(c ExecCall) string { return "" }
	target.fillArch(target)
	target.initTarget()
	target.initUselessHints()
	target.initRelatedFields()
	target.initArch(target)

	// We ignore the return value here as they are cached, and it makes more
	// sense to react to them when we attempt to execute a KFuzzTest call.
	target.kFuzzTestID = -1
	for _, call := range target.Syscalls {
		if call.Attrs.KFuzzTest {
			target.kFuzzTestID = call.ID
			break
		}
	}
	// We ignore the return value here as they are cached, and it makes more
	// sense to react to them when we attempt to execute a KFuzzTest call.
	_, _ = target.KFuzzTestRunID()

	// Give these 2 known addresses fixed positions and prepend target-specific ones at the end.
	target.SpecialPointers = append([]uint64{
		0x0000000000000000, // NULL pointer (keep this first because code uses special index=0 as NULL)
		0xffffffffffffffff, // unmapped kernel address (keep second because serialized value will match actual pointer value)
		0x9999999999999999, // non-canonical address
	}, target.SpecialPointers...)
	if len(target.SpecialPointers) > maxSpecialPointers {
		panic("too many special pointers")
	}
	if len(target.SpecialFileLenghts) == 0 {
		// Just some common lengths that can be used as PATH_MAX/MAX_NAME.
		target.SpecialFileLenghts = []int{256, 512, 4096}
	}
	for _, ln := range target.SpecialFileLenghts {
		if ln <= 0 || ln >= memAllocMaxMem {
			panic(fmt.Sprintf("bad special file length %v", ln))
		}
	}
}

func (target *Target) initTarget() {
	checkMaxCallID(len(target.Syscalls) - 1)
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}

	target.resourceMap = restoreLinks(target.Syscalls, target.Resources, target.Types)
	target.initAnyTypes()

	target.SyscallMap = make(map[string]*Syscall)
	for i, c := range target.Syscalls {
		c.ID = i
		target.SyscallMap[c.Name] = c
	}

	target.FlagsMap = make(map[string][]string)
	for _, c := range target.Flags {
		target.FlagsMap[c.Name] = c.Values
	}

	target.populateResourceCtors()
	target.resourceCtors = make(map[string][]ResourceCtor)
	for _, res := range target.Resources {
		target.resourceCtors[res.Name] = target.calcResourceCtors(res, false)
	}
}

func (target *Target) initUselessHints() {
	// Pre-compute useless hints for each type and deduplicate resulting maps
	// (there will be lots of duplicates).
	computed := make(map[Type]bool)
	dedup := make(map[string]map[uint64]struct{})
	ForeachType(target.Syscalls, func(t Type, ctx *TypeCtx) {
		hinter, ok := t.(uselessHinter)
		if !ok || computed[t] {
			return
		}
		computed[t] = true
		hints := hinter.calcUselessHints()
		if len(hints) == 0 {
			return
		}
		slices.Sort(hints)
		hints = slices.Compact(hints)
		sig := hash.String(hints)
		m := dedup[sig]
		if m == nil {
			m = make(map[uint64]struct{})
			for _, v := range hints {
				m[v] = struct{}{}
			}
			dedup[sig] = m
		}
		hinter.setUselessHints(m)
	})
}

func (target *Target) initRelatedFields() {
	// Compute sets of related fields that are used to reduce amount of produced hint replacements.
	// Related fields are sets of arguments to the same syscall, in the same position, that operate
	// on the same resource. The best example of related fields is a set of ioctl commands on the same fd:
	//
	//	ioctl$FOO1(fd fd_foo, cmd const[FOO1], ...)
	//	ioctl$FOO2(fd fd_foo, cmd const[FOO2], ...)
	//	ioctl$FOO3(fd fd_foo, cmd const[FOO3], ...)
	//
	// All cmd args related and we should not try to replace them with each other
	// (e.g. try to morph ioctl$FOO1 into ioctl$FOO2). This is both unnecessary, leads to confusing reproducers,
	// and in some cases to badly confused argument types, see e.g.:
	// https://github.com/google/syzkaller/issues/502
	// https://github.com/google/syzkaller/issues/4939
	//
	// However, notion of related fields is wider and includes e.g. socket syscall family/type/proto,
	// setsockopt consts, and in some cases even openat flags/mode.
	//
	// Related fields can include const, flags and int types.
	//
	// Notion of "same resource" is also quite generic b/c syscalls can accept several resource types,
	// and filenames/strings are also considered as a resource in this context. For example, openat syscalls
	// that operate on the same file are related, but are not related to openat calls that operate on other files.
	groups := make(map[string]map[Type]struct{})
	for _, call := range target.Syscalls {
		// Id is used to identify related syscalls.
		// We first collect all resources/strings/files. This needs to be done first b/c e.g. mmap has
		// fd resource at the end, so we need to do this before the next loop.
		id := call.CallName
		for i, field := range call.Args {
			switch arg := field.Type.(type) {
			case *ResourceType:
				id += fmt.Sprintf("-%v:%v", i, arg.Name())
			case *PtrType:
				if typ, ok := arg.Elem.(*BufferType); ok && typ.Kind == BufferString && len(typ.Values) == 1 {
					id += fmt.Sprintf("-%v:%v", i, typ.Values[0])
				}
			}
		}
		// Now we group const/flags args together.
		// But also if we see a const, we update id to include it. This is required for e.g.
		// socket/socketpair/setsockopt calls. For these calls all families can be groups, but types should be
		// grouped only for the same family, and protocols should be grouped only for the same family+type.
		// We assume the "more important" discriminating arguments come first (this is not necessary true,
		// but seems to be the case in real syscalls as it's unreasonable to pass less important things first).
		for i, field := range call.Args {
			switch field.Type.(type) {
			case *ConstType:
			case *FlagsType:
			case *IntType:
			default:
				continue
			}
			argID := fmt.Sprintf("%v/%v", id, i)
			group := groups[argID]
			if group == nil {
				group = make(map[Type]struct{})
				groups[argID] = group
			}
			call.Args[i].relatedFields = group
			group[field.Type] = struct{}{}
			switch arg := field.Type.(type) {
			case *ConstType:
				id += fmt.Sprintf("-%v:%v", i, arg.Val)
			}
		}
	}
	// Drop groups that consist of only a single field as they are not useful.
	for _, call := range target.Syscalls {
		for i := range call.Args {
			if len(call.Args[i].relatedFields) == 1 {
				call.Args[i].relatedFields = nil
			}
		}
	}
}

func (target *Target) GetConst(name string) uint64 {
	v, ok := target.ConstMap[name]
	if !ok {
		panic(fmt.Sprintf("const %v is not defined for %v/%v", name, target.OS, target.Arch))
	}
	return v
}

func (target *Target) sanitize(c *Call, fix bool) error {
	// For now, even though we accept the fix argument, it does not have the full effect.
	// It de facto only denies structural changes, e.g. deletions of arguments.
	// TODO: rewrite the corresponding sys/*/init.go code.
	return target.Neutralize(c, fix)
}

func RestoreLinks(syscalls []*Syscall, resources []*ResourceDesc, types []Type) {
	restoreLinks(syscalls, resources, types)
}

var (
	typeRefMu sync.Mutex
	typeRefs  atomic.Value // []Type
)

func restoreLinks(syscalls []*Syscall, resources []*ResourceDesc, types []Type) map[string]*ResourceDesc {
	typeRefMu.Lock()
	defer typeRefMu.Unlock()
	refs := []Type{nil}
	if old := typeRefs.Load(); old != nil {
		refs = old.([]Type)
	}
	for _, typ := range types {
		typ.setRef(Ref(len(refs)))
		refs = append(refs, typ)
	}
	typeRefs.Store(refs)

	resourceMap := make(map[string]*ResourceDesc)
	for _, res := range resources {
		resourceMap[res.Name] = res
	}

	ForeachType(syscalls, func(typ Type, ctx *TypeCtx) {
		if ref, ok := typ.(Ref); ok {
			typ = types[ref]
			*ctx.Ptr = typ
		}
		switch t := typ.(type) {
		case *ResourceType:
			t.Desc = resourceMap[t.TypeName]
			if t.Desc == nil {
				panic("no resource desc")
			}
		}
	})
	return resourceMap
}

func (target *Target) DefaultChoiceTable() *ChoiceTable {
	target.defaultOnce.Do(func() {
		target.defaultChoiceTable = target.BuildChoiceTable(nil, nil)
	})
	return target.defaultChoiceTable
}

// Clone creates a target instance that shares immutable description state with the original
// target, but can safely override target-level policy hooks and cached choice tables.
func (target *Target) Clone() *Target {
	if target == nil {
		return nil
	}
	clone := &Target{
		OS:                             target.OS,
		Arch:                           target.Arch,
		Revision:                       target.Revision,
		PtrSize:                        target.PtrSize,
		PageSize:                       target.PageSize,
		NumPages:                       target.NumPages,
		DataOffset:                     target.DataOffset,
		BigEndian:                      target.BigEndian,
		Syscalls:                       target.Syscalls,
		Resources:                      target.Resources,
		Consts:                         target.Consts,
		Flags:                          target.Flags,
		Types:                          target.Types,
		MakeDataMmap:                   target.MakeDataMmap,
		Neutralize:                     target.Neutralize,
		AnnotateCall:                   target.AnnotateCall,
		SpecialTypes:                   target.SpecialTypes,
		AuxResources:                   target.AuxResources,
		Helpers:                        target.Helpers,
		Bias:                           target.Bias,
		SelectCollideCallIndices:       target.SelectCollideCallIndices,
		RuntimePolicy:                  target.RuntimePolicy,
		SemanticStateModel:             target.SemanticStateModel,
		ApplyTargetProfile:             target.ApplyTargetProfile,
		ResourceUseScore:               target.ResourceUseScore,
		ResourceReuseScore:             target.ResourceReuseScore,
		CorpusResourceScore:            target.CorpusResourceScore,
		PreferResourceCentricBorrowing: target.PreferResourceCentricBorrowing,
		SelectResourceCtor:             target.SelectResourceCtor,
		CallRelevanceScore:             target.CallRelevanceScore,
		TriageCallScore:                target.TriageCallScore,
		ExpandEnabledCalls:             target.ExpandEnabledCalls,
		GenerateNoGenerateCalls:        cloneBoolMap(target.GenerateNoGenerateCalls),
		MinimumHintsCallRelevance:      target.MinimumHintsCallRelevance,
		MinimumTriageCallRelevance:     target.MinimumTriageCallRelevance,
		MinimumCollideCallRelevance:    target.MinimumCollideCallRelevance,
		MinimumMutationCallRelevance:   target.MinimumMutationCallRelevance,
		SpecialPointers:                target.SpecialPointers,
		SpecialFileLenghts:             target.SpecialFileLenghts,
		SyscallMap:                     target.SyscallMap,
		ConstMap:                       target.ConstMap,
		FlagsMap:                       target.FlagsMap,
		ObserveTemplateHook:            target.ObserveTemplateHook,
		fillArch:                       target.fillArch,
		initArch:                       target.initArch,
		resourceMap:                    target.resourceMap,
		resourceCtors:                  target.resourceCtors,
		any:                            target.any,
		kFuzzTestID:                    target.kFuzzTestID,
	}
	return clone
}

func cloneBoolMap(src map[int]bool) map[int]bool {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[int]bool, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func (target *Target) NoAutoChoiceTable() *ChoiceTable {
	calls := map[*Syscall]bool{}
	for _, c := range target.Syscalls {
		if c.Attrs.Automatic {
			continue
		}
		calls[c] = true
	}
	return target.BuildChoiceTable(nil, calls)
}

func (target *Target) RequiredGlobs() []string {
	globs := make(map[string]bool)
	ForeachType(target.Syscalls, func(typ Type, ctx *TypeCtx) {
		switch a := typ.(type) {
		case *BufferType:
			if a.Kind == BufferGlob {
				for _, glob := range requiredGlobs(a.SubKind) {
					globs[glob] = true
				}
			}
		}
	})
	return slices.Sorted(maps.Keys(globs))
}

func (target *Target) UpdateGlobs(globFiles map[string][]string) {
	// TODO: make host.DetectSupportedSyscalls below filter out globs with no values.
	// Also make prog package more strict with respect to generation/mutation of globs
	// with no values (they still can appear in tests and tools). We probably should
	// generate an empty string for these and never mutate.
	ForeachType(target.Syscalls, func(typ Type, ctx *TypeCtx) {
		switch a := typ.(type) {
		case *BufferType:
			if a.Kind == BufferGlob {
				a.Values = populateGlob(a.SubKind, globFiles)
			}
		}
	})
}

func requiredGlobs(pattern string) []string {
	var res []string
	for _, tok := range strings.Split(pattern, ":") {
		if tok[0] != '-' {
			res = append(res, tok)
		}
	}
	return res
}

func populateGlob(pattern string, globFiles map[string][]string) []string {
	files := make(map[string]bool)
	parts := strings.Split(pattern, ":")
	for _, tok := range parts {
		if tok[0] != '-' {
			for _, file := range globFiles[tok] {
				files[file] = true
			}
		}
	}
	for _, tok := range parts {
		if tok[0] == '-' {
			delete(files, tok[1:])
		}
	}
	return slices.Sorted(maps.Keys(files))
}

type Gen struct {
	r *randGen
	s *state
}

func (g *Gen) Target() *Target {
	return g.r.target
}

func (g *Gen) Rand() *rand.Rand {
	return g.r.Rand
}

func (g *Gen) NOutOf(n, outOf int) bool {
	return g.r.nOutOf(n, outOf)
}

func (g *Gen) Alloc(ptrType Type, dir Dir, data Arg) (Arg, []*Call) {
	return g.r.allocAddr(g.s, ptrType, dir, data.Size(), data), nil
}

func (g *Gen) GenerateArg(typ Type, dir Dir, pcalls *[]*Call) Arg {
	return g.generateArg(typ, dir, pcalls, false)
}

func (g *Gen) GenerateSpecialArg(typ Type, dir Dir, pcalls *[]*Call) Arg {
	return g.generateArg(typ, dir, pcalls, true)
}

func (g *Gen) generateArg(typ Type, dir Dir, pcalls *[]*Call, ignoreSpecial bool) Arg {
	arg, calls := g.r.generateArgImpl(g.s, typ, dir, ignoreSpecial)
	*pcalls = append(*pcalls, calls...)
	g.r.target.assignSizesArray([]Arg{arg}, []Field{{Name: "", Type: arg.Type()}}, nil)
	return arg
}

func (g *Gen) MutateArg(arg0 Arg) (calls []*Call) {
	updateSizes := true
	for stop := false; !stop; stop = g.r.oneOf(3) {
		ma := &mutationArgs{target: g.r.target, ignoreSpecial: true}
		ForeachSubArg(arg0, ma.collectArg)
		if len(ma.args) == 0 {
			// TODO(dvyukov): probably need to return this condition
			// and updateSizes to caller so that Mutate can act accordingly.
			return
		}
		arg, ctx := ma.chooseArg(g.r.Rand)
		newCalls, ok := g.r.target.mutateArg(g.r, g.s, arg, ctx, &updateSizes)
		if !ok {
			continue
		}
		calls = append(calls, newCalls...)
	}
	return calls
}

type Builder struct {
	target *Target
	ma     *memAlloc
	p      *Prog
}

func MakeProgGen(target *Target) *Builder {
	return &Builder{
		target: target,
		ma:     newMemAlloc(target.NumPages * target.PageSize),
		p: &Prog{
			Target: target,
		},
	}
}

func (pg *Builder) Append(c *Call) error {
	pg.target.assignSizesCall(c)
	pg.target.sanitize(c, true)
	pg.p.Calls = append(pg.p.Calls, c)
	return nil
}

func (pg *Builder) Allocate(size, alignment uint64) uint64 {
	return pg.ma.alloc(nil, size, alignment)
}

func (pg *Builder) AllocateVMA(npages uint64) uint64 {
	return pg.ma.alloc(nil, npages*pg.target.PageSize, pg.target.PageSize)
}

func (pg *Builder) Finalize() (*Prog, error) {
	if err := pg.p.validate(); err != nil {
		return nil, err
	}
	if _, err := pg.p.SerializeForExec(); err != nil {
		return nil, err
	}
	p := pg.p
	pg.p = nil
	return p, nil
}

// KFuzzTestRunID returns the ID for the syz_kfuzztest_run pseudo-syscall,
// or an error if it is not found in the target.
func (t *Target) KFuzzTestRunID() (int, error) {
	// The ID is initialized in lazyInit.
	if t.kFuzzTestID == -1 {
		return 0, fmt.Errorf("syz_kfuzztest_run syscall is missing")
	}
	return t.kFuzzTestID, nil
}

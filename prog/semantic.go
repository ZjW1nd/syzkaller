// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

type SemanticStateModel func(p *Prog, insertionPoint int) *SemanticState

type SemanticState struct {
	Target         *Target
	InsertionPoint int
	Resources      map[*ResultArg]map[string]bool
	Pointers       map[uint64]map[string]bool
	Operations     map[string]*SemanticOperation
	Violations     []SemanticViolation
}

type SemanticOperation struct {
	Kind    string
	Token   string
	Socket  *ResultArg
	Pointer uint64
	IOCP    *ResultArg
	Facts   map[string]bool
}

type SemanticViolation struct {
	Call   int
	Reason string
}

func BuildSemanticState(p *Prog, insertionPoint int) *SemanticState {
	if p != nil && p.Target != nil && p.Target.SemanticStateModel != nil {
		if st := p.Target.SemanticStateModel(p, insertionPoint); st != nil {
			return st
		}
	}
	return NewSemanticState(p, insertionPoint)
}

func (target *Target) BuildSemanticState(p *Prog, insertionPoint int) *SemanticState {
	if p == nil {
		p = &Prog{Target: target}
	} else if p.Target == nil {
		p = &Prog{Target: target, Calls: p.Calls, Comments: p.Comments}
	}
	return BuildSemanticState(p, insertionPoint)
}

func NewSemanticState(p *Prog, insertionPoint int) *SemanticState {
	if p != nil {
		if insertionPoint < 0 || insertionPoint > len(p.Calls) {
			insertionPoint = len(p.Calls)
		}
		return &SemanticState{
			Target:         p.Target,
			InsertionPoint: insertionPoint,
			Resources:      make(map[*ResultArg]map[string]bool),
			Pointers:       make(map[uint64]map[string]bool),
			Operations:     make(map[string]*SemanticOperation),
		}
	}
	if insertionPoint < 0 {
		insertionPoint = 0
	}
	return &SemanticState{
		InsertionPoint: insertionPoint,
		Resources:      make(map[*ResultArg]map[string]bool),
		Pointers:       make(map[uint64]map[string]bool),
		Operations:     make(map[string]*SemanticOperation),
	}
}

func (st *SemanticState) AddResourceFact(res *ResultArg, fact string) {
	if st == nil || res == nil || fact == "" {
		return
	}
	if st.Resources == nil {
		st.Resources = make(map[*ResultArg]map[string]bool)
	}
	if st.Resources[res] == nil {
		st.Resources[res] = make(map[string]bool)
	}
	st.Resources[res][fact] = true
}

func (st *SemanticState) ResourceHasFact(res *ResultArg, fact string) bool {
	return st != nil && st.Resources != nil && st.Resources[res] != nil && st.Resources[res][fact]
}

func (st *SemanticState) AddPointerFact(addr uint64, fact string) {
	if st == nil || fact == "" {
		return
	}
	if st.Pointers == nil {
		st.Pointers = make(map[uint64]map[string]bool)
	}
	if st.Pointers[addr] == nil {
		st.Pointers[addr] = make(map[string]bool)
	}
	st.Pointers[addr][fact] = true
}

func (st *SemanticState) AddOperation(op *SemanticOperation) {
	if st == nil || op == nil || op.Token == "" {
		return
	}
	if st.Operations == nil {
		st.Operations = make(map[string]*SemanticOperation)
	}
	if op.Facts == nil {
		op.Facts = make(map[string]bool)
	}
	st.Operations[op.Token] = op
}

func (op *SemanticOperation) AddFact(fact string) {
	if op == nil || fact == "" {
		return
	}
	if op.Facts == nil {
		op.Facts = make(map[string]bool)
	}
	op.Facts[fact] = true
}

func (op *SemanticOperation) HasFact(fact string) bool {
	return op != nil && op.Facts != nil && op.Facts[fact]
}

func (st *SemanticState) AddViolation(call int, reason string) {
	if st == nil {
		return
	}
	st.Violations = append(st.Violations, SemanticViolation{
		Call:   call,
		Reason: reason,
	})
}

func (st *SemanticState) Valid() bool {
	return st == nil || len(st.Violations) == 0
}

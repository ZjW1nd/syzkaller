// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import "testing"

func TestBuildSemanticStateDefaultTargetIsEmpty(t *testing.T) {
	target := InitTargetTest(t, "test", "64")
	p := &Prog{Target: target}
	st := BuildSemanticState(p, 0)
	if st == nil {
		t.Fatal("BuildSemanticState returned nil")
	}
	if st.Target != target {
		t.Fatal("semantic state target mismatch")
	}
	if st.InsertionPoint != 0 {
		t.Fatalf("insertion point=%d, want 0", st.InsertionPoint)
	}
	if len(st.Resources) != 0 || len(st.Pointers) != 0 ||
		len(st.Operations) != 0 || len(st.Violations) != 0 {
		t.Fatalf("default semantic state is not empty: %+v", st)
	}
}

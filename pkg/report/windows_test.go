// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/sys/targets"
)

func TestWindowsParse(t *testing.T) {
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:   targets.Windows,
			TargetArch: targets.AMD64,
			SysTarget:  targets.Get(targets.Windows, targets.AMD64),
		},
	}
	reporter, err := NewReporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range readDir(t, filepath.Join("testdata", targets.Windows, "report")) {
		t.Run(filepath.Base(file), func(t *testing.T) {
			testParseFile(t, reporter, file)
		})
	}
}

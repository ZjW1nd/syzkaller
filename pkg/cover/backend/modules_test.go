// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"flag"
	"testing"

	"github.com/google/syzkaller/pkg/vminfo"
)

var flagModuleDir = flag.String("module_dir", "", "directory to discover modules")

func TestLocateModules(t *testing.T) {
	// Dump modules discovered in a dir, not really an automated test, use as:
	// go test -run TestLocateModules -v ./pkg/cover/backend -module_dir=/linux/build/dir
	if *flagModuleDir == "" {
		t.Skip("no module dir specified")
	}
	paths, err := locateModules([]string{*flagModuleDir})
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range paths {
		t.Logf("%32v -> %v", name, path)
	}
}

func TestFixModulesKeepsRemoteModulesWithPaths(t *testing.T) {
	modules := []*vminfo.KernelModule{{
		Name: "afd.sys",
		Addr: 0xfffff80600000000,
		Size: 0x1000,
		Path: "afd.sys",
	}}

	got := FixModules(nil, modules, 0)

	if len(got) != 1 || got[0].Name != "afd.sys" ||
		got[0].Addr != 0xfffff80600000000 || got[0].Size != 0x1000 ||
		got[0].Path != "afd.sys" {
		t.Fatalf("FixModules()=%+v, want %+v", got, modules)
	}
}

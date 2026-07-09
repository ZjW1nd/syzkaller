// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package windows

import (
	"testing"

	"github.com/google/syzkaller/prog"
)

func TestWindowsAFDRejectsSharedPendingEvent(t *testing.T) {
	event := &prog.ResultArg{}
	p := &prog.Prog{
		Calls: []*prog.Call{
			windowsAFDPendingEventTestCall("NtDeviceIoControlFile$afd_wait_for_listen_pending_accept_tcp", event),
			windowsAFDPendingEventTestCall("NtDeviceIoControlFile$afd_query_recv_tcp_irp", event),
		},
	}
	if windowsHasValidAFDPendingEventUse(p) {
		t.Fatal("shared EVENT_HANDLE across private AFD pending IOCTLs was accepted")
	}
}

func TestWindowsAFDAllowsDistinctPendingEvents(t *testing.T) {
	p := &prog.Prog{
		Calls: []*prog.Call{
			windowsAFDPendingEventTestCall("NtDeviceIoControlFile$afd_wait_for_listen_pending_accept_tcp", &prog.ResultArg{}),
			windowsAFDPendingEventTestCall("NtDeviceIoControlFile$afd_query_recv_tcp_irp", &prog.ResultArg{}),
		},
	}
	if !windowsHasValidAFDPendingEventUse(p) {
		t.Fatal("distinct EVENT_HANDLE roots for private AFD pending IOCTLs were rejected")
	}
}

func windowsAFDPendingEventTestCall(name string, event *prog.ResultArg) *prog.Call {
	return &prog.Call{
		Meta: &prog.Syscall{Name: name},
		Args: []prog.Arg{
			nil,
			&prog.ResultArg{Res: event},
		},
	}
}

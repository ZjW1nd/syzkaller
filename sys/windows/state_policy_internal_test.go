package windows

import "testing"

func TestWindowsDefaultStatePolicyProfileExists(t *testing.T) {
	policy := selectWindowsStatePolicy(windowsProfileDefault)
	if len(policy.helpers.syscalls) == 0 {
		t.Fatal("default windows state policy has no helper syscalls")
	}
	if policy.relevance.minimumHintsCallRelevance != 3 ||
		policy.relevance.minimumTriageCallRelevance != 3 ||
		policy.relevance.minimumCollideCallRelevance != 3 ||
		policy.relevance.minimumMutationCallRelevance != 3 ||
		policy.relevance.minimumGenerationBiasCallRelevance != 3 {
		t.Fatalf("default windows policy relevance thresholds are unexpected: %+v", policy.relevance)
	}
}

func TestWindowsFocusedStatePolicyProfilesExist(t *testing.T) {
	afd := selectWindowsStatePolicy(windowsProfileAFD)
	if afd.name != windowsProfileAFD {
		t.Fatalf("got profile %q, want %q", afd.name, windowsProfileAFD)
	}
	if afd.relevance.minimumMutationCallRelevance != 2 {
		t.Fatalf("afd mutation threshold=%d, want 2", afd.relevance.minimumMutationCallRelevance)
	}
	if !afd.relevance.disabledCalls["NtFsControlFile"] {
		t.Fatal("afd profile did not disable NtFsControlFile relevance")
	}

	fsctl := selectWindowsStatePolicy(windowsProfileFSCTL)
	if fsctl.name != windowsProfileFSCTL {
		t.Fatalf("got profile %q, want %q", fsctl.name, windowsProfileFSCTL)
	}
	if len(fsctl.relevance.disabledCallPrefixes) == 0 {
		t.Fatal("fsctl profile has no disabled call prefixes")
	}
}

func TestParseWindowsProfile(t *testing.T) {
	tests := map[string]windowsProfileName{
		"default":      windowsProfileDefault,
		"afd":          windowsProfileAFD,
		"afd_transmit": windowsProfileAFDTransmit,
		"fsctl":        windowsProfileFSCTL,
		"AFD":          windowsProfileAFD,
	}
	for input, want := range tests {
		got, err := parseWindowsProfile(input)
		if err != nil {
			t.Fatalf("parseWindowsProfile(%q) failed: %v", input, err)
		}
		if got != want {
			t.Fatalf("parseWindowsProfile(%q)=%q, want %q", input, got, want)
		}
	}
	if _, err := parseWindowsProfile("missing"); err == nil {
		t.Fatal("parseWindowsProfile accepted unknown profile")
	}
}

func TestWindowsUnknownStatePolicyProfilePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("selectWindowsStatePolicy did not panic for unknown profile")
		}
	}()
	_ = selectWindowsStatePolicy("missing")
}

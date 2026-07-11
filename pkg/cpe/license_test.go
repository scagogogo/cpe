package cpeskills

import (
	"testing"
)

func TestLicense_String(t *testing.T) {
	l := NewLicense("MIT", "MIT License")
	if l.String() != "MIT" {
		t.Errorf("expected 'MIT', got %q", l.String())
	}

	var nilLic *License
	if nilLic.String() != "" {
		t.Error("expected empty string for nil license")
	}
}

func TestNewLicense(t *testing.T) {
	l := NewLicense("MIT", "MIT License")
	if l.SPDXID != "MIT" {
		t.Errorf("expected 'MIT', got %q", l.SPDXID)
	}
	if !l.IsOSIApproved {
		t.Error("MIT should be OSI approved")
	}
	if l.IsCopyleft {
		t.Error("MIT should not be copyleft")
	}
}

func TestIsOSIApproved(t *testing.T) {
	approved := []string{"MIT", "Apache-2.0", "BSD-3-Clause", "GPL-3.0-only", "MPL-2.0", "ISC"}
	for _, id := range approved {
		if !isOSIApproved(id) {
			t.Errorf("%s should be OSI approved", id)
		}
	}
	if isOSIApproved("unknown-license") {
		t.Error("unknown license should not be OSI approved")
	}
}

func TestIsCopyleft(t *testing.T) {
	copyleft := []string{"GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0-only", "LGPL-3.0-only", "MPL-2.0"}
	for _, id := range copyleft {
		if !isCopyleft(id) {
			t.Errorf("%s should be copyleft", id)
		}
	}
	if isCopyleft("MIT") {
		t.Error("MIT should not be copyleft")
	}
}

func TestCommonLicenses(t *testing.T) {
	licenses := CommonLicenses()
	if len(licenses) == 0 {
		t.Error("expected non-empty common licenses list")
	}
}

func TestDetectLicenseByName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"MIT", "MIT"},
		{"mit", "MIT"},
		{"Apache-2.0", "Apache-2.0"},
		{"apache 2.0", "Apache-2.0"},
		{"GPL-3.0", "GPL-3.0-only"},
		{"BSD-3-Clause", "BSD-3-Clause"},
		{"unknown-license-xyz", ""},
	}
	for _, tt := range tests {
		result := DetectLicenseByName(tt.name)
		if tt.want == "" {
			if result != nil {
				t.Errorf("DetectLicenseByName(%q): expected nil, got %v", tt.name, result)
			}
		} else {
			if result == nil || result.SPDXID != tt.want {
				t.Errorf("DetectLicenseByName(%q): expected %s, got %v", tt.name, tt.want, result)
			}
		}
	}
}

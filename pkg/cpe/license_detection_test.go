package cpeskills

import (
	"testing"
)

func TestDetectLicense(t *testing.T) {
	// From Licenses field
	comp := NewSBOMComponent("test", "1.0")
	comp.Licenses = []*License{NewLicense("MIT", "MIT License")}
	result := DetectLicense(comp)
	if result == nil || result.SPDXID != "MIT" {
		t.Errorf("expected MIT, got %v", result)
	}

	// From properties
	comp2 := NewSBOMComponent("test", "1.0")
	comp2.SetProperty("license", "Apache-2.0")
	result2 := DetectLicense(comp2)
	if result2 == nil || result2.SPDXID != "Apache-2.0" {
		t.Errorf("expected Apache-2.0, got %v", result2)
	}

	// From SPDX property
	comp3 := NewSBOMComponent("test", "1.0")
	comp3.SetProperty("spdx:licenseId", "GPL-3.0-only")
	result3 := DetectLicense(comp3)
	if result3 == nil || result3.SPDXID != "GPL-3.0-only" {
		t.Errorf("expected GPL-3.0-only, got %v", result3)
	}

	// No license
	comp4 := NewSBOMComponent("test", "1.0")
	result4 := DetectLicense(comp4)
	if result4 != nil {
		t.Errorf("expected nil, got %v", result4)
	}

	// Nil component
	if DetectLicense(nil) != nil {
		t.Error("expected nil for nil component")
	}
}

func TestCheckLicenseCompliance(t *testing.T) {
	comp := NewSBOMComponent("test", "1.0")
	comp.Licenses = []*License{NewLicense("MIT", "MIT License")}

	// MIT with default policy → compliant
	result := CheckLicenseCompliance(comp, nil)
	if !result.IsCompliant {
		t.Error("MIT should be compliant with default policy")
	}

	// GPL with strict policy → non-compliant
	comp2 := NewSBOMComponent("pkg", "1.0")
	comp2.Licenses = []*License{NewLicense("GPL-3.0-only", "GPL 3.0 only")}
	result2 := CheckLicenseCompliance(comp2, StrictLicensePolicy())
	if result2.IsCompliant {
		t.Error("GPL-3.0 should be non-compliant with strict policy")
	}
}

func TestCheckLicenseCompliance_NoLicense(t *testing.T) {
	comp := NewSBOMComponent("test", "1.0")
	result := CheckLicenseCompliance(comp, nil)
	if result.IsCompliant {
		t.Error("no license should be non-compliant")
	}
}

func TestBatchCheckLicenseCompliance(t *testing.T) {
	comp1 := NewSBOMComponent("pkg1", "1.0")
	comp1.Licenses = []*License{NewLicense("MIT", "MIT")}
	comp2 := NewSBOMComponent("pkg2", "2.0")
	comp2.Licenses = []*License{NewLicense("GPL-3.0-only", "GPL 3.0")}

	results := BatchCheckLicenseCompliance([]*SBOMComponent{comp1, comp2}, StrictLicensePolicy())
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
	if !results[0].IsCompliant {
		t.Error("MIT should be compliant")
	}
	if results[1].IsCompliant {
		t.Error("GPL-3.0 should be non-compliant with strict policy")
	}
}

func TestGetNonCompliantComponents(t *testing.T) {
	results := []*LicenseCompliance{
		{IsCompliant: true},
		{IsCompliant: false},
		{IsCompliant: true},
		{IsCompliant: false},
	}
	nonCompliant := GetNonCompliantComponents(results)
	if len(nonCompliant) != 2 {
		t.Errorf("expected 2 non-compliant, got %d", len(nonCompliant))
	}
}

func TestDefaultLicensePolicy(t *testing.T) {
	policy := DefaultLicensePolicy()
	if len(policy.AllowedLicenses) == 0 {
		t.Error("expected non-empty allowed licenses")
	}
	if len(policy.DeniedLicenses) == 0 {
		t.Error("expected non-empty denied licenses")
	}
	if !policy.AllowCopyleft {
		t.Error("default policy should allow copyleft")
	}
}

func TestStrictLicensePolicy(t *testing.T) {
	policy := StrictLicensePolicy()
	if policy.AllowCopyleft {
		t.Error("strict policy should not allow copyleft")
	}
}

package cpeskills

import (
	"encoding/json"
	"testing"
)

func TestNewSBOM(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test-sbom")
	if sbom.Format != SBOMFormatCycloneDX {
		t.Errorf("expected format %s, got %s", SBOMFormatCycloneDX, sbom.Format)
	}
	if sbom.Name != "test-sbom" {
		t.Errorf("expected name 'test-sbom', got %q", sbom.Name)
	}
	if sbom.SpecVersion != "1.5" {
		t.Errorf("expected spec version '1.5', got %q", sbom.SpecVersion)
	}
	if sbom.SerialNumber == "" {
		t.Error("expected non-empty serial number")
	}
	if sbom.Metadata == nil {
		t.Error("expected non-nil metadata")
	}
	if sbom.ComponentCount() != 0 {
		t.Errorf("expected 0 components, got %d", sbom.ComponentCount())
	}

	// SPDX
	sbom2 := NewSBOM(SBOMFormatSPDX, "spdx-sbom")
	if sbom2.SpecVersion != "2.3" {
		t.Errorf("expected spec version '2.3', got %q", sbom2.SpecVersion)
	}
}

func TestSBOM_AddComponent(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test")
	comp := NewSBOMComponent("lodash", "4.17.21")
	sbom.AddComponent(comp)

	if sbom.ComponentCount() != 1 {
		t.Errorf("expected 1 component, got %d", sbom.ComponentCount())
	}
	if comp.BomRef == "" {
		t.Error("expected non-empty BomRef after adding")
	}

	// nil component
	sbom.AddComponent(nil)
	if sbom.ComponentCount() != 1 {
		t.Errorf("expected still 1 component after nil add, got %d", sbom.ComponentCount())
	}
}

func TestSBOM_AddDependency(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test")
	sbom.AddDependency("comp-a", []string{"comp-b", "comp-c"})

	if sbom.DependencyCount() != 1 {
		t.Errorf("expected 1 dependency, got %d", sbom.DependencyCount())
	}
	if sbom.Dependencies[0].Ref != "comp-a" {
		t.Errorf("expected ref 'comp-a', got %q", sbom.Dependencies[0].Ref)
	}
	if len(sbom.Dependencies[0].DependsOn) != 2 {
		t.Errorf("expected 2 dependsOn, got %d", len(sbom.Dependencies[0].DependsOn))
	}
}

func TestSBOM_GetComponent(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test")
	comp := NewSBOMComponent("express", "4.17.1")
	comp.BomRef = "express-ref"
	sbom.AddComponent(comp)

	found := sbom.GetComponent("express-ref")
	if found == nil {
		t.Error("expected to find component")
	}
	if found.Name != "express" {
		t.Errorf("expected name 'express', got %q", found.Name)
	}

	notFound := sbom.GetComponent("nonexistent")
	if notFound != nil {
		t.Error("expected nil for nonexistent component")
	}
}

func TestSBOM_FindVulnerableComponents(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test")

	// 添加一个带有 CPE 的组件
	cpe, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	comp := NewSBOMComponent("log4j-core", "2.14.1")
	comp.SetCPE(cpe)
	sbom.AddComponent(comp)

	// 创建 CVE 列表
	cves := []*CVEReference{
		{
			CVEID:       "CVE-2021-44228",
			Description: "Log4Shell vulnerability",
			CVSSScore:   10.0,
			Severity:    "Critical",
			AffectedCPEs: []string{
				"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
			},
		},
	}

	results := sbom.FindVulnerableComponents(cves)
	if len(results) != 1 {
		t.Fatalf("expected 1 vulnerable component, got %d", len(results))
	}
	if results[0].MaxCVSS != 10.0 {
		t.Errorf("expected max CVSS 10.0, got %f", results[0].MaxCVSS)
	}
	if results[0].MaxSeverity != "Critical" {
		t.Errorf("expected 'Critical', got %q", results[0].MaxSeverity)
	}
	if results[0].CveCount != 1 {
		t.Errorf("expected 1 CVE, got %d", results[0].CveCount)
	}
}

func TestSBOM_EnrichWithVulnerabilities(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test")

	cpe, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	comp := NewSBOMComponent("log4j-core", "2.14.1")
	comp.SetCPE(cpe)
	sbom.AddComponent(comp)

	nvdData := &NVDCPEData{
		CPEMatchData: &CPEMatchData{
			CPEToCVEs: map[string][]string{
				"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*": {"CVE-2021-44228", "CVE-2021-45046"},
			},
		},
	}

	err := sbom.EnrichWithVulnerabilities(nvdData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if comp.Properties["cpe:cveCount"] != "2" {
		t.Errorf("expected cveCount '2', got %q", comp.Properties["cpe:cveCount"])
	}

	// nil NVD data
	err = sbom.EnrichWithVulnerabilities(nil)
	if err == nil {
		t.Error("expected error for nil NVD data")
	}
}

func TestSBOM_ToJSON(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test-sbom")
	comp := NewSBOMComponent("lodash", "4.17.21")
	sbom.AddComponent(comp)

	data, err := sbom.ToJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["name"] != "test-sbom" {
		t.Errorf("expected name 'test-sbom'")
	}
}

func TestNewSBOMComponent(t *testing.T) {
	comp := NewSBOMComponent("express", "4.17.1")
	if comp.Name != "express" {
		t.Errorf("expected name 'express', got %q", comp.Name)
	}
	if comp.Version != "4.17.1" {
		t.Errorf("expected version '4.17.1', got %q", comp.Version)
	}
	if comp.Hashes == nil {
		t.Error("expected non-nil hashes map")
	}
	if comp.Properties == nil {
		t.Error("expected non-nil properties map")
	}
}

func TestSBOMComponent_SetPURL(t *testing.T) {
	comp := NewSBOMComponent("express", "4.17.1")
	purl := NewPURL("npm", "", "express", "4.17.1")
	comp.SetPURL(purl)
	if comp.PURL == nil || comp.PURL.Name != "express" {
		t.Error("PURL not set correctly")
	}
}

func TestSBOMComponent_SetCPE(t *testing.T) {
	comp := NewSBOMComponent("log4j", "2.14.1")
	cpe, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	comp.SetCPE(cpe)
	if comp.CPE == nil || string(comp.CPE.Vendor) != "apache" {
		t.Error("CPE not set correctly")
	}
}

func TestSBOMComponent_AddHash(t *testing.T) {
	comp := NewSBOMComponent("pkg", "1.0")
	comp.AddHash("sha256", "abc123")
	if comp.Hashes["sha256"] != "abc123" {
		t.Errorf("expected hash 'abc123', got %q", comp.Hashes["sha256"])
	}
}

func TestSBOMComponent_SetProperty(t *testing.T) {
	comp := NewSBOMComponent("pkg", "1.0")
	comp.SetProperty("key", "value")
	if comp.Properties["key"] != "value" {
		t.Errorf("expected property 'value', got %q", comp.Properties["key"])
	}
}

func TestGenerateBomRef(t *testing.T) {
	// With PURL
	comp := NewSBOMComponent("express", "4.17.1")
	comp.SetPURL(NewPURL("npm", "", "express", "4.17.1"))
	ref := generateBomRef(comp)
	if ref != "pkg:npm/express@4.17.1" {
		t.Errorf("expected PURL-based ref, got %q", ref)
	}

	// With CPE only
	comp2 := NewSBOMComponent("log4j", "2.14.1")
	cpe, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	comp2.SetCPE(cpe)
	ref2 := generateBomRef(comp2)
	if ref2 != cpe.GetURI() {
		t.Errorf("expected CPE-based ref, got %q", ref2)
	}

	// Fallback
	comp3 := NewSBOMComponent("pkg", "1.0")
	ref3 := generateBomRef(comp3)
	if ref3 != "pkg@1.0" {
		t.Errorf("expected fallback ref 'pkg@1.0', got %q", ref3)
	}
}

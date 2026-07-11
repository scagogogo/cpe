package cpeskills

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExportToJSON(t *testing.T) {
	comp := NewSBOMComponent("test", "1.0")
	report := NewVulnerabilityReport(comp)
	report.AddFinding(&VulnerabilityFinding{
		CVE: &CVEReference{CVEID: "CVE-2021-44228", Severity: "Critical", CVSSScore: 10.0},
	})

	data, err := ExportToJSON(report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestExportToJSON_Nil(t *testing.T) {
	_, err := ExportToJSON(nil)
	if err == nil {
		t.Error("expected error for nil report")
	}
}

func TestExportToCSV(t *testing.T) {
	comp := NewSBOMComponent("test-pkg", "1.0.0")
	report := NewVulnerabilityReport(comp)
	report.AddFinding(&VulnerabilityFinding{
		CVE: &CVEReference{
			CVEID:     "CVE-2021-44228",
			Severity:  "Critical",
			CVSSScore: 10.0,
		},
		Reachability: "direct",
	})

	data, err := ExportToCSV([]*VulnerabilityReport{report})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	csv := string(data)
	if !strings.Contains(csv, "test-pkg") {
		t.Error("CSV should contain component name")
	}
	if !strings.Contains(csv, "CVE-2021-44228") {
		t.Error("CSV should contain CVE ID")
	}
	if !strings.HasPrefix(csv, "Component,Version,CVE") {
		t.Error("CSV should start with header")
	}
}

func TestExportToSARIF(t *testing.T) {
	comp := NewSBOMComponent("test-pkg", "1.0.0")
	report := NewVulnerabilityReport(comp)
	report.AddFinding(&VulnerabilityFinding{
		CVE: &CVEReference{
			CVEID:     "CVE-2021-44228",
			Severity:  "Critical",
			CVSSScore: 10.0,
		},
	})

	data, err := ExportToSARIF([]*VulnerabilityReport{report})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if sarif["version"] != "2.1.0" {
		t.Error("expected SARIF version 2.1.0")
	}
}

func TestExportVulnerabilityReport(t *testing.T) {
	comp := NewSBOMComponent("test", "1.0")
	report := NewVulnerabilityReport(comp)

	// JSON export
	data, err := ExportVulnerabilityReport(report, ExportFormatJSON)
	if err != nil {
		t.Fatalf("JSON export error: %v", err)
	}
	if !json.Valid(data) {
		t.Error("JSON export should produce valid JSON")
	}

	// CSV export
	data, err = ExportVulnerabilityReport(report, ExportFormatCSV)
	if err != nil {
		t.Fatalf("CSV export error: %v", err)
	}

	// SARIF export
	data, err = ExportVulnerabilityReport(report, ExportFormatSARIF)
	if err != nil {
		t.Fatalf("SARIF export error: %v", err)
	}
	if !json.Valid(data) {
		t.Error("SARIF export should produce valid JSON")
	}

	// Unknown format
	_, err = ExportVulnerabilityReport(report, "unknown")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestExportVulnerabilityReportBatch(t *testing.T) {
	comp1 := NewSBOMComponent("pkg1", "1.0")
	comp2 := NewSBOMComponent("pkg2", "2.0")
	reports := []*VulnerabilityReport{
		NewVulnerabilityReport(comp1),
		NewVulnerabilityReport(comp2),
	}

	data, err := ExportVulnerabilityReportBatch(reports, ExportFormatJSON)
	if err != nil {
		t.Fatalf("batch JSON export error: %v", err)
	}
	if !json.Valid(data) {
		t.Error("batch JSON export should produce valid JSON")
	}
}

func TestExportVulnerabilityReportBatch_CSV(t *testing.T) {
	comp1 := NewSBOMComponent("pkg1", "1.0")
	comp2 := NewSBOMComponent("pkg2", "2.0")
	report1 := NewVulnerabilityReport(comp1)
	report1.AddFinding(&VulnerabilityFinding{
		CVE: &CVEReference{CVEID: "CVE-2021-44228", Severity: "Critical", CVSSScore: 10.0},
	})
	report2 := NewVulnerabilityReport(comp2)
	report2.AddFinding(&VulnerabilityFinding{
		CVE: &CVEReference{CVEID: "CVE-2022-22965", Severity: "High", CVSSScore: 9.8},
	})
	reports := []*VulnerabilityReport{report1, report2}

	data, err := ExportVulnerabilityReportBatch(reports, ExportFormatCSV)
	if err != nil {
		t.Fatalf("batch CSV export error: %v", err)
	}
	csv := string(data)
	if !strings.Contains(csv, "pkg1") {
		t.Error("CSV should contain pkg1")
	}
	if !strings.Contains(csv, "pkg2") {
		t.Error("CSV should contain pkg2")
	}
	if !strings.Contains(csv, "CVE-2021-44228") {
		t.Error("CSV should contain CVE-2021-44228")
	}
	if !strings.Contains(csv, "CVE-2022-22965") {
		t.Error("CSV should contain CVE-2022-22965")
	}
}

func TestExportVulnerabilityReportBatch_Empty(t *testing.T) {
	data, err := ExportVulnerabilityReportBatch([]*VulnerabilityReport{}, ExportFormatJSON)
	if err != nil {
		t.Fatalf("batch JSON export with empty reports error: %v", err)
	}
	if !json.Valid(data) {
		t.Error("batch JSON export with empty reports should produce valid JSON")
	}
}

func TestExportVulnerabilityReportBatch_UnsupportedFormat(t *testing.T) {
	comp := NewSBOMComponent("pkg1", "1.0")
	reports := []*VulnerabilityReport{NewVulnerabilityReport(comp)}

	_, err := ExportVulnerabilityReportBatch(reports, "xml")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestExportSBOMToCycloneDX(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test-sbom")
	comp := NewSBOMComponent("test-lib", "1.0.0")
	sbom.AddComponent(comp)

	data, err := ExportSBOMToCycloneDX(sbom)
	if err != nil {
		t.Fatalf("ExportSBOMToCycloneDX error: %v", err)
	}
	if len(data) == 0 {
		t.Error("ExportSBOMToCycloneDX should return non-empty data")
	}
	if !json.Valid(data) {
		t.Error("ExportSBOMToCycloneDX should produce valid JSON")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Error("CycloneDX output should have bomFormat = CycloneDX")
	}
}

func TestExportSBOMToCycloneDX_Nil(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("expected panic for nil SBOM in ExportSBOMToCycloneDX")
		}
	}()
	ExportSBOMToCycloneDX(nil)
}

func TestExportSBOMToSPDX(t *testing.T) {
	sbom := NewSBOM(SBOMFormatSPDX, "test-sbom")
	comp := NewSBOMComponent("test-lib", "1.0.0")
	sbom.AddComponent(comp)

	data, err := ExportSBOMToSPDX(sbom)
	if err != nil {
		t.Fatalf("ExportSBOMToSPDX error: %v", err)
	}
	if len(data) == 0 {
		t.Error("ExportSBOMToSPDX should return non-empty data")
	}
	if !json.Valid(data) {
		t.Error("ExportSBOMToSPDX should produce valid JSON")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse SPDX JSON: %v", err)
	}
	if parsed["spdxVersion"] == nil {
		t.Error("SPDX output should have spdxVersion field")
	}
}

func TestExportSBOMToSPDX_Nil(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("expected panic for nil SBOM in ExportSBOMToSPDX")
		}
	}()
	ExportSBOMToSPDX(nil)
}

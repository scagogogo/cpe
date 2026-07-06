package cpeskills

import (
	"strings"
	"testing"
	"time"
)

// ---- export.go: SARIF severity 全分支 + nil report；CSV EPSS/KEV/Fix + nil ----

func TestExportToSARIF_AllSeverities(t *testing.T) {
	comp := NewSBOMComponent("pkg", "1.0")
	report := NewVulnerabilityReport(comp)
	report.AddFinding(&VulnerabilityFinding{CVE: &CVEReference{CVEID: "C1", Severity: "Critical", Description: "crit"}})
	report.AddFinding(&VulnerabilityFinding{CVE: &CVEReference{CVEID: "C2", Severity: "High", Description: "high"}})
	report.AddFinding(&VulnerabilityFinding{CVE: &CVEReference{CVEID: "C3", Severity: "Medium", Description: "med"}})
	report.AddFinding(&VulnerabilityFinding{CVE: &CVEReference{CVEID: "C4", Severity: "Low", Description: "low"}})
	report.AddFinding(&VulnerabilityFinding{CVE: &CVEReference{CVEID: "C5", Severity: "Weird", Description: "x"}})
	report.AddFinding(&VulnerabilityFinding{CVE: nil})
	// nil report / nil component 应被跳过
	reports := []*VulnerabilityReport{report, nil, {Component: nil}}

	data, err := ExportToSARIF(reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := string(data)
	for _, cve := range []string{"C1", "C2", "C3", "C4", "C5"} {
		if !strings.Contains(out, cve) {
			t.Errorf("SARIF should contain %s", cve)
		}
	}
}

func TestExportToCSV_AllFields(t *testing.T) {
	comp := NewSBOMComponent("pkg", "1.0")
	report := NewVulnerabilityReport(comp)
	report.AddFinding(&VulnerabilityFinding{
		CVE:          &CVEReference{CVEID: "CVE-X", Severity: "High", CVSSScore: 7.5},
		EPSSScore:    0.1234,
		KEVListed:    true,
		FixedVersion: "2.0",
		Reachability: "direct",
	})
	report.AddFinding(&VulnerabilityFinding{CVE: nil})
	reports := []*VulnerabilityReport{report, nil, {Component: nil}}

	data, err := ExportToCSV(reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "0.1234") {
		t.Error("CSV should contain EPSS score")
	}
	if !strings.Contains(out, "true") {
		t.Error("CSV should contain KEV=true")
	}
	if !strings.Contains(out, "2.0") {
		t.Error("CSV should contain fixed version")
	}
}

func TestExportToCSV_Empty(t *testing.T) {
	data, err := ExportToCSV(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(string(data), "Component,Version,CVE") {
		t.Error("empty CSV should still have header")
	}
}

func TestExportSBOMToCycloneDX_SPDX(t *testing.T) {
	sbom := NewSBOM(SBOMFormatSPDX, "test")
	if _, err := ExportSBOMToCycloneDX(sbom); err != nil {
		t.Fatalf("ExportSBOMToCycloneDX on SPDX sbom: %v", err)
	}
}

// ---- remediation.go: 未覆盖分支 ----

func TestFindRemediation_MediumLowEmptySeverity(t *testing.T) {
	// 已有测试只覆盖 Critical；补 Medium(2)/Low(3)/空(3 default) 优先级
	for _, sev := range []struct {
		name string
		prio int
	}{
		{"Medium", 2}, {"Low", 3}, {"", 3},
	} {
		comp := NewSBOMComponent("pkg", "1.0")
		finding := &VulnerabilityFinding{
			CVE:          &CVEReference{CVEID: "CVE-X", Severity: sev.name},
			FixedVersion: "2.0",
		}
		advice := FindRemediation(comp, []*VulnerabilityFinding{finding})
		if advice.Priority != sev.prio {
			t.Errorf("severity %q: expected priority %d, got %d", sev.name, sev.prio, advice.Priority)
		}
	}
}

func TestFindRemediation_OSVFixedVersion(t *testing.T) {
	// FixedVersion 为空，从 OSV 提取修复版本
	comp := NewSBOMComponent("pkg", "1.0")
	finding := &VulnerabilityFinding{
		CVE: &CVEReference{CVEID: "CVE-X", Severity: "High"},
		OSV: &OSVEntry{Affected: []*OSVAffected{{
			Ranges: []*OSVRange{{
				Events: []*OSVEvent{{Introduced: "0"}, {Fixed: "3.5"}},
			}},
		}}},
	}
	advice := FindRemediation(comp, []*VulnerabilityFinding{finding})
	if advice.RecommendedVersion != "3.5" {
		t.Errorf("expected RecommendedVersion '3.5' from OSV, got %q", advice.RecommendedVersion)
	}
}

func TestRemediationAdvice_HasFixAvailable_Empty(t *testing.T) {
	advice := &RemediationAdvice{}
	if advice.HasFixAvailable() {
		t.Error("expected false with empty RecommendedVersion")
	}
}

func TestRemediationAdvice_IsUrgent_NonCriticalPriority(t *testing.T) {
	// 已有测试覆盖 Critical+KEV 和 Medium；补 Priority!=0 直接返回 false
	advice := &RemediationAdvice{Priority: 1}
	if advice.IsUrgent([]*VulnerabilityFinding{{KEVListed: true}}) {
		t.Error("expected not urgent for non-critical priority")
	}
}

func TestIsBreakingChange_PreReleaseAndBuild(t *testing.T) {
	// 已有测试覆盖正常版本；补 pre-release / build metadata 分支
	// （splitVersionPrefix 先剥离 - / + 后缀再按 . 切分）
	if isBreakingChange("1.0.0-rc1", "1.0.0") {
		t.Error("expected no breaking change when only pre-release differs")
	}
	if isBreakingChange("1.0.0+build1", "1.0.0+build2") {
		t.Error("expected no breaking change when only build metadata differs")
	}
	// 主版本前缀不同 → breaking
	if !isBreakingChange("1.0.0-rc1", "2.0.0") {
		t.Error("expected breaking change for 1.x-rc → 2.x")
	}
}

// ---- ecosystem.go: CPEPartToEcosystemHint 默认分支 ----

func TestCPEPartToEcosystemHint_UnknownPart(t *testing.T) {
	// 已有测试覆盖 app/os/hw/nil；补 ShortName 非 a/o/h 的默认分支
	custom := &Part{ShortName: "x"}
	def := CPEPartToEcosystemHint(custom)
	if len(def) == 0 || def[0] != EcosystemGeneric {
		t.Errorf("expected [Generic] for unknown part, got %v", def)
	}
}

// ---- batch.go: scanComponent nil data source 分支 ----

func TestBatchScanner_Scan_NilDataSourceSkipped(t *testing.T) {
	// DataSources 含 nil 项应被跳过（不 panic）
	idx := NewCPEIndex(nil)
	bs := NewBatchScanner(idx, 2)
	bs.SetDataSources([]*VulnDataSource{nil})
	comp := NewSBOMComponent("pkg", "1.0")
	comp.SetCPE(mustParseCPE(t, "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"))
	results, err := bs.Scan([]*SBOMComponent{comp})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// ---- sbom_cyclonedx.go: metadata authors/component 解析 + ToCycloneDXJSON 元数据导出 ----

func TestParseCycloneDXJSON_MetadataAuthorsAndComponent(t *testing.T) {
	input := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {
			"timestamp": "2024-01-15T10:30:00Z",
			"tools": [{"name": "t", "vendor": "v", "version": "1.0"}],
			"authors": [{"name": "Jane", "email": "j@x.com"}, null],
			"component": {"type": "application", "name": "root-app", "version": "1.0"}
		},
		"components": []
	}`
	sbom, err := ParseCycloneDXJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sbom.Metadata.Authors) != 1 {
		t.Errorf("expected 1 author (null skipped), got %d", len(sbom.Metadata.Authors))
	}
	if sbom.Metadata.Authors[0].Name != "Jane" {
		t.Errorf("expected author Jane, got %q", sbom.Metadata.Authors[0].Name)
	}
	if sbom.Metadata.Component == nil || sbom.Metadata.Component.Name != "root-app" {
		t.Errorf("expected metadata component root-app, got %+v", sbom.Metadata.Component)
	}
}

func TestToCycloneDXJSON_MetadataExport(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test")
	sbom.SpecVersion = "1.5"
	ts, _ := time.Parse("2006-01-02T15:04:05Z", "2024-01-15T10:30:00Z")
	sbom.Metadata.Timestamp = ts
	sbom.Metadata.Tools = []*SBOMTool{{Name: "t", Vendor: "v", Version: "1.0"}}
	sbom.Metadata.Authors = []*SBOMAuthor{{Name: "Jane", Email: "j@x.com"}}
	sbom.Metadata.Component = NewSBOMComponent("root", "1.0")
	comp := NewSBOMComponent("lib", "2.0")
	comp.Type = "library"
	comp.Supplier = "Acme"
	comp.AddHash("SHA-256", "abc")
	comp.Properties = map[string]string{"k": "v"}
	comp.ExternalReferences = []*ExternalReference{{Type: "website", URL: "https://x", Comment: "c"}}
	comp.Licenses = []*License{{SPDXID: "MIT", Name: "MIT", URL: "https://mit"}}
	cpe := mustParseCPE(t, "cpe:2.3:a:lib:lib:2.0:*:*:*:*:*:*:*")
	comp.SetCPE(cpe)
	sbom.AddComponent(comp)

	data, err := sbom.ToCycloneDXJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := string(data)
	for _, s := range []string{"Jane", "root", "Acme", "MIT", "https://x", "\"k\""} {
		if !strings.Contains(out, s) {
			t.Errorf("expected output to contain %q", s)
		}
	}
}

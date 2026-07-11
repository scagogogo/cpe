package cpeskills

import (
	"strings"
	"testing"
	"time"
)

// 本文件补充 vex/epss/reachability 的未覆盖分支（已有测试覆盖主路径）。

// ---- vex.go ----

func TestVEXDocument_AddStatement_PreservesIDAndTime(t *testing.T) {
	doc := NewVEXDocument("cyclonedx", "prod-1", "myapp", "tester")
	// 带 ID 和 LastUpdated → 不应被覆盖
	customTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	stmt := &VEXStatement{
		ID:              "custom-id",
		VulnerabilityID: "CVE-2021-44228",
		Status:          VEXAffected,
		LastUpdated:     customTime,
	}
	doc.AddStatement(stmt)
	if doc.Statements[0].ID != "custom-id" {
		t.Errorf("expected custom-id preserved, got %q", doc.Statements[0].ID)
	}
	if !doc.Statements[0].LastUpdated.Equal(customTime) {
		t.Error("expected custom LastUpdated preserved")
	}
}

func TestApplyVEXToFindings_AllStatuses(t *testing.T) {
	// 已有测试覆盖 NotAffected/Fixed；补 UnderInvestigation/Affected/OSV/无CVE
	doc := NewVEXDocument("cyclonedx", "p", "app", "tester")
	doc.AddStatement(NewVEXStatement("CVE-3", "p", VEXUnderInvestigation))
	doc.AddStatement(NewVEXStatement("CVE-4", "p", VEXAffected))
	doc.AddStatement(NewVEXStatement("OSV-1", "p", VEXAffected))

	findings := []*VulnerabilityFinding{
		{CVE: &CVEReference{CVEID: "CVE-3"}},    // UnderInvestigation → 保留
		{CVE: &CVEReference{CVEID: "CVE-4"}},    // Affected → 保留
		{OSV: &OSVEntry{ID: "OSV-1"}},           // OSV ID 匹配 → 保留
		{CVE: &CVEReference{CVEID: "CVE-9999"}}, // 无 VEX → 保留
		{},                                      // 无 CVE 无 OSV → 保留
	}
	result := ApplyVEXToFindings(findings, doc)
	if len(result) != 5 {
		t.Errorf("expected 5 findings retained, got %d", len(result))
	}
}

func TestGenerateVEXFromFindings_OSVAndUnknown(t *testing.T) {
	// 已有测试覆盖 CVE+Fix；补 OSV-only 和 无CVE无OSV(unknown)
	comp := NewSBOMComponent("myapp", "1.0")
	findings := []*VulnerabilityFinding{
		{OSV: &OSVEntry{ID: "OSV-1", Summary: "osv sum"}},
		{}, // → vulnID "unknown"
	}
	doc := GenerateVEXFromFindings(comp, findings, "prod-1")
	if doc.StatementCount() != 2 {
		t.Fatalf("expected 2 statements, got %d", doc.StatementCount())
	}
	if doc.Statements[0].VulnerabilityID != "OSV-1" {
		t.Errorf("expected OSV-1, got %q", doc.Statements[0].VulnerabilityID)
	}
	if doc.Statements[1].VulnerabilityID != "unknown" {
		t.Errorf("expected unknown, got %q", doc.Statements[1].VulnerabilityID)
	}
}

func TestParseVEXDocument_InvalidJSON(t *testing.T) {
	_, err := ParseVEXDocument([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ---- epss.go ----

func TestEPSSScoreToRiskFactor_NegativeAndTiny(t *testing.T) {
	// 已有测试覆盖 0/正数；补负数和极小值（scaled<1 → clamp）
	if r := EPSSScoreToRiskFactor(-1); r != 0 {
		t.Errorf("expected 0 for negative, got %f", r)
	}
	if r := EPSSScoreToRiskFactor(0.0001); r != 0 {
		t.Errorf("expected 0 for tiny epss (scaled clamped to 1), got %f", r)
	}
}

func TestLog10Float_ZeroAndNegative(t *testing.T) {
	// 已有测试覆盖正数；补 0/负
	if log10Float(0) != 0 {
		t.Error("expected 0 for log10(0)")
	}
	if log10Float(-1) != 0 {
		t.Error("expected 0 for log10(negative)")
	}
}

func TestEPSSClient_ParseEPSSResponse(t *testing.T) {
	c := NewEPSSClient()
	// 含 cve/epss/percentile/date 列 + 数据行 + 缺列行 + 坏 float 行
	csvData := "cve,epss,percentile,date\n" +
		"CVE-2021-44228,0.95,0.999,2024-01-01\n" +
		"CVE-2022-22965,0.50,0.95,\n" +
		"bad-row\n" +
		"CVE-2023-1,not-a-number,0.5,2024-01-02\n"
	result, err := c.parseEPSSResponse(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("parseEPSSResponse: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 valid entries (bad-row and bad-float skipped), got %d", len(result))
	}
	if result["CVE-2021-44228"].EPSSScore != 0.95 {
		t.Errorf("expected 0.95, got %f", result["CVE-2021-44228"].EPSSScore)
	}
	if result["CVE-2021-44228"].Percentile != 0.999 {
		t.Errorf("expected percentile 0.999, got %f", result["CVE-2021-44228"].Percentile)
	}
	if result["CVE-2021-44228"].Date != "2024-01-01" {
		t.Errorf("expected date, got %q", result["CVE-2021-44228"].Date)
	}
}

func TestEPSSClient_ParseEPSSResponse_MissingColumns(t *testing.T) {
	c := NewEPSSClient()
	_, err := c.parseEPSSResponse(strings.NewReader("cve,percentile\nCVE-1,0.5\n"))
	if err == nil {
		t.Error("expected error for missing epss column")
	}
}

func TestEPSSClient_ParseEPSSResponse_HeaderError(t *testing.T) {
	c := NewEPSSClient()
	_, err := c.parseEPSSResponse(strings.NewReader(""))
	if err == nil {
		t.Error("expected error for empty CSV")
	}
}

func TestEPSSClient_EnrichVulnerabilityFinding_NilCases(t *testing.T) {
	c := NewEPSSClient()
	if err := c.EnrichVulnerabilityFinding(nil); err != nil {
		t.Errorf("nil finding should be no-op, got %v", err)
	}
	if err := c.EnrichVulnerabilityFinding(&VulnerabilityFinding{}); err != nil {
		t.Errorf("nil CVE should be no-op, got %v", err)
	}
	if err := c.EnrichVulnerabilityFinding(&VulnerabilityFinding{CVE: &CVEReference{}}); err != nil {
		t.Errorf("empty CVEID should be no-op, got %v", err)
	}
}

func TestEPSSClient_EnrichVulnerabilityFindings_Empty(t *testing.T) {
	c := NewEPSSClient()
	if err := c.EnrichVulnerabilityFindings(nil); err != nil {
		t.Errorf("nil findings should be no-op, got %v", err)
	}
	if err := c.EnrichVulnerabilityFindings([]*VulnerabilityFinding{}); err != nil {
		t.Errorf("empty findings should be no-op, got %v", err)
	}
}

// ---- reachability.go ----

func TestReachabilityAnalyze_PURLMatch(t *testing.T) {
	// 覆盖 OSV + PURL 匹配分支（已有测试覆盖 CVE+CPE 路径）
	graph := NewDependencyGraph()
	comp := NewSBOMComponent("lodash", "4.17.21")
	comp.SetPURL(NewPURL("npm", "", "lodash", "4.17.21"))
	graph.AddNode(comp)

	finding := &VulnerabilityFinding{
		OSV: &OSVEntry{
			ID: "OSV-1",
			Affected: []*OSVAffected{{
				Package: &OSVPackage{Name: "lodash"},
			}},
		},
	}
	a := NewDependencyGraphReachabilityAnalyzer()
	results, err := a.Analyze(graph, []*VulnerabilityFinding{finding})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestContainsCPE(t *testing.T) {
	cpes := []string{"cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*", "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*"}
	if !containsCPE(cpes, "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*") {
		t.Error("expected true for present CPE")
	}
	if containsCPE(cpes, "cpe:2.3:a:nonexistent:foo:*:*:*:*:*:*:*:*") {
		t.Error("expected false for absent CPE")
	}
	if containsCPE(nil, "anything") {
		t.Error("expected false for nil slice")
	}
}

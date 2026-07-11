package cpeskills

import (
	"testing"
	"time"
)

func TestNewVEXDocument(t *testing.T) {
	doc := NewVEXDocument("cyclonedx", "pkg:maven/org.example/app@1.0", "MyApp", "vendor")
	if doc == nil {
		t.Fatal("NewVEXDocument returned nil")
	}
	if doc.Format != "cyclonedx" {
		t.Errorf("expected format 'cyclonedx', got %q", doc.Format)
	}
	if doc.ProductID != "pkg:maven/org.example/app@1.0" {
		t.Errorf("unexpected ProductID: %q", doc.ProductID)
	}
	if doc.ProductName != "MyApp" {
		t.Errorf("unexpected ProductName: %q", doc.ProductName)
	}
	if doc.Author != "vendor" {
		t.Errorf("unexpected Author: %q", doc.Author)
	}
	if doc.Version != 1 {
		t.Errorf("expected Version 1, got %d", doc.Version)
	}
	if len(doc.Statements) != 0 {
		t.Errorf("expected 0 statements, got %d", len(doc.Statements))
	}
}

func TestNewVEXStatement(t *testing.T) {
	stmt := NewVEXStatement("CVE-2021-44228", "pkg:maven/org.apache/log4j@2.0", VEXAffected)
	if stmt == nil {
		t.Fatal("NewVEXStatement returned nil")
	}
	if stmt.VulnerabilityID != "CVE-2021-44228" {
		t.Errorf("expected VulnerabilityID 'CVE-2021-44228', got %q", stmt.VulnerabilityID)
	}
	if stmt.Status != VEXAffected {
		t.Errorf("expected Status 'affected', got %q", stmt.Status)
	}
	if stmt.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestVEXDocumentAddStatement(t *testing.T) {
	doc := NewVEXDocument("csaf", "product-1", "Test", "author")
	stmt := NewVEXStatement("CVE-2021-0001", "product-1", VEXNotAffected)
	doc.AddStatement(stmt)

	if doc.StatementCount() != 1 {
		t.Errorf("expected 1 statement, got %d", doc.StatementCount())
	}
}

func TestVEXDocumentFindStatement(t *testing.T) {
	doc := NewVEXDocument("csaf", "product-1", "Test", "author")
	doc.AddStatement(NewVEXStatement("CVE-2021-0001", "product-1", VEXAffected))
	doc.AddStatement(NewVEXStatement("CVE-2021-0002", "product-1", VEXNotAffected))

	found := doc.FindStatement("CVE-2021-0001")
	if found == nil {
		t.Fatal("expected to find CVE-2021-0001")
	}
	if found.Status != VEXAffected {
		t.Errorf("expected status 'affected', got %q", found.Status)
	}

	notFound := doc.FindStatement("CVE-2099-99999")
	if notFound != nil {
		t.Error("expected nil for non-existent CVE")
	}
}

func TestVEXDocumentGetAffectedStatements(t *testing.T) {
	doc := NewVEXDocument("csaf", "product-1", "Test", "author")
	doc.AddStatement(NewVEXStatement("CVE-2021-0001", "product-1", VEXAffected))
	doc.AddStatement(NewVEXStatement("CVE-2021-0002", "product-1", VEXNotAffected))
	doc.AddStatement(NewVEXStatement("CVE-2021-0003", "product-1", VEXFixed))

	affected := doc.GetAffectedStatements()
	if len(affected) != 1 {
		t.Errorf("expected 1 affected statement, got %d", len(affected))
	}
}

func TestVEXDocumentGetNotAffectedStatements(t *testing.T) {
	doc := NewVEXDocument("csaf", "product-1", "Test", "author")
	doc.AddStatement(NewVEXStatement("CVE-2021-0001", "product-1", VEXAffected))
	doc.AddStatement(NewVEXStatement("CVE-2021-0002", "product-1", VEXNotAffected))
	doc.AddStatement(NewVEXStatement("CVE-2021-0003", "product-1", VEXNotAffected))

	notAffected := doc.GetNotAffectedStatements()
	if len(notAffected) != 2 {
		t.Errorf("expected 2 not_affected statements, got %d", len(notAffected))
	}
}

func TestVEXDocumentToJSON(t *testing.T) {
	doc := NewVEXDocument("cyclonedx", "pkg:test@1.0", "Test", "author")
	doc.AddStatement(NewVEXStatement("CVE-2021-0001", "pkg:test@1.0", VEXAffected))

	data, err := doc.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}

	// Round-trip
	parsed, err := ParseVEXDocument(data)
	if err != nil {
		t.Fatalf("ParseVEXDocument failed: %v", err)
	}
	if parsed.StatementCount() != 1 {
		t.Errorf("round-trip: expected 1 statement, got %d", parsed.StatementCount())
	}
}

func TestParseVEXDocument(t *testing.T) {
	jsonData := `{
		"format": "cyclonedx",
		"id": "VEX-test",
		"author": "test-author",
		"timestamp": "2024-01-15T00:00:00Z",
		"lastUpdated": "2024-01-15T00:00:00Z",
		"version": 1,
		"productId": "pkg:test@1.0",
		"productName": "TestProduct",
		"statements": [
			{
				"id": "VEXSTMT-1",
				"vulnerabilityId": "CVE-2021-0001",
				"status": "affected",
				"productId": "pkg:test@1.0",
				"lastUpdated": "2024-01-15T00:00:00Z"
			}
		]
	}`

	doc, err := ParseVEXDocument([]byte(jsonData))
	if err != nil {
		t.Fatalf("ParseVEXDocument failed: %v", err)
	}
	if doc.Format != "cyclonedx" {
		t.Errorf("expected format 'cyclonedx', got %q", doc.Format)
	}
	if doc.ProductName != "TestProduct" {
		t.Errorf("expected ProductName 'TestProduct', got %q", doc.ProductName)
	}
	if doc.StatementCount() != 1 {
		t.Errorf("expected 1 statement, got %d", doc.StatementCount())
	}
}

func TestMergeVEXDocuments(t *testing.T) {
	doc1 := NewVEXDocument("csaf", "product-1", "Test", "author1")
	doc1.AddStatement(NewVEXStatement("CVE-2021-0001", "product-1", VEXAffected))

	doc2 := NewVEXDocument("csaf", "product-1", "Test", "author2")
	doc2.AddStatement(NewVEXStatement("CVE-2021-0001", "product-1", VEXFixed)) // override
	doc2.AddStatement(NewVEXStatement("CVE-2021-0002", "product-1", VEXNotAffected))

	merged := MergeVEXDocuments([]*VEXDocument{doc1, doc2})
	if merged == nil {
		t.Fatal("MergeVEXDocuments returned nil")
	}
	if merged.StatementCount() != 2 {
		t.Errorf("expected 2 statements after merge, got %d", merged.StatementCount())
	}

	// CVE-2021-0001 should have the status from doc2 (last wins)
	found := merged.FindStatement("CVE-2021-0001")
	if found == nil {
		t.Fatal("expected to find CVE-2021-0001")
	}
	if found.Status != VEXFixed {
		t.Errorf("expected status 'fixed' from doc2, got %q", found.Status)
	}
}

func TestMergeVEXDocumentsEmpty(t *testing.T) {
	merged := MergeVEXDocuments(nil)
	if merged != nil {
		t.Error("expected nil for empty input")
	}

	merged2 := MergeVEXDocuments([]*VEXDocument{})
	if merged2 != nil {
		t.Error("expected nil for empty slice")
	}
}

func TestGenerateVEXFromFindings(t *testing.T) {
	component := &SBOMComponent{
		Name:    "log4j-core",
		Version: "2.14.1",
	}

	findings := []*VulnerabilityFinding{
		{
			CVE: &CVEReference{
				CVEID:       "CVE-2021-44228",
				Description: "Log4Shell RCE",
			},
			FixAvailable: true,
			FixedVersion: "2.17.0",
		},
		{
			CVE: &CVEReference{
				CVEID:       "CVE-2021-45046",
				Description: "Log4j DoS",
			},
			FixAvailable: false,
		},
	}

	doc := GenerateVEXFromFindings(component, findings, "pkg:maven/org.apache/log4j-core@2.14.1")
	if doc == nil {
		t.Fatal("GenerateVEXFromFindings returned nil")
	}
	if doc.StatementCount() != 2 {
		t.Errorf("expected 2 statements, got %d", doc.StatementCount())
	}

	// First finding should be "fixed"
	fixed := doc.FindStatement("CVE-2021-44228")
	if fixed == nil {
		t.Fatal("expected to find CVE-2021-44228")
	}
	if fixed.Status != VEXFixed {
		t.Errorf("expected status 'fixed', got %q", fixed.Status)
	}

	// Second finding should be "affected"
	affected := doc.FindStatement("CVE-2021-45046")
	if affected == nil {
		t.Fatal("expected to find CVE-2021-45046")
	}
	if affected.Status != VEXAffected {
		t.Errorf("expected status 'affected', got %q", affected.Status)
	}
}

func TestApplyVEXToFindings(t *testing.T) {
	findings := []*VulnerabilityFinding{
		{CVE: &CVEReference{CVEID: "CVE-2021-0001"}},
		{CVE: &CVEReference{CVEID: "CVE-2021-0002"}},
		{CVE: &CVEReference{CVEID: "CVE-2021-0003"}},
	}

	doc := NewVEXDocument("csaf", "product-1", "Test", "author")
	doc.AddStatement(NewVEXStatement("CVE-2021-0001", "product-1", VEXNotAffected))
	doc.AddStatement(NewVEXStatement("CVE-2021-0002", "product-1", VEXFixed))

	filtered := ApplyVEXToFindings(findings, doc)
	if len(filtered) != 2 {
		t.Errorf("expected 2 findings after VEX filter, got %d", len(filtered))
	}

	// CVE-2021-0002 should be marked as fix available
	for _, f := range filtered {
		if f.CVE.CVEID == "CVE-2021-0002" && !f.FixAvailable {
			t.Error("expected CVE-2021-0002 to have FixAvailable=true")
		}
	}
}

func TestApplyVEXToFindingsNilDoc(t *testing.T) {
	findings := []*VulnerabilityFinding{
		{CVE: &CVEReference{CVEID: "CVE-2021-0001"}},
	}

	filtered := ApplyVEXToFindings(findings, nil)
	if len(filtered) != 1 {
		t.Errorf("expected all findings when doc is nil, got %d", len(filtered))
	}
}

func TestVEXStatusConstants(t *testing.T) {
	if VEXNotAffected != "not_affected" {
		t.Errorf("VEXNotAffected = %q", VEXNotAffected)
	}
	if VEXAffected != "affected" {
		t.Errorf("VEXAffected = %q", VEXAffected)
	}
	if VEXFixed != "fixed" {
		t.Errorf("VEXFixed = %q", VEXFixed)
	}
	if VEXUnderInvestigation != "under_investigation" {
		t.Errorf("VEXUnderInvestigation = %q", VEXUnderInvestigation)
	}
}

func TestVEXJustificationConstants(t *testing.T) {
	if VEXComponentNotPresent != "component_not_present" {
		t.Errorf("VEXComponentNotPresent = %q", VEXComponentNotPresent)
	}
	if VEXVulnerableCodeNotPresent != "vulnerable_code_not_present" {
		t.Errorf("VEXVulnerableCodeNotPresent = %q", VEXVulnerableCodeNotPresent)
	}
	if VEXVulnerableCodeNotInExecutePath != "vulnerable_code_not_in_execute_path" {
		t.Errorf("VEXVulnerableCodeNotInExecutePath = %q", VEXVulnerableCodeNotInExecutePath)
	}
}

func TestVEXStatementWithJustification(t *testing.T) {
	stmt := NewVEXStatement("CVE-2021-0001", "product-1", VEXNotAffected)
	stmt.Justification = VEXComponentNotPresent
	stmt.ImpactStatement = "The vulnerable component is not included in this product."
	stmt.ActionStatement = "No action required."
	stmt.ActionStatementTimestamp = time.Now()

	if stmt.Justification != VEXComponentNotPresent {
		t.Errorf("expected justification %q, got %q", VEXComponentNotPresent, stmt.Justification)
	}
}

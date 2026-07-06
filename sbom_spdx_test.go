package cpeskills

import (
	"encoding/json"
	"testing"
)

func TestParseSPDXJSON(t *testing.T) {
	// 最小的 SPDX 2.3 JSON
	input := `{
		"SPDXID": "SPDXRef-DOCUMENT",
		"spdxVersion": "SPDX-2.3",
		"name": "test-sbom",
		"dataLicense": "CC0-1.0",
		"creationInfo": {
			"created": "2024-01-15T10:30:00Z",
			"creators": ["Organization: scagogogo", "Tool: cpe-cli"]
		},
		"packages": [
			{
				"SPDXID": "SPDXRef-lodash",
				"name": "lodash",
				"versionInfo": "4.17.21",
				"downloadLocation": "NOASSERTION",
				"filesAnalyzed": false,
				"licenseConcluded": "MIT",
				"licenseDeclared": "MIT",
				"copyrightText": "NOASSERTION",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/lodash@4.17.21"
					}
				]
			}
		],
		"relationships": [
			{
				"spdxElementId": "SPDXRef-DOCUMENT",
				"relatedSpdxElement": "SPDXRef-lodash",
				"relationshipType": "DESCRIBES"
			}
		]
	}`

	sbom, err := ParseSPDXJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sbom.Format != SBOMFormatSPDX {
		t.Errorf("expected format %s, got %s", SBOMFormatSPDX, sbom.Format)
	}
	if sbom.SpecVersion != "SPDX-2.3" {
		t.Errorf("expected spec version 'SPDX-2.3', got %q", sbom.SpecVersion)
	}
	if sbom.Name != "test-sbom" {
		t.Errorf("expected name 'test-sbom', got %q", sbom.Name)
	}
	if sbom.ComponentCount() != 1 {
		t.Fatalf("expected 1 component, got %d", sbom.ComponentCount())
	}

	comp := sbom.Components[0]
	if comp.Name != "lodash" {
		t.Errorf("expected name 'lodash', got %q", comp.Name)
	}
	if comp.Version != "4.17.21" {
		t.Errorf("expected version '4.17.21', got %q", comp.Version)
	}
	if comp.PURL == nil || comp.PURL.Name != "lodash" {
		t.Error("expected PURL to be parsed")
	}
	if len(comp.Licenses) != 1 || comp.Licenses[0].SPDXID != "MIT" {
		t.Error("expected MIT license")
	}
}

func TestParseSPDXJSON_Invalid(t *testing.T) {
	_, err := ParseSPDXJSON([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestToSPDXJSON(t *testing.T) {
	sbom := NewSBOM(SBOMFormatSPDX, "test-sbom")
	sbom.SpecVersion = "SPDX-2.3"

	comp := NewSBOMComponent("lodash", "4.17.21")
	comp.Type = "library"
	comp.SetPURL(NewPURL("npm", "", "lodash", "4.17.21"))
	cpe, _ := Parse("cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*")
	comp.SetCPE(cpe)
	comp.Supplier = "npm"
	comp.Licenses = []*License{NewLicense("MIT", "MIT License")}
	sbom.AddComponent(comp)

	sbom.AddDependency("SPDXRef-DOCUMENT", []string{"SPDXRef-lodash"})

	data, err := sbom.ToSPDXJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if result["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("expected spdxVersion 'SPDX-2.3', got %v", result["spdxVersion"])
	}
	if result["name"] != "test-sbom" {
		t.Errorf("expected name 'test-sbom', got %v", result["name"])
	}

	packages, ok := result["packages"].([]interface{})
	if !ok || len(packages) != 1 {
		t.Fatalf("expected 1 package")
	}

	pkgMap := packages[0].(map[string]interface{})
	if pkgMap["name"] != "lodash" {
		t.Errorf("expected name 'lodash', got %v", pkgMap["name"])
	}
}

func TestParseSPDXJSON_RoundTrip(t *testing.T) {
	input := `{
		"SPDXID": "SPDXRef-DOCUMENT",
		"spdxVersion": "SPDX-2.3",
		"name": "test-sbom",
		"dataLicense": "CC0-1.0",
		"creationInfo": {
			"created": "2024-01-15T10:30:00Z",
			"creators": ["Organization: test"]
		},
		"packages": [
			{
				"SPDXID": "SPDXRef-express",
				"name": "express",
				"versionInfo": "4.17.1",
				"downloadLocation": "NOASSERTION",
				"filesAnalyzed": false,
				"licenseConcluded": "MIT",
				"licenseDeclared": "MIT",
				"copyrightText": "NOASSERTION",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/express@4.17.1"
					}
				]
			}
		]
	}`

	sbom, err := ParseSPDXJSON([]byte(input))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	exported, err := sbom.ToSPDXJSON()
	if err != nil {
		t.Fatalf("export error: %v", err)
	}

	sbom2, err := ParseSPDXJSON(exported)
	if err != nil {
		t.Fatalf("re-parse error: %v", err)
	}

	if sbom2.ComponentCount() != 1 {
		t.Errorf("expected 1 component after round-trip, got %d", sbom2.ComponentCount())
	}
}

func TestParseSPDXJSON_Empty(t *testing.T) {
	input := `{
		"SPDXID": "SPDXRef-DOCUMENT",
		"spdxVersion": "SPDX-2.3",
		"name": "empty-sbom",
		"dataLicense": "CC0-1.0",
		"creationInfo": {
			"created": "2024-01-01T00:00:00Z",
			"creators": ["Organization: test"]
		}
	}`

	sbom, err := ParseSPDXJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sbom.ComponentCount() != 0 {
		t.Errorf("expected 0 components, got %d", sbom.ComponentCount())
	}
}

func TestParseSPDXLicenseIdentifier(t *testing.T) {
	// 简单许可证
	l := parseSPDXLicenseIdentifier("MIT")
	if l == nil || l.SPDXID != "MIT" {
		t.Errorf("expected MIT, got %v", l)
	}

	// 复合 AND 表达式
	l = parseSPDXLicenseIdentifier("MIT AND Apache-2.0")
	if l == nil || l.SPDXID != "MIT" {
		t.Errorf("expected first license MIT, got %v", l)
	}

	// 复合 OR 表达式
	l = parseSPDXLicenseIdentifier("GPL-2.0-only OR MIT")
	if l == nil || l.SPDXID != "GPL-2.0-only" {
		t.Errorf("expected first license GPL-2.0-only, got %v", l)
	}

	// 空字符串
	l = parseSPDXLicenseIdentifier("")
	if l != nil {
		t.Error("expected nil for empty string")
	}
}

func TestParseSPDXSupplier(t *testing.T) {
	s := parseSPDXSupplier("Organization: scagogogo")
	if s != "scagogogo" {
		t.Errorf("expected 'scagogogo', got %q", s)
	}

	s = parseSPDXSupplier("NOASSERTION")
	if s != "" {
		t.Errorf("expected empty for NOASSERTION, got %q", s)
	}

	s = parseSPDXSupplier("")
	if s != "" {
		t.Errorf("expected empty, got %q", s)
	}
}

func TestParseSPDXJSON_FullPackage(t *testing.T) {
	// 覆盖 cpe23Type ref、checksums、supplier、NOASSERTION/NONE license
	input := `{
		"SPDXID": "SPDXRef-DOCUMENT",
		"spdxVersion": "SPDX-2.3",
		"name": "test",
		"dataLicense": "CC0-1.0",
		"creationInfo": {"created": "2024-01-15T10:30:00Z"},
		"packages": [
			{
				"SPDXID": "SPDXRef-1",
				"name": "pkg1",
				"versionInfo": "1.0",
				"downloadLocation": "NOASSERTION",
				"filesAnalyzed": false,
				"licenseConcluded": "NOASSERTION",
				"licenseDeclared": "NOASSERTION",
				"copyrightText": "NOASSERTION",
				"supplier": "Organization: Acme Corp",
				"checksums": [
					{"algorithm": "SHA256", "checksumValue": "abc123"}
				],
				"externalRefs": [
					{"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:acme:pkg1:1.0:*:*:*:*:*:*:*"},
					{"referenceType": "purl", "referenceLocator": "pkg:npm/pkg1@1.0"}
				]
			},
			{
				"SPDXID": "SPDXRef-2",
				"name": "pkg2",
				"downloadLocation": "NOASSERTION",
				"filesAnalyzed": false,
				"licenseDeclared": "NONE",
				"supplier": "NOASSERTION",
				"externalRefs": [
					{"referenceType": "cpe22Type", "referenceLocator": "cpe:/acme:pkg2"}
				]
			},
			{
				"SPDXID": "SPDXRef-3",
				"name": "pkg3",
				"downloadLocation": "NOASSERTION",
				"filesAnalyzed": false,
				"licenseDeclared": "GPL-3.0-only",
				"supplier": "Person: Jane Doe"
			}
		]
	}`
	sbom, err := ParseSPDXJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sbom.ComponentCount() != 3 {
		t.Fatalf("expected 3, got %d", sbom.ComponentCount())
	}
	c1 := sbom.Components[0]
	if c1.CPE == nil || string(c1.CPE.Vendor) != "acme" {
		t.Errorf("expected CPE acme, got %+v", c1.CPE)
	}
	if c1.Hashes["sha256"] != "abc123" {
		t.Errorf("expected sha256 hash, got %v", c1.Hashes)
	}
	if c1.Supplier != "Acme Corp" {
		t.Errorf("expected supplier Acme Corp, got %q", c1.Supplier)
	}
	if len(c1.Licenses) != 0 {
		t.Errorf("expected no license for NOASSERTION, got %+v", c1.Licenses)
	}
	// pkg2: NONE license, cpe22Type, NOASSERTION supplier
	c2 := sbom.Components[1]
	if c2.Supplier != "" {
		t.Errorf("expected empty supplier for NOASSERTION, got %q", c2.Supplier)
	}
	if len(c2.Licenses) != 0 {
		t.Errorf("expected no license for NONE, got %+v", c2.Licenses)
	}
	// pkg3: Person supplier
	c3 := sbom.Components[2]
	if c3.Supplier != "Jane Doe" {
		t.Errorf("expected Jane Doe, got %q", c3.Supplier)
	}
}

func TestParseSPDXJSON_InvalidTimestamp(t *testing.T) {
	input := `{
		"SPDXID": "SPDXRef-DOC",
		"spdxVersion": "SPDX-2.3",
		"name": "test",
		"dataLicense": "CC0-1.0",
		"creationInfo": {"created": "not-a-date"},
		"packages": []
	}`
	sbom, err := ParseSPDXJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sbom.Metadata.Timestamp.IsZero() {
		t.Error("expected zero time for invalid timestamp")
	}
}

func TestParseSPDXSupplier_NoPrefix(t *testing.T) {
	// supplier 无 "Type: " 前缀 → 原样返回
	s := parseSPDXSupplier("Just A Name")
	if s != "Just A Name" {
		t.Errorf("expected 'Just A Name', got %q", s)
	}
}

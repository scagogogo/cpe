package cpeskills

import (
	"encoding/json"
	"testing"
)

func TestParseCycloneDXJSON(t *testing.T) {
	// 最小的 CycloneDX JSON
	input := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {
			"timestamp": "2024-01-15T10:30:00Z",
			"tools": [
				{"name": "cpe-cli", "vendor": "scagogogo", "version": "1.0.0"}
			]
		},
		"components": [
			{
				"type": "library",
				"name": "lodash",
				"version": "4.17.21",
				"purl": "pkg:npm/lodash@4.17.21",
				"cpe": "cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*",
				"licenses": [
					{"license": {"id": "MIT"}}
				],
				"hashes": [
					{"alg": "SHA-256", "content": "abc123"}
				]
			}
		],
		"dependencies": [
			{"ref": "lodash@4.17.21", "dependsOn": []}
		]
	}`

	sbom, err := ParseCycloneDXJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sbom.Format != SBOMFormatCycloneDX {
		t.Errorf("expected format %s, got %s", SBOMFormatCycloneDX, sbom.Format)
	}
	if sbom.SpecVersion != "1.5" {
		t.Errorf("expected spec version '1.5', got %q", sbom.SpecVersion)
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
	if comp.Type != "library" {
		t.Errorf("expected type 'library', got %q", comp.Type)
	}
	if comp.PURL == nil || comp.PURL.Name != "lodash" {
		t.Error("expected PURL to be parsed")
	}
	if comp.CPE == nil || string(comp.CPE.Vendor) != "lodash" {
		t.Errorf("expected CPE to be parsed, got vendor %q", string(comp.CPE.Vendor))
	}
	if len(comp.Licenses) != 1 || comp.Licenses[0].SPDXID != "MIT" {
		t.Error("expected MIT license")
	}
	if comp.Hashes["sha-256"] != "abc123" {
		t.Errorf("expected hash 'abc123', got %q", comp.Hashes["sha-256"])
	}
	if sbom.DependencyCount() != 1 {
		t.Errorf("expected 1 dependency, got %d", sbom.DependencyCount())
	}

	// 元数据
	if len(sbom.Metadata.Tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(sbom.Metadata.Tools))
	}
	if sbom.Metadata.Tools[0].Name != "cpe-cli" {
		t.Errorf("expected tool name 'cpe-cli', got %q", sbom.Metadata.Tools[0].Name)
	}
}

func TestParseCycloneDXJSON_Invalid(t *testing.T) {
	_, err := ParseCycloneDXJSON([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestToCycloneDXJSON(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test")
	sbom.SpecVersion = "1.5"
	sbom.SerialNumber = "urn:uuid:test-123"

	comp := NewSBOMComponent("lodash", "4.17.21")
	comp.Type = "library"
	comp.SetPURL(NewPURL("npm", "", "lodash", "4.17.21"))
	cpe, _ := Parse("cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*")
	comp.SetCPE(cpe)
	comp.AddHash("SHA-256", "abc123")
	comp.Supplier = "npm"
	sbom.AddComponent(comp)

	sbom.AddDependency("lodash@4.17.21", []string{})

	data, err := sbom.ToCycloneDXJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 验证输出的 JSON 结构
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if result["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat 'CycloneDX', got %v", result["bomFormat"])
	}

	components, ok := result["components"].([]interface{})
	if !ok || len(components) != 1 {
		t.Fatalf("expected 1 component in output")
	}

	compMap := components[0].(map[string]interface{})
	if compMap["name"] != "lodash" {
		t.Errorf("expected name 'lodash', got %v", compMap["name"])
	}
}

func TestParseCycloneDXJSON_RoundTrip(t *testing.T) {
	original := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"components": [
			{
				"type": "library",
				"name": "express",
				"version": "4.17.1",
				"purl": "pkg:npm/express@4.17.1"
			}
		]
	}`

	sbom, err := ParseCycloneDXJSON([]byte(original))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	exported, err := sbom.ToCycloneDXJSON()
	if err != nil {
		t.Fatalf("export error: %v", err)
	}

	// Re-parse exported data
	sbom2, err := ParseCycloneDXJSON(exported)
	if err != nil {
		t.Fatalf("re-parse error: %v", err)
	}

	if sbom2.ComponentCount() != 1 {
		t.Errorf("expected 1 component after round-trip, got %d", sbom2.ComponentCount())
	}
	if sbom2.Components[0].Name != "express" {
		t.Errorf("expected name 'express', got %q", sbom2.Components[0].Name)
	}
}

func TestParseCycloneDXJSON_Empty(t *testing.T) {
	input := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"version": 1
	}`

	sbom, err := ParseCycloneDXJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sbom.ComponentCount() != 0 {
		t.Errorf("expected 0 components, got %d", sbom.ComponentCount())
	}
}

func TestParseCycloneDXJSON_FullComponent(t *testing.T) {
	// 覆盖 license(name 无 id)、supplier、properties、external references
	input := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {"timestamp": "2024-01-15T10:30:00.000Z"},
		"components": [
			{
				"type": "library",
				"name": "full-comp",
				"version": "1.0",
				"purl": "pkg:npm/full-comp@1.0",
				"cpe": "cpe:2.3:a:full:full-comp:1.0:*:*:*:*:*:*:*",
				"licenses": [{"license": {"name": "Custom License"}}],
				"hashes": [{"alg": "SHA-512", "content": "def456"}],
				"supplier": {"name": "Acme Corp"},
				"properties": [{"name": "key", "value": "val"}],
				"externalReferences": [{"type": "website", "url": "https://example.com", "comment": "site"}]
			},
			{
				"type": "library",
				"name": "bad-purl",
				"purl": "not-a-purl",
				"cpe": "not-a-cpe"
			}
		]
	}`
	sbom, err := ParseCycloneDXJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sbom.ComponentCount() != 2 {
		t.Fatalf("expected 2, got %d", sbom.ComponentCount())
	}
	comp := sbom.Components[0]
	if len(comp.Licenses) != 1 || comp.Licenses[0].Name != "Custom License" {
		t.Errorf("expected custom license, got %+v", comp.Licenses)
	}
	if comp.Hashes["sha-512"] != "def456" {
		t.Errorf("expected sha-512 hash, got %v", comp.Hashes)
	}
	if comp.Supplier != "Acme Corp" {
		t.Errorf("expected supplier, got %q", comp.Supplier)
	}
	if comp.Properties["key"] != "val" {
		t.Errorf("expected property, got %v", comp.Properties)
	}
	if len(comp.ExternalReferences) != 1 || comp.ExternalReferences[0].URL != "https://example.com" {
		t.Errorf("expected external ref, got %+v", comp.ExternalReferences)
	}
	// bad-purl/bad-cpe 不应导致解析失败，只是 PURL/CPE 为 nil
	comp2 := sbom.Components[1]
	if comp2.PURL != nil {
		t.Errorf("expected nil PURL for bad purl, got %+v", comp2.PURL)
	}
	if comp2.CPE != nil {
		t.Errorf("expected nil CPE for bad cpe, got %+v", comp2.CPE)
	}
	// metadata timestamp（.000Z layout）
	if sbom.Metadata.Timestamp.IsZero() {
		t.Error("expected metadata timestamp parsed")
	}
}

func TestParseCycloneDXJSON_TimezoneOffset(t *testing.T) {
	// 覆盖 -07:00 时区偏移 layout
	input := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {"timestamp": "2024-01-15T10:30:00-07:00"},
		"components": []
	}`
	sbom, err := ParseCycloneDXJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sbom.Metadata.Timestamp.IsZero() {
		t.Error("expected timestamp with tz offset parsed")
	}
}

func TestParseCycloneDXJSON_InvalidTimestamp(t *testing.T) {
	// 无效 timestamp → time.Time{}
	input := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"metadata": {"timestamp": "not-a-date"},
		"components": []
	}`
	sbom, err := ParseCycloneDXJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sbom.Metadata.Timestamp.IsZero() {
		t.Error("expected zero time for invalid timestamp")
	}
}

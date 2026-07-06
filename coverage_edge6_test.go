package cpeskills

import (
	"encoding/json"
	"strings"
	"testing"
)

// 本文件补充 sbom_enhanced.go 与 sbom_spdx.go 的未覆盖分支：
// MergeSBOMs 重复版本/nil/metadata 合并、SPDX DEPENDS_ON 解析、
// convertComponentToSPDX 的 supplier/hashes/purl 分支等。

// ---- sbom_enhanced: MergeSBOMs 重复 key 保留高版本 ----

func TestMergeSBOMs_DuplicateKeepHigherVersion(t *testing.T) {
	sbom1 := NewSBOM(SBOMFormatCycloneDX, "m")
	c1 := NewSBOMComponent("lib-a", "1.0.0")
	c1.BomRef = "ref-a"
	sbom1.AddComponent(c1)

	sbom2 := NewSBOM(SBOMFormatCycloneDX, "m")
	c2 := NewSBOMComponent("lib-a", "2.0.0")
	c2.BomRef = "ref-a" // 同 key
	sbom2.AddComponent(c2)

	merged, err := MergeSBOMs([]*SBOM{sbom1, sbom2}, SBOMFormatCycloneDX, "m")
	if err != nil {
		t.Fatalf("MergeSBOMs: %v", err)
	}
	if len(merged.Components) != 1 {
		t.Fatalf("expected 1 deduped component, got %d", len(merged.Components))
	}
	if merged.Components[0].Version != "2.0.0" {
		t.Errorf("expected higher version 2.0.0, got %q", merged.Components[0].Version)
	}
}

func TestMergeSBOMs_NilSBOMSkipped(t *testing.T) {
	sbom1 := NewSBOM(SBOMFormatCycloneDX, "m")
	sbom1.AddComponent(NewSBOMComponent("lib-a", "1.0.0"))

	// 含 nil SBOM → 跳过不 panic
	merged, err := MergeSBOMs([]*SBOM{sbom1, nil}, SBOMFormatCycloneDX, "m")
	if err != nil {
		t.Fatalf("MergeSBOMs with nil: %v", err)
	}
	if len(merged.Components) != 1 {
		t.Errorf("expected 1 component (nil skipped), got %d", len(merged.Components))
	}
}

func TestMergeSBOMs_MetadataMerged(t *testing.T) {
	sbom1 := NewSBOM(SBOMFormatCycloneDX, "m")
	sbom1.Metadata = &SBOMMetadata{
		Tools:   []*SBOMTool{{Name: "tool-a"}},
		Authors: []*SBOMAuthor{{Name: "author-a"}},
	}
	sbom1.AddComponent(NewSBOMComponent("lib-a", "1.0.0"))

	sbom2 := NewSBOM(SBOMFormatCycloneDX, "m")
	sbom2.Metadata = &SBOMMetadata{
		Tools:   []*SBOMTool{{Name: "tool-b"}},
		Authors: []*SBOMAuthor{{Name: "author-b"}},
	}
	sbom2.AddComponent(NewSBOMComponent("lib-b", "1.0.0"))

	merged, err := MergeSBOMs([]*SBOM{sbom1, sbom2}, SBOMFormatCycloneDX, "m")
	if err != nil {
		t.Fatalf("MergeSBOMs: %v", err)
	}
	if len(merged.Metadata.Tools) != 2 {
		t.Errorf("expected 2 tools, got %v", merged.Metadata.Tools)
	}
	if len(merged.Metadata.Authors) != 2 {
		t.Errorf("expected 2 authors, got %v", merged.Metadata.Authors)
	}
}

func TestMergeSBOMs_DependenciesMerged(t *testing.T) {
	sbom1 := NewSBOM(SBOMFormatCycloneDX, "m")
	sbom1.AddDependency("ref-a", []string{"ref-b"})

	sbom2 := NewSBOM(SBOMFormatCycloneDX, "m")
	sbom2.AddDependency("ref-c", []string{"ref-d"})

	merged, err := MergeSBOMs([]*SBOM{sbom1, sbom2}, SBOMFormatCycloneDX, "m")
	if err != nil {
		t.Fatalf("MergeSBOMs: %v", err)
	}
	if len(merged.Dependencies) != 2 {
		t.Errorf("expected 2 deps, got %d", len(merged.Dependencies))
	}
}

// ---- sbom_enhanced: DiffSBOMs nil 分支 ----

func TestDiffSBOMs_BothNil(t *testing.T) {
	diff := DiffSBOMs(nil, nil)
	if diff == nil {
		t.Fatal("expected non-nil diff")
	}
	if diff.HasChanges() {
		t.Error("expected no changes for both nil")
	}
}

func TestDiffSBOMs_OldNil(t *testing.T) {
	newSBOM := NewSBOM(SBOMFormatCycloneDX, "n")
	newSBOM.AddComponent(NewSBOMComponent("lib-a", "1.0"))
	diff := DiffSBOMs(nil, newSBOM)
	if len(diff.Added) != 1 {
		t.Errorf("expected 1 added, got %d", len(diff.Added))
	}
}

// ---- sbom_spdx: DEPENDS_ON 关系解析 ----

func TestParseSPDXJSON_WithDependencies(t *testing.T) {
	doc := map[string]any{
		"spdxVersion": "SPDX-2.3",
		"name":        "test",
		"packages": []map[string]any{
			{"SPDXID": "SPDXRef-pkg-a", "name": "pkg-a", "versionInfo": "1.0"},
			{"SPDXID": "SPDXRef-pkg-b", "name": "pkg-b", "versionInfo": "2.0"},
		},
		"relationships": []map[string]any{
			{"spdxElementId": "SPDXRef-pkg-a", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-pkg-b"},
			{"spdxElementId": "SPDXRef-pkg-a", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-pkg-b"},
		},
	}
	data, _ := json.Marshal(doc)
	sbom, err := ParseSPDXJSON(data)
	if err != nil {
		t.Fatalf("ParseSPDXJSON: %v", err)
	}
	if len(sbom.Components) != 2 {
		t.Errorf("expected 2 packages, got %d", len(sbom.Components))
	}
	// DEPENDS_ON 关系应生成依赖
	if len(sbom.Dependencies) == 0 {
		t.Error("expected dependencies from DEPENDS_ON")
	}
}

func TestParseSPDXJSON_RelatedElementMissing(t *testing.T) {
	// DEPENDS_ON 但 related element 不在 idToRef → 跳过
	doc := map[string]any{
		"spdxVersion": "SPDX-2.3",
		"packages": []map[string]any{
			{"SPDXID": "SPDXRef-pkg-a", "name": "pkg-a"},
		},
		"relationships": []map[string]any{
			{"spdxElementId": "SPDXRef-pkg-a", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-missing"},
		},
	}
	data, _ := json.Marshal(doc)
	sbom, err := ParseSPDXJSON(data)
	if err != nil {
		t.Fatalf("ParseSPDXJSON: %v", err)
	}
	if len(sbom.Dependencies) != 0 {
		t.Errorf("expected 0 deps (missing related), got %d", len(sbom.Dependencies))
	}
}

// ---- sbom_spdx: ToSPDXJSON 的 supplier/hashes/purl 分支 ----

func TestToSPDXJSON_SupplierHashesPURL(t *testing.T) {
	sbom := NewSBOM(SBOMFormatSPDX, "test")
	comp := NewSBOMComponent("pkg-a", "1.0")
	comp.Supplier = "Acme"
	comp.AddHash("sha256", "abc123")
	comp.SetPURL(NewPURL("npm", "", "pkg-a", "1.0"))
	sbom.AddComponent(comp)

	data, err := sbom.ToSPDXJSON()
	if err != nil {
		t.Fatalf("ToSPDXJSON: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "Acme") {
		t.Error("expected supplier in output")
	}
	if !strings.Contains(s, "sha256") {
		t.Error("expected sha256 checksum in output")
	}
}

package cpeskills

import (
	"strings"
	"testing"
)

func TestSBOMDiff_TotalChanges(t *testing.T) {
	d := &SBOMDiff{
		Added:   []*SBOMComponent{{Name: "a"}},
		Removed: []*SBOMComponent{{Name: "b"}},
		Changed: []*SBOMComponentChange{{Component: &SBOMComponent{Name: "c"}}},
	}
	if got := d.TotalChanges(); got != 3 {
		t.Errorf("expected 3, got %d", got)
	}
	if !d.HasChanges() {
		t.Error("expected HasChanges=true")
	}
}

func TestSBOMDiff_TotalChangesZero(t *testing.T) {
	d := &SBOMDiff{Unchanged: 5}
	if got := d.TotalChanges(); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
	if d.HasChanges() {
		t.Error("expected HasChanges=false")
	}
}

func TestSBOMDiff_Summary(t *testing.T) {
	d := &SBOMDiff{
		Added:   []*SBOMComponent{{Name: "a"}},
		Removed: []*SBOMComponent{{Name: "b"}},
		Changed: []*SBOMComponentChange{{}},
	}
	s := d.Summary()
	if !strings.Contains(s, "1 added") || !strings.Contains(s, "1 removed") || !strings.Contains(s, "1 changed") {
		t.Errorf("unexpected summary: %s", s)
	}
}

func TestSBOMDiff_SummaryNoChanges(t *testing.T) {
	d := &SBOMDiff{Unchanged: 3}
	s := d.Summary()
	if !strings.Contains(s, "No changes") || !strings.Contains(s, "3 components unchanged") {
		t.Errorf("expected no-changes summary, got: %s", s)
	}
}

func TestSortComponentsByRisk(t *testing.T) {
	comps := []*SBOMComponent{
		{Name: "a", CPE: mustParseCPE(t, "cpe:2.3:a:x:a:1:*:*:*:*:*:*:*")},
		{Name: "b", CPE: mustParseCPE(t, "cpe:2.3:a:x:b:1:*:*:*:*:*:*:*")},
	}
	scores := SortComponentsByRisk(comps, nil)
	if len(scores) != 2 {
		t.Errorf("expected 2 scores, got %d", len(scores))
	}
}

func TestFilterComponentsByEcosystem(t *testing.T) {
	purl, _ := ParsePURL("pkg:npm/left-pad@1.0")
	comps := []*SBOMComponent{
		{Name: "npm-pkg", PURL: purl},
		{Name: "no-purl"},
		{Name: "golang-pkg", PURL: &PackageURL{Type: "golang", Name: "x/y"}},
	}
	got := FilterComponentsByEcosystem(comps, EcosystemNPM)
	if len(got) != 1 || got[0].Name != "npm-pkg" {
		t.Errorf("expected 1 npm-pkg, got %+v", got)
	}
}

func TestFilterComponentsByType(t *testing.T) {
	comps := []*SBOMComponent{
		{Name: "a", Type: "library"},
		{Name: "b", Type: "application"},
		{Name: "c", Type: "Library"}, // 大小写不敏感
	}
	got := FilterComponentsByType(comps, "library")
	if len(got) != 2 {
		t.Errorf("expected 2, got %d", len(got))
	}
}

func TestEnrichComponentWithPedigree(t *testing.T) {
	c := &SBOMComponent{Name: "x"}
	EnrichComponentWithPedigree(c, NewSBOMPedigree())
	if c.Properties["cpe:hasPedigree"] != "true" {
		t.Error("expected hasPedigree property set")
	}
	// 已有 Properties 不应被覆盖
	c2 := &SBOMComponent{Name: "y", Properties: map[string]string{"k": "v"}}
	EnrichComponentWithPedigree(c2, nil)
	if c2.Properties["k"] != "v" {
		t.Error("existing property lost")
	}
}

func TestEnrichComponentWithEvidence(t *testing.T) {
	c := &SBOMComponent{Name: "x"}
	ev := []*SBOMEvidence{
		NewSBOMEvidence("license", "MIT", 0.9),
		NewSBOMEvidence("copyright", "2024", 0.8),
	}
	EnrichComponentWithEvidence(c, ev)
	if c.Properties["cpe:evidence:0:field"] != "license" {
		t.Errorf("expected evidence field, got %v", c.Properties)
	}
	if c.Properties["cpe:evidence:1:value"] != "2024" {
		t.Errorf("expected evidence value, got %v", c.Properties)
	}
}

func TestSetComponentCopyright_NilProperties(t *testing.T) {
	// 覆盖 SetComponentCopyright 的 Properties==nil 分支
	c := &SBOMComponent{Name: "x"}
	SetComponentCopyright(c, "Copyright 2024")
	if c.Properties["cpe:copyright"] != "Copyright 2024" {
		t.Error("expected copyright property")
	}
}

func TestComponentKey(t *testing.T) {
	// PURL 优先
	purl, _ := ParsePURL("pkg:npm/left-pad@1.0")
	c := &SBOMComponent{Name: "a", PURL: purl}
	if k := componentKey(c); !strings.HasPrefix(k, "purl:") {
		t.Errorf("expected purl: prefix, got %s", k)
	}
	// CPE 回退
	c2 := &SBOMComponent{Name: "b", CPE: &CPE{Cpe23: "cpe:2.3:a:x:b:1:*:*:*:*:*:*:*"}}
	if k := componentKey(c2); !strings.HasPrefix(k, "cpe:") {
		t.Errorf("expected cpe: prefix, got %s", k)
	}
	// BomRef 回退
	c3 := &SBOMComponent{Name: "c", BomRef: "ref-1"}
	if k := componentKey(c3); k != "ref:ref-1" {
		t.Errorf("expected ref:ref-1, got %s", k)
	}
	// name 回退
	c4 := &SBOMComponent{Name: "d"}
	if k := componentKey(c4); k != "name:d" {
		t.Errorf("expected name:d, got %s", k)
	}
}

func TestDeduplicateComponents_ByPURL(t *testing.T) {
	// 现有测试用 BomRef，这里补 PURL 去重路径
	purl, _ := ParsePURL("pkg:npm/left-pad@1.0")
	comps := []*SBOMComponent{
		{Name: "a", PURL: purl},
		{Name: "a-dup", PURL: purl},
		{Name: "c"},
	}
	got := DeduplicateComponents(comps)
	if len(got) != 2 {
		t.Errorf("expected 2 unique, got %d", len(got))
	}
}

func TestValidateSBOM_Nil(t *testing.T) {
	issues := ValidateSBOM(nil)
	if len(issues) != 1 || issues[0] != "SBOM is nil" {
		t.Errorf("expected nil issue, got %v", issues)
	}
}

func TestValidateSBOM_Issues(t *testing.T) {
	sbom := &SBOM{
		Format: SBOMFormatUnknown,
		Components: []*SBOMComponent{
			{Name: "no-ref"}, // 空 BomRef
			{Name: "ok", BomRef: "ref-ok"},
		},
		Dependencies: []*SBOMDependency{
			{Ref: "missing-ref"}, // 不存在的 ref
			{Ref: "ref-ok", DependsOn: []string{"missing-target"}},
		},
	}
	issues := ValidateSBOM(sbom)
	joined := strings.Join(issues, ";")
	if !strings.Contains(joined, "format is unknown") {
		t.Errorf("expected format unknown issue, got: %s", joined)
	}
	if !strings.Contains(joined, "name is empty") {
		t.Errorf("expected empty name issue, got: %s", joined)
	}
	if !strings.Contains(joined, "empty BomRef") {
		t.Errorf("expected empty BomRef issue, got: %s", joined)
	}
	if !strings.Contains(joined, "does not match") {
		t.Errorf("expected dependency mismatch issue, got: %s", joined)
	}
}

func TestValidateSBOM_Valid(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test")
	sbom.Components = []*SBOMComponent{{Name: "ok", BomRef: "ref-ok"}}
	sbom.Dependencies = []*SBOMDependency{{Ref: "ref-ok"}}
	issues := ValidateSBOM(sbom)
	if len(issues) != 0 {
		t.Errorf("expected no issues, got: %v", issues)
	}
}

func TestUpdateSBOMTimestamp(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test")
	UpdateSBOMTimestamp(sbom)
	if sbom.CreatedAt.IsZero() {
		t.Error("expected CreatedAt set")
	}
	// Metadata 分支
	sbom.Metadata = &SBOMMetadata{}
	UpdateSBOMTimestamp(sbom)
	if sbom.Metadata.Timestamp.IsZero() {
		t.Error("expected Metadata.Timestamp set")
	}
}

func TestSBOMPedigree_AddAncestor_AddCommit(t *testing.T) {
	p := NewSBOMPedigree()
	if p.Ancestors == nil || p.Commits == nil {
		t.Fatal("expected initialized slices")
	}
	p.AddAncestor(&SBOMComponent{Name: "ancestor"})
	p.AddCommit("abc123", "https://example.com/repo", "fix bug")
	if len(p.Ancestors) != 1 {
		t.Errorf("expected 1 ancestor, got %d", len(p.Ancestors))
	}
	if len(p.Commits) != 1 || p.Commits[0].UID != "abc123" {
		t.Errorf("expected 1 commit abc123, got %+v", p.Commits)
	}
}

// mustParseCPE 是测试辅助：解析失败即 fatal。
func mustParseCPE(t *testing.T, s string) *CPE {
	t.Helper()
	c, err := Parse(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return c
}

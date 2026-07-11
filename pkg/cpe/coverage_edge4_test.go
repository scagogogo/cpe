package cpeskills

import (
	"testing"
)

// 本文件补充 purl/sbom/vex 的未覆盖分支：ParsePURL error 路径、
// SBOMComponent 方法、generateBomRef 分支、AddStatement 自动生成分支等。

// ---- purl.go: ParsePURL error 路径 ----

func TestParsePURL_Errors(t *testing.T) {
	cases := []struct {
		name   string
		purl   string
		errSub string
	}{
		{"missing type and name", "pkg", "missing type and name"},
		{"invalid qualifiers", "pkg:npm/foo?badpair", "qualifier"},
		{"empty name", "pkg:npm/", "name cannot be empty"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePURL(tt.purl)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errSub)
			}
		})
	}
}

func TestParsePURL_WithNamespaceAndQualifiers(t *testing.T) {
	// 含 namespace + version + qualifiers
	p, err := ParsePURL("pkg:maven/org.apache/log4j@2.14?classifier=jar")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	if p.Namespace != "org.apache" {
		t.Errorf("namespace=%q", p.Namespace)
	}
	if p.Name != "log4j" {
		t.Errorf("name=%q", p.Name)
	}
	if p.Version != "2.14" {
		t.Errorf("version=%q", p.Version)
	}
	if p.Qualifiers["classifier"] != "jar" {
		t.Errorf("qualifier=%v", p.Qualifiers["classifier"])
	}
}

// ---- purl.go: NewPURLWithEcosystem error + Copy + Equal ----

func TestNewPURLWithEcosystem_Unknown(t *testing.T) {
	_, err := NewPURLWithEcosystem(Ecosystem("unknown"), "", "pkg", "1.0")
	if err == nil {
		t.Error("expected error for unknown ecosystem")
	}
}

// 已有 TestPackageURL_Equals 覆盖 nil/version/name 分支；补 qualifier 差异分支。
func TestPackageURL_Equals_QualifierDiff(t *testing.T) {
	a := NewPURL("npm", "", "pkg", "1.0")
	a.Qualifiers["x"] = "1"

	// 不同 qualifiers 数量
	c := NewPURL("npm", "", "pkg", "1.0")
	if a.Equals(c) {
		t.Error("differing qualifier count should not be equal")
	}

	// 不同 value
	d := NewPURL("npm", "", "pkg", "1.0")
	d.Qualifiers["x"] = "2"
	if a.Equals(d) {
		t.Error("differing qualifier value should not be equal")
	}

	// 相同 qualifiers 应相等
	b := NewPURL("npm", "", "pkg", "1.0")
	b.Qualifiers["x"] = "1"
	if !a.Equals(b) {
		t.Error("same qualifiers should be equal")
	}
}

// ---- purl.go: String with subpath + qualifiers ----

func TestPackageURL_String_Full(t *testing.T) {
	p := NewPURL("npm", "@scope", "pkg", "1.0")
	p.Qualifiers["arch"] = "x64"
	p.Subpath = "sub/file"
	s := p.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
}

// ---- sbom.go: generateBomRef / defaultSpecVersion ----

func TestGenerateBomRef_AllBranches(t *testing.T) {
	// PURL 分支
	c1 := NewSBOMComponent("foo", "1.0")
	c1.SetPURL(NewPURL("npm", "", "foo", "1.0"))
	if ref := generateBomRef(c1); ref == "" {
		t.Error("expected non-empty PURL bomRef")
	}

	// CPE 分支（无 PURL）
	c2 := NewSBOMComponent("foo", "1.0")
	c2.CPE = &CPE{Part: *PartApplication, Vendor: "apache", ProductName: "log4j"}
	if ref := generateBomRef(c2); ref == "" {
		t.Error("expected non-empty CPE bomRef")
	}

	// 既无 PURL 也无 CPE → name@version
	c3 := NewSBOMComponent("foo", "1.0")
	if ref := generateBomRef(c3); ref != "foo@1.0" {
		t.Errorf("expected foo@1.0, got %q", ref)
	}
}

func TestDefaultSpecVersion(t *testing.T) {
	if v := defaultSpecVersion(SBOMFormatCycloneDX); v != "1.5" {
		t.Errorf("cyclonedx version=%q", v)
	}
	if v := defaultSpecVersion(SBOMFormatSPDX); v != "2.3" {
		t.Errorf("spdx version=%q", v)
	}
	if v := defaultSpecVersion(SBOMFormat("unknown")); v != "1.0" {
		t.Errorf("default version=%q", v)
	}
}

// ---- sbom.go: FindVulnerableComponents CVE 匹配分支 ----

func TestSBOM_FindVulnerableComponents_CPEMatch(t *testing.T) {
	cpe := &CPE{Part: *PartApplication, Vendor: "apache", ProductName: "log4j"}
	cpe.Cpe23 = "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"
	comp := NewSBOMComponent("log4j", "2.14")
	comp.CPE = cpe
	sbom := &SBOM{Components: []*SBOMComponent{comp}}

	// CVE 的 AffectedCPEs 含组件 CPE → 匹配，并触发 maxCVSS 分支
	cve := &CVEReference{
		CVEID:        "CVE-2021-44228",
		CVSSScore:    9.8,
		AffectedCPEs: []string{"cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"},
	}
	results := sbom.FindVulnerableComponents([]*CVEReference{cve})
	if len(results) == 0 {
		t.Fatal("expected 1 vulnerable component, got 0")
	}
}

func TestSBOM_FindVulnerableComponents_CPECveMatch(t *testing.T) {
	// 覆盖 component.CPE.Cve == cveRef.CVEID 分支
	cpe := &CPE{Part: *PartApplication, Vendor: "apache", ProductName: "log4j"}
	cpe.Cve = "CVE-2021-44228"
	comp := NewSBOMComponent("log4j", "2.14")
	comp.CPE = cpe
	sbom := &SBOM{Components: []*SBOMComponent{comp}}

	cve := &CVEReference{CVEID: "CVE-2021-44228", CVSSScore: 7.5}
	results := sbom.FindVulnerableComponents([]*CVEReference{cve})
	if len(results) == 0 {
		t.Fatal("expected 1 vulnerable component via CPE.Cve match")
	}
}

// ---- vex.go: AddStatement 自动生成 ID 和 LastUpdated ----

func TestVEXDocument_AddStatement_AutoGenerate(t *testing.T) {
	doc := NewVEXDocument("cyclonedx", "p", "app", "tester")
	// 不设 ID 和 LastUpdated → 自动生成
	stmt := &VEXStatement{
		VulnerabilityID: "CVE-2021-44228",
		Status:          VEXAffected,
	}
	doc.AddStatement(stmt)
	if doc.Statements[0].ID == "" {
		t.Error("expected auto-generated ID")
	}
	if doc.Statements[0].LastUpdated.IsZero() {
		t.Error("expected auto-set LastUpdated")
	}
}

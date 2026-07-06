package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件补充 cve/vex/relation/normalize/dict/reach/risk/batch/export 子命令的
// JSON 输出分支与 error 路径。

// ---- relation: JSON + error ----

func TestCLI_Relation_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "relation",
		"cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*",
		"cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("relation json: %v", err)
	}
	if !strings.Contains(out, "relation") {
		t.Errorf("expected relation field, got: %s", out)
	}
}

func TestCLI_Relation_InvalidCriteria(t *testing.T) {
	_, err := runCLI(t, "relation", "not-a-cpe", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err == nil {
		t.Error("expected error for invalid criteria CPE")
	}
}

func TestCLI_Relation_InvalidTarget(t *testing.T) {
	_, err := runCLI(t, "relation", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*", "not-a-cpe")
	if err == nil {
		t.Error("expected error for invalid target CPE")
	}
}

// ---- normalize: --vendor + JSON + error ----

func TestCLI_Normalize_Vendor(t *testing.T) {
	out, err := runCLI(t, "normalize", "--vendor", "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("normalize --vendor: %v", err)
	}
	if !strings.Contains(out, "windows") {
		t.Errorf("expected windows in output, got: %s", out)
	}
}

func TestCLI_Normalize_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "normalize", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("normalize json: %v", err)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected log4j, got: %s", out)
	}
}

func TestCLI_Normalize_Invalid(t *testing.T) {
	_, err := runCLI(t, "normalize", "not-a-cpe")
	if err == nil {
		t.Error("expected error for invalid CPE")
	}
}

// ---- cve: validate JSON + extract/sort JSON + invalid ----

func TestCLI_CVE_Validate_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "cve", "validate", "CVE-2021-44228")
	if err != nil {
		t.Fatalf("cve validate json: %v", err)
	}
	if !strings.Contains(out, "valid") {
		t.Errorf("expected valid field, got: %s", out)
	}
}

func TestCLI_CVE_Validate_Invalid_JSON(t *testing.T) {
	// 无效 CVE，json 模式不返回 error（输出 valid:false）
	out, err := runCLIJSON(t, "cve", "validate", "NOT-A-CVE")
	if err != nil {
		t.Fatalf("cve validate invalid json: %v", err)
	}
	if !strings.Contains(out, "false") {
		t.Errorf("expected false, got: %s", out)
	}
}

func TestCLI_CVE_Extract_JSON(t *testing.T) {
	withStdin(t, "found CVE-2021-44228 and CVE-2022-22965 in scan")
	out, err := runCLIJSON(t, "cve", "extract")
	if err != nil {
		t.Fatalf("cve extract json: %v", err)
	}
	if !strings.Contains(out, "cves") {
		t.Errorf("expected cves field, got: %s", out)
	}
}

func TestCLI_CVE_Sort_JSON(t *testing.T) {
	withStdin(t, "CVE-2022-22965\nCVE-2021-44228\nCVE-2020-1234\n")
	out, err := runCLIJSON(t, "cve", "sort")
	if err != nil {
		t.Fatalf("cve sort json: %v", err)
	}
	if !strings.Contains(out, "CVE-2020-1234") {
		t.Errorf("expected sorted CVEs, got: %s", out)
	}
}

// ---- vex: parse JSON + error ----

func TestCLI_VEX_Parse_JSON(t *testing.T) {
	// 先用 json 模式 build 一个 VEX 文件，再 parse
	out, err := runCLIJSON(t, "vex", "build",
		"--product", "myapp", "--cve", "CVE-2021-44228",
		"--status", "not_affected",
		"--justification", "component_not_present")
	if err != nil {
		t.Fatalf("vex build: %v", err)
	}
	doc := filepath.Join(t.TempDir(), "vex.json")
	if err := os.WriteFile(doc, []byte(out), 0644); err != nil {
		t.Fatal(err)
	}
	out2, err := runCLIJSON(t, "vex", "parse", doc)
	if err != nil {
		t.Fatalf("vex parse json: %v", err)
	}
	if !strings.Contains(out2, "myapp") && !strings.Contains(out2, "product") {
		t.Errorf("expected product in output, got: %s", out2)
	}
}

func TestCLI_VEX_Parse_Text(t *testing.T) {
	// 用 json 模式 build 出有效 VEX 文档，再用 text 模式 parse
	out, err := runCLIJSON(t, "vex", "build",
		"--product", "myapp", "--cve", "CVE-2021-44228",
		"--status", "affected")
	if err != nil {
		t.Fatalf("vex build: %v", err)
	}
	doc := filepath.Join(t.TempDir(), "vex.json")
	if err := os.WriteFile(doc, []byte(out), 0644); err != nil {
		t.Fatal(err)
	}
	out2, err := runCLI(t, "vex", "parse", doc)
	if err != nil {
		t.Fatalf("vex parse text: %v", err)
	}
	if !strings.Contains(out2, "VEX Document") {
		t.Errorf("expected VEX Document header, got: %s", out2)
	}
}

func TestCLI_VEX_Parse_ReadError(t *testing.T) {
	_, err := runCLI(t, "vex", "parse", "/nonexistent/vex.json")
	if err == nil {
		t.Error("expected error for nonexistent vex file")
	}
}

func TestCLI_VEX_Parse_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)
	_, err := runCLI(t, "vex", "parse", path)
	if err == nil {
		t.Error("expected error for invalid vex json")
	}
}

func TestCLI_VEX_Build_TextOutput(t *testing.T) {
	out, err := runCLI(t, "vex", "build",
		"--product", "myapp", "--cve", "CVE-2021-44228",
		"--status", "affected", "--author", "tester")
	if err != nil {
		t.Fatalf("vex build text: %v", err)
	}
	if !strings.Contains(out, "Built VEX document") {
		t.Errorf("expected Built VEX document, got: %s", out)
	}
}

// ---- dict: parse/search JSON + error ----

func TestCLI_Dict_Parse_JSON(t *testing.T) {
	xml := writeDictFixture(t)
	out, err := runCLIJSON(t, "dict", "parse", xml)
	if err != nil {
		t.Fatalf("dict parse json: %v", err)
	}
	if !strings.Contains(out, "items") && !strings.Contains(out, "Items") {
		t.Errorf("expected items, got: %s", out)
	}
}

func TestCLI_Dict_Parse_ReadError(t *testing.T) {
	_, err := runCLI(t, "dict", "parse", "/nonexistent/dict.xml")
	if err == nil {
		t.Error("expected error for nonexistent dict file")
	}
}

func TestCLI_Dict_Parse_InvalidXML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.xml")
	os.WriteFile(path, []byte("not xml"), 0644)
	_, err := runCLI(t, "dict", "parse", path)
	if err == nil {
		t.Error("expected error for invalid dict xml")
	}
}

func TestCLI_Dict_Search_JSON(t *testing.T) {
	xml := writeDictFixture(t)
	out, err := runCLIJSON(t, "dict", "search", xml, "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("dict search json: %v", err)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected log4j, got: %s", out)
	}
}

func TestCLI_Dict_Search_ReadError(t *testing.T) {
	_, err := runCLI(t, "dict", "search", "/nonexistent/dict.xml", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err == nil {
		t.Error("expected error for nonexistent dict search file")
	}
}

func TestCLI_Dict_Search_InvalidCPE(t *testing.T) {
	xml := writeDictFixture(t)
	_, err := runCLI(t, "dict", "search", xml, "not-a-cpe")
	if err == nil {
		t.Error("expected error for invalid criteria CPE")
	}
}

// ---- reach: JSON + error ----

func TestCLI_Reach_Analyze_JSON(t *testing.T) {
	sbom := makeSBOMFixture(t)
	nvd := makeNVDFixture(t)
	out, err := runCLIJSON(t, "reach", "analyze", "--sbom", sbom, "--nvd", nvd)
	if err != nil {
		t.Fatalf("reach analyze json: %v", err)
	}
	if !strings.Contains(out, "total") {
		t.Errorf("expected total field, got: %s", out)
	}
}

func TestCLI_Reach_Analyze_SBOMError(t *testing.T) {
	nvd := makeNVDFixture(t)
	_, err := runCLI(t, "reach", "analyze", "--sbom", "/nonexistent/sbom.json", "--nvd", nvd)
	if err == nil {
		t.Error("expected error for nonexistent reach sbom")
	}
}

func TestCLI_Reach_Analyze_NVDError(t *testing.T) {
	sbom := makeSBOMFixture(t)
	_, err := runCLI(t, "reach", "analyze", "--sbom", sbom, "--nvd", "/nonexistent/nvd.json")
	if err == nil {
		t.Error("expected error for nonexistent reach nvd")
	}
}

// ---- risk: JSON + --priority + error ----

func TestCLI_Risk_Score_JSON(t *testing.T) {
	sbom := makeSBOMFixture(t)
	nvd := makeNVDFixture(t)
	out, err := runCLIJSON(t, "risk", "score", "--sbom", sbom, "--nvd", nvd)
	if err != nil {
		t.Fatalf("risk score json: %v", err)
	}
	if !strings.Contains(out, "[") {
		t.Errorf("expected json array, got: %s", out)
	}
}

func TestCLI_Risk_Score_Priority(t *testing.T) {
	sbom := makeSBOMFixture(t)
	nvd := makeNVDFixture(t)
	out, err := runCLI(t, "risk", "score", "--sbom", sbom, "--nvd", nvd, "--priority", "critical")
	if err != nil {
		t.Fatalf("risk score priority: %v", err)
	}
	if !strings.Contains(out, "Risk Scores") {
		t.Errorf("expected Risk Scores header, got: %s", out)
	}
}

func TestCLI_Risk_Score_SBOMError(t *testing.T) {
	nvd := makeNVDFixture(t)
	_, err := runCLI(t, "risk", "score", "--sbom", "/nonexistent/sbom.json", "--nvd", nvd)
	if err == nil {
		t.Error("expected error for nonexistent risk sbom")
	}
}

func TestCLI_Risk_Score_InvalidSBOMJSON(t *testing.T) {
	nvd := makeNVDFixture(t)
	path := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)
	_, err := runCLI(t, "risk", "score", "--sbom", path, "--nvd", nvd)
	if err == nil {
		t.Error("expected error for invalid risk sbom json")
	}
}

// ---- batch: match/scan JSON + error ----

func TestCLI_Batch_Match_JSON(t *testing.T) {
	dir := t.TempDir()
	crit := filepath.Join(dir, "crit.txt")
	tgt := filepath.Join(dir, "tgt.txt")
	const cpe = "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*\n"
	os.WriteFile(crit, []byte(cpe), 0644)
	os.WriteFile(tgt, []byte(cpe), 0644)
	out, err := runCLIJSON(t, "batch", "match", "--criteria", crit, "--targets", tgt)
	if err != nil {
		t.Fatalf("batch match json: %v", err)
	}
	if !strings.Contains(out, "count") && !strings.Contains(out, "Count") {
		t.Errorf("expected count, got: %s", out)
	}
}

func TestCLI_Batch_Match_CriteriaError(t *testing.T) {
	dir := t.TempDir()
	tgt := filepath.Join(dir, "tgt.txt")
	os.WriteFile(tgt, []byte("cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*\n"), 0644)
	_, err := runCLI(t, "batch", "match", "--criteria", "/nonexistent/crit.txt", "--targets", tgt)
	if err == nil {
		t.Error("expected error for nonexistent criteria file")
	}
}

func TestCLI_Batch_Match_TargetsError(t *testing.T) {
	dir := t.TempDir()
	crit := filepath.Join(dir, "crit.txt")
	os.WriteFile(crit, []byte("cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*\n"), 0644)
	_, err := runCLI(t, "batch", "match", "--criteria", crit, "--targets", "/nonexistent/tgt.txt")
	if err == nil {
		t.Error("expected error for nonexistent targets file")
	}
}

func TestCLI_Batch_Scan_JSON(t *testing.T) {
	sbom := makeSBOMFixture(t)
	nvd := makeNVDFixture(t)
	out, err := runCLIJSON(t, "batch", "scan", "--sbom", sbom, "--nvd", nvd)
	if err != nil {
		t.Fatalf("batch scan json: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Errorf("expected json array, got: %s", out)
	}
}

func TestCLI_Batch_Scan_SBOMError(t *testing.T) {
	nvd := makeNVDFixture(t)
	_, err := runCLI(t, "batch", "scan", "--sbom", "/nonexistent/sbom.json", "--nvd", nvd)
	if err == nil {
		t.Error("expected error for nonexistent batch scan sbom")
	}
}

func TestCLI_Batch_Scan_InvalidSBOMJSON(t *testing.T) {
	nvd := makeNVDFixture(t)
	path := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)
	_, err := runCLI(t, "batch", "scan", "--sbom", path, "--nvd", nvd)
	if err == nil {
		t.Error("expected error for invalid batch scan sbom json")
	}
}

// ---- export: csv/sarif --output + error ----

func TestCLI_Export_CSV_OutputFile(t *testing.T) {
	sbom := makeSBOMFixture(t)
	nvd := makeNVDFixture(t)
	out := filepath.Join(t.TempDir(), "out.csv")
	if _, err := runCLI(t, "export", "csv", "--sbom", sbom, "--nvd", nvd, "--output", out); err != nil {
		t.Fatalf("export csv --output: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), "Component") {
		t.Errorf("expected CSV header in file, got: %s", string(data))
	}
}

func TestCLI_Export_SARIF_JSON(t *testing.T) {
	// SARIF 本身即 JSON；不用 -o json（与 export 的 -o output flag 冲突）
	sbom := makeSBOMFixture(t)
	nvd := makeNVDFixture(t)
	out, err := runCLI(t, "export", "sarif", "--sbom", sbom, "--nvd", nvd)
	if err != nil {
		t.Fatalf("export sarif: %v", err)
	}
	if !strings.Contains(out, "runs") {
		t.Errorf("expected runs field, got: %s", out)
	}
}

func TestCLI_Export_SARIF_OutputFile(t *testing.T) {
	sbom := makeSBOMFixture(t)
	nvd := makeNVDFixture(t)
	out := filepath.Join(t.TempDir(), "out.sarif")
	if _, err := runCLI(t, "export", "sarif", "--sbom", sbom, "--nvd", nvd, "--output", out); err != nil {
		t.Fatalf("export sarif --output: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), "sarif") && !strings.Contains(string(data), "runs") {
		t.Errorf("expected sarif content, got: %s", string(data))
	}
}

func TestCLI_Export_CSV_SBOMError(t *testing.T) {
	nvd := makeNVDFixture(t)
	_, err := runCLI(t, "export", "csv", "--sbom", "/nonexistent/sbom.json", "--nvd", nvd)
	if err == nil {
		t.Error("expected error for nonexistent export sbom")
	}
}

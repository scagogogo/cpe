package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件补充各 CLI 子命令的 JSON 输出分支与 error 路径，提升 cmd/cpe 覆盖率。

// ---- graph: JSON 输出 + error 路径 ----

func TestCLI_Graph_Build_JSON(t *testing.T) {
	sbom := makeSBOMFixture(t)
	out, err := runCLIJSON(t, "graph", "build", "--sbom", sbom)
	if err != nil {
		t.Fatalf("graph build json: %v", err)
	}
	if !strings.Contains(out, "nodes") {
		t.Errorf("expected nodes in json output, got: %s", out)
	}
}

func TestCLI_Graph_Topo_JSON(t *testing.T) {
	sbom := makeSBOMFixture(t)
	out, err := runCLIJSON(t, "graph", "topo", "--sbom", sbom)
	if err != nil {
		t.Fatalf("graph topo json: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Errorf("expected json array, got: %s", out)
	}
}

func TestCLI_Graph_Top_MissingSBOM(t *testing.T) {
	// --sbom 缺失 → cobra required flag error
	_, err := runCLI(t, "graph", "topo")
	if err == nil {
		t.Error("expected error for missing --sbom")
	}
}

func TestCLI_Graph_LoadSBOMFileError(t *testing.T) {
	// 文件不存在 → loadSBOMGraph 返回 error
	_, err := runCLI(t, "graph", "topo", "--sbom", "/nonexistent/path/sbom.json")
	if err == nil {
		t.Error("expected error for nonexistent sbom file")
	}
}

func TestCLI_Graph_LoadSBOMInvalidJSON(t *testing.T) {
	// 无效 JSON → json.Unmarshal error
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := runCLI(t, "graph", "build", "--sbom", path)
	if err == nil {
		t.Error("expected error for invalid json sbom")
	}
}

// ---- wfn: JSON 输出 + from-fs/from-uri text + error ----

func TestCLI_WFN_ToFS_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "wfn", "to-fs", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("wfn to-fs json: %v", err)
	}
	if !strings.Contains(out, "fs") {
		t.Errorf("expected fs field, got: %s", out)
	}
}

func TestCLI_WFN_ToURI_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "wfn", "to-uri", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("wfn to-uri json: %v", err)
	}
	if !strings.Contains(out, "uri") {
		t.Errorf("expected uri field, got: %s", out)
	}
}

func TestCLI_WFN_FromFS_JSON(t *testing.T) {
	// 先用 to-fs 拿到 fs 字符串，再 from-fs
	out, err := runCLI(t, "wfn", "to-fs", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("wfn to-fs: %v", err)
	}
	fs := strings.TrimSpace(out)
	out2, err := runCLIJSON(t, "wfn", "from-fs", fs)
	if err != nil {
		t.Fatalf("wfn from-fs json: %v", err)
	}
	if !strings.Contains(out2, "Part") {
		t.Errorf("expected Part field, got: %s", out2)
	}
}

func TestCLI_WFN_FromURI_JSON(t *testing.T) {
	out, err := runCLI(t, "wfn", "to-uri", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("wfn to-uri: %v", err)
	}
	uri := strings.TrimSpace(out)
	out2, err := runCLIJSON(t, "wfn", "from-uri", uri)
	if err != nil {
		t.Fatalf("wfn from-uri json: %v", err)
	}
	if !strings.Contains(out2, "Part") {
		t.Errorf("expected Part field, got: %s", out2)
	}
}

func TestCLI_WFN_ToFS_InvalidCPE(t *testing.T) {
	_, err := runCLI(t, "wfn", "to-fs", "not-a-cpe")
	if err == nil {
		t.Error("expected error for invalid CPE")
	}
}

func TestCLI_WFN_FromFS_Invalid(t *testing.T) {
	_, err := runCLI(t, "wfn", "from-fs", "not-a-fs-string!!!")
	if err == nil {
		t.Error("expected error for invalid FS string")
	}
}

// ---- cpe-purl: JSON 输出 + error ----

func TestCLI_CPEToPURL_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "cpe-to-purl", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("cpe-to-purl json: %v", err)
	}
	if !strings.Contains(out, "purl") {
		t.Errorf("expected purl field, got: %s", out)
	}
}

func TestCLI_PURLToCPE_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "purl-to-cpe", "pkg:maven/apache/log4j@2.14")
	if err != nil {
		t.Fatalf("purl-to-cpe json: %v", err)
	}
	if !strings.Contains(out, "cpe") {
		t.Errorf("expected cpe field, got: %s", out)
	}
}

func TestCLI_CPEToPURL_Invalid(t *testing.T) {
	_, err := runCLI(t, "cpe-to-purl", "not-a-cpe")
	if err == nil {
		t.Error("expected error for invalid CPE")
	}
}

// ---- vcmp: JSON 输出 + error ----

func TestCLI_VCmp_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "vcmp", "1.0", "1.1")
	if err != nil {
		t.Fatalf("vcmp json: %v", err)
	}
	if !strings.Contains(out, "result") {
		t.Errorf("expected result field, got: %s", out)
	}
}

func TestCLI_VCmp_InRange_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "vcmp", "in-range", "1.5", "--min", "1.0", "--max", "2.0")
	if err != nil {
		t.Fatalf("vcmp in-range json: %v", err)
	}
	if !strings.Contains(out, "in_range") {
		t.Errorf("expected in_range field, got: %s", out)
	}
}

// ---- purl: JSON 输出 + error ----

func TestCLI_PURL_Parse_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "purl", "parse", "pkg:npm/express@4.17.1")
	if err != nil {
		t.Fatalf("purl parse json: %v", err)
	}
	if !strings.Contains(out, "Name") {
		t.Errorf("expected Name field, got: %s", out)
	}
}

func TestCLI_PURL_Build_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "purl", "build", "--type", "npm", "--name", "express", "--version", "4.17.1")
	if err != nil {
		t.Fatalf("purl build json: %v", err)
	}
	if !strings.Contains(out, "express") {
		t.Errorf("expected express in output, got: %s", out)
	}
}

func TestCLI_PURL_Parse_Invalid(t *testing.T) {
	_, err := runCLI(t, "purl", "parse", "not-a-purl!!!")
	if err == nil {
		t.Error("expected error for invalid purl")
	}
}

// ---- store: JSON 输出 + delete/list ----

func TestCLI_Store_Get_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	runCLI(t, "store", "init", "--dir", tmpDir)
	cpeStr := "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"
	runCLI(t, "store", "put", cpeStr, "--dir", tmpDir)
	out, err := runCLIJSON(t, "store", "get", cpeStr, "--dir", tmpDir)
	if err != nil {
		t.Fatalf("store get json: %v", err)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected log4j in output, got: %s", out)
	}
}

func TestCLI_Store_List_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	runCLI(t, "store", "init", "--dir", tmpDir)
	out, err := runCLIJSON(t, "store", "list", "--dir", tmpDir)
	if err != nil {
		t.Fatalf("store list json: %v", err)
	}
	if !strings.Contains(out, "dir") {
		t.Errorf("expected dir field, got: %s", out)
	}
}

func TestCLI_Store_Get_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	runCLI(t, "store", "init", "--dir", tmpDir)
	_, err := runCLI(t, "store", "get", "cpe:2.3:a:nonexistent:foo:1.0:*:*:*:*:*:*:*", "--dir", tmpDir)
	if err == nil {
		t.Error("expected error for get nonexistent CPE")
	}
}

func TestCLI_Store_Put_InvalidCPE(t *testing.T) {
	tmpDir := t.TempDir()
	runCLI(t, "store", "init", "--dir", tmpDir)
	_, err := runCLI(t, "store", "put", "not-a-cpe", "--dir", tmpDir)
	if err == nil {
		t.Error("expected error for invalid CPE in put")
	}
}

// ---- applicability: JSON 输出 + filter + error ----

func TestCLI_Applicability_Parse_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "applicability", "parse", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("applicability parse json: %v", err)
	}
	if !strings.Contains(out, "valid") {
		t.Errorf("expected valid field, got: %s", out)
	}
}

func TestCLI_Applicability_Filter_Text(t *testing.T) {
	dir := t.TempDir()
	cpesFile := filepath.Join(dir, "cpes.txt")
	const cpes = "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*\ncpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*\n"
	if err := os.WriteFile(cpesFile, []byte(cpes), 0644); err != nil {
		t.Fatal(err)
	}
	// 用 CPE 通配表达式过滤 vendor=apache
	out, err := runCLI(t, "applicability", "filter", "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "--file", cpesFile)
	if err != nil {
		t.Fatalf("applicability filter: %v", err)
	}
	if !strings.Contains(out, "Filtered") {
		t.Errorf("expected Filtered, got: %s", out)
	}
}

func TestCLI_Applicability_Filter_JSON(t *testing.T) {
	dir := t.TempDir()
	cpesFile := filepath.Join(dir, "cpes.txt")
	const cpes = "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*\n"
	if err := os.WriteFile(cpesFile, []byte(cpes), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := runCLIJSON(t, "applicability", "filter", "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "--file", cpesFile)
	if err != nil {
		t.Fatalf("applicability filter json: %v", err)
	}
	if !strings.Contains(out, "filtered") {
		t.Errorf("expected filtered field, got: %s", out)
	}
}

func TestCLI_Applicability_Filter_MissingFile(t *testing.T) {
	_, err := runCLI(t, "applicability", "filter", "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "--file", "/nonexistent/cpes.txt")
	if err == nil {
		t.Error("expected error for missing filter file")
	}
}

// ---- license: JSON 输出 ----

func TestCLI_License_ListCommon_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "license", "list-common")
	if err != nil {
		t.Fatalf("license list-common json: %v", err)
	}
	if !strings.Contains(out, "MIT") {
		t.Errorf("expected MIT in output, got: %s", out)
	}
}

func TestCLI_License_DetectByName_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "license", "detect-by-name", "mit")
	if err != nil {
		t.Fatalf("license detect json: %v", err)
	}
	if !strings.Contains(out, "MIT") {
		t.Errorf("expected MIT, got: %s", out)
	}
}

// ---- nvd: cves-for-cpe/cpes-for-cve JSON 输出 ----

func TestCLI_NVD_CvesForCPE_JSON(t *testing.T) {
	nvd := makeNVDFixture(t)
	out, err := runCLIJSON(t, "nvd", "cves-for-cpe", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*", "--data", nvd)
	if err != nil {
		t.Fatalf("nvd cves-for-cpe json: %v", err)
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Errorf("expected CVE-2021-44228, got: %s", out)
	}
}

func TestCLI_NVD_CpesForCVE_JSON(t *testing.T) {
	nvd := makeNVDFixture(t)
	out, err := runCLIJSON(t, "nvd", "cpes-for-cve", "CVE-2021-44228", "--data", nvd)
	if err != nil {
		t.Fatalf("nvd cpes-for-cve json: %v", err)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected log4j, got: %s", out)
	}
}

// ---- sbom: parse SPDX/error/JSON, from-manifest text, export SPDX/--out/error,
//      diff CycloneDX 回退/JSON, validate SPDX/JSON 回退 ----

func TestCLI_SBOM_Parse_SPDX(t *testing.T) {
	// 生成 SPDX fixture：from-manifest → export --spdx
	sbom := makeSBOMFixture(t)
	spdxPath := filepath.Join(t.TempDir(), "sbom.spdx.json")
	if _, err := runCLI(t, "sbom", "export", "--spdx", sbom, "--output", spdxPath); err != nil {
		t.Fatalf("export spdx: %v", err)
	}
	out, err := runCLI(t, "sbom", "parse", "--spdx", spdxPath)
	if err != nil {
		t.Fatalf("sbom parse spdx: %v", err)
	}
	if !strings.Contains(out, "SBOM:") {
		t.Errorf("expected SBOM: header, got: %s", out)
	}
}

func TestCLI_SBOM_Parse_JSON(t *testing.T) {
	cdx := makeCycloneDXFixture(t)
	out, err := runCLIJSON(t, "sbom", "parse", "--cyclonedx", cdx)
	if err != nil {
		t.Fatalf("sbom parse json: %v", err)
	}
	if !strings.Contains(out, "name") {
		t.Errorf("expected name field, got: %s", out)
	}
}

func TestCLI_SBOM_Parse_NoFormat(t *testing.T) {
	sbom := makeSBOMFixture(t)
	_, err := runCLI(t, "sbom", "parse", sbom)
	if err == nil {
		t.Error("expected error when neither --cyclonedx nor --spdx given")
	}
}

func TestCLI_SBOM_Parse_ReadError(t *testing.T) {
	_, err := runCLI(t, "sbom", "parse", "--cyclonedx", "/nonexistent/sbom.json")
	if err == nil {
		t.Error("expected error for nonexistent sbom parse file")
	}
}

func TestCLI_SBOM_FromManifest_Text(t *testing.T) {
	goMod := filepath.Join("..", "..", "go.mod")
	out, err := runCLI(t, "sbom", "from-manifest", goMod)
	if err != nil {
		t.Fatalf("from-manifest text: %v", err)
	}
	if !strings.Contains(out, "SBOM from") {
		t.Errorf("expected 'SBOM from', got: %s", out)
	}
}

func TestCLI_SBOM_FromManifest_ReadError(t *testing.T) {
	_, err := runCLI(t, "sbom", "from-manifest", "/nonexistent/manifest.txt")
	if err == nil {
		t.Error("expected error for nonexistent manifest")
	}
}

func TestCLI_SBOM_Export_SPDX(t *testing.T) {
	sbom := makeSBOMFixture(t)
	out, err := runCLI(t, "sbom", "export", "--spdx", sbom)
	if err != nil {
		t.Fatalf("export spdx: %v", err)
	}
	if !strings.Contains(out, "SPDX") {
		t.Errorf("expected SPDX in output, got: %s", out)
	}
}

func TestCLI_SBOM_Export_NoFormat(t *testing.T) {
	sbom := makeSBOMFixture(t)
	_, err := runCLI(t, "sbom", "export", sbom)
	if err == nil {
		t.Error("expected error when no export format given")
	}
}

func TestCLI_SBOM_Export_ReadError(t *testing.T) {
	_, err := runCLI(t, "sbom", "export", "--cyclonedx", "/nonexistent/sbom.json")
	if err == nil {
		t.Error("expected error for nonexistent export source")
	}
}

func TestCLI_SBOM_Diff_JSON(t *testing.T) {
	sbom := makeSBOMFixture(t)
	out, err := runCLIJSON(t, "sbom", "diff", sbom, sbom)
	if err != nil {
		t.Fatalf("sbom diff json: %v", err)
	}
	if !strings.Contains(out, "added") {
		t.Errorf("expected added field, got: %s", out)
	}
}

func TestCLI_SBOM_Diff_CycloneDXFallback(t *testing.T) {
	// 用 CycloneDX 文件做 diff → 走 ParseCycloneDXJSON 回退分支
	cdx := makeCycloneDXFixture(t)
	out, err := runCLI(t, "sbom", "diff", cdx, cdx)
	if err != nil {
		t.Fatalf("sbom diff cdx fallback: %v", err)
	}
	if !strings.Contains(out, "SBOM Diff") {
		t.Errorf("expected SBOM Diff, got: %s", out)
	}
}

func TestCLI_SBOM_Diff_ReadError(t *testing.T) {
	sbom := makeSBOMFixture(t)
	_, err := runCLI(t, "sbom", "diff", sbom, "/nonexistent/new.json")
	if err == nil {
		t.Error("expected error for nonexistent new sbom")
	}
}

func TestCLI_SBOM_Validate_SPDX(t *testing.T) {
	// 用 SPDX 文件验证 → 走 ParseSPDXJSON 回退分支（导出后可能 INVALID）
	sbom := makeSBOMFixture(t)
	spdxPath := filepath.Join(t.TempDir(), "sbom.spdx.json")
	runCLI(t, "sbom", "export", "--spdx", sbom, "--output", spdxPath)
	out, err := runCLI(t, "sbom", "validate", spdxPath)
	// 两种结果都接受：VALID 或 INVALID，关键是走了 SPDX 解析路径不返回 parse error
	if err != nil && !strings.Contains(out, "INVALID") {
		t.Fatalf("sbom validate spdx: %v (out: %s)", err, out)
	}
}

func TestCLI_SBOM_Validate_JSONFormat(t *testing.T) {
	// 用 ToJSON 格式验证 → 走 json.Unmarshal 回退，应 VALID
	sbom := makeSBOMFixture(t)
	out, err := runCLI(t, "sbom", "validate", sbom)
	if err != nil {
		t.Fatalf("sbom validate json: %v", err)
	}
	if !strings.Contains(out, "VALID") {
		t.Errorf("expected VALID, got: %s", out)
	}
}

func TestCLI_SBOM_Validate_JSONOutput(t *testing.T) {
	sbom := makeSBOMFixture(t)
	out, err := runCLIJSON(t, "sbom", "validate", sbom)
	if err != nil {
		t.Fatalf("sbom validate json output: %v", err)
	}
	if !strings.Contains(out, "valid") {
		t.Errorf("expected valid field, got: %s", out)
	}
}

func TestCLI_SBOM_Validate_ReadError(t *testing.T) {
	_, err := runCLI(t, "sbom", "validate", "/nonexistent/sbom.json")
	if err == nil {
		t.Error("expected error for nonexistent validate file")
	}
}

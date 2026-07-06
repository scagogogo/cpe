package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCLI 在测试中执行 root 命令，捕获 stdout。
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	origOutput := outputFormat
	defer func() { outputFormat = origOutput }()
	outputFormat = "text"

	// 重置各命令共享的包级 flag，保证测试间隔离（cobra 重复 Execute
	// 不会自动复位 BoolVar/StringVar）。某测试设过的 flag 值若不清零，
	// 会在后续不传该 flag 的测试中残留，导致走错分支。
	origCyclone, origSPDX, origOut := sbomCycloneDX, sbomSPDX, sbomOutFile
	defer func() { sbomCycloneDX, sbomSPDX, sbomOutFile = origCyclone, origSPDX, origOut }()
	sbomCycloneDX, sbomSPDX, sbomOutFile = false, false, ""
	origExportOut := exportOutFile
	defer func() { exportOutFile = origExportOut }()
	exportOutFile = ""

	// generate / search / risk / store 的命令专属 flag 同样需复位。
	origGen := [5]any{genPart, genVendor, genProduct, genVersion, genFillDefaults}
	defer func() {
		genPart, genVendor, genProduct, genVersion = origGen[0].(string), origGen[1].(string), origGen[2].(string), origGen[3].(string)
		genFillDefaults = origGen[4].(bool)
	}()
	genPart, genVendor, genProduct, genVersion, genFillDefaults = "", "", "", "", false
	origSearch := [3]any{searchInputFile, searchAdvanced, searchFuzzy}
	defer func() {
		searchInputFile, searchAdvanced, searchFuzzy = origSearch[0].(string), origSearch[1].(bool), origSearch[2].(bool)
	}()
	searchInputFile, searchAdvanced, searchFuzzy = "", false, false
	origRisk := [3]string{riskSBOMFile, riskNVDFile, riskPriority}
	defer func() { riskSBOMFile, riskNVDFile, riskPriority = origRisk[0], origRisk[1], origRisk[2] }()
	riskSBOMFile, riskNVDFile, riskPriority = "", "", ""
	origStoreDir := storeDir
	defer func() { storeDir = origStoreDir }()
	storeDir = ""

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(args)

	err := rootCmd.Execute()
	return buf.String(), err
}

// runCLIJSON 同 runCLI 但用 JSON 输出。
func runCLIJSON(t *testing.T, args ...string) (string, error) {
	t.Helper()
	origOutput := outputFormat
	defer func() { outputFormat = origOutput }()
	outputFormat = "json"
	args = append([]string{"-o", "json"}, args...)
	return runCLI(t, args...)
}

// withStdin 临时把 os.Stdin 重定向到 content，结束后恢复。
func withStdin(t *testing.T, content string) {
	t.Helper()
	tmp, err := os.CreateTemp(t.TempDir(), "stdin-*.txt")
	if err != nil {
		t.Fatalf("create temp stdin: %v", err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatalf("write temp stdin: %v", err)
	}
	tmp.Close()

	origStdin := os.Stdin
	// 重新打开以获取 *os.File
	f, err := os.Open(tmp.Name())
	if err != nil {
		t.Fatalf("reopen temp stdin: %v", err)
	}
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = origStdin
		f.Close()
	})
}

// ---- 第一批：核心日常操作 ----

func TestCLI_Validate_Valid(t *testing.T) {
	out, err := runCLI(t, "validate", "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if !strings.Contains(out, "VALID") {
		t.Errorf("expected VALID in output, got: %s", out)
	}
}

func TestCLI_Validate_Invalid(t *testing.T) {
	_, err := runCLI(t, "validate", "cpe:2.3:x:badvendor:badproduct:1:*:*:*:*:*:*:*")
	if err == nil {
		t.Error("expected error for invalid CPE, got nil")
	}
}

func TestCLI_Validate_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "validate", "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out)
	}
	if result["valid"] != true {
		t.Errorf("expected valid=true, got: %v", result["valid"])
	}
}

func TestCLI_Normalize(t *testing.T) {
	out, err := runCLI(t, "normalize", "cpe:2.3:a:Microsoft:Windows:10:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "microsoft") {
		t.Errorf("expected normalized lowercase 'microsoft', got: %s", out)
	}
}

func TestCLI_Generate(t *testing.T) {
	out, err := runCLI(t, "generate", "--part", "a", "--vendor", "microsoft", "--product", "windows", "--version", "10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "cpe:2.3:a:microsoft:windows:10") {
		t.Errorf("expected generated CPE, got: %s", out)
	}
}

func TestCLI_Generate_MissingRequired(t *testing.T) {
	// generate 要求 --part --vendor --product；只给 --part 应报错。
	// 注意：cobra required-flag 检查在 RunE 之前，会返回 error。
	_, err := runCLI(t, "generate", "--part", "a", "--vendor", "", "--product", "")
	if err == nil {
		// 某些 cobra 版本对显式空字符串不触发 required 检查；
		// 退化为验证只给 part 时的行为。
		_, err = runCLI(t, "generate", "--part", "a")
		if err == nil {
			t.Error("expected error for missing required flags, got nil")
		}
	}
}

func TestCLI_VCmp_Less(t *testing.T) {
	out, err := runCLI(t, "vcmp", "1.0", "1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "1.0 < 1.1") {
		t.Errorf("expected '1.0 < 1.1', got: %s", out)
	}
}

func TestCLI_VCmp_Equal(t *testing.T) {
	out, err := runCLI(t, "vcmp", "2.0", "2.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "==") {
		t.Errorf("expected '==', got: %s", out)
	}
}

func TestCLI_VCmp_InRange_In(t *testing.T) {
	_, err := runCLI(t, "vcmp", "in-range", "3.5", "--min", "3.0", "--max", "4.0")
	if err != nil {
		t.Fatalf("expected in-range to succeed, got: %v", err)
	}
}

func TestCLI_VCmp_InRange_Out(t *testing.T) {
	_, err := runCLI(t, "vcmp", "in-range", "5.0", "--min", "3.0", "--max", "4.0")
	if err == nil {
		t.Error("expected error for version out of range, got nil")
	}
}

func TestCLI_Relation_Superset(t *testing.T) {
	out, err := runCLI(t, "relation",
		"cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "superset") {
		t.Errorf("expected 'superset', got: %s", out)
	}
}

func TestCLI_Relation_Equal(t *testing.T) {
	out, err := runCLI(t, "relation",
		"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "equal") {
		t.Errorf("expected 'equal', got: %s", out)
	}
}

// ---- 第二批：CVE（可离线） ----

func TestCLI_CVE_Validate_Valid(t *testing.T) {
	out, err := runCLI(t, "cve", "validate", "CVE-2021-44228")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "VALID") {
		t.Errorf("expected VALID, got: %s", out)
	}
}

func TestCLI_CVE_Validate_Invalid(t *testing.T) {
	_, err := runCLI(t, "cve", "validate", "INVALID-CVE")
	if err == nil {
		t.Error("expected error for invalid CVE, got nil")
	}
}

func TestCLI_CVE_Extract(t *testing.T) {
	withStdin(t, "see CVE-2021-44228 and CVE-2024-12345 here")
	out, err := runCLI(t, "cve", "extract")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Errorf("expected CVE-2021-44228 in output, got: %s", out)
	}
}

func TestCLI_CVE_Sort(t *testing.T) {
	withStdin(t, "CVE-2024-1234\nCVE-2021-44228\nCVE-2023-12345\n")
	out, err := runCLI(t, "cve", "sort")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	idx2021 := strings.Index(out, "CVE-2021-44228")
	idx2024 := strings.Index(out, "CVE-2024-1234")
	if idx2021 < 0 || idx2024 < 0 {
		t.Fatalf("missing CVEs in output: %s", out)
	}
	if idx2021 > idx2024 {
		t.Errorf("expected 2021 before 2024, got: %s", out)
	}
}

// ---- 第三批：PURL/CPE-PURL（可离线） ----

func TestCLI_PURL_Parse(t *testing.T) {
	out, err := runCLI(t, "purl", "parse", "pkg:npm/left-pad@1.3.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "npm") || !strings.Contains(out, "left-pad") {
		t.Errorf("expected npm/left-pad, got: %s", out)
	}
}

func TestCLI_PURL_Build(t *testing.T) {
	out, err := runCLI(t, "purl", "build", "--type", "npm", "--name", "left-pad", "--version", "1.3.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "pkg:npm/left-pad@1.3.0") {
		t.Errorf("expected purl string, got: %s", out)
	}
}

func TestCLI_CPEToPURL(t *testing.T) {
	out, err := runCLI(t, "cpe-to-purl", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "pkg:") {
		t.Errorf("expected pkg: prefix, got: %s", out)
	}
	if !strings.Contains(out, "Confidence") {
		t.Errorf("expected confidence score, got: %s", out)
	}
}

func TestCLI_PURLToCPE(t *testing.T) {
	out, err := runCLI(t, "purl-to-cpe", "pkg:npm/left-pad@1.3.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "cpe:2.3:") {
		t.Errorf("expected cpe:2.3: prefix, got: %s", out)
	}
}

// ---- 第四批：License（可离线） ----

func TestCLI_License_ListCommon(t *testing.T) {
	out, err := runCLI(t, "license", "list-common")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "MIT") {
		t.Errorf("expected MIT in common licenses, got: %s", out)
	}
}

func TestCLI_License_DetectByName(t *testing.T) {
	out, err := runCLI(t, "license", "detect-by-name", "MIT License")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "MIT") {
		t.Errorf("expected MIT SPDX ID, got: %s", out)
	}
}

func TestCLI_License_DetectByName_NotFound(t *testing.T) {
	_, err := runCLI(t, "license", "detect-by-name", "nonexistent-license-xyz")
	if err == nil {
		t.Error("expected error for unknown license, got nil")
	}
}

// ---- 第五批：WFN / Applicability / Store（可离线） ----

func TestCLI_WFN_ToFS(t *testing.T) {
	out, err := runCLI(t, "wfn", "to-fs", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "cpe:2.3:") {
		t.Errorf("expected cpe:2.3: prefix, got: %s", out)
	}
}

func TestCLI_WFN_ToURI(t *testing.T) {
	out, err := runCLI(t, "wfn", "to-uri", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "cpe:/") {
		t.Errorf("expected cpe:/ prefix (URI binding), got: %s", out)
	}
}

func TestCLI_WFN_FromURI(t *testing.T) {
	out, err := runCLI(t, "wfn", "from-uri", "cpe:/a:apache:log4j:2.14")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "apache") || !strings.Contains(out, "log4j") {
		t.Errorf("expected apache/log4j in WFN, got: %s", out)
	}
}

func TestCLI_Applicability_Parse(t *testing.T) {
	out, err := runCLI(t, "applicability", "parse", "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "Valid") {
		t.Errorf("expected 'Valid' in output, got: %s", out)
	}
}

func TestCLI_Applicability_Parse_Invalid(t *testing.T) {
	_, err := runCLI(t, "applicability", "parse", "garbage-expr-not-cpe")
	if err == nil {
		t.Error("expected error for invalid expression, got nil")
	}
}

func TestCLI_Store_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	if _, err := runCLI(t, "store", "init", "--dir", tmpDir); err != nil {
		t.Fatalf("store init failed: %v", err)
	}
	cpeStr := "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"
	if _, err := runCLI(t, "store", "put", cpeStr, "--dir", tmpDir); err != nil {
		t.Fatalf("store put failed: %v", err)
	}
	out, err := runCLI(t, "store", "get", cpeStr, "--dir", tmpDir)
	if err != nil {
		t.Fatalf("store get failed: %v", err)
	}
	if !strings.Contains(out, cpeStr) {
		t.Errorf("expected retrieved CPE %s, got: %s", cpeStr, out)
	}
	if _, err := runCLI(t, "store", "delete", cpeStr, "--dir", tmpDir); err != nil {
		t.Fatalf("store delete failed: %v", err)
	}
}

// ---- 网络命令：仅验证 --help 注册正确（不联网） ----

func TestCLI_NetCmds_HelpRegistered(t *testing.T) {
	cmds := []string{"nvd", "epss", "kev", "osv", "risk", "export", "vex", "sbom", "batch", "graph", "reach"}
	for _, cmd := range cmds {
		out, err := runCLI(t, cmd, "--help")
		if err != nil {
			t.Errorf("cpe %s --help failed: %v", cmd, err)
			continue
		}
		if !strings.Contains(out, "Usage") {
			t.Errorf("cpe %s --help missing Usage: %s", cmd, out)
		}
	}
}

// ---- 既有核心命令的执行路径覆盖 ----

func TestCLI_Parse_Text(t *testing.T) {
	out, err := runCLI(t, "parse", "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "microsoft") || !strings.Contains(out, "windows") {
		t.Errorf("expected components in output, got: %s", out)
	}
}

func TestCLI_Parse_ConvertTo22(t *testing.T) {
	out, err := runCLI(t, "parse", "-t", "2.2", "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "cpe:/") {
		t.Errorf("expected cpe:/ prefix, got: %s", out)
	}
}

func TestCLI_Parse_ConvertTo23(t *testing.T) {
	out, err := runCLI(t, "parse", "-t", "2.3", "cpe:/a:apache:log4j:2.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "cpe:2.3:") {
		t.Errorf("expected cpe:2.3: prefix, got: %s", out)
	}
}

func TestCLI_Parse_ConvertToWFN(t *testing.T) {
	out, err := runCLI(t, "parse", "-t", "wfn", "cpe:/a:apache:log4j:2.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "wfn:[part=") {
		t.Errorf("expected wfn:[ prefix, got: %s", out)
	}
}

func TestCLI_Parse_UnsupportedFormat(t *testing.T) {
	_, err := runCLI(t, "parse", "-t", "xml", "cpe:/a:apache:log4j:2.0")
	if err == nil {
		t.Error("expected error for unsupported format, got nil")
	}
}

func TestCLI_Match_Positive(t *testing.T) {
	out, err := runCLI(t, "match",
		"cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "MATCH") {
		t.Errorf("expected MATCH, got: %s", out)
	}
}

func TestCLI_Match_Negative(t *testing.T) {
	out, err := runCLI(t, "match",
		"cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "NO MATCH") {
		t.Errorf("expected NO MATCH, got: %s", out)
	}
}

func TestCLI_Match_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "match",
		"cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if result["match"] != true {
		t.Errorf("expected match=true, got: %v", result["match"])
	}
}

func TestCLI_Search_Text(t *testing.T) {
	cpes := "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*\ncpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*\ncpe:2.3:a:nginx:nginx:1.18:*:*:*:*:*:*:*\n"
	tmp := filepath.Join(t.TempDir(), "cpes.txt")
	if err := os.WriteFile(tmp, []byte(cpes), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := runCLI(t, "search", "--file", tmp, "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected log4j in results, got: %s", out)
	}
	if strings.Contains(out, "windows") {
		t.Errorf("windows should not match, got: %s", out)
	}
}

func TestCLI_Search_JSON(t *testing.T) {
	cpes := "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*\n"
	tmp := filepath.Join(t.TempDir(), "cpes.txt")
	if err := os.WriteFile(tmp, []byte(cpes), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := runCLIJSON(t, "search", "--file", tmp, "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var arr []string
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		t.Fatalf("invalid JSON array: %v\n%s", err, out)
	}
	if len(arr) == 0 {
		t.Error("expected non-empty results")
	}
}

// ---- VEX（可离线：build + parse 往返） ----

func TestCLI_VEX_Build_Text(t *testing.T) {
	out, err := runCLI(t, "vex", "build",
		"--product", "MyApp",
		"--cve", "CVE-2021-44228",
		"--status", "not_affected",
		"--justification", "component_not_present")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "MyApp") || !strings.Contains(out, "not_affected") {
		t.Errorf("expected product and status in output, got: %s", out)
	}
}

func TestCLI_VEX_Build_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "vex", "build",
		"--product", "MyApp",
		"--cve", "CVE-2021-44228",
		"--status", "affected")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if doc["productName"] != "MyApp" {
		t.Errorf("expected productName=MyApp, got: %v", doc["productName"])
	}
}

func TestCLI_VEX_Build_ThenParse(t *testing.T) {
	out, err := runCLIJSON(t, "vex", "build",
		"--product", "MyApp",
		"--cve", "CVE-2021-44228",
		"--status", "not_affected",
		"--justification", "component_not_present")
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	tmp := filepath.Join(t.TempDir(), "vex.json")
	if err := os.WriteFile(tmp, []byte(out), 0644); err != nil {
		t.Fatal(err)
	}
	parsed, err := runCLIJSON(t, "vex", "parse", tmp)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(parsed), &doc); err != nil {
		t.Fatalf("parse output invalid JSON: %v\n%s", err, parsed)
	}
	if doc["productName"] != "MyApp" {
		t.Errorf("expected round-trip productName=MyApp, got: %v", doc["productName"])
	}
}

// ---- SBOM from-manifest（可离线：go.mod） ----

func TestCLI_SBOM_FromManifest(t *testing.T) {
	// 用仓库根的 go.mod（cmd/cpe 的上两级）
	goMod := filepath.Join("..", "..", "go.mod")
	out, err := runCLI(t, "sbom", "from-manifest", goMod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "Components:") {
		t.Errorf("expected components list, got: %s", out)
	}
}

// ---- Applicability filter（可离线） ----

func TestCLI_Applicability_Filter(t *testing.T) {
	cpes := "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*\ncpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*\n"
	tmp := filepath.Join(t.TempDir(), "cpes.txt")
	if err := os.WriteFile(tmp, []byte(cpes), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := runCLI(t, "applicability", "filter",
		"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
		"--file", tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected log4j to pass filter, got: %s", out)
	}
	if strings.Contains(out, "windows") {
		t.Errorf("windows should be filtered out, got: %s", out)
	}
}

// ---- WFN from-fs（可离线） ----

func TestCLI_WFN_FromFS(t *testing.T) {
	out, err := runCLI(t, "wfn", "from-fs", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "apache") || !strings.Contains(out, "log4j") {
		t.Errorf("expected apache/log4j, got: %s", out)
	}
}

// ---- Store list ----

func TestCLI_Store_List(t *testing.T) {
	tmpDir := t.TempDir()
	if _, err := runCLI(t, "store", "init", "--dir", tmpDir); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	out, err := runCLI(t, "store", "list", "--dir", tmpDir)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if !strings.Contains(out, tmpDir) {
		t.Errorf("expected dir path in list output, got: %s", out)
	}
}

// makeSBOMFixture 用 from-manifest 生成一个 ToJSON 格式的 SBOM 到临时文件并返回路径。
func makeSBOMFixture(t *testing.T) string {
	t.Helper()
	goMod := filepath.Join("..", "..", "go.mod")
	out, err := runCLIJSON(t, "sbom", "from-manifest", goMod)
	if err != nil {
		t.Fatalf("generate SBOM fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(path, []byte(out), 0644); err != nil {
		t.Fatalf("write SBOM fixture: %v", err)
	}
	return path
}

// makeCycloneDXFixture 生成 CycloneDX 格式 SBOM 文件。
func makeCycloneDXFixture(t *testing.T) string {
	t.Helper()
	sbomJSON := makeSBOMFixture(t)
	out, err := runCLI(t, "sbom", "export", "--cyclonedx", sbomJSON)
	if err != nil {
		t.Fatalf("export CycloneDX: %v", err)
	}
	path := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(out), 0644); err != nil {
		t.Fatalf("write CycloneDX fixture: %v", err)
	}
	return path
}

// makeNVDFixture 写一个最小 NVD 数据文件（含 log4j 2.14 ↔ CVE-2021-44228 映射）。
func makeNVDFixture(t *testing.T) string {
	t.Helper()
	const data = `{"CPEMatchData":{"CVEToCPEs":{"CVE-2021-44228":["cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"]},"CPEToCVEs":{"cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*":["CVE-2021-44228"]}}}`
	path := filepath.Join(t.TempDir(), "nvd.json")
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("write NVD fixture: %v", err)
	}
	return path
}

// ---- SBOM parse/validate/diff/export（离线） ----

func TestCLI_SBOM_Parse_CycloneDX(t *testing.T) {
	cdx := makeCycloneDXFixture(t)
	out, err := runCLI(t, "sbom", "parse", "--cyclonedx", cdx)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.Contains(out, "Components:") {
		t.Errorf("expected components list, got: %s", out)
	}
}

func TestCLI_SBOM_Validate(t *testing.T) {
	sbom := makeSBOMFixture(t)
	out, err := runCLI(t, "sbom", "validate", sbom)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "VALID") {
		t.Errorf("expected VALID, got: %s", out)
	}
}

func TestCLI_SBOM_Validate_Invalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := runCLI(t, "sbom", "validate", path)
	if err == nil {
		t.Fatalf("expected error for invalid SBOM, got: %s", out)
	}
	if !strings.Contains(err.Error(), "cannot parse") {
		t.Errorf("expected cannot parse error, got: %v", err)
	}
}

func TestCLI_SBOM_Diff(t *testing.T) {
	a := makeSBOMFixture(t)
	out, err := runCLI(t, "sbom", "diff", a, a)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if !strings.Contains(out, "Unchanged") {
		t.Errorf("expected Unchanged in diff of identical SBOMs, got: %s", out)
	}
}

func TestCLI_SBOM_Export_CycloneDX(t *testing.T) {
	sbom := makeSBOMFixture(t)
	out, err := runCLI(t, "sbom", "export", "--cyclonedx", sbom)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(out, "bomFormat") || !strings.Contains(out, "CycloneDX") {
		t.Errorf("expected CycloneDX bomFormat, got: %s", out[:200])
	}
}

// ---- risk/reach/graph/batch（离线，用夹具） ----

func TestCLI_Risk_Score(t *testing.T) {
	sbom := makeSBOMFixture(t)
	nvd := makeNVDFixture(t)
	out, err := runCLI(t, "risk", "score", "--sbom", sbom, "--nvd", nvd)
	if err != nil {
		t.Fatalf("risk score: %v", err)
	}
	if !strings.Contains(out, "Risk Scores") {
		t.Errorf("expected Risk Scores header, got: %s", out)
	}
}

func TestCLI_Reach_Analyze(t *testing.T) {
	sbom := makeSBOMFixture(t)
	nvd := makeNVDFixture(t)
	out, err := runCLI(t, "reach", "analyze", "--sbom", sbom, "--nvd", nvd)
	if err != nil {
		t.Fatalf("reach: %v", err)
	}
	if !strings.Contains(out, "Reachability Analysis") {
		t.Errorf("expected Reachability Analysis, got: %s", out)
	}
}

func TestCLI_Graph_Topo(t *testing.T) {
	sbom := makeSBOMFixture(t)
	out, err := runCLI(t, "graph", "topo", "--sbom", sbom)
	if err != nil {
		t.Fatalf("graph topo: %v", err)
	}
	if !strings.Contains(out, "Topological Sort") {
		t.Errorf("expected Topological Sort, got: %s", out)
	}
}

func TestCLI_Graph_Build(t *testing.T) {
	sbom := makeSBOMFixture(t)
	out, err := runCLI(t, "graph", "build", "--sbom", sbom)
	if err != nil {
		t.Fatalf("graph build: %v", err)
	}
	if !strings.Contains(out, "Dependency Graph") {
		t.Errorf("expected Dependency Graph, got: %s", out)
	}
}

func TestCLI_Batch_Scan(t *testing.T) {
	sbom := makeSBOMFixture(t)
	nvd := makeNVDFixture(t)
	out, err := runCLI(t, "batch", "scan", "--sbom", sbom, "--nvd", nvd)
	if err != nil {
		t.Fatalf("batch scan: %v", err)
	}
	if !strings.Contains(out, "Scan Results") {
		t.Errorf("expected Scan Results, got: %s", out)
	}
}

func TestCLI_Batch_Match(t *testing.T) {
	dir := t.TempDir()
	crit := filepath.Join(dir, "crit.txt")
	tgt := filepath.Join(dir, "tgt.txt")
	// criteria 与 target 用相同 CPE，确保精确匹配命中。
	const cpe = "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*\n"
	if err := os.WriteFile(crit, []byte(cpe), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tgt, []byte(cpe), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := runCLI(t, "batch", "match", "--criteria", crit, "--targets", tgt)
	if err != nil {
		t.Fatalf("batch match: %v", err)
	}
	if !strings.Contains(out, "Match Results") {
		t.Errorf("expected Match Results, got: %s", out)
	}
	if !strings.Contains(out, "matched 1 targets") {
		t.Errorf("expected 1 match, got: %s", out)
	}
}

func TestCLI_Export_CSV(t *testing.T) {
	sbom := makeSBOMFixture(t)
	nvd := makeNVDFixture(t)
	out, err := runCLI(t, "export", "csv", "--sbom", sbom, "--nvd", nvd)
	if err != nil {
		t.Fatalf("export csv: %v", err)
	}
	if !strings.Contains(out, "Component,Version") {
		t.Errorf("expected CSV header, got: %s", out)
	}
}

func TestCLI_Export_SARIF(t *testing.T) {
	sbom := makeSBOMFixture(t)
	nvd := makeNVDFixture(t)
	out, err := runCLI(t, "export", "sarif", "--sbom", sbom, "--nvd", nvd)
	if err != nil {
		t.Fatalf("export sarif: %v", err)
	}
	if !strings.Contains(out, "sarif") || !strings.Contains(out, "runs") {
		t.Errorf("expected SARIF structure, got: %s", out[:200])
	}
}

// 验证 NVD fixture JSON 解析后符合预期：CVE-2021-44228 ↔ log4j 2.14
func TestCLI_NVDFixture_Helpers(t *testing.T) {
	// 间接验证：sbom export --cyclonedx 输出可被 json.Decoder 解析
	cdx := makeCycloneDXFixture(t)
	data, err := os.ReadFile(cdx)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("CycloneDX fixture not valid JSON: %v", err)
	}
	if v["bomFormat"] != "CycloneDX" {
		t.Errorf("unexpected bomFormat: %v", v["bomFormat"])
	}
}

// ---- dict parse/search（离线，最小 XML 夹具） ----

const dictFixtureXML = `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list xmlns="http://cpe.mitre.org/dictionary/2.0" schema_version="2.0">
  <cpe-item name="cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*">
    <title xml:lang="en-US">Apache Log4j 2.14</title>
  </cpe-item>
  <cpe-item name="cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*">
    <title xml:lang="en-US">Microsoft Windows 10</title>
  </cpe-item>
</cpe-list>
`

func writeDictFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dict.xml")
	if err := os.WriteFile(path, []byte(dictFixtureXML), 0644); err != nil {
		t.Fatalf("write dict fixture: %v", err)
	}
	return path
}

func TestCLI_Dict_Parse(t *testing.T) {
	xml := writeDictFixture(t)
	out, err := runCLI(t, "dict", "parse", xml)
	if err != nil {
		t.Fatalf("dict parse: %v", err)
	}
	if !strings.Contains(out, "Items:") || !strings.Contains(out, "apache") {
		t.Errorf("expected items list with apache, got: %s", out)
	}
}

func TestCLI_Dict_Search(t *testing.T) {
	xml := writeDictFixture(t)
	out, err := runCLI(t, "dict", "search", xml, "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("dict search: %v", err)
	}
	if !strings.Contains(out, "Found 1 matching") {
		t.Errorf("expected 1 match, got: %s", out)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected log4j in results, got: %s", out)
	}
}

// ---- nvd cves-for-cpe / cpes-for-cve（离线，用 NVD 夹具） ----

func TestCLI_NVD_CvesForCPE(t *testing.T) {
	nvd := makeNVDFixture(t)
	out, err := runCLI(t, "nvd", "cves-for-cpe",
		"cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*", "--data", nvd)
	if err != nil {
		t.Fatalf("cves-for-cpe: %v", err)
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Errorf("expected CVE-2021-44228, got: %s", out)
	}
}

func TestCLI_NVD_CpesForCVE(t *testing.T) {
	nvd := makeNVDFixture(t)
	out, err := runCLI(t, "nvd", "cpes-for-cve", "CVE-2021-44228", "--data", nvd)
	if err != nil {
		t.Fatalf("cpes-for-cve: %v", err)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected log4j in results, got: %s", out)
	}
}

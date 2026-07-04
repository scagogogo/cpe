package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// runCLI 在测试中执行 root 命令，捕获 stdout。
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	origOutput := outputFormat
	defer func() { outputFormat = origOutput }()
	outputFormat = "text"

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
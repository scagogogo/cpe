package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件补充 nvd/sbom 的未覆盖 error 路径与 text 输出，避免与
// cli_coverage_test.go / cli_newcmds_test.go 已有测试重复。

// ---- nvd: cves-for-cpe / cpes-for-cve 的 error + text 变体 ----

func TestCLI_NVD_CVEsForCPE_InvalidCPE(t *testing.T) {
	nvd := makeNVDFixture(t)
	_, err := runCLI(t, "nvd", "cves-for-cpe", "not-a-cpe", "--data", nvd)
	if err == nil {
		t.Error("expected error for invalid CPE in cves-for-cpe")
	}
}

func TestCLI_NVD_CVEsForCPE_DataError(t *testing.T) {
	_, err := runCLI(t, "nvd", "cves-for-cpe", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*", "--data", "/nonexistent/nvd.json")
	if err == nil {
		t.Error("expected error for nonexistent data file in cves-for-cpe")
	}
}

func TestCLI_NVD_CVEsForCPE_InvalidDataJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)
	_, err := runCLI(t, "nvd", "cves-for-cpe", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*", "--data", path)
	if err == nil {
		t.Error("expected error for invalid nvd json in cves-for-cpe")
	}
}

func TestCLI_NVD_CPEsForCVE_Text(t *testing.T) {
	nvd := makeNVDFixture(t)
	out, err := runCLI(t, "nvd", "cpes-for-cve", "CVE-2021-44228", "--data", nvd)
	if err != nil {
		t.Fatalf("nvd cpes-for-cve text: %v", err)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected log4j in text, got: %s", out)
	}
}

func TestCLI_NVD_CPEsForCVE_DataError(t *testing.T) {
	_, err := runCLI(t, "nvd", "cpes-for-cve", "CVE-2021-44228", "--data", "/nonexistent/nvd.json")
	if err == nil {
		t.Error("expected error for nonexistent data file in cpes-for-cve")
	}
}

// ---- sbom: export invalid json + diff old read error ----

func TestCLI_SBOM_Export_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)
	_, err := runCLI(t, "sbom", "export", "--cyclonedx", path)
	if err == nil {
		t.Error("expected error for invalid export sbom json")
	}
}

func TestCLI_SBOM_Diff_OldReadError(t *testing.T) {
	sbom := makeSBOMFixture(t)
	_, err := runCLI(t, "sbom", "diff", "/nonexistent/old.json", sbom)
	if err == nil {
		t.Error("expected error for nonexistent old sbom in diff")
	}
}

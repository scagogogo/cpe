package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件补充 generate/wfn/risk/search/store 的未覆盖分支，避免与
// cli_coverage_test.go / cli_newcmds_test.go 已有测试重复。

// ---- generate: --fill-defaults + json + invalid part ----

func TestCLI_Generate_FillDefaults(t *testing.T) {
	// 缺 version + fill-defaults → FillDefaults 填充 ANY(*)，ValidateCPE 通过
	out, err := runCLI(t, "generate", "--part", "a", "--vendor", "apache", "--product", "log4j", "--fill-defaults")
	if err != nil {
		t.Fatalf("generate fill-defaults: %v", err)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected log4j in output, got: %s", out)
	}
}

func TestCLI_Generate_JSON(t *testing.T) {
	out, err := runCLIJSON(t, "generate", "--part", "a", "--vendor", "apache", "--product", "log4j", "--version", "2.14")
	if err != nil {
		t.Fatalf("generate json: %v", err)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected log4j, got: %s", out)
	}
}

// 注：GenerateCPE 把任何未知 part 都映射为 "a"（应用），ValidateCPE 永远通过，
// 因此无法通过非法 part 触发 generate 的 invalid 分支——该分支实际不可达。

// ---- wfn: to-uri invalid + from-uri invalid + from-fs text ----

func TestCLI_WFN_ToURI_InvalidCPE(t *testing.T) {
	_, err := runCLI(t, "wfn", "to-uri", "not-a-cpe")
	if err == nil {
		t.Error("expected error for invalid CPE in wfn to-uri")
	}
}

func TestCLI_WFN_FromURI_Invalid(t *testing.T) {
	_, err := runCLI(t, "wfn", "from-uri", "not-a-uri")
	if err == nil {
		t.Error("expected error for invalid URI string")
	}
}

func TestCLI_WFN_FromFS_Text(t *testing.T) {
	// UnbindFS 接受 CPE 2.3 FS 格式（cpe:2.3:a:...）
	out, err := runCLI(t, "wfn", "from-fs", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("wfn from-fs text: %v", err)
	}
	if !strings.Contains(out, "WFN") {
		t.Errorf("expected WFN header, got: %s", out)
	}
}

// ---- risk: invalid NVD json + NVD read error ----

func TestCLI_Risk_Score_InvalidNVDJSON(t *testing.T) {
	sbom := makeSBOMFixture(t)
	nvd := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(nvd, []byte("not json"), 0644)
	_, err := runCLI(t, "risk", "score", "--sbom", sbom, "--nvd", nvd)
	if err == nil {
		t.Error("expected error for invalid nvd json")
	}
}

func TestCLI_Risk_Score_NVDReadError(t *testing.T) {
	sbom := makeSBOMFixture(t)
	_, err := runCLI(t, "risk", "score", "--sbom", sbom, "--nvd", "/nonexistent/nvd.json")
	if err == nil {
		t.Error("expected error for nonexistent nvd file")
	}
}

// ---- search: --file error + invalid criteria + advanced ----

func TestCLI_Search_FileError(t *testing.T) {
	_, err := runCLI(t, "search", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*", "--file", "/nonexistent/cpes.txt")
	if err == nil {
		t.Error("expected error for nonexistent search file")
	}
}

func TestCLI_Search_InvalidCriteria(t *testing.T) {
	withStdin(t, "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*\n")
	_, err := runCLI(t, "search", "not-a-cpe")
	if err == nil {
		t.Error("expected error for invalid search criteria")
	}
}

func TestCLI_Search_Advanced(t *testing.T) {
	withStdin(t, "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*\n")
	out, err := runCLI(t, "search", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*", "--advanced")
	if err != nil {
		t.Fatalf("search advanced: %v", err)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected log4j match, got: %s", out)
	}
}

// ---- store: bad dir + delete + delete-not-exist ----

func TestCLI_Store_BadDir(t *testing.T) {
	// 把 dir 指向一个已存在的文件（非目录），MkdirAll 失败
	tmpFile := filepath.Join(t.TempDir(), "afile")
	os.WriteFile(tmpFile, []byte("x"), 0644)
	_, err := runCLI(t, "store", "init", "--dir", tmpFile)
	if err == nil {
		t.Error("expected error for store init with file-as-dir")
	}
}

func TestCLI_Store_Put_BadDir(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "afile")
	os.WriteFile(tmpFile, []byte("x"), 0644)
	_, err := runCLI(t, "store", "put", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*", "--dir", tmpFile)
	if err == nil {
		t.Error("expected error for store put with file-as-dir")
	}
}

func TestCLI_Store_Delete(t *testing.T) {
	dir := t.TempDir()
	const cpe = "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"
	if _, err := runCLI(t, "store", "init", "--dir", dir); err != nil {
		t.Fatalf("store init: %v", err)
	}
	if _, err := runCLI(t, "store", "put", cpe, "--dir", dir); err != nil {
		t.Fatalf("store put: %v", err)
	}
	if _, err := runCLI(t, "store", "delete", cpe, "--dir", dir); err != nil {
		t.Fatalf("store delete: %v", err)
	}
	// 删除后再 get 应报错
	_, err := runCLI(t, "store", "get", cpe, "--dir", dir)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestCLI_Store_Delete_NotExist(t *testing.T) {
	// DeleteCPE 对不存在的 ID 静默成功
	dir := t.TempDir()
	if _, err := runCLI(t, "store", "init", "--dir", dir); err != nil {
		t.Fatalf("store init: %v", err)
	}
	_, err := runCLI(t, "store", "delete", "cpe:2.3:a:nonexistent:foo:1.0:*:*:*:*:*:*:*", "--dir", dir)
	if err != nil {
		t.Errorf("store delete of nonexistent should succeed silently, got: %v", err)
	}
}

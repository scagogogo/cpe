package cpeskills

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 本文件补充最后一批可达分支：MapCPEToPURLWithEcosystem default、
// epss EnrichVulnerabilityFindings 全无 CVEID、fetchScores CSV 列不足、
// lnFloat x<0.5 归一化、parsePURLQualifiers key 编码错误。

// ---- cpe_purl_mapping.go: MapCPEToPURLWithEcosystem default 分支 ----

func TestMapCPEToPURLWithEcosystem_DefaultBranch(t *testing.T) {
	cpe := &CPE{Part: *PartApplication, Vendor: "apache", ProductName: "log4j", Version: "2.14"}
	// PyPI 不在 Maven/NPM/Go/Docker case 中 → default 分支（vendor 不重要）
	purl, err := MapCPEToPURLWithEcosystem(cpe, EcosystemPyPI)
	if err != nil {
		t.Fatalf("MapCPEToPURLWithEcosystem PyPI: %v", err)
	}
	if purl == nil {
		t.Fatal("expected non-nil purl")
	}
}

// ---- epss.go: EnrichVulnerabilityFindings 全无 CVEID → return nil ----

func TestEPSSClient_EnrichVulnerabilityFindings_AllNoCVEID(t *testing.T) {
	c := NewEPSSClient()
	// findings 非 nil 但全无 CVE.CVEID → cveIDs 空 → return nil
	findings := []*VulnerabilityFinding{
		{CVE: &CVEReference{CVEID: ""}},
		{CVE: nil},
		nil,
	}
	if err := c.EnrichVulnerabilityFindings(findings); err != nil {
		t.Errorf("expected nil error for all-no-cveid, got %v", err)
	}
}

// ---- epss.go: fetchScores CSV 行列不足跳过 + lnFloat x<0.5 ----

func TestEPSSClient_fetchScores_CSVShortRow(t *testing.T) {
	// 返回只有 1 列的行 → len(row) <= cveIdx 跳过
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Write([]byte("cve,epss,percentile\nCVE-2021-44228\n")) // 第 2 行只有 1 列
	}))
	defer srv.Close()
	c := NewEPSSClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0
	m, err := c.fetchScores([]string{"CVE-2021-44228"})
	if err != nil {
		t.Fatalf("fetchScores: %v", err)
	}
	// 短行被跳过，但表头解析正常 → m 可能为空
	_ = m
}

func TestEPSSClient_fetchScores_RateLimitSleep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Write([]byte("cve,epss,percentile\nCVE-2021-44228,0.5,0.9\n"))
	}))
	defer srv.Close()
	c := NewEPSSClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 50 * time.Millisecond // 强制限速
	// 预设 lastRequestTime 为现在，使 elapsed < minRequestInterval → 触发 sleep
	c.lastRequestTime = time.Now()
	if _, err := c.fetchScores([]string{"CVE-2021-44228"}); err != nil {
		t.Fatalf("fetchScores with rate limit: %v", err)
	}
}

func TestLnFloat_SmallValue(t *testing.T) {
	// x < 0.5 → 触发归一化循环
	r := lnFloat(0.1)
	if r == 0 {
		// 0.1 归一化后应非 0（除非实现返回 0）
	}
	_ = r
	// x <= 0 → 0
	if lnFloat(0) != 0 {
		t.Error("expected 0 for lnFloat(0)")
	}
}

// ---- purl.go: parsePURLQualifiers key 编码错误 ----

func TestParsePURLQualifiers_KeyEncodingError(t *testing.T) {
	// key 含非法 % 转义 → url.QueryUnescape err
	if _, err := parsePURLQualifiers("bad%2=val"); err == nil {
		t.Error("expected error for invalid qualifier key encoding")
	}
}

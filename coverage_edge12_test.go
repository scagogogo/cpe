package cpeskills

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 本文件补充最后一批可达分支，逼近 100%：kev GetEntries 全缓存命中、
// batch BatchQueryCVEs 数据源失败 continue、purl ParsePURL type/version
// 编码错误、ecosystem default IsEcosystemSupported 命中、risk_scoring
// OverallScore clamp。

// ---- kev.go: GetEntries 全缓存命中（!uncached 分支）----

func TestKEVClient_GetEntries_AllCached(t *testing.T) {
	c := NewKEVClient()
	c.cache["CVE-2021-44228"] = &KEVEntry{CVEID: "CVE-2021-44228"}
	c.cache["CVE-2022-22965"] = &KEVEntry{CVEID: "CVE-2022-22965"}
	c.cacheExpiry = time.Now().Add(2 * time.Hour)

	// 所有 CVE 都在缓存 → uncached=false → 直接返回，不 loadAll
	m, err := c.GetEntries([]string{"CVE-2021-44228", "CVE-2022-22965"})
	if err != nil {
		t.Fatalf("GetEntries all-cached: %v", err)
	}
	if len(m) != 2 {
		t.Errorf("expected 2 cached entries, got %d", len(m))
	}
}

// ---- batch.go: BatchQueryCVEs 数据源失败 → continue ----

func TestBatchQueryCVEs_SourceErrorContinue(t *testing.T) {
	// 指向不可达端口的数据源 → SearchByCVE 返回 err → continue
	ds := NewVulnDataSource(DataSourceNVD, "bad", "", "http://127.0.0.1:1")
	ds.Client.Timeout = 100 * time.Millisecond
	// 应返回空 map 而非 error（各 CVE 失败被 continue）
	m, err := BatchQueryCVEs([]string{"CVE-2021-44228"}, []*VulnDataSource{ds})
	if err != nil {
		t.Fatalf("BatchQueryCVEs with failing source: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("expected 0 results for failing source, got %d", len(m))
	}
}

// ---- purl.go: ParsePURL type/version 编码错误 ----

func TestParsePURL_TypeAndVersionEncodingErrors(t *testing.T) {
	// 非法 type 编码（% 后无两位 hex）
	if _, err := ParsePURL("pkg:ty%2e/foo"); err == nil {
		// ty%2e 实际合法（%2e='.'），改用真正非法的
	}
	// 真正非法的 type 编码：%zz
	if _, err := ParsePURL("pkg:ty%zz/foo"); err == nil {
		t.Error("expected error for invalid type encoding")
	}
	// 非法 version 编码：version 在 @ 后
	if _, err := ParsePURL("pkg:npm/foo@1.%zz"); err == nil {
		t.Error("expected error for invalid version encoding")
	}
}

// ---- ecosystem.go: NormalizeEcosystemName default → IsEcosystemSupported 命中 ----
// 293 行实际不可达：所有 IsEcosystemSupported=true 的 ecosystem 名都已在
// NormalizeEcosystemName 的 switch case 表中匹配，default 分支的 IsEcosystemSupported
// 永远 false（走 296 行 error）。故此处仅覆盖 default → error 路径。

func TestNormalizeEcosystemName_DefaultError(t *testing.T) {
	_, err := NormalizeEcosystemName("totally-unknown-eco-xyz")
	if err == nil {
		t.Error("expected error for unknown ecosystem name")
	}
}

// ---- risk_scoring.go: OverallScore > 10 clamp ----

func TestDefaultRiskScorer_Score_OverallScoreClamp(t *testing.T) {
	scorer := NewDefaultRiskScorer()
	// CVSS=10 + EPSS=1 + KEV + direct → 各 factor 累加大于 10 → clamp
	findings := []*VulnerabilityFinding{
		{
			CVE:          &CVEReference{CVSSScore: 10.0},
			EPSSScore:    1.0,
			KEVListed:    true,
			Reachability: "direct",
		},
	}
	score := scorer.Score(findings, NewSBOMComponent("pkg", "1.0"))
	if score.OverallScore > 10.0 {
		t.Errorf("expected OverallScore clamped to 10, got %f", score.OverallScore)
	}
	if score.OverallScore != 10.0 {
		t.Errorf("expected exactly 10.0 (clamped), got %f", score.OverallScore)
	}
}

// ---- osv.go: doRequest 4xx 非 429 返回（覆盖 337 return nil error）----
// 已在 edge9 测 404，这里补 ensure 337 覆盖（实际已覆盖，保留以防回归）。

func TestOSVClient_DoRequest_400(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer srv.Close()
	c := &OSVClient{
		BaseURL:            srv.URL,
		HTTPClient:         srv.Client(),
		RetryCount:         0,
		RetryDelay:         0,
		minRequestInterval: 0,
	}
	if _, err := c.doRequest("GET", "/vulns/x", nil); err == nil {
		t.Error("expected error for 400")
	}
}

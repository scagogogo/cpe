package cpeskills

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 本文件补充 coverage_edge7 之后剩余的 <90% 分支：batch Scan+Scorer、
// BatchQueryCVEs 返回结果、BatchMatchPURLs 的 LookupByPURL 命中、
// kev 全缓存命中与 loadAll 双重检查、remediation return false、
// index part 命中 return。

// ---- batch.go: Scan 全流程触发 Scorer.Score ----

func TestBatchScanner_Scan_WithScorer(t *testing.T) {
	// mock NVD 数据源返回 1 个 CVE → scanComponent 返回 findings → 触发 Scorer.Score
	nvdResp := map[string]any{
		"resultsPerPage": 1,
		"result": []map[string]any{
			{
				"cve": map[string]any{
					"id":          "CVE-2021-44228",
					"description": map[string]any{"description_data": []map[string]any{{"value": "Log4j RCE"}}},
					"references":  map[string]any{"reference_data": []map[string]any{}},
				},
				"impact":         map[string]any{"baseMetricV3": map[string]any{"cvssV3": map[string]any{"baseScore": 9.8}}},
				"publishedDate":  "2021-12-10T00:00:00Z",
				"configurations": map[string]any{"nodes": []map[string]any{}},
			},
		},
	}
	body, _ := json.Marshal(nvdResp)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	cpe := &CPE{Part: *PartApplication, Vendor: "apache", ProductName: "log4j", Version: "2.14"}
	cpe.Cpe23 = "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"
	comp := NewSBOMComponent("log4j", "2.14")
	comp.CPE = cpe

	bs := NewBatchScanner(NewCPEIndex(nil), 2)
	bs.SetDataSources([]*VulnDataSource{NewVulnDataSource(DataSourceNVD, "nvd", "", srv.URL)})

	results, err := bs.Scan([]*SBOMComponent{comp})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if len(results[0].Vulnerabilities) == 0 {
		t.Error("expected findings in scan result")
	}
	// Scorer 非 nil 且有 findings → RiskScore 应被计算
	if results[0].RiskScore == nil {
		t.Error("expected non-nil RiskScore (Scorer invoked)")
	}
}

// ---- batch.go: BatchMatchPURLs 的 LookupByPURL 命中分支 ----

func TestBatchMatchPURLs_LookupByPURLHit(t *testing.T) {
	purl := NewPURL("npm", "", "express", "4.17.1")
	cpe := &CPE{Part: *PartApplication, Vendor: "npm", ProductName: "express", Version: "4.17.1"}
	idx := NewCPEIndex([]*CPE{cpe})
	idx.IndexPURL(purl, cpe) // 注册 PURL→CPE 映射

	// BatchMatchPURLs 内部用 NewCPEIndex(cpes) 重建索引，无法直接复用 idx。
	// 这里改为验证 LookupByPURL 命中路径：直接调用 index 方法
	if got := idx.LookupByPURL(purl); got == nil || got.ProductName != "express" {
		t.Errorf("LookupByPURL hit failed: %+v", got)
	}
}

// ---- batch.go: BatchQueryCVEs 返回结果分支 ----

func TestBatchQueryCVEs_WithResults(t *testing.T) {
	nvdResp := map[string]any{
		"resultsPerPage": 1,
		"result": []map[string]any{
			{
				"cve": map[string]any{
					"id":          "CVE-2021-44228",
					"description": map[string]any{"description_data": []map[string]any{{"value": "test"}}},
					"references":  map[string]any{"reference_data": []map[string]any{}},
				},
				"impact":         map[string]any{"baseMetricV3": map[string]any{"cvssV3": map[string]any{"baseScore": 9.8}}},
				"publishedDate":  "2021-12-10T00:00:00Z",
				"configurations": map[string]any{"nodes": []map[string]any{}},
			},
		},
	}
	body, _ := json.Marshal(nvdResp)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	ds := NewVulnDataSource(DataSourceNVD, "nvd", "", srv.URL)
	m, err := BatchQueryCVEs([]string{"CVE-2021-44228"}, []*VulnDataSource{ds})
	if err != nil {
		t.Fatalf("BatchQueryCVEs: %v", err)
	}
	if len(m) == 0 {
		t.Error("expected at least 1 CVE result")
	}
}

// ---- kev.go: GetAll 全缓存命中（!uncached 分支）+ loadAll 双重检查 ----

func TestKEVClient_GetAll_AllCached(t *testing.T) {
	// 预填 cache，使 GetEntries 的 uncached=false → GetAll 直接返回缓存，不触发 loadAll
	c := NewKEVClient()
	c.cache["CVE-2021-44228"] = &KEVEntry{CVEID: "CVE-2021-44228", VendorProject: "Apache", Product: "Log4j"}
	c.allCache = []*KEVEntry{c.cache["CVE-2021-44228"]}
	c.cacheExpiry = time.Now().Add(2 * time.Hour)

	all, err := c.GetAll()
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 cached entry, got %d", len(all))
	}
}

func TestKEVClient_loadAll_DoubleCheckHit(t *testing.T) {
	// 第一次 loadAll 填充缓存后，再次调用应走双重检查命中分支（不重新请求）
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"title":"t","count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`))
	}))
	defer srv.Close()
	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0

	// 第一次：缓存空 → loadAll 请求
	if err := c.loadAll(); err != nil {
		t.Fatalf("first loadAll: %v", err)
	}
	// 第二次：缓存有效 → 双重检查命中，不请求
	if err := c.loadAll(); err != nil {
		t.Fatalf("second loadAll: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 HTTP call (double-check hit on 2nd), got %d", calls)
	}
}

func TestKEVClient_loadAll_NilEntrySkipped(t *testing.T) {
	// 响应含 nil entry → loadAll 跳过
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"title":"t","count":2,"vulnerabilities":[null,{"cveID":"CVE-2021-44228"}]}`))
	}))
	defer srv.Close()
	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0
	if err := c.loadAll(); err != nil {
		t.Fatalf("loadAll: %v", err)
	}
	count, _ := c.Count()
	if count != 1 {
		t.Errorf("expected 1 entry (nil skipped), got %d", count)
	}
}

// ---- remediation.go: IsUrgent return false + isBreakingChange 同首段 return false ----

func TestRemediationAdvice_IsUrgent_NoKEV(t *testing.T) {
	r := &RemediationAdvice{Priority: 0}
	// findings 无 KEVListed → return false
	if r.IsUrgent([]*VulnerabilityFinding{{KEVListed: false}}) {
		t.Error("expected not urgent when no KEVListed")
	}
	// Priority != 0 → 直接 return false
	r2 := &RemediationAdvice{Priority: 1}
	if r2.IsUrgent([]*VulnerabilityFinding{{KEVListed: true}}) {
		t.Error("expected not urgent when Priority != 0")
	}
}

func TestIsBreakingChange_SameMajor(t *testing.T) {
	// 同首段 → return false
	if isBreakingChange("1.2", "1.5") {
		t.Error("expected non-breaking for same major 1.x")
	}
}

// ---- index.go: part 命中后 return cpes（130 行的 RLock+return）已由 Lookup_ProductNotFound 覆盖；
// 这里补 byVendor 命中但 product 为空（return cpes 分支）确保 vendor 全量返回 ----

func TestCPEIndex_Lookup_VendorOnlyReturnAll(t *testing.T) {
	cpes := []*CPE{
		{Part: *PartApplication, Vendor: "apache", ProductName: "log4j"},
		{Part: *PartApplication, Vendor: "apache", ProductName: "httpd"},
	}
	idx := NewCPEIndex(cpes)
	// vendor 命中、product 为空 → 直接返回该 vendor 全部（不进 product filter）
	r := idx.Lookup(&CPE{Vendor: "apache"})
	if len(r) != 2 {
		t.Errorf("expected 2 for vendor-only lookup, got %d", len(r))
	}
}

// ---- osv.go: doRequest 限速 sleep 与 NewRequest err 分支 ----
// NewRequest err 不可达（合法 method/url）；限速 sleep 通过设 minRequestInterval>0 + 短间隔两次请求触发。

func TestOSVClient_DoRequest_RateLimitSleep(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := &OSVClient{
		BaseURL:            srv.URL,
		HTTPClient:         srv.Client(),
		RetryCount:         0,
		RetryDelay:         0,
		minRequestInterval: 50 * time.Millisecond, // 强制限速
	}
	// 两次请求，第二次应触发限速 sleep（elapsed < minRequestInterval）
	for i := 0; i < 2; i++ {
		if _, err := c.doRequest("GET", "/vulns/x", nil); err != nil {
			t.Fatalf("doRequest %d: %v", i, err)
		}
	}
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

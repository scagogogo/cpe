package cpeskills

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 本文件用 httptest mock 覆盖 KEV 客户端的网络成功路径（loadAll 拉取并解析）。
// 成功查询、缓存命中、HTTP 错误、解析错误、enrich 等。

// ---- KEV ----

// kevServer 起一个返回指定 KEV 响应的 mock server。
func kevServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

func TestKEVClient_GetEntry_Success(t *testing.T) {
	resp := KEVResponse{
		Title: "test",
		Count: 1,
		Vulnerabilities: []*KEVEntry{
			{CVEID: "CVE-2021-44228", VendorProject: "apache", Product: "log4j"},
		},
	}
	body, _ := json.Marshal(resp)
	srv := kevServer(t, 200, string(body))
	defer srv.Close()

	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0 // 测试中不限速

	entry, err := c.GetEntry("CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetEntry: %v", err)
	}
	if entry == nil || entry.Product != "log4j" {
		t.Errorf("expected log4j entry, got %+v", entry)
	}
}

func TestKEVClient_GetEntry_CacheHit(t *testing.T) {
	// 第二次 GetEntry 应命中缓存，不再请求 server
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		resp := KEVResponse{Vulnerabilities: []*KEVEntry{{CVEID: "CVE-2021-44228"}}}
		body, _ := json.Marshal(resp)
		w.Write(body)
	}))
	defer srv.Close()

	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0

	if _, err := c.GetEntry("CVE-2021-44228"); err != nil {
		t.Fatalf("first GetEntry: %v", err)
	}
	if _, err := c.GetEntry("CVE-2021-44228"); err != nil {
		t.Fatalf("second GetEntry: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 HTTP call (cache hit on 2nd), got %d", calls)
	}
}

func TestKEVClient_GetEntry_NotInCatalog(t *testing.T) {
	// KEV 中无该 CVE → 返回 nil, nil（不报错）
	resp := KEVResponse{Vulnerabilities: []*KEVEntry{{CVEID: "CVE-2021-44228"}}}
	body, _ := json.Marshal(resp)
	srv := kevServer(t, 200, string(body))
	defer srv.Close()

	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0

	entry, err := c.GetEntry("CVE-9999-0000")
	if err != nil {
		t.Fatalf("GetEntry missing: %v", err)
	}
	if entry != nil {
		t.Errorf("expected nil entry for absent CVE, got %+v", entry)
	}
}

func TestKEVClient_GetEntry_EmptyID(t *testing.T) {
	c := NewKEVClient()
	if _, err := c.GetEntry(""); err == nil {
		t.Error("expected error for empty CVE ID")
	}
}

func TestKEVClient_GetEntry_HTTPError(t *testing.T) {
	srv := kevServer(t, 500, "internal error")
	defer srv.Close()
	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0

	_, err := c.GetEntry("CVE-2021-44228")
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestKEVClient_GetEntry_BadJSON(t *testing.T) {
	srv := kevServer(t, 200, "not json")
	defer srv.Close()
	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0

	_, err := c.GetEntry("CVE-2021-44228")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestKEVClient_IsListed(t *testing.T) {
	resp := KEVResponse{Vulnerabilities: []*KEVEntry{{CVEID: "CVE-2021-44228"}}}
	body, _ := json.Marshal(resp)
	srv := kevServer(t, 200, string(body))
	defer srv.Close()
	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0

	listed, err := c.IsListed("CVE-2021-44228")
	if err != nil || !listed {
		t.Errorf("expected listed=true, got %v err=%v", listed, err)
	}

	listed, err = c.IsListed("CVE-9999-0000")
	if err != nil || listed {
		t.Errorf("expected listed=false, got %v err=%v", listed, err)
	}
}

func TestKEVClient_GetEntries(t *testing.T) {
	resp := KEVResponse{Vulnerabilities: []*KEVEntry{
		{CVEID: "CVE-2021-44228"},
		{CVEID: "CVE-2022-22965"},
	}}
	body, _ := json.Marshal(resp)
	srv := kevServer(t, 200, string(body))
	defer srv.Close()
	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0

	// 空列表
	if m, err := c.GetEntries(nil); err != nil || len(m) != 0 {
		t.Errorf("empty GetEntries: m=%v err=%v", m, err)
	}

	m, err := c.GetEntries([]string{"CVE-2021-44228", "CVE-2022-22965", "CVE-9999-0000"})
	if err != nil {
		t.Fatalf("GetEntries: %v", err)
	}
	if len(m) != 2 {
		t.Errorf("expected 2 entries, got %d", len(m))
	}
}

func TestKEVClient_EnrichVulnerabilityFinding(t *testing.T) {
	resp := KEVResponse{Vulnerabilities: []*KEVEntry{{CVEID: "CVE-2021-44228"}}}
	body, _ := json.Marshal(resp)
	srv := kevServer(t, 200, string(body))
	defer srv.Close()
	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0

	// nil / 空 CVE → no-op
	if err := c.EnrichVulnerabilityFinding(nil); err != nil {
		t.Errorf("nil finding: %v", err)
	}
	if err := c.EnrichVulnerabilityFinding(&VulnerabilityFinding{}); err != nil {
		t.Errorf("nil CVE: %v", err)
	}
	if err := c.EnrichVulnerabilityFinding(&VulnerabilityFinding{CVE: &CVEReference{}}); err != nil {
		t.Errorf("empty CVEID: %v", err)
	}

	// 正常 enrich
	f := &VulnerabilityFinding{CVE: &CVEReference{CVEID: "CVE-2021-44228"}}
	if err := c.EnrichVulnerabilityFinding(f); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !f.KEVListed {
		t.Error("expected KEVListed=true")
	}
}

func TestKEVClient_EnrichVulnerabilityFindings(t *testing.T) {
	resp := KEVResponse{Vulnerabilities: []*KEVEntry{{CVEID: "CVE-2021-44228"}}}
	body, _ := json.Marshal(resp)
	srv := kevServer(t, 200, string(body))
	defer srv.Close()
	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0

	// 空列表 → no-op
	if err := c.EnrichVulnerabilityFindings(nil); err != nil {
		t.Errorf("nil findings: %v", err)
	}
	if err := c.EnrichVulnerabilityFindings([]*VulnerabilityFinding{}); err != nil {
		t.Errorf("empty findings: %v", err)
	}

	findings := []*VulnerabilityFinding{
		{CVE: &CVEReference{CVEID: "CVE-2021-44228"}},
		{CVE: &CVEReference{CVEID: "CVE-9999-0000"}},
	}
	if err := c.EnrichVulnerabilityFindings(findings); err != nil {
		t.Fatalf("enrich batch: %v", err)
	}
	if !findings[0].KEVListed {
		t.Error("expected findings[0] KEVListed=true")
	}
	if findings[1].KEVListed {
		t.Error("expected findings[1] KEVListed=false")
	}
}

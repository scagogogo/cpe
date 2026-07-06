package cpeskills

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewKEVClient(t *testing.T) {
	client := NewKEVClient()
	if client == nil {
		t.Fatal("NewKEVClient returned nil")
	}
	if client.BaseURL != DefaultKEVBaseURL {
		t.Errorf("expected BaseURL %s, got %s", DefaultKEVBaseURL, client.BaseURL)
	}
	if client.HTTPClient == nil {
		t.Error("HTTPClient is nil")
	}
	if client.cache == nil {
		t.Error("cache is nil")
	}
}

func TestNewKEVClientWithOptions(t *testing.T) {
	client := NewKEVClientWithOptions("", 0)
	if client == nil {
		t.Fatal("NewKEVClientWithOptions returned nil")
	}
	if client.BaseURL != DefaultKEVBaseURL {
		t.Errorf("expected default BaseURL, got %s", client.BaseURL)
	}

	client2 := NewKEVClientWithOptions("https://custom.kev/api", 120e9)
	if client2.BaseURL != "https://custom.kev/api" {
		t.Errorf("expected custom BaseURL, got %s", client2.BaseURL)
	}
}

func TestKEVClientClearCache(t *testing.T) {
	client := NewKEVClient()
	client.cache["CVE-2021-44228"] = &KEVEntry{CVEID: "CVE-2021-44228"}
	client.allCache = []*KEVEntry{{CVEID: "CVE-2021-44228"}}
	client.ClearCache()
	if len(client.cache) != 0 {
		t.Errorf("cache not cleared, got %d entries", len(client.cache))
	}
	if client.allCache != nil {
		t.Error("allCache not cleared")
	}
}

func TestKEVSeverityBoost(t *testing.T) {
	tests := []struct {
		current  string
		expected string
	}{
		{"Low", "Medium"},
		{"Medium", "High"},
		{"High", "Critical"},
		{"Critical", "Critical"},
		{"Unknown", "High"},
	}

	for _, tt := range tests {
		result := KEVSeverityBoost(tt.current)
		if result != tt.expected {
			t.Errorf("KEVSeverityBoost(%q) = %q, want %q", tt.current, result, tt.expected)
		}
	}
}

func TestKEVClientFilterByVendor(t *testing.T) {
	client := NewKEVClient()
	client.allCache = []*KEVEntry{
		{CVEID: "CVE-2021-0001", VendorProject: "Apache Software Foundation", Product: "Log4j"},
		{CVEID: "CVE-2021-0002", VendorProject: "Microsoft Corporation", Product: "Windows"},
		{CVEID: "CVE-2021-0003", VendorProject: "Apache Software Foundation", Product: "Tomcat"},
	}
	client.cacheExpiry = time.Now().Add(2 * time.Hour) // future expiry

	results, err := client.FilterByVendor("apache")
	if err != nil {
		t.Fatalf("FilterByVendor failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results for 'apache', got %d", len(results))
	}

	results2, err := client.FilterByVendor("microsoft")
	if err != nil {
		t.Fatalf("FilterByVendor failed: %v", err)
	}
	if len(results2) != 1 {
		t.Errorf("expected 1 result for 'microsoft', got %d", len(results2))
	}

	results3, err := client.FilterByVendor("nonexistent")
	if err != nil {
		t.Fatalf("FilterByVendor failed: %v", err)
	}
	if len(results3) != 0 {
		t.Errorf("expected 0 results for 'nonexistent', got %d", len(results3))
	}
}

func TestKEVClientFilterByProduct(t *testing.T) {
	client := NewKEVClient()
	client.allCache = []*KEVEntry{
		{CVEID: "CVE-2021-0001", VendorProject: "Apache", Product: "Log4j"},
		{CVEID: "CVE-2021-0002", VendorProject: "Microsoft", Product: "Windows"},
		{CVEID: "CVE-2021-0003", VendorProject: "Apache", Product: "Log4j"},
	}
	client.cacheExpiry = time.Now().Add(2 * time.Hour)

	results, err := client.FilterByProduct("log4j")
	if err != nil {
		t.Fatalf("FilterByProduct failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results for 'log4j', got %d", len(results))
	}
}

func TestKEVClientCount(t *testing.T) {
	client := NewKEVClient()
	client.allCache = []*KEVEntry{
		{CVEID: "CVE-2021-0001"},
		{CVEID: "CVE-2021-0002"},
		{CVEID: "CVE-2021-0003"},
	}
	client.cacheExpiry = time.Now().Add(2 * time.Hour)

	count, err := client.Count()
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}
}

func TestKEVClientGetAll(t *testing.T) {
	client := NewKEVClient()
	client.allCache = []*KEVEntry{
		{CVEID: "CVE-2021-0001"},
		{CVEID: "CVE-2021-0002"},
	}
	client.cacheExpiry = time.Now().Add(2 * time.Hour)

	all, err := client.GetAll()
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 entries, got %d", len(all))
	}
}

func TestKEVClientGetEntryCached(t *testing.T) {
	client := NewKEVClient()
	client.cache["CVE-2021-44228"] = &KEVEntry{
		CVEID:         "CVE-2021-44228",
		VendorProject: "Apache",
		Product:       "Log4j",
	}

	entry, err := client.GetEntry("CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetEntry failed: %v", err)
	}
	if entry == nil {
		t.Fatal("expected entry, got nil")
	}
	if entry.VendorProject != "Apache" {
		t.Errorf("expected VendorProject 'Apache', got %q", entry.VendorProject)
	}
}

func TestKEVClientGetEntryEmpty(t *testing.T) {
	client := NewKEVClient()
	_, err := client.GetEntry("")
	if err == nil {
		t.Error("expected error for empty CVE ID")
	}
}

func TestKEVClientGetEntriesCached(t *testing.T) {
	client := NewKEVClient()
	client.cache["CVE-2021-0001"] = &KEVEntry{CVEID: "CVE-2021-0001"}
	client.cache["CVE-2021-0002"] = &KEVEntry{CVEID: "CVE-2021-0002"}

	entries, err := client.GetEntries([]string{"CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003"})
	if err != nil {
		t.Fatalf("GetEntries failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries from cache, got %d", len(entries))
	}
}

func TestKEVClientIsListedCached(t *testing.T) {
	client := NewKEVClient()
	client.cache["CVE-2021-44228"] = &KEVEntry{CVEID: "CVE-2021-44228"}

	listed, err := client.IsListed("CVE-2021-44228")
	if err != nil {
		t.Fatalf("IsListed failed: %v", err)
	}
	if !listed {
		t.Error("expected CVE-2021-44228 to be listed")
	}

	listed2, err := client.IsListed("CVE-2099-99999")
	if err != nil {
		t.Fatalf("IsListed failed: %v", err)
	}
	if listed2 {
		t.Error("expected CVE-2099-99999 to not be listed")
	}
}

func TestKEVClientIsRansomwareRelated(t *testing.T) {
	client := NewKEVClient()
	client.cache["CVE-2021-0001"] = &KEVEntry{
		CVEID:                      "CVE-2021-0001",
		KnownRansomwareCampaignUse: "Known",
	}
	client.cache["CVE-2021-0002"] = &KEVEntry{
		CVEID:                      "CVE-2021-0002",
		KnownRansomwareCampaignUse: "Unknown",
	}

	related, err := client.IsRansomwareRelated("CVE-2021-0001")
	if err != nil {
		t.Fatalf("IsRansomwareRelated failed: %v", err)
	}
	if !related {
		t.Error("expected CVE-2021-0001 to be ransomware related")
	}

	related2, err := client.IsRansomwareRelated("CVE-2021-0002")
	if err != nil {
		t.Fatalf("IsRansomwareRelated failed: %v", err)
	}
	if related2 {
		t.Error("expected CVE-2021-0002 to not be ransomware related")
	}
}

func TestKEVClientGetDueDate(t *testing.T) {
	client := NewKEVClient()
	client.cache["CVE-2021-0001"] = &KEVEntry{
		CVEID:   "CVE-2021-0001",
		DueDate: "2022-01-15",
	}

	dueDate, err := client.GetDueDate("CVE-2021-0001")
	if err != nil {
		t.Fatalf("GetDueDate failed: %v", err)
	}
	if dueDate != "2022-01-15" {
		t.Errorf("expected DueDate '2022-01-15', got %q", dueDate)
	}
}

func TestKEVClientGetRequiredAction(t *testing.T) {
	client := NewKEVClient()
	client.cache["CVE-2021-0001"] = &KEVEntry{
		CVEID:          "CVE-2021-0001",
		RequiredAction: "Apply vendor patch",
	}

	action, err := client.GetRequiredAction("CVE-2021-0001")
	if err != nil {
		t.Fatalf("GetRequiredAction failed: %v", err)
	}
	if action != "Apply vendor patch" {
		t.Errorf("expected 'Apply vendor patch', got %q", action)
	}
}

// ---- nil entry 分支 + EnrichVulnerabilityFinding + loadAll HTTP mock ----

func TestKEVClientGetEntry_NotInCache(t *testing.T) {
	// 缓存未命中且 allCache 为空但 cacheExpiry 未过期 → loadAll 直接返回 nil entry
	// 这里用 httptest mock loadAll
	body := `{"title":"test","count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j","dueDate":"2022-01-15","knownRansomwareCampaignUse":"known","requiredAction":"Apply patch"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	client := NewKEVClient()
	client.BaseURL = srv.URL
	client.HTTPClient = srv.Client()
	client.minRequestInterval = 0

	// 命中
	entry, err := client.GetEntry("CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetEntry: %v", err)
	}
	if entry == nil || entry.VendorProject != "Apache" {
		t.Errorf("expected Apache entry, got %+v", entry)
	}
	// 不在 KEV 中
	entry2, err := client.GetEntry("CVE-9999-0000")
	if err != nil {
		t.Fatalf("GetEntry unknown: %v", err)
	}
	if entry2 != nil {
		t.Errorf("expected nil for unknown CVE, got %+v", entry2)
	}
}

func TestKEVClientGetDueDate_NotInKEV(t *testing.T) {
	body := `{"title":"test","count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	client := NewKEVClient()
	client.BaseURL = srv.URL
	client.HTTPClient = srv.Client()
	client.minRequestInterval = 0
	_, err := client.GetDueDate("CVE-9999-0000")
	if err == nil {
		t.Error("expected error for CVE not in KEV")
	}
}

func TestKEVClientIsRansomwareRelated_NotInKEV(t *testing.T) {
	body := `{"title":"test","count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	client := NewKEVClient()
	client.BaseURL = srv.URL
	client.HTTPClient = srv.Client()
	client.minRequestInterval = 0
	got, err := client.IsRansomwareRelated("CVE-9999-0000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("expected false for CVE not in KEV")
	}
}

func TestKEVClientIsRansomwareRelated_NotKnown(t *testing.T) {
	client := NewKEVClient()
	client.cache["CVE-2021-0001"] = &KEVEntry{CVEID: "CVE-2021-0001", KnownRansomwareCampaignUse: "unknown"}
	got, err := client.IsRansomwareRelated("CVE-2021-0001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("expected false for KnownRansomwareCampaignUse=unknown")
	}
}

func TestKEVClientGetRequiredAction_NotInKEV(t *testing.T) {
	body := `{"title":"test","count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	client := NewKEVClient()
	client.BaseURL = srv.URL
	client.HTTPClient = srv.Client()
	client.minRequestInterval = 0
	_, err := client.GetRequiredAction("CVE-9999-0000")
	if err == nil {
		t.Error("expected error for CVE not in KEV")
	}
}

func TestKEVClientCount_EmptyCache(t *testing.T) {
	// allCache 为空 + cacheExpiry 过期 → 触发 loadAll（用 mock）
	body := `{"title":"test","count":0,"vulnerabilities":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	client := NewKEVClient()
	client.BaseURL = srv.URL
	client.HTTPClient = srv.Client()
	client.minRequestInterval = 0
	count, err := client.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestKEVClientEnrichVulnerabilityFinding(t *testing.T) {
	client := NewKEVClient()
	client.cache["CVE-2021-44228"] = &KEVEntry{CVEID: "CVE-2021-44228"}
	finding := &VulnerabilityFinding{CVE: &CVEReference{CVEID: "CVE-2021-44228"}}
	if err := client.EnrichVulnerabilityFinding(finding); err != nil {
		t.Fatalf("EnrichVulnerabilityFinding: %v", err)
	}
	if !finding.KEVListed {
		t.Error("expected KEVListed=true")
	}
	// 不在 KEV
	finding2 := &VulnerabilityFinding{CVE: &CVEReference{CVEID: "CVE-9999-0000"}}
	if err := client.EnrichVulnerabilityFinding(finding2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding2.KEVListed {
		t.Error("expected KEVListed=false for unknown CVE")
	}
}

func TestKEVClientEnrichVulnerabilityFinding_NilCases(t *testing.T) {
	client := NewKEVClient()
	// nil finding
	if err := client.EnrichVulnerabilityFinding(nil); err != nil {
		t.Errorf("nil finding should be no-op, got %v", err)
	}
	// nil CVE
	if err := client.EnrichVulnerabilityFinding(&VulnerabilityFinding{}); err != nil {
		t.Errorf("nil CVE should be no-op, got %v", err)
	}
	// 空 CVEID
	if err := client.EnrichVulnerabilityFinding(&VulnerabilityFinding{CVE: &CVEReference{}}); err != nil {
		t.Errorf("empty CVEID should be no-op, got %v", err)
	}
}

func TestKEVClientEnrichVulnerabilityFindings(t *testing.T) {
	client := NewKEVClient()
	client.cache["CVE-2021-44228"] = &KEVEntry{CVEID: "CVE-2021-44228"}
	findings := []*VulnerabilityFinding{
		{CVE: &CVEReference{CVEID: "CVE-2021-44228"}},
		{CVE: &CVEReference{CVEID: "CVE-9999-0000"}},
		{CVE: nil},
		nil,
	}
	if err := client.EnrichVulnerabilityFindings(findings); err != nil {
		t.Fatalf("EnrichVulnerabilityFindings: %v", err)
	}
	if !findings[0].KEVListed {
		t.Error("expected first finding KEVListed=true")
	}
	if findings[1].KEVListed {
		t.Error("expected second finding KEVListed=false")
	}
}

func TestKEVClientEnrichVulnerabilityFindings_Empty(t *testing.T) {
	client := NewKEVClient()
	if err := client.EnrichVulnerabilityFindings(nil); err != nil {
		t.Errorf("nil findings should be no-op, got %v", err)
	}
	// 全是无 CVE 的 finding
	if err := client.EnrichVulnerabilityFindings([]*VulnerabilityFinding{{}}); err != nil {
		t.Errorf("no-CVE findings should be no-op, got %v", err)
	}
}

func TestKEVClientFilterByVendorAndProduct_EmptyCache(t *testing.T) {
	body := `{"title":"test","count":0,"vulnerabilities":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	client := NewKEVClient()
	client.BaseURL = srv.URL
	client.HTTPClient = srv.Client()
	client.minRequestInterval = 0
	v, err := client.FilterByVendor("Apache")
	if err != nil {
		t.Fatalf("FilterByVendor: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected 0, got %d", len(v))
	}
	p, err := client.FilterByProduct("Log4j")
	if err != nil {
		t.Fatalf("FilterByProduct: %v", err)
	}
	if len(p) != 0 {
		t.Errorf("expected 0, got %d", len(p))
	}
}

func TestKEVClientGetAll_EmptyCache(t *testing.T) {
	body := `{"title":"test","count":2,"vulnerabilities":[{"cveID":"CVE-1"},{"cveID":"CVE-2"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	client := NewKEVClient()
	client.BaseURL = srv.URL
	client.HTTPClient = srv.Client()
	client.minRequestInterval = 0
	all, err := client.GetAll()
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2, got %d", len(all))
	}
}

func TestKEVClientLoadAll_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "server error")
	}))
	defer srv.Close()
	client := NewKEVClient()
	client.BaseURL = srv.URL
	client.HTTPClient = srv.Client()
	client.minRequestInterval = 0
	_, err := client.GetAll()
	if err == nil {
		t.Error("expected error for 500")
	}
}

func TestKEVClientLoadAll_Unreachable(t *testing.T) {
	client := NewKEVClient()
	client.BaseURL = "http://127.0.0.1:1"
	client.HTTPClient = &http.Client{Timeout: 100 * time.Millisecond}
	client.minRequestInterval = 0
	_, err := client.GetAll()
	if err == nil {
		t.Error("expected error for unreachable host")
	}
}

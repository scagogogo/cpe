package cpeskills

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewOSVClient(t *testing.T) {
	client := NewOSVClient()
	if client == nil {
		t.Fatal("NewOSVClient returned nil")
	}
	if client.BaseURL != DefaultOSVBaseURL {
		t.Errorf("expected BaseURL %s, got %s", DefaultOSVBaseURL, client.BaseURL)
	}
	if client.HTTPClient == nil {
		t.Error("HTTPClient is nil")
	}
	if client.RetryCount != 3 {
		t.Errorf("expected RetryCount 3, got %d", client.RetryCount)
	}
}

func TestNewOSVClientWithOptions(t *testing.T) {
	client := NewOSVClientWithOptions("", 0, 0)
	if client == nil {
		t.Fatal("NewOSVClientWithOptions returned nil")
	}
	if client.BaseURL != DefaultOSVBaseURL {
		t.Errorf("expected default BaseURL, got %s", client.BaseURL)
	}
}

func TestOSVEntryGetFixedVersion(t *testing.T) {
	entry := &OSVEntry{
		Affected: []*OSVAffected{
			{
				Ranges: []*OSVRange{
					{
						Events: []*OSVEvent{
							{Introduced: "2.0.0"},
							{Fixed: "2.17.0"},
						},
					},
				},
			},
		},
	}

	fixed := entry.GetFixedVersion()
	if fixed != "2.17.0" {
		t.Errorf("expected fixed version '2.17.0', got %q", fixed)
	}
}

func TestOSVEntryGetFixedVersionEmpty(t *testing.T) {
	entry := &OSVEntry{}
	fixed := entry.GetFixedVersion()
	if fixed != "" {
		t.Errorf("expected empty fixed version, got %q", fixed)
	}
}

func TestOSVEntryGetFixedVersionNil(t *testing.T) {
	var entry *OSVEntry
	fixed := entry.GetFixedVersion()
	if fixed != "" {
		t.Errorf("expected empty fixed version for nil, got %q", fixed)
	}
}

func TestOSVEntryGetIntroducedVersion(t *testing.T) {
	entry := &OSVEntry{
		Affected: []*OSVAffected{
			{
				Ranges: []*OSVRange{
					{
						Events: []*OSVEvent{
							{Introduced: "2.14.0"},
							{Fixed: "2.17.0"},
						},
					},
				},
			},
		},
	}

	introduced := entry.GetIntroducedVersion()
	if introduced != "2.14.0" {
		t.Errorf("expected introduced version '2.14.0', got %q", introduced)
	}
}

func TestOSVEntryGetAffectedVersions(t *testing.T) {
	entry := &OSVEntry{
		Affected: []*OSVAffected{
			{Versions: []string{"2.14.0", "2.14.1", "2.15.0"}},
		},
	}

	versions := entry.GetAffectedVersions()
	if len(versions) != 3 {
		t.Fatalf("expected 3 versions, got %d", len(versions))
	}
	if versions[0] != "2.14.0" {
		t.Errorf("expected version '2.14.0', got %q", versions[0])
	}
}

func TestOSVEntryHasCVE(t *testing.T) {
	entry := &OSVEntry{
		Aliases: []string{"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"},
	}

	if !entry.HasCVE() {
		t.Error("expected HasCVE=true")
	}
}

func TestOSVEntryHasCVEFalse(t *testing.T) {
	entry := &OSVEntry{
		Aliases: []string{"GHSA-jfh8-c2jp-5v3q"},
	}

	if entry.HasCVE() {
		t.Error("expected HasCVE=false for no CVE aliases")
	}
}

func TestOSVEntryGetCVEIDs(t *testing.T) {
	entry := &OSVEntry{
		Aliases: []string{"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", "CVE-2021-45046"},
	}

	cves := entry.GetCVEIDs()
	if len(cves) != 2 {
		t.Fatalf("expected 2 CVE IDs, got %d", len(cves))
	}
	if cves[0] != "CVE-2021-44228" {
		t.Errorf("expected first CVE 'CVE-2021-44228', got %q", cves[0])
	}
	if cves[1] != "CVE-2021-45046" {
		t.Errorf("expected second CVE 'CVE-2021-45046', got %q", cves[1])
	}
}

func TestOSVEntryGetMaxCVSSScore(t *testing.T) {
	entry := &OSVEntry{
		Severity: []*OSVSeverity{
			{Type: "CVSS_V3", Score: "7.5"},
			{Type: "CVSS_V3", Score: "9.8"},
		},
	}

	score := entry.GetMaxCVSSScore()
	if score != 9.8 {
		t.Errorf("expected max CVSS 9.8, got %f", score)
	}
}

func TestOSVEntryGetMaxCVSSScoreZero(t *testing.T) {
	entry := &OSVEntry{}
	score := entry.GetMaxCVSSScore()
	if score != 0.0 {
		t.Errorf("expected CVSS 0.0, got %f", score)
	}
}

func TestOSVEntryGetSeverityLevel(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{9.8, "Critical"},
		{7.5, "High"},
		{5.0, "Medium"},
		{2.0, "Low"},
		{0.0, "Unknown"},
	}

	for _, tt := range tests {
		entry := &OSVEntry{
			Severity: []*OSVSeverity{
				{Type: "CVSS_V3", Score: mustFormatFloat(tt.score)},
			},
		}
		level := entry.GetSeverityLevel()
		if level != tt.expected {
			t.Errorf("expected severity %q for score %.1f, got %q", tt.expected, tt.score, level)
		}
	}
}

func TestOSVEntryGetReferenceURLs(t *testing.T) {
	entry := &OSVEntry{
		References: []*OSVReference{
			{URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
			{URL: "https://logging.apache.org/log4j/2.x/security.html"},
		},
	}

	urls := entry.GetReferenceURLs()
	if len(urls) != 2 {
		t.Fatalf("expected 2 URLs, got %d", len(urls))
	}
}

func TestOSVEntryIsWithdrawn(t *testing.T) {
	entry := &OSVEntry{
		DatabaseSpecific: map[string]interface{}{
			"withdrawn": true,
		},
	}
	if !entry.IsWithdrawn() {
		t.Error("expected IsWithdrawn=true")
	}

	entry2 := &OSVEntry{}
	if entry2.IsWithdrawn() {
		t.Error("expected IsWithdrawn=false for nil DatabaseSpecific")
	}
}

func TestOSVEntryToVulnerabilityFinding(t *testing.T) {
	entry := &OSVEntry{
		ID:        "GHSA-jfh8-c2jp-5v3q",
		Summary:   "Log4Shell",
		Published: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
		Severity: []*OSVSeverity{
			{Type: "CVSS_V3", Score: "10.0"},
		},
		Affected: []*OSVAffected{
			{
				Ranges: []*OSVRange{
					{
						Events: []*OSVEvent{
							{Introduced: "2.0.0"},
							{Fixed: "2.17.0"},
						},
					},
				},
			},
		},
	}

	finding := entry.ToVulnerabilityFinding()
	if finding == nil {
		t.Fatal("ToVulnerabilityFinding returned nil")
	}
	if finding.FixedVersion != "2.17.0" {
		t.Errorf("expected FixedVersion '2.17.0', got %q", finding.FixedVersion)
	}
	if !finding.FixAvailable {
		t.Error("expected FixAvailable=true")
	}
	if finding.Source != "OSV" {
		t.Errorf("expected Source 'OSV', got %q", finding.Source)
	}
}

func TestOSVEntryToVulnerabilityFindingNil(t *testing.T) {
	var entry *OSVEntry
	finding := entry.ToVulnerabilityFinding()
	if finding != nil {
		t.Error("expected nil for nil OSV entry")
	}
}

func TestParseOSVEntry(t *testing.T) {
	jsonData := `{
		"id": "GHSA-test",
		"summary": "Test vulnerability",
		"aliases": ["CVE-2021-0001"],
		"published": "2021-01-01T00:00:00Z"
	}`

	entry, err := ParseOSVEntry([]byte(jsonData))
	if err != nil {
		t.Fatalf("ParseOSVEntry failed: %v", err)
	}
	if entry.ID != "GHSA-test" {
		t.Errorf("expected ID 'GHSA-test', got %q", entry.ID)
	}
	if !entry.HasCVE() {
		t.Error("expected HasCVE=true")
	}
}

func TestParseOSVEntryInvalid(t *testing.T) {
	_, err := ParseOSVEntry([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseOSVEntries(t *testing.T) {
	jsonData := `[{"id":"GHSA-1"},{"id":"GHSA-2"}]`

	entries, err := ParseOSVEntries([]byte(jsonData))
	if err != nil {
		t.Fatalf("ParseOSVEntries failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestOSVClientQueryNilPURL(t *testing.T) {
	client := NewOSVClient()
	_, err := client.Query(nil)
	if err == nil {
		t.Error("expected error for nil PURL")
	}
}

func TestOSVClientGetVulnerabilityEmptyID(t *testing.T) {
	client := NewOSVClient()
	_, err := client.GetVulnerability("")
	if err == nil {
		t.Error("expected error for empty OSV ID")
	}
}

func TestOSVClientQueryByEcosystem(t *testing.T) {
	client := NewOSVClient()
	_, err := client.QueryByEcosystem("", "test", "1.0")
	if err == nil {
		t.Error("expected error for empty ecosystem")
	}
	_, err = client.QueryByEcosystem("npm", "", "1.0")
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestOSVClientQueryByCommit(t *testing.T) {
	client := NewOSVClient()
	_, err := client.QueryByCommit("")
	if err == nil {
		t.Error("expected error for empty commit")
	}
}

func TestOSVClientQueryBatchEmpty(t *testing.T) {
	client := NewOSVClient()
	result, err := client.QueryBatch(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d entries", len(result))
	}
}

// mustFormatFloat is a test helper
func mustFormatFloat(f float64) string {
	return fmt.Sprintf("%.1f", f)
}

// ---- nil receiver 分支 + GetAffectedPackages ----

func TestOSVEntryNilReceiver(t *testing.T) {
	var e *OSVEntry
	if got := e.GetFixedVersion(); got != "" {
		t.Errorf("nil GetFixedVersion = %q, want empty", got)
	}
	if got := e.GetIntroducedVersion(); got != "" {
		t.Errorf("nil GetIntroducedVersion = %q, want empty", got)
	}
	if got := e.GetAffectedVersions(); got != nil {
		t.Errorf("nil GetAffectedVersions = %v, want nil", got)
	}
	if got := e.GetAffectedPackages(); got != nil {
		t.Errorf("nil GetAffectedPackages = %v, want nil", got)
	}
	if e.HasCVE() {
		t.Error("nil HasCVE = true, want false")
	}
	if got := e.GetCVEIDs(); got != nil {
		t.Errorf("nil GetCVEIDs = %v, want nil", got)
	}
	if got := e.GetMaxCVSSScore(); got != 0.0 {
		t.Errorf("nil GetMaxCVSSScore = %v, want 0", got)
	}
	if got := e.GetReferenceURLs(); got != nil {
		t.Errorf("nil GetReferenceURLs = %v, want nil", got)
	}
	if e.IsWithdrawn() {
		t.Error("nil IsWithdrawn = true, want false")
	}
}

func TestOSVEntryGetAffectedPackages(t *testing.T) {
	entry := &OSVEntry{
		Affected: []*OSVAffected{
			{Package: &OSVPackage{Ecosystem: "npm", Name: "left-pad", PURL: "pkg:npm/left-pad"}},
			{Package: nil},
			{Package: &OSVPackage{Ecosystem: "golang", Name: "github.com/x/y"}},
		},
	}
	pkgs := entry.GetAffectedPackages()
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "left-pad" {
		t.Errorf("expected left-pad, got %q", pkgs[0].Name)
	}
	if pkgs[1].Ecosystem != "golang" {
		t.Errorf("expected golang, got %q", pkgs[1].Ecosystem)
	}
}

func TestOSVEntryGetAffectedPackagesEmpty(t *testing.T) {
	entry := &OSVEntry{Affected: []*OSVAffected{{Package: nil}}}
	pkgs := entry.GetAffectedPackages()
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestOSVEntryGetAffectedVersionsEmpty(t *testing.T) {
	entry := &OSVEntry{}
	v := entry.GetAffectedVersions()
	if len(v) != 0 {
		t.Errorf("expected 0 versions, got %d", len(v))
	}
}

func TestOSVEntryGetCVEIDsNone(t *testing.T) {
	entry := &OSVEntry{Aliases: []string{"GHSA-xxx"}}
	cves := entry.GetCVEIDs()
	if len(cves) != 0 {
		t.Errorf("expected 0 CVEs, got %d: %v", len(cves), cves)
	}
}

func TestOSVEntryHasCVEEmpty(t *testing.T) {
	entry := &OSVEntry{}
	if entry.HasCVE() {
		t.Error("expected HasCVE=false for empty aliases")
	}
}

func TestOSVEntryGetIntroducedVersionNone(t *testing.T) {
	entry := &OSVEntry{
		Affected: []*OSVAffected{
			{Ranges: []*OSVRange{{Events: []*OSVEvent{{Fixed: "2.15.0"}}}}},
		},
	}
	if got := entry.GetIntroducedVersion(); got != "" {
		t.Errorf("expected empty introduced, got %q", got)
	}
	if got := entry.GetFixedVersion(); got != "2.15.0" {
		t.Errorf("expected fixed 2.15.0, got %q", got)
	}
}

// ---- HTTP mock 测试：Query/QueryBatch/GetVulnerability/doRequest 分支 ----

// newMockOSVClient 创建指向 httptest server、无重试延迟的 OSVClient。
func newMockOSVClient(t *testing.T, handler http.Handler) *OSVClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &OSVClient{
		BaseURL:            srv.URL,
		HTTPClient:         srv.Client(),
		RetryCount:         1,
		RetryDelay:         0,
		minRequestInterval: 0,
	}
}

func TestOSVClient_Query_Success(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/query" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"vulns":[{"id":"GHSA-xxx","summary":"test"}]}`)
	}))
	purl := &PackageURL{Type: "npm", Name: "left-pad", Version: "1.3.0"}
	purl2 := *purl
	purl2.Namespace = ""
	entries, err := srv.Query(&purl2)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "GHSA-xxx" {
		t.Errorf("unexpected entries: %+v", entries)
	}
}

func TestOSVClient_Query_InvalidPURL(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	_, err := srv.Query(nil)
	if err == nil {
		t.Error("expected error for nil PURL")
	}
	_, err = srv.Query(&PackageURL{})
	if err == nil {
		t.Error("expected error for invalid PURL")
	}
}

func TestOSVClient_GetVulnerability_Success(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/vulns/GHSA-xxx" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		fmt.Fprint(w, `{"id":"GHSA-xxx","summary":"test vuln"}`)
	}))
	entry, err := srv.GetVulnerability("GHSA-xxx")
	if err != nil {
		t.Fatalf("GetVulnerability: %v", err)
	}
	if entry.ID != "GHSA-xxx" {
		t.Errorf("expected GHSA-xxx, got %q", entry.ID)
	}
}

func TestOSVClient_GetVulnerability_EmptyID(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	_, err := srv.GetVulnerability("")
	if err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestOSVClient_QueryByEcosystem_Success(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"vulns":[{"id":"GHSA-eco"}]}`)
	}))
	entries, err := srv.QueryByEcosystem("npm", "left-pad", "1.0")
	if err != nil {
		t.Fatalf("QueryByEcosystem: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1, got %d", len(entries))
	}
}

func TestOSVClient_QueryByEcosystem_EmptyArgs(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	_, err := srv.QueryByEcosystem("", "name", "1.0")
	if err == nil {
		t.Error("expected error for empty ecosystem")
	}
	_, err = srv.QueryByEcosystem("npm", "", "1.0")
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestOSVClient_QueryByCommit_Success(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"vulns":[{"id":"GHSA-commit"}]}`)
	}))
	entries, err := srv.QueryByCommit("abc123")
	if err != nil {
		t.Fatalf("QueryByCommit: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1, got %d", len(entries))
	}
}

func TestOSVClient_QueryByCommit_Empty(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	_, err := srv.QueryByCommit("")
	if err == nil {
		t.Error("expected error for empty commit")
	}
}

func TestOSVClient_QueryBatch_Success(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/querybatch" {
			t.Errorf("expected /querybatch, got %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"results":[{"vulns":[{"id":"GHSA-1"}]},{"vulns":[]}]}`)
	}))
	p1 := &PackageURL{Type: "npm", Name: "left-pad", Version: "1.0"}
	p2 := &PackageURL{Type: "npm", Name: "right-pad", Version: "2.0"}
	res, err := srv.QueryBatch([]*PackageURL{p1, p2})
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("expected 2 results, got %d", len(res))
	}
}

func TestOSVClient_QueryBatch_LimitExceeded(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	purls := make([]*PackageURL, 1001)
	for i := range purls {
		purls[i] = &PackageURL{Type: "npm", Name: "x", Version: "1.0"}
	}
	_, err := srv.QueryBatch(purls)
	if err == nil {
		t.Error("expected error for >1000 purls")
	}
}

func TestOSVClient_QueryBatch_AllInvalid(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	res, err := srv.QueryBatch([]*PackageURL{nil, {}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected empty result, got %d", len(res))
	}
}

// doRequest 状态码分支
func TestOSVClient_DoRequest_4xx(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "not found")
	}))
	_, err := srv.QueryByEcosystem("npm", "left-pad", "1.0")
	if err == nil {
		t.Error("expected error for 404")
	}
}

func TestOSVClient_DoRequest_5xx_RetryThenFail(t *testing.T) {
	calls := 0
	srv := newMockOSVClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "server error")
	}))
	_, err := srv.QueryByEcosystem("npm", "left-pad", "1.0")
	if err == nil {
		t.Error("expected error for 500")
	}
	// RetryCount=1 → 2 次尝试
	if calls != 2 {
		t.Errorf("expected 2 calls (1 retry), got %d", calls)
	}
}

func TestOSVClient_DoRequest_429_RetryThenFail(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "rate limited")
	}))
	_, err := srv.QueryByEcosystem("npm", "left-pad", "1.0")
	if err == nil {
		t.Error("expected error for 429")
	}
}

func TestOSVClient_DoRequest_BadURL(t *testing.T) {
	// 用不可达的 URL 触发 HTTPClient.Do 错误
	c := &OSVClient{
		BaseURL:            "http://127.0.0.1:1", // 不可达端口
		HTTPClient:         &http.Client{Timeout: 100 * time.Millisecond},
		RetryCount:         0,
		RetryDelay:         0,
		minRequestInterval: 0,
	}
	_, err := c.QueryByEcosystem("npm", "left-pad", "1.0")
	if err == nil {
		t.Error("expected error for unreachable host")
	}
}

// 顶层便捷函数（用 mock server）
func TestQueryOSV_TopLevel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"vulns":[{"id":"GHSA-top"}]}`)
	}))
	defer srv.Close()
	// 临时替换默认 baseURL 不可能（常量），改用 client 方法已覆盖；
	// 这里测顶层 QueryOSV 用真实默认 URL 会联网，故仅验证 nil PURL 路径。
	_, err := QueryOSV(nil)
	if err == nil {
		t.Error("expected error for nil PURL")
	}
}

func TestQueryOSVBatch_TopLevel(t *testing.T) {
	// 空 purls 路径不联网
	res, err := QueryOSVBatch(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected empty, got %d", len(res))
	}
}

func TestBatchQueryOSVWithClient_Success(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"results":[{"vulns":[{"id":"GHSA-1"}]}]}`)
	}))
	p := &PackageURL{Type: "npm", Name: "left-pad", Version: "1.0"}
	res, err := BatchQueryOSVWithClient(srv, []*PackageURL{p})
	if err != nil {
		t.Fatalf("BatchQueryOSVWithClient: %v", err)
	}
	if len(res) != 1 {
		t.Errorf("expected 1 result, got %d", len(res))
	}
}

func TestBatchQueryOSVWithClient_NilClient(t *testing.T) {
	// nil client → 内部 NewOSVClient()，空 purls 不联网
	res, err := BatchQueryOSVWithClient(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected empty, got %d", len(res))
	}
}

func TestBatchQueryOSVWithClient_Error(t *testing.T) {
	srv := newMockOSVClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	p := &PackageURL{Type: "npm", Name: "left-pad", Version: "1.0"}
	_, err := BatchQueryOSVWithClient(srv, []*PackageURL{p})
	if err == nil {
		t.Error("expected error for 500")
	}
}

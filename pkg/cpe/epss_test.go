package cpeskills

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewEPSSClient(t *testing.T) {
	client := NewEPSSClient()
	if client == nil {
		t.Fatal("NewEPSSClient returned nil")
	}
	if client.BaseURL != DefaultEPSSBaseURL {
		t.Errorf("expected BaseURL %s, got %s", DefaultEPSSBaseURL, client.BaseURL)
	}
	if client.HTTPClient == nil {
		t.Error("HTTPClient is nil")
	}
	if client.cache == nil {
		t.Error("cache is nil")
	}
}

func TestNewEPSSClientWithOptions(t *testing.T) {
	client := NewEPSSClientWithOptions("", 0)
	if client == nil {
		t.Fatal("NewEPSSClientWithOptions returned nil")
	}
	if client.BaseURL != DefaultEPSSBaseURL {
		t.Errorf("expected default BaseURL, got %s", client.BaseURL)
	}

	client2 := NewEPSSClientWithOptions("https://custom.api/eps", 120e9)
	if client2.BaseURL != "https://custom.api/eps" {
		t.Errorf("expected custom BaseURL, got %s", client2.BaseURL)
	}
}

func TestNormalizeCVEID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CVE-2021-44228", "CVE-2021-44228"},
		{"cve-2021-44228", "CVE-2021-44228"},
		{"2021-44228", "CVE-2021-44228"},
		{"  CVE-2021-44228  ", "CVE-2021-44228"},
	}

	for _, tt := range tests {
		result := normalizeCVEID(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeCVEID(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestEPSSEntryIsHighRisk(t *testing.T) {
	tests := []struct {
		score    float64
		expected bool
	}{
		{0.5, true},
		{0.1, true},
		{0.09, false},
		{0.0, false},
		{0.99, true},
	}

	for _, tt := range tests {
		entry := &EPSSEntry{EPSSScore: tt.score}
		if entry.IsHighRisk() != tt.expected {
			t.Errorf("EPSSEntry{%.2f}.IsHighRisk() = %v, want %v", tt.score, entry.IsHighRisk(), tt.expected)
		}
	}
}

func TestEPSSEntryIsCriticalRisk(t *testing.T) {
	tests := []struct {
		score    float64
		expected bool
	}{
		{0.5, true},
		{0.49, false},
		{0.9, true},
		{0.0, false},
	}

	for _, tt := range tests {
		entry := &EPSSEntry{EPSSScore: tt.score}
		if entry.IsCriticalRisk() != tt.expected {
			t.Errorf("EPSSEntry{%.2f}.IsCriticalRisk() = %v, want %v", tt.score, entry.IsCriticalRisk(), tt.expected)
		}
	}
}

func TestEPSSEntryGetRiskLevel(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.9, "Critical"},
		{0.5, "Critical"},
		{0.2, "High"},
		{0.1, "High"},
		{0.05, "Medium"},
		{0.01, "Medium"},
		{0.005, "Low"},
		{0.0, "Low"},
	}

	for _, tt := range tests {
		entry := &EPSSEntry{EPSSScore: tt.score}
		if entry.GetRiskLevel() != tt.expected {
			t.Errorf("EPSSEntry{%.3f}.GetRiskLevel() = %q, want %q", tt.score, entry.GetRiskLevel(), tt.expected)
		}
	}
}

func TestEPSSScoreToRiskFactor(t *testing.T) {
	tests := []struct {
		epss     float64
		minRange float64
		maxRange float64
	}{
		{0.0, 0.0, 0.0},
		{0.001, 0.0, 2.0},
		{0.01, 2.0, 5.0},
		{0.1, 5.0, 8.0},
		{0.5, 7.0, 10.0},
		{0.9, 8.0, 10.0},
		{1.0, 9.0, 10.0},
	}

	for _, tt := range tests {
		factor := EPSSScoreToRiskFactor(tt.epss)
		if factor < tt.minRange || factor > tt.maxRange {
			t.Errorf("EPSSScoreToRiskFactor(%.3f) = %.2f, expected in range [%.1f, %.1f]",
				tt.epss, factor, tt.minRange, tt.maxRange)
		}
	}
}

func TestEPSSClientClearCache(t *testing.T) {
	client := NewEPSSClient()
	client.cache["CVE-2021-0001"] = &EPSSEntry{EPSSScore: 0.5}
	client.ClearCache()
	if client.CacheSize() != 0 {
		t.Errorf("CacheSize after ClearCache = %d, want 0", client.CacheSize())
	}
}

func TestEPSSClientCacheSize(t *testing.T) {
	client := NewEPSSClient()
	if client.CacheSize() != 0 {
		t.Errorf("initial CacheSize = %d, want 0", client.CacheSize())
	}
	client.cache["CVE-2021-0001"] = &EPSSEntry{EPSSScore: 0.5}
	if client.CacheSize() != 1 {
		t.Errorf("CacheSize after insert = %d, want 1", client.CacheSize())
	}
}

func TestEPSSParseCSVResponse(t *testing.T) {
	client := NewEPSSClient()
	csvData := "cve,epss,percentile,date\nCVE-2021-44228,0.97504,0.99998,2024-01-15\nCVE-2021-45046,0.91000,0.99950,2024-01-15\n"

	result, err := client.parseEPSSResponse(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("parseEPSSResponse failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}

	entry, ok := result["CVE-2021-44228"]
	if !ok {
		t.Fatal("CVE-2021-44228 not found")
	}
	if entry.EPSSScore != 0.97504 {
		t.Errorf("expected EPSS 0.97504, got %f", entry.EPSSScore)
	}
	if entry.Percentile != 0.99998 {
		t.Errorf("expected percentile 0.99998, got %f", entry.Percentile)
	}

	entry2, ok := result["CVE-2021-45046"]
	if !ok {
		t.Fatal("CVE-2021-45046 not found")
	}
	if entry2.EPSSScore != 0.91 {
		t.Errorf("expected EPSS 0.91, got %f", entry2.EPSSScore)
	}
}

func TestEPSSParseCSVResponseEmpty(t *testing.T) {
	client := NewEPSSClient()
	csvData := "cve,epss,percentile,date\n"

	result, err := client.parseEPSSResponse(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("parseEPSSResponse failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 entries, got %d", len(result))
	}
}

func TestEPSSParseCSVResponseMissingColumns(t *testing.T) {
	client := NewEPSSClient()
	csvData := "wrong,columns,here\nval1,val2,val3\n"

	_, err := client.parseEPSSResponse(strings.NewReader(csvData))
	if err == nil {
		t.Error("expected error for missing columns, got nil")
	}
}

func TestLog10Float(t *testing.T) {
	tests := []struct {
		input    float64
		expected float64
	}{
		{1, 0},
		{10, 1},
		{100, 2},
		{1000, 3},
		{0.1, -1},
		{0.01, -2},
	}

	for _, tt := range tests {
		result := log10Float(tt.input)
		if abs(result-tt.expected) > 0.01 {
			t.Errorf("log10Float(%f) = %f, want %f (diff: %f)", tt.input, result, tt.expected, abs(result-tt.expected))
		}
	}
}

func TestLnFloat(t *testing.T) {
	tests := []struct {
		input    float64
		expected float64
	}{
		{1, 0},
		{2.718281828, 1},
		{7.389056, 2},
	}

	for _, tt := range tests {
		result := lnFloat(tt.input)
		if abs(result-tt.expected) > 0.05 {
			t.Errorf("lnFloat(%f) = %f, want %f (diff: %f)", tt.input, result, tt.expected, abs(result-tt.expected))
		}
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// newMockEPSSServer creates an httptest.Server that returns EPSS CSV data.
func newMockEPSSServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		cveParam := r.URL.Query().Get("cve")
		if cveParam == "" {
			fmt.Fprintln(w, "cve,epss,percentile,date")
			return
		}
		cves := strings.Split(cveParam, ",")
		fmt.Fprintln(w, "cve,epss,percentile,date")
		for i, cve := range cves {
			epss := 0.9 - float64(i)*0.3
			percentile := 0.99 - float64(i)*0.2
			if epss < 0 {
				epss = 0.001
			}
			if percentile < 0 {
				percentile = 0.5
			}
			fmt.Fprintf(w, "%s,%.5f,%.5f,2024-01-15\n", cve, epss, percentile)
		}
	}))
}

func TestEPSSClient_GetScore(t *testing.T) {
	server := newMockEPSSServer()
	defer server.Close()

	client := NewEPSSClient()
	client.BaseURL = server.URL
	client.HTTPClient = server.Client()

	entry, err := client.GetScore("CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetScore failed: %v", err)
	}
	if entry == nil {
		t.Fatal("GetScore returned nil entry")
	}
	if entry.CVEID != "CVE-2021-44228" {
		t.Errorf("expected CVEID CVE-2021-44228, got %s", entry.CVEID)
	}
	if entry.EPSSScore <= 0 {
		t.Errorf("expected positive EPSS score, got %f", entry.EPSSScore)
	}
}

func TestEPSSClient_GetScore_EmptyCVE(t *testing.T) {
	client := NewEPSSClient()
	_, err := client.GetScore("")
	if err == nil {
		t.Error("expected error for empty CVE ID, got nil")
	}
}

func TestEPSSClient_GetScore_CacheHit(t *testing.T) {
	server := newMockEPSSServer()
	defer server.Close()

	client := NewEPSSClient()
	client.BaseURL = server.URL
	client.HTTPClient = server.Client()

	// First call fetches from API
	entry1, err := client.GetScore("CVE-2021-44228")
	if err != nil {
		t.Fatalf("first GetScore failed: %v", err)
	}

	// Second call should use cache (server not called again)
	entry2, err := client.GetScore("CVE-2021-44228")
	if err != nil {
		t.Fatalf("cached GetScore failed: %v", err)
	}
	if entry2.EPSSScore != entry1.EPSSScore {
		t.Errorf("cached score %f != original %f", entry2.EPSSScore, entry1.EPSSScore)
	}
}

func TestEPSSClient_GetScore_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "internal server error")
	}))
	defer server.Close()

	client := NewEPSSClient()
	client.BaseURL = server.URL
	client.HTTPClient = server.Client()

	_, err := client.GetScore("CVE-2021-44228")
	if err == nil {
		t.Error("expected error for API error response, got nil")
	}
}

func TestEPSSClient_GetScores(t *testing.T) {
	server := newMockEPSSServer()
	defer server.Close()

	client := NewEPSSClient()
	client.BaseURL = server.URL
	client.HTTPClient = server.Client()

	scores, err := client.GetScores([]string{"CVE-2021-44228", "CVE-2021-45046"})
	if err != nil {
		t.Fatalf("GetScores failed: %v", err)
	}
	if len(scores) != 2 {
		t.Errorf("expected 2 scores, got %d", len(scores))
	}
	if _, ok := scores["CVE-2021-44228"]; !ok {
		t.Error("CVE-2021-44228 not found in results")
	}
	if _, ok := scores["CVE-2021-45046"]; !ok {
		t.Error("CVE-2021-45046 not found in results")
	}
}

func TestEPSSClient_GetScores_EmptyList(t *testing.T) {
	client := NewEPSSClient()
	scores, err := client.GetScores([]string{})
	if err != nil {
		t.Fatalf("GetScores with empty list failed: %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("expected 0 scores for empty list, got %d", len(scores))
	}
}

func TestEPSSClient_GetScores_CacheHit(t *testing.T) {
	server := newMockEPSSServer()
	defer server.Close()

	client := NewEPSSClient()
	client.BaseURL = server.URL
	client.HTTPClient = server.Client()

	// Pre-populate cache
	client.cache["CVE-2021-44228"] = &EPSSEntry{CVEID: "CVE-2021-44228", EPSSScore: 0.97}

	scores, err := client.GetScores([]string{"CVE-2021-44228"})
	if err != nil {
		t.Fatalf("GetScores failed: %v", err)
	}
	if len(scores) != 1 {
		t.Errorf("expected 1 score, got %d", len(scores))
	}
	if scores["CVE-2021-44228"].EPSSScore != 0.97 {
		t.Errorf("expected cached score 0.97, got %f", scores["CVE-2021-44228"].EPSSScore)
	}
}

func TestEPSSClient_EnrichVulnerabilityFinding(t *testing.T) {
	server := newMockEPSSServer()
	defer server.Close()

	client := NewEPSSClient()
	client.BaseURL = server.URL
	client.HTTPClient = server.Client()

	finding := &VulnerabilityFinding{
		CVE: &CVEReference{CVEID: "CVE-2021-44228"},
	}

	err := client.EnrichVulnerabilityFinding(finding)
	if err != nil {
		t.Fatalf("EnrichVulnerabilityFinding failed: %v", err)
	}
	if finding.EPSSScore <= 0 {
		t.Errorf("expected positive EPSS score after enrichment, got %f", finding.EPSSScore)
	}
}

func TestEPSSClient_EnrichVulnerabilityFinding_NilFinding(t *testing.T) {
	client := NewEPSSClient()
	err := client.EnrichVulnerabilityFinding(nil)
	if err != nil {
		t.Errorf("expected nil error for nil finding, got %v", err)
	}
}

func TestEPSSClient_EnrichVulnerabilityFinding_NilCVE(t *testing.T) {
	client := NewEPSSClient()
	err := client.EnrichVulnerabilityFinding(&VulnerabilityFinding{})
	if err != nil {
		t.Errorf("expected nil error for nil CVE, got %v", err)
	}
}

func TestEPSSClient_EnrichVulnerabilityFinding_EmptyCVEID(t *testing.T) {
	client := NewEPSSClient()
	err := client.EnrichVulnerabilityFinding(&VulnerabilityFinding{
		CVE: &CVEReference{CVEID: ""},
	})
	if err != nil {
		t.Errorf("expected nil error for empty CVE ID, got %v", err)
	}
}

func TestEPSSClient_EnrichVulnerabilityFindings(t *testing.T) {
	server := newMockEPSSServer()
	defer server.Close()

	client := NewEPSSClient()
	client.BaseURL = server.URL
	client.HTTPClient = server.Client()

	findings := []*VulnerabilityFinding{
		{CVE: &CVEReference{CVEID: "CVE-2021-44228"}},
		{CVE: &CVEReference{CVEID: "CVE-2021-45046"}},
	}

	err := client.EnrichVulnerabilityFindings(findings)
	if err != nil {
		t.Fatalf("EnrichVulnerabilityFindings failed: %v", err)
	}
	for i, f := range findings {
		if f.EPSSScore <= 0 {
			t.Errorf("finding[%d]: expected positive EPSS score, got %f", i, f.EPSSScore)
		}
	}
}

func TestEPSSClient_EnrichVulnerabilityFindings_EmptyList(t *testing.T) {
	client := NewEPSSClient()
	err := client.EnrichVulnerabilityFindings([]*VulnerabilityFinding{})
	if err != nil {
		t.Errorf("expected nil error for empty list, got %v", err)
	}
}

func TestEPSSClient_EnrichVulnerabilityFindings_NilEntries(t *testing.T) {
	server := newMockEPSSServer()
	defer server.Close()

	client := NewEPSSClient()
	client.BaseURL = server.URL
	client.HTTPClient = server.Client()

	findings := []*VulnerabilityFinding{
		nil,
		{CVE: nil},
		{CVE: &CVEReference{CVEID: ""}},
		{CVE: &CVEReference{CVEID: "CVE-2021-44228"}},
	}

	err := client.EnrichVulnerabilityFindings(findings)
	if err != nil {
		t.Fatalf("EnrichVulnerabilityFindings failed: %v", err)
	}
	// Only the last finding should have a score
	if findings[3].EPSSScore <= 0 {
		t.Errorf("expected positive EPSS score for last finding, got %f", findings[3].EPSSScore)
	}
}

func TestEPSSClient_fetchScore_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		fmt.Fprintln(w, "cve,epss,percentile,date")
	}))
	defer server.Close()

	client := NewEPSSClient()
	client.BaseURL = server.URL
	client.HTTPClient = server.Client()

	_, err := client.fetchScore("CVE-2099-00001")
	if err == nil {
		t.Error("expected error for CVE not found in response, got nil")
	}
}

func TestEPSSClient_fetchScores_EmptyList(t *testing.T) {
	client := NewEPSSClient()
	scores, err := client.fetchScores([]string{})
	if err != nil {
		t.Fatalf("fetchScores with empty list failed: %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("expected 0 scores, got %d", len(scores))
	}
}

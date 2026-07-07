package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cpeskills "github.com/scagogogo/cpe-skills"
)

// nvd_net_test.go — 通过 nvdHTTPClientOverride 注入 redirectTransport，
// 把 NVD feed 请求导向 httptest，离线覆盖 runNVDDownload 的 text/json 路径。
// 另用 t.TempDir() 写假 NVDCPEData JSON 覆盖 cves-for-cpe/cpes-for-cve 的 error 路径。

// redirectTransport 把所有请求重定向到 targetURL（复刻自主包 nvd_test.go）。
type cliRedirectTransport struct {
	targetURL string
}

func (t *cliRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := t.targetURL + req.URL.Path
	newReq, err := http.NewRequest(req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return http.DefaultTransport.RoundTrip(newReq)
}

const nvdDictXML = `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3" generated="2021-12-10T00:00:00Z">
  <cpe-item name="cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*">
    <title>Apache Log4j 2.14</title>
  </cpe-item>
</cpe-list>`

func newNVDMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	matchData := map[string]interface{}{
		"matches": []map[string]interface{}{
			{
				"cpe23Uri": "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*",
				"cveNames": []string{"CVE-2021-44228"},
			},
		},
	}
	matchBody, _ := json.Marshal(matchData)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		gw := gzip.NewWriter(w)
		if strings.HasSuffix(r.URL.Path, ".xml.gz") {
			io.WriteString(gw, nvdDictXML)
		} else {
			gw.Write(matchBody)
		}
		gw.Close()
	}))
}

func TestRunNVDDownload_TextJSON(t *testing.T) {
	srv := newNVDMockServer(t)
	defer srv.Close()

	// nvdHTTPClientOverride 不被 runCLI 复位（见 cli_newcmds_test.go 注释），
	// 测试自行 save/restore。
	origOverride := nvdHTTPClientOverride
	defer func() { nvdHTTPClientOverride = origOverride }()
	nvdHTTPClientOverride = &http.Client{
		Transport: &cliRedirectTransport{targetURL: srv.URL},
		Timeout:   30 * time.Second,
	}
	// 用临时 cache dir，避免污染默认缓存。
	cacheDir := t.TempDir()

	// text 路径
	out, err := runCLI(t, "nvd", "download", "--cache-dir", cacheDir, "--cache-max-age", "1")
	if err != nil {
		t.Fatalf("nvd download text: %v", err)
	}
	if !strings.Contains(out, "Downloaded NVD data") {
		t.Errorf("expected download summary, got: %s", out)
	}

	// json 路径
	out, err = runCLIJSON(t, "nvd", "download", "--cache-dir", cacheDir, "--cache-max-age", "1")
	if err != nil {
		t.Fatalf("nvd download json: %v", err)
	}
	if !strings.Contains(out, "CPEDictionary") {
		t.Errorf("expected CPEDictionary in json, got: %s", out[:200])
	}
}

func TestRunNVDDownload_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	origOverride := nvdHTTPClientOverride
	defer func() { nvdHTTPClientOverride = origOverride }()
	nvdHTTPClientOverride = &http.Client{
		Transport: &cliRedirectTransport{targetURL: srv.URL},
		Timeout:   10 * time.Second,
	}
	_, err := runCLI(t, "nvd", "download", "--cache-dir", t.TempDir(), "--cache-max-age", "1")
	if err == nil {
		t.Fatal("expected error for NVD 500")
	}
}

// writeFakeNVDData 写一个最小合法 NVDCPEData JSON 到临时文件，供
// cves-for-cpe / cpes-for-cve 加载。
func writeFakeNVDData(t *testing.T) string {
	t.Helper()
	data := &cpeskills.NVDCPEData{
		CPEMatchData: &cpeskills.CPEMatchData{
			CPEToCVEs: map[string][]string{
				"cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*": {"CVE-2021-44228"},
			},
			CVEToCPEs: map[string][]string{
				"CVE-2021-44228": {"cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"},
			},
		},
	}
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal fake nvd: %v", err)
	}
	p := filepath.Join(t.TempDir(), "nvd.json")
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatalf("write fake nvd: %v", err)
	}
	return p
}

func TestRunNVD_CVEsForCPE(t *testing.T) {
	p := writeFakeNVDData(t)
	out, err := runCLI(t, "nvd", "cves-for-cpe", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*", "--data", p)
	if err != nil {
		t.Fatalf("cves-for-cpe: %v", err)
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Errorf("expected cve in output, got: %s", out)
	}
}

func TestRunNVD_CPEsForCVE_JSON(t *testing.T) {
	p := writeFakeNVDData(t)
	out, err := runCLIJSON(t, "nvd", "cpes-for-cve", "CVE-2021-44228", "--data", p)
	if err != nil {
		t.Fatalf("cpes-for-cve: %v", err)
	}
	if !strings.Contains(out, "log4j") {
		t.Errorf("expected cpe in json, got: %s", out)
	}
}

func TestRunNVD_MissingDataFile(t *testing.T) {
	// --data 指向不存在的文件 → loadNVDData error
	_, err := runCLI(t, "nvd", "cves-for-cpe", "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*", "--data", "/nonexistent/nvd.json")
	if err == nil {
		t.Fatal("expected error for missing data file")
	}
}

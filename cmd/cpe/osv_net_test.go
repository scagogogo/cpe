package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// osv_net_test.go — 通过 --base-url 注入 httptest，离线覆盖 runOSV 的
// --purl / --ecosystem 两条查询路径，以及 parse-error / query-error 路径。

const osvJSONOK = `{"vulns":[
  {"id":"GHSA-1","summary":"RCE in left-pad","modified":"2022-01-01T00:00:00Z"}
]}`

func TestRunOSV_Purl_TextJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(osvJSONOK))
	}))
	defer srv.Close()

	out, err := runCLI(t, "osv", "--base-url", srv.URL, "query", "--purl", "pkg:npm/left-pad@1.3.0")
	if err != nil {
		t.Fatalf("osv purl: %v", err)
	}
	if !strings.Contains(out, "GHSA-1") {
		t.Errorf("expected vuln id, got: %s", out)
	}

	out, err = runCLIJSON(t, "osv", "--base-url", srv.URL, "query", "--purl", "pkg:npm/left-pad@1.3.0")
	if err != nil {
		t.Fatalf("osv purl json: %v", err)
	}
	if !strings.Contains(out, "GHSA-1") {
		t.Errorf("expected vuln id in json, got: %s", out)
	}
}

func TestRunOSV_Ecosystem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(osvJSONOK))
	}))
	defer srv.Close()

	out, err := runCLI(t, "osv", "--base-url", srv.URL, "query", "--ecosystem", "npm", "--name", "left-pad", "--version", "1.3.0")
	if err != nil {
		t.Fatalf("osv ecosystem: %v", err)
	}
	if !strings.Contains(out, "GHSA-1") {
		t.Errorf("expected vuln id, got: %s", out)
	}
}

func TestRunOSV_NoArgs(t *testing.T) {
	// 既无 --purl 也无 --ecosystem+--name → 返回参数错误
	_, err := runCLI(t, "osv", "query")
	if err == nil {
		t.Fatal("expected error for missing query args")
	}
}

func TestRunOSV_BadPURL(t *testing.T) {
	// 非法 purl → ParsePURL 错误
	_, err := runCLI(t, "osv", "query", "--purl", "not-a-purl%%%")
	if err == nil {
		t.Fatal("expected error for invalid purl")
	}
}

func TestRunOSV_QueryError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("down"))
	}))
	defer srv.Close()

	_, err := runCLI(t, "osv", "--base-url", srv.URL, "query", "--purl", "pkg:npm/left-pad@1.3.0")
	if err == nil {
		t.Fatal("expected error for OSV 503")
	}
}

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// kev_net_test.go — 通过 --base-url 注入 httptest，离线覆盖 kev 的
// is-listed / get / list 三命令的 text/json/error 路径。

const kevJSONOK = `{"title":"CISA KEV","count":1,"vulnerabilities":[
  {"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j",
   "vulnerabilityName":"Log4j Remote Code Execution",
   "dueDate":"2022-01-10","requiredAction":"Apply updates",
   "knownRansomwareCampaignUse":"Known"}
]}`

func TestRunKEV_IsListed_TextJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(kevJSONOK))
	}))
	defer srv.Close()

	// text 路径：listed
	out, err := runCLI(t, "kev", "--base-url", srv.URL, "is-listed", "CVE-2021-44228")
	if err != nil {
		t.Fatalf("kev is-listed: %v", err)
	}
	if !strings.Contains(out, "LISTED") {
		t.Errorf("expected LISTED, got: %s", out)
	}

	// text 路径：not listed（KEV 里没有该 CVE）
	out, err = runCLI(t, "kev", "--base-url", srv.URL, "is-listed", "CVE-9999-9999")
	if err != nil {
		t.Fatalf("kev is-listed missing: %v", err)
	}
	if !strings.Contains(out, "NOT LISTED") {
		t.Errorf("expected NOT LISTED, got: %s", out)
	}

	// json 路径
	out, err = runCLIJSON(t, "kev", "--base-url", srv.URL, "is-listed", "CVE-2021-44228")
	if err != nil {
		t.Fatalf("kev is-listed json: %v", err)
	}
	if !strings.Contains(out, `"listed": true`) {
		t.Errorf("expected listed:true, got: %s", out)
	}
}

func TestRunKEV_Get_TextJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(kevJSONOK))
	}))
	defer srv.Close()

	out, err := runCLI(t, "kev", "--base-url", srv.URL, "get", "CVE-2021-44228")
	if err != nil {
		t.Fatalf("kev get: %v", err)
	}
	if !strings.Contains(out, "Log4j") {
		t.Errorf("expected Log4j in output, got: %s", out)
	}

	out, err = runCLIJSON(t, "kev", "--base-url", srv.URL, "get", "CVE-2021-44228")
	if err != nil {
		t.Fatalf("kev get json: %v", err)
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Errorf("expected cve in json, got: %s", out)
	}
}

func TestRunKEV_List_TextJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(kevJSONOK))
	}))
	defer srv.Close()

	out, err := runCLI(t, "kev", "--base-url", srv.URL, "list")
	if err != nil {
		t.Fatalf("kev list: %v", err)
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Errorf("expected cve in list, got: %s", out)
	}

	out, err = runCLIJSON(t, "kev", "--base-url", srv.URL, "list")
	if err != nil {
		t.Fatalf("kev list json: %v", err)
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Errorf("expected cve in json list, got: %s", out)
	}
}

func TestRunKEV_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("down"))
	}))
	defer srv.Close()

	_, err := runCLI(t, "kev", "--base-url", srv.URL, "list")
	if err == nil {
		t.Fatal("expected error for KEV 502")
	}
}

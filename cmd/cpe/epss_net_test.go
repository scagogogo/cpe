package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// epss_net_test.go — 通过 epssBaseURL 注入 httptest，离线覆盖 runEPSS 的
// text/json 输出与 query error 路径。

const epssCSVOK = "cve,epss,percentile,date\nCVE-2021-44228,0.875,0.956,2022-01-01\n"

func TestRunEPSS_TextAndJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Write([]byte(epssCSVOK))
	}))
	defer srv.Close()

	// 通过 --base-url flag 注入（runCLI 会先复位包级变量，再由 cobra 解析 flag 设回）。
	// text 路径
	out, err := runCLI(t, "epss", "--base-url", srv.URL, "CVE-2021-44228")
	if err != nil {
		t.Fatalf("epss text: %v", err)
	}
	if !strings.Contains(out, "0.8750") {
		t.Errorf("epss text missing score, got: %s", out)
	}

	// json 路径
	out, err = runCLIJSON(t, "epss", "--base-url", srv.URL, "CVE-2021-44228")
	if err != nil {
		t.Fatalf("epss json: %v", err)
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Errorf("epss json missing cve, got: %s", out)
	}
}

func TestRunEPSS_QueryError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	_, err := runCLI(t, "epss", "--base-url", srv.URL, "CVE-2021-44228")
	if err == nil {
		t.Fatal("expected error for EPSS 500")
	}
}

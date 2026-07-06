package cpeskills

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 本文件补充最后几个可达分支：index Lookup 全量返回分支（criteria 全空）、
// osv QueryBatch 的 Unmarshal error、doRequest 的 4xx 非 429 返回。

// ---- index.go: Lookup 末尾全量返回分支（criteria 非 nil 但 vendor/product/part 全空）----

func TestCPEIndex_Lookup_AllFieldsEmpty(t *testing.T) {
	cpes := []*CPE{
		{Part: *PartApplication, Vendor: "apache", ProductName: "log4j"},
		{Part: *PartApplication, Vendor: "microsoft", ProductName: "office"},
	}
	idx := NewCPEIndex(cpes)
	// criteria 非 nil，但 Vendor/ProductName/Part.ShortName 全空 → 末尾全量返回
	r := idx.Lookup(&CPE{})
	if len(r) != 2 {
		t.Errorf("expected all 2 CPEs for empty criteria, got %d", len(r))
	}
}

// ---- osv.go: QueryBatch Unmarshal error（bad JSON 响应）----

func TestOSVClient_QueryBatch_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()
	c := &OSVClient{
		BaseURL:            srv.URL,
		HTTPClient:         srv.Client(),
		RetryCount:         0,
		RetryDelay:         0,
		minRequestInterval: 0,
	}
	purl := NewPURL("npm", "", "left-pad", "1.0")
	_, err := c.QueryBatch([]*PackageURL{purl})
	if err == nil {
		t.Error("expected QueryBatch error for bad JSON")
	}
}

// ---- osv.go: doRequest 4xx 非 429 返回（已部分测，确保 337 行覆盖）----

func TestOSVClient_DoRequest_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
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
		t.Error("expected error for 404")
	}
}

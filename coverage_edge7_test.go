package cpeskills

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 本文件补充剩余 <90% 函数的未覆盖分支：osv query error 路径、kev/epss
// 网络失败分支、purl 编码错误与 qualifier 排序、index 多分支、vendor
// 规范化双下划线折叠、export batch SARIF、sbom timestamp/空 BomRef、
// remediation IsUrgent/breaking-change、batch 数据源查询等。

// ---- osv.go: Query/GetVulnerability/QueryByEcosystem/QueryByCommit 的 doRequest 失败与 bad-JSON 分支 ----

func TestOSVClient_Query_DoRequestFail(t *testing.T) {
	c := &OSVClient{
		BaseURL:            "http://127.0.0.1:1", // 不可达端口
		HTTPClient:         &http.Client{Timeout: 100 * time.Millisecond},
		RetryCount:         0,
		RetryDelay:         0,
		minRequestInterval: 0,
	}
	purl := NewPURL("npm", "", "left-pad", "1.0")
	if _, err := c.Query(purl); err == nil {
		t.Error("expected Query error for unreachable host")
	}
	if _, err := c.QueryByEcosystem("npm", "left-pad", "1.0"); err == nil {
		t.Error("expected QueryByEcosystem error for unreachable host")
	}
	if _, err := c.QueryByCommit("abc123"); err == nil {
		t.Error("expected QueryByCommit error for unreachable host")
	}
	if _, err := c.GetVulnerability("GHSA-xxx"); err == nil {
		t.Error("expected GetVulnerability error for unreachable host")
	}
}

func TestOSVClient_Query_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
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
	if _, err := c.Query(purl); err == nil {
		t.Error("expected Query error for bad JSON")
	}
	if _, err := c.QueryByEcosystem("npm", "left-pad", "1.0"); err == nil {
		t.Error("expected QueryByEcosystem error for bad JSON")
	}
	if _, err := c.QueryByCommit("abc123"); err == nil {
		t.Error("expected QueryByCommit error for bad JSON")
	}
}

func TestOSVClient_GetVulnerability_BadJSON(t *testing.T) {
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
	if _, err := c.GetVulnerability("GHSA-xxx"); err == nil {
		t.Error("expected GetVulnerability error for bad JSON")
	}
}

// ---- purl.go: ParsePURL 编码错误分支 ----

func TestParsePURL_EncodingErrors(t *testing.T) {
	cases := []string{
		"pkg:npm/%zz",          // 非法 name 编码
		"pkg:npm/@sc%2ope/foo", // 非法 namespace 编码
		"pkg:type%zz/foo",      // 非法 type 编码
	}
	for _, p := range cases {
		if _, err := ParsePURL(p); err == nil {
			t.Errorf("expected encoding error for %q", p)
		}
	}
}

// ---- purl.go: Copy nil receiver + sortedQualifierKeys 多 key 排序 ----

func TestPackageURL_Copy_NilReceiver(t *testing.T) {
	var p *PackageURL
	if cp := p.Copy(); cp != nil {
		t.Errorf("expected nil copy for nil receiver, got %+v", cp)
	}
}

func TestSortedQualifierKeys_InsertionSortSwap(t *testing.T) {
	// 多个 key 触发插入排序的交换分支
	m := map[string]string{
		"zebra":  "1",
		"apple":  "2",
		"mango":  "3",
		"banana": "4",
	}
	keys := sortedQualifierKeys(m)
	want := []string{"apple", "banana", "mango", "zebra"}
	if len(keys) != len(want) {
		t.Fatalf("expected %d keys, got %d", len(want), len(keys))
	}
	for i, k := range keys {
		if k != want[i] {
			t.Errorf("keys[%d]=%q, want %q", i, k, want[i])
		}
	}
}

func TestParsePURLQualifiers_Errors(t *testing.T) {
	// 非法 value 编码
	if _, err := parsePURLQualifiers("key=val%2"); err == nil {
		t.Error("expected error for invalid qualifier value encoding")
	}
}

// ---- index.go: Lookup 的 byProduct/byPart 命中与未命中、IndexPURL nil 分支 ----

func TestCPEIndex_Lookup_ProductNotFound(t *testing.T) {
	cpes := []*CPE{{Part: *PartApplication, Vendor: "apache", ProductName: "log4j"}}
	idx := NewCPEIndex(cpes)
	// 存在 vendor 但 product 不匹配 → byProduct 路径未命中（vendor != ""）
	if r := idx.Lookup(&CPE{Vendor: "apache", ProductName: "nonexistent"}); len(r) != 0 {
		t.Errorf("expected 0 for non-matching product, got %d", len(r))
	}
	// 仅 product（无 vendor），product 不存在 → byProduct ok=false → return nil
	if r := idx.Lookup(&CPE{ProductName: "nonexistent"}); r != nil {
		t.Errorf("expected nil for absent product, got %v", r)
	}
	// part 存在
	if r := idx.Lookup(&CPE{Part: *PartApplication}); len(r) != 1 {
		t.Errorf("expected 1 for part lookup, got %d", len(r))
	}
	// part 不存在（用 OS part，索引中只有 application）
	if r := idx.Lookup(&CPE{Part: *PartOperationSystem}); r != nil {
		t.Errorf("expected nil for absent part, got %v", r)
	}
}

func TestCPEIndex_IndexPURL_NilArgs(t *testing.T) {
	idx := NewCPEIndex(nil)
	cpe := &CPE{Part: *PartApplication, Vendor: "apache", ProductName: "log4j"}
	idx.IndexPURL(nil, cpe) // nil purl → no-op
	idx.IndexPURL(NewPURL("npm", "", "x", "1"), nil) // nil cpe → no-op
	if len(idx.byPURL) != 0 {
		t.Errorf("expected empty byPURL after nil args, got %d", len(idx.byPURL))
	}
}

// ---- vendor_normalization.go: canonicalForm/normalizeKey 双下划线折叠 ----

func TestCanonicalForm_DoubleUnderscoreCollapse(t *testing.T) {
	// canonicalForm 只替换空格和 '-'（不替换 '.'），并折叠双下划线
	cases := map[string]string{
		"Apache__Software": "apache_software",
		"foo---bar":        "foo_bar",
		"  __leading__  ":  "leading",
		"a____b":           "a_b",
	}
	for in, want := range cases {
		if got := canonicalForm(in); got != want {
			t.Errorf("canonicalForm(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestNormalizeKey_DoubleUnderscoreCollapse(t *testing.T) {
	// normalizeKey 替换空格/连字符/点为下划线，再折叠双下划线
	if got := normalizeKey("foo---bar  baz..qux"); got != "foo_bar_baz_qux" {
		t.Errorf("normalizeKey multi-sep: got %q", got)
	}
	if got := normalizeKey("a_____b"); got != "a_b" {
		t.Errorf("normalizeKey collapse: got %q", got)
	}
}

// ---- remediation.go: IsUrgent KEV 触发 + isBreakingChange 空段 ----

func TestRemediationAdvice_IsUrgent_KEVTriggers(t *testing.T) {
	r := &RemediationAdvice{Priority: 0}
	findings := []*VulnerabilityFinding{{KEVListed: true}}
	if !r.IsUrgent(findings) {
		t.Error("expected urgent when KEVListed and Priority==0")
	}
}

func TestIsBreakingChange_EmptySegments(t *testing.T) {
	// splitVersionPrefix("") 返回 [""]（长度 1），故 "" vs "1" 视为 breaking（首段不同）
	if !isBreakingChange("", "1.0") {
		t.Error("expected breaking change for empty current vs 1.0")
	}
	if !isBreakingChange("1.0", "") {
		t.Error("expected breaking change for 1.0 vs empty new")
	}
	// 同首段 → 非破坏性
	if isBreakingChange("1.2.3", "1.5.0") {
		t.Error("expected non-breaking for same major")
	}
}

// ---- export.go: ExportVulnerabilityReportBatch SARIF 分支 ----

func TestExportVulnerabilityReportBatch_SARIF(t *testing.T) {
	comp := NewSBOMComponent("pkg1", "1.0")
	report := NewVulnerabilityReport(comp)
	report.AddFinding(&VulnerabilityFinding{
		CVE: &CVEReference{CVEID: "CVE-2021-44228", Severity: "Critical", CVSSScore: 9.8},
	})
	data, err := ExportVulnerabilityReportBatch([]*VulnerabilityReport{report}, ExportFormatSARIF)
	if err != nil {
		t.Fatalf("batch SARIF export: %v", err)
	}
	if !json.Valid(data) {
		t.Error("batch SARIF export should produce valid JSON")
	}
}

// ---- sbom.go: AddHash/SetProperty nil init 分支（直接构造零值组件）----

func TestSBOMComponent_AddHash_SetProperty_NilInit(t *testing.T) {
	// 直接构造零值 SBOMComponent（Hashes/Properties 为 nil），触发 nil init
	c := &SBOMComponent{Name: "foo"}
	c.AddHash("sha256", "abc")
	if c.Hashes["sha256"] != "abc" {
		t.Errorf("AddHash nil init failed: %v", c.Hashes)
	}
	c.SetProperty("key", "val")
	if c.Properties["key"] != "val" {
		t.Errorf("SetProperty nil init failed: %v", c.Properties)
	}
}

func TestSBOM_EnrichWithVulnerabilities_NilProperties(t *testing.T) {
	// EnrichWithVulnerabilities 写 CVE 到 Properties，组件 Properties 为 nil → 触发 init
	comp := &SBOMComponent{Name: "log4j", Version: "2.14"} // Properties nil
	cpe := &CPE{Part: *PartApplication, Vendor: "apache", ProductName: "log4j", Version: "2.14"}
	cpe.Cpe23 = "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"
	comp.CPE = cpe
	sbom := &SBOM{Components: []*SBOMComponent{comp}}

	nvd := &NVDCPEData{
		CPEMatchData: &CPEMatchData{
			CPEToCVEs: map[string][]string{
				"cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*": {"CVE-2021-44228"},
			},
		},
	}
	if err := sbom.EnrichWithVulnerabilities(nvd); err != nil {
		t.Fatalf("EnrichWithVulnerabilities: %v", err)
	}
	if comp.Properties == nil || !strings.Contains(comp.Properties["cpe:cves"], "CVE-2021-44228") {
		t.Errorf("expected cpe:cves property set, got %v", comp.Properties)
	}

	// nil nvd → error
	if err := sbom.EnrichWithVulnerabilities(nil); err == nil {
		t.Error("expected error for nil nvd")
	}
}

// ---- sbom_spdx.go: BomRef 空时自动生成 + parseSPDXTimestamp 空 + relationship 元素缺失 ----

func TestParseSPDXJSON_EmptyBomRefAutoGenerated(t *testing.T) {
	// package 无 SPDXID → convertSPDXPackageToComponent 返回空 BomRef → 自动生成 pkg-N
	doc := map[string]any{
		"spdxVersion": "SPDX-2.3",
		"name":        "test",
		"packages": []map[string]any{
			{"name": "pkg-a", "versionInfo": "1.0"}, // 无 SPDXID
		},
	}
	data, _ := json.Marshal(doc)
	sbom, err := ParseSPDXJSON(data)
	if err != nil {
		t.Fatalf("ParseSPDXJSON: %v", err)
	}
	if len(sbom.Components) != 1 || sbom.Components[0].BomRef == "" {
		t.Errorf("expected auto-generated BomRef, got %+v", sbom.Components)
	}
}

func TestParseSPDXJSON_SPDXElementMissing(t *testing.T) {
	// DEPENDS_ON 的 spdxElementId 不在 idToRef → 跳过（与 related 缺失不同的分支）
	doc := map[string]any{
		"spdxVersion": "SPDX-2.3",
		"packages": []map[string]any{
			{"SPDXID": "SPDXRef-pkg-a", "name": "pkg-a"},
		},
		"relationships": []map[string]any{
			{"spdxElementId": "SPDXRef-missing", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-pkg-a"},
		},
	}
	data, _ := json.Marshal(doc)
	sbom, err := ParseSPDXJSON(data)
	if err != nil {
		t.Fatalf("ParseSPDXJSON: %v", err)
	}
	if len(sbom.Dependencies) != 0 {
		t.Errorf("expected 0 deps (element missing), got %d", len(sbom.Dependencies))
	}
}

func TestParseSPDXTimestamp_EmptyAndInvalid(t *testing.T) {
	if !parseSPDXTimestamp("").IsZero() {
		t.Error("expected zero for empty timestamp")
	}
	if !parseSPDXTimestamp("not-a-date").IsZero() {
		t.Error("expected zero for invalid timestamp")
	}
	// 合法时间戳应解析成功
	if parseSPDXTimestamp("2024-01-15T00:00:00Z").IsZero() {
		t.Error("expected parsed time for valid timestamp")
	}
}

func TestParseCycloneDXTimestamp_EmptyAndInvalid(t *testing.T) {
	if !parseCycloneDXTimestamp("").IsZero() {
		t.Error("expected zero for empty timestamp")
	}
	if !parseCycloneDXTimestamp("garbage").IsZero() {
		t.Error("expected zero for invalid timestamp")
	}
	if parseCycloneDXTimestamp("2024-06-01T12:30:00Z").IsZero() {
		t.Error("expected parsed time for valid timestamp")
	}
}

func TestConvertComponentToSPDXPackage_EmptyBomRef(t *testing.T) {
	// BomRef 空 → 用 SPDXRef-<name>
	comp := &SBOMComponent{Name: "mypkg", Version: "1.0"}
	pkg := convertComponentToSPDXPackage(comp)
	if pkg.SPDXID != "SPDXRef-mypkg" {
		t.Errorf("expected SPDXRef-mypkg, got %q", pkg.SPDXID)
	}
}

// ---- sbom_enhanced.go: DiffSBOMs downgrade 分支 ----

func TestDiffSBOMs_Downgrade(t *testing.T) {
	// 手动设相同 BomRef，使 componentKey 一致；version 不同 → Changed 分支
	old := NewSBOM(SBOMFormatCycloneDX, "o")
	oldC := NewSBOMComponent("pkg", "2.0")
	oldC.BomRef = "ref-pkg"
	old.AddComponent(oldC) // AddComponent 不会覆盖已设的 BomRef
	newS := NewSBOM(SBOMFormatCycloneDX, "n")
	newC := NewSBOMComponent("pkg", "1.0") // 版本更低 → downgrade
	newC.BomRef = "ref-pkg"
	newS.AddComponent(newC)
	diff := DiffSBOMs(old, newS)
	if len(diff.Changed) != 1 {
		t.Fatalf("expected 1 changed, got %d (added=%d)", len(diff.Changed), len(diff.Added))
	}
	if diff.Changed[0].ChangeType != "downgrade" {
		t.Errorf("expected downgrade, got %q", diff.Changed[0].ChangeType)
	}
}

// ---- kev.go: 网络失败触发 IsListed/GetDueDate/IsRansomware/GetRequiredAction/Count/GetAll/FilterBy 的 error 分支 ----

func kevFailServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
}

func TestKEVClient_ErrorPaths(t *testing.T) {
	srv := kevFailServer(t)
	defer srv.Close()
	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0

	// loadAll 失败 → 各方法返回 error
	if _, err := c.IsListed("CVE-2021-44228"); err == nil {
		t.Error("expected IsListed error on loadAll failure")
	}
	if _, err := c.GetDueDate("CVE-2021-44228"); err == nil {
		t.Error("expected GetDueDate error on loadAll failure")
	}
	if _, err := c.IsRansomwareRelated("CVE-2021-44228"); err == nil {
		t.Error("expected IsRansomwareRelated error on loadAll failure")
	}
	if _, err := c.GetRequiredAction("CVE-2021-44228"); err == nil {
		t.Error("expected GetRequiredAction error on loadAll failure")
	}
	if _, err := c.Count(); err == nil {
		t.Error("expected Count error on loadAll failure")
	}
	if _, err := c.GetAll(); err == nil {
		t.Error("expected GetAll error on loadAll failure")
	}
	if _, err := c.FilterByVendor("apache"); err == nil {
		t.Error("expected FilterByVendor error on loadAll failure")
	}
	if _, err := c.FilterByProduct("log4j"); err == nil {
		t.Error("expected FilterByProduct error on loadAll failure")
	}
}

func TestKEVClient_EnrichVulnerabilityFinding_LoadAllFail(t *testing.T) {
	srv := kevFailServer(t)
	defer srv.Close()
	c := NewKEVClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0

	f := &VulnerabilityFinding{CVE: &CVEReference{CVEID: "CVE-2021-44228"}}
	if err := c.EnrichVulnerabilityFinding(f); err == nil {
		t.Error("expected EnrichVulnerabilityFinding error on loadAll failure")
	}
	if err := c.EnrichVulnerabilityFindings([]*VulnerabilityFinding{f}); err == nil {
		t.Error("expected EnrichVulnerabilityFindings error on loadAll failure")
	}
}

// ---- epss.go: GetScore 失败 → Enrich 返回 error；fetchScores non-200 ----

func TestEPSSClient_EnrichVulnerabilityFinding_GetScoreFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := NewEPSSClientWithOptions(srv.URL, 5*time.Second)
	c.minRequestInterval = 0

	f := &VulnerabilityFinding{CVE: &CVEReference{CVEID: "CVE-2021-44228"}}
	if err := c.EnrichVulnerabilityFinding(f); err == nil {
		t.Error("expected EnrichVulnerabilityFinding error on GetScore failure")
	}
	if err := c.EnrichVulnerabilityFindings([]*VulnerabilityFinding{f}); err == nil {
		t.Error("expected EnrichVulnerabilityFindings error on GetScores failure")
	}
}

func TestEPSSClient_fetchScores_BadURL(t *testing.T) {
	c := NewEPSSClient()
	c.BaseURL = "http://127.0.0.1:1" // 不可达
	c.HTTPClient = &http.Client{Timeout: 100 * time.Millisecond}
	c.minRequestInterval = 0
	if _, err := c.fetchScores([]string{"CVE-2021-44228"}); err == nil {
		t.Error("expected fetchScores error for unreachable host")
	}
}

func TestEPSSScoreToRiskFactor_HighClamped(t *testing.T) {
	// epssScore=1.0 → scaled=1000 → factor=10（边界，不超 10）
	r := EPSSScoreToRiskFactor(1.0)
	if r > 10.0 {
		t.Errorf("expected factor <= 10, got %f", r)
	}
	// 大于 1 的非法值也应被 clamp 到 10
	r2 := EPSSScoreToRiskFactor(5.0)
	if r2 > 10.0 {
		t.Errorf("expected factor clamped to 10, got %f", r2)
	}
}

// ---- batch.go: scanComponent 通过 DataSources 查询；BatchMatchPURLs PURL→CPE 转换；BatchQueryCVEs ----

func TestBatchScanner_scanComponent_DataSourceQuery(t *testing.T) {
	// mock NVD server 返回一个 CVE 条目，让 SearchVulnerabilitiesByCPE 成功返回 findings
	nvdResp := map[string]any{
		"resultsPerPage": 1,
		"result": []map[string]any{
			{
				"cve": map[string]any{
					"id": "CVE-2021-44228",
					"description": map[string]any{
						"description_data": []map[string]any{{"value": "Log4j RCE"}},
					},
					"references": map[string]any{"reference_data": []map[string]any{}},
				},
				"impact": map[string]any{
					"baseMetricV3": map[string]any{
						"cvssV3": map[string]any{"baseScore": 10.0},
					},
				},
				"publishedDate":    "2021-12-10T00:00:00Z",
				"lastModifiedDate": "2021-12-13T00:00:00Z",
				"configurations":   map[string]any{"nodes": []map[string]any{}},
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

	bs := NewBatchScanner(NewCPEIndex(nil), 0)
	bs.DataSources = []*VulnDataSource{
		NewVulnDataSource(DataSourceNVD, "mock-nvd", "", srv.URL),
		nil, // nil 数据源应被跳过
	}
	findings := bs.scanComponent(comp)
	if len(findings) == 0 {
		t.Error("expected findings from data source query")
	}
}

func TestBatchMatchPURLs_PURLToCPEConversion(t *testing.T) {
	// PURL 不在 byPURL 索引 → 走 PURLToCPE 转换 + index.Lookup
	// maven/org.apache/log4j 经 inferVendorProductFromPURL 推断 vendor="org", product="log4j"
	purl := NewPURL("maven", "org.apache", "log4j", "2.14")
	cpe := &CPE{Part: *PartApplication, Vendor: "org", ProductName: "log4j", Version: "2.14"}
	cpes := []*CPE{cpe}

	m := BatchMatchPURLs([]*PackageURL{purl, nil}, cpes)
	if len(m) != 1 {
		t.Fatalf("expected 1 mapped PURL (nil skipped), got %d", len(m))
	}
}

func TestBatchQueryCVEs_MultiSourceSearch(t *testing.T) {
	// 无数据源 → multiSearch 各 CVE 返回空/err → continue，最终返回空 map
	m, err := BatchQueryCVEs([]string{"CVE-2021-44228"}, nil)
	if err != nil {
		t.Fatalf("BatchQueryCVEs: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("expected empty map for no data sources, got %d", len(m))
	}
}

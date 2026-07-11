package cpeskills

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OSVClient OSV API 客户端
type OSVClient struct {
	// BaseURL OSV API 基础 URL
	BaseURL string

	// HTTPClient HTTP 客户端
	HTTPClient *http.Client

	// RetryCount 请求失败重试次数
	RetryCount int

	// RetryDelay 重试间隔
	RetryDelay time.Duration

	// mu 保护并发请求的速率限制
	mu sync.Mutex

	// lastRequestTime 上次请求时间，用于速率限制
	lastRequestTime time.Time

	// minRequestInterval 最小请求间隔
	minRequestInterval time.Duration
}

// DefaultOSVBaseURL OSV API 默认基础 URL
const DefaultOSVBaseURL = "https://api.osv.dev/v1"

// NewOSVClient 创建 OSV API 客户端
func NewOSVClient() *OSVClient {
	return &OSVClient{
		BaseURL:            DefaultOSVBaseURL,
		HTTPClient:         &http.Client{Timeout: 30 * time.Second},
		RetryCount:         3,
		RetryDelay:         1 * time.Second,
		minRequestInterval: 100 * time.Millisecond,
	}
}

// NewOSVClientWithOptions 创建带自定义选项的 OSV API 客户端
func NewOSVClientWithOptions(baseURL string, timeout time.Duration, retryCount int) *OSVClient {
	if baseURL == "" {
		baseURL = DefaultOSVBaseURL
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if retryCount <= 0 {
		retryCount = 3
	}
	return &OSVClient{
		BaseURL:            baseURL,
		HTTPClient:         &http.Client{Timeout: timeout},
		RetryCount:         retryCount,
		RetryDelay:         1 * time.Second,
		minRequestInterval: 100 * time.Millisecond,
	}
}

// OSVQuery 表示 OSV 查询请求
type OSVQuery struct {
	// Package 包信息
	Package *OSVPackage `json:"package,omitempty"`

	// Version 要查询的版本
	Version string `json:"version,omitempty"`

	// Commit 要查询的提交哈希
	Commit string `json:"commit,omitempty"`
}

// OSVQueryBatch 表示 OSV 批量查询请求
type OSVQueryBatch struct {
	// Queries 查询列表
	Queries []*OSVQuery `json:"queries"`
}

// OSVQueryResult 表示 OSV 查询结果
type OSVQueryResult struct {
	// Vulns 发现的漏洞列表
	Vulns []*OSVEntry `json:"vulns,omitempty"`
}

// OSVBatchResult 表示 OSV 批量查询结果
type OSVBatchResult struct {
	// Results 每个查询的结果
	Results []*OSVQueryResult `json:"results"`
}

// QueryOSV 查询单个包的漏洞信息（便捷函数）
func QueryOSV(purl *PackageURL) ([]*OSVEntry, error) {
	client := NewOSVClient()
	return client.Query(purl)
}

// QueryOSVBatch 批量查询包的漏洞信息（便捷函数）
func QueryOSVBatch(purls []*PackageURL) (map[string][]*OSVEntry, error) {
	client := NewOSVClient()
	return client.QueryBatch(purls)
}

// Query 查询单个包的漏洞信息
//
// 向 OSV API 发送查询请求，获取指定包的所有已知漏洞。
// 支持通过 PURL 进行查询，自动映射生态系统和包名。
func (c *OSVClient) Query(purl *PackageURL) ([]*OSVEntry, error) {
	if purl == nil || !purl.IsValid() {
		return nil, fmt.Errorf("invalid PURL")
	}

	query := &OSVQuery{
		Package: &OSVPackage{
			Ecosystem: purl.Type,
			Name:      purl.FullName(),
			PURL:      purl.String(),
		},
		Version: purl.Version,
	}

	data, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV query: %w", err)
	}

	respBody, err := c.doRequest("POST", "/query", data)
	if err != nil {
		return nil, fmt.Errorf("OSV query failed: %w", err)
	}

	var result OSVQueryResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse OSV query response: %w", err)
	}

	return result.Vulns, nil
}

// QueryBatch 批量查询包的漏洞信息
//
// 一次请求查询最多 1000 个包的漏洞信息，大幅减少网络开销。
// 返回以 PURL 字符串为键、漏洞列表为值的映射。
func (c *OSVClient) QueryBatch(purls []*PackageURL) (map[string][]*OSVEntry, error) {
	result := make(map[string][]*OSVEntry)

	if len(purls) == 0 {
		return result, nil
	}

	// OSV API 限制每次最多 1000 个查询
	if len(purls) > 1000 {
		return nil, fmt.Errorf("batch query limit exceeded: max 1000 queries per request, got %d", len(purls))
	}

	queries := make([]*OSVQuery, 0, len(purls))
	purlIndex := make([]string, 0, len(purls)) // 保持顺序映射

	for _, purl := range purls {
		if purl == nil || !purl.IsValid() {
			continue
		}
		queries = append(queries, &OSVQuery{
			Package: &OSVPackage{
				Ecosystem: purl.Type,
				Name:      purl.FullName(),
				PURL:      purl.String(),
			},
			Version: purl.Version,
		})
		purlIndex = append(purlIndex, purl.String())
	}

	if len(queries) == 0 {
		return result, nil
	}

	batch := &OSVQueryBatch{Queries: queries}
	data, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV batch query: %w", err)
	}

	respBody, err := c.doRequest("POST", "/querybatch", data)
	if err != nil {
		return nil, fmt.Errorf("OSV batch query failed: %w", err)
	}

	var batchResult OSVBatchResult
	if err := json.Unmarshal(respBody, &batchResult); err != nil {
		return nil, fmt.Errorf("failed to parse OSV batch query response: %w", err)
	}

	// 将结果映射回 PURL
	for i, queryResult := range batchResult.Results {
		if i < len(purlIndex) && queryResult != nil {
			result[purlIndex[i]] = queryResult.Vulns
		}
	}

	return result, nil
}

// GetVulnerability 根据 OSV ID 获取漏洞详情
//
// 通过 OSV ID（如 "GHSA-xxxx-xxxx-xxxx"）获取完整的漏洞条目信息。
func (c *OSVClient) GetVulnerability(osvID string) (*OSVEntry, error) {
	if osvID == "" {
		return nil, fmt.Errorf("OSV ID cannot be empty")
	}

	respBody, err := c.doRequest("GET", "/vulns/"+osvID, nil)
	if err != nil {
		return nil, fmt.Errorf("OSV get vulnerability failed: %w", err)
	}

	return ParseOSVEntry(respBody)
}

// QueryByEcosystem 按生态系统和包名查询漏洞
//
// 不依赖 PURL，直接使用生态系统和包名进行查询。
func (c *OSVClient) QueryByEcosystem(ecosystem, name, version string) ([]*OSVEntry, error) {
	if ecosystem == "" || name == "" {
		return nil, fmt.Errorf("ecosystem and name cannot be empty")
	}

	query := &OSVQuery{
		Package: &OSVPackage{
			Ecosystem: ecosystem,
			Name:      name,
		},
		Version: version,
	}

	data, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV query: %w", err)
	}

	respBody, err := c.doRequest("POST", "/query", data)
	if err != nil {
		return nil, fmt.Errorf("OSV query failed: %w", err)
	}

	var result OSVQueryResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse OSV query response: %w", err)
	}

	return result.Vulns, nil
}

// QueryByCommit 按 Git 提交哈希查询漏洞
//
// 用于查找特定提交引入或修复的漏洞。
func (c *OSVClient) QueryByCommit(commitHash string) ([]*OSVEntry, error) {
	if commitHash == "" {
		return nil, fmt.Errorf("commit hash cannot be empty")
	}

	query := &OSVQuery{
		Commit: commitHash,
	}

	data, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV query: %w", err)
	}

	respBody, err := c.doRequest("POST", "/query", data)
	if err != nil {
		return nil, fmt.Errorf("OSV query by commit failed: %w", err)
	}

	var result OSVQueryResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse OSV query response: %w", err)
	}

	return result.Vulns, nil
}

// doRequest 执行 HTTP 请求，包含重试和速率限制
func (c *OSVClient) doRequest(method, path string, body []byte) ([]byte, error) {
	url := c.BaseURL + path

	var lastErr error
	for attempt := 0; attempt <= c.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(c.RetryDelay * time.Duration(attempt))
		}

		// 速率限制
		c.mu.Lock()
		elapsed := time.Since(c.lastRequestTime)
		if elapsed < c.minRequestInterval {
			time.Sleep(c.minRequestInterval - elapsed)
		}
		c.lastRequestTime = time.Now()
		c.mu.Unlock()

		var reqBody io.Reader
		if body != nil {
			reqBody = bytes.NewReader(body)
		}

		req, err := http.NewRequest(method, url, reqBody)
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %w", err)
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "cpe-skills/1.0")

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			lastErr = fmt.Errorf("failed to read response: %w", err)
			continue
		}

		// 检查 HTTP 状态码
		if resp.StatusCode == http.StatusOK {
			return respBody, nil
		}

		// 429 Too Many Requests — 等待后重试
		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("rate limited (429)")
			time.Sleep(c.RetryDelay * 2)
			continue
		}

		// 4xx 客户端错误（非 429）不重试
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
			return nil, fmt.Errorf("OSV API error (status %d): %s", resp.StatusCode, string(respBody))
		}

		// 5xx 服务端错误 — 重试
		lastErr = fmt.Errorf("OSV API server error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil, fmt.Errorf("OSV request failed after %d retries: %w", c.RetryCount+1, lastErr)
}

// ParseOSVEntry 解析 OSV JSON 数据为单个条目
func ParseOSVEntry(data []byte) (*OSVEntry, error) {
	var entry OSVEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("failed to parse OSV entry: %w", err)
	}
	return &entry, nil
}

// ParseOSVEntries 解析 OSV JSON 数组数据
func ParseOSVEntries(data []byte) ([]*OSVEntry, error) {
	var entries []*OSVEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse OSV entries: %w", err)
	}
	return entries, nil
}

// GetFixedVersion 从 OSV 条目中提取修复版本
//
// 遍历所有受影响的范围和事件，返回第一个找到的修复版本。
func (e *OSVEntry) GetFixedVersion() string {
	if e == nil {
		return ""
	}
	for _, affected := range e.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					return event.Fixed
				}
			}
		}
	}
	return ""
}

// GetIntroducedVersion 从 OSV 条目中提取引入漏洞的版本
func (e *OSVEntry) GetIntroducedVersion() string {
	if e == nil {
		return ""
	}
	for _, affected := range e.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Introduced != "" {
					return event.Introduced
				}
			}
		}
	}
	return ""
}

// GetAffectedVersions 从 OSV 条目中提取受影响的版本列表
func (e *OSVEntry) GetAffectedVersions() []string {
	if e == nil {
		return nil
	}
	versions := make([]string, 0)
	for _, affected := range e.Affected {
		versions = append(versions, affected.Versions...)
	}
	return versions
}

// GetAffectedPackages 从 OSV 条目中提取受影响的包信息
func (e *OSVEntry) GetAffectedPackages() []*OSVPackage {
	if e == nil {
		return nil
	}
	packages := make([]*OSVPackage, 0)
	for _, affected := range e.Affected {
		if affected.Package != nil {
			packages = append(packages, affected.Package)
		}
	}
	return packages
}

// HasCVE 检查 OSV 条目是否关联了 CVE
func (e *OSVEntry) HasCVE() bool {
	if e == nil {
		return false
	}
	for _, alias := range e.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return true
		}
	}
	return false
}

// GetCVEIDs 从 OSV 条目中提取 CVE ID
func (e *OSVEntry) GetCVEIDs() []string {
	if e == nil {
		return nil
	}
	cves := make([]string, 0)
	for _, alias := range e.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cves = append(cves, alias)
		}
	}
	return cves
}

// GetMaxCVSSScore 从 OSV 条目中获取最高 CVSS 评分
func (e *OSVEntry) GetMaxCVSSScore() float64 {
	if e == nil {
		return 0.0
	}
	maxScore := 0.0
	for _, s := range e.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V4" {
			var score float64
			if _, err := fmt.Sscanf(s.Score, "%f", &score); err == nil {
				if score > maxScore {
					maxScore = score
				}
			}
		}
	}
	return maxScore
}

// GetSeverityLevel 获取 OSV 条目的严重级别字符串
func (e *OSVEntry) GetSeverityLevel() string {
	score := e.GetMaxCVSSScore()
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score > 0:
		return "Low"
	default:
		return "Unknown"
	}
}

// GetReferenceURLs 获取 OSV 条目的参考链接 URL 列表
func (e *OSVEntry) GetReferenceURLs() []string {
	if e == nil {
		return nil
	}
	urls := make([]string, 0, len(e.References))
	for _, ref := range e.References {
		if ref.URL != "" {
			urls = append(urls, ref.URL)
		}
	}
	return urls
}

// IsWithdrawn 检查 OSV 条目是否已被撤回
func (e *OSVEntry) IsWithdrawn() bool {
	if e == nil {
		return false
	}
	if e.DatabaseSpecific != nil {
		if withdrawn, ok := e.DatabaseSpecific["withdrawn"]; ok {
			if w, ok := withdrawn.(bool); ok {
				return w
			}
		}
	}
	return false
}

// ToVulnerabilityFinding 将 OSV 条目转换为 VulnerabilityFinding
func (e *OSVEntry) ToVulnerabilityFinding() *VulnerabilityFinding {
	if e == nil {
		return nil
	}

	finding := &VulnerabilityFinding{
		OSV:           e,
		FixedVersion:  e.GetFixedVersion(),
		FixAvailable:  e.GetFixedVersion() != "",
		Reachability:  "unknown",
		PublishedAt:   e.Published,
		Source:        "OSV",
	}

	// 设置 CVSS 评分
	cvssScore := e.GetMaxCVSSScore()
	if cvssScore > 0 {
		finding.CVE = &CVEReference{
			CVSSScore: cvssScore,
			Severity:  e.GetSeverityLevel(),
		}
	}

	return finding
}

// BatchQueryOSVWithClient 使用指定客户端批量查询，支持自动分批
//
// 当 PURL 数量超过 1000 时自动分批查询，合并结果后返回。
func BatchQueryOSVWithClient(client *OSVClient, purls []*PackageURL) (map[string][]*OSVEntry, error) {
	if client == nil {
		client = NewOSVClient()
	}

	result := make(map[string][]*OSVEntry)

	// 分批处理，每批最多 1000 个
	batchSize := 1000
	for i := 0; i < len(purls); i += batchSize {
		end := i + batchSize
		if end > len(purls) {
			end = len(purls)
		}

		batch, err := client.QueryBatch(purls[i:end])
		if err != nil {
			return result, fmt.Errorf("batch query failed at offset %d: %w", i, err)
		}

		for k, v := range batch {
			result[k] = v
		}
	}

	return result, nil
}

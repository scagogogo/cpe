package cpeskills

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EPSSClient EPSS (Exploit Prediction Scoring System) API 客户端
//
// EPSS 由 FIRST.org 维护，提供漏洞在未来 30 天内被利用的概率预测。
// 评分范围 0.0-1.0，数值越高表示被利用的可能性越大。
// 数据每日更新，API 地址: https://api.first.org/data/v1/epss
type EPSSClient struct {
	// BaseURL EPSS API 基础 URL
	BaseURL string

	// HTTPClient HTTP 客户端
	HTTPClient *http.Client

	// Cache 内存缓存，避免重复请求
	cache map[string]*EPSSEntry

	// cacheExpiry 缓存过期时间
	cacheExpiry time.Time

	// mu 保护缓存和速率限制
	mu sync.RWMutex

	// lastRequestTime 上次请求时间
	lastRequestTime time.Time

	// minRequestInterval 最小请求间隔
	minRequestInterval time.Duration
}

// EPSSEntry 表示一个 EPSS 评分条目
type EPSSEntry struct {
	// CVEID CVE 标识符
	CVEID string `json:"cve"`

	// EPSSScore EPSS 评分 (0.0-1.0)，表示未来 30 天内被利用的概率
	EPSSScore float64 `json:"epss"`

	// Percentile EPSS 百分位 (0.0-1.0)，表示该评分在所有 CVE 中的相对位置
	Percentile float64 `json:"percentile"`

	// Date 评分日期
	Date string `json:"date"`
}

// EPSSResponse EPSS API 响应结构
type EPSSResponse struct {
	// Status 响应状态
	Status string `json:"status"`

	// StatusCode HTTP 状态码
	StatusCode int `json:"status-code"`

	// Version API 版本
	Version string `json:"version"`

	// Access 访问权限
	Access string `json:"access"`

	// Total 总条目数
	Total int `json:"total"`

	// Offset 偏移量
	Offset int `json:"offset"`

	// Limit 限制数
	Limit int `json:"limit"`

	// Data EPSS 数据条目
	Data []struct {
		// CVE CVE ID
		CVE string `json:"cve"`

		// EPSS EPSS 评分
		EPSS string `json:"epss"`

		// Percentile 百分位
		Percentile string `json:"percentile"`

		// Date 日期
		Date string `json:"date"`
	} `json:"data"`
}

// DefaultEPSSBaseURL EPSS API 默认基础 URL
const DefaultEPSSBaseURL = "https://api.first.org/data/v1/epss"

// NewEPSSClient 创建 EPSS API 客户端
func NewEPSSClient() *EPSSClient {
	return &EPSSClient{
		BaseURL:            DefaultEPSSBaseURL,
		HTTPClient:         &http.Client{Timeout: 60 * time.Second},
		cache:              make(map[string]*EPSSEntry),
		minRequestInterval: 500 * time.Millisecond,
	}
}

// NewEPSSClientWithOptions 创建带自定义选项的 EPSS API 客户端
func NewEPSSClientWithOptions(baseURL string, timeout time.Duration) *EPSSClient {
	if baseURL == "" {
		baseURL = DefaultEPSSBaseURL
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &EPSSClient{
		BaseURL:            baseURL,
		HTTPClient:         &http.Client{Timeout: timeout},
		cache:              make(map[string]*EPSSEntry),
		minRequestInterval: 500 * time.Millisecond,
	}
}

// GetScore 获取单个 CVE 的 EPSS 评分
//
// 优先从缓存读取，缓存未命中时发起 API 请求。
func (c *EPSSClient) GetScore(cveID string) (*EPSSEntry, error) {
	if cveID == "" {
		return nil, fmt.Errorf("CVE ID cannot be empty")
	}

	// 标准化 CVE ID
	cveID = normalizeCVEID(cveID)

	// 检查缓存
	c.mu.RLock()
	if entry, ok := c.cache[cveID]; ok {
		c.mu.RUnlock()
		return entry, nil
	}
	c.mu.RUnlock()

	// 从 API 获取
	entry, err := c.fetchScore(cveID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	c.mu.Lock()
	c.cache[cveID] = entry
	c.mu.Unlock()

	return entry, nil
}

// GetScores 批量获取多个 CVE 的 EPSS 评分
//
// 使用 EPSS API 的批量查询能力，一次请求获取多个 CVE 的评分。
// 当 cveIDs 数量较少时（≤100），使用单次请求；超过则分批。
func (c *EPSSClient) GetScores(cveIDs []string) (map[string]*EPSSEntry, error) {
	if len(cveIDs) == 0 {
		return make(map[string]*EPSSEntry), nil
	}

	result := make(map[string]*EPSSEntry, len(cveIDs))

	// 标准化所有 CVE ID
	normalized := make([]string, len(cveIDs))
	for i, id := range cveIDs {
		normalized[i] = normalizeCVEID(id)
	}

	// 先检查缓存
	var uncached []string
	c.mu.RLock()
	for _, id := range normalized {
		if entry, ok := c.cache[id]; ok {
			result[id] = entry
		} else {
			uncached = append(uncached, id)
		}
	}
	c.mu.RUnlock()

	if len(uncached) == 0 {
		return result, nil
	}

	// 分批获取未缓存的（EPSS API 限制每次最多 100 个）
	batchSize := 100
	for i := 0; i < len(uncached); i += batchSize {
		end := i + batchSize
		if end > len(uncached) {
			end = len(uncached)
		}

		batch, err := c.fetchScores(uncached[i:end])
		if err != nil {
			return result, fmt.Errorf("EPSS batch fetch failed at offset %d: %w", i, err)
		}

		c.mu.Lock()
		for id, entry := range batch {
			c.cache[id] = entry
			result[id] = entry
		}
		c.mu.Unlock()
	}

	return result, nil
}

// EnrichVulnerabilityFinding 使用 EPSS 数据丰富漏洞发现
//
// 为 VulnerabilityFinding 填充 EPSSScore 字段。
func (c *EPSSClient) EnrichVulnerabilityFinding(finding *VulnerabilityFinding) error {
	if finding == nil || finding.CVE == nil || finding.CVE.CVEID == "" {
		return nil
	}

	entry, err := c.GetScore(finding.CVE.CVEID)
	if err != nil {
		return err
	}

	finding.EPSSScore = entry.EPSSScore
	return nil
}

// EnrichVulnerabilityFindings 批量使用 EPSS 数据丰富漏洞发现列表
func (c *EPSSClient) EnrichVulnerabilityFindings(findings []*VulnerabilityFinding) error {
	if len(findings) == 0 {
		return nil
	}

	// 收集所有 CVE ID
	cveIDs := make([]string, 0, len(findings))
	for _, f := range findings {
		if f != nil && f.CVE != nil && f.CVE.CVEID != "" {
			cveIDs = append(cveIDs, f.CVE.CVEID)
		}
	}

	if len(cveIDs) == 0 {
		return nil
	}

	// 批量获取评分
	scores, err := c.GetScores(cveIDs)
	if err != nil {
		return err
	}

	// 填充评分
	for _, f := range findings {
		if f != nil && f.CVE != nil {
			if entry, ok := scores[f.CVE.CVEID]; ok {
				f.EPSSScore = entry.EPSSScore
			}
		}
	}

	return nil
}

// IsHighRisk 判断 EPSS 评分是否为高风险（≥ 0.1，即 10% 概率）
func (e *EPSSEntry) IsHighRisk() bool {
	return e.EPSSScore >= 0.1
}

// IsCriticalRisk 判断 EPSS 评分是否为严重风险（≥ 0.5，即 50% 概率）
func (e *EPSSEntry) IsCriticalRisk() bool {
	return e.EPSSScore >= 0.5
}

// GetRiskLevel 获取 EPSS 风险级别
func (e *EPSSEntry) GetRiskLevel() string {
	switch {
	case e.EPSSScore >= 0.5:
		return "Critical"
	case e.EPSSScore >= 0.1:
		return "High"
	case e.EPSSScore >= 0.01:
		return "Medium"
	default:
		return "Low"
	}
}

// ClearCache 清除 EPSS 客户端缓存
func (c *EPSSClient) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*EPSSEntry)
	c.cacheExpiry = time.Time{}
}

// CacheSize 返回缓存条目数
func (c *EPSSClient) CacheSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// fetchScore 从 API 获取单个 CVE 的 EPSS 评分
func (c *EPSSClient) fetchScore(cveID string) (*EPSSEntry, error) {
	scores, err := c.fetchScores([]string{cveID})
	if err != nil {
		return nil, err
	}
	if entry, ok := scores[cveID]; ok {
		return entry, nil
	}
	return nil, fmt.Errorf("EPSS score not found for %s", cveID)
}

// fetchScores 从 API 批量获取 EPSS 评分
func (c *EPSSClient) fetchScores(cveIDs []string) (map[string]*EPSSEntry, error) {
	if len(cveIDs) == 0 {
		return make(map[string]*EPSSEntry), nil
	}

	// 速率限制
	c.mu.Lock()
	elapsed := time.Since(c.lastRequestTime)
	if elapsed < c.minRequestInterval {
		time.Sleep(c.minRequestInterval - elapsed)
	}
	c.lastRequestTime = time.Now()
	c.mu.Unlock()

	// 构建请求 URL
	url := fmt.Sprintf("%s?cve=%s", c.BaseURL, strings.Join(cveIDs, ","))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create EPSS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cpe-skills/1.0")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("EPSS request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("EPSS API error (status %d): %s", resp.StatusCode, string(body))
	}

	// EPSS API 返回 CSV 格式的数据
	return c.parseEPSSResponse(resp.Body)
}

// parseEPSSResponse 解析 EPSS API 的 CSV 响应
func (c *EPSSClient) parseEPSSResponse(reader io.Reader) (map[string]*EPSSEntry, error) {
	csvReader := csv.NewReader(reader)
	csvReader.TrimLeadingSpace = true

	result := make(map[string]*EPSSEntry)

	// 读取表头
	header, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read EPSS CSV header: %w", err)
	}

	// 找到各列索引
	cveIdx := -1
	epssIdx := -1
	percentileIdx := -1
	dateIdx := -1

	for i, col := range header {
		switch strings.TrimSpace(strings.ToLower(col)) {
		case "cve":
			cveIdx = i
		case "epss":
			epssIdx = i
		case "percentile":
			percentileIdx = i
		case "date":
			dateIdx = i
		}
	}

	if cveIdx == -1 || epssIdx == -1 {
		return nil, fmt.Errorf("EPSS CSV missing required columns (cve, epss)")
	}

	// 读取数据行
	for {
		row, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // 跳过解析错误行
		}

		if len(row) <= cveIdx || len(row) <= epssIdx {
			continue
		}

		cveID := normalizeCVEID(strings.TrimSpace(row[cveIdx]))
		epssStr := strings.TrimSpace(row[epssIdx])

		epssScore, err := strconv.ParseFloat(epssStr, 64)
		if err != nil {
			continue
		}

		entry := &EPSSEntry{
			CVEID:     cveID,
			EPSSScore: epssScore,
		}

		if percentileIdx >= 0 && percentileIdx < len(row) {
			if p, err := strconv.ParseFloat(strings.TrimSpace(row[percentileIdx]), 64); err == nil {
				entry.Percentile = p
			}
		}

		if dateIdx >= 0 && dateIdx < len(row) {
			entry.Date = strings.TrimSpace(row[dateIdx])
		}

		result[cveID] = entry
	}

	return result, nil
}

// normalizeCVEID 标准化 CVE ID 格式
func normalizeCVEID(cveID string) string {
	cveID = strings.TrimSpace(cveID)
	cveID = strings.ToUpper(cveID)
	if !strings.HasPrefix(cveID, "CVE-") {
		cveID = "CVE-" + cveID
	}
	return cveID
}

// EPSSScoreToRiskFactor 将 EPSS 评分转换为风险因子 (0-10)
func EPSSScoreToRiskFactor(epssScore float64) float64 {
	// 使用对数变换将 EPSS 评分映射到 0-10 的范围
	// EPSS 0.001 → ~1.0, EPSS 0.01 → ~3.3, EPSS 0.1 → ~6.7, EPSS 0.5 → ~9.0, EPSS 0.9 → ~10.0
	if epssScore <= 0 {
		return 0
	}
	// 映射: factor = 10 * (log10(epssScore * 1000) / log10(1000))
	// 这样 epss=0.001 → 0, epss=1.0 → 10
	scaled := epssScore * 1000
	if scaled < 1 {
		scaled = 1
	}
	factor := 10.0 * (log10Float(scaled) / 3.0)
	if factor > 10.0 {
		factor = 10.0
	}
	return factor
}

// log10Float 计算 log10，避免导入 math 包
func log10Float(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// 使用自然对数转换: log10(x) = ln(x) / ln(10)
	return lnFloat(x) / 2.302585092994046
}

// lnFloat 使用泰勒级数近似计算自然对数
func lnFloat(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// 将 x 归一化到 [0.5, 2] 范围
	exp := 0
	for x > 2 {
		x /= 2
		exp++
	}
	for x < 0.5 {
		x *= 2
		exp--
	}
	// 泰勒级数: ln(1+y) where y = x-1
	y := (x - 1) / (x + 1)
	y2 := y * y
	sum := y
	term := y
	for n := 1; n < 20; n++ {
		term *= y2
		sum += term / float64(2*n+1)
	}
	return 2*sum + float64(exp)*0.6931471805599453
}

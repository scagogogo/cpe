package cpeskills

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// KEVClient CISA KEV (Known Exploited Vulnerabilities) 目录客户端
//
// CISA KEV 目录记录了已被实际利用的漏洞，是漏洞优先级排序的关键数据源。
// 根据 BOD 22-01 指令，联邦机构必须在规定期限内修复 KEV 中的漏洞。
// 数据来源: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
type KEVClient struct {
	// BaseURL KEV API 基础 URL
	BaseURL string

	// HTTPClient HTTP 客户端
	HTTPClient *http.Client

	// cache 内存缓存
	cache map[string]*KEVEntry

	// allCache 全量数据缓存
	allCache []*KEVEntry

	// cacheExpiry 缓存过期时间
	cacheExpiry time.Time

	// mu 保护缓存
	mu sync.RWMutex

	// lastRequestTime 上次请求时间
	lastRequestTime time.Time

	// minRequestInterval 最小请求间隔
	minRequestInterval time.Duration
}

// KEVEntry 表示 CISA KEV 目录中的一个条目
type KEVEntry struct {
	// CVEID CVE 标识符
	CVEID string `json:"cveID"`

	// VendorProject 供应商/项目名称
	VendorProject string `json:"vendorProject"`

	// Product 产品名称
	Product string `json:"product"`

	// VulnerabilityName 漏洞名称
	VulnerabilityName string `json:"vulnerabilityName"`

	// DateAdded 添加到 KEV 目录的日期
	DateAdded string `json:"dateAdded"`

	// ShortDescription 简短描述
	ShortDescription string `json:"shortDescription"`

	// RequiredAction 要求的修复措施
	RequiredAction string `json:"requiredAction"`

	// DueDate 修复截止日期
	DueDate string `json:"dueDate"`

	// KnownRansomwareCampaignUse 是否被勒索软件活动利用
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`

	// Notes 备注
	Notes string `json:"notes"`

	// CWEs 关联的 CWE 列表
	CWEs []string `json:"cwes,omitempty"`
}

// KEVResponse CISA KEV API 响应结构
type KEVResponse struct {
	// Title 响应标题
	Title string `json:"title"`

	// CatalogVersion 目录版本
	CatalogVersion string `json:"catalogVersion"`

	// DateReleased 发布日期
	DateReleased string `json:"dateReleased"`

	// Count 条目数量
	Count int `json:"count"`

	// Vulnerabilities 漏洞列表
	Vulnerabilities []*KEVEntry `json:"vulnerabilities"`
}

// DefaultKEVBaseURL CISA KEV API 默认基础 URL
const DefaultKEVBaseURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// NewKEVClient 创建 KEV 目录客户端
func NewKEVClient() *KEVClient {
	return &KEVClient{
		BaseURL:            DefaultKEVBaseURL,
		HTTPClient:         &http.Client{Timeout: 30 * time.Second},
		cache:              make(map[string]*KEVEntry),
		minRequestInterval: 1 * time.Second,
	}
}

// NewKEVClientWithOptions 创建带自定义选项的 KEV 目录客户端
func NewKEVClientWithOptions(baseURL string, timeout time.Duration) *KEVClient {
	if baseURL == "" {
		baseURL = DefaultKEVBaseURL
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &KEVClient{
		BaseURL:            baseURL,
		HTTPClient:         &http.Client{Timeout: timeout},
		cache:              make(map[string]*KEVEntry),
		minRequestInterval: 1 * time.Second,
	}
}

// IsListed 检查 CVE 是否在 KEV 目录中
func (c *KEVClient) IsListed(cveID string) (bool, error) {
	entry, err := c.GetEntry(cveID)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

// GetEntry 获取 CVE 的 KEV 条目
//
// 优先从缓存读取，缓存未命中时从 API 获取全量数据。
func (c *KEVClient) GetEntry(cveID string) (*KEVEntry, error) {
	if cveID == "" {
		return nil, fmt.Errorf("CVE ID cannot be empty")
	}

	cveID = normalizeCVEID(cveID)

	// 检查缓存
	c.mu.RLock()
	if entry, ok := c.cache[cveID]; ok {
		c.mu.RUnlock()
		return entry, nil
	}
	c.mu.RUnlock()

	// 加载全量数据
	if err := c.loadAll(); err != nil {
		return nil, err
	}

	// 再次检查缓存
	c.mu.RLock()
	entry, ok := c.cache[cveID]
	c.mu.RUnlock()

	if ok {
		return entry, nil
	}

	return nil, nil // 不在 KEV 中，不返回错误
}

// GetEntries 批量获取多个 CVE 的 KEV 条目
func (c *KEVClient) GetEntries(cveIDs []string) (map[string]*KEVEntry, error) {
	if len(cveIDs) == 0 {
		return make(map[string]*KEVEntry), nil
	}

	result := make(map[string]*KEVEntry, len(cveIDs))

	// 标准化所有 CVE ID
	normalized := make([]string, len(cveIDs))
	for i, id := range cveIDs {
		normalized[i] = normalizeCVEID(id)
	}

	// 检查缓存
	var uncached bool
	c.mu.RLock()
	for _, id := range normalized {
		if entry, ok := c.cache[id]; ok {
			result[id] = entry
		} else {
			uncached = true
		}
	}
	c.mu.RUnlock()

	if !uncached {
		return result, nil
	}

	// 加载全量数据
	if err := c.loadAll(); err != nil {
		return result, err
	}

	// 从缓存中查找
	c.mu.RLock()
	for _, id := range normalized {
		if _, alreadyFound := result[id]; !alreadyFound {
			if entry, ok := c.cache[id]; ok {
				result[id] = entry
			}
		}
	}
	c.mu.RUnlock()

	return result, nil
}

// GetAll 获取 KEV 目录中的所有条目
func (c *KEVClient) GetAll() ([]*KEVEntry, error) {
	if err := c.loadAll(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*KEVEntry, len(c.allCache))
	copy(result, c.allCache)
	return result, nil
}

// EnrichVulnerabilityFinding 使用 KEV 数据丰富漏洞发现
func (c *KEVClient) EnrichVulnerabilityFinding(finding *VulnerabilityFinding) error {
	if finding == nil || finding.CVE == nil || finding.CVE.CVEID == "" {
		return nil
	}

	listed, err := c.IsListed(finding.CVE.CVEID)
	if err != nil {
		return err
	}

	finding.KEVListed = listed
	return nil
}

// EnrichVulnerabilityFindings 批量使用 KEV 数据丰富漏洞发现列表
func (c *KEVClient) EnrichVulnerabilityFindings(findings []*VulnerabilityFinding) error {
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

	// 批量获取条目
	entries, err := c.GetEntries(cveIDs)
	if err != nil {
		return err
	}

	// 填充 KEV 状态
	for _, f := range findings {
		if f != nil && f.CVE != nil {
			if _, ok := entries[f.CVE.CVEID]; ok {
				f.KEVListed = true
			}
		}
	}

	return nil
}

// GetDueDate 获取 CVE 的修复截止日期（如果在 KEV 中）
func (c *KEVClient) GetDueDate(cveID string) (string, error) {
	entry, err := c.GetEntry(cveID)
	if err != nil {
		return "", err
	}
	if entry == nil {
		return "", fmt.Errorf("CVE %s not found in KEV catalog", cveID)
	}
	return entry.DueDate, nil
}

// IsRansomwareRelated 检查 CVE 是否与勒索软件活动相关
func (c *KEVClient) IsRansomwareRelated(cveID string) (bool, error) {
	entry, err := c.GetEntry(cveID)
	if err != nil {
		return false, err
	}
	if entry == nil {
		return false, nil
	}
	return strings.EqualFold(entry.KnownRansomwareCampaignUse, "known"), nil
}

// GetRequiredAction 获取 CVE 要求的修复措施
func (c *KEVClient) GetRequiredAction(cveID string) (string, error) {
	entry, err := c.GetEntry(cveID)
	if err != nil {
		return "", err
	}
	if entry == nil {
		return "", fmt.Errorf("CVE %s not found in KEV catalog", cveID)
	}
	return entry.RequiredAction, nil
}

// Count 返回 KEV 目录中的漏洞总数
func (c *KEVClient) Count() (int, error) {
	if err := c.loadAll(); err != nil {
		return 0, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.allCache), nil
}

// FilterByVendor 按供应商过滤 KEV 条目
func (c *KEVClient) FilterByVendor(vendor string) ([]*KEVEntry, error) {
	all, err := c.GetAll()
	if err != nil {
		return nil, err
	}

	vendor = strings.ToLower(vendor)
	var result []*KEVEntry
	for _, entry := range all {
		if strings.Contains(strings.ToLower(entry.VendorProject), vendor) {
			result = append(result, entry)
		}
	}
	return result, nil
}

// FilterByProduct 按产品过滤 KEV 条目
func (c *KEVClient) FilterByProduct(product string) ([]*KEVEntry, error) {
	all, err := c.GetAll()
	if err != nil {
		return nil, err
	}

	product = strings.ToLower(product)
	var result []*KEVEntry
	for _, entry := range all {
		if strings.Contains(strings.ToLower(entry.Product), product) {
			result = append(result, entry)
		}
	}
	return result, nil
}

// ClearCache 清除 KEV 客户端缓存
func (c *KEVClient) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*KEVEntry)
	c.allCache = nil
	c.cacheExpiry = time.Time{}
}

// loadAll 从 API 加载全量 KEV 数据
func (c *KEVClient) loadAll() error {
	c.mu.RLock()
	if len(c.allCache) > 0 && time.Since(c.cacheExpiry) < 1*time.Hour {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// 双重检查
	if len(c.allCache) > 0 && time.Since(c.cacheExpiry) < 1*time.Hour {
		return nil
	}

	// 速率限制
	elapsed := time.Since(c.lastRequestTime)
	if elapsed < c.minRequestInterval {
		time.Sleep(c.minRequestInterval - elapsed)
	}
	c.lastRequestTime = time.Now()

	req, err := http.NewRequest("GET", c.BaseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create KEV request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cpe-skills/1.0")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("KEV request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("KEV API error (status %d): %s", resp.StatusCode, string(body))
	}

	var kevResp KEVResponse
	if err := json.NewDecoder(resp.Body).Decode(&kevResp); err != nil {
		return fmt.Errorf("failed to parse KEV response: %w", err)
	}

	// 重建缓存
	c.cache = make(map[string]*KEVEntry, len(kevResp.Vulnerabilities))
	c.allCache = make([]*KEVEntry, 0, len(kevResp.Vulnerabilities))

	for _, entry := range kevResp.Vulnerabilities {
		if entry == nil {
			continue
		}
		entry.CVEID = normalizeCVEID(entry.CVEID)
		c.cache[entry.CVEID] = entry
		c.allCache = append(c.allCache, entry)
	}

	c.cacheExpiry = time.Now()
	return nil
}

// KEVSeverityBoost 返回 KEV 收录带来的严重性提升因子
//
// KEV 收录的漏洞应被视为严重级别至少提升一级。
func KEVSeverityBoost(currentSeverity string) string {
	switch currentSeverity {
	case "Low":
		return "Medium"
	case "Medium":
		return "High"
	case "High":
		return "Critical"
	case "Critical":
		return "Critical"
	default:
		return "High"
	}
}

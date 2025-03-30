package cpe

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// DataSourceType 表示数据源类型
type DataSourceType string

const (
	// DataSourceNVD NVD数据源
	DataSourceNVD DataSourceType = "NVD"

	// DataSourceMITRE MITRE数据源
	DataSourceMITRE DataSourceType = "MITRE"

	// DataSourceGitHub GitHub安全公告
	DataSourceGitHub DataSourceType = "GitHub"

	// DataSourceRedHatCVE RedHat CVE数据库
	DataSourceRedHatCVE DataSourceType = "RedHat"

	// DataSourceOWASP OWASP数据源
	DataSourceOWASP DataSourceType = "OWASP"

	// DataSourceCustom 自定义数据源
	DataSourceCustom DataSourceType = "Custom"
)

// DataSource 表示一个漏洞数据源
type DataSource struct {
	// 数据源类型
	Type DataSourceType

	// 数据源名称
	Name string

	// 数据源描述
	Description string

	// 数据源URL
	URL string

	// 认证信息
	Authentication *DataSourceAuth

	// HTTP客户端
	Client *http.Client

	// 上次更新时间
	LastUpdated time.Time

	// 缓存设置
	CacheSettings *CacheSettings

	// 自定义选项
	Options map[string]interface{}
}

// DataSourceAuth 数据源认证信息
type DataSourceAuth struct {
	// API密钥
	APIKey string

	// 用户名
	Username string

	// 密码
	Password string

	// 认证令牌
	Token string

	// 自定义头信息
	Headers map[string]string
}

// CacheSettings 缓存设置
type CacheSettings struct {
	// 是否启用缓存
	Enabled bool

	// 缓存目录
	Directory string

	// 缓存过期时间(小时)
	ExpiryHours int

	// 缓存文件名模板
	FileNameTemplate string
}

// NewDataSource 创建新的数据源
func NewDataSource(sourceType DataSourceType, name, description, url string) *DataSource {
	return &DataSource{
		Type:        sourceType,
		Name:        name,
		Description: description,
		URL:         url,
		Client:      &http.Client{Timeout: 60 * time.Second},
		CacheSettings: &CacheSettings{
			Enabled:     true,
			Directory:   "./cache",
			ExpiryHours: 24,
		},
		Options: make(map[string]interface{}),
	}
}

// SetAuthentication 设置数据源认证信息
func (ds *DataSource) SetAuthentication(auth *DataSourceAuth) {
	ds.Authentication = auth
}

// SetCacheSettings 设置缓存设置
func (ds *DataSource) SetCacheSettings(cache *CacheSettings) {
	ds.CacheSettings = cache
}

// FetchData 从数据源获取数据
func (ds *DataSource) FetchData(endpoint string) ([]byte, error) {
	url := ds.URL
	if endpoint != "" {
		if !strings.HasSuffix(url, "/") && !strings.HasPrefix(endpoint, "/") {
			url += "/"
		}
		url += endpoint
	}

	// 创建请求
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	// 添加认证信息
	if ds.Authentication != nil {
		// API密钥认证
		if ds.Authentication.APIKey != "" {
			// 根据不同数据源类型处理API密钥
			switch ds.Type {
			case DataSourceNVD:
				req.Header.Add("apiKey", ds.Authentication.APIKey)
			case DataSourceGitHub:
				req.Header.Add("Authorization", "token "+ds.Authentication.APIKey)
			default:
				req.Header.Add("X-API-Key", ds.Authentication.APIKey)
			}
		}

		// 基本认证
		if ds.Authentication.Username != "" && ds.Authentication.Password != "" {
			req.SetBasicAuth(ds.Authentication.Username, ds.Authentication.Password)
		}

		// 令牌认证
		if ds.Authentication.Token != "" {
			req.Header.Add("Authorization", "Bearer "+ds.Authentication.Token)
		}

		// 自定义头信息
		for key, value := range ds.Authentication.Headers {
			req.Header.Add(key, value)
		}
	}

	// 设置通用头信息
	req.Header.Add("User-Agent", "CPE-Library/1.0")
	req.Header.Add("Accept", "application/json")

	// 发送请求
	resp, err := ds.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("请求返回非成功状态码: %d", resp.StatusCode)
	}

	// 读取响应内容
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	// 更新最后更新时间
	ds.LastUpdated = time.Now()

	return body, nil
}

// GetVulnerabilities 获取漏洞信息
func (ds *DataSource) GetVulnerabilities(params map[string]string) ([]*CVEReference, error) {
	// 构建查询参数
	endpoint := ""
	queryParams := []string{}

	for key, value := range params {
		queryParams = append(queryParams, fmt.Sprintf("%s=%s", key, value))
	}

	if len(queryParams) > 0 {
		endpoint = "?" + strings.Join(queryParams, "&")
	}

	// 根据数据源类型设置特定的端点
	switch ds.Type {
	case DataSourceNVD:
		endpoint = "vuln/search" + endpoint
	case DataSourceGitHub:
		endpoint = "advisories" + endpoint
	case DataSourceRedHatCVE:
		endpoint = "rest/cve" + endpoint
	default:
		// 使用默认端点或自定义端点
		if ep, ok := ds.Options["endpoint"].(string); ok && ep != "" {
			endpoint = ep + endpoint
		}
	}

	// 获取数据
	data, err := ds.FetchData(endpoint)
	if err != nil {
		return nil, err
	}

	// 解析为CVE引用对象
	var vulnerabilities []*CVEReference

	switch ds.Type {
	case DataSourceNVD:
		// 解析NVD格式
		vulnerabilities, err = ds.parseNVDVulnerabilities(data)
	case DataSourceGitHub:
		// 解析GitHub格式
		vulnerabilities, err = ds.parseGitHubVulnerabilities(data)
	case DataSourceRedHatCVE:
		// 解析RedHat格式
		vulnerabilities, err = ds.parseRedHatVulnerabilities(data)
	default:
		// 尝试通用解析
		err = json.Unmarshal(data, &vulnerabilities)
	}

	if err != nil {
		return nil, fmt.Errorf("解析漏洞数据失败: %w", err)
	}

	return vulnerabilities, nil
}

// GetVulnerabilityById 根据CVE ID获取漏洞信息
func (ds *DataSource) GetVulnerabilityById(cveID string) (*CVEReference, error) {
	// 标准化CVE ID
	cveID = standardizeCVEID(cveID)

	var endpoint string

	// 根据数据源类型构建请求
	switch ds.Type {
	case DataSourceNVD:
		endpoint = fmt.Sprintf("vuln/%s", cveID)
	case DataSourceRedHatCVE:
		endpoint = fmt.Sprintf("rest/cve/%s", cveID)
	default:
		// 使用查询参数
		endpoint = fmt.Sprintf("?cve=%s", cveID)

		// 使用自定义端点如果有提供
		if ep, ok := ds.Options["endpoint"].(string); ok && ep != "" {
			endpoint = ep + endpoint
		}
	}

	// 获取数据
	data, err := ds.FetchData(endpoint)
	if err != nil {
		return nil, err
	}

	// 解析CVE信息
	var cveRef *CVEReference

	switch ds.Type {
	case DataSourceNVD:
		// 解析NVD单个CVE格式
		cveRefs, err := ds.parseNVDVulnerabilities(data)
		if err != nil {
			return nil, err
		}
		if len(cveRefs) > 0 {
			cveRef = cveRefs[0]
		}
	case DataSourceRedHatCVE:
		// 解析RedHat单个CVE格式
		cveRefs, err := ds.parseRedHatVulnerabilities(data)
		if err != nil {
			return nil, err
		}
		if len(cveRefs) > 0 {
			cveRef = cveRefs[0]
		}
	default:
		// 尝试通用解析
		err = json.Unmarshal(data, &cveRef)
	}

	if err != nil {
		return nil, fmt.Errorf("解析CVE数据失败: %w", err)
	}

	if cveRef == nil {
		return nil, fmt.Errorf("未找到CVE: %s", cveID)
	}

	return cveRef, nil
}

// SearchVulnerabilitiesByCPE 根据CPE查找相关漏洞
func (ds *DataSource) SearchVulnerabilitiesByCPE(cpe *CPE) ([]*CVEReference, error) {
	params := map[string]string{
		"cpe": cpe.Cpe23,
	}

	return ds.GetVulnerabilities(params)
}

// 解析NVD格式的漏洞数据
func (ds *DataSource) parseNVDVulnerabilities(data []byte) ([]*CVEReference, error) {
	// NVD API响应结构
	type NVDVuln struct {
		CVE struct {
			ID          string `json:"id"`
			Description struct {
				DescriptionData []struct {
					Value string `json:"value"`
				} `json:"description_data"`
			} `json:"description"`
			References struct {
				ReferenceData []struct {
					URL string `json:"url"`
				} `json:"reference_data"`
			} `json:"references"`
		} `json:"cve"`
		Impact struct {
			BaseMetricV3 struct {
				CVSSV3 struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssV3"`
			} `json:"baseMetricV3"`
		} `json:"impact"`
		PublishedDate    string `json:"publishedDate"`
		LastModifiedDate string `json:"lastModifiedDate"`
		Configurations   struct {
			Nodes []struct {
				CPEMatch []struct {
					CPE23URI string `json:"cpe23Uri"`
				} `json:"cpe_match"`
			} `json:"nodes"`
		} `json:"configurations"`
	}

	type NVDResponse struct {
		ResultCount int       `json:"resultsPerPage"`
		Results     []NVDVuln `json:"result"`
	}

	var nvdResp NVDResponse
	err := json.Unmarshal(data, &nvdResp)
	if err != nil {
		// 尝试解析单个漏洞响应
		var singleVuln NVDVuln
		err = json.Unmarshal(data, &singleVuln)
		if err != nil {
			return nil, err
		}
		nvdResp.Results = []NVDVuln{singleVuln}
	}

	var cveRefs []*CVEReference

	for _, vuln := range nvdResp.Results {
		cveRef := &CVEReference{
			CVEID: vuln.CVE.ID,
		}

		// 提取描述
		if len(vuln.CVE.Description.DescriptionData) > 0 {
			cveRef.Description = vuln.CVE.Description.DescriptionData[0].Value
		}

		// 提取CVSS评分
		cveRef.CVSSScore = vuln.Impact.BaseMetricV3.CVSSV3.BaseScore

		// 提取日期
		if vuln.PublishedDate != "" {
			pubDate, err := time.Parse(time.RFC3339, vuln.PublishedDate)
			if err == nil {
				cveRef.PublishedDate = pubDate
			}
		}

		if vuln.LastModifiedDate != "" {
			modDate, err := time.Parse(time.RFC3339, vuln.LastModifiedDate)
			if err == nil {
				cveRef.LastModifiedDate = modDate
			}
		}

		// 提取参考链接
		var refs []string
		for _, ref := range vuln.CVE.References.ReferenceData {
			refs = append(refs, ref.URL)
		}
		cveRef.References = refs

		// 提取受影响的CPE
		var affectedProducts []string
		for _, node := range vuln.Configurations.Nodes {
			for _, match := range node.CPEMatch {
				affectedProducts = append(affectedProducts, match.CPE23URI)
			}
		}
		cveRef.AffectedCPEs = affectedProducts

		cveRefs = append(cveRefs, cveRef)
	}

	return cveRefs, nil
}

// 解析GitHub格式的漏洞数据
func (ds *DataSource) parseGitHubVulnerabilities(data []byte) ([]*CVEReference, error) {
	// GitHub Security Advisory响应结构
	type GitHubAdvisory struct {
		ID          string `json:"ghsa_id"`
		CVEID       string `json:"cve_id"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		PublishedAt string `json:"published_at"`
		UpdatedAt   string `json:"updated_at"`
		References  []struct {
			URL string `json:"url"`
		} `json:"references"`
		Vulnerabilities []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"ranges"`
		} `json:"vulnerabilities"`
	}

	var advisories []GitHubAdvisory
	err := json.Unmarshal(data, &advisories)
	if err != nil {
		// 尝试解析单个公告
		var singleAdvisory GitHubAdvisory
		err = json.Unmarshal(data, &singleAdvisory)
		if err != nil {
			return nil, err
		}
		advisories = []GitHubAdvisory{singleAdvisory}
	}

	var cveRefs []*CVEReference

	for _, advisory := range advisories {
		// 跳过没有CVE ID的公告
		if advisory.CVEID == "" {
			continue
		}

		cveRef := &CVEReference{
			CVEID:       advisory.CVEID,
			Description: advisory.Description,
		}

		// 设置CVSS评分 (GitHub使用严重性描述而不是具体分数)
		switch advisory.Severity {
		case "critical":
			cveRef.CVSSScore = 9.0
		case "high":
			cveRef.CVSSScore = 7.0
		case "medium":
			cveRef.CVSSScore = 5.0
		case "low":
			cveRef.CVSSScore = 3.0
		default:
			cveRef.CVSSScore = 0.0
		}

		// 解析日期
		if advisory.PublishedAt != "" {
			pubDate, err := time.Parse(time.RFC3339, advisory.PublishedAt)
			if err == nil {
				cveRef.PublishedDate = pubDate
			}
		}

		if advisory.UpdatedAt != "" {
			modDate, err := time.Parse(time.RFC3339, advisory.UpdatedAt)
			if err == nil {
				cveRef.LastModifiedDate = modDate
			}
		}

		// 提取参考链接
		var refs []string
		for _, ref := range advisory.References {
			refs = append(refs, ref.URL)
		}
		cveRef.References = refs

		// 为受影响的包创建CPE
		var affectedProducts []string
		for _, vuln := range advisory.Vulnerabilities {
			// 创建CPE 2.3格式字符串
			// 格式: cpe:2.3:a:[ecosystem]:[package_name]:[version_range]:*:*:*:*:*:*:*
			for _, r := range vuln.Ranges {
				var version string
				if r.Introduced != "" && r.Fixed != "" {
					version = fmt.Sprintf("%s-%s", r.Introduced, r.Fixed)
				} else if r.Introduced != "" {
					version = fmt.Sprintf("%s-*", r.Introduced)
				} else if r.Fixed != "" {
					version = fmt.Sprintf("*-%s", r.Fixed)
				} else {
					version = "*"
				}

				cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
					strings.ToLower(vuln.Package.Ecosystem),
					strings.ToLower(vuln.Package.Name),
					version)

				affectedProducts = append(affectedProducts, cpe)
			}
		}
		cveRef.AffectedCPEs = affectedProducts

		cveRefs = append(cveRefs, cveRef)
	}

	return cveRefs, nil
}

// 解析RedHat格式的漏洞数据
func (ds *DataSource) parseRedHatVulnerabilities(data []byte) ([]*CVEReference, error) {
	// RedHat CVE响应结构
	type RedHatCVE struct {
		CVE              string   `json:"CVE"`
		BugzillaID       string   `json:"bugzilla"`
		CVSSScore        float64  `json:"cvss_score"`
		CVSSVersion      string   `json:"cvss_version"`
		Description      string   `json:"description"`
		PublicDate       string   `json:"public_date"`
		Modified         string   `json:"modified_date"`
		Details          []string `json:"details"`
		AffectedPackages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"affected_packages"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	}

	var redhatCVEs []RedHatCVE
	err := json.Unmarshal(data, &redhatCVEs)
	if err != nil {
		// 尝试解析单个CVE
		var singleCVE RedHatCVE
		err = json.Unmarshal(data, &singleCVE)
		if err != nil {
			return nil, err
		}
		redhatCVEs = []RedHatCVE{singleCVE}
	}

	var cveRefs []*CVEReference

	for _, rh := range redhatCVEs {
		cveRef := &CVEReference{
			CVEID:       rh.CVE,
			Description: rh.Description,
			CVSSScore:   rh.CVSSScore,
		}

		// 解析日期
		if rh.PublicDate != "" {
			pubDate, err := time.Parse("2006-01-02", rh.PublicDate)
			if err == nil {
				cveRef.PublishedDate = pubDate
			}
		}

		if rh.Modified != "" {
			modDate, err := time.Parse("2006-01-02", rh.Modified)
			if err == nil {
				cveRef.LastModifiedDate = modDate
			}
		}

		// 提取参考链接
		var refs []string
		for _, ref := range rh.References {
			refs = append(refs, ref.URL)
		}
		cveRef.References = refs

		// 为受影响的包创建CPE
		var affectedProducts []string
		for _, pkg := range rh.AffectedPackages {
			// 创建CPE 2.3格式字符串
			// 格式: cpe:2.3:a:redhat:[package_name]:[version]:*:*:*:*:*:*:*
			cpe := fmt.Sprintf("cpe:2.3:a:redhat:%s:%s:*:*:*:*:*:*:*",
				strings.ToLower(pkg.Name),
				pkg.Version)

			affectedProducts = append(affectedProducts, cpe)
		}
		cveRef.AffectedCPEs = affectedProducts

		cveRefs = append(cveRefs, cveRef)
	}

	return cveRefs, nil
}

// MultiSourceVulnerabilitySearch 多数据源漏洞搜索
type MultiSourceVulnerabilitySearch struct {
	// 数据源列表
	Sources []*DataSource

	// 并发级别
	ConcurrencyLevel int

	// 超时时间（秒）
	TimeoutSeconds int

	// 是否合并结果
	MergeResults bool
}

// NewMultiSourceSearch 创建新的多数据源搜索
func NewMultiSourceSearch(sources []*DataSource) *MultiSourceVulnerabilitySearch {
	return &MultiSourceVulnerabilitySearch{
		Sources:          sources,
		ConcurrencyLevel: 3,
		TimeoutSeconds:   30,
		MergeResults:     true,
	}
}

// SearchByCVE 根据CVE ID在多个数据源中搜索
func (ms *MultiSourceVulnerabilitySearch) SearchByCVE(cveID string) ([]*CVEReference, error) {
	cveID = standardizeCVEID(cveID)

	// 用于保存搜索结果
	type searchResult struct {
		source  string
		cveRefs []*CVEReference
		err     error
	}

	// 创建通道和等待组
	resultChan := make(chan searchResult, len(ms.Sources))

	// 限制并发
	sem := make(chan struct{}, ms.ConcurrencyLevel)

	// 为每个数据源创建goroutine
	for _, source := range ms.Sources {
		sem <- struct{}{} // 获取信号量

		go func(s *DataSource) {
			defer func() { <-sem }() // 释放信号量

			// 设置超时
			ctx := s.Client.Timeout
			s.Client.Timeout = time.Duration(ms.TimeoutSeconds) * time.Second
			defer func() { s.Client.Timeout = ctx }()

			// 搜索漏洞
			params := map[string]string{
				"cve": cveID,
			}

			cveRefs, err := s.GetVulnerabilities(params)

			// 发送结果到通道
			resultChan <- searchResult{
				source:  s.Name,
				cveRefs: cveRefs,
				err:     err,
			}
		}(source)
	}

	// 收集所有数据源的结果
	var allResults []*CVEReference
	var errors []string

	// 存储CVE引用的map，用于去重
	cveRefMap := make(map[string]*CVEReference)

	// 等待所有搜索完成
	for i := 0; i < len(ms.Sources); i++ {
		result := <-resultChan

		if result.err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", result.source, result.err))
			continue
		}

		if ms.MergeResults {
			// 合并结果
			for _, cveRef := range result.cveRefs {
				// 如果这个CVE已经在map中
				if existing, ok := cveRefMap[cveRef.CVEID]; ok {
					// 合并受影响产品
					existing.AffectedCPEs = mergeStringSlices(existing.AffectedCPEs, cveRef.AffectedCPEs)

					// 合并参考链接
					existing.References = mergeStringSlices(existing.References, cveRef.References)

					// 使用最高的CVSS评分
					if cveRef.CVSSScore > existing.CVSSScore {
						existing.CVSSScore = cveRef.CVSSScore
					}

					// 使用最早的发布日期
					if !cveRef.PublishedDate.IsZero() && (existing.PublishedDate.IsZero() || cveRef.PublishedDate.Before(existing.PublishedDate)) {
						existing.PublishedDate = cveRef.PublishedDate
					}

					// 使用最新的修改日期
					if !cveRef.LastModifiedDate.IsZero() && (existing.LastModifiedDate.IsZero() || cveRef.LastModifiedDate.After(existing.LastModifiedDate)) {
						existing.LastModifiedDate = cveRef.LastModifiedDate
					}

					// 如果当前描述更长，使用当前描述
					if len(cveRef.Description) > len(existing.Description) {
						existing.Description = cveRef.Description
					}
				} else {
					// 添加新的CVE引用
					cveRefMap[cveRef.CVEID] = cveRef
				}
			}
		} else {
			// 不合并，直接添加所有结果
			allResults = append(allResults, result.cveRefs...)
		}
	}

	// 如果合并结果，将map转换为切片
	if ms.MergeResults {
		for _, cveRef := range cveRefMap {
			allResults = append(allResults, cveRef)
		}
	}

	// 如果有错误但我们仍然获得了一些结果，只是返回结果
	if len(errors) > 0 && len(allResults) > 0 {
		return allResults, nil
	}

	// 如果只有错误，返回第一个错误
	if len(errors) > 0 {
		return nil, fmt.Errorf("多源搜索错误: %s", errors[0])
	}

	return allResults, nil
}

// SearchByCPE 根据CPE在多个数据源中搜索
func (ms *MultiSourceVulnerabilitySearch) SearchByCPE(cpe *CPE) ([]*CVEReference, error) {
	// 用于保存搜索结果
	type searchResult struct {
		source  string
		cveRefs []*CVEReference
		err     error
	}

	// 创建通道和等待组
	resultChan := make(chan searchResult, len(ms.Sources))

	// 限制并发
	sem := make(chan struct{}, ms.ConcurrencyLevel)

	// 为每个数据源创建goroutine
	for _, source := range ms.Sources {
		sem <- struct{}{} // 获取信号量

		go func(s *DataSource) {
			defer func() { <-sem }() // 释放信号量

			// 设置超时
			ctx := s.Client.Timeout
			s.Client.Timeout = time.Duration(ms.TimeoutSeconds) * time.Second
			defer func() { s.Client.Timeout = ctx }()

			// 搜索漏洞
			cveRefs, err := s.SearchVulnerabilitiesByCPE(cpe)

			// 发送结果到通道
			resultChan <- searchResult{
				source:  s.Name,
				cveRefs: cveRefs,
				err:     err,
			}
		}(source)
	}

	// 收集所有数据源的结果
	var allResults []*CVEReference
	var errors []string

	// 存储CVE引用的map，用于去重
	cveRefMap := make(map[string]*CVEReference)

	// 等待所有搜索完成
	for i := 0; i < len(ms.Sources); i++ {
		result := <-resultChan

		if result.err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", result.source, result.err))
			continue
		}

		if ms.MergeResults {
			// 合并结果
			for _, cveRef := range result.cveRefs {
				// 如果这个CVE已经在map中
				if existing, ok := cveRefMap[cveRef.CVEID]; ok {
					// 合并受影响产品
					existing.AffectedCPEs = mergeStringSlices(existing.AffectedCPEs, cveRef.AffectedCPEs)

					// 合并参考链接
					existing.References = mergeStringSlices(existing.References, cveRef.References)

					// 使用最高的CVSS评分
					if cveRef.CVSSScore > existing.CVSSScore {
						existing.CVSSScore = cveRef.CVSSScore
					}

					// 使用最早的发布日期
					if !cveRef.PublishedDate.IsZero() && (existing.PublishedDate.IsZero() || cveRef.PublishedDate.Before(existing.PublishedDate)) {
						existing.PublishedDate = cveRef.PublishedDate
					}

					// 使用最新的修改日期
					if !cveRef.LastModifiedDate.IsZero() && (existing.LastModifiedDate.IsZero() || cveRef.LastModifiedDate.After(existing.LastModifiedDate)) {
						existing.LastModifiedDate = cveRef.LastModifiedDate
					}

					// 如果当前描述更长，使用当前描述
					if len(cveRef.Description) > len(existing.Description) {
						existing.Description = cveRef.Description
					}
				} else {
					// 添加新的CVE引用
					cveRefMap[cveRef.CVEID] = cveRef
				}
			}
		} else {
			// 不合并，直接添加所有结果
			allResults = append(allResults, result.cveRefs...)
		}
	}

	// 如果合并结果，将map转换为切片
	if ms.MergeResults {
		for _, cveRef := range cveRefMap {
			allResults = append(allResults, cveRef)
		}
	}

	// 如果有错误但我们仍然获得了一些结果，只是返回结果
	if len(errors) > 0 && len(allResults) > 0 {
		return allResults, nil
	}

	// 如果只有错误，返回第一个错误
	if len(errors) > 0 {
		return nil, fmt.Errorf("多源搜索错误: %s", errors[0])
	}

	return allResults, nil
}

// 合并两个字符串切片，去除重复项
func mergeStringSlices(slice1, slice2 []string) []string {
	// 使用map去重
	uniqueMap := make(map[string]bool)

	for _, item := range slice1 {
		uniqueMap[item] = true
	}

	for _, item := range slice2 {
		uniqueMap[item] = true
	}

	// 转换回切片
	result := make([]string, 0, len(uniqueMap))
	for item := range uniqueMap {
		result = append(result, item)
	}

	return result
}

// CreateNVDDataSource 创建NVD数据源
func CreateNVDDataSource(apiKey string) *DataSource {
	ds := NewDataSource(
		DataSourceNVD,
		"National Vulnerability Database",
		"美国国家漏洞数据库",
		"https://services.nvd.nist.gov/rest/json/",
	)

	if apiKey != "" {
		ds.SetAuthentication(&DataSourceAuth{
			APIKey: apiKey,
		})
	}

	return ds
}

// CreateGitHubDataSource 创建GitHub数据源
func CreateGitHubDataSource(token string) *DataSource {
	ds := NewDataSource(
		DataSourceGitHub,
		"GitHub Security Advisories",
		"GitHub安全公告",
		"https://api.github.com/security-advisories/",
	)

	if token != "" {
		ds.SetAuthentication(&DataSourceAuth{
			APIKey: token,
		})
	}

	return ds
}

// CreateRedHatDataSource 创建RedHat数据源
func CreateRedHatDataSource() *DataSource {
	return NewDataSource(
		DataSourceRedHatCVE,
		"Red Hat Security Data API",
		"Red Hat安全数据API",
		"https://access.redhat.com/labs/securitydataapi/",
	)
}

// CreateDefaultMultiSourceSearch 创建默认的多源搜索
func CreateDefaultMultiSourceSearch() *MultiSourceVulnerabilitySearch {
	// 创建默认数据源
	nvd := CreateNVDDataSource("")
	redhat := CreateRedHatDataSource()

	sources := []*DataSource{nvd, redhat}

	return NewMultiSourceSearch(sources)
}

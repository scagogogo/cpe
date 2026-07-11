package cpeskills

import (
	"sync"
	"time"
)

// ScanResult 表示一次批量扫描的结果
type ScanResult struct {
	// Component 被扫描的组件
	Component *SBOMComponent `json:"component"`

	// Vulnerabilities 发现的漏洞列表
	Vulnerabilities []*VulnerabilityFinding `json:"vulnerabilities"`

	// RiskScore 风险评分
	RiskScore *RiskScore `json:"riskScore,omitempty"`

	// Duration 扫描耗时
	Duration time.Duration `json:"duration"`

	// Error 扫描错误
	Error string `json:"error,omitempty"`
}

// BatchScanner 批量扫描器
//
// 支持并发扫描大量组件，适用于 CI/CD 集成和定期安全扫描。
type BatchScanner struct {
	// Index CPE 索引
	Index *CPEIndex

	// DataSources 漏洞数据源列表
	DataSources []*VulnDataSource

	// Scorer 风险评分器
	Scorer RiskScorer

	// Concurrency 并发级别
	Concurrency int
}

// NewBatchScanner 创建批量扫描器
func NewBatchScanner(index *CPEIndex, concurrency int) *BatchScanner {
	if concurrency <= 0 {
		concurrency = 4
	}
	return &BatchScanner{
		Index:       index,
		Concurrency: concurrency,
		Scorer:      NewDefaultRiskScorer(),
	}
}

// SetDataSources 设置漏洞数据源
func (bs *BatchScanner) SetDataSources(sources []*VulnDataSource) {
	bs.DataSources = sources
}

// Scan 批量扫描组件
func (bs *BatchScanner) Scan(components []*SBOMComponent) ([]*ScanResult, error) {
	results := make([]*ScanResult, len(components))

	// 使用信号量控制并发
	sem := make(chan struct{}, bs.Concurrency)
	var wg sync.WaitGroup

	for i, comp := range components {
		wg.Add(1)
		sem <- struct{}{} // 获取信号量

		go func(idx int, component *SBOMComponent) {
			defer wg.Done()
			defer func() { <-sem }() // 释放信号量

			start := time.Now()
			result := &ScanResult{
				Component: component,
			}

			// 查找漏洞
			findings := bs.scanComponent(component)
			result.Vulnerabilities = findings

			// 计算风险评分
			if bs.Scorer != nil && len(findings) > 0 {
				result.RiskScore = bs.Scorer.Score(findings, component)
			}

			result.Duration = time.Since(start)
			results[idx] = result
		}(i, comp)
	}

	wg.Wait()
	return results, nil
}

// scanComponent 扫描单个组件
func (bs *BatchScanner) scanComponent(component *SBOMComponent) []*VulnerabilityFinding {
	var findings []*VulnerabilityFinding

	// 通过 CPE 索引查找
	if component.CPE != nil && bs.Index != nil {
		cpes := bs.Index.Lookup(component.CPE)
		for _, c := range cpes {
			_ = c
		}
	}

	// 通过数据源查询（简化实现）
	for _, ds := range bs.DataSources {
		if ds == nil {
			continue
		}
		// 使用数据源搜索与组件相关的漏洞
		if component.CPE != nil {
			cveRefs, err := ds.SearchVulnerabilitiesByCPE(component.CPE)
			if err == nil {
				for _, cveRef := range cveRefs {
					findings = append(findings, &VulnerabilityFinding{
						CVE:          cveRef,
						Reachability: "unknown",
						Source:       ds.Name,
					})
				}
			}
		}
	}

	return findings
}

// MatchResult 表示批量 CPE 匹配的结果
type MatchResult struct {
	// Criteria 匹配条件
	Criteria *CPE `json:"criteria"`

	// Targets 匹配到的目标
	Targets []*CPE `json:"targets"`

	// Count 匹配数量
	Count int `json:"count"`
}

// BatchMatchCPEs 批量匹配 CPE
//
// 在 targets 中查找匹配每个 criteria 的所有 CPE。
func BatchMatchCPEs(criteria []*CPE, targets []*CPE) []MatchResult {
	// 先构建索引以加速匹配
	index := NewCPEIndex(targets)

	results := make([]MatchResult, 0, len(criteria))
	for _, c := range criteria {
		matched := index.Lookup(c)
		result := MatchResult{
			Criteria: c,
			Targets:  matched,
			Count:    len(matched),
		}
		results = append(results, result)
	}

	return results
}

// BatchMatchPURLs 批量匹配 PURL 到 CPE
//
// 返回每个 PURL 对应的 CPE 映射。
func BatchMatchPURLs(purls []*PackageURL, cpes []*CPE) map[string]*CPE {
	index := NewCPEIndex(cpes)
	result := make(map[string]*CPE, len(purls))

	for _, purl := range purls {
		if purl == nil {
			continue
		}
		// 尝试从索引查找
		if cpe := index.LookupByPURL(purl); cpe != nil {
			result[purl.String()] = cpe
			continue
		}

		// 通过 PURL→CPE 转换查找
		if cpe, _, err := PURLToCPE(purl); err == nil && cpe != nil {
			// 在索引中查找匹配的 CPE
			matches := index.Lookup(cpe)
			if len(matches) > 0 {
				result[purl.String()] = matches[0]
			}
		}
	}

	return result
}

// BatchQueryCVEs 批量查询 CVE 信息
//
// 根据 CVE ID 列表，从数据源批量获取 CVE 详细信息。
func BatchQueryCVEs(cveIDs []string, dataSources []*VulnDataSource) (map[string]*CVEReference, error) {
	result := make(map[string]*CVEReference)

	// 使用多数据源搜索
	multiSearch := NewMultiSourceSearch(dataSources)
	multiSearch.ConcurrencyLevel = 5

	for _, cveID := range cveIDs {
		cveRefs, err := multiSearch.SearchByCVE(cveID)
		if err != nil {
			continue
		}
		for _, ref := range cveRefs {
			if ref.CVEID == cveID {
				result[cveID] = ref
				break
			}
		}
	}

	return result, nil
}

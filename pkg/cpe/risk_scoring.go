package cpeskills

import (
	"sort"
)

// RiskPriority 风险优先级
type RiskPriority string

const (
	// RiskPriorityCritical 危急
	RiskPriorityCritical RiskPriority = "critical"

	// RiskPriorityHigh 高危
	RiskPriorityHigh RiskPriority = "high"

	// RiskPriorityMedium 中危
	RiskPriorityMedium RiskPriority = "medium"

	// RiskPriorityLow 低危
	RiskPriorityLow RiskPriority = "low"

	// RiskPriorityNone 无风险
	RiskPriorityNone RiskPriority = "none"
)

// RiskScore 表示组件的风险评分
type RiskScore struct {
	// Component 被评估的组件
	Component *SBOMComponent `json:"component"`

	// OverallScore 综合风险评分 (0-10)
	OverallScore float64 `json:"overallScore"`

	// CVSSMax 最高 CVSS 评分
	CVSSMax float64 `json:"cvssMax"`

	// EPSSScore EPSS 漏洞利用预测评分 (0.0-1.0)
	EPSSScore float64 `json:"epssScore,omitempty"`

	// KEVListed 是否在 CISA KEV 目录中
	KEVListed bool `json:"kevListed"`

	// ExploitMaturity 漏洞利用成熟度
	ExploitMaturity string `json:"exploitMaturity,omitempty"`

	// Reachability 可达性
	Reachability string `json:"reachability"`

	// Priority 风险优先级
	Priority RiskPriority `json:"priority"`

	// Factors 各因素的贡献值
	Factors map[string]float64 `json:"factors,omitempty"`
}

// RiskScorer 风险评分器接口
type RiskScorer interface {
	// Score 计算单个组件的风险评分
	Score(findings []*VulnerabilityFinding, component *SBOMComponent) *RiskScore
}

// DefaultRiskScorer 默认风险评分器
//
// 综合考虑 CVSS、EPSS、KEV、可达性和漏洞利用成熟度。
type DefaultRiskScorer struct {
	// CVSSWeight CVSS 评分权重
	CVSSWeight float64

	// EPSSWeight EPSS 评分权重
	EPSSWeight float64

	// KEVWeight KEV 收录权重
	KEVWeight float64

	// ReachabilityWeight 可达性权重
	ReachabilityWeight float64
}

// NewDefaultRiskScorer 创建默认风险评分器
func NewDefaultRiskScorer() *DefaultRiskScorer {
	return &DefaultRiskScorer{
		CVSSWeight:        0.5,
		EPSSWeight:        0.2,
		KEVWeight:         0.2,
		ReachabilityWeight: 0.1,
	}
}

// Score 计算风险评分
func (s *DefaultRiskScorer) Score(findings []*VulnerabilityFinding, component *SBOMComponent) *RiskScore {
	score := &RiskScore{
		Component: component,
		Factors:   make(map[string]float64),
	}

	if len(findings) == 0 {
		score.Priority = RiskPriorityNone
		return score
	}

	// 计算各因素
	maxCVSS := 0.0
	maxEPSS := 0.0
	kevListed := false
	reachabilityScore := 0.0

	for _, f := range findings {
		if f.CVE != nil && f.CVE.CVSSScore > maxCVSS {
			maxCVSS = f.CVE.CVSSScore
		}
		if f.EPSSScore > maxEPSS {
			maxEPSS = f.EPSSScore
		}
		if f.KEVListed {
			kevListed = true
		}
		if f.Reachability == "direct" {
			reachabilityScore = 1.0
		} else if f.Reachability == "transitive" {
			reachabilityScore = 0.5
		}
	}

	score.CVSSMax = maxCVSS
	score.EPSSScore = maxEPSS
	score.KEVListed = kevListed
	score.Reachability = reachabilityToString(reachabilityScore)

	// 计算综合评分 (0-10)
	cvssFactor := (maxCVSS / 10.0) * 10.0 * s.CVSSWeight
	epssFactor := maxEPSS * 10.0 * s.EPSSWeight
	kevFactor := 0.0
	if kevListed {
		kevFactor = 10.0 * s.KEVWeight
	}
	reachFactor := reachabilityScore * 10.0 * s.ReachabilityWeight

	score.Factors["cvss"] = cvssFactor
	score.Factors["epss"] = epssFactor
	score.Factors["kev"] = kevFactor
	score.Factors["reachability"] = reachFactor

	score.OverallScore = cvssFactor + epssFactor + kevFactor + reachFactor
	if score.OverallScore > 10.0 {
		score.OverallScore = 10.0
	}

	// 确定优先级
	score.Priority = determinePriority(score.OverallScore, kevListed)

	return score
}

// ScoreComponents 批量计算组件风险评分
func ScoreComponents(components []*SBOMComponent, nvdData *NVDCPEData) []*RiskScore {
	scorer := NewDefaultRiskScorer()
	var scores []*RiskScore

	for _, comp := range components {
		var findings []*VulnerabilityFinding
		if comp.CPE != nil && nvdData != nil {
			cves := nvdData.FindCVEsForCPE(comp.CPE)
			for _, cveID := range cves {
				findings = append(findings, &VulnerabilityFinding{
					CVE:          &CVEReference{CVEID: cveID},
					Reachability: "unknown",
				})
			}
		}
		scores = append(scores, scorer.Score(findings, comp))
	}

	return scores
}

// SortByRisk 按风险评分降序排序
func SortByRisk(scores []*RiskScore) {
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].OverallScore > scores[j].OverallScore
	})
}

// FilterByPriority 按优先级过滤风险评分
func FilterByPriority(scores []*RiskScore, priority RiskPriority) []*RiskScore {
	var result []*RiskScore
	for _, s := range scores {
		if s.Priority == priority {
			result = append(result, s)
		}
	}
	return result
}

// determinePriority 根据评分确定优先级
func determinePriority(score float64, kevListed bool) RiskPriority {
	if kevListed && score >= 7.0 {
		return RiskPriorityCritical
	}
	switch {
	case score >= 9.0:
		return RiskPriorityCritical
	case score >= 7.0:
		return RiskPriorityHigh
	case score >= 4.0:
		return RiskPriorityMedium
	case score > 0:
		return RiskPriorityLow
	default:
		return RiskPriorityNone
	}
}

// reachabilityToString 将可达性分数转换为字符串
func reachabilityToString(score float64) string {
	switch {
	case score >= 1.0:
		return "direct"
	case score >= 0.5:
		return "transitive"
	default:
		return "unknown"
	}
}

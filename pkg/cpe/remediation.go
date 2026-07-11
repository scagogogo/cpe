package cpeskills

import (
	"strings"
)

// RemediationAdvice 表示修复建议
//
// 用于指导用户如何修复组件中的已知漏洞，包括推荐的升级版本、
// 是否有破坏性更改以及修复优先级。
type RemediationAdvice struct {
	// Component 需要修复的组件
	Component *SBOMComponent `json:"component"`

	// CurrentVersion 当前版本
	CurrentVersion string `json:"currentVersion"`

	// RecommendedVersion 推荐的修复版本
	RecommendedVersion string `json:"recommendedVersion"`

	// BreakingChange 是否有破坏性更改
	BreakingChange bool `json:"breakingChange"`

	// CVEIDs 此修复解决的 CVE ID 列表
	CVEIDs []string `json:"cveIDs"`

	// Priority 修复优先级 (0=最高, 1=高, 2=中, 3=低)
	Priority int `json:"priority"`

	// Summary 修复建议摘要
	Summary string `json:"summary"`
}

// FindRemediation 为组件查找修复建议
//
// 根据漏洞发现列表，确定最佳的修复版本并提供修复建议。
func FindRemediation(component *SBOMComponent, findings []*VulnerabilityFinding) *RemediationAdvice {
	advice := &RemediationAdvice{
		Component:       component,
		CurrentVersion:  component.Version,
		CVEIDs:          make([]string, 0),
		Priority:        3, // 默认低优先级
	}

	// 收集 CVE ID 和修复版本
	fixedVersions := make(map[string]int) // version → frequency count
	maxSeverity := 0

	for _, f := range findings {
		if f.CVE != nil {
			advice.CVEIDs = append(advice.CVEIDs, f.CVE.CVEID)

			// 跟踪最高严重级别
			sevRank := severityRank(f.CVE.Severity)
			if sevRank > maxSeverity {
				maxSeverity = sevRank
			}
		}

		// 收集修复版本
		if f.FixedVersion != "" {
			fixedVersions[f.FixedVersion]++
		}

		// 从 OSV 数据收集修复版本
		if f.OSV != nil {
			osvFixed := f.OSV.GetFixedVersion()
			if osvFixed != "" {
				fixedVersions[osvFixed]++
			}
		}
	}

	// 确定推荐的修复版本（出现频率最高的）
	maxCount := 0
	for ver, count := range fixedVersions {
		if count > maxCount {
			maxCount = count
			advice.RecommendedVersion = ver
		}
	}

	// 检查是否有破坏性更改（简化实现：主版本号变更）
	if advice.RecommendedVersion != "" && component.Version != "" {
		advice.BreakingChange = isBreakingChange(component.Version, advice.RecommendedVersion)
	}

	// 设置修复可用标志
	_ = advice.RecommendedVersion != ""

	// 根据严重级别设置优先级
	switch maxSeverity {
	case 4: // Critical
		advice.Priority = 0
		advice.Summary = "Critical vulnerabilities found. Immediate remediation required."
	case 3: // High
		advice.Priority = 1
		advice.Summary = "High severity vulnerabilities found. Remediation recommended within 30 days."
	case 2: // Medium
		advice.Priority = 2
		advice.Summary = "Medium severity vulnerabilities found. Plan remediation in next release cycle."
	default:
		advice.Priority = 3
		advice.Summary = "Low severity issues found. Monitor for updates."
	}

	return advice
}

// FixAvailable 是否有可用的修复版本
func (r *RemediationAdvice) HasFixAvailable() bool {
	return r.RecommendedVersion != ""
}

// IsUrgent 是否需要紧急修复（Critical 且在 KEV 中）
func (r *RemediationAdvice) IsUrgent(findings []*VulnerabilityFinding) bool {
	if r.Priority != 0 {
		return false
	}
	for _, f := range findings {
		if f.KEVListed {
			return true
		}
	}
	return false
}

// isBreakingChange 检查版本升级是否涉及主版本号变更
func isBreakingChange(currentVersion, newVersion string) bool {
	curParts := splitVersionPrefix(currentVersion)
	newParts := splitVersionPrefix(newVersion)
	if len(curParts) > 0 && len(newParts) > 0 {
		return curParts[0] != newParts[0]
	}
	return false
}

// splitVersionPrefix 分割版本号的前两个数字段
func splitVersionPrefix(version string) []string {
	// 移除 pre-release 和 build metadata
	version = strings.SplitN(version, "-", 2)[0]
	version = strings.SplitN(version, "+", 2)[0]
	parts := strings.Split(version, ".")
	return parts
}

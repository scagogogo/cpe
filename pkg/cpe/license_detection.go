package cpeskills

import "strings"

// LicenseCompliance 表示许可证合规性检查结果
type LicenseCompliance struct {
	// Component 被检查的组件
	Component *SBOMComponent `json:"component"`

	// DetectedLicense 检测到的许可证
	DetectedLicense *License `json:"detectedLicense,omitempty"`

	// DeclaredLicense 声明的许可证
	DeclaredLicense *License `json:"declaredLicense,omitempty"`

	// Conflicts 许可证冲突列表
	Conflicts []string `json:"conflicts,omitempty"`

	// RiskLevel 许可证风险级别
	RiskLevel string `json:"riskLevel"`

	// IsCompliant 是否合规
	IsCompliant bool `json:"isCompliant"`
}

// LicensePolicy 许可证策略
type LicensePolicy struct {
	// AllowedLicenses 允许的许可证 SPDX ID 列表
	AllowedLicenses []string `json:"allowedLicenses"`

	// DeniedLicenses 禁止的许可证 SPDX ID 列表
	DeniedLicenses []string `json:"deniedLicenses"`

	// AllowCopyleft 是否允许 Copyleft 许可证
	AllowCopyleft bool `json:"allowCopyleft"`

	// RequireOSIApproved 是否要求 OSI 批准
	RequireOSIApproved bool `json:"requireOSIApproved"`
}

// DefaultLicensePolicy 返回默认的许可证策略（宽松）
func DefaultLicensePolicy() *LicensePolicy {
	return &LicensePolicy{
		AllowedLicenses: []string{
			"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
			"ISC", "Unlicense", "CC0-1.0", "Zlib", "PostgreSQL",
		},
		DeniedLicenses: []string{
			"AGPL-3.0-only", "AGPL-3.0-or-later",
		},
		AllowCopyleft:     true,
		RequireOSIApproved: true,
	}
}

// StrictLicensePolicy 返回严格的许可证策略
func StrictLicensePolicy() *LicensePolicy {
	return &LicensePolicy{
		AllowedLicenses: []string{
			"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
		},
		DeniedLicenses: []string{
			"GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
			"AGPL-3.0-only", "AGPL-3.0-or-later",
		},
		AllowCopyleft:      false,
		RequireOSIApproved:  true,
	}
}

// DetectLicense 从组件信息中检测许可证
//
// 根据组件的名称、属性和元数据推断许可证类型。
func DetectLicense(component *SBOMComponent) *License {
	if component == nil {
		return nil
	}

	// 从组件的 Licenses 字段获取
	if len(component.Licenses) > 0 {
		return component.Licenses[0]
	}

	// 从属性中检测
	if licenseName, ok := component.Properties["license"]; ok {
		return DetectLicenseByName(licenseName)
	}

	// 从 SPDX 许可证标识符检测
	if spdxID, ok := component.Properties["spdx:licenseId"]; ok {
		return NewLicense(spdxID, spdxID)
	}

	return nil
}

// CheckLicenseCompliance 检查许可证合规性
func CheckLicenseCompliance(component *SBOMComponent, policy *LicensePolicy) *LicenseCompliance {
	compliance := &LicenseCompliance{
		Component:  component,
		IsCompliant: true,
	}

	if policy == nil {
		policy = DefaultLicensePolicy()
	}

	// 检测许可证
	detected := DetectLicense(component)
	compliance.DetectedLicense = detected

	// 获取声明的许可证
	if len(component.Licenses) > 0 {
		compliance.DeclaredLicense = component.Licenses[0]
	}

	// 如果没有检测到许可证
	if detected == nil {
		compliance.RiskLevel = "unknown"
		compliance.IsCompliant = false
		compliance.Conflicts = append(compliance.Conflicts, "No license detected")
		return compliance
	}

	// 检查是否在禁止列表中
	for _, denied := range policy.DeniedLicenses {
		if strings.EqualFold(detected.SPDXID, denied) {
			compliance.IsCompliant = false
			compliance.Conflicts = append(compliance.Conflicts, "License is in denied list: "+detected.SPDXID)
		}
	}

	// 检查是否在允许列表中
	if len(policy.AllowedLicenses) > 0 {
		allowed := false
		for _, a := range policy.AllowedLicenses {
			if strings.EqualFold(detected.SPDXID, a) {
				allowed = true
				break
			}
		}
		if !allowed {
			compliance.IsCompliant = false
			compliance.Conflicts = append(compliance.Conflicts, "License not in allowed list: "+detected.SPDXID)
		}
	}

	// 检查 Copyleft 限制
	if !policy.AllowCopyleft && detected.IsCopyleft {
		compliance.IsCompliant = false
		compliance.Conflicts = append(compliance.Conflicts, "Copyleft license not allowed: "+detected.SPDXID)
	}

	// 检查 OSI 批准要求
	if policy.RequireOSIApproved && !detected.IsOSIApproved {
		compliance.IsCompliant = false
		compliance.Conflicts = append(compliance.Conflicts, "License is not OSI approved: "+detected.SPDXID)
	}

	// 确定风险级别
	if compliance.IsCompliant {
		compliance.RiskLevel = "low"
	} else if detected.IsCopyleft {
		compliance.RiskLevel = "high"
	} else {
		compliance.RiskLevel = "medium"
	}

	return compliance
}

// BatchCheckLicenseCompliance 批量检查许可证合规性
func BatchCheckLicenseCompliance(components []*SBOMComponent, policy *LicensePolicy) []*LicenseCompliance {
	results := make([]*LicenseCompliance, 0, len(components))
	for _, comp := range components {
		results = append(results, CheckLicenseCompliance(comp, policy))
	}
	return results
}

// GetNonCompliantComponents 获取不合规的组件
func GetNonCompliantComponents(complianceResults []*LicenseCompliance) []*LicenseCompliance {
	var results []*LicenseCompliance
	for _, c := range complianceResults {
		if !c.IsCompliant {
			results = append(results, c)
		}
	}
	return results
}

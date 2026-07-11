package cpeskills

import (
	"encoding/json"
	"fmt"
	"time"
)

// SBOMFormat 表示 SBOM 文档格式
type SBOMFormat string

const (
	// SBOMFormatCycloneDX CycloneDX 格式
	SBOMFormatCycloneDX SBOMFormat = "cyclonedx"

	// SBOMFormatSPDX SPDX 格式
	SBOMFormatSPDX SBOMFormat = "spdx"

	// SBOMFormatUnknown 未知格式
	SBOMFormatUnknown SBOMFormat = "unknown"
)

// SBOM 表示一个软件物料清单（Software Bill of Materials）
//
// SBOM 是一个通用的、厂商无关的 SBOM 数据模型，可以映射到 CycloneDX 和 SPDX 格式。
// 作为 SCA 系统的核心数据结构，SBOM 包含组件列表、依赖关系和元数据。
type SBOM struct {
	// Format SBOM 格式 (CycloneDX, SPDX)
	Format SBOMFormat `json:"format"`

	// SpecVersion 规范版本
	SpecVersion string `json:"specVersion"`

	// SerialNumber 序列号，唯一标识此 SBOM 文档
	SerialNumber string `json:"serialNumber"`

	// Name SBOM 文档名称
	Name string `json:"name"`

	// Components 软件组件列表
	Components []*SBOMComponent `json:"components"`

	// Dependencies 依赖关系列表
	Dependencies []*SBOMDependency `json:"dependencies"`

	// Metadata SBOM 元数据
	Metadata *SBOMMetadata `json:"metadata,omitempty"`

	// CreatedAt 创建时间
	CreatedAt time.Time `json:"createdAt"`
}

// SBOMComponent 表示 SBOM 中的一个软件组件
type SBOMComponent struct {
	// BomRef 组件在 SBOM 中的唯一引用标识符
	BomRef string `json:"bomRef"`

	// Type 组件类型 (application, framework, library, container, operating-system, device, file)
	Type string `json:"type"`

	// Name 组件名称
	Name string `json:"name"`

	// Version 组件版本
	Version string `json:"version"`

	// Group 组件分组 (如 Maven groupId)
	Group string `json:"group,omitempty"`

	// PURL 包 URL
	PURL *PackageURL `json:"purl,omitempty"`

	// CPE 通用平台枚举
	CPE *CPE `json:"cpe,omitempty"`

	// Licenses 许可证列表
	Licenses []*License `json:"licenses,omitempty"`

	// Hashes 文件哈希值 (alg → value)
	Hashes map[string]string `json:"hashes,omitempty"`

	// Supplier 供应商信息
	Supplier string `json:"supplier,omitempty"`

	// Description 组件描述
	Description string `json:"description,omitempty"`

	// Properties 自定义属性
	Properties map[string]string `json:"properties,omitempty"`

	// ExternalReferences 外部参考链接
	ExternalReferences []*ExternalReference `json:"externalReferences,omitempty"`
}

// SBOMDependency 表示组件之间的依赖关系
type SBOMDependency struct {
	// Ref 依赖方的 BomRef
	Ref string `json:"ref"`

	// DependsOn 被依赖方的 BomRef 列表
	DependsOn []string `json:"dependsOn"`
}

// SBOMMetadata 包含 SBOM 文档的元数据
type SBOMMetadata struct {
	// Timestamp 生成时间戳
	Timestamp time.Time `json:"timestamp"`

	// Tools 生成工具列表
	Tools []*SBOMTool `json:"tools,omitempty"`

	// Authors 作者列表
	Authors []*SBOMAuthor `json:"authors,omitempty"`

	// Component 文档主题组件 (最顶层的组件)
	Component *SBOMComponent `json:"component,omitempty"`

	// Licenses 文档级许可证
	Licenses []*License `json:"licenses,omitempty"`

	// Properties 自定义属性
	Properties map[string]string `json:"properties,omitempty"`
}

// SBOMTool 表示生成 SBOM 的工具
type SBOMTool struct {
	// Name 工具名称
	Name string `json:"name"`

	// Vendor 工具供应商
	Vendor string `json:"vendor,omitempty"`

	// Version 工具版本
	Version string `json:"version,omitempty"`
}

// SBOMAuthor 表示 SBOM 文档作者
type SBOMAuthor struct {
	// Name 作者姓名
	Name string `json:"name"`

	// Email 作者邮箱
	Email string `json:"email,omitempty"`
}

// ExternalReference 表示组件的外部参考
type ExternalReference struct {
	// Type 参考类型 (website, issue-tracker, vcs, etc.)
	Type string `json:"type"`

	// URL 参考链接
	URL string `json:"url"`

	// Comment 备注
	Comment string `json:"comment,omitempty"`
}

// VulnerableComponent 表示一个有漏洞的组件
type VulnerableComponent struct {
	// Component 组件信息
	Component *SBOMComponent `json:"component"`

	// Vulnerabilities 关联的漏洞列表
	Vulnerabilities []*VulnerabilityFinding `json:"vulnerabilities"`

	// MaxCVSS 最高 CVSS 评分
	MaxCVSS float64 `json:"maxCVSS"`

	// MaxSeverity 最高严重级别
	MaxSeverity string `json:"maxSeverity"`

	// CveCount 漏洞总数
	CveCount int `json:"cveCount"`
}

// NewSBOM 创建一个新的 SBOM 文档
func NewSBOM(format SBOMFormat, name string) *SBOM {
	serial := generateSBOMSerial()
	return &SBOM{
		Format:       format,
		SpecVersion:  defaultSpecVersion(format),
		SerialNumber: serial,
		Name:         name,
		Components:   make([]*SBOMComponent, 0),
		Dependencies: make([]*SBOMDependency, 0),
		Metadata: &SBOMMetadata{
			Timestamp: time.Now(),
			Tools:     make([]*SBOMTool, 0),
			Authors:   make([]*SBOMAuthor, 0),
		},
		CreatedAt: time.Now(),
	}
}

// AddComponent 向 SBOM 中添加一个组件
func (s *SBOM) AddComponent(component *SBOMComponent) {
	if component == nil {
		return
	}
	if component.BomRef == "" {
		component.BomRef = generateBomRef(component)
	}
	s.Components = append(s.Components, component)
}

// AddDependency 向 SBOM 中添加一个依赖关系
func (s *SBOM) AddDependency(ref string, dependsOn []string) {
	s.Dependencies = append(s.Dependencies, &SBOMDependency{
		Ref:       ref,
		DependsOn: dependsOn,
	})
}

// GetComponent 根据 BomRef 查找组件
func (s *SBOM) GetComponent(bomRef string) *SBOMComponent {
	for _, c := range s.Components {
		if c.BomRef == bomRef {
			return c
		}
	}
	return nil
}

// FindVulnerableComponents 在 SBOM 中查找存在漏洞的组件
//
// 根据提供的 CVE 列表，匹配 SBOM 中的组件并返回存在漏洞的组件列表。
// 匹配基于组件的 CPE 和 PURL 进行。
func (s *SBOM) FindVulnerableComponents(cves []*CVEReference) []*VulnerableComponent {
	var results []*VulnerableComponent

	for _, component := range s.Components {
		findings := s.matchVulnerabilities(component, cves)
		if len(findings) == 0 {
			continue
		}

		maxCVSS := 0.0
		maxSeverity := ""
		for _, f := range findings {
			if f.CVE != nil && f.CVE.CVSSScore > maxCVSS {
				maxCVSS = f.CVE.CVSSScore
				maxSeverity = f.CVE.Severity
			}
		}

		results = append(results, &VulnerableComponent{
			Component:       component,
			Vulnerabilities: findings,
			MaxCVSS:         maxCVSS,
			MaxSeverity:     maxSeverity,
			CveCount:        len(findings),
		})
	}

	return results
}

// EnrichWithVulnerabilities 使用 NVD 数据丰富 SBOM 组件
//
// 此方法使用提供的 NVD 数据为每个组件查找关联的 CVE，并将 CVE ID 写入组件属性。
func (s *SBOM) EnrichWithVulnerabilities(nvdData *NVDCPEData) error {
	if nvdData == nil {
		return fmt.Errorf("NVD data is nil")
	}

	for _, component := range s.Components {
		if component.CPE != nil {
			cves := nvdData.FindCVEsForCPE(component.CPE)
			if len(cves) > 0 {
				if component.Properties == nil {
					component.Properties = make(map[string]string)
				}
				// 存储 CVE 列表（逗号分隔）
				cveList := ""
				for i, cve := range cves {
					if i > 0 {
						cveList += ","
					}
					cveList += cve
				}
				component.Properties["cpe:cves"] = cveList
				component.Properties["cpe:cveCount"] = fmt.Sprintf("%d", len(cves))
			}
		}
	}
	return nil
}

// ToJSON 将 SBOM 序列化为带缩进的 JSON
func (s *SBOM) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// ComponentCount 返回 SBOM 中的组件数量
func (s *SBOM) ComponentCount() int {
	return len(s.Components)
}

// DependencyCount 返回 SBOM 中的依赖关系数量
func (s *SBOM) DependencyCount() int {
	return len(s.Dependencies)
}

// matchVulnerabilities 匹配单个组件的漏洞
func (s *SBOM) matchVulnerabilities(component *SBOMComponent, cves []*CVEReference) []*VulnerabilityFinding {
	var findings []*VulnerabilityFinding

	for _, cveRef := range cves {
		matched := false

		// 通过 CPE 匹配
		if component.CPE != nil && cveRef.AffectedCPEs != nil {
			for _, affectedCPE := range cveRef.AffectedCPEs {
				if matchedCPE, _ := Parse(affectedCPE); matchedCPE != nil {
					if component.CPE.Match(matchedCPE) {
						matched = true
						break
					}
				}
			}
		}

		// 通过 PURL 匹配（如果在组件属性中有 CVE）
		if !matched && component.CPE != nil {
			if component.CPE.Cve == cveRef.CVEID {
				matched = true
			}
		}

		if matched {
			findings = append(findings, &VulnerabilityFinding{
				CVE:          cveRef,
				FixAvailable: false,
				Reachability: "unknown",
			})
		}
	}

	return findings
}

// NewSBOMComponent 创建一个新的 SBOM 组件
func NewSBOMComponent(name, version string) *SBOMComponent {
	return &SBOMComponent{
		Name:       name,
		Version:    version,
		Hashes:     make(map[string]string),
		Properties: make(map[string]string),
	}
}

// SetPURL 设置组件的 PURL
func (c *SBOMComponent) SetPURL(purl *PackageURL) {
	c.PURL = purl
}

// SetCPE 设置组件的 CPE
func (c *SBOMComponent) SetCPE(cpe *CPE) {
	c.CPE = cpe
}

// AddHash 添加文件哈希
func (c *SBOMComponent) AddHash(algorithm, value string) {
	if c.Hashes == nil {
		c.Hashes = make(map[string]string)
	}
	c.Hashes[algorithm] = value
}

// SetProperty 设置自定义属性
func (c *SBOMComponent) SetProperty(key, value string) {
	if c.Properties == nil {
		c.Properties = make(map[string]string)
	}
	c.Properties[key] = value
}

// generateSBOMSerial 生成 SBOM 序列号
func generateSBOMSerial() string {
	return fmt.Sprintf("urn:uuid:%s", generateUUIDv4())
}

// generateBomRef 为组件生成 BomRef
func generateBomRef(component *SBOMComponent) string {
	if component.PURL != nil && component.PURL.IsValid() {
		return component.PURL.String()
	}
	if component.CPE != nil {
		return component.CPE.GetURI()
	}
	return fmt.Sprintf("%s@%s", component.Name, component.Version)
}

// defaultSpecVersion 获取默认规范版本
func defaultSpecVersion(format SBOMFormat) string {
	switch format {
	case SBOMFormatCycloneDX:
		return "1.5"
	case SBOMFormatSPDX:
		return "2.3"
	default:
		return "1.0"
	}
}

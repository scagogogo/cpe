package cpeskills

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// cyclonedxBom CycloneDX 1.5 JSON 原始结构
type cyclonedxBom struct {
	BomFormat    string                 `json:"bomFormat"`
	SpecVersion  string                 `json:"specVersion"`
	SerialNumber string                 `json:"serialNumber,omitempty"`
	Version      int                    `json:"version"`
	Metadata     *cyclonedxMetadata     `json:"metadata,omitempty"`
	Components   []*cyclonedxComponent  `json:"components,omitempty"`
	Dependencies []*cyclonedxDependency `json:"dependencies,omitempty"`
}

type cyclonedxMetadata struct {
	Timestamp string               `json:"timestamp,omitempty"`
	Tools     []*cyclonedxTool     `json:"tools,omitempty"`
	Authors   []*cyclonedxAuthor   `json:"authors,omitempty"`
	Component *cyclonedxComponent  `json:"component,omitempty"`
}

type cyclonedxTool struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor,omitempty"`
	Version string `json:"version,omitempty"`
}

type cyclonedxAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

type cyclonedxComponent struct {
	BomRef             string                       `json:"bom-ref,omitempty"`
	Type               string                       `json:"type"`
	Name               string                       `json:"name"`
	Version            string                       `json:"version,omitempty"`
	Group              string                       `json:"group,omitempty"`
	PURL               string                       `json:"purl,omitempty"`
	CPE                string                       `json:"cpe,omitempty"`
	Licenses           []*cyclonedxLicense          `json:"licenses,omitempty"`
	Hashes             []*cyclonedxHash             `json:"hashes,omitempty"`
	Supplier           *cyclonedxOrganizationalEntity `json:"supplier,omitempty"`
	Description        string                       `json:"description,omitempty"`
	Properties         []*cyclonedxProperty         `json:"properties,omitempty"`
	ExternalReferences []*cyclonedxExtRef           `json:"externalReferences,omitempty"`
}

type cyclonedxLicense struct {
	License *cyclonedxLicenseChoice `json:"license,omitempty"`
}

type cyclonedxLicenseChoice struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type cyclonedxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cyclonedxOrganizationalEntity struct {
	Name string `json:"name,omitempty"`
}

type cyclonedxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cyclonedxExtRef struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment,omitempty"`
}

type cyclonedxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// ParseCycloneDXJSON 解析 CycloneDX JSON 格式的 SBOM
func ParseCycloneDXJSON(data []byte) (*SBOM, error) {
	var bom cyclonedxBom
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("failed to parse CycloneDX JSON: %w", err)
	}

	sbom := NewSBOM(SBOMFormatCycloneDX, "")
	sbom.SpecVersion = bom.SpecVersion
	sbom.SerialNumber = bom.SerialNumber

	// 解析元数据
	if bom.Metadata != nil {
		sbom.Metadata.Timestamp = parseCycloneDXTimestamp(bom.Metadata.Timestamp)

		for _, t := range bom.Metadata.Tools {
			if t != nil {
				sbom.Metadata.Tools = append(sbom.Metadata.Tools, &SBOMTool{
					Name:    t.Name,
					Vendor:  t.Vendor,
					Version: t.Version,
				})
			}
		}
		for _, a := range bom.Metadata.Authors {
			if a != nil {
				sbom.Metadata.Authors = append(sbom.Metadata.Authors, &SBOMAuthor{
					Name:  a.Name,
					Email: a.Email,
				})
			}
		}
		if bom.Metadata.Component != nil {
			sbom.Metadata.Component = convertCycloneDXComponent(bom.Metadata.Component)
		}
	}

	// 解析组件
	for _, c := range bom.Components {
		if c != nil {
			sbom.AddComponent(convertCycloneDXComponent(c))
		}
	}

	// 解析依赖关系
	for _, d := range bom.Dependencies {
		if d != nil {
			sbom.AddDependency(d.Ref, d.DependsOn)
		}
	}

	return sbom, nil
}

// ToCycloneDXJSON 将 SBOM 导出为 CycloneDX JSON 格式
func (s *SBOM) ToCycloneDXJSON() ([]byte, error) {
	bom := &cyclonedxBom{
		BomFormat:    "CycloneDX",
		SpecVersion:  s.SpecVersion,
		SerialNumber: s.SerialNumber,
		Version:      1,
	}

	// 转换元数据
	if s.Metadata != nil {
		bom.Metadata = &cyclonedxMetadata{}
		if !s.Metadata.Timestamp.IsZero() {
			bom.Metadata.Timestamp = s.Metadata.Timestamp.Format("2006-01-02T15:04:05Z")
		}
		for _, t := range s.Metadata.Tools {
			bom.Metadata.Tools = append(bom.Metadata.Tools, &cyclonedxTool{
				Name:    t.Name,
				Vendor:  t.Vendor,
				Version: t.Version,
			})
		}
		for _, a := range s.Metadata.Authors {
			bom.Metadata.Authors = append(bom.Metadata.Authors, &cyclonedxAuthor{
				Name:  a.Name,
				Email: a.Email,
			})
		}
		if s.Metadata.Component != nil {
			bom.Metadata.Component = convertToCycloneDXComponent(s.Metadata.Component)
		}
	}

	// 转换组件
	for _, c := range s.Components {
		bom.Components = append(bom.Components, convertToCycloneDXComponent(c))
	}

	// 转换依赖关系
	for _, d := range s.Dependencies {
		bom.Dependencies = append(bom.Dependencies, &cyclonedxDependency{
			Ref:       d.Ref,
			DependsOn: d.DependsOn,
		})
	}

	return json.MarshalIndent(bom, "", "  ")
}

// convertCycloneDXComponent 将 CycloneDX 原始组件转换为 SBOM 组件
func convertCycloneDXComponent(c *cyclonedxComponent) *SBOMComponent {
	comp := &SBOMComponent{
		BomRef:      c.BomRef,
		Type:        c.Type,
		Name:        c.Name,
		Version:     c.Version,
		Group:       c.Group,
		Description: c.Description,
		Hashes:      make(map[string]string),
		Properties:  make(map[string]string),
	}

	// 解析 PURL
	if c.PURL != "" {
		if purl, err := ParsePURL(c.PURL); err == nil {
			comp.PURL = purl
		}
	}

	// 解析 CPE
	if c.CPE != "" {
		if cpe, err := Parse(c.CPE); err == nil {
			comp.CPE = cpe
		}
	}

	// 解析许可证
	for _, l := range c.Licenses {
		if l != nil && l.License != nil {
			license := &License{
				SPDXID: l.License.ID,
				Name:   l.License.Name,
				URL:    l.License.URL,
			}
			comp.Licenses = append(comp.Licenses, license)
		}
	}

	// 解析哈希值
	for _, h := range c.Hashes {
		if h != nil {
			comp.Hashes[strings.ToLower(h.Alg)] = h.Content
		}
	}

	// 解析供应商
	if c.Supplier != nil {
		comp.Supplier = c.Supplier.Name
	}

	// 解析属性
	for _, p := range c.Properties {
		if p != nil {
			comp.Properties[p.Name] = p.Value
		}
	}

	// 解析外部参考
	for _, r := range c.ExternalReferences {
		if r != nil {
			comp.ExternalReferences = append(comp.ExternalReferences, &ExternalReference{
				Type:    r.Type,
				URL:     r.URL,
				Comment: r.Comment,
			})
		}
	}

	return comp
}

// convertToCycloneDXComponent 将 SBOM 组件转换为 CycloneDX 格式
func convertToCycloneDXComponent(comp *SBOMComponent) *cyclonedxComponent {
	c := &cyclonedxComponent{
		BomRef:      comp.BomRef,
		Type:        comp.Type,
		Name:        comp.Name,
		Version:     comp.Version,
		Group:       comp.Group,
		Description: comp.Description,
	}

	if comp.PURL != nil && comp.PURL.IsValid() {
		c.PURL = comp.PURL.String()
	}
	if comp.CPE != nil {
		c.CPE = comp.CPE.GetURI()
	}

	for _, l := range comp.Licenses {
		c.Licenses = append(c.Licenses, &cyclonedxLicense{
			License: &cyclonedxLicenseChoice{
				ID:   l.SPDXID,
				Name: l.Name,
				URL:  l.URL,
			},
		})
	}

	for alg, val := range comp.Hashes {
		c.Hashes = append(c.Hashes, &cyclonedxHash{
			Alg:     alg,
			Content: val,
		})
	}

	if comp.Supplier != "" {
		c.Supplier = &cyclonedxOrganizationalEntity{Name: comp.Supplier}
	}

	for k, v := range comp.Properties {
		c.Properties = append(c.Properties, &cyclonedxProperty{
			Name:  k,
			Value: v,
		})
	}

	for _, r := range comp.ExternalReferences {
		c.ExternalReferences = append(c.ExternalReferences, &cyclonedxExtRef{
			Type:    r.Type,
			URL:     r.URL,
			Comment: r.Comment,
		})
	}

	return c
}

// parseCycloneDXTimestamp 解析 CycloneDX 时间戳
func parseCycloneDXTimestamp(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}
	layouts := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05-07:00",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, ts); err == nil {
			return t
		}
	}
	return time.Time{}
}

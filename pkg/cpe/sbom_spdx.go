package cpeskills

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// spdxDocument SPDX 2.3 JSON 原始结构
type spdxDocument struct {
	SPDXID          string             `json:"SPDXID"`
	SPDXVersion     string             `json:"spdxVersion"`
	Name            string             `json:"name"`
	DataLicense     string             `json:"dataLicense"`
	DocumentDescribes []string         `json:"documentDescribes,omitempty"`
	CreationInfo    *spdxCreationInfo  `json:"creationInfo"`
	Packages        []*spdxPackage     `json:"packages,omitempty"`
	Relationships   []*spdxRelationship `json:"relationships,omitempty"`
	HasExtractedLicensingInfos []*spdxExtractedLicense `json:"hasExtractedLicensingInfos,omitempty"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID               string                    `json:"SPDXID"`
	Name                 string                    `json:"name"`
	VersionInfo          string                    `json:"versionInfo,omitempty"`
	PackageFileName      string                    `json:"packageFileName,omitempty"`
	Supplier             string                    `json:"supplier,omitempty"`
	DownloadLocation     string                    `json:"downloadLocation"`
	FilesAnalyzed        bool                      `json:"filesAnalyzed"`
	Checksums            []*spdxChecksum           `json:"checksums,omitempty"`
	ExternalRefs         []*spdxExternalRef        `json:"externalRefs,omitempty"`
	LicenseConcluded     string                    `json:"licenseConcluded"`
	LicenseDeclared      string                    `json:"licenseDeclared"`
	CopyrightText        string                    `json:"copyrightText"`
	Description          string                    `json:"description,omitempty"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

type spdxExtractedLicense struct {
	LicenseID    string `json:"licenseId"`
	ExtractedText string `json:"extractedText"`
}

// ParseSPDXJSON 解析 SPDX JSON 格式的 SBOM
func ParseSPDXJSON(data []byte) (*SBOM, error) {
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse SPDX JSON: %w", err)
	}

	sbom := NewSBOM(SBOMFormatSPDX, doc.Name)
	sbom.SpecVersion = doc.SPDXVersion

	// 解析创建信息
	if doc.CreationInfo != nil {
		sbom.Metadata.Timestamp = parseSPDXTimestamp(doc.CreationInfo.Created)
		for _, c := range doc.CreationInfo.Creators {
			parts := strings.SplitN(c, ": ", 2)
			if len(parts) == 2 {
				sbom.Metadata.Authors = append(sbom.Metadata.Authors, &SBOMAuthor{
					Name: parts[1],
				})
			}
		}
	}

	// 记录创建工具
	sbom.Metadata.Tools = append(sbom.Metadata.Tools, &SBOMTool{
		Name:    "SPDX Document",
		Version: doc.SPDXVersion,
	})

	// 构建包 ID → BomRef 映射
	idToRef := make(map[string]string)
	refToID := make(map[string]string)

	// 解析包（作为组件）
	for i, pkg := range doc.Packages {
		comp := convertSPDXPackageToComponent(pkg)
		if comp.BomRef == "" {
			comp.BomRef = fmt.Sprintf("pkg-%d", i)
		}
		idToRef[pkg.SPDXID] = comp.BomRef
		refToID[comp.BomRef] = pkg.SPDXID
		sbom.AddComponent(comp)
	}

	// 解析依赖关系
	for _, rel := range doc.Relationships {
		if rel.RelationshipType == "DEPENDS_ON" {
			ref, ok := idToRef[rel.SPDXElementID]
			if !ok {
				continue
			}
			depRef, ok := idToRef[rel.RelatedSPDXElement]
			if !ok {
				continue
			}
			sbom.AddDependency(ref, []string{depRef})
		}
	}

	return sbom, nil
}

// ToSPDXJSON 将 SBOM 导出为 SPDX JSON 格式
func (s *SBOM) ToSPDXJSON() ([]byte, error) {
	doc := &spdxDocument{
		SPDXID:       "SPDXRef-DOCUMENT",
		SPDXVersion:  s.SpecVersion,
		Name:         s.Name,
		DataLicense:  "CC0-1.0",
		CreationInfo: &spdxCreationInfo{
			Created:  time.Now().Format("2006-01-02T15:04:05Z"),
			Creators: []string{"Organization: cpe-skills", "Tool: cpe-skills-sbom"},
		},
	}

	// 转换组件为包
	for _, comp := range s.Components {
		pkg := convertComponentToSPDXPackage(comp)
		doc.Packages = append(doc.Packages, pkg)
	}

	// 转换依赖关系
	for _, dep := range s.Dependencies {
		rel := &spdxRelationship{
			SPDXElementID:      dep.Ref,
			RelatedSPDXElement: dep.DependsOn[0],
			RelationshipType:   "DEPENDS_ON",
		}
		doc.Relationships = append(doc.Relationships, rel)
	}

	// 设置文档描述的顶层包
	for _, pkg := range doc.Packages {
		doc.DocumentDescribes = append(doc.DocumentDescribes, pkg.SPDXID)
	}

	return json.MarshalIndent(doc, "", "  ")
}

// convertSPDXPackageToComponent 将 SPDX 包转换为 SBOM 组件
func convertSPDXPackageToComponent(pkg *spdxPackage) *SBOMComponent {
	comp := &SBOMComponent{
		BomRef:      pkg.SPDXID,
		Type:        "library",
		Name:        pkg.Name,
		Version:     pkg.VersionInfo,
		Description: pkg.Description,
		Supplier:    parseSPDXSupplier(pkg.Supplier),
		Hashes:      make(map[string]string),
		Properties:  make(map[string]string),
	}

	// 解析哈希值
	for _, cs := range pkg.Checksums {
		comp.Hashes[strings.ToLower(cs.Algorithm)] = cs.ChecksumValue
	}

	// 解析外部参考（PURL 和 CPE）
	for _, ref := range pkg.ExternalRefs {
		switch ref.ReferenceType {
		case "purl":
			if purl, err := ParsePURL(ref.ReferenceLocator); err == nil {
				comp.PURL = purl
			}
		case "cpe23Type", "cpe22Type":
			if cpe, err := Parse(ref.ReferenceLocator); err == nil {
				comp.CPE = cpe
			}
		}
	}

	// 解析许可证
	if pkg.LicenseDeclared != "" && pkg.LicenseDeclared != "NOASSERTION" && pkg.LicenseDeclared != "NONE" {
		license := parseSPDXLicenseIdentifier(pkg.LicenseDeclared)
		comp.Licenses = append(comp.Licenses, license)
	}

	return comp
}

// convertComponentToSPDXPackage 将 SBOM 组件转换为 SPDX 包
func convertComponentToSPDXPackage(comp *SBOMComponent) *spdxPackage {
	spdxID := comp.BomRef
	if spdxID == "" {
		spdxID = fmt.Sprintf("SPDXRef-%s", comp.Name)
	}

	pkg := &spdxPackage{
		SPDXID:           spdxID,
		Name:             comp.Name,
		VersionInfo:      comp.Version,
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		Description:      comp.Description,
	}

	if comp.Supplier != "" {
		pkg.Supplier = fmt.Sprintf("Organization: %s", comp.Supplier)
	}

	// 转换哈希值
	for alg, val := range comp.Hashes {
		pkg.Checksums = append(pkg.Checksums, &spdxChecksum{
			Algorithm:     alg,
			ChecksumValue: val,
		})
	}

	// 添加 PURL 外部参考
	if comp.PURL != nil && comp.PURL.IsValid() {
		pkg.ExternalRefs = append(pkg.ExternalRefs, &spdxExternalRef{
			ReferenceCategory: "PACKAGE-MANAGER",
			ReferenceType:     "purl",
			ReferenceLocator:  comp.PURL.String(),
		})
	}

	// 添加 CPE 外部参考
	if comp.CPE != nil {
		pkg.ExternalRefs = append(pkg.ExternalRefs, &spdxExternalRef{
			ReferenceCategory: "SECURITY",
			ReferenceType:     "cpe23Type",
			ReferenceLocator:  comp.CPE.GetURI(),
		})
	}

	// 设置许可证
	if len(comp.Licenses) > 0 {
		licenseIDs := make([]string, 0, len(comp.Licenses))
		for _, l := range comp.Licenses {
			licenseIDs = append(licenseIDs, l.SPDXID)
		}
		pkg.LicenseDeclared = strings.Join(licenseIDs, " AND ")
		pkg.LicenseConcluded = pkg.LicenseDeclared
	} else {
		pkg.LicenseDeclared = "NOASSERTION"
		pkg.LicenseConcluded = "NOASSERTION"
	}

	pkg.CopyrightText = "NOASSERTION"

	return pkg
}

// parseSPDXTimestamp 解析 SPDX 时间戳
func parseSPDXTimestamp(ts string) time.Time {
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

// parseSPDXSupplier 解析 SPDX 供应商字符串
func parseSPDXSupplier(supplier string) string {
	if supplier == "" || supplier == "NOASSERTION" {
		return ""
	}
	// 格式: "Organization: Name" 或 "Person: Name"
	parts := strings.SplitN(supplier, ": ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return supplier
}

// parseSPDXLicenseIdentifier 解析 SPDX 许可证标识符
func parseSPDXLicenseIdentifier(id string) *License {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	// 处理复合许可证表达式（取第一个）
	if strings.Contains(id, " AND ") {
		ids := strings.Split(id, " AND ")
		id = strings.TrimSpace(ids[0])
	} else if strings.Contains(id, " OR ") {
		ids := strings.Split(id, " OR ")
		id = strings.TrimSpace(ids[0])
	}

	return &License{
		SPDXID: id,
		Name:   id,
	}
}

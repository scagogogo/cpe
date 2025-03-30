package cpe

import (
	"strings"
	"time"
)

// CVEReference 表示一个CVE安全漏洞
type CVEReference struct {
	// CVEID 是CVE的唯一标识符，例如 CVE-2021-44228
	CVEID string

	// Description 是CVE的描述
	Description string

	// PublishedDate 是CVE发布日期
	PublishedDate time.Time

	// LastModifiedDate 是CVE最后修改日期
	LastModifiedDate time.Time

	// CVSSScore 是CVE的CVSS评分 (0.0-10.0)
	CVSSScore float64

	// Severity 是CVE的严重性级别 (Low, Medium, High, Critical)
	Severity string

	// References 是CVE的参考链接
	References []string

	// AffectedCPEs 是受影响的CPE URI列表
	AffectedCPEs []string

	// Metadata 是CVE的额外元数据
	Metadata map[string]interface{}
}

// NewCVEReference 创建一个新的CVE引用
func NewCVEReference(cveID string) *CVEReference {
	return &CVEReference{
		CVEID:            cveID,
		References:       []string{},
		AffectedCPEs:     []string{},
		Metadata:         make(map[string]interface{}),
		PublishedDate:    time.Now(),
		LastModifiedDate: time.Now(),
	}
}

// AddAffectedCPE 添加一个受影响的CPE
func (cve *CVEReference) AddAffectedCPE(cpeURI string) {
	// 检查CPE是否已存在
	for _, existingCPE := range cve.AffectedCPEs {
		if existingCPE == cpeURI {
			return
		}
	}

	cve.AffectedCPEs = append(cve.AffectedCPEs, cpeURI)
	cve.LastModifiedDate = time.Now()
}

// RemoveAffectedCPE 移除一个受影响的CPE
func (cve *CVEReference) RemoveAffectedCPE(cpeURI string) bool {
	for i, existingCPE := range cve.AffectedCPEs {
		if existingCPE == cpeURI {
			// 移除元素
			cve.AffectedCPEs = append(cve.AffectedCPEs[:i], cve.AffectedCPEs[i+1:]...)
			cve.LastModifiedDate = time.Now()
			return true
		}
	}
	return false
}

// AddReference 添加一个参考链接
func (cve *CVEReference) AddReference(reference string) {
	// 检查参考链接是否已存在
	for _, existingRef := range cve.References {
		if existingRef == reference {
			return
		}
	}

	cve.References = append(cve.References, reference)
	cve.LastModifiedDate = time.Now()
}

// SetSeverity 设置CVE的严重性级别
func (cve *CVEReference) SetSeverity(cvssScore float64) {
	cve.CVSSScore = cvssScore

	// 根据CVSS评分设置严重性级别
	switch {
	case cvssScore >= 9.0:
		cve.Severity = "Critical"
	case cvssScore >= 7.0:
		cve.Severity = "High"
	case cvssScore >= 4.0:
		cve.Severity = "Medium"
	default:
		cve.Severity = "Low"
	}

	cve.LastModifiedDate = time.Now()
}

// SetMetadata 设置元数据
func (cve *CVEReference) SetMetadata(key string, value interface{}) {
	cve.Metadata[key] = value
	cve.LastModifiedDate = time.Now()
}

// GetMetadata 获取元数据
func (cve *CVEReference) GetMetadata(key string) (interface{}, bool) {
	value, exists := cve.Metadata[key]
	return value, exists
}

// RemoveMetadata 移除元数据
func (cve *CVEReference) RemoveMetadata(key string) bool {
	_, exists := cve.Metadata[key]
	if exists {
		delete(cve.Metadata, key)
		cve.LastModifiedDate = time.Now()
		return true
	}
	return false
}

// QueryByCVE 根据CVE查询上面绑定的CPE
// 参数cve：CVE ID，如"CVE-2021-44228"
// 返回与此CVE关联的所有CPE
func QueryByCVE(cves []*CVEReference, cveID string) []*CPE {
	var result []*CPE

	// 标准化CVE ID格式
	cveID = standardizeCVEID(cveID)

	// 查找匹配的CVE
	for _, cve := range cves {
		if cve.CVEID == cveID {
			// 对于每个受影响的产品，创建一个CPE对象
			for _, cpeString := range cve.AffectedCPEs {
				if strings.HasPrefix(cpeString, "cpe:2.3:") {
					// 解析CPE 2.3格式
					cpe, err := ParseCpe23(cpeString)
					if err == nil {
						cpe.Cve = cveID
						result = append(result, cpe)
					}
				} else if strings.HasPrefix(cpeString, "cpe:/") {
					// 解析CPE 2.2格式
					cpe, err := ParseCpe22(cpeString)
					if err == nil {
						cpe.Cve = cveID
						result = append(result, cpe)
					}
				}
			}
			break
		}
	}

	return result
}

// standardizeCVEID 标准化CVE ID格式
// 例如: "cve-2021-44228" -> "CVE-2021-44228"
func standardizeCVEID(cveID string) string {
	// 转为大写
	cveID = strings.ToUpper(cveID)

	// 确保使用正确的格式 CVE-YYYY-NNNNN
	if !strings.HasPrefix(cveID, "CVE-") {
		if strings.HasPrefix(cveID, "CVE") {
			cveID = "CVE-" + cveID[3:]
		}
	}

	return cveID
}

// GetCVEInfo 获取CVE详细信息
func GetCVEInfo(cves []*CVEReference, cveID string) *CVEReference {
	cveID = standardizeCVEID(cveID)

	for _, cve := range cves {
		if cve.CVEID == cveID {
			return cve
		}
	}

	return nil
}

// QueryByProduct 根据产品信息查询相关CVE
// 返回可能影响指定产品的所有CVE信息
func QueryByProduct(cves []*CVEReference, vendor, product string, version string) []*CVEReference {
	var results []*CVEReference

	for _, cve := range cves {
		for _, cpeString := range cve.AffectedCPEs {
			// 首先尝试解析CPE
			var cpe *CPE
			var err error

			if strings.HasPrefix(cpeString, "cpe:2.3:") {
				cpe, err = ParseCpe23(cpeString)
			} else if strings.HasPrefix(cpeString, "cpe:/") {
				cpe, err = ParseCpe22(cpeString)
			} else {
				continue
			}

			if err != nil {
				continue
			}

			// 检查是否匹配产品条件
			vendorMatch := vendor == "" || strings.EqualFold(string(cpe.Vendor), vendor)
			productMatch := product == "" || strings.EqualFold(string(cpe.ProductName), product)
			versionMatch := version == "" || string(cpe.Version) == version || string(cpe.Version) == "*"

			if vendorMatch && productMatch && versionMatch {
				results = append(results, cve)
				break // 找到一个匹配项即可，避免重复添加同一个CVE
			}
		}
	}

	return results
}

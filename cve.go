package cpe

import (
	"strings"
	"time"

	"github.com/scagogogo/cve"
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
// 输入:
//   - cveID: string 类型，CVE的唯一标识符，例如 "CVE-2021-44228"
//
// 输出:
//   - *CVEReference: 返回初始化的CVE引用对象，包含空的References和AffectedCPEs切片，
//     以及初始化的Metadata映射，PublishedDate和LastModifiedDate设置为当前时间
//
// 示例:
//
//	cve := NewCVEReference("CVE-2021-44228")
//	cve.Description = "Log4j远程代码执行漏洞"
//	cve.SetSeverity(10.0) // 设置为Critical级别
func NewCVEReference(cveID string) *CVEReference {
	// 使用cve库格式化输入的CVE ID
	formattedCVEID := cve.Format(cveID)

	return &CVEReference{
		CVEID:            formattedCVEID,
		References:       []string{},
		AffectedCPEs:     []string{},
		Metadata:         make(map[string]interface{}),
		PublishedDate:    time.Now(),
		LastModifiedDate: time.Now(),
	}
}

// AddAffectedCPE 添加一个受影响的CPE
// 输入:
//   - cpeURI: string 类型，要添加的CPE URI，支持CPE 2.2格式(cpe:/)或CPE 2.3格式(cpe:2.3:)
//     例如："cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*" 或 "cpe:/a:apache:log4j:2.0"
//
// 输出:
//   - 无返回值，直接修改CVEReference对象
//
// 行为:
//   - 如果CPE已存在于AffectedCPEs列表中，则不会重复添加
//   - 添加CPE后，会自动更新LastModifiedDate为当前时间
//
// 示例:
//
//	cve := NewCVEReference("CVE-2021-44228")
//	cve.AddAffectedCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
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
// 输入:
//   - cpeURI: string 类型，要移除的CPE URI
//
// 输出:
//   - bool: 移除操作是否成功
//     true - 找到并移除了指定的CPE
//     false - 未找到指定的CPE，无需移除
//
// 行为:
//   - 成功移除CPE后，会自动更新LastModifiedDate为当前时间
//   - 如果移除成功，受影响的CPE列表长度将减少1
//
// 示例:
//
//	cve := NewCVEReference("CVE-2021-44228")
//	cve.AddAffectedCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
//	removed := cve.RemoveAffectedCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*") // 返回 true
//	notRemoved := cve.RemoveAffectedCPE("cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*") // 返回 false
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
// 输入:
//   - reference: string 类型，要添加的参考链接URL或其他引用
//     例如："https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
//
// 输出:
//   - 无返回值，直接修改CVEReference对象
//
// 行为:
//   - 如果参考链接已存在于References列表中，则不会重复添加
//   - 添加链接后，会自动更新LastModifiedDate为当前时间
//
// 示例:
//
//	cve := NewCVEReference("CVE-2021-44228")
//	cve.AddReference("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")
//	cve.AddReference("https://www.cve.org/CVERecord?id=CVE-2021-44228")
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
// 输入:
//   - cvssScore: float64 类型，CVE的CVSS评分，取值范围为0.0-10.0
//
// 输出:
//   - 无返回值，直接修改CVEReference对象的CVSSScore和Severity字段
//
// 行为:
//   - 根据CVSS评分自动设置对应的严重性级别:
//   - 9.0-10.0: "Critical" (危急)
//   - 7.0-8.9:  "High"     (高危)
//   - 4.0-6.9:  "Medium"   (中危)
//   - 0.0-3.9:  "Low"      (低危)
//   - 设置后，会自动更新LastModifiedDate为当前时间
//
// 示例:
//
//	cve := NewCVEReference("CVE-2021-44228")
//	cve.SetSeverity(10.0) // 设置为Critical级别
//	cve.SetSeverity(5.5)  // 设置为Medium级别
//	cve.SetSeverity(2.0)  // 设置为Low级别
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
// 输入:
//   - key: string 类型，元数据的键名
//   - value: interface{} 类型，元数据的值，可以是任意类型
//
// 输出:
//   - 无返回值，直接修改CVEReference对象的Metadata映射
//
// 行为:
//   - 如果键已存在，将覆盖原有值
//   - 设置后，会自动更新LastModifiedDate为当前时间
//
// 示例:
//
//	cve := NewCVEReference("CVE-2021-44228")
//	cve.SetMetadata("exploitAvailable", true)
//	cve.SetMetadata("patchDate", "2021-12-10")
//	cve.SetMetadata("affectedVersions", []string{"2.0", "2.1", "2.2"})
func (cve *CVEReference) SetMetadata(key string, value interface{}) {
	cve.Metadata[key] = value
	cve.LastModifiedDate = time.Now()
}

// GetMetadata 获取元数据
// 输入:
//   - key: string 类型，要获取的元数据键名
//
// 输出:
//   - interface{}: 返回与键关联的值，如果键不存在则为nil
//   - bool: 指示键是否存在
//     true - 键存在
//     false - 键不存在
//
// 示例:
//
//	cve := NewCVEReference("CVE-2021-44228")
//	cve.SetMetadata("exploitAvailable", true)
//
//	value, exists := cve.GetMetadata("exploitAvailable")
//	if exists {
//	  isExploitable := value.(bool) // 将返回true
//	}
//
//	_, notExists := cve.GetMetadata("nonExistentKey")
//	// notExists将为false
func (cve *CVEReference) GetMetadata(key string) (interface{}, bool) {
	value, exists := cve.Metadata[key]
	return value, exists
}

// RemoveMetadata 移除元数据
// 输入:
//   - key: string 类型，要移除的元数据键名
//
// 输出:
//   - bool: 移除操作是否成功
//     true - 键存在并被成功移除
//     false - 键不存在，无需移除
//
// 行为:
//   - 成功移除元数据后，会自动更新LastModifiedDate为当前时间
//
// 示例:
//
//	cve := NewCVEReference("CVE-2021-44228")
//	cve.SetMetadata("exploitAvailable", true)
//
//	removed := cve.RemoveMetadata("exploitAvailable") // 返回true
//	notRemoved := cve.RemoveMetadata("nonExistentKey") // 返回false
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
// 输入:
//   - cves: []*CVEReference 类型，CVE引用对象的切片
//   - cveID: string 类型，CVE ID，例如"CVE-2021-44228"，不区分大小写，格式会被标准化
//
// 输出:
//   - []*CPE: 返回与指定CVE关联的所有CPE对象的切片
//
// 行为:
//   - 会使用github.com/scagogogo/cve库标准化CVE ID的格式
//   - 解析每个匹配CVE的所有受影响CPE，并将CVE信息关联到CPE对象
//   - 支持解析CPE 2.2和CPE 2.3格式
//
// 数据样例:
//
//	输入CVE列表: [
//	  {CVEID: "CVE-2021-44228", AffectedCPEs: ["cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"]},
//	  {CVEID: "CVE-2022-12345", AffectedCPEs: ["cpe:/a:vendor:product:1.0"]}
//	]
//	输入cveID: "CVE-2021-44228"
//
//	返回: [
//	  {Part:"a", Vendor:"apache", ProductName:"log4j", Version:"2.0", Cve:"CVE-2021-44228", ...},
//	]
//
// 示例:
//
//	cves := []*CVEReference{...} // 从数据源加载的CVE列表
//	cpes := QueryByCVE(cves, "CVE-2021-44228")
//	for _, cpe := range cpes {
//	  fmt.Printf("受影响产品: %s %s %s\n", cpe.Vendor, cpe.ProductName, cpe.Version)
//	}
func QueryByCVE(cves []*CVEReference, cveID string) []*CPE {
	var result []*CPE

	// 标准化CVE ID格式
	cveID = cve.Format(cveID)

	// 查找匹配的CVE
	for _, cve := range cves {
		if cve.CVEID == cveID {
			// 对于每个受影响的产品，创建一个CPE对象
			for _, cpeString := range cve.AffectedCPEs {
				// 判断CPE字符串格式并进行相应解析
				// CPE (Common Platform Enumeration) 是一种标准化的方法，用于识别IT系统、软件和软件包
				if strings.HasPrefix(cpeString, "cpe:2.3:") {
					// 处理CPE 2.3格式 (形如 "cpe:2.3:a:vendor:product:version:...")
					// 这是较新的URI绑定格式，使用冒号分隔各个组件
					cpe, err := ParseCpe23(cpeString)
					if err == nil {
						cpe.Cve = cveID
						result = append(result, cpe)
					}
				} else if strings.HasPrefix(cpeString, "cpe:/") {
					// 处理CPE 2.2格式 (形如 "cpe:/a:vendor:product:version:...")
					// 这是较旧的格式，以斜杠开头，使用冒号分隔各个组件
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

// GetCVEInfo 获取CVE详细信息
// 输入:
//   - cves: []*CVEReference 类型，CVE引用对象的切片
//   - cveID: string 类型，待查询的CVE ID，不区分大小写，格式会被标准化
//
// 输出:
//   - *CVEReference: 返回匹配的CVE引用对象，如果未找到则返回nil
//
// 行为:
//   - 会使用github.com/scagogogo/cve库标准化CVE ID的格式
//   - 从CVE列表中查找完全匹配的CVE ID
//
// 示例:
//
//	cves := []*CVEReference{...} // 从数据源加载的CVE列表
//	cve := GetCVEInfo(cves, "CVE-2021-44228")
//	if cve != nil {
//	  fmt.Printf("CVE描述: %s\n", cve.Description)
//	  fmt.Printf("严重级别: %s (CVSS: %.1f)\n", cve.Severity, cve.CVSSScore)
//	} else {
//	  fmt.Println("未找到指定的CVE")
//	}
func GetCVEInfo(cves []*CVEReference, cveID string) *CVEReference {
	cveID = cve.Format(cveID)

	for _, c := range cves {
		if c.CVEID == cveID {
			return c
		}
	}

	return nil
}

// ExtractCVEsFromText 从文本中提取所有CVE ID
// 输入:
//   - text: string 类型，可能包含CVE ID的文本内容
//
// 输出:
//   - []string: 返回从文本中提取的所有唯一的、格式化的CVE ID
//
// 行为:
//   - 使用github.com/scagogogo/cve库的ExtractCve函数提取文本中的所有CVE ID
//   - 自动标准化提取的CVE ID格式
//   - 提取结果已去重
//
// 示例:
//
//	text := "系统受到CVE-2021-44228和cve-2022-12345漏洞的影响"
//	cveIDs := ExtractCVEsFromText(text)
//	// 返回 ["CVE-2021-44228", "CVE-2022-12345"]
func ExtractCVEsFromText(text string) []string {
	return cve.ExtractCve(text)
}

// GroupCVEsByYear 按年份对CVE ID进行分组
// 输入:
//   - cveIDs: []string 类型，CVE ID列表
//
// 输出:
//   - map[string][]string: 返回以年份为键、对应年份CVE列表为值的映射
//
// 行为:
//   - 使用github.com/scagogogo/cve库的GroupByYear函数按年份对CVE ID进行分组
//   - 支持标准化的CVE ID格式
//
// 示例:
//
//	cveIDs := []string{"CVE-2021-44228", "CVE-2022-12345", "CVE-2021-45046"}
//	groupedCVEs := GroupCVEsByYear(cveIDs)
//	// 返回:
//	// {
//	//   "2021": ["CVE-2021-44228", "CVE-2021-45046"],
//	//   "2022": ["CVE-2022-12345"]
//	// }
func GroupCVEsByYear(cveIDs []string) map[string][]string {
	return cve.GroupByYear(cveIDs)
}

// SortCVEs 对CVE ID列表进行排序
// 输入:
//   - cveIDs: []string 类型，CVE ID列表
//
// 输出:
//   - []string: 返回排序后的CVE ID列表
//
// 行为:
//   - 使用github.com/scagogogo/cve库的SortCves函数对CVE ID列表进行排序
//   - 排序规则：先按年份排序，然后按序列号排序
//
// 示例:
//
//	cveIDs := []string{"CVE-2022-12345", "CVE-2021-44228", "CVE-2021-0001"}
//	sortedCVEs := SortCVEs(cveIDs)
//	// 返回 ["CVE-2021-0001", "CVE-2021-44228", "CVE-2022-12345"]
func SortCVEs(cveIDs []string) []string {
	return cve.SortCves(cveIDs)
}

// RemoveDuplicateCVEs 去除CVE ID列表中的重复项
// 输入:
//   - cveIDs: []string 类型，可能包含重复项的CVE ID列表
//
// 输出:
//   - []string: 返回去重后的CVE ID列表
//
// 行为:
//   - 使用github.com/scagogogo/cve库的RemoveDuplicateCves函数去除重复项
//   - 标准化所有CVE ID格式
//
// 示例:
//
//	cveIDs := []string{"CVE-2021-44228", "cve-2021-44228", "CVE-2022-12345"}
//	uniqueCVEs := RemoveDuplicateCVEs(cveIDs)
//	// 返回 ["CVE-2021-44228", "CVE-2022-12345"]
func RemoveDuplicateCVEs(cveIDs []string) []string {
	return cve.RemoveDuplicateCves(cveIDs)
}

// GetRecentCVEs 获取最近N年的CVE ID
// 输入:
//   - cveIDs: []string 类型，CVE ID列表
//   - years: int 类型，年份范围，如2表示最近2年
//
// 输出:
//   - []string: 返回最近N年的CVE ID列表
//
// 行为:
//   - 使用github.com/scagogogo/cve库的GetRecentCves函数筛选最近N年的CVE
//
// 示例:
//
//	cveIDs := []string{"CVE-2021-44228", "CVE-2018-12345", "CVE-2022-56789"}
//	recentCVEs := GetRecentCVEs(cveIDs, 2) // 假设当前是2023年
//	// 返回 ["CVE-2021-44228", "CVE-2022-56789"]
func GetRecentCVEs(cveIDs []string, years int) []string {
	return cve.GetRecentCves(cveIDs, years)
}

// ValidateCVE 验证CVE ID是否有效
// 输入:
//   - cveID: string 类型，待验证的CVE ID
//
// 输出:
//   - bool: 返回CVE ID是否有效
//
// 行为:
//   - 使用github.com/scagogogo/cve库的ValidateCve函数验证CVE ID
//   - 验证包括格式和年份有效性检查
//
// 示例:
//
//	isValid := ValidateCVE("CVE-2021-44228") // 返回true
//	isValid := ValidateCVE("CVE-2099-12345") // 返回false (年份超前)
//	isValid := ValidateCVE("CVE2021-44228")  // 返回false (格式错误)
func ValidateCVE(cveID string) bool {
	return cve.ValidateCve(cveID)
}

// QueryByProduct 根据产品信息查询相关CVE
// 输入:
//   - cves: []*CVEReference 类型，CVE引用对象的切片
//   - vendor: string 类型，供应商名称，不区分大小写，空字符串表示匹配任何供应商
//   - product: string 类型，产品名称，不区分大小写，空字符串表示匹配任何产品
//   - version: string 类型，产品版本，区分大小写，空字符串表示匹配任何版本，"*"也表示任何版本
//
// 输出:
//   - []*CVEReference: 返回匹配的CVE引用对象的切片
//
// 行为:
//   - 解析每个CVE的受影响CPE列表
//   - 支持解析CPE 2.2和CPE 2.3格式
//   - 根据供应商、产品名和版本进行匹配过滤
//   - 对于每个CVE，一旦发现一个匹配的CPE，便立即添加到结果中并跳过该CVE的其余CPE，避免重复
//   - 匹配时vendor和product不区分大小写，但version区分大小写
//   - 使用scagogogo/cve库对CVE ID进行标准化和验证
//
// 示例:
//
//	cves := []*CVEReference{...} // 从数据源加载的CVE列表
//
//	// 查找影响Apache Log4j的所有CVE
//	apacheLog4jCVEs := QueryByProduct(cves, "apache", "log4j", "")
//
//	// 查找影响特定版本的CVE
//	versionCVEs := QueryByProduct(cves, "apache", "log4j", "2.0")
//
//	// 查找特定供应商的所有产品漏洞
//	vendorCVEs := QueryByProduct(cves, "apache", "", "")
func QueryByProduct(cves []*CVEReference, vendor, product string, version string) []*CVEReference {
	var results []*CVEReference

	for _, cveRef := range cves {
		// 确保CVEID是标准格式
		cveRef.CVEID = cve.Format(cveRef.CVEID)

		for _, cpeString := range cveRef.AffectedCPEs {
			// 首先尝试解析CPE
			var cpe *CPE
			var err error

			// 判断CPE字符串格式并进行相应解析
			if strings.HasPrefix(cpeString, "cpe:2.3:") {
				// 处理CPE 2.3格式
				cpe, err = ParseCpe23(cpeString)
			} else if strings.HasPrefix(cpeString, "cpe:/") {
				// 处理CPE 2.2格式
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
				results = append(results, cveRef)
				break // 找到一个匹配项即可，避免重复添加同一个CVE
			}
		}
	}

	return results
}

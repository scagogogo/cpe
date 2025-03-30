package cpe

import (
	"strings"
)

/**
 * CPE 表示Common Platform Enumeration结构体，用于标识IT产品、系统和软件包
 *
 * CPE是一种标准化方法，用于描述和识别运行在企业系统上的应用程序、操作系统和硬件设备类型。
 * 支持CPE 2.2和2.3两种格式规范，包含各种属性如供应商、产品名称、版本等。
 *
 * 示例:
 *   ```go
 *   // 创建一个表示Windows 10的CPE
 *   windowsCPE := &cpe.CPE{
 *       Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
 *       Part:        *cpe.PartApplication,
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("windows"),
 *       Version:     cpe.Version("10"),
 *   }
 *
 *   // 或者使用解析函数创建
 *   windowsCPE, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
 *   if err != nil {
 *       log.Fatalf("解析CPE失败: %v", err)
 *   }
 *   ```
 */
type CPE struct {

	// CPE 2.3格式的完整字符串，例如"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
	Cpe23 string `json:"cpe_23" bson:"cpe_23"`

	// 组件类型，可以是应用(a)、硬件(h)或操作系统(o)
	Part Part `json:"part" bson:"part"`

	// 供应商名称，如"microsoft"、"adobe"等
	Vendor Vendor `json:"vendor" bson:"vendor"`

	// 产品名称，如"windows"、"acrobat_reader"等
	ProductName Product `json:"product_name" bson:"product_name"`

	// 产品版本号，如"10"、"2021.001.20150"等
	Version Version `json:"version" bson:"version"`

	// 更新标识符，通常是特定版本的更新或补丁级别
	Update Update `json:"update" bson:"update"`

	// 特定版本的版本类型
	Edition Edition `json:"edition" bson:"edition"`

	// 语言标识符
	Language Language `json:"language" bson:"language"`

	// 软件版本，如"professional"、"enterprise"等
	SoftwareEdition string `json:"software_edition" bson:"software_edition"`

	// 目标软件环境
	TargetSoftware string `json:"target_software" bson:"target_software"`

	// 目标硬件环境
	TargetHardware string `json:"target_hardware" bson:"target_hardware"`

	// 其他属性
	Other string `json:"other" bson:"other"`

	// 关联的CVE编号，表示此CPE受影响的漏洞
	Cve string `json:"cve" bson:"cve"`

	// 此CPE信息的来源URL
	Url string `json:"url" bson:"url"`
}

// 判断当前CPE是否匹配另一个CPE
// 根据CPE Name Matching规范实现
// 返回true表示匹配，false表示不匹配
/**
 * Match 判断当前CPE是否匹配另一个CPE
 *
 * 根据CPE名称匹配规范实现，对比两个CPE对象的各属性是否匹配。
 * 匹配规则考虑了通配符"*"和不适用标记"-"的特殊语义。
 *
 * @param other 要与当前CPE进行匹配的目标CPE对象
 * @return bool 如果匹配返回true，否则返回false
 *
 * 匹配规则:
 *   1. 相同CPE URI直接返回true
 *   2. Part必须完全匹配
 *   3. 其他属性依次匹配，任一不匹配则返回false
 *   4. 属性匹配时遵循特殊规则:
 *      - 任一方是通配符"*"，则匹配
 *      - 双方都是不适用"-"，则匹配
 *      - 否则需要完全相等
 *
 * 示例:
 *   ```go
 *   // 创建两个CPE对象
 *   windowsCPE, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
 *   windowsPattern, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*")
 *
 *   // 检查是否匹配
 *   if windowsPattern.Match(windowsCPE) {
 *       fmt.Println("Windows 10匹配通配模式")
 *   }
 *   // 输出: Windows 10匹配通配模式
 *
 *   // 不同Part不匹配
 *   osPattern, _ := cpe.ParseCpe23("cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*")
 *   if !osPattern.Match(windowsCPE) {
 *       fmt.Println("应用程序和操作系统不匹配")
 *   }
 *   // 输出: 应用程序和操作系统不匹配
 *   ```
 */
func (x *CPE) Match(other *CPE) bool {
	// 如果两个CPE一样，直接返回true
	if x.Cpe23 == other.Cpe23 {
		return true
	}

	// 必须Part一致
	if x.Part.ShortName != other.Part.ShortName {
		return false
	}

	// 检查Vendor
	if !matchAttribute(string(x.Vendor), string(other.Vendor)) {
		return false
	}

	// 检查Product
	if !matchAttribute(string(x.ProductName), string(other.ProductName)) {
		return false
	}

	// 检查Version
	if !matchAttribute(string(x.Version), string(other.Version)) {
		return false
	}

	// 检查Update
	if !matchAttribute(string(x.Update), string(other.Update)) {
		return false
	}

	// 检查Edition
	if !matchAttribute(string(x.Edition), string(other.Edition)) {
		return false
	}

	// 检查Language
	if !matchAttribute(string(x.Language), string(other.Language)) {
		return false
	}

	// 检查SoftwareEdition
	if !matchAttribute(x.SoftwareEdition, other.SoftwareEdition) {
		return false
	}

	// 检查TargetSoftware
	if !matchAttribute(x.TargetSoftware, other.TargetSoftware) {
		return false
	}

	// 检查TargetHardware
	if !matchAttribute(x.TargetHardware, other.TargetHardware) {
		return false
	}

	// 检查Other
	if !matchAttribute(x.Other, other.Other) {
		return false
	}

	return true
}

// 匹配两个属性值
// 根据CPE匹配规范，考虑通配符和特殊值
/**
 * matchAttribute 匹配两个CPE属性值
 *
 * 根据CPE规范的属性匹配规则，处理通配符和特殊值的情况。
 *
 * @param a 第一个属性值
 * @param b 第二个属性值
 * @return bool 如果属性值匹配返回true，否则返回false
 *
 * 匹配规则:
 *   1. 任一方是通配符"*"，则匹配
 *   2. 双方都是不适用"-"，则匹配
 *   3. 其他情况需要完全相等
 *
 * 示例:
 *   ```go
 *   // 通配符匹配任意值
 *   fmt.Println(cpe.matchAttribute("*", "windows"))   // 输出: true
 *   fmt.Println(cpe.matchAttribute("windows", "*"))   // 输出: true
 *
 *   // 两个不适用值匹配
 *   fmt.Println(cpe.matchAttribute("-", "-"))         // 输出: true
 *
 *   // 完全相等才匹配
 *   fmt.Println(cpe.matchAttribute("windows", "windows"))    // 输出: true
 *   fmt.Println(cpe.matchAttribute("windows", "linux"))      // 输出: false
 *   ```
 */
func matchAttribute(a, b string) bool {
	// 如果有一个是ANY (*), 则匹配
	if a == "*" || b == "*" {
		return true
	}

	// 如果两个值都是NA (-), 则匹配
	if a == "-" && b == "-" {
		return true
	}

	// 精确匹配
	return a == b
}

// GetURI 获取CPE的URI表示
/**
 * GetURI 获取CPE的标准URI表示
 *
 * 返回当前CPE的标准URI字符串表示形式，通常是CPE 2.3格式。
 * 如果CPE已有Cpe23字段值，则直接返回；否则通过FormatURI函数构建。
 *
 * @return string 返回CPE的URI字符串
 *
 * 示例:
 *   ```go
 *   // 创建一个CPE并获取其URI
 *   windowsCPE, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
 *   uri := windowsCPE.GetURI()
 *   fmt.Println("CPE URI:", uri)
 *   // 输出: CPE URI: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
 *
 *   // 用于存储和检索CPE
 *   storage, _ := cpe.NewFileStorage("/tmp/cpe-storage", true)
 *   err := storage.StoreCPE(windowsCPE)
 *   if err != nil {
 *       log.Fatalf("存储CPE失败: %v", err)
 *   }
 *
 *   // 之后可以用URI检索CPE
 *   retrievedCPE, _ := storage.RetrieveCPE(windowsCPE.GetURI())
 *   ```
 */
func (c *CPE) GetURI() string {
	return FormatURI(c)
}

// FormatURI 将CPE格式化为URI字符串
func FormatURI(cpe *CPE) string {
	if cpe == nil {
		return ""
	}

	// 如果已经有了Cpe23，直接返回
	if cpe.Cpe23 != "" {
		return cpe.Cpe23
	}

	// 构建CPE 2.3格式的URI
	parts := []string{
		"cpe:2.3",
		string(cpe.Part.ShortName),
		string(cpe.Vendor),
		string(cpe.ProductName),
		string(cpe.Version),
		string(cpe.Update),
		string(cpe.Edition),
		string(cpe.Language),
		cpe.SoftwareEdition,
		cpe.TargetSoftware,
		cpe.TargetHardware,
		cpe.Other,
	}

	return strings.Join(parts, ":")
}

// MatchCPE 判断两个CPE是否匹配
func MatchCPE(criteria *CPE, target *CPE, options *MatchOptions) bool {
	if criteria == nil || target == nil {
		return false
	}

	// 如果忽略版本，创建临时拷贝
	if options != nil && options.IgnoreVersion {
		criteriaCopy := *criteria
		targetCopy := *target

		// 设置版本为通配符，让匹配器忽略版本比较
		criteriaCopy.Version = "*"
		targetCopy.Version = "*"

		return criteriaCopy.Match(&targetCopy)
	}

	// 特殊处理不同产品名的情况，确保不会错误匹配
	if string(criteria.ProductName) != "" &&
		string(criteria.ProductName) != "*" &&
		string(target.ProductName) != "" &&
		string(target.ProductName) != "*" &&
		string(criteria.ProductName) != string(target.ProductName) {
		return false
	}

	// 使用现有的Match方法，它已经实现了CPE匹配逻辑
	return criteria.Match(target)
}

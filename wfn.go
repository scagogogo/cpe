package cpe

import (
	"fmt"
	"regexp"
	"strings"
)

// WFN (Well-Formed Name) 表示CPE的规范化内部表示
type WFN struct {
	Part            string
	Vendor          string
	Product         string
	Version         string
	Update          string
	Edition         string
	Language        string
	SoftwareEdition string
	TargetSoftware  string
	TargetHardware  string
	Other           string
}

// FromCPE 从CPE结构体创建WFN
func FromCPE(cpe *CPE) *WFN {
	return &WFN{
		Part:            cpe.Part.ShortName,
		Vendor:          string(cpe.Vendor),
		Product:         string(cpe.ProductName),
		Version:         string(cpe.Version),
		Update:          string(cpe.Update),
		Edition:         string(cpe.Edition),
		Language:        string(cpe.Language),
		SoftwareEdition: cpe.SoftwareEdition,
		TargetSoftware:  cpe.TargetSoftware,
		TargetHardware:  cpe.TargetHardware,
		Other:           cpe.Other,
	}
}

// ToCPE 转换WFN为CPE结构体
func (w *WFN) ToCPE() *CPE {
	cpe := &CPE{
		Vendor:          Vendor(w.Vendor),
		ProductName:     Product(w.Product),
		Version:         Version(w.Version),
		Update:          Update(w.Update),
		Edition:         Edition(w.Edition),
		Language:        Language(w.Language),
		SoftwareEdition: w.SoftwareEdition,
		TargetSoftware:  w.TargetSoftware,
		TargetHardware:  w.TargetHardware,
		Other:           w.Other,
	}

	// 设置Part
	switch w.Part {
	case "a":
		cpe.Part = *PartApplication
	case "h":
		cpe.Part = *PartHardware
	case "o":
		cpe.Part = *PartOperationSystem
	default:
		cpe.Part = *PartApplication
	}

	// 生成CPE 2.3格式字符串
	cpe.Cpe23 = w.ToCPE23String()

	return cpe
}

// FromCPE23String 从CPE 2.3格式字符串创建WFN
func FromCPE23String(cpe23 string) (*WFN, error) {
	// 移除cpe:2.3:前缀
	if !strings.HasPrefix(cpe23, "cpe:2.3:") {
		return nil, fmt.Errorf("invalid CPE 2.3 format: %s", cpe23)
	}

	parts := strings.Split(cpe23, ":")
	if len(parts) != 13 {
		return nil, fmt.Errorf("invalid CPE 2.3 format, expected 13 parts: %s", cpe23)
	}

	wfn := &WFN{
		Part:            parts[2],
		Vendor:          unescapeValue(parts[3]),
		Product:         unescapeValue(parts[4]),
		Version:         unescapeValue(parts[5]),
		Update:          unescapeValue(parts[6]),
		Edition:         unescapeValue(parts[7]),
		Language:        unescapeValue(parts[8]),
		SoftwareEdition: unescapeValue(parts[9]),
		TargetSoftware:  unescapeValue(parts[10]),
		TargetHardware:  unescapeValue(parts[11]),
		Other:           unescapeValue(parts[12]),
	}

	return wfn, nil
}

// FromCPE22String 从CPE 2.2格式字符串创建WFN
func FromCPE22String(cpe22 string) (*WFN, error) {
	// 转换成CPE 2.3格式，再解析
	cpe23 := convertCpe22ToCpe23(cpe22)
	return FromCPE23String(cpe23)
}

// ToCPE23String 转换WFN为CPE 2.3格式字符串
func (w *WFN) ToCPE23String() string {
	parts := []string{
		"cpe", "2.3",
		w.Part,
		escapeValue(w.Vendor),
		escapeValue(w.Product),
		escapeValue(w.Version),
		escapeValue(w.Update),
		escapeValue(w.Edition),
		escapeValue(w.Language),
		escapeValue(w.SoftwareEdition),
		escapeValue(w.TargetSoftware),
		escapeValue(w.TargetHardware),
		escapeValue(w.Other),
	}

	return strings.Join(parts, ":")
}

// ToCPE22String 转换WFN为CPE 2.2格式字符串
func (w *WFN) ToCPE22String() string {
	cpePrefix := "cpe:/"
	mainParts := []string{
		w.Part,
		escapeValueForCpe22(w.Vendor),
		escapeValueForCpe22(w.Product),
		escapeValueForCpe22(w.Version),
		escapeValueForCpe22(w.Update),
	}

	// 将主要部分组合成CPE 2.2格式
	result := cpePrefix + strings.Join(mainParts, ":")

	// 如果有扩展属性，添加到结果中
	if w.Edition != "" || w.Language != "" || w.SoftwareEdition != "" ||
		w.TargetSoftware != "" || w.TargetHardware != "" || w.Other != "" {

		extParts := []string{
			escapeValueForCpe22(w.Edition),
			"", // CPE 2.2没有明确的位置给这个字段
			"", // CPE 2.2没有明确的位置给这个字段
			escapeValueForCpe22(w.Language),
			escapeValueForCpe22(w.SoftwareEdition),
			escapeValueForCpe22(w.TargetSoftware),
			escapeValueForCpe22(w.TargetHardware),
			escapeValueForCpe22(w.Other),
		}

		// 移除末尾的空值
		for i := len(extParts) - 1; i >= 0; i-- {
			if extParts[i] != "" {
				extParts = extParts[:i+1]
				break
			}
		}

		if len(extParts) > 0 {
			result += ":" + strings.Join(extParts, "~")
		}
	}

	return result
}

// escapeValue 对CPE 2.3格式的值进行转义
func escapeValue(value string) string {
	// 如果是特殊值或空值，不需要转义
	if value == "*" || value == "-" || value == "" {
		return value
	}

	// 检查是否是版本字段，版本字段中的点不做双重转义
	// 通常版本字段的格式为数字.数字.数字
	isVersion := false
	if len(value) >= 3 {
		versionPattern := regexp.MustCompile(`^\d+(\.\d+)+$`)
		isVersion = versionPattern.MatchString(value)
	}

	// 转义值
	escaped := value

	if !isVersion {
		// 转义点号，除非在版本号中
		escaped = strings.ReplaceAll(escaped, ".", "\\.")
	}

	// 转义其他特殊字符
	escaped = strings.ReplaceAll(escaped, ":", "\\:")

	return escaped
}

// unescapeValue 对CPE 2.3格式的值进行反转义
func unescapeValue(value string) string {
	if value == "*" || value == "-" || value == "" {
		return value
	}

	// 使用正则表达式识别转义序列
	re := regexp.MustCompile(`\\(.)`)
	return re.ReplaceAllString(value, "$1")
}

// escapeValueForCpe22 对CPE 2.2格式的值进行转义
func escapeValueForCpe22(value string) string {
	if value == "*" || value == "-" || value == "" {
		return value
	}

	// 替换特殊字符
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		":", "%3a",
		"/", "%2f",
		"~", "%7e",
	)

	return replacer.Replace(value)
}

// Match 比较两个WFN是否匹配
func (w *WFN) Match(other *WFN) bool {
	// 检查Part
	if !matchWFNAttribute(w.Part, other.Part) {
		return false
	}

	// 检查其他属性
	return matchWFNAttribute(w.Vendor, other.Vendor) &&
		matchWFNAttribute(w.Product, other.Product) &&
		matchWFNAttribute(w.Version, other.Version) &&
		matchWFNAttribute(w.Update, other.Update) &&
		matchWFNAttribute(w.Edition, other.Edition) &&
		matchWFNAttribute(w.Language, other.Language) &&
		matchWFNAttribute(w.SoftwareEdition, other.SoftwareEdition) &&
		matchWFNAttribute(w.TargetSoftware, other.TargetSoftware) &&
		matchWFNAttribute(w.TargetHardware, other.TargetHardware) &&
		matchWFNAttribute(w.Other, other.Other)
}

// matchWFNAttribute 匹配WFN的单个属性
func matchWFNAttribute(a, b string) bool {
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

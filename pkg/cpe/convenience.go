package cpeskills

/**
 * convenience.go - 便捷函数集合
 *
 * 本文件提供一组高级便捷函数，简化常见的CPE操作。
 * 这些函数是对底层API的封装，提供更简洁的调用方式。
 */

import (
	"fmt"
	"strings"
)

// MustParse 解析CPE字符串，如果解析失败则panic
// 适用于初始化场景，如全局变量赋值
//
// 示例:
//
//	var myCPE = cpe.MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
func MustParse(cpeStr string) *CPE {
	result, err := Parse(cpeStr)
	if err != nil {
		panic(fmt.Sprintf("failed to parse CPE %q: %v", cpeStr, err))
	}
	return result
}

// ParseOr 解析CPE字符串，如果解析失败则返回默认值
//
// 示例:
//
//	cpe := cpe.ParseOr("invalid", defaultCPE)
func ParseOr(cpeStr string, defaultCPE *CPE) *CPE {
	result, err := Parse(cpeStr)
	if err != nil {
		return defaultCPE
	}
	return result
}

// IsCPE23String 判断字符串是否为有效的CPE 2.3 URI格式
//
// 示例:
//
//	cpe.IsCPE23String("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*") // true
//	cpe.IsCPE23String("not a cpe") // false
func IsCPE23String(s string) bool {
	return strings.HasPrefix(s, "cpe:2.3:")
}

// IsCPE22String 判断字符串是否为有效的CPE 2.2 URI格式
//
// 示例:
//
//	cpe.IsCPE22String("cpe:/a:microsoft:windows:10") // true
func IsCPE22String(s string) bool {
	return strings.HasPrefix(s, "cpe:/")
}

// QuickMatch 快速判断两个CPE字符串是否匹配
// 这是最简单的匹配接口，不需要创建CPE对象
//
// 示例:
//
//	matched, err := cpe.QuickMatch("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
//	                                   "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
func QuickMatch(cpeStr1, cpeStr2 string) (bool, error) {
	cpe1, err := Parse(cpeStr1)
	if err != nil {
		return false, fmt.Errorf("failed to parse first CPE: %w", err)
	}
	cpe2, err := Parse(cpeStr2)
	if err != nil {
		return false, fmt.Errorf("failed to parse second CPE: %w", err)
	}
	return cpe1.Match(cpe2), nil
}

// StringToPart 将字符串转换为Part类型
//
// 示例:
//
//	part := cpe.StringToPart("a") // PartApplication
func StringToPart(s string) (*Part, error) {
	switch strings.ToLower(s) {
	case "a", "application":
		return PartApplication, nil
	case "h", "hardware":
		return PartHardware, nil
	case "o", "operating system", "os":
		return PartOperationSystem, nil
	default:
		return nil, fmt.Errorf("invalid part: %q, must be a/h/o", s)
	}
}

// FormatCPE 格式化CPE为指定版本的字符串
// version 可以是 "2.2" 或 "2.3"
//
// 示例:
//
//	str, err := cpe.FormatCPE(cpeObj, "2.3")
func FormatCPE(cpe *CPE, version string) (string, error) {
	if cpe == nil {
		return "", ErrInvalidData
	}
	switch version {
	case "2.3", "23", "":
		return FormatCpe23(cpe), nil
	case "2.2", "22":
		return FormatCpe22(cpe), nil
	default:
		return "", fmt.Errorf("unsupported CPE version: %q, use 2.2 or 2.3", version)
	}
}

// Clone 深拷贝一个CPE对象
//
// 示例:
//
//	copy := cpe.Clone(originalCPE)
func Clone(cpe *CPE) *CPE {
	if cpe == nil {
		return nil
	}
	clone := *cpe
	return &clone
}

// CPEsToStrings 将CPE切片转换为字符串切片
//
// 示例:
//
//	strs := cpe.CPEsToStrings(cpes)
func CPEsToStrings(cpes []*CPE) []string {
	result := make([]string, 0, len(cpes))
	for _, c := range cpes {
		if c != nil {
			result = append(result, c.Cpe23)
		}
	}
	return result
}

// StringsToCPEs 将字符串切片转换为CPE切片
// 忽略解析失败的字符串
//
// 示例:
//
//	cpes := cpe.StringsToCPEs([]string{"cpe:2.3:a:...", "invalid"})
func StringsToCPEs(strs []string) []*CPE {
	result := make([]*CPE, 0, len(strs))
	for _, s := range strs {
		if c, err := Parse(s); err == nil {
			result = append(result, c)
		}
	}
	return result
}

// FilterByPart 按Part类型筛选CPE列表
//
// 示例:
//
//	apps := cpe.FilterByPart(allCPEs, cpe.PartApplication)
func FilterByPart(cpes []*CPE, part *Part) []*CPE {
	result := make([]*CPE, 0)
	for _, c := range cpes {
		if c != nil && string(c.Part.ShortName) == string(part.ShortName) {
			result = append(result, c)
		}
	}
	return result
}

// FilterByVendor 按Vendor筛选CPE列表
//
// 示例:
//
//	msCPEs := cpe.FilterByVendor(allCPEs, "microsoft")
func FilterByVendor(cpes []*CPE, vendor string) []*CPE {
	result := make([]*CPE, 0)
	for _, c := range cpes {
		if c != nil && string(c.Vendor) == vendor {
			result = append(result, c)
		}
	}
	return result
}

// FilterByProduct 按Product筛选CPE列表
//
// 示例:
//
//	winCPEs := cpe.FilterByProduct(allCPEs, "windows")
func FilterByProduct(cpes []*CPE, product string) []*CPE {
	result := make([]*CPE, 0)
	for _, c := range cpes {
		if c != nil && string(c.ProductName) == product {
			result = append(result, c)
		}
	}
	return result
}

// GetPartName 获取Part的可读名称
//
// 示例:
//
//	cpe.GetPartName("a") // "Application"
func GetPartName(shortName string) string {
	switch strings.ToLower(shortName) {
	case "a":
		return "Application"
	case "h":
		return "Hardware"
	case "o":
		return "Operating System"
	default:
		return "Unknown"
	}
}

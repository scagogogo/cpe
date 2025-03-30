package cpe

import (
	"regexp"
	"strconv"
	"strings"
)

// MatchOptions 匹配选项
type MatchOptions struct {
	// 是否忽略版本匹配
	IgnoreVersion bool

	// 是否允许子版本匹配，例如1.0匹配所有1.0.x
	AllowSubVersions bool

	// 使用正则表达式匹配
	UseRegex bool

	// 比较版本范围而不是精确匹配
	VersionRange bool

	// 最小版本（含）
	MinVersion string

	// 最大版本（含）
	MaxVersion string
}

// DefaultMatchOptions 返回默认匹配选项
func DefaultMatchOptions() *MatchOptions {
	return &MatchOptions{
		IgnoreVersion:    false,
		AllowSubVersions: true,
		UseRegex:         false,
		VersionRange:     false,
	}
}

// Search 在CPE列表中搜索匹配指定条件的CPE
func Search(cpes []*CPE, criteria *CPE, options *MatchOptions) []*CPE {
	if options == nil {
		options = DefaultMatchOptions()
	}

	var results []*CPE

	for _, cpe := range cpes {
		if matchCPE(cpe, criteria, options) {
			results = append(results, cpe)
		}
	}

	return results
}

// matchCPE 判断一个CPE是否匹配搜索条件
func matchCPE(cpe, criteria *CPE, options *MatchOptions) bool {
	// 匹配Part (必须完全匹配)
	if criteria.Part.ShortName != "" && criteria.Part.ShortName != cpe.Part.ShortName {
		return false
	}

	// 匹配Vendor
	if string(criteria.Vendor) != "" && string(criteria.Vendor) != "*" {
		if options.UseRegex {
			matched, _ := regexp.MatchString(string(criteria.Vendor), string(cpe.Vendor))
			if !matched {
				return false
			}
		} else if string(criteria.Vendor) != string(cpe.Vendor) {
			return false
		}
	}

	// 匹配Product
	if string(criteria.ProductName) != "" && string(criteria.ProductName) != "*" {
		if options.UseRegex {
			matched, _ := regexp.MatchString(string(criteria.ProductName), string(cpe.ProductName))
			if !matched {
				return false
			}
		} else if string(criteria.ProductName) != string(cpe.ProductName) {
			return false
		}
	}

	// 匹配Version
	if !options.IgnoreVersion && string(criteria.Version) != "" && string(criteria.Version) != "*" {
		if options.VersionRange {
			// 版本范围匹配
			if options.MinVersion != "" {
				if compareVersionsSimple(string(cpe.Version), options.MinVersion) < 0 {
					return false
				}
			}

			if options.MaxVersion != "" {
				if compareVersionsSimple(string(cpe.Version), options.MaxVersion) > 0 {
					return false
				}
			}
		} else if options.AllowSubVersions {
			// 子版本匹配
			if !strings.HasPrefix(string(cpe.Version), string(criteria.Version)) {
				return false
			}
		} else if string(criteria.Version) != string(cpe.Version) {
			// 精确匹配
			return false
		}
	}

	// 匹配Update
	if string(criteria.Update) != "" && string(criteria.Update) != "*" {
		if options.UseRegex {
			matched, _ := regexp.MatchString(string(criteria.Update), string(cpe.Update))
			if !matched {
				return false
			}
		} else if string(criteria.Update) != string(cpe.Update) {
			return false
		}
	}

	return true
}

// compareVersions 比较两个版本号
// 返回: -1 (v1 < v2), 0 (v1 == v2), 1 (v1 > v2)
func compareVersionsSimple(v1, v2 string) int {
	// 处理特殊情况
	if v1 == v2 {
		return 0
	}
	if v1 == "*" || v2 == "*" {
		return 0
	}
	if v1 == "" {
		return -1
	}
	if v2 == "" {
		return 1
	}

	// 分割版本号为数字部分
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	// 比较每一部分
	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		// 尝试将部分转换为数字
		num1, err1 := strconv.Atoi(parts1[i])
		num2, err2 := strconv.Atoi(parts2[i])

		if err1 == nil && err2 == nil {
			// 两部分都是数字，直接比较
			if num1 < num2 {
				return -1
			}
			if num1 > num2 {
				return 1
			}
		} else {
			// 至少有一部分不是数字，按字符串比较
			if parts1[i] < parts2[i] {
				return -1
			}
			if parts1[i] > parts2[i] {
				return 1
			}
		}
	}

	// 如果前面的部分都相等，较长的版本号较大
	if len(parts1) < len(parts2) {
		return -1
	}
	if len(parts1) > len(parts2) {
		return 1
	}

	return 0
}

// FindVulnerableCPEs 查找可能受特定漏洞影响的CPE
// cves参数为CVE ID列表，返回包含这些CVE的CPE
func FindVulnerableCPEs(cpes []*CPE, cves []string) []*CPE {
	var results []*CPE

	for _, cpe := range cpes {
		for _, cve := range cves {
			if cpe.Cve == cve {
				results = append(results, cpe)
				break
			}
		}
	}

	return results
}

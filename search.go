package cpe

import (
	"regexp"
	"strings"

	"github.com/scagogogo/versions"
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
				cpeVersion := versions.NewVersion(string(cpe.Version))
				minVersion := versions.NewVersion(options.MinVersion)
				if cpeVersion.CompareTo(minVersion) < 0 {
					return false
				}
			}

			if options.MaxVersion != "" {
				cpeVersion := versions.NewVersion(string(cpe.Version))
				maxVersion := versions.NewVersion(options.MaxVersion)
				if cpeVersion.CompareTo(maxVersion) > 0 {
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

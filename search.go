package cpe

import (
	"regexp"
	"strings"

	"github.com/scagogogo/versions"
)

/**
 * MatchOptions 匹配选项结构体
 *
 * 用于配置CPE匹配过程中的各种行为选项，包括版本匹配逻辑、正则表达式支持等。
 * 此结构体可用于精细控制Search和matchCPE函数的匹配行为。
 *
 * 注意事项：
 *   - 启用正则表达式会对性能有一定影响，大规模CPE集合时要谨慎使用
 *   - 版本范围和子版本匹配不能同时生效，启用VersionRange会优先于AllowSubVersions
 *
 * 示例：
 *   ```go
 *   // 创建匹配选项，忽略版本匹配
 *   options := &cpe.MatchOptions{
 *       IgnoreVersion: true,
 *   }
 *
 *   // 创建匹配选项，使用版本范围匹配
 *   options := &cpe.MatchOptions{
 *       VersionRange: true,
 *       MinVersion: "2.0",
 *       MaxVersion: "3.5",
 *   }
 *   ```
 */
type MatchOptions struct {
	// 是否忽略版本匹配
	// 设为true时版本号不参与匹配判断，适用于只需比较产品名称或供应商的场景
	IgnoreVersion bool

	// 是否允许子版本匹配
	// 设为true时，查询版本"1.0"可匹配"1.0"、"1.0.1"、"1.0.2"等所有子版本
	// 仅当IgnoreVersion为false且VersionRange为false时有效
	AllowSubVersions bool

	// 使用正则表达式匹配
	// 设为true时，Vendor、ProductName等字符串字段将使用正则表达式进行匹配
	// 注意：正则表达式匹配会降低性能，大规模匹配时慎用
	UseRegex bool

	// 比较版本范围而不是精确匹配
	// 设为true时，将使用MinVersion和MaxVersion定义的版本范围进行匹配
	// 此选项优先于AllowSubVersions
	VersionRange bool

	// 最小版本（含）
	// 指定版本范围的下限，当VersionRange为true时生效
	// 匹配时CPE版本必须大于或等于此版本
	MinVersion string

	// 最大版本（含）
	// 指定版本范围的上限，当VersionRange为true时生效
	// 匹配时CPE版本必须小于或等于此版本
	MaxVersion string
}

/**
 * DefaultMatchOptions 返回默认匹配选项
 *
 * 创建并返回一个预设默认值的MatchOptions实例，用于简化匹配选项的创建过程。
 * 默认配置下：
 *   - 会考虑版本匹配(IgnoreVersion = false)
 *   - 允许子版本匹配(AllowSubVersions = true)
 *   - 不使用正则表达式匹配(UseRegex = false)
 *   - 不使用版本范围匹配(VersionRange = false)
 *
 * @return *MatchOptions 预设了默认值的匹配选项对象
 *
 * 示例：
 *   ```go
 *   // 使用默认匹配选项
 *   options := cpe.DefaultMatchOptions()
 *
 *   // 在默认选项基础上修改
 *   options := cpe.DefaultMatchOptions()
 *   options.UseRegex = true
 *   ```
 *
 * 注意事项：
 *   - 返回的是指针类型，可以直接修改其属性
 *   - 在大多数简单匹配场景下，默认选项已经能满足需求
 */
func DefaultMatchOptions() *MatchOptions {
	return &MatchOptions{
		IgnoreVersion:    false,
		AllowSubVersions: true,
		UseRegex:         false,
		VersionRange:     false,
	}
}

/**
 * Search 在CPE列表中搜索匹配指定条件的CPE
 *
 * 根据提供的条件CPE(criteria)和匹配选项(options)，在给定的CPE列表中查找匹配的CPE项。
 * 此方法支持多种灵活的匹配策略，包括精确匹配、模糊匹配、版本范围匹配等。
 *
 * @param cpes []*CPE CPE对象列表，作为搜索的数据源，不可为nil
 * @param criteria *CPE 搜索条件CPE，包含要匹配的字段，可以部分字段为空
 * @param options *MatchOptions 匹配选项，控制匹配行为，如为nil则使用默认选项
 * @return []*CPE 所有匹配条件的CPE对象列表，如无匹配项则返回空切片
 *
 * 示例：
 *   ```go
 *   // 示例1：查找所有Microsoft Windows产品
 *   criteria := &cpe.CPE{
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("windows"),
 *   }
 *   results := cpe.Search(allCPEs, criteria, nil) // 使用默认匹配选项
 *
 *   // 示例2：查找所有2.0到3.0版本范围的Apache产品
 *   criteria := &cpe.CPE{
 *       Vendor: cpe.Vendor("apache"),
 *   }
 *   options := cpe.DefaultMatchOptions()
 *   options.VersionRange = true
 *   options.MinVersion = "2.0"
 *   options.MaxVersion = "3.0"
 *   results := cpe.Search(allCPEs, criteria, options)
 *
 *   // 示例3：使用正则表达式查找所有包含"sql"的产品
 *   criteria := &cpe.CPE{
 *       ProductName: cpe.Product(".*sql.*"),
 *   }
 *   options := cpe.DefaultMatchOptions()
 *   options.UseRegex = true
 *   results := cpe.Search(allCPEs, criteria, options)
 *   ```
 *
 * 注意事项：
 *   - criteria中的空字段不参与匹配判断
 *   - 时间复杂度为O(n)，其中n为cpes的长度
 *   - 在大规模CPE集合上使用正则表达式可能会导致性能下降
 */
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

/**
 * matchCPE 判断一个CPE是否匹配搜索条件
 *
 * 根据提供的条件CPE(criteria)和匹配选项(options)，判断目标CPE是否满足匹配条件。
 * 内部函数，主要被Search函数调用，实现了具体的匹配逻辑。
 *
 * @param cpe *CPE 要检查的目标CPE对象
 * @param criteria *CPE 包含匹配条件的CPE对象
 * @param options *MatchOptions 匹配选项，控制匹配行为
 * @return bool 如果cpe匹配criteria条件则返回true，否则返回false
 *
 * 匹配逻辑说明：
 *   1. 必须匹配Part字段（如果criteria中指定了）
 *   2. 必须匹配Vendor字段（如果criteria中指定了且不为"*"）
 *   3. 必须匹配Product字段（如果criteria中指定了且不为"*"）
 *   4. 根据options中的配置匹配Version字段
 *   5. 必须匹配Update字段（如果criteria中指定了且不为"*"）
 *
 * 版本匹配支持以下几种模式：
 *   - 精确匹配：版本必须完全相同
 *   - 子版本匹配：只要前缀相同即可匹配（如"1.0"匹配"1.0.1"）
 *   - 版本范围匹配：版本在指定的最小和最大版本范围内
 *
 * 注意事项：
 *   - "*"在criteria中表示通配符，可匹配任何值
 *   - 当options.UseRegex为true时，字符串字段使用正则表达式匹配
 *   - 匹配逻辑是"与"关系，所有指定的字段都必须匹配
 */
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

/**
 * FindVulnerableCPEs 查找可能受特定漏洞影响的CPE
 *
 * 根据提供的CVE ID列表，查找并返回在给定CPE列表中可能受影响的所有CPE对象。
 * 此方法用于快速识别特定漏洞影响范围内的软件和系统。
 *
 * @param cpes []*CPE CPE对象列表，表示要检查的软件/系统集合
 * @param cves []string CVE ID列表，表示要查找的漏洞编号
 * @return []*CPE 匹配任一CVE ID的所有CPE对象列表
 *
 * 匹配逻辑：
 *   - 如果CPE对象的Cve字段与cves参数中的任何一个CVE ID匹配，则将其添加到结果中
 *   - 每个CPE只会在结果列表中出现一次，即使它与多个CVE ID匹配
 *
 * 示例：
 *   ```go
 *   // 查找受CVE-2021-44228和CVE-2021-45046漏洞影响的所有软件
 *   cveIds := []string{"CVE-2021-44228", "CVE-2021-45046"}
 *   vulnerableCPEs := cpe.FindVulnerableCPEs(allCPEs, cveIds)
 *
 *   // 打印受影响软件的数量和详情
 *   fmt.Printf("发现%d个受影响的软件\n", len(vulnerableCPEs))
 *   for _, vulnerableCPE := range vulnerableCPEs {
 *       fmt.Printf("- %s: %s %s %s\n",
 *           vulnerableCPE.Cve,
 *           vulnerableCPE.Vendor,
 *           vulnerableCPE.ProductName,
 *           vulnerableCPE.Version)
 *   }
 *   ```
 *
 * 注意事项：
 *   - 时间复杂度为O(n*m)，其中n为cpes的长度，m为cves的长度
 *   - 如果CPE对象的Cve字段未设置，则永远不会匹配
 *   - 返回的列表保持原始CPE列表中的顺序
 *   - 此方法不修改输入参数
 */
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

package cpe

import (
	"regexp"
	"strings"

	"github.com/scagogogo/versions"
)

// AdvancedMatchOptions 定义了高级匹配选项
type AdvancedMatchOptions struct {
	// 是否使用正则表达式匹配
	UseRegex bool

	// 是否忽略大小写
	IgnoreCase bool

	// 是否使用模糊匹配
	UseFuzzyMatch bool

	// 是否只匹配常见字段 (part, vendor, product, version)
	MatchCommonOnly bool

	// 部分匹配
	PartialMatch bool

	// 匹配模式 (exact, subset, superset, distance)
	MatchMode string

	// 版本比较模式 (exact, greater, less, range)
	VersionCompareMode string

	// 版本低界限
	VersionLower string

	// 版本高界限
	VersionUpper string

	// 字段特定选项
	FieldOptions map[string]FieldMatchOption

	// 匹配得分阈值 (0.0-1.0)
	ScoreThreshold float64
}

// FieldMatchOption 定义字段特定的匹配选项
type FieldMatchOption struct {
	// 匹配权重 (0.0-1.0)
	Weight float64

	// 是否必须匹配此字段
	Required bool

	// 匹配方法
	MatchMethod string
}

// NewAdvancedMatchOptions 创建默认的高级匹配选项
func NewAdvancedMatchOptions() *AdvancedMatchOptions {
	return &AdvancedMatchOptions{
		UseRegex:           false,
		IgnoreCase:         false,
		UseFuzzyMatch:      false,
		MatchCommonOnly:    false,
		PartialMatch:       false,
		MatchMode:          "exact",
		VersionCompareMode: "exact",
		VersionLower:       "",
		VersionUpper:       "",
		FieldOptions:       make(map[string]FieldMatchOption),
		ScoreThreshold:     0.7, // 默认要求70%的匹配度
	}
}

// AdvancedMatchCPE 执行高级CPE匹配
func AdvancedMatchCPE(criteria *CPE, target *CPE, options *AdvancedMatchOptions) bool {
	if criteria == nil || target == nil {
		return false
	}

	// 使用默认选项如果没有提供
	if options == nil {
		options = NewAdvancedMatchOptions()
	}

	// 根据匹配模式选择不同的匹配策略
	switch options.MatchMode {
	case "exact":
		// 基本字段匹配
		return matchCommonFields(criteria, target, options)
	case "subset":
		// 子集匹配
		return matchSubset(criteria, target, options)
	case "superset":
		// 超集匹配
		return matchSuperset(criteria, target, options)
	case "distance":
		// 距离匹配
		return matchDistance(criteria, target, options)
	default:
		// 如果未指定匹配模式或使用未知模式，继续尝试不同方式
	}

	// 如果启用了正则表达式匹配
	if options.UseRegex {
		return matchWithRegex(criteria, target, options)
	}

	// 如果启用了部分匹配
	if options.PartialMatch {
		return matchPartial(criteria, target, options)
	}

	// 默认使用常规字段匹配
	return matchCommonFields(criteria, target, options)
}

// matchCommonFields 仅匹配常见字段
func matchCommonFields(criteria *CPE, target *CPE, options *AdvancedMatchOptions) bool {
	// 匹配Part
	if !matchField(string(criteria.Part.ShortName), string(target.Part.ShortName), options) {
		return false
	}

	// 匹配Vendor
	if !matchField(string(criteria.Vendor), string(target.Vendor), options) {
		return false
	}

	// 匹配ProductName
	if !matchField(string(criteria.ProductName), string(target.ProductName), options) {
		return false
	}

	// 匹配Version - 根据选项决定使用哪种版本比较方式
	if options.VersionCompareMode != "exact" {
		// 使用版本比较逻辑
		if !compareVersions(criteria, target, options) {
			return false
		}
	} else {
		// 使用普通字段匹配
		if !matchField(string(criteria.Version), string(target.Version), options) {
			return false
		}
	}

	return true
}

// matchWithRegex 使用正则表达式匹配
func matchWithRegex(criteria *CPE, target *CPE, options *AdvancedMatchOptions) bool {
	// 匹配Part
	if !matchFieldWithRegex(string(criteria.Part.ShortName), string(target.Part.ShortName), options) {
		return false
	}

	// 匹配Vendor
	if !matchFieldWithRegex(string(criteria.Vendor), string(target.Vendor), options) {
		return false
	}

	// 匹配ProductName
	if !matchFieldWithRegex(string(criteria.ProductName), string(target.ProductName), options) {
		return false
	}

	// 匹配Version
	if !matchFieldWithRegex(string(criteria.Version), string(target.Version), options) {
		return false
	}

	// 如果不仅匹配常见字段，还需匹配其它字段
	if !options.MatchCommonOnly {
		// 匹配Update
		if !matchFieldWithRegex(string(criteria.Update), string(target.Update), options) {
			return false
		}

		// 匹配Edition
		if !matchFieldWithRegex(string(criteria.Edition), string(target.Edition), options) {
			return false
		}

		// 匹配Language
		if !matchFieldWithRegex(string(criteria.Language), string(target.Language), options) {
			return false
		}

		// 匹配SoftwareEdition
		if !matchFieldWithRegex(criteria.SoftwareEdition, target.SoftwareEdition, options) {
			return false
		}

		// 匹配TargetSoftware
		if !matchFieldWithRegex(criteria.TargetSoftware, target.TargetSoftware, options) {
			return false
		}

		// 匹配TargetHardware
		if !matchFieldWithRegex(criteria.TargetHardware, target.TargetHardware, options) {
			return false
		}

		// 匹配Other
		if !matchFieldWithRegex(criteria.Other, target.Other, options) {
			return false
		}
	}

	return true
}

// matchPartial 部分匹配 - 只匹配非空字段
func matchPartial(criteria *CPE, target *CPE, options *AdvancedMatchOptions) bool {
	// 匹配Part (如果有值)
	if string(criteria.Part.ShortName) != "" && string(criteria.Part.ShortName) != "*" {
		if !matchField(string(criteria.Part.ShortName), string(target.Part.ShortName), options) {
			return false
		}
	}

	// 匹配Vendor (如果有值)
	if string(criteria.Vendor) != "" && string(criteria.Vendor) != "*" {
		if !matchField(string(criteria.Vendor), string(target.Vendor), options) {
			return false
		}
	}

	// 匹配ProductName (如果有值)
	if string(criteria.ProductName) != "" && string(criteria.ProductName) != "*" {
		if !matchField(string(criteria.ProductName), string(target.ProductName), options) {
			return false
		}
	}

	// 匹配Version (如果有值)
	if string(criteria.Version) != "" && string(criteria.Version) != "*" {
		// 如果使用版本比较
		if options.VersionCompareMode != "exact" {
			if !compareVersions(criteria, target, options) {
				return false
			}
		} else {
			if !matchField(string(criteria.Version), string(target.Version), options) {
				return false
			}
		}
	}

	// 如果不仅匹配常见字段，还需匹配其它非空字段
	if !options.MatchCommonOnly {
		// 匹配Update (如果有值)
		if string(criteria.Update) != "" && string(criteria.Update) != "*" {
			if !matchField(string(criteria.Update), string(target.Update), options) {
				return false
			}
		}

		// 匹配Edition (如果有值)
		if string(criteria.Edition) != "" && string(criteria.Edition) != "*" {
			if !matchField(string(criteria.Edition), string(target.Edition), options) {
				return false
			}
		}

		// 匹配Language (如果有值)
		if string(criteria.Language) != "" && string(criteria.Language) != "*" {
			if !matchField(string(criteria.Language), string(target.Language), options) {
				return false
			}
		}

		// 匹配SoftwareEdition (如果有值)
		if criteria.SoftwareEdition != "" && criteria.SoftwareEdition != "*" {
			if !matchField(criteria.SoftwareEdition, target.SoftwareEdition, options) {
				return false
			}
		}

		// 匹配TargetSoftware (如果有值)
		if criteria.TargetSoftware != "" && criteria.TargetSoftware != "*" {
			if !matchField(criteria.TargetSoftware, target.TargetSoftware, options) {
				return false
			}
		}

		// 匹配TargetHardware (如果有值)
		if criteria.TargetHardware != "" && criteria.TargetHardware != "*" {
			if !matchField(criteria.TargetHardware, target.TargetHardware, options) {
				return false
			}
		}

		// 匹配Other (如果有值)
		if criteria.Other != "" && criteria.Other != "*" {
			if !matchField(criteria.Other, target.Other, options) {
				return false
			}
		}
	}

	return true
}

// matchField 匹配单个字段值，考虑匹配选项
func matchField(a, b string, options *AdvancedMatchOptions) bool {
	if a == "*" || b == "*" {
		return true
	}

	if a == "-" && b == "-" {
		return true
	}

	if options.IgnoreCase {
		a = strings.ToLower(a)
		b = strings.ToLower(b)
	}

	if options.UseFuzzyMatch {
		// 简单的模糊匹配实现：检查一个是否包含另一个
		return strings.Contains(a, b) || strings.Contains(b, a)
	}

	return a == b
}

// matchFieldWithRegex 使用正则表达式匹配字段
func matchFieldWithRegex(a, b string, options *AdvancedMatchOptions) bool {
	// 如果a为空，表示没有约束条件，匹配成功
	if a == "" || a == "*" {
		return true
	}

	// 如果b为空或是NA值，不匹配
	if b == "" || b == "-" {
		return false
	}

	// 如果b是通配符，匹配成功
	if b == "*" {
		return true
	}

	// 创建正则表达式
	var re *regexp.Regexp
	var err error

	// 处理不同的选项
	if options != nil && options.IgnoreCase {
		// 忽略大小写，添加(?i)前缀
		re, err = regexp.Compile("(?i)" + a)
	} else {
		re, err = regexp.Compile(a)
	}

	// 如果正则表达式有问题，则执行精确匹配
	if err != nil {
		if options != nil && options.IgnoreCase {
			return strings.EqualFold(a, b)
		}
		return a == b
	}

	// 执行正则表达式匹配
	return re.MatchString(b)
}

// matchNonVersionFields 匹配除版本外的所有字段
func matchNonVersionFields(criteria *CPE, target *CPE, options *AdvancedMatchOptions) bool {
	// 匹配Part
	if !matchField(string(criteria.Part.ShortName), string(target.Part.ShortName), options) {
		return false
	}

	// 匹配Vendor
	if !matchField(string(criteria.Vendor), string(target.Vendor), options) {
		return false
	}

	// 匹配ProductName
	if !matchField(string(criteria.ProductName), string(target.ProductName), options) {
		return false
	}

	// 如果不仅匹配常见字段，还需匹配其它字段
	if !options.MatchCommonOnly {
		// 非必须字段，可以返回true即使这些字段不匹配
		// 计算匹配得分，如果得分超过阈值，返回true
		totalWeight := 3.0 // Part, Vendor, Product已经匹配，权重各1.0
		matchedWeight := 3.0

		// 使用默认字段权重
		fieldWeights := map[string]float64{
			"update":          0.6,
			"edition":         0.6,
			"language":        0.4,
			"softwareEdition": 0.4,
			"targetSoftware":  0.4,
			"targetHardware":  0.4,
			"other":           0.2,
		}

		// Update
		w := fieldWeights["update"]
		totalWeight += w
		if matchField(string(criteria.Update), string(target.Update), options) {
			matchedWeight += w
		}

		// Edition
		w = fieldWeights["edition"]
		totalWeight += w
		if matchField(string(criteria.Edition), string(target.Edition), options) {
			matchedWeight += w
		}

		// Language
		w = fieldWeights["language"]
		totalWeight += w
		if matchField(string(criteria.Language), string(target.Language), options) {
			matchedWeight += w
		}

		// SoftwareEdition
		w = fieldWeights["softwareEdition"]
		totalWeight += w
		if matchField(criteria.SoftwareEdition, target.SoftwareEdition, options) {
			matchedWeight += w
		}

		// TargetSoftware
		w = fieldWeights["targetSoftware"]
		totalWeight += w
		if matchField(criteria.TargetSoftware, target.TargetSoftware, options) {
			matchedWeight += w
		}

		// TargetHardware
		w = fieldWeights["targetHardware"]
		totalWeight += w
		if matchField(criteria.TargetHardware, target.TargetHardware, options) {
			matchedWeight += w
		}

		// Other
		w = fieldWeights["other"]
		totalWeight += w
		if matchField(criteria.Other, target.Other, options) {
			matchedWeight += w
		}

		// 计算匹配得分，如果得分超过0.7，则匹配成功
		score := matchedWeight / totalWeight
		return score >= 0.7
	}

	return true
}

// compareVersions 比较CPE版本
func compareVersions(criteria *CPE, target *CPE, options *AdvancedMatchOptions) bool {
	criteriaVersion := string(criteria.Version)
	targetVersion := string(target.Version)

	// 如果任一版本为通配符或NA，使用标准匹配规则
	if criteriaVersion == "*" || targetVersion == "*" || criteriaVersion == "-" || targetVersion == "-" {
		return matchField(criteriaVersion, targetVersion, options)
	}

	// 解析版本为Version对象
	criteriaVer := versions.NewVersion(criteriaVersion)
	targetVer := versions.NewVersion(targetVersion)

	// 根据版本比较模式执行比较
	switch options.VersionCompareMode {
	case "greater":
		// target版本必须大于criteria版本
		return targetVer.CompareTo(criteriaVer) > 0
	case "greaterOrEqual":
		// target版本必须大于等于criteria版本
		return targetVer.CompareTo(criteriaVer) >= 0
	case "less":
		// target版本必须小于criteria版本
		return targetVer.CompareTo(criteriaVer) < 0
	case "lessOrEqual":
		// target版本必须小于等于criteria版本
		return targetVer.CompareTo(criteriaVer) <= 0
	case "range":
		// 版本必须在指定范围内
		if options.VersionLower != "" {
			lowerVer := versions.NewVersion(options.VersionLower)
			if targetVer.CompareTo(lowerVer) < 0 {
				return false
			}
		}
		if options.VersionUpper != "" {
			upperVer := versions.NewVersion(options.VersionUpper)
			if targetVer.CompareTo(upperVer) > 0 {
				return false
			}
		}
		return true
	default:
		// 默认使用精确匹配
		return criteriaVersion == targetVersion
	}
}

// matchSubset 检查target是否是criteria的子集
func matchSubset(criteria *CPE, target *CPE, options *AdvancedMatchOptions) bool {
	if criteria == nil || target == nil {
		return false
	}

	// 检查Part
	if criteria.Part.ShortName != "" && criteria.Part.ShortName != "*" &&
		criteria.Part.ShortName != target.Part.ShortName {
		return false
	}

	// 检查Vendor
	if string(criteria.Vendor) != "" && string(criteria.Vendor) != "*" &&
		!matchField(string(criteria.Vendor), string(target.Vendor), options) {
		return false
	}

	// 检查Product
	if string(criteria.ProductName) != "" && string(criteria.ProductName) != "*" &&
		!matchField(string(criteria.ProductName), string(target.ProductName), options) {
		return false
	}

	// 如果需要匹配版本
	if !options.MatchCommonOnly {
		// 检查Version
		if string(criteria.Version) != "" && string(criteria.Version) != "*" &&
			!compareVersions(criteria, target, options) {
			return false
		}

		// 检查Update
		if string(criteria.Update) != "" && string(criteria.Update) != "*" &&
			!matchField(string(criteria.Update), string(target.Update), options) {
			return false
		}

		// 检查Edition
		if string(criteria.Edition) != "" && string(criteria.Edition) != "*" &&
			!matchField(string(criteria.Edition), string(target.Edition), options) {
			return false
		}

		// 检查Language
		if string(criteria.Language) != "" && string(criteria.Language) != "*" &&
			!matchField(string(criteria.Language), string(target.Language), options) {
			return false
		}

		// 检查SoftwareEdition
		if criteria.SoftwareEdition != "" && criteria.SoftwareEdition != "*" &&
			!matchField(criteria.SoftwareEdition, target.SoftwareEdition, options) {
			return false
		}

		// 检查TargetSoftware
		if criteria.TargetSoftware != "" && criteria.TargetSoftware != "*" &&
			!matchField(criteria.TargetSoftware, target.TargetSoftware, options) {
			return false
		}

		// 检查TargetHardware
		if criteria.TargetHardware != "" && criteria.TargetHardware != "*" &&
			!matchField(criteria.TargetHardware, target.TargetHardware, options) {
			return false
		}

		// 检查Other
		if criteria.Other != "" && criteria.Other != "*" &&
			!matchField(criteria.Other, target.Other, options) {
			return false
		}
	}

	return true
}

// matchSuperset 检查target是否是criteria的超集
func matchSuperset(criteria *CPE, target *CPE, options *AdvancedMatchOptions) bool {
	if criteria == nil || target == nil {
		return false
	}

	// 检查Part
	if target.Part.ShortName != "" && target.Part.ShortName != "*" &&
		criteria.Part.ShortName != target.Part.ShortName {
		return false
	}

	// 检查Vendor
	if string(target.Vendor) != "" && string(target.Vendor) != "*" &&
		!matchField(string(criteria.Vendor), string(target.Vendor), options) {
		return false
	}

	// 检查Product
	if string(target.ProductName) != "" && string(target.ProductName) != "*" &&
		!matchField(string(criteria.ProductName), string(target.ProductName), options) {
		return false
	}

	// 如果需要匹配版本
	if !options.MatchCommonOnly {
		// 检查Version - 超集匹配中，版本比较是特殊的
		if string(target.Version) != "" && string(target.Version) != "*" {
			// 在超集匹配中，如果目标有指定版本，标准也必须有对应版本
			if string(criteria.Version) == "" || string(criteria.Version) == "*" {
				return false
			}

			// 使用版本比较
			if !compareVersions(criteria, target, options) {
				return false
			}
		}

		// 检查Update
		if string(target.Update) != "" && string(target.Update) != "*" &&
			!matchField(string(criteria.Update), string(target.Update), options) {
			return false
		}

		// 检查Edition
		if string(target.Edition) != "" && string(target.Edition) != "*" &&
			!matchField(string(criteria.Edition), string(target.Edition), options) {
			return false
		}

		// 检查Language
		if string(target.Language) != "" && string(target.Language) != "*" &&
			!matchField(string(criteria.Language), string(target.Language), options) {
			return false
		}

		// 检查SoftwareEdition
		if target.SoftwareEdition != "" && target.SoftwareEdition != "*" &&
			!matchField(criteria.SoftwareEdition, target.SoftwareEdition, options) {
			return false
		}

		// 检查TargetSoftware
		if target.TargetSoftware != "" && target.TargetSoftware != "*" &&
			!matchField(criteria.TargetSoftware, target.TargetSoftware, options) {
			return false
		}

		// 检查TargetHardware
		if target.TargetHardware != "" && target.TargetHardware != "*" &&
			!matchField(criteria.TargetHardware, target.TargetHardware, options) {
			return false
		}

		// 检查Other
		if target.Other != "" && target.Other != "*" &&
			!matchField(criteria.Other, target.Other, options) {
			return false
		}
	}

	return true
}

// matchDistance 基于字段相似度的匹配
func matchDistance(criteria *CPE, target *CPE, options *AdvancedMatchOptions) bool {
	// 计算总权重和匹配权重
	totalWeight := 0.0
	matchedWeight := 0.0

	// 使用默认字段权重
	fieldWeights := map[string]float64{
		"part":            1.0,
		"vendor":          1.0,
		"product":         1.0,
		"version":         0.8,
		"update":          0.6,
		"edition":         0.6,
		"language":        0.4,
		"softwareEdition": 0.4,
		"targetSoftware":  0.4,
		"targetHardware":  0.4,
		"other":           0.2,
	}

	// 覆盖默认权重为用户自定义权重
	for field, option := range options.FieldOptions {
		if _, ok := fieldWeights[field]; ok {
			fieldWeights[field] = option.Weight
		}
	}

	// Part
	w := fieldWeights["part"]
	totalWeight += w
	if matchField(string(criteria.Part.ShortName), string(target.Part.ShortName), options) {
		matchedWeight += w
	} else if isRequiredField(options, "part") {
		return false
	}

	// Vendor
	w = fieldWeights["vendor"]
	totalWeight += w
	if matchField(string(criteria.Vendor), string(target.Vendor), options) {
		matchedWeight += w
	} else if isRequiredField(options, "vendor") {
		return false
	}

	// Product
	w = fieldWeights["product"]
	totalWeight += w
	if matchField(string(criteria.ProductName), string(target.ProductName), options) {
		matchedWeight += w
	} else if isRequiredField(options, "product") {
		return false
	}

	// Version
	w = fieldWeights["version"]
	totalWeight += w
	if options.VersionCompareMode != "exact" {
		if compareVersions(criteria, target, options) {
			matchedWeight += w
		} else if isRequiredField(options, "version") {
			return false
		}
	} else {
		if matchField(string(criteria.Version), string(target.Version), options) {
			matchedWeight += w
		} else if isRequiredField(options, "version") {
			return false
		}
	}

	// 如果需要匹配所有字段
	if !options.MatchCommonOnly {
		// Update
		w = fieldWeights["update"]
		totalWeight += w
		if matchField(string(criteria.Update), string(target.Update), options) {
			matchedWeight += w
		} else if isRequiredField(options, "update") {
			return false
		}

		// Edition
		w = fieldWeights["edition"]
		totalWeight += w
		if matchField(string(criteria.Edition), string(target.Edition), options) {
			matchedWeight += w
		} else if isRequiredField(options, "edition") {
			return false
		}

		// Language
		w = fieldWeights["language"]
		totalWeight += w
		if matchField(string(criteria.Language), string(target.Language), options) {
			matchedWeight += w
		} else if isRequiredField(options, "language") {
			return false
		}

		// SoftwareEdition
		w = fieldWeights["softwareEdition"]
		totalWeight += w
		if matchField(criteria.SoftwareEdition, target.SoftwareEdition, options) {
			matchedWeight += w
		} else if isRequiredField(options, "softwareEdition") {
			return false
		}

		// TargetSoftware
		w = fieldWeights["targetSoftware"]
		totalWeight += w
		if matchField(criteria.TargetSoftware, target.TargetSoftware, options) {
			matchedWeight += w
		} else if isRequiredField(options, "targetSoftware") {
			return false
		}

		// TargetHardware
		w = fieldWeights["targetHardware"]
		totalWeight += w
		if matchField(criteria.TargetHardware, target.TargetHardware, options) {
			matchedWeight += w
		} else if isRequiredField(options, "targetHardware") {
			return false
		}

		// Other
		w = fieldWeights["other"]
		totalWeight += w
		if matchField(criteria.Other, target.Other, options) {
			matchedWeight += w
		} else if isRequiredField(options, "other") {
			return false
		}
	}

	// 计算匹配得分
	score := matchedWeight / totalWeight

	return score >= options.ScoreThreshold
}

// isRequiredField 检查字段是否是必需的
func isRequiredField(options *AdvancedMatchOptions, field string) bool {
	option, ok := options.FieldOptions[field]
	return ok && option.Required
}

package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/scagogogo/cpe"
)

// 打印匹配结果
func printMatchingResult(description string, target *cpe.CPE, criteria *cpe.CPE, options *cpe.MatchOptions, isMatch bool) {
	fmt.Printf("==== %s ====\n", description)
	fmt.Printf("目标CPE: %s\n", target.GetURI())

	criteriaDesc := []string{
		fmt.Sprintf("Part: %s", criteria.Part.ShortName),
	}

	if criteria.Vendor != "" {
		criteriaDesc = append(criteriaDesc, fmt.Sprintf("Vendor: %s", criteria.Vendor))
	}

	if criteria.ProductName != "" {
		criteriaDesc = append(criteriaDesc, fmt.Sprintf("Product: %s", criteria.ProductName))
	}

	if criteria.Version != "" {
		criteriaDesc = append(criteriaDesc, fmt.Sprintf("Version: %s", criteria.Version))
	}

	fmt.Printf("匹配条件: %s\n", strings.Join(criteriaDesc, ", "))

	if options != nil {
		fmt.Printf("匹配选项: ")
		optionsDesc := []string{}

		if options.IgnoreVersion {
			optionsDesc = append(optionsDesc, "忽略版本")
		}

		if options.UseRegex {
			optionsDesc = append(optionsDesc, "使用正则表达式")
		}

		if options.VersionRange {
			optionsDesc = append(optionsDesc, fmt.Sprintf("版本范围(%s到%s)", options.MinVersion, options.MaxVersion))
		}

		if len(optionsDesc) > 0 {
			fmt.Printf("%s\n", strings.Join(optionsDesc, ", "))
		} else {
			fmt.Printf("无\n")
		}
	}

	fmt.Printf("匹配结果: %t\n\n", isMatch)
}

func main() {
	// 高级匹配算法示例
	// 展示CPE库的高级匹配功能

	fmt.Println("========= 高级匹配算法示例 =========")

	// 示例1: 基本精确匹配
	fmt.Println("\n===== 示例1: 基本精确匹配 =====")

	// 创建目标CPE
	targetCPE, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析目标CPE失败: %v", err)
	}

	// 创建匹配条件 - 精确匹配
	exactCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	// 测试精确匹配
	exactMatch := cpe.MatchCPE(exactCriteria, targetCPE, nil)
	printMatchingResult("精确匹配", targetCPE, exactCriteria, nil, exactMatch)

	// 创建不匹配条件
	nonMatchCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "11",
	}

	// 测试不匹配
	nonMatch := cpe.MatchCPE(nonMatchCriteria, targetCPE, nil)
	printMatchingResult("版本不匹配", targetCPE, nonMatchCriteria, nil, nonMatch)

	/*
		输出示例:
		===== 示例1: 基本精确匹配 =====
		==== 精确匹配 ====
		目标CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		匹配条件: Part: a, Vendor: microsoft, Product: windows, Version: 10
		匹配选项: 无
		匹配结果: true

		==== 版本不匹配 ====
		目标CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		匹配条件: Part: a, Vendor: microsoft, Product: windows, Version: 11
		匹配选项: 无
		匹配结果: false
	*/

	// 示例2: 部分匹配和通配符
	fmt.Println("\n===== 示例2: 部分匹配和通配符 =====")

	// 创建仅匹配vendor和product的条件
	partialCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
	}

	// 测试部分匹配
	partialMatch := cpe.MatchCPE(partialCriteria, targetCPE, nil)
	printMatchingResult("部分匹配 (仅Vendor和Product)", targetCPE, partialCriteria, nil, partialMatch)

	// 创建通配符条件
	wildcardCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "*",
		ProductName: "windows",
	}

	// 测试通配符匹配
	wildcardMatch := cpe.MatchCPE(wildcardCriteria, targetCPE, nil)
	printMatchingResult("通配符匹配 (任意Vendor)", targetCPE, wildcardCriteria, nil, wildcardMatch)

	/*
		输出示例:
		===== 示例2: 部分匹配和通配符 =====
		==== 部分匹配 (仅Vendor和Product) ====
		目标CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		匹配条件: Part: a, Vendor: microsoft, Product: windows
		匹配选项: 无
		匹配结果: true

		==== 通配符匹配 (任意Vendor) ====
		目标CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		匹配条件: Part: a, Vendor: *, Product: windows
		匹配选项: 无
		匹配结果: true
	*/

	// 示例3: 版本范围匹配
	fmt.Println("\n===== 示例3: 版本范围匹配 =====")

	// 创建版本范围匹配选项
	versionRangeOptions := &cpe.MatchOptions{
		VersionRange: true,
		MinVersion:   "8",
		MaxVersion:   "11",
	}

	// 测试版本范围匹配
	versionRangeMatch := cpe.MatchCPE(partialCriteria, targetCPE, versionRangeOptions)
	printMatchingResult("版本范围匹配 (8到11)", targetCPE, partialCriteria, versionRangeOptions, versionRangeMatch)

	// 创建不匹配的版本范围
	nonMatchVersionOptions := &cpe.MatchOptions{
		VersionRange: true,
		MinVersion:   "11",
		MaxVersion:   "12",
	}

	// 测试不匹配的版本范围
	nonVersionMatch := cpe.MatchCPE(partialCriteria, targetCPE, nonMatchVersionOptions)
	printMatchingResult("版本范围不匹配 (11到12)", targetCPE, partialCriteria, nonMatchVersionOptions, nonVersionMatch)

	/*
		输出示例:
		===== 示例3: 版本范围匹配 =====
		==== 版本范围匹配 (8到11) ====
		目标CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		匹配条件: Part: a, Vendor: microsoft, Product: windows
		匹配选项: 版本范围(8到11)
		匹配结果: true

		==== 版本范围不匹配 (11到12) ====
		目标CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		匹配条件: Part: a, Vendor: microsoft, Product: windows
		匹配选项: 版本范围(11到12)
		匹配结果: false
	*/

	// 示例4: 忽略版本匹配
	fmt.Println("\n===== 示例4: 忽略版本匹配 =====")

	// 创建不匹配版本的条件
	wrongVersionCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "11",
	}

	// 创建忽略版本的选项
	ignoreVersionOptions := &cpe.MatchOptions{
		IgnoreVersion: true,
	}

	// 测试忽略版本匹配
	ignoreVersionMatch := cpe.MatchCPE(wrongVersionCriteria, targetCPE, ignoreVersionOptions)
	printMatchingResult("忽略版本匹配", targetCPE, wrongVersionCriteria, ignoreVersionOptions, ignoreVersionMatch)

	/*
		输出示例:
		===== 示例4: 忽略版本匹配 =====
		==== 忽略版本匹配 ====
		目标CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		匹配条件: Part: a, Vendor: microsoft, Product: windows, Version: 11
		匹配选项: 忽略版本
		匹配结果: true
	*/

	// 示例5: 正则表达式匹配
	fmt.Println("\n===== 示例5: 正则表达式匹配 =====")

	// 创建正则表达式匹配条件
	regexCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "micro.*",
		ProductName: "win.*",
	}

	// 创建正则表达式匹配选项
	regexOptions := &cpe.MatchOptions{
		UseRegex: true,
	}

	// 测试正则表达式匹配
	regexMatch := cpe.MatchCPE(regexCriteria, targetCPE, regexOptions)
	printMatchingResult("正则表达式匹配", targetCPE, regexCriteria, regexOptions, regexMatch)

	// 创建不匹配的正则表达式条件
	nonMatchRegexCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "micro.*",
		ProductName: "office.*",
	}

	// 测试不匹配的正则表达式
	nonRegexMatch := cpe.MatchCPE(nonMatchRegexCriteria, targetCPE, regexOptions)
	printMatchingResult("正则表达式不匹配", targetCPE, nonMatchRegexCriteria, regexOptions, nonRegexMatch)

	/*
		输出示例:
		===== 示例5: 正则表达式匹配 =====
		==== 正则表达式匹配 ====
		目标CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		匹配条件: Part: a, Vendor: micro.*, Product: win.*
		匹配选项: 使用正则表达式
		匹配结果: true

		==== 正则表达式不匹配 ====
		目标CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		匹配条件: Part: a, Vendor: micro.*, Product: office.*
		匹配选项: 使用正则表达式
		匹配结果: false
	*/

	// 示例6: 组合匹配选项
	fmt.Println("\n===== 示例6: 组合匹配选项 =====")

	// 创建组合匹配选项 (正则表达式 + 版本范围)
	combinedOptions := &cpe.MatchOptions{
		UseRegex:     true,
		VersionRange: true,
		MinVersion:   "9",
		MaxVersion:   "11",
	}

	// 测试组合匹配
	combinedMatch := cpe.MatchCPE(regexCriteria, targetCPE, combinedOptions)
	printMatchingResult("组合匹配 (正则 + 版本范围)", targetCPE, regexCriteria, combinedOptions, combinedMatch)

	// 创建更复杂的目标CPE
	complexCPE, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows_server:2019:r2:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析复杂CPE失败: %v", err)
	}

	// 创建复杂匹配条件
	complexCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "micro.*",
		ProductName: "windows_.*",
		Update:      "r.*",
	}

	// 测试复杂匹配
	complexMatch := cpe.MatchCPE(complexCriteria, complexCPE, regexOptions)
	printMatchingResult("复杂匹配", complexCPE, complexCriteria, regexOptions, complexMatch)

	/*
		输出示例:
		===== 示例6: 组合匹配选项 =====
		==== 组合匹配 (正则 + 版本范围) ====
		目标CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		匹配条件: Part: a, Vendor: micro.*, Product: win.*
		匹配选项: 使用正则表达式, 版本范围(9到11)
		匹配结果: true

		==== 复杂匹配 ====
		目标CPE: cpe:2.3:a:microsoft:windows_server:2019:r2:*:*:*:*:*:*
		匹配条件: Part: a, Vendor: micro.*, Product: windows_.*, Update: r.*
		匹配选项: 使用正则表达式
		匹配结果: true
	*/
}

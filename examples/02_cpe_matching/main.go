package main

import (
	"fmt"
	"log"

	"github.com/scagogogo/cpe"
)

func main() {
	// 示例1: 简单CPE匹配
	fmt.Println("========= 基本CPE匹配 =========")

	// 创建两个CPE对象
	cpe1, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析CPE1失败: %v", err)
	}

	cpe2, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析CPE2失败: %v", err)
	}

	// 使用Match方法检查匹配
	fmt.Printf("CPE1: %s\n", cpe1.GetURI())
	fmt.Printf("CPE2: %s\n", cpe2.GetURI())
	fmt.Printf("CPE1匹配CPE2: %t\n", cpe1.Match(cpe2))
	fmt.Printf("CPE2匹配CPE1: %t\n", cpe2.Match(cpe1))
	fmt.Println()

	/*
		输出示例:
		========= 基本CPE匹配 =========
		CPE1: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		CPE2: cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*
		CPE1匹配CPE2: true
		CPE2匹配CPE1: true
	*/

	// 示例2: 使用MatchCPE函数匹配
	fmt.Println("========= 使用MatchCPE函数匹配 =========")

	// 创建目标CPE和查询条件
	targetCpe, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析目标CPE失败: %v", err)
	}

	// 创建查询条件
	criteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
	}

	// 默认匹配选项
	defaultOptions := cpe.DefaultMatchOptions()
	fmt.Printf("默认匹配选项:\n")
	fmt.Printf("  忽略版本: %t\n", defaultOptions.IgnoreVersion)
	fmt.Printf("  允许子版本: %t\n", defaultOptions.AllowSubVersions)
	fmt.Printf("  使用正则表达式: %t\n", defaultOptions.UseRegex)
	fmt.Printf("  使用版本范围: %t\n", defaultOptions.VersionRange)
	fmt.Println()

	// 使用MatchCPE函数测试匹配
	fmt.Printf("目标CPE: %s\n", targetCpe.GetURI())
	fmt.Printf("条件: Vendor=%s, Product=%s\n", criteria.Vendor, criteria.ProductName)
	fmt.Printf("默认选项匹配结果: %t\n", cpe.MatchCPE(criteria, targetCpe, defaultOptions))

	/*
		输出示例:
		========= 使用MatchCPE函数匹配 =========
		默认匹配选项:
		  忽略版本: false
		  允许子版本: true
		  使用正则表达式: false
		  使用版本范围: false

		目标CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		条件: Vendor=microsoft, Product=windows
		默认选项匹配结果: true
	*/

	// 示例3: 忽略版本匹配
	fmt.Println("\n========= 忽略版本匹配 =========")

	// 创建两个版本不同的CPE
	cpeV10, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析CPE v10失败: %v", err)
	}

	cpeV11, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析CPE v11失败: %v", err)
	}

	// 标准匹配（考虑版本）
	fmt.Printf("CPE v10: %s\n", cpeV10.GetURI())
	fmt.Printf("CPE v11: %s\n", cpeV11.GetURI())
	fmt.Printf("标准匹配结果: %t\n", cpeV10.Match(cpeV11))

	// 忽略版本的匹配选项
	ignoreVersionOptions := &cpe.MatchOptions{
		IgnoreVersion: true,
	}

	// 使用MatchCPE函数忽略版本进行匹配
	fmt.Printf("忽略版本匹配结果: %t\n", cpe.MatchCPE(cpeV10, cpeV11, ignoreVersionOptions))

	/*
		输出示例:
		========= 忽略版本匹配 =========
		CPE v10: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		CPE v11: cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*
		标准匹配结果: false
		忽略版本匹配结果: true
	*/

	// 示例4: 版本范围匹配
	fmt.Println("\n========= 版本范围匹配 =========")

	// 创建版本3.5的CPE
	cpeVersion, err := cpe.ParseCpe23("cpe:2.3:a:apache:log4j:3.5:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析版本CPE失败: %v", err)
	}

	// 创建版本范围匹配选项
	versionRangeOptions := &cpe.MatchOptions{
		VersionRange: true,
		MinVersion:   "3.0",
		MaxVersion:   "4.0",
	}

	// 创建匹配条件
	versionCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "apache",
		ProductName: "log4j",
	}

	// 检查版本范围匹配
	fmt.Printf("CPE版本: %s\n", cpeVersion.GetURI())
	fmt.Printf("版本范围: %s 到 %s\n", versionRangeOptions.MinVersion, versionRangeOptions.MaxVersion)
	fmt.Printf("版本范围匹配结果: %t\n", cpe.MatchCPE(versionCriteria, cpeVersion, versionRangeOptions))

	// 改变版本范围
	versionRangeOptions.MinVersion = "2.0"
	versionRangeOptions.MaxVersion = "3.0"
	fmt.Printf("新版本范围: %s 到 %s\n", versionRangeOptions.MinVersion, versionRangeOptions.MaxVersion)
	fmt.Printf("新版本范围匹配结果: %t\n", cpe.MatchCPE(versionCriteria, cpeVersion, versionRangeOptions))

	/*
		输出示例:
		========= 版本范围匹配 =========
		CPE版本: cpe:2.3:a:apache:log4j:3.5:*:*:*:*:*:*:*
		版本范围: 3.0 到 4.0
		版本范围匹配结果: true
		新版本范围: 2.0 到 3.0
		新版本范围匹配结果: false
	*/

	// 示例5: 使用正则表达式匹配
	fmt.Println("\n========= 使用正则表达式匹配 =========")

	// 创建目标CPE
	targetRegexCpe, err := cpe.ParseCpe23("cpe:2.3:a:spring-projects:spring-framework:5.3.20:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析正则表达式匹配目标CPE失败: %v", err)
	}

	// 创建使用正则表达式的匹配选项
	regexOptions := &cpe.MatchOptions{
		UseRegex: true,
	}

	// 创建使用正则表达式的匹配条件
	regexCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "spring.*",
		ProductName: "spring-.*",
	}

	// 检查正则表达式匹配
	fmt.Printf("目标CPE: %s\n", targetRegexCpe.GetURI())
	fmt.Printf("正则条件: Vendor=%s, Product=%s\n", regexCriteria.Vendor, regexCriteria.ProductName)
	fmt.Printf("正则匹配结果: %t\n", cpe.MatchCPE(regexCriteria, targetRegexCpe, regexOptions))

	/*
		输出示例:
		========= 使用正则表达式匹配 =========
		目标CPE: cpe:2.3:a:spring-projects:spring-framework:5.3.20:*:*:*:*:*:*:*
		正则条件: Vendor=spring.*, Product=spring-.*
		正则匹配结果: true
	*/
}

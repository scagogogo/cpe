package main

import (
	"fmt"
	"log"

	"github.com/scagogogo/cpe"
)

func main() {
	// CPE适用性语言示例
	// 展示如何构建简单的CPE匹配规则和匹配集合

	fmt.Println("========= CPE适用性语言示例 =========")

	// 创建一些CPE对象作为匹配目标
	cpeWindows10, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Windows 10 CPE失败: %v", err)
	}

	cpeWindows11, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Windows 11 CPE失败: %v", err)
	}

	cpeAcrobat, err := cpe.ParseCpe23("cpe:2.3:a:adobe:acrobat_reader:dc:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Acrobat Reader CPE失败: %v", err)
	}

	cpeJava8, err := cpe.ParseCpe23("cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Java 8 CPE失败: %v", err)
	}

	// 示例1: 基本CPE匹配
	fmt.Println("\n===== 示例1: 基本CPE匹配 =====")

	// 创建匹配条件
	windowsCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
	}

	acrobatCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "adobe",
		ProductName: "acrobat_reader",
	}

	// 测试单个CPE匹配
	fmt.Printf("Windows 10 匹配Windows条件: %t\n", cpe.MatchCPE(windowsCriteria, cpeWindows10, nil))
	fmt.Printf("Windows 11 匹配Windows条件: %t\n", cpe.MatchCPE(windowsCriteria, cpeWindows11, nil))
	fmt.Printf("Acrobat Reader 匹配Windows条件: %t\n", cpe.MatchCPE(windowsCriteria, cpeAcrobat, nil))
	fmt.Printf("Java 8 匹配Windows条件: %t\n", cpe.MatchCPE(windowsCriteria, cpeJava8, nil))

	fmt.Printf("\nAcrobat Reader 匹配Acrobat条件: %t\n", cpe.MatchCPE(acrobatCriteria, cpeAcrobat, nil))

	/*
		输出示例:
		===== 示例1: 基本CPE匹配 =====
		Windows 10 匹配Windows条件: true
		Windows 11 匹配Windows条件: true
		Acrobat Reader 匹配Windows条件: false
		Java 8 匹配Windows条件: false

		Acrobat Reader 匹配Acrobat条件: true
	*/

	// 示例2: 版本范围匹配
	fmt.Println("\n===== 示例2: 版本范围匹配 =====")

	// 创建针对Windows 7到10的匹配条件
	windowsVersionOptions := &cpe.MatchOptions{
		VersionRange: true,
		MinVersion:   "7",
		MaxVersion:   "10",
	}

	// 测试不同Windows版本
	fmt.Printf("Windows版本范围匹配(7到10):\n")
	fmt.Printf("Windows 10 匹配: %t\n", cpe.MatchCPE(windowsCriteria, cpeWindows10, windowsVersionOptions))
	fmt.Printf("Windows 11 匹配: %t\n", cpe.MatchCPE(windowsCriteria, cpeWindows11, windowsVersionOptions))

	/*
		输出示例:
		===== 示例2: 版本范围匹配 =====
		Windows版本范围匹配(7到10):
		Windows 10 匹配: true
		Windows 11 匹配: false
	*/

	// 示例3: 忽略版本匹配
	fmt.Println("\n===== 示例3: 忽略版本匹配 =====")

	ignoreVersionOptions := &cpe.MatchOptions{
		IgnoreVersion: true,
	}

	// 创建特定版本匹配条件
	windows10Criteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	// 测试忽略版本匹配
	fmt.Printf("Windows 10条件 (标准匹配):\n")
	fmt.Printf("Windows 10 匹配: %t\n", cpe.MatchCPE(windows10Criteria, cpeWindows10, nil))
	fmt.Printf("Windows 11 匹配: %t\n", cpe.MatchCPE(windows10Criteria, cpeWindows11, nil))

	fmt.Printf("\nWindows 10条件 (忽略版本匹配):\n")
	fmt.Printf("Windows 10 匹配: %t\n", cpe.MatchCPE(windows10Criteria, cpeWindows10, ignoreVersionOptions))
	fmt.Printf("Windows 11 匹配: %t\n", cpe.MatchCPE(windows10Criteria, cpeWindows11, ignoreVersionOptions))

	/*
		输出示例:
		===== 示例3: 忽略版本匹配 =====
		Windows 10条件 (标准匹配):
		Windows 10 匹配: true
		Windows 11 匹配: false

		Windows 10条件 (忽略版本匹配):
		Windows 10 匹配: true
		Windows 11 匹配: true
	*/

	// 示例4: 正则表达式匹配
	fmt.Println("\n===== 示例4: 正则表达式匹配 =====")

	// 创建使用正则表达式的匹配条件
	regexCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "micro.*",
		ProductName: "win.*",
	}

	regexOptions := &cpe.MatchOptions{
		UseRegex: true,
	}

	// 测试正则表达式匹配
	fmt.Printf("正则条件: Vendor=%s, Product=%s\n", regexCriteria.Vendor, regexCriteria.ProductName)
	fmt.Printf("Windows 10 匹配正则条件: %t\n", cpe.MatchCPE(regexCriteria, cpeWindows10, regexOptions))
	fmt.Printf("Windows 11 匹配正则条件: %t\n", cpe.MatchCPE(regexCriteria, cpeWindows11, regexOptions))
	fmt.Printf("Acrobat Reader 匹配正则条件: %t\n", cpe.MatchCPE(regexCriteria, cpeAcrobat, regexOptions))

	/*
		输出示例:
		===== 示例4: 正则表达式匹配 =====
		正则条件: Vendor=micro.*, Product=win.*
		Windows 10 匹配正则条件: true
		Windows 11 匹配正则条件: true
		Acrobat Reader 匹配正则条件: false
	*/

	// 示例5: 手动实现简单的集合匹配逻辑
	fmt.Println("\n===== 示例5: 手动实现简单的集合匹配逻辑 =====")

	// 创建CPE集合
	cpeSet := []*cpe.CPE{cpeWindows10, cpeWindows11, cpeAcrobat, cpeJava8}

	// 手动实现AND匹配 (都必须匹配)
	matchAND := func(cpes []*cpe.CPE, criteria1, criteria2 *cpe.CPE, options *cpe.MatchOptions) bool {
		match1Found := false
		match2Found := false

		for _, c := range cpes {
			if cpe.MatchCPE(criteria1, c, options) {
				match1Found = true
			}
			if cpe.MatchCPE(criteria2, c, options) {
				match2Found = true
			}
		}

		return match1Found && match2Found
	}

	// 手动实现OR匹配 (任一匹配即可)
	matchOR := func(cpes []*cpe.CPE, criteria1, criteria2 *cpe.CPE, options *cpe.MatchOptions) bool {
		for _, c := range cpes {
			if cpe.MatchCPE(criteria1, c, options) || cpe.MatchCPE(criteria2, c, options) {
				return true
			}
		}
		return false
	}

	// 测试自定义匹配逻辑
	fmt.Printf("集合包含Windows AND Acrobat: %t\n",
		matchAND(cpeSet, windowsCriteria, acrobatCriteria, nil))

	fmt.Printf("集合包含Windows OR Acrobat: %t\n",
		matchOR(cpeSet, windowsCriteria, acrobatCriteria, nil))

	// 创建Java匹配条件
	javaCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "oracle",
		ProductName: "java",
	}

	fmt.Printf("集合包含Windows AND Java: %t\n",
		matchAND(cpeSet, windowsCriteria, javaCriteria, nil))

	// 创建没有匹配项的条件
	unknownCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "unknown",
		ProductName: "product",
	}

	fmt.Printf("集合包含Windows AND Unknown: %t\n",
		matchAND(cpeSet, windowsCriteria, unknownCriteria, nil))

	fmt.Printf("集合包含Windows OR Unknown: %t\n",
		matchOR(cpeSet, windowsCriteria, unknownCriteria, nil))

	/*
		输出示例:
		===== 示例5: 手动实现简单的集合匹配逻辑 =====
		集合包含Windows AND Acrobat: true
		集合包含Windows OR Acrobat: true
		集合包含Windows AND Java: true
		集合包含Windows AND Unknown: false
		集合包含Windows OR Unknown: true
	*/
}

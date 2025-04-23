package main

import (
	"fmt"
	"log"

	"github.com/scagogogo/cpe"
	"github.com/scagogogo/versions"
)

func main() {
	// 版本比较是CPE库中的重要功能
	// 用于比较软件版本的大小，判断版本范围匹配等

	// 示例1: 基本版本比较
	fmt.Println("========= 基本版本比较 =========")

	// 比较不同格式的版本号
	v1Str := "1.0.0"
	v2Str := "2.0.0"
	v3Str := "1.0.5"

	// 使用versions库比较版本
	// 返回值: -1 (v1 < v2), 0 (v1 == v2), 1 (v1 > v2)
	v1 := versions.NewVersion(v1Str)
	v2 := versions.NewVersion(v2Str)
	v3 := versions.NewVersion(v3Str)

	fmt.Printf("比较 %s 和 %s: %d\n", v1Str, v2Str, v1.CompareTo(v2))
	fmt.Printf("比较 %s 和 %s: %d\n", v2Str, v1Str, v2.CompareTo(v1))
	fmt.Printf("比较 %s 和 %s: %d\n", v1Str, v3Str, v1.CompareTo(v3))

	/*
		输出示例:
		========= 基本版本比较 =========
		比较 1.0.0 和 2.0.0: -1
		比较 2.0.0 和 1.0.0: 1
		比较 1.0.0 和 1.0.5: -1
	*/

	// 示例2: 版本相等性比较
	fmt.Println("\n========= 版本相等性比较 =========")

	// 比较相同版本
	v4Str := "1.0.0"
	v5Str := "1.0.0"
	v4 := versions.NewVersion(v4Str)
	v5 := versions.NewVersion(v5Str)
	fmt.Printf("比较 %s 和 %s: %d\n", v4Str, v5Str, v4.CompareTo(v5))

	// 比较通配符版本（versions库可能不直接支持"*"通配符，需要特殊处理）
	v6Str := "*"
	fmt.Printf("比较 %s 和 %s: 特殊情况，被视为相等\n", v1Str, v6Str)
	fmt.Printf("比较 %s 和 %s: 特殊情况，被视为相等\n", v6Str, v2Str)

	/*
		输出示例:
		========= 版本相等性比较 =========
		比较 1.0.0 和 1.0.0: 0
		比较 1.0.0 和 *: 特殊情况，被视为相等
		比较 * 和 2.0.0: 特殊情况，被视为相等
	*/

	// 示例3: 比较不同长度的版本号
	fmt.Println("\n========= 比较不同长度的版本号 =========")

	vAStr := "1.0"
	vBStr := "1.0.0"
	vCStr := "1.0.1"
	vA := versions.NewVersion(vAStr)
	vB := versions.NewVersion(vBStr)
	vC := versions.NewVersion(vCStr)

	fmt.Printf("比较 %s 和 %s: %d\n", vAStr, vBStr, vA.CompareTo(vB))
	fmt.Printf("比较 %s 和 %s: %d\n", vBStr, vAStr, vB.CompareTo(vA))
	fmt.Printf("比较 %s 和 %s: %d\n", vAStr, vCStr, vA.CompareTo(vC))

	/*
		输出示例:
		========= 比较不同长度的版本号 =========
		比较 1.0 和 1.0.0: 0
		比较 1.0.0 和 1.0: 0
		比较 1.0 和 1.0.1: -1
	*/

	// 示例4: 比较包含字母的版本号
	fmt.Println("\n========= 比较包含字母的版本号 =========")

	vAlphaStr := "1.0-alpha"
	vBetaStr := "1.0-beta"
	vRCStr := "1.0-rc"
	vFinalStr := "1.0"
	vAlpha := versions.NewVersion(vAlphaStr)
	vBeta := versions.NewVersion(vBetaStr)
	vRC := versions.NewVersion(vRCStr)
	vFinal := versions.NewVersion(vFinalStr)

	fmt.Printf("比较 %s 和 %s: %d\n", vAlphaStr, vBetaStr, vAlpha.CompareTo(vBeta))
	fmt.Printf("比较 %s 和 %s: %d\n", vBetaStr, vRCStr, vBeta.CompareTo(vRC))
	fmt.Printf("比较 %s 和 %s: %d\n", vRCStr, vFinalStr, vRC.CompareTo(vFinal))

	/*
		输出示例:
		========= 比较包含字母的版本号 =========
		比较 1.0-alpha 和 1.0-beta: -1
		比较 1.0-beta 和 1.0-rc: -1
		比较 1.0-rc 和 1.0: -1
	*/

	// 示例5: 在CPE对象中进行版本比较
	fmt.Println("\n========= 在CPE对象中进行版本比较 =========")

	// 创建两个不同版本的CPE
	cpe1, err := cpe.ParseCpe23("cpe:2.3:a:apache:tomcat:8.5.20:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析CPE1失败: %v", err)
	}

	cpe2, err := cpe.ParseCpe23("cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析CPE2失败: %v", err)
	}

	// 检查版本匹配
	// 创建版本范围匹配选项
	options := &cpe.MatchOptions{
		VersionRange: true,
		MinVersion:   "8.0.0",
		MaxVersion:   "9.0.0",
	}

	// 创建适用于版本范围的条件
	criteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "apache",
		ProductName: "tomcat",
	}

	// 检查版本范围匹配
	fmt.Printf("CPE1版本: %s\n", cpe1.Version)
	fmt.Printf("CPE2版本: %s\n", cpe2.Version)
	fmt.Printf("版本范围: %s 到 %s\n", options.MinVersion, options.MaxVersion)
	fmt.Printf("CPE1在版本范围内: %t\n", cpe.MatchCPE(criteria, cpe1, options))
	fmt.Printf("CPE2在版本范围内: %t\n", cpe.MatchCPE(criteria, cpe2, options))

	/*
		输出示例:
		========= 在CPE对象中进行版本比较 =========
		CPE1版本: 8.5.20
		CPE2版本: 9.0.0
		版本范围: 8.0.0 到 9.0.0
		CPE1在版本范围内: true
		CPE2在版本范围内: true
	*/

	// 示例6: 设置更严格的版本范围
	fmt.Println("\n========= 设置更严格的版本范围 =========")

	// 修改版本范围
	options.MinVersion = "8.0.0"
	options.MaxVersion = "8.9.0"

	fmt.Printf("新版本范围: %s 到 %s\n", options.MinVersion, options.MaxVersion)
	fmt.Printf("CPE1在新版本范围内: %t\n", cpe.MatchCPE(criteria, cpe1, options))
	fmt.Printf("CPE2在新版本范围内: %t\n", cpe.MatchCPE(criteria, cpe2, options))

	/*
		输出示例:
		========= 设置更严格的版本范围 =========
		新版本范围: 8.0.0 到 8.9.0
		CPE1在新版本范围内: true
		CPE2在新版本范围内: false
	*/

	// 示例7: 使用versions库的高级功能
	fmt.Println("\n========= versions库的高级功能 =========")

	// 版本分组
	versionList := []*versions.Version{
		versions.NewVersion("1.0.0"),
		versions.NewVersion("1.1.0"),
		versions.NewVersion("1.2.0"),
		versions.NewVersion("2.0.0"),
		versions.NewVersion("2.1.0"),
		versions.NewVersion("3.0.0-beta"),
	}

	// 对版本列表排序
	sortedVersions := versions.SortVersionSlice(versionList)
	fmt.Println("排序后的版本列表:")
	for i, v := range sortedVersions {
		fmt.Printf("%d. %s\n", i+1, v.Raw)
	}

	// 按主版本号分组
	groupMap := versions.Group(versionList)
	fmt.Printf("\n版本分组结果 (共%d个组):\n", len(groupMap))
	for groupID, group := range groupMap {
		// 使用Versions()获取所有版本，然后计算长度
		versions := group.Versions()
		fmt.Printf("版本组 %s: 包含%d个版本\n", groupID, len(versions))
	}
}

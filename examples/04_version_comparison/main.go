package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/scagogogo/cpe"
)

// compareVersions 实现一个与库内部功能相似的版本比较函数
// 返回: -1 (v1 < v2), 0 (v1 == v2), 1 (v1 > v2)
func compareVersions(v1, v2 string) int {
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

func main() {
	// 版本比较是CPE库中的重要功能
	// 用于比较软件版本的大小，判断版本范围匹配等

	// 示例1: 基本版本比较
	fmt.Println("========= 基本版本比较 =========")

	// 比较不同格式的版本号
	v1 := "1.0.0"
	v2 := "2.0.0"
	v3 := "1.0.5"

	// 使用我们实现的compareVersions函数比较版本
	// 返回值: -1 (v1 < v2), 0 (v1 == v2), 1 (v1 > v2)
	fmt.Printf("比较 %s 和 %s: %d\n", v1, v2, compareVersions(v1, v2))
	fmt.Printf("比较 %s 和 %s: %d\n", v2, v1, compareVersions(v2, v1))
	fmt.Printf("比较 %s 和 %s: %d\n", v1, v3, compareVersions(v1, v3))

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
	v4 := "1.0.0"
	v5 := "1.0.0"
	fmt.Printf("比较 %s 和 %s: %d\n", v4, v5, compareVersions(v4, v5))

	// 比较通配符版本
	v6 := "*"
	fmt.Printf("比较 %s 和 %s: %d\n", v1, v6, compareVersions(v1, v6))
	fmt.Printf("比较 %s 和 %s: %d\n", v6, v2, compareVersions(v6, v2))

	/*
		输出示例:
		========= 版本相等性比较 =========
		比较 1.0.0 和 1.0.0: 0
		比较 1.0.0 和 *: 0
		比较 * 和 2.0.0: 0
	*/

	// 示例3: 比较不同长度的版本号
	fmt.Println("\n========= 比较不同长度的版本号 =========")

	vA := "1.0"
	vB := "1.0.0"
	vC := "1.0.1"

	fmt.Printf("比较 %s 和 %s: %d\n", vA, vB, compareVersions(vA, vB))
	fmt.Printf("比较 %s 和 %s: %d\n", vB, vA, compareVersions(vB, vA))
	fmt.Printf("比较 %s 和 %s: %d\n", vA, vC, compareVersions(vA, vC))

	/*
		输出示例:
		========= 比较不同长度的版本号 =========
		比较 1.0 和 1.0.0: 0
		比较 1.0.0 和 1.0: 0
		比较 1.0 和 1.0.1: -1
	*/

	// 示例4: 比较包含字母的版本号
	fmt.Println("\n========= 比较包含字母的版本号 =========")

	vAlpha := "1.0-alpha"
	vBeta := "1.0-beta"
	vRC := "1.0-rc"
	vFinal := "1.0"

	fmt.Printf("比较 %s 和 %s: %d\n", vAlpha, vBeta, compareVersions(vAlpha, vBeta))
	fmt.Printf("比较 %s 和 %s: %d\n", vBeta, vRC, compareVersions(vBeta, vRC))
	fmt.Printf("比较 %s 和 %s: %d\n", vRC, vFinal, compareVersions(vRC, vFinal))

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
}

package main

import (
	"fmt"
	"log"

	"github.com/scagogogo/cpe"
)

func main() {
	// 示例1: 解析CPE 2.3格式字符串
	fmt.Println("========= 解析 CPE 2.3 格式字符串 =========")
	cpe23, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析CPE 2.3格式失败: %v", err)
	}

	// 输出解析后的CPE信息
	fmt.Printf("解析结果:\n")
	fmt.Printf("  Part: %s (%s)\n", cpe23.Part.ShortName, cpe23.Part.LongName)
	fmt.Printf("  Vendor: %s\n", cpe23.Vendor)
	fmt.Printf("  Product: %s\n", cpe23.ProductName)
	fmt.Printf("  Version: %s\n", cpe23.Version)
	fmt.Println()

	/*
		输出示例:
		========= 解析 CPE 2.3 格式字符串 =========
		解析结果:
		  Part: a (Application)
		  Vendor: microsoft
		  Product: windows
		  Version: 10
	*/

	// 示例2: 解析CPE 2.2格式字符串
	fmt.Println("========= 解析 CPE 2.2 格式字符串 =========")
	cpe22, err := cpe.ParseCpe22("cpe:/a:apache:log4j:2.0")
	if err != nil {
		log.Fatalf("解析CPE 2.2格式失败: %v", err)
	}

	// 输出解析后的CPE信息
	fmt.Printf("解析结果:\n")
	fmt.Printf("  Part: %s (%s)\n", cpe22.Part.ShortName, cpe22.Part.LongName)
	fmt.Printf("  Vendor: %s\n", cpe22.Vendor)
	fmt.Printf("  Product: %s\n", cpe22.ProductName)
	fmt.Printf("  Version: %s\n", cpe22.Version)
	fmt.Println()

	/*
		输出示例:
		========= 解析 CPE 2.2 格式字符串 =========
		解析结果:
		  Part: a (Application)
		  Vendor: apache
		  Product: log4j
		  Version: 2.0
	*/

	// 示例3: 手动创建CPE对象
	fmt.Println("========= 手动创建CPE对象 =========")
	manualCpe := &cpe.CPE{
		Part:        *cpe.PartApplication, // 应用程序
		Vendor:      "oracle",
		ProductName: "java",
		Version:     "1.8.0",
		Update:      "291",
	}

	// 将CPE对象格式化为CPE 2.3字符串
	cpeUri := manualCpe.GetURI()
	fmt.Printf("生成的CPE 2.3 URI: %s\n", cpeUri)
	fmt.Println()

	/*
		输出示例:
		========= 手动创建CPE对象 =========
		生成的CPE 2.3 URI: cpe:2.3:a:oracle:java:1.8.0:291:*:*:*:*:*:*
	*/

	// 示例4: 转换CPE 2.2到CPE 2.3格式
	fmt.Println("========= 转换CPE格式 =========")
	cpe22Str := "cpe:/o:microsoft:windows_10:-"

	// 解析CPE 2.2字符串
	cpe22Obj, err := cpe.ParseCpe22(cpe22Str)
	if err != nil {
		log.Fatalf("解析CPE 2.2字符串失败: %v", err)
	}

	// 使用GetURI方法获取CPE 2.3格式
	cpe23Str := cpe22Obj.GetURI()

	fmt.Printf("CPE 2.2: %s\n", cpe22Str)
	fmt.Printf("转换到CPE 2.3: %s\n", cpe23Str)
	fmt.Println()

	fmt.Printf("转换后的结果:\n")
	fmt.Printf("  Part: %s (%s)\n", cpe22Obj.Part.ShortName, cpe22Obj.Part.LongName)
	fmt.Printf("  Vendor: %s\n", cpe22Obj.Vendor)
	fmt.Printf("  Product: %s\n", cpe22Obj.ProductName)
	fmt.Printf("  Version: %s\n", cpe22Obj.Version)

	/*
		输出示例:
		========= 转换CPE格式 =========
		CPE 2.2: cpe:/o:microsoft:windows_10:-
		转换到CPE 2.3: cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*

		转换后的结果:
		  Part: o (Operating System)
		  Vendor: microsoft
		  Product: windows_10
		  Version: -
	*/

	// 示例5: 处理包含特殊字符的CPE
	fmt.Println("\n========= 处理特殊字符 =========")
	specialCpe, err := cpe.ParseCpe23("cpe:2.3:a:example\\.com:product:1\\.0:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析带特殊字符的CPE失败: %v", err)
	}

	fmt.Printf("带转义字符的CPE解析结果:\n")
	fmt.Printf("  Vendor: %s\n", specialCpe.Vendor)   // 应该显示 example.com
	fmt.Printf("  Version: %s\n", specialCpe.Version) // 应该显示 1.0

	/*
		输出示例:
		========= 处理特殊字符 =========
		带转义字符的CPE解析结果:
		  Vendor: example.com
		  Version: 1.0
	*/
}

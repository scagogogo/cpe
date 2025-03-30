package main

import (
	"fmt"
	"log"

	"github.com/scagogogo/cpe"
)

func main() {
	// WFN (Well-Formed Name) 是CPE的规范化内部表示形式
	// 可以在CPE和WFN之间进行转换

	// 示例1: 从CPE创建WFN
	fmt.Println("========= 从CPE创建WFN =========")

	// 解析CPE字符串
	originalCpe, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析CPE失败: %v", err)
	}

	// 从CPE创建WFN
	wfn := cpe.FromCPE(originalCpe)

	// 输出WFN信息
	fmt.Printf("原始CPE: %s\n", originalCpe.GetURI())
	fmt.Printf("WFN信息:\n")
	fmt.Printf("  Part: %s\n", wfn.Part)
	fmt.Printf("  Vendor: %s\n", wfn.Vendor)
	fmt.Printf("  Product: %s\n", wfn.Product)
	fmt.Printf("  Version: %s\n", wfn.Version)
	fmt.Println()

	/*
		输出示例:
		========= 从CPE创建WFN =========
		原始CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		WFN信息:
		  Part: a
		  Vendor: microsoft
		  Product: windows
		  Version: 10
	*/

	// 示例2: 从WFN创建CPE
	fmt.Println("========= 从WFN创建CPE =========")

	// 从WFN转换回CPE
	convertedCpe := wfn.ToCPE()

	// 检查转换后的CPE
	fmt.Printf("WFN转换后的CPE: %s\n", convertedCpe.GetURI())
	fmt.Printf("与原始CPE相同: %t\n", originalCpe.GetURI() == convertedCpe.GetURI())
	fmt.Println()

	/*
		输出示例:
		========= 从WFN创建CPE =========
		WFN转换后的CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		与原始CPE相同: true
	*/

	// 示例3: 从CPE 2.3字符串创建WFN
	fmt.Println("========= 从CPE 2.3字符串创建WFN =========")

	// 直接从CPE 2.3字符串创建WFN
	cpe23Str := "cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*"
	wfnFromStr, err := cpe.FromCPE23String(cpe23Str)
	if err != nil {
		log.Fatalf("从CPE 2.3字符串创建WFN失败: %v", err)
	}

	// 输出WFN信息
	fmt.Printf("CPE 2.3字符串: %s\n", cpe23Str)
	fmt.Printf("WFN信息:\n")
	fmt.Printf("  Part: %s\n", wfnFromStr.Part)
	fmt.Printf("  Vendor: %s\n", wfnFromStr.Vendor)
	fmt.Printf("  Product: %s\n", wfnFromStr.Product)
	fmt.Printf("  Version: %s\n", wfnFromStr.Version)
	fmt.Println()

	/*
		输出示例:
		========= 从CPE 2.3字符串创建WFN =========
		CPE 2.3字符串: cpe:2.3:a:apache:tomcat:9.0.50:*:*:*:*:*:*:*
		WFN信息:
		  Part: a
		  Vendor: apache
		  Product: tomcat
		  Version: 9.0.50
	*/

	// 示例4: 从CPE 2.2字符串创建WFN
	fmt.Println("========= 从CPE 2.2字符串创建WFN =========")

	// 从CPE 2.2字符串创建WFN
	cpe22Str := "cpe:/a:nginx:nginx:1.20.1"
	wfnFrom22, err := cpe.FromCPE22String(cpe22Str)
	if err != nil {
		log.Fatalf("从CPE 2.2字符串创建WFN失败: %v", err)
	}

	// 输出WFN信息
	fmt.Printf("CPE 2.2字符串: %s\n", cpe22Str)
	fmt.Printf("WFN信息:\n")
	fmt.Printf("  Part: %s\n", wfnFrom22.Part)
	fmt.Printf("  Vendor: %s\n", wfnFrom22.Vendor)
	fmt.Printf("  Product: %s\n", wfnFrom22.Product)
	fmt.Printf("  Version: %s\n", wfnFrom22.Version)
	fmt.Println()

	/*
		输出示例:
		========= 从CPE 2.2字符串创建WFN =========
		CPE 2.2字符串: cpe:/a:nginx:nginx:1.20.1
		WFN信息:
		  Part: a
		  Vendor: nginx
		  Product: nginx
		  Version: 1.20.1
	*/

	// 示例5: WFN与WFN匹配
	fmt.Println("========= WFN匹配 =========")

	// 创建两个WFN对象
	wfn1 := &cpe.WFN{
		Part:    "a",
		Vendor:  "oracle",
		Product: "java",
		Version: "1.8.0",
	}

	wfn2 := &cpe.WFN{
		Part:    "a",
		Vendor:  "oracle",
		Product: "java",
		Version: "*", // 通配符
	}

	// 测试WFN匹配
	fmt.Printf("WFN1: Part=%s, Vendor=%s, Product=%s, Version=%s\n",
		wfn1.Part, wfn1.Vendor, wfn1.Product, wfn1.Version)
	fmt.Printf("WFN2: Part=%s, Vendor=%s, Product=%s, Version=%s\n",
		wfn2.Part, wfn2.Vendor, wfn2.Product, wfn2.Version)
	fmt.Printf("WFN1匹配WFN2: %t\n", wfn1.Match(wfn2))
	fmt.Printf("WFN2匹配WFN1: %t\n", wfn2.Match(wfn1))

	/*
		输出示例:
		========= WFN匹配 =========
		WFN1: Part=a, Vendor=oracle, Product=java, Version=1.8.0
		WFN2: Part=a, Vendor=oracle, Product=java, Version=*
		WFN1匹配WFN2: true
		WFN2匹配WFN1: true
	*/
}

package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/scagogogo/cpe"
)

func main() {
	// CVE映射示例
	// 展示如何将CVE与CPE关联

	fmt.Println("========= CVE映射示例 =========")

	// 创建临时目录用于存储数据
	tempDir, err := os.MkdirTemp("", "cpe-cve-example")
	if err != nil {
		log.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir) // 程序结束时清理目录

	fmt.Printf("使用临时目录存储CVE/CPE数据: %s\n", tempDir)

	// 示例1: 创建CPE和CVE数据
	fmt.Println("\n===== 示例1: 创建CPE和CVE数据 =====")

	// 创建CPE对象
	cpeWin10, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Windows 10 CPE失败: %v", err)
	}

	cpeJava8, err := cpe.ParseCpe23("cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Java 8 CPE失败: %v", err)
	}

	// 创建CVE引用
	cve1 := &cpe.CVEReference{
		CVEID:            "CVE-2020-1234",
		Description:      "Windows 10中的安全漏洞，允许攻击者执行任意代码。",
		PublishedDate:    time.Date(2020, 6, 15, 0, 0, 0, 0, time.UTC),
		LastModifiedDate: time.Now(),
		CVSSScore:        7.8,
		Severity:         "High",
		References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-1234"},
		AffectedCPEs:     []string{cpeWin10.GetURI()},
	}

	cve2 := &cpe.CVEReference{
		CVEID:            "CVE-2020-5678",
		Description:      "Java 8中的远程代码执行漏洞。",
		PublishedDate:    time.Date(2020, 7, 10, 0, 0, 0, 0, time.UTC),
		LastModifiedDate: time.Now(),
		CVSSScore:        9.1,
		Severity:         "Critical",
		References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-5678"},
		AffectedCPEs:     []string{cpeJava8.GetURI()},
	}

	cve3 := &cpe.CVEReference{
		CVEID:            "CVE-2020-9012",
		Description:      "影响多个产品的跨站脚本攻击漏洞。",
		PublishedDate:    time.Date(2020, 8, 5, 0, 0, 0, 0, time.UTC),
		LastModifiedDate: time.Now(),
		CVSSScore:        6.5,
		Severity:         "Medium",
		References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-9012"},
		AffectedCPEs:     []string{cpeWin10.GetURI(), cpeJava8.GetURI()},
	}

	fmt.Printf("创建了3个CVE引用:\n")
	fmt.Printf("1. %s - %s (CVSS: %.1f)\n", cve1.CVEID, cve1.Description, cve1.CVSSScore)
	fmt.Printf("   影响的CPE: %s\n", cve1.AffectedCPEs[0])

	fmt.Printf("2. %s - %s (CVSS: %.1f)\n", cve2.CVEID, cve2.Description, cve2.CVSSScore)
	fmt.Printf("   影响的CPE: %s\n", cve2.AffectedCPEs[0])

	fmt.Printf("3. %s - %s (CVSS: %.1f)\n", cve3.CVEID, cve3.Description, cve3.CVSSScore)
	fmt.Printf("   影响的CPE: %s, %s\n", cve3.AffectedCPEs[0], cve3.AffectedCPEs[1])

	/*
		输出示例:
		===== 示例1: 创建CPE和CVE数据 =====
		创建了3个CVE引用:
		1. CVE-2020-1234 - Windows 10中的安全漏洞，允许攻击者执行任意代码。 (CVSS: 7.8)
		   影响的CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		2. CVE-2020-5678 - Java 8中的远程代码执行漏洞。 (CVSS: 9.1)
		   影响的CPE: cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*
		3. CVE-2020-9012 - 影响多个产品的跨站脚本攻击漏洞。 (CVSS: 6.5)
		   影响的CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*
	*/

	// 示例2: 存储CPE和CVE数据
	fmt.Println("\n===== 示例2: 存储CPE和CVE数据 =====")

	// 初始化文件存储
	storage, err := cpe.NewFileStorage(tempDir, false)
	if err != nil {
		log.Fatalf("初始化文件存储失败: %v", err)
	}

	// 存储CPE
	err = storage.StoreCPE(cpeWin10)
	if err != nil {
		log.Fatalf("存储Windows 10 CPE失败: %v", err)
	}

	err = storage.StoreCPE(cpeJava8)
	if err != nil {
		log.Fatalf("存储Java 8 CPE失败: %v", err)
	}

	// 存储CVE
	err = storage.StoreCVE(cve1)
	if err != nil {
		log.Fatalf("存储CVE-2020-1234失败: %v", err)
	}

	err = storage.StoreCVE(cve2)
	if err != nil {
		log.Fatalf("存储CVE-2020-5678失败: %v", err)
	}

	err = storage.StoreCVE(cve3)
	if err != nil {
		log.Fatalf("存储CVE-2020-9012失败: %v", err)
	}

	fmt.Printf("已存储2个CPE对象和3个CVE引用\n")

	// 显示存储的文件
	files, err := os.ReadDir(tempDir)
	if err != nil {
		log.Fatalf("读取存储目录失败: %v", err)
	}

	fmt.Printf("\n存储目录中的文件:\n")
	for _, file := range files {
		fmt.Printf("- %s\n", file.Name())
	}

	/*
		输出示例:
		===== 示例2: 存储CPE和CVE数据 =====
		已存储2个CPE对象和3个CVE引用

		存储目录中的文件:
		- cpe_2.3_a_microsoft_windows_10_.__.__.__.__
		- cpe_2.3_a_oracle_java_1.8.0_.__.__.__.__
		- cve_CVE-2020-1234.json
		- cve_CVE-2020-5678.json
		- cve_CVE-2020-9012.json
	*/

	// 示例3: 检索CVE
	fmt.Println("\n===== 示例3: 检索CVE =====")

	// 检索存储的CVE
	retrievedCVE, err := storage.RetrieveCVE(cve1.CVEID)
	if err != nil {
		log.Fatalf("检索CVE-2020-1234失败: %v", err)
	}

	fmt.Printf("检索到的CVE: %s\n", retrievedCVE.CVEID)
	fmt.Printf("描述: %s\n", retrievedCVE.Description)
	fmt.Printf("发布日期: %s\n", retrievedCVE.PublishedDate.Format("2006-01-02"))
	fmt.Printf("CVSS评分: %.1f\n", retrievedCVE.CVSSScore)
	fmt.Printf("严重性: %s\n", retrievedCVE.Severity)
	fmt.Printf("影响的CPE: %s\n", retrievedCVE.AffectedCPEs[0])

	/*
		输出示例:
		===== 示例3: 检索CVE =====
		检索到的CVE: CVE-2020-1234
		描述: Windows 10中的安全漏洞，允许攻击者执行任意代码。
		发布日期: 2020-06-15
		CVSS评分: 7.8
		严重性: High
		影响的CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
	*/

	// 示例4: 通过CPE查找CVE
	fmt.Println("\n===== 示例4: 通过CPE查找CVE =====")

	// 查找影响Windows 10的CVE
	windowsCVEs, err := storage.FindCVEsByCPE(cpeWin10)
	if err != nil {
		log.Fatalf("查找Windows 10 CVE失败: %v", err)
	}

	fmt.Printf("影响 %s 的CVE数量: %d\n", cpeWin10.GetURI(), len(windowsCVEs))
	for i, cve := range windowsCVEs {
		fmt.Printf("%d. %s - %s (CVSS: %.1f)\n", i+1, cve.CVEID, cve.Description, cve.CVSSScore)
		fmt.Printf("   发布日期: %s\n", cve.PublishedDate.Format("2006-01-02"))
	}

	/*
		输出示例:
		===== 示例4: 通过CPE查找CVE =====
		影响 cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:* 的CVE数量: 2
		1. CVE-2020-1234 - Windows 10中的安全漏洞，允许攻击者执行任意代码。 (CVSS: 7.8)
		   发布日期: 2020-06-15
		2. CVE-2020-9012 - 影响多个产品的跨站脚本攻击漏洞。 (CVSS: 6.5)
		   发布日期: 2020-08-05
	*/

	// 示例5: 查找高严重性CVE (CVSS >= 7.0)
	fmt.Println("\n===== 示例5: 查找高严重性CVE =====")

	// 获取所有CVE
	allCVEs := []*cpe.CVEReference{cve1, cve2, cve3}

	// 查找高严重性CVE
	var highSeverityCVEs []*cpe.CVEReference
	for _, cve := range allCVEs {
		if cve.CVSSScore >= 7.0 {
			highSeverityCVEs = append(highSeverityCVEs, cve)
		}
	}

	fmt.Printf("高严重性CVE (CVSS >= 7.0) 数量: %d\n", len(highSeverityCVEs))
	for i, cve := range highSeverityCVEs {
		fmt.Printf("%d. %s - %s\n", i+1, cve.CVEID, cve.Description)
		fmt.Printf("   CVSS评分: %.1f\n", cve.CVSSScore)
		fmt.Printf("   影响的CPE数量: %d\n", len(cve.AffectedCPEs))
	}

	/*
		输出示例:
		===== 示例5: 查找高严重性CVE =====
		高严重性CVE (CVSS >= 7.0) 数量: 2
		1. CVE-2020-1234 - Windows 10中的安全漏洞，允许攻击者执行任意代码。
		   CVSS评分: 7.8
		   影响的CPE数量: 1
		2. CVE-2020-5678 - Java 8中的远程代码执行漏洞。
		   CVSS评分: 9.1
		   影响的CPE数量: 1
	*/

	// 示例6: 通过CVE ID查找CPE
	fmt.Println("\n===== 示例6: 通过CVE ID查找CPE =====")

	// 查找CVE-2020-9012影响的CPE
	cpe9012, err := storage.FindCPEsByCVE(cve3.CVEID)
	if err != nil {
		log.Fatalf("查找CVE-2020-9012的CPE失败: %v", err)
	}

	fmt.Printf("CVE-2020-9012影响的CPE数量: %d\n", len(cpe9012))
	for i, cp := range cpe9012 {
		fmt.Printf("%d. %s\n", i+1, cp.GetURI())
		fmt.Printf("   Part: %s (%s)\n", cp.Part.ShortName, cp.Part.LongName)
		fmt.Printf("   Vendor: %s\n", cp.Vendor)
		fmt.Printf("   Product: %s\n", cp.ProductName)
		fmt.Printf("   Version: %s\n", cp.Version)
	}

	/*
		输出示例:
		===== 示例6: 通过CVE ID查找CPE =====
		CVE-2020-9012影响的CPE数量: 2
		1. cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		   Part: a (application)
		   Vendor: microsoft
		   Product: windows
		   Version: 10
		2. cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*
		   Part: a (application)
		   Vendor: oracle
		   Product: java
		   Version: 1.8.0
	*/

	// 示例7: 更新CVE信息
	fmt.Println("\n===== 示例7: 更新CVE信息 =====")

	// 修改CVE信息
	cve1.CVSSScore = 8.2
	cve1.Description = "Windows 10中的高危安全漏洞，允许远程攻击者执行任意代码。"

	// 更新CVE
	err = storage.UpdateCVE(cve1)
	if err != nil {
		log.Fatalf("更新CVE-2020-1234失败: %v", err)
	}

	// 检索更新后的CVE
	updatedCVE, err := storage.RetrieveCVE(cve1.CVEID)
	if err != nil {
		log.Fatalf("检索更新后的CVE失败: %v", err)
	}

	fmt.Printf("更新前的CVE描述: Windows 10中的安全漏洞，允许攻击者执行任意代码。\n")
	fmt.Printf("更新前的CVSS评分: 7.8\n")
	fmt.Printf("\n更新后的CVE: %s\n", updatedCVE.CVEID)
	fmt.Printf("更新后的描述: %s\n", updatedCVE.Description)
	fmt.Printf("更新后的CVSS评分: %.1f\n", updatedCVE.CVSSScore)

	/*
		输出示例:
		===== 示例7: 更新CVE信息 =====
		更新前的CVE描述: Windows 10中的安全漏洞，允许攻击者执行任意代码。
		更新前的CVSS评分: 7.8

		更新后的CVE: CVE-2020-1234
		更新后的描述: Windows 10中的高危安全漏洞，允许远程攻击者执行任意代码。
		更新后的CVSS评分: 8.2
	*/
}

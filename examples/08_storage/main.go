package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/scagogogo/cpe"
)

func main() {
	// CPE存储示例
	// 展示如何使用CPE的存储和持久化功能

	fmt.Println("========= CPE存储示例 =========")

	// 创建临时目录作为数据存储路径
	tempDir, err := os.MkdirTemp("", "cpe-storage-example")
	if err != nil {
		log.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir) // 程序结束时清理目录

	fmt.Printf("使用临时目录存储CPE数据: %s\n", tempDir)

	// 示例1: 创建文件存储
	fmt.Println("\n===== 示例1: 创建文件存储 =====")

	// 初始化文件存储
	storage, err := cpe.NewFileStorage(tempDir, true)
	if err != nil {
		log.Fatalf("初始化文件存储失败: %v", err)
	}

	fmt.Printf("成功创建文件存储\n")

	// 示例2: 存储CPE
	fmt.Println("\n===== 示例2: 存储CPE =====")

	// 创建一些CPE对象
	cpeWin10, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Windows 10 CPE失败: %v", err)
	}

	cpeAcrobat, err := cpe.ParseCpe23("cpe:2.3:a:adobe:acrobat_reader:dc:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Acrobat Reader CPE失败: %v", err)
	}

	cpeJava8, err := cpe.ParseCpe23("cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Java 8 CPE失败: %v", err)
	}

	// 存储CPE
	err = storage.StoreCPE(cpeWin10)
	if err != nil {
		log.Fatalf("存储Windows 10 CPE失败: %v", err)
	}

	err = storage.StoreCPE(cpeAcrobat)
	if err != nil {
		log.Fatalf("存储Acrobat Reader CPE失败: %v", err)
	}

	err = storage.StoreCPE(cpeJava8)
	if err != nil {
		log.Fatalf("存储Java 8 CPE失败: %v", err)
	}

	fmt.Printf("成功存储3个CPE对象\n")
	fmt.Printf("- %s\n", cpeWin10.GetURI())
	fmt.Printf("- %s\n", cpeAcrobat.GetURI())
	fmt.Printf("- %s\n", cpeJava8.GetURI())

	// 查看存储的文件
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
		===== 示例2: 存储CPE =====
		成功存储3个CPE对象
		- cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		- cpe:2.3:a:adobe:acrobat_reader:dc:*:*:*:*:*:*:*
		- cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*

		存储目录中的文件:
		- cpe_2.3_a_adobe_acrobat_reader_dc_.__.__.__.__
		- cpe_2.3_a_microsoft_windows_10_.__.__.__.__
		- cpe_2.3_a_oracle_java_1.8.0_.__.__.__.__
	*/

	// 示例3: 获取CPE
	fmt.Println("\n===== 示例3: 获取CPE =====")

	// 通过URI获取CPE
	retrievedCPE, err := storage.RetrieveCPE(cpeWin10.GetURI())
	if err != nil {
		log.Fatalf("获取Windows 10 CPE失败: %v", err)
	}

	fmt.Printf("成功获取CPE: %s\n", retrievedCPE.GetURI())
	fmt.Printf("Part: %s (%s)\n", retrievedCPE.Part.ShortName, retrievedCPE.Part.LongName)
	fmt.Printf("Vendor: %s\n", retrievedCPE.Vendor)
	fmt.Printf("Product: %s\n", retrievedCPE.ProductName)
	fmt.Printf("Version: %s\n", retrievedCPE.Version)

	/*
		输出示例:
		===== 示例3: 获取CPE =====
		成功获取CPE: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		Part: a (application)
		Vendor: microsoft
		Product: windows
		Version: 10
	*/

	// 示例4: 搜索CPE
	fmt.Println("\n===== 示例4: 搜索CPE =====")

	// 搜索所有CPE
	allCPEs, err := storage.SearchCPE(nil, nil)
	if err != nil {
		log.Fatalf("搜索所有CPE失败: %v", err)
	}

	fmt.Printf("找到%d个CPE:\n", len(allCPEs))
	for _, c := range allCPEs {
		fmt.Printf("- %s\n", c.GetURI())
	}

	// 搜索特定Vendor的CPE
	microsoftCriteria := &cpe.CPE{
		Vendor: "microsoft",
	}

	microsoftCPEs, err := storage.SearchCPE(microsoftCriteria, nil)
	if err != nil {
		log.Fatalf("搜索Microsoft CPE失败: %v", err)
	}

	fmt.Printf("\n找到%d个Microsoft CPE:\n", len(microsoftCPEs))
	for _, c := range microsoftCPEs {
		fmt.Printf("- %s\n", c.GetURI())
	}

	/*
		输出示例:
		===== 示例4: 搜索CPE =====
		找到3个CPE:
		- cpe:2.3:a:adobe:acrobat_reader:dc:*:*:*:*:*:*:*
		- cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
		- cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*

		找到1个Microsoft CPE:
		- cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
	*/

	// 示例5: 更新CPE
	fmt.Println("\n===== 示例5: 更新CPE =====")

	// 修改CPE对象
	cpeWin10.Update = "sp1"

	// 更新存储中的CPE
	err = storage.UpdateCPE(cpeWin10)
	if err != nil {
		log.Fatalf("更新Windows 10 CPE失败: %v", err)
	}

	fmt.Printf("已更新CPE: %s\n", cpeWin10.GetURI())

	// 获取更新后的CPE
	updatedCPE, err := storage.RetrieveCPE(cpeWin10.GetURI())
	if err != nil {
		log.Fatalf("获取更新后的Windows 10 CPE失败: %v", err)
	}

	fmt.Printf("\n更新后的CPE详情:\n")
	fmt.Printf("URI: %s\n", updatedCPE.GetURI())
	fmt.Printf("Part: %s\n", updatedCPE.Part.ShortName)
	fmt.Printf("Vendor: %s\n", updatedCPE.Vendor)
	fmt.Printf("Product: %s\n", updatedCPE.ProductName)
	fmt.Printf("Version: %s\n", updatedCPE.Version)
	fmt.Printf("Update: %s\n", updatedCPE.Update)

	/*
		输出示例:
		===== 示例5: 更新CPE =====
		已更新CPE: cpe:2.3:a:microsoft:windows:10:sp1:*:*:*:*:*:*

		更新后的CPE详情:
		URI: cpe:2.3:a:microsoft:windows:10:sp1:*:*:*:*:*:*
		Part: a
		Vendor: microsoft
		Product: windows
		Version: 10
		Update: sp1
	*/

	// 示例6: 删除CPE
	fmt.Println("\n===== 示例6: 删除CPE =====")

	// 删除CPE
	err = storage.DeleteCPE(cpeAcrobat.GetURI())
	if err != nil {
		log.Fatalf("删除Acrobat Reader CPE失败: %v", err)
	}

	fmt.Printf("成功删除CPE: %s\n", cpeAcrobat.GetURI())

	// 检查删除结果
	remainingCPEs, err := storage.SearchCPE(nil, nil)
	if err != nil {
		log.Fatalf("搜索剩余CPE失败: %v", err)
	}

	fmt.Printf("\n剩余%d个CPE:\n", len(remainingCPEs))
	for _, c := range remainingCPEs {
		fmt.Printf("- %s\n", c.GetURI())
	}

	// 检查删除后的文件
	files, err = os.ReadDir(tempDir)
	if err != nil {
		log.Fatalf("读取存储目录失败: %v", err)
	}

	fmt.Printf("\n删除后存储目录中的文件:\n")
	for _, file := range files {
		fmt.Printf("- %s\n", file.Name())
	}

	/*
		输出示例:
		===== 示例6: 删除CPE =====
		成功删除CPE: cpe:2.3:a:adobe:acrobat_reader:dc:*:*:*:*:*:*:*

		剩余2个CPE:
		- cpe:2.3:a:microsoft:windows:10:sp1:*:*:*:*:*:*
		- cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*

		删除后存储目录中的文件:
		- cpe_2.3_a_microsoft_windows_10_sp1_.__.__.__.__
		- cpe_2.3_a_oracle_java_1.8.0_.__.__.__.__
	*/

	// 示例7: 文件存储的位置和文件名格式
	fmt.Println("\n===== 示例7: 文件存储的位置和文件名格式 =====")

	// 检查单个CPE文件的内容
	cpeFilePath := filepath.Join(tempDir, cpe.URIToFSString(cpeJava8.GetURI()))
	fileContent, err := os.ReadFile(cpeFilePath)
	if err != nil {
		log.Fatalf("读取CPE文件内容失败: %v", err)
	}

	fmt.Printf("CPE文件路径: %s\n", cpeFilePath)
	fmt.Printf("CPE文件内容:\n%s\n", string(fileContent))

	// 打印存储格式转换
	fmt.Printf("\nCPE URI到文件名的转换:\n")
	fmt.Printf("CPE URI: %s\n", cpeJava8.GetURI())
	fmt.Printf("文件名: %s\n", cpe.URIToFSString(cpeJava8.GetURI()))

	fmt.Printf("\n文件名到CPE URI的转换:\n")
	fileName := cpe.URIToFSString(cpeJava8.GetURI())
	uri := cpe.FSStringToURI(fileName)
	fmt.Printf("文件名: %s\n", fileName)
	fmt.Printf("CPE URI: %s\n", uri)

	/*
		输出示例:
		===== 示例7: 文件存储的位置和文件名格式 =====
		CPE文件路径: /tmp/cpe-storage-example123456/cpe_2.3_a_oracle_java_1.8.0_.__.__.__.__
		CPE文件内容:
		{
		  "cpe": {
		    "part": {"shortName": "a", "longName": "application"},
		    "vendor": "oracle",
		    "product": "java",
		    "version": "1.8.0",
		    "update": "*",
		    "edition": "*",
		    "language": "*",
		    "sw_edition": "*",
		    "target_sw": "*",
		    "target_hw": "*",
		    "other": "*"
		  }
		}

		CPE URI到文件名的转换:
		CPE URI: cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*
		文件名: cpe_2.3_a_oracle_java_1.8.0_.__.__.__.__

		文件名到CPE URI的转换:
		文件名: cpe_2.3_a_oracle_java_1.8.0_.__.__.__.__
		CPE URI: cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*
	*/
}

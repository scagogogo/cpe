package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/scagogogo/cpe"
)

func main() {
	// NVD集成示例
	// 展示如何与NVD CPE字典集成

	fmt.Println("========= NVD集成示例 =========")

	// 创建临时目录用于存储数据
	tempDir, err := os.MkdirTemp("", "cpe-nvd-example")
	if err != nil {
		log.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir) // 程序结束时清理目录

	fmt.Printf("使用临时目录存储NVD数据: %s\n", tempDir)

	// 示例1: 初始化NVD数据源
	fmt.Println("\n===== 示例1: 初始化NVD数据源 =====")

	// 在真实场景中，我们会使用NVD API密钥
	// 这里我们只是创建一个简单的数据源
	nvdDataSource := cpe.CreateNVDDataSource("")
	// 配置缓存
	nvdDataSource.SetCacheSettings(&cpe.CacheSettings{
		Enabled:     true,
		Directory:   tempDir,
		ExpiryHours: 24,
	})

	// 显示数据源信息
	fmt.Printf("NVD数据源: %s\n", nvdDataSource.Name)
	fmt.Printf("描述: %s\n", nvdDataSource.Description)
	fmt.Printf("URL: %s\n", nvdDataSource.URL)
	fmt.Printf("缓存已启用: %t\n", nvdDataSource.CacheSettings.Enabled)
	fmt.Printf("缓存目录: %s\n", nvdDataSource.CacheSettings.Directory)
	fmt.Printf("缓存过期时间: %d小时\n", nvdDataSource.CacheSettings.ExpiryHours)

	/*
		输出示例:
		===== 示例1: 初始化NVD数据源 =====
		NVD数据源: NVD CPE Dictionary
		描述: National Vulnerability Database CPE Dictionary
		URL: https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz
		缓存已启用: true
		缓存目录: /tmp/cpe-nvd-example012345678
		缓存过期时间: 24小时
	*/

	// 示例2: 模拟CPE字典
	fmt.Println("\n===== 示例2: 模拟CPE字典 =====")

	// 创建一些CPE条目
	cpeWin10, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Windows 10 CPE失败: %v", err)
	}

	cpeAcrobat, err := cpe.ParseCpe23("cpe:2.3:a:adobe:acrobat_reader:dc:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Acrobat Reader CPE失败: %v", err)
	}

	// 创建CPE字典项
	win10Item := &cpe.CPEItem{
		Name:  cpeWin10.GetURI(),
		Title: "Microsoft Windows 10",
		References: []cpe.Reference{
			{
				URL:  "https://www.microsoft.com/windows/windows-10",
				Type: "Vendor",
			},
		},
		CPE: cpeWin10,
	}

	acrobatItem := &cpe.CPEItem{
		Name:  cpeAcrobat.GetURI(),
		Title: "Adobe Acrobat Reader DC",
		References: []cpe.Reference{
			{
				URL:  "https://acrobat.adobe.com/us/en/acrobat/pdf-reader.html",
				Type: "Vendor",
			},
		},
		CPE: cpeAcrobat,
	}

	// 创建CPE字典
	dictionary := &cpe.CPEDictionary{
		Items:         []*cpe.CPEItem{win10Item, acrobatItem},
		GeneratedAt:   time.Now(),
		SchemaVersion: "2.3",
	}

	fmt.Printf("模拟CPE字典中包含 %d 个CPE条目\n", len(dictionary.Items))
	fmt.Printf("生成日期: %s\n", dictionary.GeneratedAt.Format(time.RFC3339))
	fmt.Printf("Schema版本: %s\n", dictionary.SchemaVersion)

	/*
		输出示例:
		===== 示例2: 模拟CPE字典 =====
		模拟CPE字典中包含 2 个CPE条目
		生成日期: 2023-07-20T14:30:45Z
		Schema版本: 2.3
	*/

	// 示例3: 解析CPE字典
	fmt.Println("\n===== 示例3: 解析CPE字典 =====")

	// 显示字典中的条目
	fmt.Printf("CPE字典条目:\n")
	for i, item := range dictionary.Items {
		fmt.Printf("%d. %s - %s\n", i+1, item.Name, item.Title)

		// 显示引用
		if len(item.References) > 0 {
			fmt.Printf("   引用:\n")
			for j, ref := range item.References {
				fmt.Printf("   %d. %s (%s)\n", j+1, ref.URL, ref.Type)
			}
		}
	}

	/*
		输出示例:
		===== 示例3: 解析CPE字典 =====
		CPE字典条目:
		1. cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:* - Microsoft Windows 10
		   引用:
		   1. https://www.microsoft.com/windows/windows-10 (Vendor)
		2. cpe:2.3:a:adobe:acrobat_reader:dc:*:*:*:*:*:*:* - Adobe Acrobat Reader DC
		   引用:
		   1. https://acrobat.adobe.com/us/en/acrobat/pdf-reader.html (Vendor)
	*/

	// 示例4: 存储CPE字典到本地存储
	fmt.Println("\n===== 示例4: 存储CPE字典到本地存储 =====")

	// 初始化文件存储
	storage, err := cpe.NewFileStorage(tempDir, true)
	if err != nil {
		log.Fatalf("初始化文件存储失败: %v", err)
	}

	// 存储字典
	err = storage.StoreDictionary(dictionary)
	if err != nil {
		log.Fatalf("存储字典失败: %v", err)
	}

	// 存储最后更新时间
	err = storage.StoreModificationTimestamp("dictionary_last_updated", time.Now())
	if err != nil {
		log.Fatalf("存储时间戳失败: %v", err)
	}

	// 检查存储文件
	dictFilePath := filepath.Join(tempDir, "dictionary.json")
	fileInfo, err := os.Stat(dictFilePath)
	if err != nil {
		// 尝试以不同的路径查找文件
		dictFilePath = storage.DictionaryFilePath()
		fileInfo, err = os.Stat(dictFilePath)
		if err != nil {
			log.Fatalf("获取字典文件信息失败: %v", err)
		}
	}

	fmt.Printf("字典成功存储到文件: %s\n", dictFilePath)
	fmt.Printf("文件大小: %d 字节\n", fileInfo.Size())
	fmt.Printf("修改时间: %s\n", fileInfo.ModTime().Format(time.RFC3339))

	/*
		输出示例:
		===== 示例4: 存储CPE字典到本地存储 =====
		字典成功存储到文件: /tmp/cpe-nvd-example012345678/dictionary.json
		文件大小: 1205 字节
		修改时间: 2023-07-20T14:30:45Z
	*/

	// 示例5: 从本地存储检索CPE字典
	fmt.Println("\n===== 示例5: 从本地存储检索CPE字典 =====")

	// 检索字典
	retrievedDict, err := storage.RetrieveDictionary()
	if err != nil {
		log.Fatalf("检索字典失败: %v", err)
	}

	fmt.Printf("成功检索字典\n")
	fmt.Printf("字典条目数量: %d\n", len(retrievedDict.Items))
	fmt.Printf("生成日期: %s\n", retrievedDict.GeneratedAt.Format(time.RFC3339))

	/*
		输出示例:
		===== 示例5: 从本地存储检索CPE字典 =====
		成功检索字典
		字典条目数量: 2
		生成日期: 2023-07-20T14:30:45Z
	*/

	// 示例6: 搜索CPE字典
	fmt.Println("\n===== 示例6: 搜索CPE字典 =====")

	// 创建搜索条件
	searchCriteria, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("创建搜索条件失败: %v", err)
	}

	// 搜索字典
	matchCount := 0
	fmt.Printf("搜索所有Microsoft产品:\n")
	fmt.Printf("搜索条件: %s\n", searchCriteria.GetURI())
	fmt.Printf("匹配结果:\n")

	for _, item := range retrievedDict.Items {
		if cpe.MatchCPE(searchCriteria, item.CPE, nil) {
			matchCount++
			fmt.Printf("%d. %s - %s\n", matchCount, item.Name, item.Title)
		}
	}

	fmt.Printf("共找到 %d 个匹配项\n", matchCount)

	/*
		输出示例:
		===== 示例6: 搜索CPE字典 =====
		搜索所有Microsoft产品:
		搜索条件: cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*
		匹配结果:
		1. cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:* - Microsoft Windows 10
		共找到 1 个匹配项
	*/

	// 示例7: 管理更新时间戳
	fmt.Println("\n===== 示例7: 管理更新时间戳 =====")

	// 检索上次更新时间
	lastUpdateTime, err := storage.RetrieveModificationTimestamp("dictionary_last_updated")
	if err != nil {
		log.Printf("无法检索上次更新时间: %v", err)
		lastUpdateTime = time.Time{} // 使用零值时间
	}

	// 检查是否需要更新
	now := time.Now()
	needsUpdate := true

	if !lastUpdateTime.IsZero() {
		// 如果上次更新时间不是零值，检查是否已经超过24小时
		timeSinceLastUpdate := now.Sub(lastUpdateTime)
		needsUpdate = timeSinceLastUpdate.Hours() >= 24

		fmt.Printf("上次更新时间: %s\n", lastUpdateTime.Format(time.RFC3339))
		fmt.Printf("距上次更新: %.2f 小时\n", timeSinceLastUpdate.Hours())
	} else {
		fmt.Println("没有找到上次更新时间记录")
	}

	fmt.Printf("是否需要更新: %t\n", needsUpdate)

	// 模拟执行更新
	if needsUpdate {
		fmt.Println("执行字典更新...")

		// 在实际场景中，这里会从NVD下载新数据
		// 为了演示，我们只更新时间戳
		err = storage.StoreModificationTimestamp("dictionary_last_updated", now)
		if err != nil {
			log.Fatalf("更新时间戳失败: %v", err)
		}

		fmt.Printf("字典已更新，新的更新时间: %s\n", now.Format(time.RFC3339))
	} else {
		fmt.Println("字典已是最新，无需更新")
	}

	/*
		输出示例:
		===== 示例7: 管理更新时间戳 =====
		上次更新时间: 2023-07-20T14:30:45Z
		距上次更新: 0.05 小时
		是否需要更新: false
		字典已是最新，无需更新
	*/
}

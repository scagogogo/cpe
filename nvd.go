package cpe

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/scagogogo/cve"
)

/**
 * NVDFeedOptions 定义美国国家漏洞数据库(NVD)数据Feed的下载和处理选项
 *
 * 该结构体包含配置NVD数据Feed获取过程的各项参数，包括缓存策略、并发控制、
 * 进度显示以及HTTP客户端自定义等。这些选项影响数据获取的效率、资源消耗和用户体验。
 *
 * 字段说明:
 *   - CacheDir: 缓存目录路径，用于存储下载的NVD数据Feed文件
 *   - CacheMaxAge: 缓存有效期（小时），超过此时间将重新下载数据
 *   - MaxConcurrentDownloads: 最大并发下载数，控制同时进行的下载任务数量
 *   - ShowProgress: 是否显示下载进度信息
 *   - HTTPClient: 自定义HTTP客户端，可设置超时、代理等参数
 *
 * 使用示例:
 *   ```go
 *   // 使用默认选项
 *   options := cpe.DefaultNVDFeedOptions()
 *
 *   // 自定义选项
 *   customOptions := &cpe.NVDFeedOptions{
 *       CacheDir: "/tmp/my-nvd-cache",
 *       CacheMaxAge: 48,                     // 缓存48小时有效
 *       MaxConcurrentDownloads: 5,           // 最多5个并发下载
 *       ShowProgress: true,
 *       HTTPClient: &http.Client{
 *           Timeout: 120 * time.Second,      // 设置2分钟超时
 *           Transport: &http.Transport{
 *               Proxy: http.ProxyFromEnvironment,
 *               MaxIdleConns: 10,
 *               IdleConnTimeout: 30 * time.Second,
 *           },
 *       },
 *   }
 *
 *   // 下载NVD数据
 *   data, err := cpe.DownloadAllNVDData(customOptions)
 *   if err != nil {
 *       log.Fatalf("下载NVD数据失败: %v", err)
 *   }
 *   ```
 *
 * 注意事项:
 *   - 缓存目录需要有写入权限
 *   - 网络环境不稳定时可能需要增加HTTP客户端的超时时间
 *   - 较大的并发下载数可能导致NVD服务器拒绝请求，请谨慎设置
 */
type NVDFeedOptions struct {
	// CacheDir 缓存目录路径，用于存储下载的NVD数据Feed文件
	// 默认为系统临时目录下的"cpe-cache"子目录
	CacheDir string

	// CacheMaxAge 缓存最大有效期（小时）
	// 超过此时间后，缓存将被视为过期，需要重新下载数据
	// 默认为24小时
	CacheMaxAge int

	// MaxConcurrentDownloads 最大并发下载数
	// 控制同时进行的下载任务数量，避免过多并发请求导致资源耗尽或被服务器限制
	// 默认为3
	MaxConcurrentDownloads int

	// ShowProgress 是否显示进度信息
	// 设置为true时，下载过程中会在标准输出中显示进度信息
	// 默认为true
	ShowProgress bool

	// HTTPClient 用户自定义的HTTP客户端
	// 可配置超时时间、代理设置、传输参数等
	// 默认为带有60秒超时的标准HTTP客户端
	HTTPClient *http.Client
}

// 默认NVD CPE Feed URL
const (
	// NVDCPEMatch NVD CPE匹配数据Feed URL
	// 包含CPE和CVE之间的映射关系
	NVDCPEMatch = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz"

	// NVDCPEFeedURL NVD CPE数据Feed URL
	// 包含所有CPE条目的详细信息
	NVDCPEFeedURL = "https://nvd.nist.gov/feeds/json/cpe/1.0/nvdcpe-1.0.json.gz"

	// NVDCPEDict NVD CPE字典XML URL
	// 包含官方CPE字典的XML格式数据
	NVDCPEDict = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"

	// NVDCVERecentURL NVD最近CVE数据Feed URL
	// 包含最近添加或更新的CVE条目
	NVDCVERecentURL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
)

/**
 * DefaultNVDFeedOptions 返回配置了合理默认值的NVD Feed下载选项
 *
 * 此函数创建并返回一个NVDFeedOptions结构体实例，其中所有字段都设置了适合大多数使用场景的默认值。
 * 用户可以在此基础上根据需要修改特定字段，避免手动设置所有参数的麻烦。
 *
 * @return *NVDFeedOptions 配置了默认值的NVD Feed下载选项
 *
 * 默认配置:
 *   - CacheDir: 系统临时目录下的"cpe-cache"子目录
 *   - CacheMaxAge: 24小时
 *   - MaxConcurrentDownloads: 3
 *   - ShowProgress: true
 *   - HTTPClient: 带有60秒超时的标准HTTP客户端
 *
 * 使用示例:
 *   ```go
 *   // 获取默认选项
 *   options := cpe.DefaultNVDFeedOptions()
 *
 *   // 只修改缓存相关设置，保留其他默认值
 *   options.CacheDir = "/var/cache/nvd-data"
 *   options.CacheMaxAge = 12  // 降低缓存有效期至12小时
 *
 *   // 使用修改后的选项下载数据
 *   dict, err := cpe.DownloadAndParseCPEDict(options)
 *   if err != nil {
 *       log.Fatalf("下载CPE字典失败: %v", err)
 *   }
 *   ```
 *
 * 注意事项:
 *   - 返回的是指针类型，可以直接修改其字段值
 *   - 默认HTTP客户端设置的超时时间为60秒，对于网络条件较差的环境可能需要增加
 */
func DefaultNVDFeedOptions() *NVDFeedOptions {
	return &NVDFeedOptions{
		CacheDir:               filepath.Join(os.TempDir(), "cpe-cache"),
		CacheMaxAge:            24,
		MaxConcurrentDownloads: 3,
		ShowProgress:           true,
		HTTPClient:             &http.Client{Timeout: 60 * time.Second},
	}
}

/**
 * NVDCPEData 集成了从NVD获取的CPE和CVE关联数据
 *
 * 此结构体封装了从美国国家漏洞数据库(NVD)获取的多种数据，包括CPE字典和CPE与CVE之间的映射关系。
 * 它为应用程序提供了一个统一的接口来获取漏洞信息，便于进行安全评估和漏洞管理。
 *
 * 字段说明:
 *   - CPEDictionary: CPE字典，包含所有正式注册的CPE条目及其详细信息
 *   - CPEMatchData: CPE与CVE的映射关系数据，用于查找特定CPE相关的漏洞或特定漏洞影响的CPE
 *   - DownloadTime: 数据下载的时间戳，便于判断数据的新鲜度
 *
 * 使用示例:
 *   ```go
 *   // 下载NVD数据
 *   options := cpe.DefaultNVDFeedOptions()
 *   nvdData, err := cpe.DownloadAllNVDData(options)
 *   if err != nil {
 *       log.Fatalf("下载NVD数据失败: %v", err)
 *   }
 *
 *   // 查找特定CPE相关的CVE
 *   windowsCPE, _ := cpe.ParseCpe23("cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*")
 *   cves := nvdData.FindCVEsForCPE(windowsCPE)
 *   fmt.Printf("找到%d个影响Windows 10的CVE\n", len(cves))
 *   for i, cveID := range cves[:5] { // 只显示前5个
 *       fmt.Printf("%d. %s\n", i+1, cveID)
 *   }
 *
 *   // 查找特定CVE影响的CPE
 *   cveID := "CVE-2021-44228" // Log4Shell
 *   affectedCPEs := nvdData.FindCPEsForCVE(cveID)
 *   fmt.Printf("%s影响了%d个CPE\n", cveID, len(affectedCPEs))
 *
 *   // 获取数据下载时间
 *   fmt.Printf("数据更新时间: %s\n", nvdData.DownloadTime.Format(time.RFC3339))
 *   ```
 *
 * 注意事项:
 *   - NVD数据量较大，首次下载和处理可能需要较长时间
 *   - 定期更新数据以获取最新的漏洞信息
 *   - FindCVEsForCPE和FindCPEsForCVE方法支持模糊匹配，但可能不如精确匹配准确
 */
type NVDCPEData struct {
	// CPEDictionary 包含所有官方注册的CPE条目及其详细信息
	// 通过此字段可以获取特定CPE的标准化表示和元数据
	CPEDictionary *CPEDictionary

	// CPEMatchData 包含CPE与CVE之间的双向映射关系
	// 用于快速查找特定CPE关联的漏洞，或特定漏洞影响的产品
	CPEMatchData *CPEMatchData

	// DownloadTime 记录数据下载的时间戳
	// 可用于判断数据的新鲜度，决定是否需要更新
	DownloadTime time.Time
}

/**
 * CPEMatchData 存储CPE与CVE之间的双向映射关系
 *
 * 此结构体维护了CPE和CVE之间的关联数据，提供了高效的双向查询能力。
 * 通过这些映射，可以快速找出影响特定产品的所有漏洞，或者受特定漏洞影响的所有产品。
 *
 * 字段说明:
 *   - CVEToCPEs: 从CVE ID到相关CPE URI列表的映射，用于查找受特定漏洞影响的所有产品
 *   - CPEToCVEs: 从CPE URI到相关CVE ID列表的映射，用于查找特定产品的所有漏洞
 *
 * 使用示例:
 *   ```go
 *   // 假设已经获取了CPEMatchData
 *   matchData := nvdData.CPEMatchData
 *
 *   // 查找特定CVE影响的所有CPE
 *   cveID := "CVE-2021-44228"
 *   if cpeURIs, exists := matchData.CVEToCPEs[cveID]; exists {
 *       fmt.Printf("%s影响了%d个CPE\n", cveID, len(cpeURIs))
 *       for i, uri := range cpeURIs[:3] { // 只显示前3个
 *           fmt.Printf("%d. %s\n", i+1, uri)
 *       }
 *   }
 *
 *   // 查找特定CPE存在的所有漏洞
 *   cpeURI := "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"
 *   if cveIDs, exists := matchData.CPEToCVEs[cpeURI]; exists {
 *       fmt.Printf("%s存在%d个漏洞\n", cpeURI, len(cveIDs))
 *       for i, id := range cveIDs[:3] { // 只显示前3个
 *           fmt.Printf("%d. %s\n", i+1, id)
 *       }
 *   }
 *   ```
 *
 * 注意事项:
 *   - 映射使用完整的CPE URI和CVE ID作为键，确保使用标准格式
 *   - CVE ID通常采用"CVE-YYYY-NNNNN"格式，其中YYYY是年份，NNNNN是编号
 *   - 某些CPE可能没有关联的CVE，某些CVE可能没有关联的CPE
 */
type CPEMatchData struct {
	// CVEToCPEs 从CVE ID到影响的CPE URI列表的映射
	// 键: CVE ID (如"CVE-2021-44228")
	// 值: 受该CVE影响的CPE URI列表
	CVEToCPEs map[string][]string

	// CPEToCVEs 从CPE URI到相关CVE ID列表的映射
	// 键: CPE URI (如"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
	// 值: 影响该CPE的CVE ID列表
	CPEToCVEs map[string][]string
}

/**
 * DownloadAndParseCPEDict 下载并解析NVD CPE字典数据
 *
 * 此函数从NVD获取官方的CPE字典数据，包含所有正式注册的CPE条目及其元数据，
 * 并将其解析为CPEDictionary结构，便于应用程序使用。
 *
 * 参数:
 *   - options: NVDFeedOptions，配置下载选项，如缓存目录、HTTP客户端等
 *
 * 返回:
 *   - *CPEDictionary: 解析后的CPE字典数据，包含所有CPE条目
 *   - error: 发生的错误，如下载失败、解析错误等，成功时为nil
 *
 * 使用示例:
 *   ```go
 *   options := cpe.DefaultNVDFeedOptions()
 *   // 设置缓存目录为当前目录下的cache文件夹
 *   options.CacheDir = "./cache"
 *
 *   cpeDict, err := cpe.DownloadAndParseCPEDict(options)
 *   if err != nil {
 *       log.Fatalf("下载CPE字典失败: %v", err)
 *   }
 *
 *   // 打印字典中的CPE条目数量
 *   fmt.Printf("CPE字典包含%d个条目\n", len(cpeDict.Items))
 *
 *   // 查找特定产品的CPE
 *   for _, item := range cpeDict.Items {
 *       if strings.Contains(item.Title, "Windows 10") {
 *           fmt.Printf("找到Windows 10的CPE: %s\n", item.Name)
 *           fmt.Printf("标题: %s\n", item.Title)
 *           fmt.Printf("参考链接: %s\n", item.References)
 *           break
 *       }
 *   }
 *   ```
 *
 * 注意事项:
 *   - NVD CPE字典数据较大(约几十MB)，下载和解析可能需要一定时间
 *   - 首次下载会在options.CacheDir指定的目录中缓存数据
 *   - 后续调用如果缓存未过期，将直接使用缓存数据，提高性能
 *   - 建议定期更新数据以获取最新的CPE条目
 */
func DownloadAndParseCPEDict(options *NVDFeedOptions) (*CPEDictionary, error) {
	if options == nil {
		options = DefaultNVDFeedOptions()
	}

	// 创建缓存目录
	err := os.MkdirAll(options.CacheDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// 缓存文件路径
	cacheFile := filepath.Join(options.CacheDir, "nvdcpe-dictionary.xml")

	// 检查缓存是否有效
	useCache := false
	if fileInfo, err := os.Stat(cacheFile); err == nil {
		// 检查缓存是否过期
		if time.Since(fileInfo.ModTime()).Hours() < float64(options.CacheMaxAge) {
			useCache = true
		}
	}

	var dictFile io.Reader

	if useCache {
		// 使用缓存
		f, err := os.Open(cacheFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open cache file: %w", err)
		}
		defer f.Close()
		dictFile = f

		if options.ShowProgress {
			fmt.Println("Using cached CPE dictionary.")
		}
	} else {
		// 下载新的数据
		if options.ShowProgress {
			fmt.Println("Downloading CPE dictionary from NVD...")
		}

		resp, err := options.HTTPClient.Get(NVDCPEDict)
		if err != nil {
			return nil, fmt.Errorf("failed to download CPE dictionary: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to download CPE dictionary, status code: %d", resp.StatusCode)
		}

		// 解压gzip
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress CPE dictionary: %w", err)
		}
		defer gzipReader.Close()

		// 保存到缓存
		cacheContent, err := ioutil.ReadAll(gzipReader)
		if err != nil {
			return nil, fmt.Errorf("failed to read CPE dictionary: %w", err)
		}

		err = ioutil.WriteFile(cacheFile, cacheContent, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to save CPE dictionary to cache: %w", err)
		}

		dictFile = strings.NewReader(string(cacheContent))
	}

	// 解析字典
	dict, err := ParseDictionary(dictFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CPE dictionary: %w", err)
	}

	return dict, nil
}

/**
 * DownloadAndParseCPEMatch 下载并解析NVD CPE匹配数据
 *
 * 此函数从NVD获取CPE与CVE的映射关系数据，解析后提供双向的查询能力，
 * 可用于查找特定产品的所有漏洞，或特定漏洞影响的所有产品。
 *
 * 参数:
 *   - options: NVDFeedOptions，配置下载选项，如缓存目录、HTTP客户端等
 *
 * 返回:
 *   - *CPEMatchData: 解析后的CPE匹配数据，包含CPE与CVE的双向映射
 *   - error: 发生的错误，如下载失败、解析错误等，成功时为nil
 *
 * 使用示例:
 *   ```go
 *   options := cpe.DefaultNVDFeedOptions()
 *   // 禁用进度显示
 *   options.ShowProgress = false
 *
 *   matchData, err := cpe.DownloadAndParseCPEMatch(options)
 *   if err != nil {
 *       log.Fatalf("下载CPE匹配数据失败: %v", err)
 *   }
 *
 *   // 查找Log4j相关的CVE
 *   log4jCPE := "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"
 *   if cves, exists := matchData.CPEToCVEs[log4jCPE]; exists {
 *       fmt.Printf("Log4j 2.0存在%d个漏洞\n", len(cves))
 *       for i, cve := range cves[:3] { // 只显示前3个
 *           fmt.Printf("%d. %s\n", i+1, cve)
 *       }
 *   }
 *
 *   // 查找特定CVE影响的产品
 *   cveID := "CVE-2021-44228"
 *   if cpes, exists := matchData.CVEToCPEs[cveID]; exists {
 *       fmt.Printf("%s影响了%d个CPE\n", cveID, len(cpes))
 *       for i, cpe := range cpes[:3] { // 只显示前3个
 *           fmt.Printf("%d. %s\n", i+1, cpe)
 *       }
 *   }
 *   ```
 *
 * 注意事项:
 *   - NVD CPE匹配数据较大，下载和解析可能需要较长时间
 *   - 数据会在options.CacheDir指定的目录中缓存
 *   - 如果缓存未过期，后续调用将使用缓存数据，提高性能
 *   - 对于大规模的安全扫描和分析，建议在本地持久化存储这些映射关系
 */
func DownloadAndParseCPEMatch(options *NVDFeedOptions) (*CPEMatchData, error) {
	if options == nil {
		options = DefaultNVDFeedOptions()
	}

	// 创建缓存目录
	err := os.MkdirAll(options.CacheDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// 缓存文件路径
	cacheFile := filepath.Join(options.CacheDir, "nvdcpematch.json")

	// 检查缓存是否有效
	useCache := false
	if fileInfo, err := os.Stat(cacheFile); err == nil {
		// 检查缓存是否过期
		if time.Since(fileInfo.ModTime()).Hours() < float64(options.CacheMaxAge) {
			useCache = true
		}
	}

	var matchFile []byte

	if useCache {
		// 使用缓存
		var err error
		matchFile, err = ioutil.ReadFile(cacheFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read cache file: %w", err)
		}

		if options.ShowProgress {
			fmt.Println("Using cached CPE match data.")
		}
	} else {
		// 下载新的数据
		if options.ShowProgress {
			fmt.Println("Downloading CPE match data from NVD...")
		}

		resp, err := options.HTTPClient.Get(NVDCPEMatch)
		if err != nil {
			return nil, fmt.Errorf("failed to download CPE match data: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to download CPE match data, status code: %d", resp.StatusCode)
		}

		// 解压gzip
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress CPE match data: %w", err)
		}
		defer gzipReader.Close()

		// 读取内容
		matchFile, err = ioutil.ReadAll(gzipReader)
		if err != nil {
			return nil, fmt.Errorf("failed to read CPE match data: %w", err)
		}

		// 保存到缓存
		err = ioutil.WriteFile(cacheFile, matchFile, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to save CPE match data to cache: %w", err)
		}
	}

	// 解析CPE Match数据
	type CPEMatch struct {
		CPEName string   `json:"cpe23Uri"`
		CVEs    []string `json:"cveNames"`
	}

	type CPEMatchRoot struct {
		Matches []CPEMatch `json:"matches"`
	}

	var root CPEMatchRoot
	err = json.Unmarshal(matchFile, &root)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CPE match data: %w", err)
	}

	// 构建映射关系
	result := &CPEMatchData{
		CVEToCPEs: make(map[string][]string),
		CPEToCVEs: make(map[string][]string),
	}

	for _, match := range root.Matches {
		// CPE到CVE的映射
		result.CPEToCVEs[match.CPEName] = match.CVEs

		// CVE到CPE的映射
		for _, cve := range match.CVEs {
			if _, ok := result.CVEToCPEs[cve]; !ok {
				result.CVEToCPEs[cve] = make([]string, 0)
			}
			result.CVEToCPEs[cve] = append(result.CVEToCPEs[cve], match.CPEName)
		}
	}

	return result, nil
}

/**
 * DownloadAllNVDData 下载并解析所有NVD数据
 *
 * 此函数综合获取NVD的CPE字典和CPE匹配数据，提供完整的数据集供应用程序使用。
 * 它是获取全面NVD数据的便捷方法，避免分别调用多个下载函数。
 *
 * 参数:
 *   - options: NVDFeedOptions，配置下载选项，如缓存目录、HTTP客户端等
 *
 * 返回:
 *   - *NVDCPEData: 包含CPE字典和CPE匹配数据的综合结构
 *   - error: 发生的错误，如下载失败、解析错误等，成功时为nil
 *
 * 使用示例:
 *   ```go
 *   options := cpe.DefaultNVDFeedOptions()
 *   // 设置缓存目录和最大缓存期限
 *   options.CacheDir = "./nvd_cache"
 *   options.CacheMaxAge = 7 * 24 * time.Hour // 7天
 *
 *   // 下载所有NVD数据
 *   fmt.Println("开始下载NVD数据...")
 *   nvdData, err := cpe.DownloadAllNVDData(options)
 *   if err != nil {
 *       log.Fatalf("下载NVD数据失败: %v", err)
 *   }
 *   fmt.Println("NVD数据下载完成!")
 *
 *   // 查找特定产品的漏洞
 *   apacheTomcatCPE, _ := cpe.ParseCpe23("cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*")
 *   cves := nvdData.FindCVEsForCPE(apacheTomcatCPE)
 *   fmt.Printf("发现Apache Tomcat 9.0.0存在%d个漏洞\n", len(cves))
 *
 *   // 查找指定漏洞影响的产品
 *   heartbleedCVE := "CVE-2014-0160"
 *   affectedCPEs := nvdData.FindCPEsForCVE(heartbleedCVE)
 *   fmt.Printf("Heartbleed漏洞(CVE-2014-0160)影响了%d个产品\n", len(affectedCPEs))
 *   ```
 *
 * 注意事项:
 *   - 此函数执行两次独立的下载操作，总下载时间可能较长
 *   - 对于生产环境，建议定期(如每周)后台更新NVD数据
 *   - 下载完成的数据可以持久化存储，以便多个应用程序共享使用
 *   - 如果只需要特定类型的数据，可以单独调用DownloadAndParseCPEDict或DownloadAndParseCPEMatch
 */
func DownloadAllNVDData(options *NVDFeedOptions) (*NVDCPEData, error) {
	if options == nil {
		options = DefaultNVDFeedOptions()
	}

	// 并发下载字典和匹配数据
	var wg sync.WaitGroup
	var dict *CPEDictionary
	var match *CPEMatchData
	var dictErr, matchErr error

	wg.Add(2)

	// 下载字典
	go func() {
		defer wg.Done()
		dict, dictErr = DownloadAndParseCPEDict(options)
	}()

	// 下载匹配数据
	go func() {
		defer wg.Done()
		match, matchErr = DownloadAndParseCPEMatch(options)
	}()

	wg.Wait()

	// 检查错误
	if dictErr != nil {
		return nil, fmt.Errorf("failed to download CPE dictionary: %w", dictErr)
	}

	if matchErr != nil {
		return nil, fmt.Errorf("failed to download CPE match data: %w", matchErr)
	}

	return &NVDCPEData{
		CPEDictionary: dict,
		CPEMatchData:  match,
		DownloadTime:  time.Now(),
	}, nil
}

// FindCVEsForCPE 查找与特定CPE相关的所有CVE
func (data *NVDCPEData) FindCVEsForCPE(cpe *CPE) []string {
	if data == nil || data.CPEMatchData == nil {
		return nil
	}

	// 获取CPE字符串
	cpeStr := cpe.Cpe23

	// 查找精确匹配
	if cves, ok := data.CPEMatchData.CPEToCVEs[cpeStr]; ok {
		return cves
	}

	// 查找宽松匹配
	var results []string
	for cpeName, cves := range data.CPEMatchData.CPEToCVEs {
		// 解析CPE字符串
		otherCpe, err := ParseCpe23(cpeName)
		if err != nil {
			continue
		}

		// 使用宽松匹配
		options := NewAdvancedMatchOptions()
		options.MatchMode = "distance"
		options.ScoreThreshold = 0.8 // 要求80%匹配度

		if AdvancedMatchCPE(cpe, otherCpe, options) {
			// 添加匹配的CVE
			for _, cve := range cves {
				// 检查是否已存在
				found := false
				for _, existingCVE := range results {
					if existingCVE == cve {
						found = true
						break
					}
				}

				if !found {
					results = append(results, cve)
				}
			}
		}
	}

	return results
}

// FindCPEsForCVE 查找与特定CVE相关的所有CPE
func (data *NVDCPEData) FindCPEsForCVE(cveID string) []*CPE {
	if data == nil || data.CPEMatchData == nil {
		return nil
	}

	// 标准化CVE ID
	cveID = cve.Format(cveID)

	// 获取CPE字符串列表
	cpeStrs, ok := data.CPEMatchData.CVEToCPEs[cveID]
	if !ok {
		return nil
	}

	// 解析CPE字符串
	var results []*CPE
	for _, cpeStr := range cpeStrs {
		cpe, err := ParseCpe23(cpeStr)
		if err != nil {
			continue
		}

		// 设置CVE ID
		cpe.Cve = cveID

		results = append(results, cpe)
	}

	return results
}

// EnrichCPEWithVulnerabilityData 使用NVD数据丰富CPE信息
func (data *NVDCPEData) EnrichCPEWithVulnerabilityData(cpe *CPE) {
	if data == nil || cpe == nil {
		return
	}

	// 查找相关的CVE
	cves := data.FindCVEsForCPE(cpe)
	if len(cves) > 0 {
		// 设置第一个CVE
		cpe.Cve = cves[0]
	}
}

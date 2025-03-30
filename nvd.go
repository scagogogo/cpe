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
)

// NVDFeedOptions NVD Feed下载选项
type NVDFeedOptions struct {
	// 缓存目录
	CacheDir string

	// 缓存最大有效期（小时）
	CacheMaxAge int

	// 最大并发下载数
	MaxConcurrentDownloads int

	// 是否显示进度信息
	ShowProgress bool

	// 用户自定义的HTTP客户端
	HTTPClient *http.Client
}

// 默认NVD CPE Feed URL
const (
	NVDCPEMatch     = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz"
	NVDCPEFeedURL   = "https://nvd.nist.gov/feeds/json/cpe/1.0/nvdcpe-1.0.json.gz"
	NVDCPEDict      = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
	NVDCVERecentURL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
)

// DefaultNVDFeedOptions 返回默认的NVD Feed下载选项
func DefaultNVDFeedOptions() *NVDFeedOptions {
	return &NVDFeedOptions{
		CacheDir:               filepath.Join(os.TempDir(), "cpe-cache"),
		CacheMaxAge:            24,
		MaxConcurrentDownloads: 3,
		ShowProgress:           true,
		HTTPClient:             &http.Client{Timeout: 60 * time.Second},
	}
}

// NVDCPEData NVD CPE数据
type NVDCPEData struct {
	// CPE字典
	CPEDictionary *CPEDictionary

	// CPE与CVE的映射关系
	CPEMatchData *CPEMatchData

	// 下载时间
	DownloadTime time.Time
}

// CPEMatchData CPE与CVE的映射关系
type CPEMatchData struct {
	// CVE到影响的CPE映射
	CVEToCPEs map[string][]string

	// CPE到相关CVE的映射
	CPEToCVEs map[string][]string
}

// DownloadAndParseCPEDict 下载并解析NVD CPE字典
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

// DownloadAndParseCPEMatch 下载并解析NVD CPE Match数据
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

// DownloadAllNVDData 下载所有NVD数据
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
	cveID = standardizeCVEID(cveID)

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

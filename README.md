# CPE - Common Platform Enumeration 库

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Go Version](https://img.shields.io/badge/go-%3E%3D1.18-blue.svg)

</div>

## 📖 简介

CPE (Common Platform Enumeration) 库是一个完整的Go语言实现，用于处理、解析、匹配和存储CPE (通用平台枚举)。CPE是一种结构化命名方案，用于标识IT系统、软件和软件包的类别。

该库还包括与CVE (Common Vulnerabilities and Exposures) 集成的功能，使开发者能够将软件组件与已知的安全漏洞关联起来。

## ✨ 特性

- 完整支持CPE 2.2和CPE 2.3格式
- 高级匹配功能，包括正则表达式和模糊匹配
- 内置版本比较功能
- 表达式语言用于复杂的适用性语句
- 多种存储选项（内存、文件）
- 与NVD数据源集成
- CVE关联和查询功能
- 可扩展的数据源架构

## 🚀 安装

使用Go模块安装:

```bash
go get github.com/scagogogo/cpe
```

## 🔍 快速开始

### 基本使用

```go
package main

import (
    "fmt"
    "github.com/scagogogo/cpe"
)

func main() {
    // 解析CPE 2.3字符串
    cpeObj, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("CPE详情: 供应商=%s, 产品=%s, 版本=%s\n", 
               cpeObj.Vendor, cpeObj.ProductName, cpeObj.Version)
               
    // 创建匹配条件
    criteria := &cpe.CPE{
        Vendor: "microsoft",
        ProductName: "windows",
    }
    
    // 执行匹配
    if cpeObj.Match(criteria) {
        fmt.Println("匹配成功!")
    }
}
```

### 使用CVE功能

```go
package main

import (
    "fmt"
    "github.com/scagogogo/cpe"
)

func main() {
    // 从文本中提取CVE ID
    text := "系统受到CVE-2021-44228和CVE-2022-22965漏洞的影响"
    cveIDs := cpe.ExtractCVEsFromText(text)
    fmt.Printf("发现CVE: %v\n", cveIDs)
    
    // 按年份分组
    grouped := cpe.GroupCVEsByYear(cveIDs)
    fmt.Printf("按年份分组: %v\n", grouped)
    
    // 创建CVE引用
    cveRef := cpe.NewCVEReference("CVE-2021-44228")
    cveRef.Description = "Log4j远程代码执行漏洞"
    cveRef.SetSeverity(10.0) // Critical
    
    // 添加受影响的CPE
    cveRef.AddAffectedCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
}
```

## 📚 API 文档

<details open>
<summary><b>CPE 相关功能</b></summary>

### 解析与格式化

#### `ParseCpe23(cpe23 string) (*CPE, error)`

解析CPE 2.3格式字符串并转换为CPE结构体。

```go
cpe, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
```

#### `ParseCpe22(cpe22 string) (*CPE, error)`

解析CPE 2.2格式字符串并转换为CPE结构体。

```go
cpe, err := cpe.ParseCpe22("cpe:/a:microsoft:windows:10")
```

#### `FormatCpe23(cpe *CPE) string`

将CPE对象格式化为CPE 2.3字符串。

```go
cpeString := cpe.FormatCpe23(cpeObj)
```

#### `FormatCpe22(cpe *CPE) string`

将CPE对象格式化为CPE 2.2字符串。

```go
cpeString := cpe.FormatCpe22(cpeObj)
```

### 匹配功能

#### `Match(other *CPE) bool`

检查CPE是否与给定的CPE匹配。

```go
if cpe1.Match(cpe2) {
    fmt.Println("匹配成功")
}
```

#### `MatchCPE(criteria *CPE, target *CPE, options *MatchOptions) bool`

高级CPE匹配功能，支持自定义匹配选项。

```go
options := cpe.DefaultMatchOptions()
options.IgnoreVersion = true
if cpe.MatchCPE(criteria, target, options) {
    fmt.Println("匹配成功")
}
```

#### `AdvancedMatchCPE(criteria *CPE, target *CPE, options *AdvancedMatchOptions) bool`

最灵活的CPE匹配功能，支持高级选项如正则表达式、模糊匹配等。

```go
options := cpe.NewAdvancedMatchOptions()
options.UseRegex = true
options.IgnoreCase = true
if cpe.AdvancedMatchCPE(criteria, target, options) {
    fmt.Println("匹配成功")
}
```

### 版本比较

#### `compareVersions(criteria *CPE, target *CPE, options *AdvancedMatchOptions) bool`

比较两个CPE的版本。

```go
options := cpe.NewAdvancedMatchOptions()
options.VersionCompareMode = "greater"
options.VersionLower = "2.0"
result := cpe.compareVersions(cpe1, cpe2, options)
```

#### `compareVersionStrings(v1, v2 string) int`

比较两个版本字符串，返回-1 (v1 < v2)、0 (v1 == v2) 或 1 (v1 > v2)。

```go
result := cpe.compareVersionStrings("1.2.3", "1.3.0")
if result < 0 {
    fmt.Println("v1 < v2")
}
```

</details>

<details open>
<summary><b>CVE 相关功能</b></summary>

### CVE引用

#### `NewCVEReference(cveID string) *CVEReference`

创建一个新的CVE引用。

```go
cveRef := cpe.NewCVEReference("CVE-2021-44228")
```

#### `AddAffectedCPE(cpeURI string)`

向CVE引用添加受影响的CPE。

```go
cveRef.AddAffectedCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
```

#### `RemoveAffectedCPE(cpeURI string) bool`

从CVE引用中移除受影响的CPE。

```go
removed := cveRef.RemoveAffectedCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
```

#### `AddReference(reference string)`

添加参考链接到CVE引用。

```go
cveRef.AddReference("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")
```

#### `SetSeverity(cvssScore float64)`

设置CVE的CVSS评分和对应的严重性级别。

```go
cveRef.SetSeverity(9.8) // 设置为Critical级别
```

#### `SetMetadata(key string, value interface{})`

设置CVE的元数据。

```go
cveRef.SetMetadata("exploitAvailable", true)
```

#### `GetMetadata(key string) (interface{}, bool)`

获取CVE的元数据。

```go
value, exists := cveRef.GetMetadata("exploitAvailable")
```

#### `RemoveMetadata(key string) bool`

移除CVE的元数据。

```go
removed := cveRef.RemoveMetadata("exploitAvailable")
```

### CVE查询与处理

#### `QueryByCVE(cves []*CVEReference, cveID string) []*CPE`

根据CVE ID查询关联的CPE。

```go
cpes := cpe.QueryByCVE(cveList, "CVE-2021-44228")
```

#### `GetCVEInfo(cves []*CVEReference, cveID string) *CVEReference`

获取CVE的详细信息。

```go
cveInfo := cpe.GetCVEInfo(cveList, "CVE-2021-44228")
```

#### `ExtractCVEsFromText(text string) []string`

从文本中提取CVE ID。

```go
cveIDs := cpe.ExtractCVEsFromText("系统受到CVE-2021-44228影响")
```

#### `GroupCVEsByYear(cveIDs []string) map[string][]string`

按年份对CVE ID进行分组。

```go
grouped := cpe.GroupCVEsByYear(cveIDs)
```

#### `SortCVEs(cveIDs []string) []string`

对CVE ID列表进行排序。

```go
sorted := cpe.SortCVEs(cveIDs)
```

#### `RemoveDuplicateCVEs(cveIDs []string) []string`

去除CVE ID列表中的重复项。

```go
unique := cpe.RemoveDuplicateCVEs(cveIDs)
```

#### `GetRecentCVEs(cveIDs []string, years int) []string`

获取最近N年的CVE ID。

```go
recent := cpe.GetRecentCVEs(cveIDs, 2) // 获取最近2年的CVE
```

#### `ValidateCVE(cveID string) bool`

验证CVE ID是否有效。

```go
isValid := cpe.ValidateCVE("CVE-2021-44228")
```

#### `QueryByProduct(cves []*CVEReference, vendor, product, version string) []*CVEReference`

根据产品信息查询相关CVE。

```go
results := cpe.QueryByProduct(cveList, "apache", "log4j", "2.0")
```

</details>

<details open>
<summary><b>存储相关功能</b></summary>

### 内存存储

#### `NewMemoryStorage() *MemoryStorage`

创建一个新的内存存储实例。

```go
storage := cpe.NewMemoryStorage()
err := storage.Initialize()
```

#### `StoreCPE(cpe *CPE) error`

存储CPE到内存。

```go
err := storage.StoreCPE(cpeObj)
```

#### `RetrieveCPE(id string) (*CPE, error)`

从内存检索CPE。

```go
cpe, err := storage.RetrieveCPE("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
```

### 文件存储

#### `NewFileStorage(baseDir string, useCache bool) (*FileStorage, error)`

创建一个新的文件存储实例。

```go
storage, err := cpe.NewFileStorage("./cpe_data", true)
err = storage.Initialize()
```

#### `StoreCPE(cpe *CPE) error`

存储CPE到文件系统。

```go
err := storage.StoreCPE(cpeObj)
```

#### `RetrieveCPE(id string) (*CPE, error)`

从文件系统检索CPE。

```go
cpe, err := storage.RetrieveCPE("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
```

### 通用存储接口

所有存储实现都兼容Storage接口，可以互换使用。

```go
var storage cpe.Storage
storage = cpe.NewMemoryStorage()
// 或
storage, _ = cpe.NewFileStorage("./cpe_data", true)

// 使用通用接口操作
err := storage.Initialize()
err = storage.StoreCPE(cpeObj)
cpe, err := storage.RetrieveCPE(cpeID)
```

</details>

<details open>
<summary><b>集合与过滤</b></summary>

### CPE集合

#### `NewCPESet(name string, description string) *CPESet`

创建一个新的CPE集合。

```go
set := cpe.NewCPESet("Windows产品", "微软Windows系列产品")
```

#### `Add(cpe *CPE)`

向集合中添加CPE。

```go
set.Add(cpeObj)
```

#### `Remove(cpe *CPE) bool`

从集合中移除CPE。

```go
removed := set.Remove(cpeObj)
```

#### `Contains(cpe *CPE) bool`

检查集合是否包含指定CPE。

```go
if set.Contains(cpeObj) {
    fmt.Println("集合包含该CPE")
}
```

#### `Size() int`

返回集合大小。

```go
count := set.Size()
```

#### `Filter(criteria *CPE, options *MatchOptions) *CPESet`

根据条件过滤集合。

```go
criteria := &cpe.CPE{Vendor: "microsoft"}
options := cpe.DefaultMatchOptions()
filteredSet := set.Filter(criteria, options)
```

#### `Union(other *CPESet) *CPESet`

计算两个集合的并集。

```go
unionSet := set1.Union(set2)
```

#### `Intersection(other *CPESet) *CPESet`

计算两个集合的交集。

```go
intersectionSet := set1.Intersection(set2)
```

#### `Difference(other *CPESet) *CPESet`

计算两个集合的差集。

```go
differenceSet := set1.Difference(set2)
```

</details>

<details open>
<summary><b>适用性语言</b></summary>

### 表达式

#### `ParseExpression(expr string) (Expression, error)`

解析适用性表达式。

```go
expr, err := cpe.ParseExpression("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
```

#### `FilterCPEs(cpes []*CPE, expr Expression) []*CPE`

使用表达式过滤CPE列表。

```go
filteredCPEs := cpe.FilterCPEs(cpeList, expr)
```

### 表达式类型

- `CPEExpression` - 匹配单个CPE
- `ANDExpression` - 匹配所有子表达式
- `ORExpression` - 匹配任一子表达式
- `NOTExpression` - 反转子表达式的匹配结果

```go
// AND表达式示例
expr, _ := cpe.ParseExpression("AND(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*)")

// OR表达式示例
expr, _ := cpe.ParseExpression("OR(cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*, cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*)")

// NOT表达式示例
expr, _ := cpe.ParseExpression("NOT(cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*)")
```

</details>

<details open>
<summary><b>NVD集成</b></summary>

### NVD数据源

#### `DefaultNVDFeedOptions() *NVDFeedOptions`

创建默认的NVD Feed下载选项。

```go
options := cpe.DefaultNVDFeedOptions()
options.CacheDir = "/tmp/nvd-cache"
```

#### `DownloadAndParseCPEDict(options *NVDFeedOptions) (*CPEDictionary, error)`

下载并解析NVD CPE字典。

```go
dict, err := cpe.DownloadAndParseCPEDict(options)
```

#### `DownloadAndParseCPEMatch(options *NVDFeedOptions) (*CPEMatchData, error)`

下载并解析NVD CPE Match数据。

```go
match, err := cpe.DownloadAndParseCPEMatch(options)
```

#### `DownloadAllNVDData(options *NVDFeedOptions) (*NVDCPEData, error)`

下载所有NVD数据。

```go
data, err := cpe.DownloadAllNVDData(options)
```

### NVD数据查询

#### `FindCVEsForCPE(cpe *CPE) []string`

查找与特定CPE相关的所有CVE。

```go
cves := nvdData.FindCVEsForCPE(cpeObj)
```

#### `FindCPEsForCVE(cveID string) []*CPE`

查找与特定CVE相关的所有CPE。

```go
cpes := nvdData.FindCPEsForCVE("CVE-2021-44228")
```

</details>

<details open>
<summary><b>数据源集成</b></summary>

### 数据源

#### `NewDataSource(sourceType DataSourceType, name, description, url string) *DataSource`

创建新的数据源。

```go
ds := cpe.NewDataSource(cpe.DataSourceNVD, "NVD", "National Vulnerability Database", "https://services.nvd.nist.gov/rest/json/")
```

#### `CreateNVDDataSource(apiKey string) *DataSource`

创建NVD数据源。

```go
nvd := cpe.CreateNVDDataSource("YOUR_API_KEY")
```

#### `CreateGitHubDataSource(token string) *DataSource`

创建GitHub数据源。

```go
github := cpe.CreateGitHubDataSource("YOUR_GITHUB_TOKEN")
```

#### `CreateRedHatDataSource() *DataSource`

创建RedHat数据源。

```go
redhat := cpe.CreateRedHatDataSource()
```

### 多源搜索

#### `NewMultiSourceSearch(sources []*DataSource) *MultiSourceVulnerabilitySearch`

创建新的多数据源搜索。

```go
sources := []*cpe.DataSource{nvd, github, redhat}
search := cpe.NewMultiSourceSearch(sources)
```

#### `SearchByCVE(cveID string) ([]*CVEReference, error)`

根据CVE ID在多个数据源中搜索。

```go
results, err := search.SearchByCVE("CVE-2021-44228")
```

#### `SearchByCPE(cpe *CPE) ([]*CVEReference, error)`

根据CPE在多个数据源中搜索。

```go
results, err := search.SearchByCPE(cpeObj)
```

</details>

## 📊 使用场景

- 软件组件分析 (SCA)
- 漏洞管理系统
- 供应链安全
- 合规检查
- 资产清单管理
- 安全产品集成

## 📄 开源协议

本项目采用 [MIT 协议](https://github.com/scagogogo/cpe/blob/main/LICENSE) 进行许可。

## 🤝 贡献指南

欢迎贡献代码、文档和反馈。请通过GitHub Issues和Pull Requests提交您的贡献。

## 📦 相关项目

- [scagogogo/cve](https://github.com/scagogogo/cve) - CVE处理工具库






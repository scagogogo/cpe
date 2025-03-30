# CPE - Common Platform Enumeration 库

这是一个用于解析、匹配和管理 CPE (Common Platform Enumeration) 信息的 Go 语言库。CPE是一种标准化方法，用于标识IT系统、软件和软件包的信息技术产品、平台和组件。

## 功能特性

- 支持 CPE 2.2 和 2.3 格式的解析和生成
- 支持 CPE 名称匹配和比较（包括通配符和特殊值）
- 支持 WFN (Well-Formed Name) 格式及其转换
- 支持 CPE 适用性语言 (CPE Applicability Language)
- 提供版本比较和范围匹配功能
- 提供 CPE 字典功能，支持 XML 导入导出
- 支持 CVE 与 CPE 的关联查询
- 提供高级匹配算法（支持部分匹配、超集匹配等）
- 支持 CPE 集合操作（并集、交集、差集等）
- 集成 NVD CPE Feed，提供漏洞关联查询
- 结构化的错误处理机制
- 支持多种存储后端的数据持久化
- 集成缓存机制，优化查询性能

## 安装

```bash
go get github.com/scagogogo/cpe
```

## API 用法文档

本节详细介绍库的主要API和使用方法，包括代码示例和说明。

### 1. CPE 解析与格式化

#### 1.1 解析 CPE 字符串

CPE库支持解析 CPE 2.2 和 2.3 两种格式的字符串，并将其转换为内部的 `CPE` 结构体。

```go
// 解析 CPE 2.3 格式
cpe23, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Vendor: %s, Product: %s, Version: %s\n", 
    cpe23.Vendor, cpe23.ProductName, cpe23.Version)
// 输出: Vendor: microsoft, Product: windows, Version: 10

// 解析 CPE 2.2 格式
cpe22, err := cpe.ParseCpe22("cpe:/a:microsoft:windows:10")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Vendor: %s, Product: %s, Version: %s\n", 
    cpe22.Vendor, cpe22.ProductName, cpe22.Version)
// 输出: Vendor: microsoft, Product: windows, Version: 10
```

#### 1.2 手动创建 CPE 对象

您可以通过手动创建 `CPE` 结构体对象，然后使用 `GetURI` 方法获取其标准化的 CPE 字符串表示。

```go
// 创建表示 Oracle Java 8 的 CPE
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
// 输出: 生成的CPE 2.3 URI: cpe:2.3:a:oracle:java:1.8.0:291:*:*:*:*:*:*
```

#### 1.3 格式转换 (CPE 2.2 ↔ CPE 2.3)

```go
// 从 CPE 2.2 转换到 CPE 2.3
cpe22Str := "cpe:/o:microsoft:windows_10:-"
cpe22Obj, err := cpe.ParseCpe22(cpe22Str)
if err != nil {
    log.Fatal(err)
}
cpe23Str := cpe22Obj.GetURI()
fmt.Printf("CPE 2.2: %s\n", cpe22Str)
fmt.Printf("转换到CPE 2.3: %s\n", cpe23Str)
// 输出: 
// CPE 2.2: cpe:/o:microsoft:windows_10:-
// 转换到CPE 2.3: cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*
```

### 2. CPE 匹配

CPE匹配是该库的核心功能，用于确定一个 CPE 是否与另一个 CPE 或匹配条件相匹配。

#### 2.1 基本匹配

```go
// 创建两个CPE对象
cpe1, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
cpe2, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*")

// 使用Match方法检查匹配
if cpe1.Match(cpe2) {
    fmt.Println("CPE1 匹配 CPE2") // 会输出
}

if cpe2.Match(cpe1) {
    fmt.Println("CPE2 匹配 CPE1") // 会输出
}
```

#### 2.2 使用 MatchCPE 函数

`MatchCPE` 函数提供了更灵活的匹配选项，可以实现忽略版本、版本范围匹配等高级功能。

```go
// 创建匹配条件
criteria := &cpe.CPE{
    Part:        *cpe.PartApplication,
    Vendor:      "microsoft",
    ProductName: "windows",
}

// 创建目标CPE
target, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")

// 默认匹配选项
defaultOptions := cpe.DefaultMatchOptions()
match := cpe.MatchCPE(criteria, target, defaultOptions)
fmt.Printf("默认选项匹配结果: %t\n", match)
// 输出: 默认选项匹配结果: true

// 忽略版本匹配
ignoreVersionOptions := &cpe.MatchOptions{
    IgnoreVersion: true,
}
match = cpe.MatchCPE(criteria, target, ignoreVersionOptions)
fmt.Printf("忽略版本匹配结果: %t\n", match)
// 输出: 忽略版本匹配结果: true
```

#### 2.3 版本范围匹配

```go
// 创建版本范围匹配选项
versionRangeOptions := &cpe.MatchOptions{
    VersionRange: true,
    MinVersion:   "3.0",
    MaxVersion:   "4.0",
}

// 创建目标CPE (版本3.5)
target, _ := cpe.ParseCpe23("cpe:2.3:a:apache:log4j:3.5:*:*:*:*:*:*:*")

// 创建匹配条件
criteria := &cpe.CPE{
    Part:        *cpe.PartApplication,
    Vendor:      "apache",
    ProductName: "log4j",
}

// 检查版本范围匹配
match := cpe.MatchCPE(criteria, target, versionRangeOptions)
fmt.Printf("版本范围匹配结果: %t\n", match)
// 输出: 版本范围匹配结果: true
```

#### 2.4 正则表达式匹配

```go
// 创建使用正则表达式的匹配选项
regexOptions := &cpe.MatchOptions{
    UseRegex: true,
}

// 创建使用正则表达式的匹配条件
regexCriteria := &cpe.CPE{
    Part:        *cpe.PartApplication,
    Vendor:      "spring.*",
    ProductName: "spring-.*",
}

// 创建目标CPE
target, _ := cpe.ParseCpe23("cpe:2.3:a:spring-projects:spring-framework:5.3.20:*:*:*:*:*:*:*")

// 检查正则表达式匹配
match := cpe.MatchCPE(regexCriteria, target, regexOptions)
fmt.Printf("正则匹配结果: %t\n", match)
// 输出: 正则匹配结果: true
```

### 3. CPE 适用性语言

CPE 适用性语言允许您创建复杂的逻辑组合表达式，用于匹配 CPE。

#### 3.1 解析适用性语言表达式

```go
// 创建复杂的适用性表达式
exprStr := "AND(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, NOT(cpe:2.3:a:microsoft:windows:10:1903:*:*:*:*:*:*))"
expr, err := cpe.ParseExpression(exprStr)
if err != nil {
    log.Fatal(err)
}

// 检查特定 CPE 是否匹配表达式
cpe, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:2004:*:*:*:*:*:*")
if expr.Evaluate(cpe) {
    fmt.Println("CPE 匹配表达式")
    // 输出: CPE 匹配表达式
}
```

#### 3.2 复杂逻辑组合

支持的表达式类型包括：
- 单个CPE表达式：`cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*`
- AND逻辑组合：`AND(expr1, expr2, ...)`
- OR逻辑组合：`OR(expr1, expr2, ...)`
- NOT逻辑求反：`NOT(expr)`

```go
// OR 表达式示例
orExprStr := "OR(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*)"
orExpr, _ := cpe.ParseExpression(orExprStr)

// AND 表达式示例
andExprStr := "AND(cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*, cpe:2.3:a:*:windows:*:*:*:*:*:*:*:*)"
andExpr, _ := cpe.ParseExpression(andExprStr)

// 嵌套表达式示例
nestedExprStr := "AND(cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*, NOT(OR(cpe:2.3:a:*:office:*:*:*:*:*:*:*:*, cpe:2.3:a:*:edge:*:*:*:*:*:*:*:*)))"
nestedExpr, _ := cpe.ParseExpression(nestedExprStr)
```

#### 3.3 过滤 CPE 列表

```go
// 创建一个CPE列表
cpeList := []*cpe.CPE{
    cpe1, // Windows 10
    cpe2, // Windows (通配)
    cpe3, // Office
}

// 使用表达式过滤列表
filteredList := cpe.FilterCPEs(cpeList, expr)
fmt.Printf("过滤后的CPE数量: %d\n", len(filteredList))
```

### 4. CPE 字典

CPE 字典是一个包含多个 CPE 条目的集合，通常用于存储和查询 CPE 数据。

#### 4.1 解析 CPE 字典 XML

```go
// 解析 CPE 字典 XML
file, _ := os.Open("official-cpe-dictionary_v2.3.xml")
dict, err := cpe.ParseDictionary(file)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("字典包含 %d 个CPE条目\n", len(dict.Items))
fmt.Printf("生成日期: %s\n", dict.GeneratedAt.Format(time.RFC3339))
```

#### 4.2 创建和存储 CPE 字典

```go
// 创建 CPE 条目
cpeWin10, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
win10Item := &cpe.CPEItem{
    Name:  cpeWin10.GetURI(),
    Title: "Microsoft Windows 10",
    References: []cpe.Reference{
        {
            URL:  "https://www.microsoft.com/windows",
            Type: "Vendor",
        },
    },
    CPE: cpeWin10,
}

// 创建 CPE 字典
dictionary := &cpe.CPEDictionary{
    Items:         []*cpe.CPEItem{win10Item},
    GeneratedAt:   time.Now(),
    SchemaVersion: "2.3",
}

// 初始化文件存储
storage, err := cpe.NewFileStorage("./cpe-data", true)
if err != nil {
    log.Fatal(err)
}

// 存储字典
err = storage.StoreDictionary(dictionary)
if err != nil {
    log.Fatal(err)
}
```

#### 4.3 检索和搜索 CPE 字典

```go
// 检索字典
retrievedDict, err := storage.RetrieveDictionary()
if err != nil {
    log.Fatal(err)
}

// 创建搜索条件
searchCriteria, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*")

// 搜索匹配的 CPE 条目
for _, item := range retrievedDict.Items {
    if cpe.MatchCPE(searchCriteria, item.CPE, nil) {
        fmt.Printf("找到匹配项: %s - %s\n", item.Name, item.Title)
    }
}
```

### 5. 存储与持久化

该库提供了多种存储实现，用于持久化 CPE 和相关数据。

#### 5.1 文件存储

```go
// 创建文件存储
fsStorage, err := cpe.NewFileStorage("./cpe-data", true) // 第二个参数表示是否使用缓存
if err != nil {
    log.Fatal(err)
}
defer fsStorage.Close()

// 存储 CPE
cpe1, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
err = fsStorage.StoreCPE(cpe1)
if err != nil {
    log.Fatal(err)
}

// 检索 CPE
retrievedCPE, err := fsStorage.RetrieveCPE(cpe1.GetURI())
if err != nil {
    log.Fatal(err)
}
```

#### 5.2 内存存储

```go
// 创建内存存储（适合临时数据或小型数据集）
memStorage := cpe.NewMemoryStorage()
memStorage.Initialize()
defer memStorage.Close()

// 存储 CPE
cpe1, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
err := memStorage.StoreCPE(cpe1)
if err != nil {
    log.Fatal(err)
}

// 检索 CPE
retrievedCPE, err := memStorage.RetrieveCPE(cpe1.GetURI())
if err != nil {
    log.Fatal(err)
}
```

#### 5.3 搜索 CPE

```go
// 创建搜索条件
criteria := &cpe.CPE{
    Part:        *cpe.PartApplication,
    Vendor:      "microsoft",
    ProductName: "windows",
}

// 搜索匹配的 CPE
options := &cpe.MatchOptions{IgnoreVersion: true}
results, err := fsStorage.SearchCPE(criteria, options)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("找到 %d 个匹配项\n", len(results))
for _, cpe := range results {
    fmt.Printf("- %s\n", cpe.GetURI())
}
```

### 6. NVD 集成

该库提供了与美国国家漏洞数据库(NVD)集成的功能，可以下载和管理 CPE 和 CVE 数据。

#### 6.1 初始化 NVD 数据源

```go
// 设置数据源
nvdDataSource := &cpe.DataSource{
    Type:        "nvd",
    Name:        "NVD CPE Dictionary",
    Description: "National Vulnerability Database CPE Dictionary",
    URL:         "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz",
    CacheSettings: &cpe.CacheSettings{
        Enabled:     true,
        Directory:   "./nvd-cache",
        ExpiryHours: 24,
    },
}
```

#### 6.2 下载和管理 NVD 数据

```go
// 设置下载选项
options := cpe.DefaultNVDFeedOptions()
options.CacheDir = "./nvd-cache"
options.ShowProgress = true

// 下载并解析 NVD 数据
nvdData, err := cpe.DownloadAllNVDData(options)
if err != nil {
    log.Fatal(err)
}

// 查找与特定 CPE 相关的 CVE
apacheLog4j, _ := cpe.ParseCpe23("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
cves := nvdData.FindCVEsForCPE(apacheLog4j)
fmt.Printf("找到 %d 个与 Apache Log4j 2.0 相关的 CVE\n", len(cves))
```

#### 6.3 管理数据更新

```go
// 检索上次更新时间
lastUpdateTime, err := storage.RetrieveModificationTimestamp("nvd_last_updated")
if err != nil {
    // 处理错误
}

// 检查是否需要更新
now := time.Now()
needsUpdate := true

if !lastUpdateTime.IsZero() {
    // 如果上次更新时间不是零值，检查是否已经超过24小时
    timeSinceLastUpdate := now.Sub(lastUpdateTime)
    needsUpdate = timeSinceLastUpdate.Hours() >= 24
}

if needsUpdate {
    // 执行更新
    // ...
    
    // 更新时间戳
    err = storage.StoreModificationTimestamp("nvd_last_updated", now)
    if err != nil {
        log.Fatal(err)
    }
}
```

### 7. CVE 关联

该库支持管理 CPE 和 CVE (Common Vulnerabilities and Exposures) 之间的关联关系。

#### 7.1 创建和管理 CVE 引用

```go
// 创建 CVE 引用
cve := cpe.NewCVEReference("CVE-2021-44228") // Log4Shell
cve.Description = "Log4Shell 远程代码执行漏洞"
cve.SetSeverity(9.8) // CVSS 分数

// 添加受影响的 CPE
cve.AddAffectedCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
cve.AddAffectedCPE("cpe:2.3:a:apache:log4j:2.1:*:*:*:*:*:*:*")

// 存储 CVE
err = fsStorage.StoreCVE(cve)
if err != nil {
    log.Fatal(err)
}
```

#### 7.2 查找 CVE 和 CPE 关联

```go
// 根据 CPE 查找相关的 CVE
cpe, _ := cpe.ParseCpe23("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
relatedCVEs, err := fsStorage.FindCVEsByCPE(cpe)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("找到 %d 个关联的 CVE\n", len(relatedCVEs))
for _, cve := range relatedCVEs {
    fmt.Printf("- %s: %s (CVSS: %.1f)\n", cve.ID, cve.Description, cve.CVSS)
}

// 根据 CVE ID 查找相关的 CPE
relatedCPEs, err := fsStorage.FindCPEsByCVE("CVE-2021-44228")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("找到 %d 个受影响的 CPE\n", len(relatedCPEs))
for _, cpe := range relatedCPEs {
    fmt.Printf("- %s\n", cpe.GetURI())
}
```

### 8. 高级匹配和集合操作

该库提供了高级的匹配算法和集合操作功能。

#### 8.1 CPE 集合

```go
// 创建 CPE 集合
set := cpe.NewCPESet()

// 添加 CPE 到集合
cpe1, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
cpe2, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*")
set.Add(cpe1, cpe2)

// 集合操作
otherSet := cpe.NewCPESet()
otherSet.Add(cpe2)

// 求并集
unionSet := set.Union(otherSet)

// 求交集
intersectSet := set.Intersect(otherSet)

// 求差集
diffSet := set.Difference(otherSet)
```

#### 8.2 高级匹配

```go
// 创建高级匹配选项
options := cpe.NewAdvancedMatchOptions()
options.MatchMode = "distance"      // 距离匹配模式
options.ScoreThreshold = 0.7        // 要求最少 70% 匹配度

// 使用高级匹配过滤集合
filterCPE, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*")
microsoftProducts := set.AdvancedFilter(filterCPE, options)
```

### 9. WFN (Well-Formed Name) 转换

WFN是CPE规范定义的内部表示形式，该库支持CPE和WFN之间的转换。

```go
// 将CPE转换为WFN
cpe, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
wfn := cpe.ToWFN()

// 将WFN转换回CPE
convertedCpe := wfn.ToCPE()
```

### 10. 错误处理

该库使用结构化的错误处理机制，提供了多种预定义错误类型。

```go
// 尝试解析无效的CPE
_, err := cpe.ParseCpe23("invalid:format")
if err != nil {
    // 检查错误类型
    if invalidFormatErr, ok := err.(*cpe.InvalidFormatError); ok {
        fmt.Printf("无效的CPE格式: %s\n", invalidFormatErr.Input)
    } else {
        fmt.Printf("解析失败: %v\n", err)
    }
}

// 尝试检索不存在的CPE
_, err = storage.RetrieveCPE("non-existent-cpe")
if err != nil {
    if notFoundErr, ok := err.(*cpe.NotFoundError); ok {
        fmt.Printf("未找到CPE: %s\n", notFoundErr.ID)
    } else {
        fmt.Printf("检索失败: %v\n", err)
    }
}
```

## 高级使用场景

以下是一些高级使用场景示例，展示如何将库的不同功能结合起来。

### 场景1: 漏洞扫描与检测

```go
// 创建一个包含系统中所有软件的CPE清单
systemCPEs := []*cpe.CPE{
    // Windows 10系统
    parseCpe("cpe:2.3:o:microsoft:windows:10:1909:*:*:*:*:*:*"),
    // 已安装的软件
    parseCpe("cpe:2.3:a:adobe:acrobat_reader:dc:2021.001.20145:*:*:*:*:*:*"),
    parseCpe("cpe:2.3:a:google:chrome:92.0.4515.131:*:*:*:*:*:*:*"),
    parseCpe("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"),
}

// 从NVD获取最新漏洞数据
nvdData, _ := cpe.DownloadAllNVDData(options)

// 对每个CPE检查漏洞
for _, systemCpe := range systemCPEs {
    cves := nvdData.FindCVEsForCPE(systemCpe)
    if len(cves) > 0 {
        fmt.Printf("发现 %s 存在 %d 个漏洞!\n", systemCpe.GetURI(), len(cves))
        
        // 输出高危漏洞
        for _, cve := range cves {
            if cve.CVSS >= 7.0 {
                fmt.Printf("  高危漏洞: %s (CVSS: %.1f) - %s\n", 
                    cve.ID, cve.CVSS, cve.Description)
            }
        }
    }
}
```

### 场景2: 软件资产管理

```go
// 创建软件资产存储
assetStorage, _ := cpe.NewFileStorage("./asset-inventory", true)

// 导入现有资产
existingDict, _ := assetStorage.RetrieveDictionary()
assetManager := cpe.NewAssetManager(existingDict)

// 添加新发现的软件
newSoftware, _ := cpe.ParseCpe23("cpe:2.3:a:oracle:java:11.0.12:*:*:*:*:*:*:*")
assetManager.AddAsset(newSoftware, "Development Server", "Critical")

// 查找特定类型的资产
javaAssets := assetManager.FindAssetsByCriteria(&cpe.CPE{
    Vendor:      "oracle",
    ProductName: "java",
})

// 生成资产报告
report := assetManager.GenerateReport()
for _, category := range report.Categories {
    fmt.Printf("%s: %d 个资产\n", category.Name, len(category.Assets))
}
```

### 场景3: 补丁管理

```go
// 创建补丁管理器
patchManager := cpe.NewPatchManager(storage)

// 注册需要监控的软件
patchManager.RegisterSoftware("Apache Log4j", "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
patchManager.RegisterSoftware("Windows 10", "cpe:2.3:o:microsoft:windows:10:1909:*:*:*:*:*:*")

// 检查补丁状态
patchStatus, _ := patchManager.CheckPatchStatus()
for software, status := range patchStatus {
    if status.OutOfDate {
        fmt.Printf("%s 需要更新! 当前版本: %s, 最新版本: %s\n",
            software, status.CurrentVersion, status.LatestVersion)
        
        // 显示解决的漏洞
        for _, cve := range status.ResolvedVulnerabilities {
            fmt.Printf("  - 更新后将修复: %s (%s)\n", cve.ID, cve.Description)
        }
    }
}
```

## 最佳实践

1. **定期更新NVD数据**：漏洞数据库每天都在更新，建议至少每天更新一次NVD数据。

2. **使用缓存**：对于频繁访问的数据，启用缓存可以显著提高性能。

3. **正确处理错误**：始终检查函数返回的错误，并根据错误类型采取适当的处理措施。

4. **选择合适的存储后端**：对于大量数据，建议使用持久化存储；对于临时数据或小型数据集，可以使用内存存储。

5. **版本控制**：在匹配CPE时，考虑使用版本范围和版本比较功能，以确保匹配的准确性。

## 许可证

本项目采用 MIT 许可证






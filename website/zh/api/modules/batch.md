---
title: Batch
outline: deep
---

# 📦 批量扫描

`batch` 模块支持对 SBOM 组件基于 `CPEIndex` 与一个或多个漏洞数据源进行并发扫描，并提供用于 CPE 匹配、PURL 到 CPE 解析以及 CVE 查询的独立批量助手。

## 类型：ScanResult

```go
type ScanResult struct {
    Component        *SBOMComponent          `json:"component"`
    Vulnerabilities  []*VulnerabilityFinding `json:"vulnerabilities"`
    RiskScore        *RiskScore              `json:"riskScore,omitempty"`
    Duration         time.Duration           `json:"duration"`
    Error            string                  `json:"error,omitempty"`
}
```

扫描单个 `SBOMComponent` 的结果：组件本身、发现的漏洞、可选的风险评分、扫描耗时以及错误字符串（若有）。

## 类型：BatchScanner

```go
type BatchScanner struct {
    Index        *CPEIndex
    DataSources  []*VulnDataSource
    Scorer       RiskScorer
    Concurrency  int
}
```

基于 `CPEIndex` 与一组漏洞数据源的并发扫描器。`Concurrency` 控制 goroutine 数量。用 `NewBatchScanner` 构造，用 `SetDataSources` 配置数据源。

## 类型：MatchResult

```go
type MatchResult struct {
    Criteria *CPE   `json:"criteria"`
    Targets  []*CPE `json:"targets"`
    Count    int    `json:"count"`
}
```

将单个 criteria CPE 与目标列表匹配的结果：条件、匹配到的目标及数量。

## 🏗️ NewBatchScanner

```go
func NewBatchScanner(index *CPEIndex, concurrency int) *BatchScanner
```

创建一个以 `index` 为支撑的 `BatchScanner`。当 `concurrency <= 0` 时默认为 `4`。扫描器初始化时使用默认风险评分器（`NewDefaultRiskScorer`）。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `index` | `*CPEIndex` | 用于查找的 CPE 索引，可为 `nil` |
| `concurrency` | `int` | 最大并发扫描数；`<= 0` 时取 `4` |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `*BatchScanner` | 配置好的扫描器 |

```go
index := cpeskills.NewCPEIndex(cpes)
scanner := cpeskills.NewBatchScanner(index, 8)
```

## 🔌 SetDataSources

```go
func (bs *BatchScanner) SetDataSources(sources []*VulnDataSource)
```

替换扫描器的漏洞数据源。每个非 `nil` 的数据源会按组件通过 `SearchVulnerabilitiesByCPE` 被查询。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `sources` | `[]*VulnDataSource` | 要使用的数据源 |

```go
scanner.SetDataSources([]*cpeskills.VulnDataSource{nvdSource, osvSource})
```

## 🚀 Scan

```go
func (bs *BatchScanner) Scan(components []*SBOMComponent) ([]*ScanResult, error)
```

并发（受 `bs.Concurrency` 限制）扫描每个组件，按输入顺序为每个组件返回一个 `ScanResult`。对每个组件，扫描器：当组件 CPE 与 `bs.Index` 均非 `nil` 时在索引中查找；查询每个数据源按 CPE 获取漏洞；当设置了风险评分器且存在发现时计算风险评分。当前返回的 error 恒为 `nil`，逐组件的失败记录在 `ScanResult.Error` 中。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `components` | `[]*SBOMComponent` | 待扫描的组件 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `[]*ScanResult` | 每个组件一个结果，按输入顺序 |
| 第 2 个 | `error` | 当前实现中恒为 `nil` |

```go
scanner := cpeskills.NewBatchScanner(index, 8)
scanner.SetDataSources(sources)
results, err := scanner.Scan(components)
if err != nil {
    log.Fatal(err)
}
for _, r := range results {
    fmt.Printf("%s: %d 个漏洞，风险 %v\n",
        r.Component.Name, len(r.Vulnerabilities), r.RiskScore)
}
```

## 🎯 BatchMatchCPEs

```go
func BatchMatchCPEs(criteria []*CPE, targets []*CPE) []MatchResult
```

使用内部构建的 `CPEIndex` 加速，将 `criteria` 中的每个 CPE 与 `targets` 匹配。按相同顺序为每个 criteria 返回一个 `MatchResult`。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `criteria` | `[]*CPE` | 待匹配的 criteria CPE |
| `targets` | `[]*CPE` | 被搜索的 CPE 列表 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `[]MatchResult` | 每个 criteria 一个匹配结果，按顺序 |

```go
criteria := []*cpeskills.CPE{
    cpeskills.MustParse("cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*"),
    cpeskills.MustParse("cpe:2.3:a:adobe:reader:*:*:*:*:*:*:*:*"),
}
results := cpeskills.BatchMatchCPEs(criteria, allCPEs)
for _, r := range results {
    fmt.Printf("criteria 匹配到 %d 个目标\n", r.Count)
}
```

## 🏷️ BatchMatchPURLs

```go
func BatchMatchPURLs(purls []*PackageURL, cpes []*CPE) map[string]*CPE
```

将每个 PURL 解析为 CPE：先查询由 `cpes` 构建的索引（`LookupByPURL`），再回退到 `PURLToCPE` 转换后做索引查找。返回的映射以 PURL 的字符串形式（`purl.String()`）为键。`nil` 的 PURL 被跳过，无匹配的 PURL 不出现在映射中。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `purls` | `[]*PackageURL` | 待解析的包 URL |
| `cpes` | `[]*CPE` | 用于匹配的 CPE 全集 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `map[string]*CPE` | PURL 字符串 → 匹配到的 CPE |

```go
purls := []*cpeskills.PackageURL{pkgURL1, pkgURL2}
mapping := cpeskills.BatchMatchPURLs(purls, allCPEs)
for purlStr, cpe := range mapping {
    fmt.Printf("%s -> %s\n", purlStr, cpe.GetURI())
}
```

## 📋 BatchQueryCVEs

```go
func BatchQueryCVEs(cveIDs []string, dataSources []*VulnDataSource) (map[string]*CVEReference, error)
```

通过多源搜索（并发级别 5）跨所提供数据源查询每个 CVE ID 的详细信息。保留首个返回 `CVEID` 匹配的引用。无结果的 CVE 不出现在映射中。单个 ID 的查询错误被吞掉（循环继续）；当前实现始终返回 `nil` 的 error。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveIDs` | `[]string` | 待查询的 CVE ID |
| `dataSources` | `[]*VulnDataSource` | 待查询的数据源 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `map[string]*CVEReference` | CVE ID → 引用（仅含解析成功的 ID） |
| 第 2 个 | `error` | 当前实现中恒为 `nil` |

```go
ids := []string{"CVE-2021-44228", "CVE-2021-45046"}
refs, err := cpeskills.BatchQueryCVEs(ids, []*cpeskills.VulnDataSource{nvdSource})
if err != nil {
    log.Fatal(err)
}
for id, ref := range refs {
    fmt.Printf("%s: %s\n", id, ref.Description)
}
```

## 📐 批量扫描流程图

```mermaid
flowchart TD
    C[components 组件] --> BS[BatchScanner.Scan]
    BS --> SEM[并发信号量]
    SEM --> GO[逐组件 goroutine]
    GO --> IDX{Index 非 nil?}
    IDX -->|是| LK[Index.Lookup 按 CPE]
    IDX -->|否| DS
    LK --> DS[查询各 DataSource SearchVulnerabilitiesByCPE]
    DS --> F[VulnerabilityFinding 列表]
    F --> SC{Scorer 已设置且有发现?}
    SC -->|是| RS[对发现评分]
    SC -->|否| SR[ScanResult]
    RS --> SR
    SR --> OUT[[]ScanResult 按顺序]
    BC[BatchMatchCPEs] --> IDX2[用 targets 构建 CPEIndex]
    IDX2 --> LK2[逐 criteria Lookup]
    LK2 --> MR[[]MatchResult]
    BP[BatchMatchPURLs] --> LBP[LookupByPURL 或 PURLToCPE]
    LBP --> PM[map string *CPE]
    BQ[BatchQueryCVEs] --> MSS[MultiSourceSearch 级别 5]
    MSS --> CRM[map string *CVEReference]
    style C fill:#e8f5e9,stroke:#2e7d32
    style OUT fill:#f3e5f5,stroke:#6a1b9a
    style MR fill:#f3e5f5,stroke:#6a1b9a
    style PM fill:#f3e5f5,stroke:#6a1b9a
    style CRM fill:#f3e5f5,stroke:#6a1b9a
```

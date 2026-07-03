---
title: OSV
outline: deep
---

# 🌍 OSV

`osv` 模块查询位于 `https://api.osv.dev/v1` 的开源漏洞（OSV）数据库。支持按包 URL（PURL）进行单查与批量查询，导出 OSV 请求/响应结构体，并以 `OSVEntry` 类型建模结果。

## 常量

```go
const DefaultOSVBaseURL = "https://api.osv.dev/v1"
```

## 类型：OSVClient

```go
type OSVClient struct {
    BaseURL            string        // OSV API 基础 URL
    HTTPClient         *http.Client  // HTTP 客户端
    RetryCount         int           // 失败重试次数
    RetryDelay         time.Duration // 重试间隔
    // 未导出：mu、lastRequestTime、minRequestInterval（速率限制）
}
```

OSV API 的 HTTP 客户端。`NewOSVClient` 设置 30 秒超时、3 次重试、1 秒重试间隔，以及 100ms 最小请求间隔。

## 类型：OSVQuery

```go
type OSVQuery struct {
    Package *OSVPackage `json:"package,omitempty"`
    Version string      `json:"version,omitempty"`
    Commit  string      `json:"commit,omitempty"`
}
```

单查询请求体。

## 类型：OSVQueryBatch

```go
type OSVQueryBatch struct {
    Queries []*OSVQuery `json:"queries"`
}
```

批量查询请求体。

## 类型：OSVQueryResult

```go
type OSVQueryResult struct {
    Vulns []*OSVEntry `json:"vulns,omitempty"`
}
```

单查询响应。

## 类型：OSVBatchResult

```go
type OSVBatchResult struct {
    Results []*OSVQueryResult `json:"results"`
}
```

批量查询响应；每个输入查询对应一个 `OSVQueryResult`，按顺序排列。

## 类型：OSVEntry

```go
type OSVEntry struct {
    ID              string                   `json:"id"`                  // OSV ID，如 "GHSA-xxxx-xxxx-xxxx"
    Summary         string                   `json:"summary,omitempty"`
    Details         string                   `json:"details,omitempty"`
    Aliases         []string                 `json:"aliases,omitempty"`   // 如 CVE ID
    Modified        time.Time                `json:"modified,omitempty"`
    Published       time.Time                `json:"published,omitempty"`
    Severity        []*OSVSeverity           `json:"severity,omitempty"`
    Affected        []*OSVAffected           `json:"affected,omitempty"`
    References      []*OSVReference          `json:"references,omitempty"`
    DatabaseSpecific map[string]interface{}  `json:"databaseSpecific,omitempty"`
}
```

单条 OSV 漏洞记录。支撑子类型（`OSVSeverity`、`OSVAffected`、`OSVPackage`、`OSVRange`、`OSVEvent`、`OSVReference`）定义于 `vulnerability_report` 源文件。

## 🆕 NewOSVClient

```go
func NewOSVClient() *OSVClient
```

创建一个指向 `DefaultOSVBaseURL` 的 `OSVClient`，含 30 秒超时、3 次重试、1 秒重试间隔、100ms 最小请求间隔。

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*OSVClient` | 新的 OSV 客户端 |

```go
client := cpeskills.NewOSVClient()
```

## 🆕 NewOSVClientWithOptions

```go
func NewOSVClientWithOptions(baseURL string, timeout time.Duration, retryCount int) *OSVClient
```

以自定义选项创建 `OSVClient`。空 `baseURL`、非正 `timeout`、非正 `retryCount` 均回退到默认值。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `baseURL` | `string` | OSV API 基础 URL；`""` 表示默认 |
| `timeout` | `time.Duration` | HTTP 超时；`<=0` 表示默认（30s） |
| `retryCount` | `int` | 重试次数；`<=0` 表示默认（3） |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*OSVClient` | 新的 OSV 客户端 |

```go
client := cpeskills.NewOSVClientWithOptions("", 60*time.Second, 5)
```

## 🔎 QueryOSV

```go
func QueryOSV(purl *PackageURL) ([]*OSVEntry, error)
```

便捷函数，创建默认 `OSVClient` 并查询单个 PURL 的漏洞。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `purl` | `*PackageURL` | 要查询的包 URL |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]*OSVEntry` | 匹配的漏洞条目 |
| #2 | `error` | 查询错误 |

```go
purl, _ := cpeskills.ParsePurl("pkg:golang/github.com/apache/log4j@2.0")
vulns, err := cpeskills.QueryOSV(purl)
```

## 🔎 QueryOSVBatch

```go
func QueryOSVBatch(purls []*PackageURL) (map[string][]*OSVEntry, error)
```

便捷函数，创建默认 `OSVClient` 并批量查询最多 1000 个 PURL 的漏洞。返回以 PURL 字符串为键的映射。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `purls` | `[]*PackageURL` | 要查询的包 URL（最多 1000 个） |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `map[string][]*OSVEntry` | PURL 字符串 -> 漏洞条目 |
| #2 | `error` | 查询错误（含超限错误） |

```go
results, err := cpeskills.QueryOSVBatch([]*cpeskills.PackageURL{p1, p2})
for purl, vulns := range results {
    fmt.Printf("%s: %d 个漏洞\n", purl, len(vulns))
}
```

## 🧭 OSV 查询流程

```mermaid
flowchart TD
    P[PackageURL] --> Q[QueryOSV]
    PS[[]PackageURL 最多 1000] --> QB[QueryOSVBatch]
    Q --> C1[默认 OSVClient]
    QB --> C2[默认 OSVClient]
    C1 --> REQ1[POST /query]
    C2 --> REQ2[POST /querybatch]
    REQ1 --> R1[OSVQueryResult]
    REQ2 --> R2[OSVBatchResult]
    R1 --> E1[[]OSVEntry]
    R2 --> E2[map PURL -> []OSVEntry]
    style P fill:#e8f5e9,stroke:#2e7d32
    style PS fill:#e8f5e9,stroke:#2e7d32
    style E1 fill:#f3e5f5,stroke:#6a1b9a
    style E2 fill:#f3e5f5,stroke:#6a1b9a
```

---
title: EPSS
outline: deep
---

# 📊 EPSS

`epss` 模块查询 FIRST.org 的漏洞利用预测评分系统（EPSS）API。EPSS 预测某 CVE 在未来 30 天内被利用的概率（评分 0.0–1.0），每日更新。客户端缓存结果，并可在原地富化 `VulnerabilityFinding` 记录。

## 常量

```go
const DefaultEPSSBaseURL = "https://api.first.org/data/v1/epss"
```

## 类型：EPSSClient

```go
type EPSSClient struct {
    BaseURL            string        // EPSS API 基础 URL
    HTTPClient         *http.Client  // HTTP 客户端
    // 未导出：cache、cacheExpiry、mu、lastRequestTime、minRequestInterval（500ms 速率限制）
}
```

`NewEPSSClient` 设置 60 秒超时与 500ms 最小请求间隔，带内存缓存。

## 类型：EPSSEntry

```go
type EPSSEntry struct {
    CVEID      string  `json:"cve"`        // CVE 标识符
    EPSSScore  float64 `json:"epss"`       // 利用概率 0.0-1.0
    Percentile float64 `json:"percentile"` // 相对排名 0.0-1.0
    Date       string  `json:"date"`       // 评分日期
}
```

单条 EPSS 评分记录。

## 类型：EPSSResponse

```go
type EPSSResponse struct {
    Status      string `json:"status"`
    StatusCode  int    `json:"status-code"`
    Version     string `json:"version"`
    Access      string `json:"access"`
    Total       int    `json:"total"`
    Offset      int    `json:"offset"`
    Limit       int    `json:"limit"`
    Data        []struct {
        CVE        string `json:"cve"`
        EPSS       string `json:"epss"`
        Percentile string `json:"percentile"`
        Date       string `json:"date"`
    } `json:"data"`
}
```

EPSS API 原始响应。`Data` 切片携带字符串形式的评分，会被解析为 `EPSSEntry` 的浮点数。

## 🆕 NewEPSSClient

```go
func NewEPSSClient() *EPSSClient
```

创建一个指向 `DefaultEPSSBaseURL` 的 `EPSSClient`，含 60 秒超时与 500ms 速率限制。

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*EPSSClient` | 新的 EPSS 客户端 |

```go
client := cpeskills.NewEPSSClient()
```

## 🆕 NewEPSSClientWithOptions

```go
func NewEPSSClientWithOptions(baseURL string, timeout time.Duration) *EPSSClient
```

以自定义基础 URL 与超时创建 `EPSSClient`。空 `baseURL`、非正 `timeout` 均回退到默认值。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `baseURL` | `string` | EPSS API 基础 URL；`""` 表示默认 |
| `timeout` | `time.Duration` | HTTP 超时；`<=0` 表示默认（60s） |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*EPSSClient` | 新的 EPSS 客户端 |

```go
client := cpeskills.NewEPSSClientWithOptions("", 120*time.Second)
```

## 📈 GetScore

```go
func (c *EPSSClient) GetScore(cveID string) (*EPSSEntry, error)
```

返回单个 CVE 的 EPSS 条目。命中缓存则立即返回；未命中则发起 API 请求。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveID` | `string` | CVE 标识符 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*EPSSEntry` | EPSS 条目 |
| #2 | `error` | 查询错误 |

```go
entry, err := client.GetScore("CVE-2021-44228")
fmt.Printf("EPSS=%.4f 百分位=%.4f\n", entry.EPSSScore, entry.Percentile)
```

## 📈 GetScores

```go
func (c *EPSSClient) GetScores(cveIDs []string) (map[string]*EPSSEntry, error)
```

通过单次 API 请求返回多个 CVE 的 EPSS 条目，以 CVE ID 为键。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveIDs` | `[]string` | CVE 标识符 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `map[string]*EPSSEntry` | CVE ID -> EPSS 条目 |
| #2 | `error` | 查询错误 |

```go
scores, err := client.GetScores([]string{"CVE-2021-44228", "CVE-2021-45046"})
```

## ✨ EnrichVulnerabilityFinding

```go
func (c *EPSSClient) EnrichVulnerabilityFinding(finding *VulnerabilityFinding) error
```

获取 `finding` 对应 CVE 的 EPSS 评分并写入 `finding.EPSSScore`。当 finding 无 CVE 或 CVE 未找到时不做任何操作。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `finding` | `*VulnerabilityFinding` | 要富化的 finding（就地修改） |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `error` | 查询错误 |

```go
err := client.EnrichVulnerabilityFinding(finding)
```

## ✨ EnrichVulnerabilityFindings

```go
func (c *EPSSClient) EnrichVulnerabilityFindings(findings []*VulnerabilityFinding) error
```

批量富化多个 finding，一次性请求获取所有 CVE 的评分。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `findings` | `[]*VulnerabilityFinding` | 要富化的 finding |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `error` | 查询错误 |

```go
err := client.EnrichVulnerabilityFindings(findings)
```

## ⚠️ IsHighRisk

```go
func (e *EPSSEntry) IsHighRisk() bool
```

返回 EPSS 评分是否不低于 0.1（10% 利用概率）。

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `bool` | `EPSSScore >= 0.1` 时为 `true` |

```go
if entry.IsHighRisk() { /* 优先修复 */ }
```

## 🚨 IsCriticalRisk

```go
func (e *EPSSEntry) IsCriticalRisk() bool
```

返回 EPSS 评分是否不低于 0.5（50% 利用概率）。

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `bool` | `EPSSScore >= 0.5` 时为 `true` |

```go
if entry.IsCriticalRisk() { /* 紧急修复 */ }
```

## 🏷️ GetRiskLevel

```go
func (e *EPSSEntry) GetRiskLevel() string
```

返回由评分推导的离散风险级别：`Critical`（>=0.5）、`High`（>=0.1）、`Medium`（>=0.01），否则 `Low`。

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `string` | `"Critical"`、`"High"`、`"Medium"` 或 `"Low"` |

```go
fmt.Println(entry.GetRiskLevel())
```

## 🧹 ClearCache

```go
func (c *EPSSClient) ClearCache()
```

清空内存中的 EPSS 评分缓存。

```go
client.ClearCache()
```

## 📏 CacheSize

```go
func (c *EPSSClient) CacheSize() int
```

返回当前缓存中的条目数。

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `int` | 缓存条目数 |

```go
fmt.Printf("已缓存 %d 条评分\n", client.CacheSize())
```

## 🧮 EPSSScoreToRiskFactor

```go
func EPSSScoreToRiskFactor(epssScore float64) float64
```

通过对数变换将 EPSS 评分（0.0–1.0）映射为 0–10 的风险因子。参考点：EPSS 0.001 → ~1.0、0.01 → ~3.3、0.1 → ~6.7、0.5 → ~9.0、0.9 → ~10.0。评分 `<=0` 返回 0。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `epssScore` | `float64` | EPSS 评分 0.0–1.0 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `float64` | 风险因子 0.0–10.0 |

```go
factor := cpeskills.EPSSScoreToRiskFactor(0.5) // ~9.0
```

## 🧭 EPSS 富化流程

```mermaid
flowchart TD
    CID[CVE ID] --> GS[GetScore]
    CIDS[[]CVE ID] --> GB[GetScores]
    GS --> CACHE{缓存命中?}
    CACHE -->|是| E1[EPSSEntry]
    CACHE -->|否| API[EPSS API]
    API --> E1
    E1 --> IR[IsHighRisk / IsCriticalRisk / GetRiskLevel]
    VF[VulnerabilityFinding] --> EVF[EnrichVulnerabilityFinding]
    VFS[[]VulnerabilityFinding] --> EVFS[EnrichVulnerabilityFindings]
    E1 --> EVF
    E1 --> EVFS
    S[epssScore] --> RF[EPSSScoreToRiskFactor -> 0-10]
    style CID fill:#e8f5e9,stroke:#2e7d32
    style E1 fill:#fff3e0,stroke:#ef6c00
    style VF fill:#e3f2fd,stroke:#1565c0
```

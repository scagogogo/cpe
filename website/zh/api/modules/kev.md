---
title: KEV
outline: deep
---

# 🚨 KEV

`kev` 模块查询 CISA 已知被利用漏洞（KEV）目录——即经确认已被实际利用的漏洞清单。依据 BOD 22-01 指令，联邦机构须在截止日期前修复目录中的漏洞。客户端在本地缓存完整目录，并可用 KEV 状态富化 `VulnerabilityFinding` 记录。

## 常量

```go
const DefaultKEVBaseURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
```

## 类型：KEVClient

```go
type KEVClient struct {
    BaseURL    string        // KEV 目录 JSON URL
    HTTPClient *http.Client  // HTTP 客户端
    // 未导出：cache、allCache、cacheExpiry、mu、lastRequestTime、minRequestInterval（1s 速率限制）
}
```

`NewKEVClient` 设置 30 秒超时与 1 秒最小请求间隔，按 CVE ID 缓存条目，并缓存完整目录。

## 类型：KEVEntry

```go
type KEVEntry struct {
    CVEID                      string   `json:"cveID"`
    VendorProject              string   `json:"vendorProject"`
    Product                    string   `json:"product"`
    VulnerabilityName          string   `json:"vulnerabilityName"`
    DateAdded                  string   `json:"dateAdded"`
    ShortDescription           string   `json:"shortDescription"`
    RequiredAction             string   `json:"requiredAction"`
    DueDate                    string   `json:"dueDate"`
    KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
    Notes                      string   `json:"notes"`
    CWEs                       []string `json:"cwes,omitempty"`
}
```

单条 KEV 目录条目。

## 类型：KEVResponse

```go
type KEVResponse struct {
    Title           string      `json:"title"`
    CatalogVersion  string      `json:"catalogVersion"`
    DateReleased    string      `json:"dateReleased"`
    Count           int         `json:"count"`
    Vulnerabilities []*KEVEntry `json:"vulnerabilities"`
}
```

完整 KEV 目录响应。

## 🆕 NewKEVClient

```go
func NewKEVClient() *KEVClient
```

创建一个指向 `DefaultKEVBaseURL` 的 `KEVClient`，含 30 秒超时与 1 秒速率限制。

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*KEVClient` | 新的 KEV 客户端 |

```go
client := cpeskills.NewKEVClient()
```

## 🆕 NewKEVClientWithOptions

```go
func NewKEVClientWithOptions(baseURL string, timeout time.Duration) *KEVClient
```

以自定义基础 URL 与超时创建 `KEVClient`。空 `baseURL`、非正 `timeout` 均回退到默认值。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `baseURL` | `string` | KEV 目录 URL；`""` 表示默认 |
| `timeout` | `time.Duration` | HTTP 超时；`<=0` 表示默认（30s） |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*KEVClient` | 新的 KEV 客户端 |

```go
client := cpeskills.NewKEVClientWithOptions("", 60*time.Second)
```

## ✅ IsListed

```go
func (c *KEVClient) IsListed(cveID string) (bool, error)
```

返回该 CVE 是否出现在 KEV 目录中。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveID` | `string` | CVE 标识符 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `bool` | 在 KEV 中时为 `true` |
| #2 | `error` | 查询/加载错误 |

```go
listed, err := client.IsListed("CVE-2021-44228")
```

## 📋 GetEntry

```go
func (c *KEVClient) GetEntry(cveID string) (*KEVEntry, error)
```

返回某 CVE 的 KEV 条目，未列出时返回 `nil`（无错误）。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveID` | `string` | CVE 标识符 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*KEVEntry` | 匹配的条目，未列出则为 `nil` |
| #2 | `error` | 查询/加载错误 |

```go
entry, err := client.GetEntry("CVE-2021-44228")
```

## 📋 GetEntries

```go
func (c *KEVClient) GetEntries(cveIDs []string) (map[string]*KEVEntry, error)
```

返回多个 CVE 的 KEV 条目，以 CVE ID 为键。未列出的 CVE 不会出现在映射中。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveIDs` | `[]string` | CVE 标识符 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `map[string]*KEVEntry` | CVE ID -> 条目（仅含已列出者） |
| #2 | `error` | 查询/加载错误 |

```go
entries, err := client.GetEntries([]string{"CVE-2021-44228", "CVE-2021-40444"})
```

## 📚 GetAll

```go
func (c *KEVClient) GetAll() ([]*KEVEntry, error)
```

返回整个 KEV 目录，首次访问时加载并缓存。

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]*KEVEntry` | 全部 KEV 条目 |
| #2 | `error` | 加载错误 |

```go
all, err := client.GetAll()
fmt.Printf("%d 条 KEV 条目\n", len(all))
```

## ✨ EnrichVulnerabilityFinding

```go
func (c *KEVClient) EnrichVulnerabilityFinding(finding *VulnerabilityFinding) error
```

依据 finding 的 CVE 是否在 KEV 目录中，设置 `finding.KEVListed`。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `finding` | `*VulnerabilityFinding` | 要富化的 finding（就地修改） |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `error` | 查询/加载错误 |

```go
err := client.EnrichVulnerabilityFinding(finding)
```

## ✨ EnrichVulnerabilityFindings

```go
func (c *KEVClient) EnrichVulnerabilityFindings(findings []*VulnerabilityFinding) error
```

使用单次目录加载批量富化多个 finding。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `findings` | `[]*VulnerabilityFinding` | 要富化的 finding |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `error` | 加载错误 |

```go
err := client.EnrichVulnerabilityFindings(findings)
```

## 📅 GetDueDate

```go
func (c *KEVClient) GetDueDate(cveID string) (string, error)
```

返回已列出 CVE 的 BOD 22-01 修复截止日期；未列出则返回错误。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveID` | `string` | CVE 标识符 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `string` | 截止日期（目录中发布的格式） |
| #2 | `error` | 未列出时返回错误 |

```go
due, err := client.GetDueDate("CVE-2021-44228")
```

## 🦠 IsRansomwareRelated

```go
func (c *KEVClient) IsRansomwareRelated(cveID string) (bool, error)
```

返回该 CVE 是否被标记为与已知勒索软件活动相关。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveID` | `string` | CVE 标识符 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `bool` | 与勒索软件相关时为 `true` |
| #2 | `error` | 未列出时返回错误 |

```go
rw, err := client.IsRansomwareRelated("CVE-2021-44228")
```

## 🛠️ GetRequiredAction

```go
func (c *KEVClient) GetRequiredAction(cveID string) (string, error)
```

返回已列出 CVE 的要求修复措施；未列出则返回错误。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveID` | `string` | CVE 标识符 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `string` | 要求的修复措施文本 |
| #2 | `error` | 未列出时返回错误 |

```go
action, err := client.GetRequiredAction("CVE-2021-44228")
```

## 🔢 Count

```go
func (c *KEVClient) Count() (int, error)
```

返回 KEV 目录中的条目总数。

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `int` | 条目数 |
| #2 | `error` | 加载错误 |

```go
n, err := client.Count()
```

## 🔍 FilterByVendor

```go
func (c *KEVClient) FilterByVendor(vendor string) ([]*KEVEntry, error)
```

返回 `VendorProject` 匹配 `vendor` 的全部 KEV 条目。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `vendor` | `string` | 要匹配的厂商名 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]*KEVEntry` | 匹配的条目 |
| #2 | `error` | 加载错误 |

```go
ms, err := client.FilterByVendor("Microsoft")
```

## 🔍 FilterByProduct

```go
func (c *KEVClient) FilterByProduct(product string) ([]*KEVEntry, error)
```

返回 `Product` 匹配 `product` 的全部 KEV 条目。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `product` | `string` | 要匹配的产品名 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]*KEVEntry` | 匹配的条目 |
| #2 | `error` | 加载错误 |

```go
entries, err := client.FilterByProduct("Exchange Server")
```

## 🧹 ClearCache

```go
func (c *KEVClient) ClearCache()
```

清空 KEV 条目缓存与完整目录缓存，使下次查询强制重新加载目录。

```go
client.ClearCache()
```

## ⬆️ KEVSeverityBoost

```go
func KEVSeverityBoost(currentSeverity string) string
```

返回比 `currentSeverity` 高一级的严重性，反映 KEV 列出漏洞所升高的风险：`Low` → `Medium`、`Medium` → `High`、`High` → `Critical`、`Critical` → `Critical`。未知输入返回 `High`。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `currentSeverity` | `string` | 当前严重性标签 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `string` | 提升后的严重性标签 |

```go
cpeskills.KEVSeverityBoost("Medium") // High
cpeskills.KEVSeverityBoost("High")   // Critical
```

## 🧭 KEV 查询流程

```mermaid
flowchart TD
    CID[CVE ID] --> IL[IsListed]
    CID --> GE[GetEntry]
    CIDS[[]CVE ID] --> GES[GetEntries]
    CID --> DD[GetDueDate]
    CID --> RW[IsRansomwareRelated]
    CID --> RA[GetRequiredAction]
    V[vendor] --> FV[FilterByVendor]
    P[product] --> FP[FilterByProduct]
    ALL[ ] --> GA[GetAll]
    ALL --> CT[Count]
    IL & GE & GES & DD & RW & RA & FV & FP & GA & CT --> LOAD{目录已加载?}
    LOAD -->|否| FETCH[拉取 JSON Feed]
    FETCH --> CACHE[缓存目录]
    LOAD -->|是| CACHE
    CACHE --> RES[KEVEntry / bool / count]
    VF[VulnerabilityFinding] --> EVF[EnrichVulnerabilityFinding]
    VFS[[]VulnerabilityFinding] --> EVFS[EnrichVulnerabilityFindings]
    CACHE --> EVF
    CACHE --> EVFS
    style CID fill:#e8f5e9,stroke:#2e7d32
    style CACHE fill:#fff3e0,stroke:#ef6c00
    style RES fill:#f3e5f5,stroke:#6a1b9a
```

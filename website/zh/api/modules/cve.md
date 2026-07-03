---
title: CVE
outline: deep
---

# 🛡️ CVE

`cve` 模块提供表示单个漏洞的值类型 `CVEReference`（含 CVE ID、描述、日期、CVSS 评分、严重性、参考链接、受影响 CPE、任意元数据），以及构造器和变更方法，外加一组包级工具函数，用于解析、校验、分组、排序、去重和查询 CVE 引用列表。

## 类型：CVEReference

```go
type CVEReference struct {
    CVEID            string                   // CVE 标识符，如 "CVE-2021-44228"
    Description      string                   // 漏洞描述
    PublishedDate    time.Time                // 发布日期
    LastModifiedDate time.Time                // 最后修改日期
    CVSSScore        float64                  // CVSS 评分 0.0-10.0
    Severity         string                   // Low / Medium / High / Critical
    References       []string                 // 参考链接
    AffectedCPEs     []string                 // 受影响 CPE URI（2.2 或 2.3 格式）
    Metadata         map[string]interface{}   // 额外元数据
}
```

## 🆕 NewCVEReference

```go
func NewCVEReference(cveID string) *CVEReference
```

创建一个 `CVEReference`，CVE ID 经 `cve.Format` 标准化。`References` 与 `AffectedCPEs` 初始化为空切片，`Metadata` 初始化为空映射，两个日期均设为当前时间。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveID` | `string` | CVE 标识符，如 `"CVE-2021-44228"` |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*CVEReference` | 初始化后的 CVE 引用 |

```go
cve := cpeskills.NewCVEReference("CVE-2021-44228")
cve.Description = "Log4j 远程代码执行漏洞"
cve.SetSeverity(10.0)
```

## ➕ AddAffectedCPE

```go
func (cve *CVEReference) AddAffectedCPE(cpeURI string)
```

添加一个受影响 CPE URI。重复 URI 会被忽略。`LastModifiedDate` 更新为当前时间。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpeURI` | `string` | CPE URI，2.2（`cpe:/`）或 2.3（`cpe:2.3:`）格式 |

```go
cve.AddAffectedCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
```

## ➖ RemoveAffectedCPE

```go
func (cve *CVEReference) RemoveAffectedCPE(cpeURI string) bool
```

移除给定 CPE URI 的首次出现，返回是否发生移除。成功时 `LastModifiedDate` 更新。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpeURI` | `string` | 要移除的 CPE URI |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `bool` | 该 URI 存在且被移除时为 `true` |

```go
removed := cve.RemoveAffectedCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
```

## 🔗 AddReference

```go
func (cve *CVEReference) AddReference(reference string)
```

追加一个参考链接，跳过重复项。`LastModifiedDate` 更新。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `reference` | `string` | 参考 URL |

```go
cve.AddReference("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")
```

## 🎚️ SetSeverity

```go
func (cve *CVEReference) SetSeverity(cvssScore float64)
```

设置 `CVSSScore` 并据此推导 `Severity`：`>=9.0` Critical、`>=7.0` High、`>=4.0` Medium，否则 Low。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cvssScore` | `float64` | CVSS 评分，0.0–10.0 |

```go
cve.SetSeverity(9.8)
fmt.Println(cve.Severity) // Critical
```

## 🏷️ SetMetadata

```go
func (cve *CVEReference) SetMetadata(key string, value interface{})
```

在 `key` 下存储或覆盖一个元数据项。`LastModifiedDate` 更新。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `key` | `string` | 元数据键 |
| `value` | `interface{}` | 元数据值 |

```go
cve.SetMetadata("cwe", "CWE-502")
```

## 🔎 GetMetadata

```go
func (cve *CVEReference) GetMetadata(key string) (interface{}, bool)
```

返回 `key` 对应的元数据值以及该键是否存在。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `key` | `string` | 元数据键 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `interface{}` | 存储的值（不存在时为零值） |
| #2 | `bool` | 该键是否存在 |

```go
val, ok := cve.GetMetadata("cwe")
```

## 🗑️ RemoveMetadata

```go
func (cve *CVEReference) RemoveMetadata(key string) bool
```

移除一个元数据项，返回它是否存在。成功时 `LastModifiedDate` 更新。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `key` | `string` | 元数据键 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `bool` | 该键存在且被移除时为 `true` |

```go
cve.RemoveMetadata("cwe")
```

## 🔎 QueryByCVE

```go
func QueryByCVE(cves []*CVEReference, cveID string) []*CPE
```

在 `cves` 中查找 `CVEID` 匹配（经标准化后）的那一项，并将其 `AffectedCPEs` 解析为 `*CPE` 对象返回。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cves` | `[]*CVEReference` | 要搜索的 CVE 列表 |
| `cveID` | `string` | 要查找的 CVE 标识符 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]*CPE` | 匹配 CVE 受影响的 CPE；未找到则为空 |

```go
cpes := cpeskills.QueryByCVE(cveList, "CVE-2021-44228")
```

## ℹ️ GetCVEInfo

```go
func GetCVEInfo(cves []*CVEReference, cveID string) *CVEReference
```

返回 `cves` 中 `CVEID` 匹配（经标准化后）的 `CVEReference`，无则返回 `nil`。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cves` | `[]*CVEReference` | 要搜索的 CVE 列表 |
| `cveID` | `string` | CVE 标识符 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*CVEReference` | 匹配的 CVE，未找到则为 `nil` |

```go
ref := cpeskills.GetCVEInfo(cveList, "CVE-2021-44228")
```

## 📝 ExtractCVEsFromText

```go
func ExtractCVEsFromText(text string) []string
```

扫描 `text` 中的 CVE-ID 模式（`CVE-YYYY-NNNNN+`），按出现顺序返回，保留重复项。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `text` | `string` | 任意文本 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]string` | 找到的全部 CVE ID |

```go
ids := cpeskills.ExtractCVEsFromText("修复了 CVE-2021-44228 与 CVE-2021-45046。")
```

## 📅 GroupCVEsByYear

```go
func GroupCVEsByYear(cveIDs []string) map[string][]string
```

按年份分量（`CVE-YYYY-NNNNN` 中的 `YYYY`）对 CVE ID 分组。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveIDs` | `[]string` | CVE ID |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `map[string][]string` | 年份 -> CVE ID 列表 |

```go
byYear := cpeskills.GroupCVEsByYear([]string{"CVE-2021-44228", "CVE-2020-1472"})
```

## ↕️ SortCVEs

```go
func SortCVEs(cveIDs []string) []string
```

返回按年份、再按年份内编号排序的新 CVE ID 切片。不修改输入。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveIDs` | `[]string` | CVE ID |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]string` | 排序后的 CVE ID |

```go
sorted := cpeskills.SortCVEs([]string{"CVE-2021-44228", "CVE-2014-0160", "CVE-2021-45046"})
```

## 🧹 RemoveDuplicateCVEs

```go
func RemoveDuplicateCVEs(cveIDs []string) []string
```

返回去除重复项后的输入，保留首次出现顺序。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveIDs` | `[]string` | 可能含重复的 CVE ID |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]string` | 去重后的 CVE ID |

```go
unique := cpeskills.RemoveDuplicateCVEs([]string{"CVE-2021-44228", "CVE-2021-44228"})
```

## 🕒 GetRecentCVEs

```go
func GetRecentCVEs(cveIDs []string, years int) []string
```

返回年份在最近 `years` 年内（相对输入中最晚年份或当前时间）的 CVE ID。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveIDs` | `[]string` | CVE ID |
| `years` | `int` | 保留的最近年数 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]string` | 最近年份内的 CVE ID |

```go
recent := cpeskills.GetRecentCVEs(cveIDs, 3)
```

## ✅ ValidateCVE

```go
func ValidateCVE(cveID string) bool
```

返回 `cveID` 是否匹配标准 CVE 格式 `CVE-YYYY-NNNNN`（至少 4 位编号）。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cveID` | `string` | 待校验字符串 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `bool` | 字符串是合法 CVE ID 时为 `true` |

```go
cpeskills.ValidateCVE("CVE-2021-44228") // true
cpeskills.ValidateCVE("CVE-21-1")        // false
```

## 🔎 QueryByProduct

```go
func QueryByProduct(cves []*CVEReference, vendor, product string, version string) []*CVEReference
```

通过匹配每个 CVE 的 `AffectedCPEs`，返回 `cves` 中影响给定 vendor/product（可选 version）的 CVE 引用。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cves` | `[]*CVEReference` | 要过滤的 CVE 列表 |
| `vendor` | `string` | 要匹配的 CPE 厂商 |
| `product` | `string` | 要匹配的 CPE 产品 |
| `version` | `string` | CPE 版本；传 `""` 表示忽略版本 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]*CVEReference` | 匹配的 CVE 引用 |

```go
hits := cpeskills.QueryByProduct(cveList, "apache", "log4j", "2.0")
```

## 🧭 CVE 操作总览

```mermaid
flowchart TD
    ID[cveID] --> N[NewCVEReference]
    N --> MUT[AddAffectedCPE / AddReference / SetSeverity / SetMetadata]
    LIST[[]CVEReference] --> QBCVE[QueryByCVE -> []CPE]
    LIST --> GCVE[GetCVEInfo -> CVEReference]
    LIST --> QBP[QueryByProduct -> []CVEReference]
    TXT[text] --> EX[ExtractCVEsFromText]
    EX --> IDS[CVE ID 列表]
    IDS --> G[GroupCVEsByYear]
    IDS --> S[SortCVEs]
    IDS --> R[RemoveDuplicateCVEs]
    IDS --> RE[GetRecentCVEs]
    IDS --> V[ValidateCVE]
    style ID fill:#e8f5e9,stroke:#2e7d32
    style LIST fill:#e3f2fd,stroke:#1565c0
    style IDS fill:#fff3e0,stroke:#ef6c00
```

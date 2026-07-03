---
title: CPE Index
outline: deep
---

# 📇 CPE Index

`index` 模块提供 `CPEIndex`——对一组 CPE 的并发安全内存索引，支持按厂商、产品、part 或 PURL 进行 O(1) 平均复杂度的查询。专为批处理扫描场景设计：同一组 CPE 会被反复查询。`sync.RWMutex` 保护所有 map，因此读写可并发进行。

## 类型：CPEIndex

```go
type CPEIndex struct {
    mu        sync.RWMutex         // 保护所有 map 字段
    byVendor  map[string][]*CPE    // 按厂商名索引
    byProduct map[string][]*CPE    // 按产品名索引
    byPart    map[string][]*CPE    // 按 part（a/h/o）索引
    byPURL    map[string]*CPE      // 按 PURL 字符串索引
    all       []*CPE               // 索引中所有 CPE
}
```

所有字段均为非导出。厂商或产品为空或等于 `ValueANY` 的 CPE 不会被加入对应索引（但仍保留在 `all` 中）；PURL 映射需通过 `IndexPURL` 显式添加。

## 🆕 NewCPEIndex

```go
func NewCPEIndex(cpes []*CPE) *CPEIndex
```

从 CPE 切片创建新索引，构建厂商、产品、part 索引。`cpes` 中的 `nil` 条目会被跳过。`byPURL` map 初始为空（使用 `IndexPURL` 填充）。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpes` | `[]*CPE` | 要索引的初始 CPE |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*CPEIndex` | 已填充的新索引 |

```go
cpes, _ := cpeskills.NewFileStorage("/tmp/cpe-data", false).SearchCPE(nil, nil)
idx := cpeskills.NewCPEIndex(cpes)
fmt.Println(idx.Size())
```

## 🔍 Lookup

```go
func (idx *CPEIndex) Lookup(criteria *CPE) []*CPE
```

使用最快的可用索引返回匹配 `criteria` 的 CPE。优先顺序：厂商（再按产品进一步过滤）、产品、part。若 `criteria` 为 `nil` 或无可用字段，返回所有 CPE 的副本。并发读取安全。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |
| `criteria` | `*CPE` | 匹配条件；`nil` 返回全部 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]*CPE` | 匹配的 CPE（或全部的副本） |

```go
results := idx.Lookup(&cpeskills.CPE{
    Vendor:      cpeskills.Vendor("apache"),
    ProductName: cpeskills.Product("log4j"),
})
```

## 🔍 LookupByPURL

```go
func (idx *CPEIndex) LookupByPURL(purl *PackageURL) *CPE
```

返回映射到 `purl` 的 CPE，无则返回 `nil`。并发读取安全。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |
| `purl` | `*PackageURL` | 要查询的 Package URL |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*CPE` | 映射的 CPE，或 `nil` |

```go
cpe := idx.LookupByPURL(purl)
```

## ➕ IndexPURL

```go
func (idx *CPEIndex) IndexPURL(purl *PackageURL, cpe *CPE)
```

将 `purl`（按其字符串形式）映射到 `cpe`，覆盖任何已有映射。任一参数为 `nil` 时空操作。并发写入安全。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |
| `purl` | `*PackageURL` | Package URL |
| `cpe` | `*CPE` | 要关联的 CPE |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| （无） | | |

```go
idx.IndexPURL(purl, cpe)
```

## 📏 Size

```go
func (idx *CPEIndex) Size() int
```

返回索引中 CPE 的数量（`all` 的长度）。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `int` | 已索引的 CPE 数 |

```go
fmt.Println(idx.Size())
```

## 📋 All

```go
func (idx *CPEIndex) All() []*CPE
```

返回索引中所有 CPE 的副本。返回的切片可安全修改，不影响索引。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]*CPE` | 所有已索引 CPE 的副本 |

```go
all := idx.All()
```

## 🏷️ GetByVendor

```go
func (idx *CPEIndex) GetByVendor(vendor string) []*CPE
```

返回 `vendor` 下索引的所有 CPE（直接返回底层切片，非副本）。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |
| `vendor` | `string` | 厂商名 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]*CPE` | 该厂商的 CPE（无则 `nil`） |

```go
cpes := idx.GetByVendor("apache")
```

## 🏷️ GetByProduct

```go
func (idx *CPEIndex) GetByProduct(product string) []*CPE
```

返回 `product` 下索引的所有 CPE（直接返回底层切片，非副本）。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |
| `product` | `string` | 产品名 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]*CPE` | 该产品的 CPE（无则 `nil`） |

```go
cpes := idx.GetByProduct("log4j")
```

## 🏷️ GetByPart

```go
func (idx *CPEIndex) GetByPart(part string) []*CPE
```

返回 `part` 下索引的所有 CPE（part 短名：`a`、`h` 或 `o`）。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |
| `part` | `string` | part 短名 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]*CPE` | 该 part 的 CPE（无则 `nil`） |

```go
apps := idx.GetByPart("a")
```

## 📊 VendorCount

```go
func (idx *CPEIndex) VendorCount() int
```

返回索引中不同厂商的数量。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `int` | 不同厂商数 |

```go
fmt.Println(idx.VendorCount())
```

## 📊 ProductCount

```go
func (idx *CPEIndex) ProductCount() int
```

返回索引中不同产品的数量。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `int` | 不同产品数 |

```go
fmt.Println(idx.ProductCount())
```

## ➕ Add

```go
func (idx *CPEIndex) Add(cpe *CPE)
```

将 `cpe` 加入索引：追加到 `all` 并插入厂商、产品、part 索引（受空/`ValueANY` 规则约束）。`cpe` 为 `nil` 时空操作。并发写入安全。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |
| `cpe` | `*CPE` | 要添加的 CPE |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| （无） | | |

```go
idx.Add(cpe)
```

## ➖ Remove

```go
func (idx *CPEIndex) Remove(cpeURI string)
```

从 `all`、厂商、产品、PURL 索引中移除 `Cpe23` 等于 `cpeURI` 的 CPE。未找到时空操作。并发写入安全。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |
| `cpeURI` | `string` | 要移除 CPE 的 2.3 URI |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| （无） | | |

```go
idx.Remove("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
```

## 🧹 Clear

```go
func (idx *CPEIndex) Clear()
```

清空所有索引项，重置所有 map 并将 `all` 置为 `nil`。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEIndex` | 索引 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| （无） | | |

```go
idx.Clear()
```

## 🧭 CPEIndex 索引结构

```mermaid
flowchart TD
    SRC[cpes []*CPE] --> NEW[NewCPEIndex]
    NEW --> ALL[all []]
    NEW --> BV[byVendor map]
    NEW --> BP[byProduct map]
    NEW --> BT[byPart map]
    IP[IndexPURL] --> BPU[byPURL map]
    L[Lookup] --> PRF{优先厂商?}
    PRF -->|是| BV
    PRF -->|否, 有产品?| BP
    PRF -->|否, 有 part?| BT
    PRF -->|都无| ALL
    LBP[LookupByPURL] --> BPU
    ADD[Add] --> ALL
    ADD --> BV
    ADD --> BP
    ADD --> BT
    REM[Remove] --> ALL
    REM --> BV
    REM --> BP
    REM --> BPU
    CLR[Clear] --> ALL
    style NEW fill:#e8f5e9,stroke:#2e7d32
    style L fill:#e3f2fd,stroke:#1565c0
    style CLR fill:#fff3e0,stroke:#ef6c00
```

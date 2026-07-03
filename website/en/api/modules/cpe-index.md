---
title: CPE Index
outline: deep
---

# 📇 CPE Index

The `index` module provides `CPEIndex`, a concurrent-safe in-memory index over a slice of CPEs offering O(1) average lookups by vendor, product, part, or PURL. It is designed for batch scanning scenarios where the same set of CPEs is queried repeatedly. A `sync.RWMutex` guards all maps, so reads and writes can proceed concurrently.

## Type: CPEIndex

```go
type CPEIndex struct {
    mu        sync.RWMutex         // guards all map fields
    byVendor  map[string][]*CPE    // index by vendor name
    byProduct map[string][]*CPE    // index by product name
    byPart    map[string][]*CPE    // index by part (a/h/o)
    byPURL    map[string]*CPE      // index by PURL string
    all       []*CPE               // all CPEs in the index
}
```

All fields are unexported. CPEs whose vendor or product is empty or equals `ValueANY` are not added to those specific indexes (but remain in `all`); PURL mappings are added explicitly via `IndexPURL`.

## 🆕 NewCPEIndex

```go
func NewCPEIndex(cpes []*CPE) *CPEIndex
```

Creates a new index from a CPE slice, building the vendor, product, and part indexes. `nil` entries in `cpes` are skipped. The `byPURL` map starts empty (use `IndexPURL` to populate it).

| Parameter | Type | Description |
| --- | --- | --- |
| `cpes` | `[]*CPE` | Initial CPEs to index |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*CPEIndex` | A new, populated index |

```go
cpes, _ := cpeskills.NewFileStorage("/tmp/cpe-data", false).SearchCPE(nil, nil)
idx := cpeskills.NewCPEIndex(cpes)
fmt.Println(idx.Size())
```

## 🔍 Lookup

```go
func (idx *CPEIndex) Lookup(criteria *CPE) []*CPE
```

Returns CPEs matching `criteria` using the fastest available index. Preference order: vendor (then further filtered by product), product, part. If `criteria` is `nil` or has no usable field, a copy of all CPEs is returned. Thread-safe for concurrent reads.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |
| `criteria` | `*CPE` | Match criteria; `nil` returns all |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*CPE` | Matching CPEs (or a copy of all) |

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

Returns the CPE mapped to `purl`, or `nil` if none. Thread-safe for concurrent reads.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |
| `purl` | `*PackageURL` | The package URL to look up |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*CPE` | The mapped CPE, or `nil` |

```go
cpe := idx.LookupByPURL(purl)
```

## ➕ IndexPURL

```go
func (idx *CPEIndex) IndexPURL(purl *PackageURL, cpe *CPE)
```

Maps `purl` (by its string form) to `cpe`, overwriting any prior mapping. No-ops if either argument is `nil`. Thread-safe for concurrent writes.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |
| `purl` | `*PackageURL` | The package URL |
| `cpe` | `*CPE` | The CPE to associate |

| Return | Type | Description |
| --- | --- | --- |
| (none) | | |

```go
idx.IndexPURL(purl, cpe)
```

## 📏 Size

```go
func (idx *CPEIndex) Size() int
```

Returns the number of CPEs in the index (the length of `all`).

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `int` | Number of indexed CPEs |

```go
fmt.Println(idx.Size())
```

## 📋 All

```go
func (idx *CPEIndex) All() []*CPE
```

Returns a copy of all CPEs in the index. The returned slice is safe to mutate without affecting the index.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*CPE` | A copy of all indexed CPEs |

```go
all := idx.All()
```

## 🏷️ GetByVendor

```go
func (idx *CPEIndex) GetByVendor(vendor string) []*CPE
```

Returns all CPEs indexed under `vendor` (returns the underlying slice directly, not a copy).

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |
| `vendor` | `string` | Vendor name |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*CPE` | CPEs for that vendor (`nil` if none) |

```go
cpes := idx.GetByVendor("apache")
```

## 🏷️ GetByProduct

```go
func (idx *CPEIndex) GetByProduct(product string) []*CPE
```

Returns all CPEs indexed under `product` (returns the underlying slice directly, not a copy).

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |
| `product` | `string` | Product name |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*CPE` | CPEs for that product (`nil` if none) |

```go
cpes := idx.GetByProduct("log4j")
```

## 🏷️ GetByPart

```go
func (idx *CPEIndex) GetByPart(part string) []*CPE
```

Returns all CPEs indexed under `part` (the short part name: `a`, `h`, or `o`).

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |
| `part` | `string` | Short part name |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*CPE` | CPEs for that part (`nil` if none) |

```go
apps := idx.GetByPart("a")
```

## 📊 VendorCount

```go
func (idx *CPEIndex) VendorCount() int
```

Returns the number of distinct vendors in the index.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `int` | Distinct vendor count |

```go
fmt.Println(idx.VendorCount())
```

## 📊 ProductCount

```go
func (idx *CPEIndex) ProductCount() int
```

Returns the number of distinct products in the index.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `int` | Distinct product count |

```go
fmt.Println(idx.ProductCount())
```

## ➕ Add

```go
func (idx *CPEIndex) Add(cpe *CPE)
```

Adds `cpe` to the index: appended to `all` and inserted into the vendor, product, and part indexes (subject to the empty/`ValueANY` rule). No-ops if `cpe` is `nil`. Thread-safe for concurrent writes.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |
| `cpe` | `*CPE` | The CPE to add |

| Return | Type | Description |
| --- | --- | --- |
| (none) | | |

```go
idx.Add(cpe)
```

## ➖ Remove

```go
func (idx *CPEIndex) Remove(cpeURI string)
```

Removes the CPE whose `Cpe23` equals `cpeURI` from `all`, the vendor, product, and PURL indexes. No-ops if not found. Thread-safe for concurrent writes.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |
| `cpeURI` | `string` | CPE 2.3 URI of the CPE to remove |

| Return | Type | Description |
| --- | --- | --- |
| (none) | | |

```go
idx.Remove("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
```

## 🧹 Clear

```go
func (idx *CPEIndex) Clear()
```

Removes all entries from every index, resetting all maps and setting `all` to `nil`.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEIndex` | The index |

| Return | Type | Description |
| --- | --- | --- |
| (none) | | |

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
    L[Lookup] --> PRF{prefer vendor?}
    PRF -->|yes| BV
    PRF -->|no product?| BP
    PRF -->|no part?| BT
    PRF -->|nothing| ALL
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

---
title: Dictionary
outline: deep
---

# 📚 CPE Dictionary

The `dictionary` module models the NVD CPE Dictionary: a `CPEDictionary` holds a list of `CPEItem` entries, each wrapping a `CPE` plus human-readable metadata (title, references, deprecation status). The module parses the official NVD XML dictionary and re-exports it, and offers in-memory lookup and mutation helpers.

## Type: CPEDictionary

```go
type CPEDictionary struct {
    Items         []*CPEItem `json:"items" bson:"items"`           // CPE entries
    GeneratedAt   time.Time  `json:"generated_at" bson:"generated_at"` // dictionary generation time
    SchemaVersion string     `json:"schema_version" bson:"schema_version"` // CPE schema version
}
```

`CPEDictionary` is the top-level container. `Items` is the authoritative list; `GeneratedAt` and `SchemaVersion` carry provenance from the source XML.

## Type: CPEItem

```go
type CPEItem struct {
    Name            string     `json:"name" xml:"name" bson:"name"`                 // standard CPE name (2.3 form)
    Title           string     `json:"title" xml:"title" bson:"title"`              // human-readable title
    References      []Reference `json:"references" xml:"references>reference" bson:"references"` // reference links
    Deprecated      bool       `json:"deprecated" xml:"deprecated,attr" bson:"deprecated"` // deprecated flag
    DeprecationDate *time.Time `json:"deprecation_date" xml:"deprecation_date" bson:"deprecation_date"` // deprecation date
    CPE             *CPE       `json:"cpe" bson:"cpe"`                               // parsed CPE object
}
```

`CPEItem` represents a single dictionary entry. `CPE` is the parsed form of `Name` (populated by `ParseDictionary`); it is `nil` if the name could not be parsed.

## Type: Reference

```go
type Reference struct {
    URL  string `json:"url" xml:"href,attr" bson:"url"`  // reference URL
    Type string `json:"type" xml:"type" bson:"type"`     // reference type, e.g. "Vendor", "Advisory"
}
```

`Reference` is a single external link attached to a `CPEItem`.

## 📖 ParseDictionary

```go
func ParseDictionary(r io.Reader) (*CPEDictionary, error)
```

Decodes an NVD CPE Dictionary XML stream from `r`, converting each `<cpe-item>` into a `CPEItem`. Each item's `Name` is parsed (2.3 or 2.2) into `CPE`; `Deprecated`/`DeprecationDate` and `References` are populated from XML attributes/children. `GeneratedAt` is parsed as RFC3339 when present. Returns an `OperationFailedError` wrapping the XML decode error on failure.

| Parameter | Type | Description |
| --- | --- | --- |
| `r` | `io.Reader` | XML data stream |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*CPEDictionary` | The parsed dictionary |
| #2 | `error` | Non-nil (wrapped) on XML decode failure |

```go
file, _ := os.Open("official-cpe-dictionary_v2.3.xml")
defer file.Close()
dict, err := cpeskills.ParseDictionary(file)
if err != nil {
    log.Fatalf("parse: %v", err)
}
fmt.Printf("%d items\n", len(dict.Items))
```

## 📤 ExportDictionary

```go
func ExportDictionary(dict *CPEDictionary, w io.Writer) error
```

Serializes `dict` back to NVD CPE Dictionary XML, writing the XML header and an indented `<cpe-list>` to `w`. Returns an `OperationFailedError` wrapping the underlying I/O or encode error on failure.

| Parameter | Type | Description |
| --- | --- | --- |
| `dict` | `*CPEDictionary` | The dictionary to export |
| `w` | `io.Writer` | Destination for the XML |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `error` | Non-nil (wrapped) on write/encode failure |

```go
var buf bytes.Buffer
if err := cpeskills.ExportDictionary(dict, &buf); err != nil {
    log.Fatalf("export: %v", err)
}
```

## 🔍 FindItemByName

```go
func (d *CPEDictionary) FindItemByName(name string) *CPEItem
```

Returns the first item whose `Name` equals `name`, or `nil` if none.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEDictionary` | The dictionary |
| `name` | `string` | CPE name (2.3 form) to find |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*CPEItem` | The matching item, or `nil` |

```go
item := dict.FindItemByName("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
```

## 🔍 FindItemsByCriteria

```go
func (d *CPEDictionary) FindItemsByCriteria(criteria *CPE, options *MatchOptions) []*CPEItem
```

Returns all items whose parsed `CPE` matches `criteria` under `options` (via the package-internal `matchCPE`). Items with a `nil` `CPE` are skipped.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEDictionary` | The dictionary |
| `criteria` | `*CPE` | Match criteria |
| `options` | `*MatchOptions` | Match options |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*CPEItem` | Matching items (empty/nil if none) |

```go
items := dict.FindItemsByCriteria(&cpeskills.CPE{
    Vendor: cpeskills.Vendor("apache"),
}, &cpeskills.MatchOptions{IgnoreVersion: true})
```

## ➕ AddItem

```go
func (d *CPEDictionary) AddItem(item *CPEItem)
```

Adds `item` to the dictionary. If an existing item shares the same `Name`, it is replaced in place; otherwise the item is appended.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEDictionary` | The dictionary |
| `item` | `*CPEItem` | The item to add |

| Return | Type | Description |
| --- | --- | --- |
| (none) | | |

```go
dict.AddItem(cpeskills.NewCPEItem(cpe, "Apache Log4j 2.0"))
```

## ➖ RemoveItem

```go
func (d *CPEDictionary) RemoveItem(name string) bool
```

Removes the item whose `Name` equals `name`. Returns `true` if an item was removed, `false` otherwise.

| Parameter | Type | Description |
| --- | --- | --- |
| Receiver | `*CPEDictionary` | The dictionary |
| `name` | `string` | CPE name to remove |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `bool` | `true` if removed |

```go
if dict.RemoveItem("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*") {
    fmt.Println("removed")
}
```

## 🆕 NewCPEItem

```go
func NewCPEItem(cpe *CPE, title string) *CPEItem
```

Creates a `CPEItem` from `cpe` and `title`. `Name` is set to `cpe.Cpe23` when non-empty, otherwise to `FormatCpe23(cpe)`. `CPE` is set to `cpe`.

| Parameter | Type | Description |
| --- | --- | --- |
| `cpe` | `*CPE` | The CPE |
| `title` | `string` | Human-readable title |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*CPEItem` | A new dictionary item |

```go
item := cpeskills.NewCPEItem(cpe, "Apache Log4j 2.0")
dict.AddItem(item)
```

## 🧭 Dictionary 解析与查询流

```mermaid
flowchart TD
    XML[NVD XML stream] --> PD[ParseDictionary]
    PD --> DICT[CPEDictionary]
    DICT --> ITEMS[Items []*CPEItem]
    ITEMS --> NAME[Name]
    ITEMS --> TITLE[Title]
    ITEMS --> REF[References]
    ITEMS --> CPE[CPE parsed]
    PC[ParseCpe23/22] -. populates .-> CPE
    ED[ExportDictionary] --> OUT[XML output]
    DICT --> ED
    FIN[FindItemByName] --> ITEMS
    FIC[FindItemsByCriteria] --> matchCPE
    matchCPE --> CPE
    AI[AddItem] --> ITEMS
    RI[RemoveItem] --> ITEMS
    NCI[NewCPEItem] --> AI
    style PD fill:#e8f5e9,stroke:#2e7d32
    style ED fill:#e3f2fd,stroke:#1565c0
    style FIN fill:#fff3e0,stroke:#ef6c00
```

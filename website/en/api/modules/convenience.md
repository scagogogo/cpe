---
title: Convenience Functions
outline: deep
---

# 🛠️ Convenience Functions

This module exposes a set of package-level helper functions that simplify common CPE operations: parsing, validation, matching, conversion and filtering.

## 🚀 MustParse

```go
func MustParse(cpeStr string) *CPE
```

Parses a CPE string and panics on failure. Suited for constants or test code.

| Parameter | Type | Description |
| --- | --- | --- |
| `cpeStr` | `string` | The CPE string |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*CPE` | The parsed CPE object |

```go
cpe := cpeskills.MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
```

## 🔁 ParseOr

```go
func ParseOr(cpeStr string, defaultCPE *CPE) *CPE
```

Parses a CPE string, returning `defaultCPE` on failure instead of an error.

| Parameter | Type | Description |
| --- | --- | --- |
| `cpeStr` | `string` | The CPE string |
| `defaultCPE` | `*CPE` | Fallback value when parsing fails |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*CPE` | The parsed result or the default |

```go
cpe := cpeskills.ParseOr("bad-string", cpeskills.MustParse("cpe:2.3:a:*:*:*:*:*:*:*:*:*"))
```

## ✅ IsCPE23String

```go
func IsCPE23String(s string) bool
```

Reports whether the string conforms to the CPE 2.3 format.

| Parameter | Type | Description |
| --- | --- | --- |
| `s` | `string` | The string to test |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `bool` | `true` if it is a 2.3-formatted string |

```go
fmt.Println(cpeskills.IsCPE23String("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"))
```

## ✅ IsCPE22String

```go
func IsCPE22String(s string) bool
```

Reports whether the string conforms to the CPE 2.2 format.

| Parameter | Type | Description |
| --- | --- | --- |
| `s` | `string` | The string to test |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `bool` | `true` if it is a 2.2-formatted string |

```go
fmt.Println(cpeskills.IsCPE22String("cpe:/a:microsoft:windows:10"))
```

## ⚡ QuickMatch

```go
func QuickMatch(cpeStr1, cpeStr2 string) (bool, error)
```

Quickly matches two CPE strings without manual parsing.

| Parameter | Type | Description |
| --- | --- | --- |
| `cpeStr1` | `string` | The first CPE string |
| `cpeStr2` | `string` | The second CPE string |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `bool` | `true` if they match |
| #2 | `error` | An error if parsing fails |

```go
ok, err := cpeskills.QuickMatch(
    "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
    "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
)
```

## 🏷️ StringToPart

```go
func StringToPart(s string) (*Part, error)
```

Converts a string into a `Part` value.

| Parameter | Type | Description |
| --- | --- | --- |
| `s` | `string` | The part string (e.g. `a`/`o`/`h`) |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*Part` | The converted part |
| #2 | `error` | An error for invalid values |

```go
part, err := cpeskills.StringToPart("a")
```

## 📝 FormatCPE

```go
func FormatCPE(cpe *CPE, version string) (string, error)
```

Formats a CPE object according to the given CPE version (`"2.2"` or `"2.3"`).

| Parameter | Type | Description |
| --- | --- | --- |
| `cpe` | `*CPE` | The CPE object to format |
| `version` | `string` | Target version |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `string` | The formatted result |
| #2 | `error` | An error for an invalid version |

```go
cpe := cpeskills.MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
s, _ := cpeskills.FormatCPE(cpe, "2.2")
```

## 🧬 Clone

```go
func Clone(cpe *CPE) *CPE
```

Deep-copies a CPE object.

| Parameter | Type | Description |
| --- | --- | --- |
| `cpe` | `*CPE` | The CPE object to clone |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*CPE` | A new cloned object |

```go
cpe := cpeskills.MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
clone := cpeskills.Clone(cpe)
```

## 🔁 CPEsToStrings

```go
func CPEsToStrings(cpes []*CPE) []string
```

Converts a slice of CPE objects into a slice of URI strings (2.3 format).

| Parameter | Type | Description |
| --- | --- | --- |
| `cpes` | `[]*CPE` | The CPE slice |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]string` | A slice of URI strings |

```go
cpes := []*CPE{cpeskills.MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")}
strs := cpeskills.CPEsToStrings(cpes)
```

## 🔁 StringsToCPEs

```go
func StringsToCPEs(strs []string) []*CPE
```

Converts a slice of strings into a slice of CPE objects. Entries that fail to parse are skipped.

| Parameter | Type | Description |
| --- | --- | --- |
| `strs` | `[]string` | The CPE string slice |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*CPE` | The parsed CPE slice |

```go
cpes := cpeskills.StringsToCPEs([]string{"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"})
```

## 🔎 FilterByPart

```go
func FilterByPart(cpes []*CPE, part *Part) []*CPE
```

Filters a CPE list by part type.

| Parameter | Type | Description |
| --- | --- | --- |
| `cpes` | `[]*CPE` | The list to filter |
| `part` | `*Part` | The target part |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*CPE` | The matching subset |

```go
part, _ := cpeskills.StringToPart("a")
apps := cpeskills.FilterByPart(cpes, part)
```

## 🔎 FilterByVendor

```go
func FilterByVendor(cpes []*CPE, vendor string) []*CPE
```

Filters a CPE list by vendor.

| Parameter | Type | Description |
| --- | --- | --- |
| `cpes` | `[]*CPE` | The list to filter |
| `vendor` | `string` | The target vendor |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*CPE` | The matching subset |

```go
ms := cpeskills.FilterByVendor(cpes, "microsoft")
```

## 🔎 FilterByProduct

```go
func FilterByProduct(cpes []*CPE, product string) []*CPE
```

Filters a CPE list by product name.

| Parameter | Type | Description |
| --- | --- | --- |
| `cpes` | `[]*CPE` | The list to filter |
| `product` | `string` | The target product |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*CPE` | The matching subset |

```go
wins := cpeskills.FilterByProduct(cpes, "windows")
```

## 🏷️ GetPartName

```go
func GetPartName(shortName string) string
```

Converts a part short name (`a`/`o`/`h`) into its full name.

| Parameter | Type | Description |
| --- | --- | --- |
| `shortName` | `string` | The short name |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `string` | The full name |

```go
fmt.Println(cpeskills.GetPartName("a")) // application
```

## 🧭 Convenience Function Map

```mermaid
flowchart TD
    S[CPE string] --> MP[MustParse]
    S --> PO[ParseOr]
    S --> I23[IsCPE23String]
    S --> I22[IsCPE22String]
    S --> QM[QuickMatch]
    S --> STP[StringToPart]
    C[CPE object] --> FC[FormatCPE]
    C --> CL[Clone]
    CS[[]CPE] --> C2S[CPEsToStrings]
    SS[[]string] --> S2C[StringsToCPEs]
    CS --> FBP[FilterByPart]
    CS --> FBV[FilterByVendor]
    CS --> FBP2[FilterByProduct]
    style S fill:#fff3e0,stroke:#ef6c00
    style C fill:#e8f5e9,stroke:#2e7d32
```

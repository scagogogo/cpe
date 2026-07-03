---
title: CVE
outline: deep
---

# 🛡️ CVE

The `cve` module provides a `CVEReference` value type modeling a single vulnerability (CVE ID, description, dates, CVSS score, severity, references, affected CPEs, free-form metadata), along with constructors and mutation methods, plus a set of package-level utilities for parsing, validating, grouping, sorting, deduplicating, and querying lists of CVE references.

## Type: CVEReference

```go
type CVEReference struct {
    CVEID            string                   // CVE identifier, e.g. "CVE-2021-44228"
    Description      string                   // vulnerability description
    PublishedDate    time.Time                // publication date
    LastModifiedDate time.Time                // last modification date
    CVSSScore        float64                  // CVSS score 0.0-10.0
    Severity         string                   // Low / Medium / High / Critical
    References       []string                 // reference URLs
    AffectedCPEs     []string                 // affected CPE URIs (2.2 or 2.3)
    Metadata         map[string]interface{}   // extra metadata
}
```

## 🆕 NewCVEReference

```go
func NewCVEReference(cveID string) *CVEReference
```

Creates a `CVEReference` with the CVE ID normalized via `cve.Format`. `References` and `AffectedCPEs` are initialized to empty slices, `Metadata` to an empty map, and both dates to the current time.

| Parameter | Type | Description |
| --- | --- | --- |
| `cveID` | `string` | CVE identifier, e.g. `"CVE-2021-44228"` |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*CVEReference` | Initialized CVE reference |

```go
cve := cpeskills.NewCVEReference("CVE-2021-44228")
cve.Description = "Log4j remote code execution"
cve.SetSeverity(10.0)
```

## ➕ AddAffectedCPE

```go
func (cve *CVEReference) AddAffectedCPE(cpeURI string)
```

Adds an affected CPE URI. Duplicate URIs are ignored. `LastModifiedDate` is updated to the current time.

| Parameter | Type | Description |
| --- | --- | --- |
| `cpeURI` | `string` | CPE URI, 2.2 (`cpe:/`) or 2.3 (`cpe:2.3:`) format |

```go
cve.AddAffectedCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
```

## ➖ RemoveAffectedCPE

```go
func (cve *CVEReference) RemoveAffectedCPE(cpeURI string) bool
```

Removes the first occurrence of the given CPE URI. Returns whether a removal happened. `LastModifiedDate` is updated on success.

| Parameter | Type | Description |
| --- | --- | --- |
| `cpeURI` | `string` | CPE URI to remove |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `bool` | `true` if the URI was present and removed |

```go
removed := cve.RemoveAffectedCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
```

## 🔗 AddReference

```go
func (cve *CVEReference) AddReference(reference string)
```

Appends a reference URL, skipping duplicates. `LastModifiedDate` is updated.

| Parameter | Type | Description |
| --- | --- | --- |
| `reference` | `string` | Reference URL |

```go
cve.AddReference("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")
```

## 🎚️ SetSeverity

```go
func (cve *CVEReference) SetSeverity(cvssScore float64)
```

Sets `CVSSScore` and derives `Severity` from the score: `>=9.0` Critical, `>=7.0` High, `>=4.0` Medium, otherwise Low.

| Parameter | Type | Description |
| --- | --- | --- |
| `cvssScore` | `float64` | CVSS score in 0.0–10.0 |

```go
cve.SetSeverity(9.8)
fmt.Println(cve.Severity) // Critical
```

## 🏷️ SetMetadata

```go
func (cve *CVEReference) SetMetadata(key string, value interface{})
```

Stores or overwrites a metadata entry under `key`. `LastModifiedDate` is updated.

| Parameter | Type | Description |
| --- | --- | --- |
| `key` | `string` | Metadata key |
| `value` | `interface{}` | Metadata value |

```go
cve.SetMetadata("cwe", "CWE-502")
```

## 🔎 GetMetadata

```go
func (cve *CVEReference) GetMetadata(key string) (interface{}, bool)
```

Returns the metadata value for `key` and whether the key existed.

| Parameter | Type | Description |
| --- | --- | --- |
| `key` | `string` | Metadata key |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `interface{}` | The stored value (zero value if absent) |
| #2 | `bool` | Whether the key was present |

```go
val, ok := cve.GetMetadata("cwe")
```

## 🗑️ RemoveMetadata

```go
func (cve *CVEReference) RemoveMetadata(key string) bool
```

Removes a metadata entry, returning whether it existed. `LastModifiedDate` is updated on success.

| Parameter | Type | Description |
| --- | --- | --- |
| `key` | `string` | Metadata key |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `bool` | `true` if the key was present and removed |

```go
cve.RemoveMetadata("cwe")
```

## 🔎 QueryByCVE

```go
func QueryByCVE(cves []*CVEReference, cveID string) []*CPE
```

Searches `cves` for the one whose `CVEID` matches (after normalization) and returns its `AffectedCPEs` parsed into `*CPE` objects.

| Parameter | Type | Description |
| --- | --- | --- |
| `cves` | `[]*CVEReference` | The CVE list to search |
| `cveID` | `string` | CVE identifier to find |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*CPE` | CPEs affected by the matched CVE; empty if not found |

```go
cpes := cpeskills.QueryByCVE(cveList, "CVE-2021-44228")
```

## ℹ️ GetCVEInfo

```go
func GetCVEInfo(cves []*CVEReference, cveID string) *CVEReference
```

Returns the `CVEReference` in `cves` whose `CVEID` matches (after normalization), or `nil` if none.

| Parameter | Type | Description |
| --- | --- | --- |
| `cves` | `[]*CVEReference` | The CVE list to search |
| `cveID` | `string` | CVE identifier |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*CVEReference` | The matched CVE, `nil` if not found |

```go
ref := cpeskills.GetCVEInfo(cveList, "CVE-2021-44228")
```

## 📝 ExtractCVEsFromText

```go
func ExtractCVEsFromText(text string) []string
```

Scans `text` for CVE-ID patterns (`CVE-YYYY-NNNNN+`) and returns them in order of appearance, preserving duplicates.

| Parameter | Type | Description |
| --- | --- | --- |
| `text` | `string` | Arbitrary text |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]string` | All CVE IDs found |

```go
ids := cpeskills.ExtractCVEsFromText("Fixed CVE-2021-44228 and CVE-2021-45046.")
```

## 📅 GroupCVEsByYear

```go
func GroupCVEsByYear(cveIDs []string) map[string][]string
```

Groups CVE IDs by their year component (the `YYYY` in `CVE-YYYY-NNNNN`).

| Parameter | Type | Description |
| --- | --- | --- |
| `cveIDs` | `[]string` | CVE IDs |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `map[string][]string` | Year -> list of CVE IDs |

```go
byYear := cpeskills.GroupCVEsByYear([]string{"CVE-2021-44228", "CVE-2020-1472"})
```

## ↕️ SortCVEs

```go
func SortCVEs(cveIDs []string) []string
```

Returns a new slice of CVE IDs sorted chronologically by year, then by numeric sequence within the year. The input is not modified.

| Parameter | Type | Description |
| --- | --- | --- |
| `cveIDs` | `[]string` | CVE IDs |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]string` | Sorted CVE IDs |

```go
sorted := cpeskills.SortCVEs([]string{"CVE-2021-44228", "CVE-2014-0160", "CVE-2021-45046"})
```

## 🧹 RemoveDuplicateCVEs

```go
func RemoveDuplicateCVEs(cveIDs []string) []string
```

Returns the input with duplicates removed, preserving first-occurrence order.

| Parameter | Type | Description |
| --- | --- | --- |
| `cveIDs` | `[]string` | CVE IDs, possibly with duplicates |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]string` | Deduplicated CVE IDs |

```go
unique := cpeskills.RemoveDuplicateCVEs([]string{"CVE-2021-44228", "CVE-2021-44228"})
```

## 🕒 GetRecentCVEs

```go
func GetRecentCVEs(cveIDs []string, years int) []string
```

Returns CVE IDs whose year is within the last `years` years (relative to the most recent year present, or current time).

| Parameter | Type | Description |
| --- | --- | --- |
| `cveIDs` | `[]string` | CVE IDs |
| `years` | `int` | Number of recent years to keep |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]string` | CVE IDs from recent years |

```go
recent := cpeskills.GetRecentCVEs(cveIDs, 3)
```

## ✅ ValidateCVE

```go
func ValidateCVE(cveID string) bool
```

Returns whether `cveID` matches the standard CVE format `CVE-YYYY-NNNNN` (with at least four digits).

| Parameter | Type | Description |
| --- | --- | --- |
| `cveID` | `string` | String to validate |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `bool` | `true` if the string is a valid CVE ID |

```go
cpeskills.ValidateCVE("CVE-2021-44228") // true
cpeskills.ValidateCVE("CVE-21-1")        // false
```

## 🔎 QueryByProduct

```go
func QueryByProduct(cves []*CVEReference, vendor, product string, version string) []*CVEReference
```

Returns the CVE references in `cves` that affect the given vendor/product (and optionally version) by matching each CVE's `AffectedCPEs`.

| Parameter | Type | Description |
| --- | --- | --- |
| `cves` | `[]*CVEReference` | The CVE list to filter |
| `vendor` | `string` | CPE vendor to match |
| `product` | `string` | CPE product to match |
| `version` | `string` | CPE version; pass `""` to ignore version |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*CVEReference` | Matching CVE references |

```go
hits := cpeskills.QueryByProduct(cveList, "apache", "log4j", "2.0")
```

## 🧭 CVE Operations Overview

```mermaid
flowchart TD
    ID[cveID] --> N[NewCVEReference]
    N --> MUT[AddAffectedCPE / AddReference / SetSeverity / SetMetadata]
    LIST[[]CVEReference] --> QBCVE[QueryByCVE -> []CPE]
    LIST --> GCVE[GetCVEInfo -> CVEReference]
    LIST --> QBP[QueryByProduct -> []CVEReference]
    TXT[text] --> EX[ExtractCVEsFromText]
    EX --> IDS[CVE ID list]
    IDS --> G[GroupCVEsByYear]
    IDS --> S[SortCVEs]
    IDS --> R[RemoveDuplicateCVEs]
    IDS --> RE[GetRecentCVEs]
    IDS --> V[ValidateCVE]
    style ID fill:#e8f5e9,stroke:#2e7d32
    style LIST fill:#e3f2fd,stroke:#1565c0
    style IDS fill:#fff3e0,stroke:#ef6c00
```

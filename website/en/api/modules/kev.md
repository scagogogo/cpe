---
title: KEV
outline: deep
---

# 🚨 KEV

The `kev` module queries the CISA Known Exploited Vulnerabilities (KEV) catalog — the list of vulnerabilities confirmed to have been actively exploited. Under BOD 22-01, federal agencies must remediate listed vulnerabilities by their due dates. The client caches the full catalog locally and can enrich `VulnerabilityFinding` records with KEV status.

## Constant

```go
const DefaultKEVBaseURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
```

## Type: KEVClient

```go
type KEVClient struct {
    BaseURL    string        // KEV catalog JSON URL
    HTTPClient *http.Client  // HTTP client
    // unexported: cache, allCache, cacheExpiry, mu, lastRequestTime, minRequestInterval (1s rate limit)
}
```

`NewKEVClient` sets a 30-second timeout and a 1-second minimum request interval, caching entries by CVE ID and the full catalog.

## Type: KEVEntry

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

A single KEV catalog entry.

## Type: KEVResponse

```go
type KEVResponse struct {
    Title           string      `json:"title"`
    CatalogVersion  string      `json:"catalogVersion"`
    DateReleased    string      `json:"dateReleased"`
    Count           int         `json:"count"`
    Vulnerabilities []*KEVEntry `json:"vulnerabilities"`
}
```

The full KEV catalog response.

## 🆕 NewKEVClient

```go
func NewKEVClient() *KEVClient
```

Creates a `KEVClient` pointed at `DefaultKEVBaseURL` with a 30-second timeout and 1-second rate limiting.

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*KEVClient` | New KEV client |

```go
client := cpeskills.NewKEVClient()
```

## 🆕 NewKEVClientWithOptions

```go
func NewKEVClientWithOptions(baseURL string, timeout time.Duration) *KEVClient
```

Creates a `KEVClient` with a custom base URL and timeout. Empty `baseURL` and non-positive `timeout` fall back to defaults.

| Parameter | Type | Description |
| --- | --- | --- |
| `baseURL` | `string` | KEV catalog URL; `""` for default |
| `timeout` | `time.Duration` | HTTP timeout; `<=0` for default (30s) |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*KEVClient` | New KEV client |

```go
client := cpeskills.NewKEVClientWithOptions("", 60*time.Second)
```

## ✅ IsListed

```go
func (c *KEVClient) IsListed(cveID string) (bool, error)
```

Returns whether the CVE is present in the KEV catalog.

| Parameter | Type | Description |
| --- | --- | --- |
| `cveID` | `string` | CVE identifier |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `bool` | `true` if listed in KEV |
| #2 | `error` | Query/load error |

```go
listed, err := client.IsListed("CVE-2021-44228")
```

## 📋 GetEntry

```go
func (c *KEVClient) GetEntry(cveID string) (*KEVEntry, error)
```

Returns the KEV entry for a CVE, or `nil` (no error) when it is not listed.

| Parameter | Type | Description |
| --- | --- | --- |
| `cveID` | `string` | CVE identifier |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*KEVEntry` | The matching entry, `nil` if not listed |
| #2 | `error` | Query/load error |

```go
entry, err := client.GetEntry("CVE-2021-44228")
```

## 📋 GetEntries

```go
func (c *KEVClient) GetEntries(cveIDs []string) (map[string]*KEVEntry, error)
```

Returns KEV entries for multiple CVEs, keyed by CVE ID. Unlisted CVEs are omitted from the map.

| Parameter | Type | Description |
| --- | --- | --- |
| `cveIDs` | `[]string` | CVE identifiers |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `map[string]*KEVEntry` | CVE ID -> entry (only listed ones) |
| #2 | `error` | Query/load error |

```go
entries, err := client.GetEntries([]string{"CVE-2021-44228", "CVE-2021-40444"})
```

## 📚 GetAll

```go
func (c *KEVClient) GetAll() ([]*KEVEntry, error)
```

Returns the entire KEV catalog, loading and caching it on first access.

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*KEVEntry` | All KEV entries |
| #2 | `error` | Load error |

```go
all, err := client.GetAll()
fmt.Printf("%d KEV entries\n", len(all))
```

## ✨ EnrichVulnerabilityFinding

```go
func (c *KEVClient) EnrichVulnerabilityFinding(finding *VulnerabilityFinding) error
```

Sets `finding.KEVListed` based on whether the finding's CVE is in the KEV catalog.

| Parameter | Type | Description |
| --- | --- | --- |
| `finding` | `*VulnerabilityFinding` | Finding to enrich (modified in place) |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `error` | Query/load error |

```go
err := client.EnrichVulnerabilityFinding(finding)
```

## ✨ EnrichVulnerabilityFindings

```go
func (c *KEVClient) EnrichVulnerabilityFindings(findings []*VulnerabilityFinding) error
```

Batch-enriches multiple findings using a single catalog load.

| Parameter | Type | Description |
| --- | --- | --- |
| `findings` | `[]*VulnerabilityFinding` | Findings to enrich |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `error` | Load error |

```go
err := client.EnrichVulnerabilityFindings(findings)
```

## 📅 GetDueDate

```go
func (c *KEVClient) GetDueDate(cveID string) (string, error)
```

Returns the BOD 22-01 remediation due date for a listed CVE, or an error if not listed.

| Parameter | Type | Description |
| --- | --- | --- |
| `cveID` | `string` | CVE identifier |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `string` | Due date (as published in the catalog) |
| #2 | `error` | Error if not listed |

```go
due, err := client.GetDueDate("CVE-2021-44228")
```

## 🦠 IsRansomwareRelated

```go
func (c *KEVClient) IsRansomwareRelated(cveID string) (bool, error)
```

Returns whether the CVE is flagged as associated with a known ransomware campaign.

| Parameter | Type | Description |
| --- | --- | --- |
| `cveID` | `string` | CVE identifier |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `bool` | `true` if ransomware-related |
| #2 | `error` | Error if not listed |

```go
rw, err := client.IsRansomwareRelated("CVE-2021-44228")
```

## 🛠️ GetRequiredAction

```go
func (c *KEVClient) GetRequiredAction(cveID string) (string, error)
```

Returns the required remediation action for a listed CVE, or an error if not listed.

| Parameter | Type | Description |
| --- | --- | --- |
| `cveID` | `string` | CVE identifier |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `string` | Required action text |
| #2 | `error` | Error if not listed |

```go
action, err := client.GetRequiredAction("CVE-2021-44228")
```

## 🔢 Count

```go
func (c *KEVClient) Count() (int, error)
```

Returns the total number of entries in the KEV catalog.

| Return | Type | Description |
| --- | --- | --- |
| #1 | `int` | Entry count |
| #2 | `error` | Load error |

```go
n, err := client.Count()
```

## 🔍 FilterByVendor

```go
func (c *KEVClient) FilterByVendor(vendor string) ([]*KEVEntry, error)
```

Returns all KEV entries whose `VendorProject` matches `vendor`.

| Parameter | Type | Description |
| --- | --- | --- |
| `vendor` | `string` | Vendor name to match |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*KEVEntry` | Matching entries |
| #2 | `error` | Load error |

```go
ms, err := client.FilterByVendor("Microsoft")
```

## 🔍 FilterByProduct

```go
func (c *KEVClient) FilterByProduct(product string) ([]*KEVEntry, error)
```

Returns all KEV entries whose `Product` matches `product`.

| Parameter | Type | Description |
| --- | --- | --- |
| `product` | `string` | Product name to match |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*KEVEntry` | Matching entries |
| #2 | `error` | Load error |

```go
entries, err := client.FilterByProduct("Exchange Server")
```

## 🧹 ClearCache

```go
func (c *KEVClient) ClearCache()
```

Empties the KEV entry cache and full-catalog cache, forcing the next query to reload the catalog.

```go
client.ClearCache()
```

## ⬆️ KEVSeverityBoost

```go
func KEVSeverityBoost(currentSeverity string) string
```

Returns a severity one level higher than `currentSeverity`, reflecting the elevated risk of a KEV-listed vulnerability: `Low` → `Medium`, `Medium` → `High`, `High` → `Critical`, `Critical` → `Critical`. Unknown inputs return `High`.

| Parameter | Type | Description |
| --- | --- | --- |
| `currentSeverity` | `string` | Current severity label |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `string` | Boosted severity label |

```go
cpeskills.KEVSeverityBoost("Medium") // High
cpeskills.KEVSeverityBoost("High")   // Critical
```

## 🧭 KEV Query Flow

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
    IL & GE & GES & DD & RW & RA & FV & FP & GA & CT --> LOAD{catalog loaded?}
    LOAD -->|no| FETCH[fetch JSON feed]
    FETCH --> CACHE[cache catalog]
    LOAD -->|yes| CACHE
    CACHE --> RES[KEVEntry / bool / count]
    VF[VulnerabilityFinding] --> EVF[EnrichVulnerabilityFinding]
    VFS[[]VulnerabilityFinding] --> EVFS[EnrichVulnerabilityFindings]
    CACHE --> EVF
    CACHE --> EVFS
    style CID fill:#e8f5e9,stroke:#2e7d32
    style CACHE fill:#fff3e0,stroke:#ef6c00
    style RES fill:#f3e5f5,stroke:#6a1b9a
```

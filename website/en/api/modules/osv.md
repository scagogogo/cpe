---
title: OSV
outline: deep
---

# 🌍 OSV

The `osv` module queries the Open Source Vulnerabilities (OSV) database at `https://api.osv.dev/v1`. It supports single and batch queries by package URL (PURL), exposes the OSV request/response structs, and models results with the `OSVEntry` type.

## Constant

```go
const DefaultOSVBaseURL = "https://api.osv.dev/v1"
```

## Type: OSVClient

```go
type OSVClient struct {
    BaseURL            string        // OSV API base URL
    HTTPClient         *http.Client  // HTTP client
    RetryCount         int           // retry count on failure
    RetryDelay         time.Duration // delay between retries
    // unexported: mu, lastRequestTime, minRequestInterval (rate limiting)
}
```

HTTP client for the OSV API. `NewOSVClient` sets a 30-second timeout, 3 retries, 1-second retry delay, and a 100ms minimum request interval.

## Type: OSVQuery

```go
type OSVQuery struct {
    Package *OSVPackage `json:"package,omitempty"`
    Version string      `json:"version,omitempty"`
    Commit  string      `json:"commit,omitempty"`
}
```

Single-query request body.

## Type: OSVQueryBatch

```go
type OSVQueryBatch struct {
    Queries []*OSVQuery `json:"queries"`
}
```

Batch-query request body.

## Type: OSVQueryResult

```go
type OSVQueryResult struct {
    Vulns []*OSVEntry `json:"vulns,omitempty"`
}
```

Single-query response.

## Type: OSVBatchResult

```go
type OSVBatchResult struct {
    Results []*OSVQueryResult `json:"results"`
}
```

Batch-query response; one `OSVQueryResult` per input query, in order.

## Type: OSVEntry

```go
type OSVEntry struct {
    ID              string                   `json:"id"`                  // OSV ID, e.g. "GHSA-xxxx-xxxx-xxxx"
    Summary         string                   `json:"summary,omitempty"`
    Details         string                   `json:"details,omitempty"`
    Aliases         []string                 `json:"aliases,omitempty"`   // e.g. CVE IDs
    Modified        time.Time                `json:"modified,omitempty"`
    Published       time.Time                `json:"published,omitempty"`
    Severity        []*OSVSeverity           `json:"severity,omitempty"`
    Affected        []*OSVAffected           `json:"affected,omitempty"`
    References      []*OSVReference          `json:"references,omitempty"`
    DatabaseSpecific map[string]interface{}  `json:"databaseSpecific,omitempty"`
}
```

A single OSV vulnerability record. Supporting sub-types (`OSVSeverity`, `OSVAffected`, `OSVPackage`, `OSVRange`, `OSVEvent`, `OSVReference`) are defined in the `vulnerability_report` source.

## 🆕 NewOSVClient

```go
func NewOSVClient() *OSVClient
```

Creates an `OSVClient` pointed at `DefaultOSVBaseURL` with a 30-second timeout, 3 retries, 1-second retry delay, and 100ms minimum request interval.

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*OSVClient` | New OSV client |

```go
client := cpeskills.NewOSVClient()
```

## 🆕 NewOSVClientWithOptions

```go
func NewOSVClientWithOptions(baseURL string, timeout time.Duration, retryCount int) *OSVClient
```

Creates an `OSVClient` with custom options. Empty `baseURL`, non-positive `timeout`, and non-positive `retryCount` fall back to defaults.

| Parameter | Type | Description |
| --- | --- | --- |
| `baseURL` | `string` | OSV API base URL; `""` for default |
| `timeout` | `time.Duration` | HTTP timeout; `<=0` for default (30s) |
| `retryCount` | `int` | Retry count; `<=0` for default (3) |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*OSVClient` | New OSV client |

```go
client := cpeskills.NewOSVClientWithOptions("", 60*time.Second, 5)
```

## 🔎 QueryOSV

```go
func QueryOSV(purl *PackageURL) ([]*OSVEntry, error)
```

Convenience function that creates a default `OSVClient` and queries vulnerabilities for a single PURL.

| Parameter | Type | Description |
| --- | --- | --- |
| `purl` | `*PackageURL` | Package URL to query |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*OSVEntry` | Matching vulnerability entries |
| #2 | `error` | Query error |

```go
purl, _ := cpeskills.ParsePurl("pkg:golang/github.com/apache/log4j@2.0")
vulns, err := cpeskills.QueryOSV(purl)
```

## 🔎 QueryOSVBatch

```go
func QueryOSVBatch(purls []*PackageURL) (map[string][]*OSVEntry, error)
```

Convenience function that creates a default `OSVClient` and batch-queries vulnerabilities for up to 1000 PURLs. Returns a map keyed by the PURL string.

| Parameter | Type | Description |
| --- | --- | --- |
| `purls` | `[]*PackageURL` | Package URLs to query (max 1000) |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `map[string][]*OSVEntry` | PURL string -> vulnerability entries |
| #2 | `error` | Query error (including over-limit) |

```go
results, err := cpeskills.QueryOSVBatch([]*cpeskills.PackageURL{p1, p2})
for purl, vulns := range results {
    fmt.Printf("%s: %d vulns\n", purl, len(vulns))
}
```

## 🧭 OSV Query Flow

```mermaid
flowchart TD
    P[PackageURL] --> Q[QueryOSV]
    PS[[]PackageURL max 1000] --> QB[QueryOSVBatch]
    Q --> C1[default OSVClient]
    QB --> C2[default OSVClient]
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

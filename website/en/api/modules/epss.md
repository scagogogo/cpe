---
title: EPSS
outline: deep
---

# 📊 EPSS

The `epss` module queries the Exploit Prediction Scoring System (EPSS) API at FIRST.org. EPSS predicts the probability that a given CVE will be exploited in the next 30 days (score 0.0–1.0), updated daily. The client caches results and can enrich `VulnerabilityFinding` records in place.

## Constant

```go
const DefaultEPSSBaseURL = "https://api.first.org/data/v1/epss"
```

## Type: EPSSClient

```go
type EPSSClient struct {
    BaseURL            string        // EPSS API base URL
    HTTPClient         *http.Client  // HTTP client
    // unexported: cache, cacheExpiry, mu, lastRequestTime, minRequestInterval (500ms rate limit)
}
```

`NewEPSSClient` sets a 60-second timeout and a 500ms minimum request interval, with in-memory caching.

## Type: EPSSEntry

```go
type EPSSEntry struct {
    CVEID      string  `json:"cve"`        // CVE identifier
    EPSSScore  float64 `json:"epss"`       // exploit probability 0.0-1.0
    Percentile float64 `json:"percentile"` // relative rank 0.0-1.0
    Date       string  `json:"date"`       // scoring date
}
```

A single EPSS scoring record.

## Type: EPSSResponse

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

Raw EPSS API response. The `Data` slice carries string-typed scores that are parsed into `EPSSEntry` floats.

## 🆕 NewEPSSClient

```go
func NewEPSSClient() *EPSSClient
```

Creates an `EPSSClient` pointed at `DefaultEPSSBaseURL` with a 60-second timeout and 500ms rate limiting.

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*EPSSClient` | New EPSS client |

```go
client := cpeskills.NewEPSSClient()
```

## 🆕 NewEPSSClientWithOptions

```go
func NewEPSSClientWithOptions(baseURL string, timeout time.Duration) *EPSSClient
```

Creates an `EPSSClient` with a custom base URL and timeout. Empty `baseURL` and non-positive `timeout` fall back to defaults.

| Parameter | Type | Description |
| --- | --- | --- |
| `baseURL` | `string` | EPSS API base URL; `""` for default |
| `timeout` | `time.Duration` | HTTP timeout; `<=0` for default (60s) |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*EPSSClient` | New EPSS client |

```go
client := cpeskills.NewEPSSClientWithOptions("", 120*time.Second)
```

## 📈 GetScore

```go
func (c *EPSSClient) GetScore(cveID string) (*EPSSEntry, error)
```

Returns the EPSS entry for a single CVE. Cache hits return immediately; misses trigger an API request.

| Parameter | Type | Description |
| --- | --- | --- |
| `cveID` | `string` | CVE identifier |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*EPSSEntry` | EPSS entry |
| #2 | `error` | Query error |

```go
entry, err := client.GetScore("CVE-2021-44228")
fmt.Printf("EPSS=%.4f percentile=%.4f\n", entry.EPSSScore, entry.Percentile)
```

## 📈 GetScores

```go
func (c *EPSSClient) GetScores(cveIDs []string) (map[string]*EPSSEntry, error)
```

Returns EPSS entries for multiple CVEs in a single API request, keyed by CVE ID.

| Parameter | Type | Description |
| --- | --- | --- |
| `cveIDs` | `[]string` | CVE identifiers |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `map[string]*EPSSEntry` | CVE ID -> EPSS entry |
| #2 | `error` | Query error |

```go
scores, err := client.GetScores([]string{"CVE-2021-44228", "CVE-2021-45046"})
```

## ✨ EnrichVulnerabilityFinding

```go
func (c *EPSSClient) EnrichVulnerabilityFinding(finding *VulnerabilityFinding) error
```

Fetches the EPSS score for `finding`'s CVE and writes it to `finding.EPSSScore`. No-op when the finding has no CVE or the CVE is not found.

| Parameter | Type | Description |
| --- | --- | --- |
| `finding` | `*VulnerabilityFinding` | Finding to enrich (modified in place) |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `error` | Query error |

```go
err := client.EnrichVulnerabilityFinding(finding)
```

## ✨ EnrichVulnerabilityFindings

```go
func (c *EPSSClient) EnrichVulnerabilityFindings(findings []*VulnerabilityFinding) error
```

Batch-enriches multiple findings, fetching scores for all their CVEs in one request.

| Parameter | Type | Description |
| --- | --- | --- |
| `findings` | `[]*VulnerabilityFinding` | Findings to enrich |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `error` | Query error |

```go
err := client.EnrichVulnerabilityFindings(findings)
```

## ⚠️ IsHighRisk

```go
func (e *EPSSEntry) IsHighRisk() bool
```

Returns whether the EPSS score is at least 0.1 (10% exploit probability).

| Return | Type | Description |
| --- | --- | --- |
| #1 | `bool` | `true` if `EPSSScore >= 0.1` |

```go
if entry.IsHighRisk() { /* prioritize remediation */ }
```

## 🚨 IsCriticalRisk

```go
func (e *EPSSEntry) IsCriticalRisk() bool
```

Returns whether the EPSS score is at least 0.5 (50% exploit probability).

| Return | Type | Description |
| --- | --- | --- |
| #1 | `bool` | `true` if `EPSSScore >= 0.5` |

```go
if entry.IsCriticalRisk() { /* emergency remediation */ }
```

## 🏷️ GetRiskLevel

```go
func (e *EPSSEntry) GetRiskLevel() string
```

Returns a discrete risk level derived from the score: `Critical` (>=0.5), `High` (>=0.1), `Medium` (>=0.01), otherwise `Low`.

| Return | Type | Description |
| --- | --- | --- |
| #1 | `string` | `"Critical"`, `"High"`, `"Medium"`, or `"Low"` |

```go
fmt.Println(entry.GetRiskLevel())
```

## 🧹 ClearCache

```go
func (c *EPSSClient) ClearCache()
```

Empties the in-memory EPSS score cache.

```go
client.ClearCache()
```

## 📏 CacheSize

```go
func (c *EPSSClient) CacheSize() int
```

Returns the number of entries currently in the cache.

| Return | Type | Description |
| --- | --- | --- |
| #1 | `int` | Cache entry count |

```go
fmt.Printf("cached %d scores\n", client.CacheSize())
```

## 🧮 EPSSScoreToRiskFactor

```go
func EPSSScoreToRiskFactor(epssScore float64) float64
```

Maps an EPSS score (0.0–1.0) to a 0–10 risk factor via a logarithmic transform. Reference points: EPSS 0.001 → ~1.0, 0.01 → ~3.3, 0.1 → ~6.7, 0.5 → ~9.0, 0.9 → ~10.0. Scores `<=0` return 0.

| Parameter | Type | Description |
| --- | --- | --- |
| `epssScore` | `float64` | EPSS score 0.0–1.0 |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `float64` | Risk factor 0.0–10.0 |

```go
factor := cpeskills.EPSSScoreToRiskFactor(0.5) // ~9.0
```

## 🧭 EPSS Enrichment Flow

```mermaid
flowchart TD
    CID[CVE ID] --> GS[GetScore]
    CIDS[[]CVE ID] --> GB[GetScores]
    GS --> CACHE{cache hit?}
    CACHE -->|yes| E1[EPSSEntry]
    CACHE -->|no| API[EPSS API]
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

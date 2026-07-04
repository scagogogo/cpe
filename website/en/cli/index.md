---
title: CLI Overview
outline: deep
---

# 🛠️ CLI Overview

The `cpe` command-line tool provides command-line access to the core functionality of the `cpe-skills` library — parsing, matching, searching, and dictionary operations for CPE (Common Platform Enumeration) identifiers, plus an MCP server mode for AI assistants.

## Installation

Install the CLI with `go install`:

```sh
go install github.com/scagogogo/cpe-skills/cmd/cpe@latest
```

Verify the installation:

```sh
cpe version
```

Expected output:

```text
cpe CLI:     0.1.0
Git Commit:  unknown
Build Date:  unknown
Go Version:  go1.23.x
OS/Arch:     linux/amd64
```

## Global Flags

These flags are defined on the root command and inherited by every subcommand.

| Flag         | Shorthand | Type   | Default | Description                          |
| ------------ | --------- | ------ | ------- | ------------------------------------ |
| `--output`   | `-o`      | string | `text`  | Output format (`text` or `json`)     |
| `--no-color` |           | bool   | `false` | Disable colored output               |

## Subcommands

The CLI exposes 30 subcommands organized into five capability groups.

### Core Operations

| Command    | Description                                                       |
| ---------- | ----------------------------------------------------------------- |
| `parse`    | Parse a CPE 2.2/2.3 string and display its components            |
| `validate` | Validate a CPE string and report any issues                      |
| `normalize`| Normalize a CPE string to its canonical form                    |
| `generate` | Generate a CPE string from components (part/vendor/product/ver)  |
| `vcmp`     | Compare two version strings (`vcmp a b`, `vcmp in-range v ...`)  |
| `relation` | Determine the set relation between two CPEs (equal/subset/...)   |
| `match`    | Check if two CPEs match (NISTIR 7696 semantics)                  |
| `search`   | Search CPEs from input that match criteria                       |
| `wfn`      | Well-Formed Name binding conversions (to-fs/to-uri/from-*)       |

### Vulnerability Data

| Command | Description                                                              |
| ------- | ------------------------------------------------------------------------ |
| `nvd`   | NVD operations: download, cves-for-cpe, cpes-for-cve                     |
| `cve`   | CVE utilities: validate, extract (stdin), sort (stdin)                   |
| `epss`  | Query EPSS exploit-prediction score for a CVE                            |
| `kev`   | CISA Known Exploited Vulnerabilities catalog (is-listed/get/list)        |
| `osv`   | Query OSV (Open Source Vulnerabilities) database by purl or ecosystem    |

### PURL & SBOM

| Command      | Description                                                          |
| ------------ | -------------------------------------------------------------------- |
| `purl`       | Package URL utilities (parse / build)                               |
| `cpe-to-purl`| Convert CPE to Package URL with confidence score                    |
| `purl-to-cpe`| Convert Package URL to CPE with confidence score                    |
| `sbom`       | SBOM operations: parse / from-manifest / export / diff / validate    |

### VEX, Risk, Export, License

| Command   | Description                                                              |
| --------- | ------------------------------------------------------------------------ |
| `vex`     | Vulnerability Exploitability eXchange: parse / build                    |
| `risk`    | Risk scoring for SBOM components (`risk score --sbom --nvd`)            |
| `export`  | Export vulnerability reports to CSV or SARIF                            |
| `license` | License utilities (list-common, detect-by-name)                         |

### Advanced Analysis

| Command         | Description                                                       |
| --------------- | ----------------------------------------------------------------- |
| `applicability` | Applicability expression parse / filter                          |
| `batch`         | Batch CPE matching and SBOM scanning                              |
| `store`         | Persistent file-based CPE storage (init/put/get/delete/list)      |
| `graph`         | Dependency graph build / topological sort                         |
| `reach`         | Reachability analysis for vulnerabilities                         |
| `dict`          | CPE dictionary operations (parse / search XML)                    |
| `mcp`           | MCP (Model Context Protocol) server commands                      |
| `version`       | Print version information                                         |

## Subcommand Map

The diagram below shows how a request flows from the root `cpe` command into one of its subcommands groups, and which library module group each ultimately calls.

```mermaid
flowchart TD
    Root["cpe &lt;cmd&gt; [flags]"] --> Core["Core ops<br/>parse/validate/normalize/generate<br/>vcmp/relation/match/search/wfn"]
    Root --> Vuln["Vuln data<br/>nvd/cve/epss/kev/osv"]
    Root -> Supply["Supply chain<br/>purl/cpe-to-purl/purl-to-cpe/sbom"]
    Root --> Report["Reporting<br/>vex/risk/export/license"]
    Root --> Adv["Advanced<br/>applicability/batch/store<br/>graph/reach/dict/mcp/version"]

    Core --> LibP["Parser / Validation / Generation / WFN / Matching"]
    Vuln --> LibV["NVD / CVE / EPSS / KEV / OSV clients"]
    Supply --> LibS["PURL / SBOM / CycloneDX / SPDX"]
    Report --> LibR["VEX / Risk Scoring / Export / License"]
    Adv --> LibA["Applicability / Batch / Storage / DepGraph / Reachability"]
```

## Quick Reference

```sh
# Parse a CPE and show its components
cpe parse "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"

# Validate a CPE string (exits 0 if valid, 1 otherwise)
cpe validate "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"

# Normalize a CPE (also normalize vendor/product aliases with --vendor)
cpe normalize --vendor "cpe:2.3:a:Microsoft Corp.:Windows:10:*:*:*:*:*:*:*"

# Generate a CPE from components
cpe generate --part a --vendor microsoft --product windows --version 10

# Compare two versions (-1/0/1)
cpe vcmp 1.0 1.1

# Check if a version falls within a range
cpe vcmp in-range 3.5 --min 3.0 --max 4.0

# Determine the set relation between two CPEs
cpe relation "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*" "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"

# Validate / extract / sort CVE identifiers
cpe cve validate CVE-2021-44228
echo "see CVE-2021-44228 and CVE-2024-12345" | cpe cve extract
printf "CVE-2024-1\nCVE-2021-2\n" | cpe cve sort

# Parse / build a Package URL
cpe purl parse pkg:npm/left-pad@1.3.0
cpe purl build --type npm --name left-pad --version 1.3.0

# Convert between CPE and PURL (with confidence score)
cpe cpe-to-purl "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"
cpe purl-to-cpe pkg:npm/left-pad@1.3.0

# WFN binding conversions
cpe wfn to-fs "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"
cpe wfn to-uri "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"

# License utilities
cpe license list-common
cpe license detect-by-name "MIT License"

# Applicability expression
cpe applicability parse "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"

# Persistent CPE storage
cpe store init --dir ./cpe-db
cpe store put "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*" --dir ./cpe-db
cpe store get "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*" --dir ./cpe-db

# Network commands (need connectivity / cached data)
cpe nvd download --cache-dir ~/.cache/nvd
cpe nvd cves-for-cpe "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*" --data ~/.cache/nvd/nvd_data.json
cpe epss CVE-2021-44228
cpe kev is-listed CVE-2021-44228
cpe osv query --purl pkg:npm/left-pad@1.3.0

# SBOM operations
cpe sbom parse --cyclonedx bom.json
cpe sbom from-manifest go.mod
cpe sbom diff old.json new.json
cpe sbom validate bom.json

# VEX / Risk / Export
cpe vex build --product "MyApp" --cve CVE-2021-44228 --status not_affected --justification component_not_present
cpe risk score --sbom sbom.json --nvd nvd.json --priority critical
cpe export csv --sbom sbom.json --nvd nvd.json -o report.csv
cpe export sarif --sbom sbom.json --nvd nvd.json -o report.sarif

# Batch matching / dependency graph / reachability
cpe batch match --criteria crits.txt --targets targets.txt
cpe graph topo --sbom sbom.json
cpe reach analyze --sbom sbom.json --nvd nvd.json

# Start the MCP server on stdio
cpe mcp serve

# Get JSON output from any command
cpe -o json parse "cpe:/a:apache:log4j:2.0"
```

## Exit Codes

The CLI exits with code `0` on success and `1` on error. Error messages are written to standard error.

## Related Documentation

- [API: Parsing](../api/parsing) — the parser modules behind `cpe parse`
- [API: Matching](../api/matching) — the matching algorithm behind `cpe match` / `cpe search`
- [API: Dictionary](../api/dictionary) — the dictionary module behind `cpe dict`
- [Guide: Basic Parsing](../guide/basic-parsing) — a walkthrough of parsing concepts

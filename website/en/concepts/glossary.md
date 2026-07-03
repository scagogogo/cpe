---
title: Glossary
outline: deep
---

# 📖 Glossary

Terms used throughout the `cpeskills` documentation and the wider CPE / vulnerability-management ecosystem.

| Term      | Expansion                                          | Meaning                                                                                       |
|-----------|----------------------------------------------------|-----------------------------------------------------------------------------------------------|
| CPE       | Common Platform Enumeration                        | NIST standard for naming IT products (software, OS, hardware). See [/en/concepts/cpe-overview](/en/concepts/cpe-overview). |
| WFN       | Well-Formed Name                                   | The logical, attribute-based representation a CPE 2.2/2.3 string maps to. See [/en/api/modules/wfn](/en/api/modules/wfn). |
| CVE       | Common Vulnerabilities and Exposures               | A unique `CVE-YYYY-NNNNN` identifier for a publicly disclosed security vulnerability.         |
| NVD       | National Vulnerability Database                    | NIST's database of CVEs and their affected CPEs. See [/en/concepts/nvd](/en/concepts/nvd).     |
| OSV       | Open Source Vulnerabilities                        | An open, distributed vulnerability database for open-source packages. See [/en/concepts/osv](/en/concepts/osv). |
| EPSS      | Exploit Prediction Scoring System                  | A 0–1 probability that a given CVE will be exploited in the wild within 30 days.              |
| KEV       | Known Exploited Vulnerabilities                    | CISA's catalogue of vulnerabilities known to be actively exploited; carries remediation due dates. |
| SBOM      | Software Bill of Materials                         | A machine-readable inventory of components in a software product.                             |
| VEX       | Vulnerability Exploitability eXchange              | An assertion document stating whether a product is affected by specific CVEs. See [/en/concepts/vex](/en/concepts/vex). |
| PURL      | Package URL                                        | A `pkg:` URI that identifies a package by type, namespace, name, version. See [/en/concepts/purl](/en/concepts/purl). |
| CycloneDX | —                                                  | An OWASP SBOM standard (JSON/XML). `ParseCycloneDXJSON` reads it.                             |
| SPDX      | Software Package Data Exchange                     | A Linux Foundation SBOM standard. `ParseSPDXJSON` reads it.                                   |
| SARIF     | Static Analysis Results Interchange Format         | A JSON format for reporting static-analysis findings, used by many scanners.                  |
| CVSS      | Common Vulnerability Scoring System                | A framework for scoring vulnerability severity (e.g. CVSS 3.1 base score 0–10).               |
| ANY       | —                                                  | The CPE wildcard `*` — matches any value in a comparison.                                     |
| NA        | Not Applicable                                     | The CPE value `-` — the attribute has no meaningful value; only matches another `-`.          |
| NISTIR    | NIST Interagency Report                            | NIST's technical report series; the CPE specification is published as NISTIR 7695/7696.       |

## Matching terminology

CPE name matching (NISTIR 7696) defines relations between two CPE names. These terms appear throughout the matching docs.

| Term        | Meaning                                                                    |
|-------------|----------------------------------------------------------------------------|
| Superset    | One CPE covers a broader set than another (`IsSupersetOf`).                |
| Subset      | The inverse — a CPE is contained within another's scope (`IsSubsetOf`).   |
| Equal       | The two CPEs name the same thing (`IsEqualTo`).                           |
| Disjoint    | The two CPEs share no overlap (`IsDisjointWith`).                         |
| ANY (`*`)   | Wildcard — matches any value on the other side.                           |
| NA (`-`)    | Not applicable — matches only another NA.                                 |

See [/en/concepts/matching-relations](/en/concepts/matching-relations) for the full relation matrix.

## Attribute-field shorthand

The 11 fields of a CPE 2.3 Formatted String, in order:

`cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>`

| # | Field         | WFN attribute         |
|---|---------------|-----------------------|
| 1 | part          | `part`                |
| 2 | vendor        | `vendor`              |
| 3 | product       | `product`             |
| 4 | version       | `version`             |
| 5 | update        | `update`              |
| 6 | edition       | `edition`             |
| 7 | language      | `language`            |
| 8 | sw_edition    | `sw_edition`          |
| 9 | target_sw     | `target_sw`           |
|10 | target_hw     | `target_hw`           |
|11 | other         | `target_hw`/`other`   |

## Part values

| Short | Long form    | Meaning          |
|-------|--------------|------------------|
| `a`   | application  | Software app     |
| `o`   | operating system | OS           |
| `h`   | hardware     | Hardware device  |

## Summary

When a term is ambiguous, fall back to this table. The two CPE-specific sentinels to remember are `*` (ANY, wildcard) and `-` (NA, not applicable); their matching semantics differ and are the source of most beginner mistakes.

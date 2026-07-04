package main

import (
	"encoding/json"
	"fmt"
	"os"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// nvd.go — `cpe nvd` parent + subcommands:
//   - `cpe nvd download [--cache-dir DIR] [--cache-max-age H]` → DownloadAllNVDData
//   - `cpe nvd cves-for-cpe <cpe> --data cache.json` → FindCVEsForCPE
//   - `cpe nvd cpes-for-cve <cve-id> --data cache.json` → FindCPEsForCVE
// 注意：真实网络调用需要 NVD API key（可选），离线测试用 --data 指定已缓存文件。

var (
	nvdCacheDir    string
	nvdCacheMaxAge int
	nvdDataFile    string
)

var nvdCmd = &cobra.Command{
	Use:   "nvd",
	Short: "NVD (National Vulnerability Database) operations",
	Long: `Query and download NVD CPE/CVE data.

Subcommands:
  nvd download              Download all NVD data (CPE dict + CPE match)
  nvd cves-for-cpe <cpe>    Find CVEs affecting a CPE (requires --data)
  nvd cpes-for-cve <cve>    Find CPEs affected by a CVE (requires --data)

The download command caches data locally. For subsequent queries,
use --data to specify the cached JSON file to avoid re-downloading.

Examples:
  cpe nvd download --cache-dir ~/.cache/nvd --cache-max-age 24
  cpe nvd cves-for-cpe "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*" --data ~/.cache/nvd/nvd_data.json
  cpe nvd cpes-for-cve CVE-2021-44228 --data ~/.cache/nvd/nvd_data.json`,
}

var nvdDownloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download all NVD data (CPE dictionary + match feed)",
	RunE:  runNVDDownload,
}

var nvdCVEsForCPECmd = &cobra.Command{
	Use:   "cves-for-cpe <cpe-string>",
	Short: "Find CVEs affecting a CPE",
	Args:  cobra.ExactArgs(1),
	RunE:  runNVDCVEsForCPE,
}

var nvdCPEsForCVECmd = &cobra.Command{
	Use:   "cpes-for-cve <cve-id>",
	Short: "Find CPEs affected by a CVE",
	Args:  cobra.ExactArgs(1),
	RunE:  runNVDCPEsForCVE,
}

func init() {
	nvdDownloadCmd.Flags().StringVar(&nvdCacheDir, "cache-dir", "", "Directory to cache NVD data (default: temp dir)")
	nvdDownloadCmd.Flags().IntVar(&nvdCacheMaxAge, "cache-max-age", 0, "Max cache age in hours (0 = no expiry)")

	nvdCVEsForCPECmd.Flags().StringVar(&nvdDataFile, "data", "", "Path to cached NVD data JSON (required)")
	nvdCVEsForCPECmd.MarkFlagRequired("data")

	nvdCPEsForCVECmd.Flags().StringVar(&nvdDataFile, "data", "", "Path to cached NVD data JSON (required)")
	nvdCPEsForCVECmd.MarkFlagRequired("data")

	nvdCmd.AddCommand(nvdDownloadCmd)
	nvdCmd.AddCommand(nvdCVEsForCPECmd)
	nvdCmd.AddCommand(nvdCPEsForCVECmd)
	rootCmd.AddCommand(nvdCmd)
}

func runNVDDownload(cmd *cobra.Command, args []string) error {
	opts := cpeskills.DefaultNVDFeedOptions()
	if nvdCacheDir != "" {
		opts.CacheDir = nvdCacheDir
	}
	if nvdCacheMaxAge > 0 {
		opts.CacheMaxAge = nvdCacheMaxAge
	}

	data, err := cpeskills.DownloadAllNVDData(opts)
	if err != nil {
		return fmt.Errorf("download NVD data: %w", err)
	}

	// 输出到 stdout 或文件
	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	}

	// text 格式：简单摘要
	fmt.Fprintf(cmd.OutOrStdout(), "Downloaded NVD data:\n")
	if data.CPEDictionary != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "  CPE Dictionary entries: %d\n", len(data.CPEDictionary.Items))
	}
	if data.CPEMatchData != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "  CPE Match entries: %d CVEs, %d CPEs\n", len(data.CPEMatchData.CVEToCPEs), len(data.CPEMatchData.CPEToCVEs))
	}
	if nvdCacheDir != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "  Cache directory: %s\n", nvdCacheDir)
	}
	return nil
}

func runNVDCVEsForCPE(cmd *cobra.Command, args []string) error {
	cpe, err := parseCPEString(args[0])
	if err != nil {
		return fmt.Errorf("parse CPE: %w", err)
	}

	// 从文件加载 NVDCPEData
	data, err := loadNVDData(nvdDataFile)
	if err != nil {
		return fmt.Errorf("load NVD data: %w", err)
	}

	cves := data.FindCVEsForCPE(cpe)

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"cpe":   cpe.GetURI(),
			"cves":  cves,
			"count": len(cves),
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(), "CVEs affecting %s (%d):\n", cpe.GetURI(), len(cves))
	for _, cve := range cves {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", cve)
	}
	return nil
}

func runNVDCPEsForCVE(cmd *cobra.Command, args []string) error {
	cveID := args[0]

	data, err := loadNVDData(nvdDataFile)
	if err != nil {
		return fmt.Errorf("load NVD data: %w", err)
	}

	cpes := data.FindCPEsForCVE(cveID)

	if outputFormat == "json" {
		uris := make([]string, len(cpes))
		for i, c := range cpes {
			uris[i] = c.GetURI()
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"cve":   cveID,
			"cpes":  uris,
			"count": len(cpes),
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(), "CPEs affected by %s (%d):\n", cveID, len(cpes))
	for _, c := range cpes {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", c.GetURI())
	}
	return nil
}

// loadNVDData 从 JSON 文件加载 NVDCPEData
func loadNVDData(path string) (*cpeskills.NVDCPEData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var data cpeskills.NVDCPEData
	dec := json.NewDecoder(f)
	if err := dec.Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}
package main

import (
	"encoding/json"
	"fmt"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// epss.go — `cpe epss <cve-id>` → NewEPSSClient + GetScore(cveID)
// EPSS (Exploit Prediction Scoring System) 是 FIRST 的漏洞利用预测评分。
// 返回 EPSSEntry 含 EPSS 评分、百分位、日期等。

var epssCmd = &cobra.Command{
	Use:   "epss <cve-id>",
	Short: "Query EPSS score for a CVE",
	Long: `Query the Exploit Prediction Scoring System (EPSS) score for a CVE.
EPSS scores predict the probability of exploitability in the next 30 days.

Output includes EPSS score (0-1), percentile, and date.

Examples:
  cpe epss CVE-2021-44228
  cpe epss -o json CVE-2021-44228`,
	Args: cobra.ExactArgs(1),
	RunE: runEPSS,
}

func init() {
	rootCmd.AddCommand(epssCmd)
}

func runEPSS(cmd *cobra.Command, args []string) error {
	cveID := args[0]

	client := cpeskills.NewEPSSClient()
	entry, err := client.GetScore(cveID)
	if err != nil {
		return fmt.Errorf("query EPSS: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(entry)
	}

	// text 格式
	fmt.Fprintf(cmd.OutOrStdout(), "EPSS Score for %s:\n", cveID)
	fmt.Fprintf(cmd.OutOrStdout(), "  Score:     %.4f\n", entry.EPSSScore)
	fmt.Fprintf(cmd.OutOrStdout(), "  Percentile: %.2f\n", entry.Percentile)
	fmt.Fprintf(cmd.OutOrStdout(), "  Date:      %s\n", entry.Date)
	return nil
}
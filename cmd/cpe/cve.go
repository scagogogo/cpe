package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	cpeskills "github.com/scagogogo/cpe-skills/pkg/cpe"
	"github.com/spf13/cobra"
)

// cve.go — `cpe cve` parent + subcommands:
//   - `cpe cve validate <cve-id>` → ValidateCVE (返回 bool)
//   - `cpe cve extract` (stdin) → ExtractCVEsFromText
//   - `cpe cve sort` (stdin CVE 列表) → SortCVEs
// 注意：ValidateCVE 返回 bool，不是 error，所以命令输出 true/false。

var cveCmd = &cobra.Command{
	Use:   "cve",
	Short: "CVE identifier utilities",
	Long: `Validate, extract, and sort CVE identifiers.

Subcommands:
  cve validate <cve-id>  Check if a CVE ID is valid (format: CVE-YYYY-NNNN)
  cve extract            Extract CVE IDs from stdin text
  cve sort               Sort CVE IDs chronologically (stdin)

Examples:
  cpe cve validate CVE-2021-44228
  cat report.txt | cpe cve extract
  cat cves.txt | cpe cve sort`,
}

var cveValidateCmd = &cobra.Command{
	Use:   "validate <cve-id>",
	Short: "Validate CVE ID format",
	Args:  cobra.ExactArgs(1),
	RunE:  runCVEValidate,
}

var cveExtractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract CVE IDs from stdin text",
	RunE:  runCVEExtract,
}

var cveSortCmd = &cobra.Command{
	Use:   "sort",
	Short: "Sort CVE IDs chronologically (stdin)",
	RunE:  runCVESort,
}

func init() {
	cveCmd.AddCommand(cveValidateCmd)
	cveCmd.AddCommand(cveExtractCmd)
	cveCmd.AddCommand(cveSortCmd)
	rootCmd.AddCommand(cveCmd)
}

func runCVEValidate(cmd *cobra.Command, args []string) error {
	cveID := args[0]
	valid := cpeskills.ValidateCVE(cveID)

	if outputFormat == "json" {
		fmt.Fprintf(cmd.OutOrStdout(), `{"cve": "%s", "valid": %t}`, cveID, valid)
		fmt.Fprintln(cmd.OutOrStdout())
		return nil
	}

	if valid {
		fmt.Fprintf(cmd.OutOrStdout(), "VALID: %s\n", cveID)
		return nil
	}
	return fmt.Errorf("INVALID: %s", cveID)
}

func runCVEExtract(cmd *cobra.Command, args []string) error {
	text, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	cves := cpeskills.ExtractCVEsFromText(string(text))

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"cves":  cves,
			"count": len(cves),
		})
	}

	for _, cve := range cves {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", cve)
	}
	return nil
}

func runCVESort(cmd *cobra.Command, args []string) error {
	text, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	// stdin 每行一个 CVE
	lines := splitLines(string(text))
	sorted := cpeskills.SortCVEs(lines)

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(sorted)
	}

	for _, cve := range sorted {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", cve)
	}
	return nil
}

// splitLines 按换行分割并过滤空行
func splitLines(s string) []string {
	var result []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

package main

import (
	"encoding/json"
	"fmt"
	"os"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// applicability.go — `cpe applicability parse "<expr>"` → ParseExpression
//                    `cpe applicability filter "<expr>" --file cpes.txt` → FilterCPEs
// Applicability 表达式用于按条件过滤 CPE 列表。

var applicabilityCmd = &cobra.Command{
	Use:   "applicability",
	Short: "Applicability expression utilities",
	Long: `Parse and apply applicability expressions to filter CPEs.

Subcommands:
  applicability parse "<expr>"   Parse an expression (validates syntax)
  applicability filter "<expr>" --file cpes.txt  Filter CPEs from file

Examples:
  cpe applicability parse "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
  cpe applicability parse "AND(cpe:..., cpe:...)"
  cpe applicability filter "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*" --file cpes.txt`,
}

var applicabilityParseCmd = &cobra.Command{
	Use:   "parse <expression>",
	Short: "Parse an applicability expression",
	Args:  cobra.ExactArgs(1),
	RunE:  runApplicabilityParse,
}

var applicabilityFile string

var applicabilityFilterCmd = &cobra.Command{
	Use:   "filter <expression>",
	Short: "Filter CPEs from a file using an expression",
	Args:  cobra.ExactArgs(1),
	RunE:  runApplicabilityFilter,
}

func init() {
	applicabilityFilterCmd.Flags().StringVar(&applicabilityFile, "file", "", "File containing CPE strings (one per line)")
	applicabilityFilterCmd.MarkFlagRequired("file")

	applicabilityCmd.AddCommand(applicabilityParseCmd)
	applicabilityCmd.AddCommand(applicabilityFilterCmd)
	rootCmd.AddCommand(applicabilityCmd)
}

func runApplicabilityParse(cmd *cobra.Command, args []string) error {
	expr, err := cpeskills.ParseExpression(args[0])
	if err != nil {
		return fmt.Errorf("parse expression: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"valid":      true,
			"expression": args[0],
			"parsed":     fmt.Sprintf("%v", expr),
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Valid expression: %s\n", args[0])
	return nil
}

func runApplicabilityFilter(cmd *cobra.Command, args []string) error {
	expr, err := cpeskills.ParseExpression(args[0])
	if err != nil {
		return fmt.Errorf("parse expression: %w", err)
	}

	content, err := os.ReadFile(applicabilityFile)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	// 解析每行为 CPE
	lines := splitLines(string(content))
	var cpes []*cpeskills.CPE
	for _, line := range lines {
		c, parseErr := parseCPEString(line)
		if parseErr != nil {
			continue
		}
		cpes = append(cpes, c)
	}

	filtered := cpeskills.FilterCPEs(cpes, expr)

	if outputFormat == "json" {
		uris := make([]string, len(filtered))
		for i, c := range filtered {
			uris[i] = c.GetURI()
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"input":    len(cpes),
			"filtered": len(filtered),
			"cpes":     uris,
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Filtered %d/%d CPEs:\n", len(filtered), len(cpes))
	for _, c := range filtered {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", c.GetURI())
	}
	return nil
}
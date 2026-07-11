package main

import (
	"fmt"

	cpeskills "github.com/scagogogo/cpe-skills/pkg/cpe"
	"github.com/spf13/cobra"
)

// normalize.go — `cpe normalize <cpe>` → cpeskills.NormalizeCPE (validation.go:326)
// 可选 --vendor 同时调 cpeskills.NormalizeCPEVendorProduct (vendor_normalization.go:344)
// 把 CPE 各字段的空白、大小写、特殊字符规范化到标准形态。

var (
	normalizeVendor bool
)

var normalizeCmd = &cobra.Command{
	Use:   "normalize <cpe-string>",
	Short: "Normalize a CPE string to its canonical form",
	Long: `Normalize the fields of a CPE 2.2 or 2.3 string: trim whitespace,
collapse case, and escape special characters to their canonical form.

With --vendor, also run vendor/product-name normalization (collapses
spelling aliases like "Microsoft Corp." → "microsoft").

Examples:
  cpe normalize "cpe:2.3:a:Microsoft:Windows:10:*:*:*:*:*:*:*"
  cpe normalize --vendor "cpe:2.3:a:Microsoft Corp.:Windows:10:*:*:*:*:*:*:*"
  cpe normalize -o json "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"`,
	Args: cobra.ExactArgs(1),
	RunE: runNormalize,
}

func init() {
	normalizeCmd.Flags().BoolVar(&normalizeVendor, "vendor", false, "Also normalize vendor/product name aliases")
	rootCmd.AddCommand(normalizeCmd)
}

func runNormalize(cmd *cobra.Command, args []string) error {
	c, err := parseCPEString(args[0])
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	normalized := cpeskills.NormalizeCPE(c)
	if normalizeVendor {
		normalized = cpeskills.NormalizeCPEVendorProduct(normalized)
	}

	return outputCPE(cmd.OutOrStdout(), normalized, outputFormat)
}

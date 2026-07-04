package main

import (
	"fmt"
	"os"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// vcmp.go — `cpe vcmp <a> <b>` → cpeskills.CompareVersions (version_compare.go:12)
//            `cpe vcmp in-range <v> --min --max` → cpeskills.IsVersionInRange (version_compare.go:20)
// 注意：命令名用 vcmp 而非 version，避免与现有 `cpe version`（CLI 版本号）冲突。
// 与 mcp serve 的 compare_versions 工具同源。

var (
	inRangeMin string
	inRangeMax string
)

var vcmpCmd = &cobra.Command{
	Use:   "vcmp",
	Short: "Compare two version strings",
	Long: `Compare version strings using CPE-style version semantics.
Returns -1, 0, or 1 (a < b, a == b, a > b).

Subcommands:
  vcmp <a> <b>            Compare two versions
  vcmp in-range <v>       Check if a version is in a range (--min, --max)

Examples:
  cpe vcmp 1.0 1.1
  cpe vcmp 2.14.0 2.14.1
  cpe vcmp in-range 3.5 --min 3.0 --max 4.0`,
}

var vcmpCompareCmd = &cobra.Command{
	Use:   "vcmp <a> <b>",
	Short: "Compare two versions, output -1/0/1",
	Args:  cobra.ExactArgs(2),
	RunE:  runVcmpCompare,
}

var vcmpInRangeCmd = &cobra.Command{
	Use:   "in-range <version>",
	Short: "Check if a version falls within [min, max]",
	Args:  cobra.ExactArgs(1),
	RunE:  runVcmpInRange,
}

func init() {
	vcmpInRangeCmd.Flags().StringVar(&inRangeMin, "min", "", "Minimum version (inclusive)")
	vcmpInRangeCmd.Flags().StringVar(&inRangeMax, "max", "", "Maximum version (inclusive)")

	vcmpCmd.AddCommand(vcmpCompareCmd)
	vcmpCmd.AddCommand(vcmpInRangeCmd)
	// 让 `cpe vcmp a b` 直接工作（不带子命令时退化为比较）
	vcmpCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 2 {
			return runVcmpCompare(cmd, args)
		}
		return cmd.Help()
	}
	rootCmd.AddCommand(vcmpCmd)
}

func runVcmpCompare(cmd *cobra.Command, args []string) error {
	result := cpeskills.CompareVersions(args[0], args[1])

	if outputFormat == "json" {
		fmt.Fprintf(cmd.OutOrStdout(), `{"a": "%s", "b": "%s", "result": %d}`, args[0], args[1], result)
		fmt.Fprintln(cmd.OutOrStdout())
		return nil
	}

	var op string
	switch {
	case result < 0:
		op = "<"
	case result > 0:
		op = ">"
	default:
		op = "=="
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s %s %s (cmp=%d)\n", args[0], op, args[1], result)
	return nil
}

func runVcmpInRange(cmd *cobra.Command, args []string) error {
	v := args[0]
	if inRangeMin == "" && inRangeMax == "" {
		return fmt.Errorf("at least one of --min or --max must be set")
	}
	result := cpeskills.IsVersionInRange(v, inRangeMin, inRangeMax)

	if outputFormat == "json" {
		fmt.Fprintf(cmd.OutOrStdout(), `{"version": "%s", "min": "%s", "max": "%s", "in_range": %t}`, v, inRangeMin, inRangeMax, result)
		fmt.Fprintln(cmd.OutOrStdout())
		return nil
	}

	if result {
		fmt.Fprintf(cmd.OutOrStdout(), "IN RANGE: %s ∈ [%s, %s]\n", v, inRangeMin, inRangeMax)
		return nil
	}
	fmt.Fprintf(os.Stderr, "NOT IN RANGE: %s ∉ [%s, %s]\n", v, inRangeMin, inRangeMax)
	// 不在范围内用非零退出码，便于 CI 判定
	return fmt.Errorf("not in range")
}

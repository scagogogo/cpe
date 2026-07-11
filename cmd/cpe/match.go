package main

import (
	"fmt"

	cpeskills "github.com/scagogogo/cpe-skills/pkg/cpe"
	"github.com/spf13/cobra"
)

var (
	matchIgnoreVersion bool
	matchUseRegex      bool
	matchMinVersion    string
	matchMaxVersion    string
)

var matchCmd = &cobra.Command{
	Use:   "match <criteria-cpe> <target-cpe>",
	Short: "Check if two CPEs match",
	Long: `Compare two CPE strings and check if they match.
The first argument is the criteria, the second is the target.

Supports options for ignoring version, using regex patterns,
and specifying version ranges.

Examples:
  cpe match "cpe:2.3:a:microsoft:windows:*" "cpe:2.3:a:microsoft:windows:10"
  cpe match --ignore-version "cpe:2.3:a:microsoft:windows:10" "cpe:2.3:a:microsoft:windows:11"
  cpe match --min-version 3.0 --max-version 4.0 "cpe:2.3:a:apache:log4j" "cpe:2.3:a:apache:log4j:3.5"`,
	Args: cobra.ExactArgs(2),
	RunE: runMatch,
}

func init() {
	matchCmd.Flags().BoolVar(&matchIgnoreVersion, "ignore-version", false, "Ignore version when matching")
	matchCmd.Flags().BoolVar(&matchUseRegex, "regex", false, "Use regex matching for string fields")
	matchCmd.Flags().StringVar(&matchMinVersion, "min-version", "", "Minimum version for range matching")
	matchCmd.Flags().StringVar(&matchMaxVersion, "max-version", "", "Maximum version for range matching")
	rootCmd.AddCommand(matchCmd)
}

func runMatch(cmd *cobra.Command, args []string) error {
	criteria, err := parseCPEString(args[0])
	if err != nil {
		return fmt.Errorf("parsing criteria CPE: %w", err)
	}

	target, err := parseCPEString(args[1])
	if err != nil {
		return fmt.Errorf("parsing target CPE: %w", err)
	}

	options := &cpeskills.MatchOptions{
		IgnoreVersion:    matchIgnoreVersion,
		UseRegex:         matchUseRegex,
		AllowSubVersions: true,
		VersionRange:     matchMinVersion != "" || matchMaxVersion != "",
		MinVersion:       matchMinVersion,
		MaxVersion:       matchMaxVersion,
	}

	result := cpeskills.MatchCPE(criteria, target, options)

	if outputFormat == "json" {
		fmt.Fprintf(cmd.OutOrStdout(), `{"match": %t, "criteria": "%s", "target": "%s"}`, result, criteria.GetURI(), target.GetURI())
		fmt.Fprintln(cmd.OutOrStdout())
	} else {
		if result {
			fmt.Fprintf(cmd.OutOrStdout(), "MATCH: %s matches %s\n", criteria.GetURI(), target.GetURI())
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "NO MATCH: %s does not match %s\n", criteria.GetURI(), target.GetURI())
		}
	}

	return nil
}

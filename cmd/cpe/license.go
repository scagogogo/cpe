package main

import (
	"encoding/json"
	"fmt"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// license.go — `cpe license list-common` → CommonLicenses
//              `cpe license detect-by-name <name>` → DetectLicenseByName
// 许可证信息查询。

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "License information utilities",
	Long: `Query common software licenses and detect license by name.

Subcommands:
  license list-common      List common SPDX licenses
  license detect-by-name   Detect license ID from a name string

Examples:
  cpe license list-common
  cpe license list-common -o json
  cpe license detect-by-name "MIT License"
  cpe license detect-by-name "Apache 2.0"`,
}

var licenseListCommonCmd = &cobra.Command{
	Use:   "list-common",
	Short: "List common SPDX licenses",
	RunE:  runLicenseListCommon,
}

var licenseDetectCmd = &cobra.Command{
	Use:   "detect-by-name <name>",
	Short: "Detect license ID from a name string",
	Args:  cobra.ExactArgs(1),
	RunE:  runLicenseDetect,
}

func init() {
	licenseCmd.AddCommand(licenseListCommonCmd)
	licenseCmd.AddCommand(licenseDetectCmd)
	rootCmd.AddCommand(licenseCmd)
}

func runLicenseListCommon(cmd *cobra.Command, args []string) error {
	licenses := cpeskills.CommonLicenses()

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(licenses)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Common Licenses (%d):\n", len(licenses))
	for _, lic := range licenses {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s\n", lic.SPDXID, lic.Name)
	}
	return nil
}

func runLicenseDetect(cmd *cobra.Command, args []string) error {
	lic := cpeskills.DetectLicenseByName(args[0])
	if lic == nil {
		return fmt.Errorf("license not found: %s", args[0])
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(lic)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Detected License:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  SPDX ID: %s\n", lic.SPDXID)
	fmt.Fprintf(cmd.OutOrStdout(), "  Name:    %s\n", lic.Name)
	return nil
}
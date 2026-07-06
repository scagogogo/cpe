package main

import (
	"encoding/json"
	"fmt"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// purl.go — `cpe purl parse <purl>` → ParsePURL
//            `cpe purl build --type npm --name foo --version 1.0` → NewPURL
// PURL (Package URL) 是 purl-spec 定义的标准包标识符格式。

var (
	purlType      string
	purlNamespace string
	purlName      string
	purlVersion   string
)

var purlCmd = &cobra.Command{
	Use:   "purl",
	Short: "Package URL (purl) utilities",
	Long: `Parse and build Package URL strings (pkg:type/name@version).

Subcommands:
  purl parse <purl>  Parse a purl string into components
  purl build         Build a purl from --type, --name, --version flags

Examples:
  cpe purl parse pkg:npm/left-pad@1.3.0
  cpe purl parse -o json pkg:golang/github.com/golang/go@1.19
  cpe purl build --type npm --name left-pad --version 1.3.0
  cpe purl build --type golang --namespace github.com/golang --name go --version 1.19`,
}

var purlParseCmd = &cobra.Command{
	Use:   "parse <purl-string>",
	Short: "Parse a Package URL string",
	Args:  cobra.ExactArgs(1),
	RunE:  runPURLParse,
}

var purlBuildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build a Package URL from components",
	RunE:  runPURLBuild,
}

func init() {
	purlBuildCmd.Flags().StringVarP(&purlType, "type", "t", "", "Package type (npm, golang, maven, pip, etc.)")
	purlBuildCmd.Flags().StringVarP(&purlNamespace, "namespace", "n", "", "Package namespace (optional)")
	purlBuildCmd.Flags().StringVarP(&purlName, "name", "m", "", "Package name")
	purlBuildCmd.Flags().StringVarP(&purlVersion, "version", "v", "", "Package version")
	purlBuildCmd.MarkFlagRequired("type")
	purlBuildCmd.MarkFlagRequired("name")

	purlCmd.AddCommand(purlParseCmd)
	purlCmd.AddCommand(purlBuildCmd)
	rootCmd.AddCommand(purlCmd)
}

func runPURLParse(cmd *cobra.Command, args []string) error {
	purl, err := cpeskills.ParsePURL(args[0])
	if err != nil {
		return fmt.Errorf("parse purl: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(purl)
	}

	// text 格式
	fmt.Fprintf(cmd.OutOrStdout(), "Package URL: %s\n", args[0])
	fmt.Fprintf(cmd.OutOrStdout(), "  Type:      %s\n", purl.Type)
	fmt.Fprintf(cmd.OutOrStdout(), "  Namespace: %s\n", purl.Namespace)
	fmt.Fprintf(cmd.OutOrStdout(), "  Name:      %s\n", purl.Name)
	fmt.Fprintf(cmd.OutOrStdout(), "  Version:   %s\n", purl.Version)
	return nil
}

func runPURLBuild(cmd *cobra.Command, args []string) error {
	purl := cpeskills.NewPURL(purlType, purlNamespace, purlName, purlVersion)

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(purl)
	}

	fmt.Fprintln(cmd.OutOrStdout(), purl.String())
	return nil
}

package main

import (
	"encoding/json"
	"fmt"
	"os"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

var dictCmd = &cobra.Command{
	Use:   "dict",
	Short: "CPE dictionary operations",
	Long: `Operations on CPE dictionaries: parse XML dictionary files,
export dictionaries, and search within dictionaries.

A CPE dictionary is a collection of CPE items with metadata
like titles, references, and deprecation status.`,
}

var dictParseCmd = &cobra.Command{
	Use:   "parse <xml-file>",
	Short: "Parse a CPE dictionary XML file",
	Args:  cobra.ExactArgs(1),
	RunE:  runDictParse,
}

var dictSearchCmd = &cobra.Command{
	Use:   "search <xml-file> <criteria-cpe>",
	Short: "Search within a CPE dictionary",
	Args:  cobra.ExactArgs(2),
	RunE:  runDictSearch,
}

func init() {
	dictCmd.AddCommand(dictParseCmd)
	dictCmd.AddCommand(dictSearchCmd)
	rootCmd.AddCommand(dictCmd)
}

func runDictParse(cmd *cobra.Command, args []string) error {
	f, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("opening dictionary file: %w", err)
	}
	defer func() { _ = f.Close() }()

	dict, err := cpeskills.ParseDictionary(f)
	if err != nil {
		return fmt.Errorf("parsing dictionary: %w", err)
	}

	if outputFormat == "json" {
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(dict)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "CPE Dictionary\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Schema Version: %s\n", dict.SchemaVersion)
	fmt.Fprintf(cmd.OutOrStdout(), "  Generated At:   %s\n", dict.GeneratedAt)
	fmt.Fprintf(cmd.OutOrStdout(), "  Items:          %d\n\n", len(dict.Items))

	for i, item := range dict.Items {
		fmt.Fprintf(cmd.OutOrStdout(), "%d. %s\n", i+1, item.Name)
		if item.Title != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "   Title: %s\n", item.Title)
		}
		if item.Deprecated {
			fmt.Fprintf(cmd.OutOrStdout(), "   Deprecated: %s\n", item.DeprecationDate)
		}
	}
	return nil
}

func runDictSearch(cmd *cobra.Command, args []string) error {
	f, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("opening dictionary file: %w", err)
	}
	defer func() { _ = f.Close() }()

	dict, err := cpeskills.ParseDictionary(f)
	if err != nil {
		return fmt.Errorf("parsing dictionary: %w", err)
	}

	criteria, err := parseCPEString(args[1])
	if err != nil {
		return fmt.Errorf("parsing criteria CPE: %w", err)
	}

	items := dict.FindItemsByCriteria(criteria, cpeskills.DefaultMatchOptions())

	fmt.Fprintf(cmd.OutOrStdout(), "Found %d matching item(s):\n", len(items))
	for i, item := range items {
		fmt.Fprintf(cmd.OutOrStdout(), "%d. %s", i+1, item.Name)
		if item.Title != "" {
			fmt.Fprintf(cmd.OutOrStdout(), " - %s", item.Title)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}
	return nil
}

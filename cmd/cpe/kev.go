package main

import (
	"encoding/json"
	"fmt"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// kev.go — `cpe kev` parent + subcommands:
//   - `cpe kev is-listed <cve-id>` → KEVClient.IsListed (返回 bool)
//   - `cpe kev get <cve-id>` → KEVClient.GetEntry (返回 *KEVEntry)
//   - `cpe kev list` → KEVClient.GetAll (返回 []*KEVEntry)
// KEV (Known Exploited Vulnerabilities) 是 CISA 的已知被利用漏洞清单。

var kevCmd = &cobra.Command{
	Use:   "kev",
	Short: "CISA Known Exploited Vulnerabilities (KEV) catalog",
	Long: `Query the CISA Known Exploited Vulnerabilities catalog.

Subcommands:
  kev is-listed <cve-id>  Check if CVE is in KEV catalog
  kev get <cve-id>        Get full KEV entry for a CVE
  kev list                List all KEV entries

Examples:
  cpe kev is-listed CVE-2021-44228
  cpe kev get CVE-2021-44228
  cpe kev list | head -20`,
}

var kevIsListedCmd = &cobra.Command{
	Use:   "is-listed <cve-id>",
	Short: "Check if a CVE is in the KEV catalog",
	Args:  cobra.ExactArgs(1),
	RunE:  runKEVIsListed,
}

var kevGetCmd = &cobra.Command{
	Use:   "get <cve-id>",
	Short: "Get KEV entry for a CVE",
	Args:  cobra.ExactArgs(1),
	RunE:  runKEVGet,
}

var kevListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all KEV entries",
	RunE:  runKEVList,
}

func init() {
	kevCmd.AddCommand(kevIsListedCmd)
	kevCmd.AddCommand(kevGetCmd)
	kevCmd.AddCommand(kevListCmd)
	rootCmd.AddCommand(kevCmd)
}

func runKEVIsListed(cmd *cobra.Command, args []string) error {
	cveID := args[0]

	client := cpeskills.NewKEVClient()
	listed, err := client.IsListed(cveID)
	if err != nil {
		return fmt.Errorf("query KEV: %w", err)
	}

	if outputFormat == "json" {
		fmt.Fprintf(cmd.OutOrStdout(), `{"cve": "%s", "listed": %t}`, cveID, listed)
		fmt.Fprintln(cmd.OutOrStdout())
		return nil
	}

	if listed {
		fmt.Fprintf(cmd.OutOrStdout(), "LISTED: %s is in CISA KEV catalog\n", cveID)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "NOT LISTED: %s is not in CISA KEV catalog\n", cveID)
	return nil
}

func runKEVGet(cmd *cobra.Command, args []string) error {
	cveID := args[0]

	client := cpeskills.NewKEVClient()
	entry, err := client.GetEntry(cveID)
	if err != nil {
		return fmt.Errorf("get KEV entry: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(entry)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "KEV Entry for %s:\n", cveID)
	fmt.Fprintf(cmd.OutOrStdout(), "  Vulnerability: %s\n", entry.VulnerabilityName)
	fmt.Fprintf(cmd.OutOrStdout(), "  Due Date:      %s\n", entry.DueDate)
	fmt.Fprintf(cmd.OutOrStdout(), "  Required Action: %s\n", entry.RequiredAction)
	fmt.Fprintf(cmd.OutOrStdout(), "  Known Ransomware: %s\n", entry.KnownRansomwareCampaignUse)
	return nil
}

func runKEVList(cmd *cobra.Command, args []string) error {
	client := cpeskills.NewKEVClient()
	entries, err := client.GetAll()
	if err != nil {
		return fmt.Errorf("list KEV: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}

	for _, entry := range entries {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", entry.CVEID, entry.VulnerabilityName, entry.DueDate)
	}
	return nil
}
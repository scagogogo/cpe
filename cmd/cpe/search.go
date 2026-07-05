package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

var (
	searchInputFile string
	searchAdvanced  bool
	searchFuzzy     bool
)

var searchCmd = &cobra.Command{
	Use:   "search <criteria-cpe>",
	Short: "Search CPEs from input that match criteria",
	Long: `Search for CPEs that match the given criteria.
Reads CPE strings from stdin (one per line) or from a file (--file).

Examples:
  cat cpes.txt | cpe search "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*"
  cpe search --file cpes.txt "cpe:2.3:a:apache:*:*:*:*:*:*:*:*"
  cpe search --advanced "cpe:2.3:a:*:log4j:*:*:*:*:*:*:*" < cpes.txt`,
	Args: cobra.ExactArgs(1),
	RunE: runSearch,
}

func init() {
	searchCmd.Flags().StringVarP(&searchInputFile, "file", "f", "", "Input file with CPE strings (one per line)")
	searchCmd.Flags().BoolVar(&searchAdvanced, "advanced", false, "Use advanced matching")
	searchCmd.Flags().BoolVar(&searchFuzzy, "fuzzy", false, "Enable fuzzy matching (requires --advanced)")
	rootCmd.AddCommand(searchCmd)
}

func runSearch(cmd *cobra.Command, args []string) error {
	criteria, err := parseCPEString(args[0])
	if err != nil {
		return fmt.Errorf("parsing criteria CPE: %w", err)
	}

	// 读取输入 CPE 列表
	var scanner *bufio.Scanner
	if searchInputFile != "" {
		f, err := os.Open(searchInputFile)
		if err != nil {
			return fmt.Errorf("opening input file: %w", err)
		}
		defer func() { _ = f.Close() }()
		scanner = bufio.NewScanner(f)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}

	var matches []*cpeskills.CPE
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		target, err := parseCPEString(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Skipping invalid CPE: %s (%v)\n", line, err)
			continue
		}

		matched := false
		if searchAdvanced {
			opts := cpeskills.NewAdvancedMatchOptions()
			opts.UseFuzzyMatch = searchFuzzy
			matched = cpeskills.AdvancedMatchCPE(criteria, target, opts)
		} else {
			matched = cpeskills.MatchCPE(criteria, target, nil)
		}

		if matched {
			matches = append(matches, target)
		}
	}

	// 输出结果
	if outputFormat == "json" {
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "[")
		for i, m := range matches {
			if i > 0 {
				fmt.Fprintf(w, ", ")
			}
			fmt.Fprintf(w, `"%s"`, m.GetURI())
		}
		fmt.Fprintf(w, "]\n")
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Found %d matching CPE(s):\n", len(matches))
		for i, m := range matches {
			fmt.Fprintf(cmd.OutOrStdout(), "%d. %s\n", i+1, m.GetURI())
		}
	}

	return scanner.Err()
}

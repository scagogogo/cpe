package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	outputFormat string
	noColor      bool
)

var rootCmd = &cobra.Command{
	Use:   "cpe",
	Short: "CPE (Common Platform Enumeration) CLI tool",
	Long: `A CLI tool for parsing, matching, searching and managing
CPE (Common Platform Enumeration) identifiers.

CPE is a standardized naming scheme for identifying IT systems,
software, and packages. This tool provides command-line access
to the cpe library's core functionality.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "text", "Output format (text|json)")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
}

func execute() {
	os.Exit(executeRun())
}

// executeRun 执行根命令并返回退出码，供测试调用以避免 os.Exit。
func executeRun() int {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

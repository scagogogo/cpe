package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	cpeskills "github.com/scagogogo/cpe-skills/pkg/cpe"
	"github.com/spf13/cobra"
)

// osv.go — `cpe osv query --purl <purl>` → OSVClient.Query
//            `cpe osv query --ecosystem npm --name foo --version 1.0` → QueryByEcosystem
// OSV (Open Source Vulnerabilities) 是 Google 的开源漏洞数据库。

// osvBaseURL 覆盖 OSV API 基础 URL，空则用默认。测试注入 httptest URL。
var osvBaseURL string

var (
	osvPurl      string
	osvEcosystem string
	osvName      string
	osvVersion   string
)

var osvCmd = &cobra.Command{
	Use:   "osv query",
	Short: "Query OSV (Open Source Vulnerabilities) database",
	Long: `Query the OSV database for vulnerabilities in open-source packages.

Two query modes:
  --purl               Query by Package URL (e.g., pkg:npm/foo@1.0)
  --ecosystem --name --version  Query by ecosystem, name, version

Examples:
  cpe osv query --purl pkg:npm/left-pad@1.3.0
  cpe osv query --ecosystem npm --name left-pad --version 1.3.0
  cpe osv query -o json --purl pkg:golang/github.com/golang/go@1.19`,
	RunE: runOSV,
}

func init() {
	osvCmd.Flags().StringVar(&osvPurl, "purl", "", "Package URL to query")
	osvCmd.Flags().StringVar(&osvEcosystem, "ecosystem", "", "Ecosystem (npm, golang, pip, maven, etc.)")
	osvCmd.Flags().StringVar(&osvName, "name", "", "Package name")
	osvCmd.Flags().StringVar(&osvVersion, "version", "", "Package version")
	osvCmd.Flags().StringVar(&osvBaseURL, "base-url", "", "OSV API base URL (default: osv.dev endpoint)")

	rootCmd.AddCommand(osvCmd)
}

func runOSV(cmd *cobra.Command, args []string) error {
	client := cpeskills.NewOSVClient()
	if osvBaseURL != "" {
		client.BaseURL = osvBaseURL
		client.HTTPClient = &http.Client{Timeout: 10 * time.Second}
		client.RetryCount = 0 // 测试/自定义端点不重试，避免慢
	}

	var entries []*cpeskills.OSVEntry
	var err error

	if osvPurl != "" {
		// 用 PURL 查询
		purl, parseErr := cpeskills.ParsePURL(osvPurl)
		if parseErr != nil {
			return fmt.Errorf("parse PURL: %w", parseErr)
		}
		entries, err = client.Query(purl)
	} else if osvEcosystem != "" && osvName != "" {
		// 用 ecosystem + name + version 查询
		entries, err = client.QueryByEcosystem(osvEcosystem, osvName, osvVersion)
	} else {
		return fmt.Errorf("must provide --purl or (--ecosystem + --name + optional --version)")
	}

	if err != nil {
		return fmt.Errorf("query OSV: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}

	// text 格式
	fmt.Fprintf(cmd.OutOrStdout(), "OSV vulnerabilities (%d):\n", len(entries))
	for _, entry := range entries {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s\n", entry.ID, entry.Summary)
	}
	return nil
}

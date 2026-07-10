package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	// 这些变量在 release 构建时由 goreleaser 通过 -ldflags -X 注入
	// （见 .goreleaser.yml builds.ldflags）。开发构建（go build/test）时
	// 保持占位值，不误导用户以为运行的是某个已发布版本。
	cliVersion   = "dev"
	cliGitCommit = "unknown"
	cliBuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print the version, git commit, build date, and Go runtime information.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("cpe CLI:     %s\n", cliVersion)
		fmt.Printf("Git Commit:  %s\n", cliGitCommit)
		fmt.Printf("Build Date:  %s\n", cliBuildDate)
		fmt.Printf("Go Version:  %s\n", runtime.Version())
		fmt.Printf("OS/Arch:     %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

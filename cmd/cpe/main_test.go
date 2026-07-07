package main

import (
	"io"
	"strings"
	"testing"
)

// main_test.go — 覆盖入口函数 executeRun（避免 os.Exit）与 newMCPServer
// 构造。main() 本身无法测试（调 os.Exit），但 executeRun 的两条返回路径
// 可直接断言。

func TestExecuteRun_Success(t *testing.T) {
	// version 子命令正常返回，无 error → 退出码 0
	orig := outputFormat
	defer func() { outputFormat = orig }()
	outputFormat = "text"

	// 明确设 args，避免复用上一次 runCLI 留下的 SetArgs
	rootCmd.SetArgs([]string{"version"})
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	defer rootCmd.SetArgs([]string{})
	rc := executeRun()
	if rc != 0 {
		t.Errorf("expected exit code 0 for version, got %d", rc)
	}
}

func TestExecuteRun_Error(t *testing.T) {
	// 未知子命令 → rootCmd.Execute 返回 error → 退出码 1
	orig := outputFormat
	defer func() { outputFormat = orig }()
	outputFormat = "text"

	// 用 rootCmd.SetArgs 直接驱动，避免 runCLI 的复位逻辑干扰
	rootCmd.SetArgs([]string{"no-such-subcommand"})
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	defer rootCmd.SetArgs([]string{}) // 复位
	rc := executeRun()
	if rc != 1 {
		t.Errorf("expected exit code 1 for unknown command, got %d", rc)
	}
}

func TestNewMCPServer_NonNil(t *testing.T) {
	srv := newMCPServer()
	if srv == nil {
		t.Fatal("expected non-nil MCP server")
	}
}

func TestMCPServe_Help(t *testing.T) {
	// `mcp serve --help` 走 cobra 帮助路径，不真正启动 stdio server
	out, err := runCLI(t, "mcp", "serve", "--help")
	if err != nil {
		t.Fatalf("mcp serve --help: %v", err)
	}
	if !strings.Contains(out, "stdio") && !strings.Contains(out, "MCP") {
		t.Errorf("expected MCP/stdio in help, got: %s", out)
	}
}

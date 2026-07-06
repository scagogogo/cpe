package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// 本文件通过 InMemoryTransport 起 server+client，端到端调用 6 个 MCP 工具，
// 覆盖各 handler 的 success 与 error 路径（registerMCPTools 内的闭包）。

// startMCPServer 起一个注册了全部 CPE 工具的 server，返回连接它的 client session。
// 调用者负责 cs.Close()；server 在 ctx 取消时退出。
func startMCPServer(t *testing.T) (*mcp.ClientSession, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	srvTransport, clientTransport := mcp.NewInMemoryTransports()

	srv := mcp.NewServer(&mcp.Implementation{Name: "cpe-skills", Version: "test"}, nil)
	registerMCPTools(srv)
	go func() { _ = srv.Run(ctx, srvTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		cancel()
		t.Fatalf("client connect: %v", err)
	}
	return cs, cancel
}

// callTool 调用指定工具，返回结果文本。失败 fatal。
func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	return textOf(t, res)
}

func TestMCP_ParseCPE_Success(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "parse_cpe", map[string]any{
		"cpe": "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*",
	})
	if !strings.Contains(out, "apache") || !strings.Contains(out, `"format": "2.3"`) {
		t.Errorf("parse_cpe success output unexpected: %s", out)
	}
}

func TestMCP_ParseCPE_MissingArg(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "parse_cpe", map[string]any{})
	if !strings.Contains(out, "missing 'cpe'") {
		t.Errorf("expected missing arg error, got: %s", out)
	}
}

func TestMCP_ParseCPE_Invalid(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "parse_cpe", map[string]any{"cpe": "not-a-cpe"})
	if !strings.Contains(out, "unrecognized") && !strings.Contains(out, "invalid") && !strings.Contains(out, "error") {
		t.Errorf("expected error for invalid cpe, got: %s", out)
	}
}

func TestMCP_FormatCPE_AllFormats(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	for _, to := range []string{"2.2", "2.3", "wfn"} {
		out := callTool(t, cs, "format_cpe", map[string]any{
			"cpe": "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*",
			"to":  to,
		})
		if !strings.Contains(out, "result") {
			t.Errorf("format_cpe to=%s unexpected: %s", to, out)
		}
	}
}

func TestMCP_FormatCPE_InvalidCPE(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "format_cpe", map[string]any{"cpe": "bad", "to": "2.3"})
	if !strings.Contains(out, "unrecognized") && !strings.Contains(out, "invalid") && !strings.Contains(out, "error") {
		t.Errorf("expected error for invalid cpe, got: %s", out)
	}
}

func TestMCP_FormatCPE_UnsupportedTarget(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "format_cpe", map[string]any{
		"cpe": "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*",
		"to":  "xml",
	})
	if !strings.Contains(out, "unsupported target format") {
		t.Errorf("expected unsupported format error, got: %s", out)
	}
}

func TestMCP_MatchCPE_Success(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "match_cpe", map[string]any{
		"criteria":       "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*",
		"target":         "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*",
		"ignore_version": true,
	})
	if !strings.Contains(out, `"match": true`) {
		t.Errorf("expected match=true, got: %s", out)
	}
}

func TestMCP_MatchCPE_InvalidCriteria(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "match_cpe", map[string]any{
		"criteria": "bad",
		"target":   "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*",
	})
	if !strings.Contains(out, "criteria") {
		t.Errorf("expected criteria error, got: %s", out)
	}
}

func TestMCP_MatchCPE_InvalidTarget(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "match_cpe", map[string]any{
		"criteria": "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*",
		"target":   "bad",
	})
	if !strings.Contains(out, "target") {
		t.Errorf("expected target error, got: %s", out)
	}
}

func TestMCP_ValidateCPE_Valid(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "validate_cpe", map[string]any{
		"cpe": "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*",
	})
	if !strings.Contains(out, `"valid": true`) {
		t.Errorf("expected valid=true, got: %s", out)
	}
}

func TestMCP_ValidateCPE_Invalid(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "validate_cpe", map[string]any{"cpe": "not-a-cpe"})
	if !strings.Contains(out, `"valid": false`) {
		t.Errorf("expected valid=false, got: %s", out)
	}
}

func TestMCP_GenerateCPE_Success(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "generate_cpe", map[string]any{
		"part": "a", "vendor": "apache", "product": "log4j", "version": "2.14",
	})
	// 版本中的 "." 在 CPE 2.3 中被转义为 "\."，故只检查 vendor/product
	if !strings.Contains(out, "apache") || !strings.Contains(out, "log4j") {
		t.Errorf("expected generated cpe with apache/log4j, got: %s", out)
	}
}

func TestMCP_CompareVersions_Basic(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "compare_versions", map[string]any{
		"a": "2.14.0", "b": "2.15.0",
	})
	// JSON 编码会把 "<" 转义为 "<"，故只检查 comparison 数值
	if !strings.Contains(out, `"comparison": -1`) {
		t.Errorf("expected comparison=-1 (a<b), got: %s", out)
	}
}

func TestMCP_CompareVersions_WithRange(t *testing.T) {
	cs, cancel := startMCPServer(t)
	defer cancel()
	defer cs.Close()

	out := callTool(t, cs, "compare_versions", map[string]any{
		"a": "2.14.0", "b": "2.15.0", "min": "2.0", "max": "3.0",
	})
	if !strings.Contains(out, `"in_range": true`) {
		t.Errorf("expected in_range=true, got: %s", out)
	}
}

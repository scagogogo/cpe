package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP (Model Context Protocol) server commands",
	Long: `Run cpe-skills as an MCP (Model Context Protocol) server,
exposing CPE parsing, matching, generation, and validation as
tools that AI assistants can call directly over stdio.

Examples:
  cpe mcp serve                  # start the MCP server on stdio`,
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server on stdio",
	Long: `Start an MCP (Model Context Protocol) server that communicates
over standard input/output (stdio).

Add this to your MCP client configuration (e.g. Claude Desktop):

  {
    "mcpServers": {
      "cpe-skills": {
        "command": "cpe",
        "args": ["mcp", "serve"]
      }
    }
  }

The server exposes these tools:
  - parse_cpe          Parse a CPE 2.2/2.3 string into components
  - format_cpe         Convert a CPE between 2.2/2.3/wfn formats
  - match_cpe          Check if two CPEs match (NISTIR 7696)
  - validate_cpe       Validate a CPE string
  - generate_cpe       Generate a CPE from part/vendor/product/version
  - compare_versions   Compare two version strings`,
	Args: cobra.NoArgs,
	RunE: runMCPServe,
}

func init() {
	mcpCmd.AddCommand(mcpServeCmd)
	rootCmd.AddCommand(mcpCmd)
}

// newMCPServer 构造一个已注册全部 CPE 工具的 MCP server，供测试调用。
func newMCPServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "cpe-skills",
		Version: cliVersion,
	}, nil)
	registerMCPTools(srv)
	return srv
}

func runMCPServe(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	srv := newMCPServer()
	return srv.Run(ctx, &mcp.StdioTransport{})
}

// argsOf extracts the tool call arguments as a map[string]any.
// CallToolParams.Arguments is a json.RawMessage; we unmarshal it once per call.
func argsOf(req *mcp.CallToolRequest) map[string]any {
	if req == nil || req.Params == nil {
		return map[string]any{}
	}
	raw := req.Params.Arguments
	if len(raw) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]any{}
	}
	return m
}

func argString(args map[string]any, key string) string {
	v, ok := args[key].(string)
	if !ok {
		return ""
	}
	return v
}

func argBool(args map[string]any, key string) bool {
	v, ok := args[key].(bool)
	return ok && v
}

// registerMCPTools wires all CPE tools into the MCP server.
func registerMCPTools(srv *mcp.Server) {
	// parse_cpe: parse a CPE string into its components.
	srv.AddTool(&mcp.Tool{
		Name:        "parse_cpe",
		Description: "Parse a CPE 2.2 or 2.3 string into its components (part, vendor, product, version, update, edition, language, etc.). Auto-detects the format.",
		InputSchema: rawSchema(`{
			"type": "object",
			"properties": {
				"cpe": {"type": "string", "description": "CPE string (2.2 URI or 2.3 Formatted String)"}
			},
			"required": ["cpe"]
		}`),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := argsOf(req)
		cpeStr := argString(args, "cpe")
		if cpeStr == "" {
			return toolError("missing 'cpe' argument"), nil
		}
		c, err := parseCPEString(cpeStr)
		if err != nil {
			return toolError(err.Error()), nil
		}
		return toolJSON(map[string]any{
			"input":    cpeStr,
			"format":   detectFormat(cpeStr),
			"part":     c.Part,
			"vendor":   c.Vendor,
			"product":  c.ProductName,
			"version":  c.Version,
			"update":   c.Update,
			"edition":  c.Edition,
			"language": c.Language,
			"cpe_2_2":  cpeskills.FormatCpe22(c),
			"cpe_2_3":  cpeskills.FormatCpe23(c),
		})
	})

	// format_cpe: convert a CPE between formats.
	srv.AddTool(&mcp.Tool{
		Name:        "format_cpe",
		Description: "Convert a CPE string to another format: 2.2 (URI), 2.3 (Formatted String), or wfn (Well-Formed Name).",
		InputSchema: rawSchema(`{
			"type": "object",
			"properties": {
				"cpe": {"type": "string", "description": "Input CPE string"},
				"to": {"type": "string", "enum": ["2.2", "2.3", "wfn"], "description": "Target format"}
			},
			"required": ["cpe", "to"]
		}`),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := argsOf(req)
		cpeStr := argString(args, "cpe")
		to := argString(args, "to")
		c, err := parseCPEString(cpeStr)
		if err != nil {
			return toolError(err.Error()), nil
		}
		var out string
		switch to {
		case "2.2":
			out = cpeskills.FormatCpe22(c)
		case "2.3":
			out = cpeskills.FormatCpe23(c)
		case "wfn":
			wfn := cpeskills.FromCPE(c)
			out = fmt.Sprintf("wfn:[part=%s,vendor=%s,product=%s,version=%s,update=%s,edition=%s,language=%s]",
				wfn.Part, wfn.Vendor, wfn.Product, wfn.Version, wfn.Update, wfn.Edition, wfn.Language)
		default:
			return toolError(fmt.Sprintf("unsupported target format %q (use 2.2, 2.3, or wfn)", to)), nil
		}
		return toolJSON(map[string]any{"input": cpeStr, "to": to, "result": out})
	})

	// match_cpe: NISTIR 7696 matching.
	srv.AddTool(&mcp.Tool{
		Name:        "match_cpe",
		Description: "Check if two CPEs match according to NISTIR 7696 name matching semantics. Returns whether the criteria CPE matches the target CPE.",
		InputSchema: rawSchema(`{
			"type": "object",
			"properties": {
				"criteria": {"type": "string", "description": "Criteria CPE string"},
				"target": {"type": "string", "description": "Target CPE string"},
				"ignore_version": {"type": "boolean", "default": false, "description": "Ignore version when matching"}
			},
			"required": ["criteria", "target"]
		}`),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := argsOf(req)
		cStr := argString(args, "criteria")
		tStr := argString(args, "target")
		ignoreVer := argBool(args, "ignore_version")

		criteria, err := parseCPEString(cStr)
		if err != nil {
			return toolError("criteria: " + err.Error()), nil
		}
		target, err := parseCPEString(tStr)
		if err != nil {
			return toolError("target: " + err.Error()), nil
		}
		result := cpeskills.MatchCPE(criteria, target, &cpeskills.MatchOptions{
			IgnoreVersion:    ignoreVer,
			AllowSubVersions: true,
		})
		return toolJSON(map[string]any{
			"criteria":       cStr,
			"target":         tStr,
			"match":          result,
			"ignore_version": ignoreVer,
		})
	})

	// validate_cpe: validate a CPE string.
	srv.AddTool(&mcp.Tool{
		Name:        "validate_cpe",
		Description: "Validate a CPE string (format and components). Returns whether the CPE is valid and any error message.",
		InputSchema: rawSchema(`{
			"type": "object",
			"properties": {
				"cpe": {"type": "string", "description": "CPE string to validate"}
			},
			"required": ["cpe"]
		}`),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := argsOf(req)
		cpeStr := argString(args, "cpe")
		c, err := parseCPEString(cpeStr)
		valid := err == nil
		var errMsg string
		if err != nil {
			errMsg = err.Error()
		} else if vErr := cpeskills.ValidateCPE(c); vErr != nil {
			valid = false
			errMsg = vErr.Error()
		}
		return toolJSON(map[string]any{
			"cpe":    cpeStr,
			"valid":  valid,
			"error":  errMsg,
			"format": detectFormat(cpeStr),
		})
	})

	// generate_cpe: build a CPE from components.
	srv.AddTool(&mcp.Tool{
		Name:        "generate_cpe",
		Description: "Generate a CPE 2.3 string from individual components (part, vendor, product, version). Part is 'a' (application), 'o' (operating system), or 'h' (hardware).",
		InputSchema: rawSchema(`{
			"type": "object",
			"properties": {
				"part": {"type": "string", "enum": ["a", "o", "h"], "description": "a=application, o=operating system, h=hardware"},
				"vendor": {"type": "string"},
				"product": {"type": "string"},
				"version": {"type": "string"}
			},
			"required": ["part", "vendor", "product", "version"]
		}`),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := argsOf(req)
		part := argString(args, "part")
		vendor := argString(args, "vendor")
		product := argString(args, "product")
		version := argString(args, "version")

		c := cpeskills.GenerateCPE(part, vendor, product, version)
		if c == nil {
			return toolError("failed to generate CPE from given components"), nil
		}
		return toolJSON(map[string]any{
			"cpe_2_3": cpeskills.FormatCpe23(c),
			"cpe_2_2": cpeskills.FormatCpe22(c),
			"components": map[string]string{
				"part": part, "vendor": vendor, "product": product, "version": version,
			},
		})
	})

	// compare_versions: compare two version strings.
	srv.AddTool(&mcp.Tool{
		Name:        "compare_versions",
		Description: "Compare two version strings. Returns -1 if a < b, 0 if a == b, 1 if a > b, plus whether a is within an optional range.",
		InputSchema: rawSchema(`{
			"type": "object",
			"properties": {
				"a": {"type": "string", "description": "First version"},
				"b": {"type": "string", "description": "Second version"},
				"min": {"type": "string", "description": "Optional range minimum"},
				"max": {"type": "string", "description": "Optional range maximum"}
			},
			"required": ["a", "b"]
		}`),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := argsOf(req)
		a := argString(args, "a")
		b := argString(args, "b")
		cmp := cpeskills.CompareVersions(a, b)
		result := map[string]any{
			"a":          a,
			"b":          b,
			"comparison": cmp,
			"meaning":    comparisonMeaning(cmp),
		}
		if min := argString(args, "min"); min != "" {
			max := argString(args, "max")
			result["in_range"] = cpeskills.IsVersionInRange(a, min, max)
			result["range"] = map[string]string{"min": min, "max": max}
		}
		return toolJSON(result)
	})
}

// --- helpers ---

func rawSchema(s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		// Should never happen with hand-written schemas; fall back to empty object.
		return map[string]any{"type": "object"}
	}
	return v
}

func detectFormat(s string) string {
	if len(s) >= 6 && s[:6] == "cpe:2." {
		return "2.3"
	}
	if len(s) >= 5 && s[:5] == "cpe:/" {
		return "2.2"
	}
	return "unknown"
}

func comparisonMeaning(cmp int) string {
	switch {
	case cmp < 0:
		return "a < b"
	case cmp > 0:
		return "a > b"
	default:
		return "a == b"
	}
}

// toolJSON returns a successful CallToolResult with a JSON text payload.
func toolJSON(v any) (*mcp.CallToolResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError("failed to encode result: " + err.Error()), nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil
}

// toolError returns a CallToolResult flagged as a tool-level error (visible to the LLM).
func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cpeskills "github.com/scagogogo/cpe-skills/pkg/cpe"
)

func TestParseCPEString_CPE23(t *testing.T) {
	result, err := parseCPEString("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Vendor != "microsoft" {
		t.Errorf("expected vendor microsoft, got %s", result.Vendor)
	}
	if result.ProductName != "windows" {
		t.Errorf("expected product windows, got %s", result.ProductName)
	}
	if result.Version != "10" {
		t.Errorf("expected version 10, got %s", result.Version)
	}
}

func TestParseCPEString_CPE22(t *testing.T) {
	result, err := parseCPEString("cpe:/a:apache:log4j:2.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Vendor != "apache" {
		t.Errorf("expected vendor apache, got %s", result.Vendor)
	}
	if result.ProductName != "log4j" {
		t.Errorf("expected product log4j, got %s", result.ProductName)
	}
}

func TestParseCPEString_InvalidFormat(t *testing.T) {
	_, err := parseCPEString("invalid-cpe-string")
	if err == nil {
		t.Error("expected error for invalid CPE string, got nil")
	}
}

func TestOutputCPE_TextFormat(t *testing.T) {
	c, _ := cpeskills.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	var buf bytes.Buffer
	err := outputCPE(&buf, c, "text")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "microsoft") {
		t.Errorf("expected output to contain 'microsoft', got: %s", output)
	}
	if !strings.Contains(output, "windows") {
		t.Errorf("expected output to contain 'windows', got: %s", output)
	}
}

func TestOutputCPE_JSONFormat(t *testing.T) {
	c, _ := cpeskills.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	var buf bytes.Buffer
	err := outputCPE(&buf, c, "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestOutputConversion_To22(t *testing.T) {
	c, _ := cpeskills.ParseCpe23("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
	result := cpeskills.FormatCpe22(c)
	if !strings.HasPrefix(result, "cpe:/") {
		t.Errorf("expected CPE 2.2 format, got: %s", result)
	}
}

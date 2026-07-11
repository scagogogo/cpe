package cpeskills

import (
	"testing"
)

// TestCPEExpression 测试CPE表达式
func TestCPEExpression(t *testing.T) {
	// 创建一个CPE和一个表达式
	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	expr := &CPEExpression{
		CPE: cpe,
	}

	// 测试Type方法
	if expr.Type() != ExpressionTypeCPE {
		t.Errorf("CPEExpression.Type() = %v, want %v", expr.Type(), ExpressionTypeCPE)
	}

	// 测试匹配的Evaluate方法
	target := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	if !expr.Evaluate(target) {
		t.Errorf("CPEExpression.Evaluate() = false, want true for matching CPE")
	}

	// 测试不匹配的Evaluate方法
	nonMatch := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "11",
	}

	if expr.Evaluate(nonMatch) {
		t.Errorf("CPEExpression.Evaluate() = true, want false for non-matching CPE")
	}

	// 测试String方法
	expectedString := "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
	if expr.String() != expectedString {
		t.Errorf("CPEExpression.String() = %v, want %v", expr.String(), expectedString)
	}
}

// TestANDExpression 测试AND表达式
func TestANDExpression(t *testing.T) {
	// 创建两个CPE表达式
	cpe1 := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	cpe2 := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "office",
		Version:     "2019",
	}

	expr1 := &CPEExpression{CPE: cpe1}
	expr2 := &CPEExpression{CPE: cpe2}

	// 创建AND表达式
	andExpr := &ANDExpression{
		Expressions: []Expression{expr1, expr2},
	}

	// 测试Type方法
	if andExpr.Type() != ExpressionTypeAND {
		t.Errorf("ANDExpression.Type() = %v, want %v", andExpr.Type(), ExpressionTypeAND)
	}

	// 测试Evaluate方法 - 两个表达式都匹配的情况
	target := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	// 对于AND，所有表达式都必须匹配，但我们的目标只匹配第一个表达式
	if andExpr.Evaluate(target) {
		t.Errorf("ANDExpression.Evaluate() = true, want false when not all expressions match")
	}

	// 测试Evaluate方法 - 只有一个表达式匹配的情况
	nonMatch := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "11",
	}

	if andExpr.Evaluate(nonMatch) {
		t.Errorf("ANDExpression.Evaluate() = true, want false when no expressions match")
	}

	// 测试String方法
	expectedString := "AND(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*)"
	if andExpr.String() != expectedString {
		t.Errorf("ANDExpression.String() = %v, want %v", andExpr.String(), expectedString)
	}
}

// TestORExpression 测试OR表达式
func TestORExpression(t *testing.T) {
	// 创建两个CPE表达式
	cpe1 := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	cpe2 := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "office",
		Version:     "2019",
	}

	expr1 := &CPEExpression{CPE: cpe1}
	expr2 := &CPEExpression{CPE: cpe2}

	// 创建OR表达式
	orExpr := &ORExpression{
		Expressions: []Expression{expr1, expr2},
	}

	// 测试Type方法
	if orExpr.Type() != ExpressionTypeOR {
		t.Errorf("ORExpression.Type() = %v, want %v", orExpr.Type(), ExpressionTypeOR)
	}

	// 测试Evaluate方法 - 匹配第一个表达式
	target1 := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	if !orExpr.Evaluate(target1) {
		t.Errorf("ORExpression.Evaluate() = false, want true when first expression matches")
	}

	// 测试Evaluate方法 - 匹配第二个表达式
	target2 := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "office",
		Version:     "2019",
	}

	if !orExpr.Evaluate(target2) {
		t.Errorf("ORExpression.Evaluate() = false, want true when second expression matches")
	}

	// 测试Evaluate方法 - 都不匹配
	nonMatch := &CPE{
		Cpe23:       "cpe:2.3:a:adobe:reader:dc:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "adobe",
		ProductName: "reader",
		Version:     "dc",
	}

	if orExpr.Evaluate(nonMatch) {
		t.Errorf("ORExpression.Evaluate() = true, want false when no expressions match")
	}

	// 测试String方法
	expectedString := "OR(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*)"
	if orExpr.String() != expectedString {
		t.Errorf("ORExpression.String() = %v, want %v", orExpr.String(), expectedString)
	}
}

// TestNOTExpression 测试NOT表达式
func TestNOTExpression(t *testing.T) {
	// 创建一个CPE表达式
	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	expr := &CPEExpression{CPE: cpe}

	// 创建NOT表达式
	notExpr := &NOTExpression{
		Expression: expr,
	}

	// 测试Type方法
	if notExpr.Type() != ExpressionTypeNOT {
		t.Errorf("NOTExpression.Type() = %v, want %v", notExpr.Type(), ExpressionTypeNOT)
	}

	// 测试Evaluate方法 - 匹配的情况
	target := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	// 对于NOT，如果表达式匹配，结果应该是false
	if notExpr.Evaluate(target) {
		t.Errorf("NOTExpression.Evaluate() = true, want false when expression matches")
	}

	// 测试Evaluate方法 - 不匹配的情况
	nonMatch := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "11",
	}

	// 对于NOT，如果表达式不匹配，结果应该是true
	if !notExpr.Evaluate(nonMatch) {
		t.Errorf("NOTExpression.Evaluate() = false, want true when expression doesn't match")
	}

	// 测试String方法
	expectedString := "NOT(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*)"
	if notExpr.String() != expectedString {
		t.Errorf("NOTExpression.String() = %v, want %v", notExpr.String(), expectedString)
	}
}

// TestParseExpression 测试解析表达式
func TestParseExpression(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		wantErr  bool
		wantType ExpressionType
	}{
		{
			name:     "简单CPE表达式",
			expr:     "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr:  false,
			wantType: ExpressionTypeCPE,
		},
		{
			name:     "AND表达式",
			expr:     "AND(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*)",
			wantErr:  false,
			wantType: ExpressionTypeAND,
		},
		{
			name:     "OR表达式",
			expr:     "OR(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*)",
			wantErr:  false,
			wantType: ExpressionTypeOR,
		},
		{
			name:     "NOT表达式",
			expr:     "NOT(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*)",
			wantErr:  false,
			wantType: ExpressionTypeNOT,
		},
		{
			name:     "无效表达式",
			expr:     "INVALID(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*)",
			wantErr:  true,
			wantType: 0,
		},
		{
			name:     "复杂嵌套表达式",
			expr:     "AND(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, OR(cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*, NOT(cpe:2.3:a:adobe:reader:dc:*:*:*:*:*:*:*)))",
			wantErr:  false,
			wantType: ExpressionTypeAND,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseExpression(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseExpression() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && got.Type() != tt.wantType {
				t.Errorf("ParseExpression() type = %v, want %v", got.Type(), tt.wantType)
			}
		})
	}
}

// TestParseANDExpressionExtended tests additional branches of parseANDExpression
func TestParseANDExpressionExtended(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{
			name:    "AND with invalid sub-expression",
			expr:    "AND(INVALID(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*))",
			wantErr: true,
		},
		{
			name:    "AND with nested expressions",
			expr:    "AND(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, OR(cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*, cpe:2.3:a:adobe:reader:*:*:*:*:*:*:*:*))",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseANDExpression(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseANDExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParseORExpressionExtended tests additional branches of parseORExpression
func TestParseORExpressionExtended(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{
			name:    "OR with invalid sub-expression",
			expr:    "OR(INVALID(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*))",
			wantErr: true,
		},
		{
			name:    "OR with CPE 2.2 format",
			expr:    "OR(cpe:/a:microsoft:windows:10, cpe:/a:adobe:reader:dc)",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseORExpression(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseORExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParseNOTExpressionExtended tests additional branches of parseNOTExpression
func TestParseNOTExpressionExtended(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{
			name:    "NOT with invalid inner expression",
			expr:    "NOT(INVALID(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*))",
			wantErr: true,
		},
		{
			name:    "NOT with CPE 2.2 format",
			expr:    "NOT(cpe:/a:microsoft:windows:10)",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseNOTExpression(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseNOTExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParseCPEExpressionExtended tests additional branches of parseCPEExpression
func TestParseCPEExpressionExtended(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{
			name:    "CPE 2.2 format",
			expr:    "cpe:/a:microsoft:windows:10",
			wantErr: false,
		},
		{
			name:    "CPE 2.3 format",
			expr:    "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: false,
		},
		{
			name:    "Invalid CPE format - no recognized prefix after cpe:",
			expr:    "cpe:invalid:format",
			wantErr: true,
		},
		{
			name:    "Invalid CPE 2.2 format - parse error",
			expr:    "cpe:/x:microsoft:windows:10",
			wantErr: true,
		},
		{
			name:    "Invalid CPE 2.3 format - wrong part count",
			expr:    "cpe:2.3:a:microsoft:windows",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCPEExpression(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCPEExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestSplitExpressionsExtended tests additional branches of splitExpressions
func TestSplitExpressionsExtended(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
		count   int
	}{
		{
			name:    "empty expression returns no sub-expressions",
			expr:    "",
			wantErr: false,
			count:   0,
		},
		{
			name:    "single expression",
			expr:    "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: false,
			count:   1,
		},
		{
			name:    "unmatched parentheses",
			expr:    "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, OR(cpe:2.3:a:adobe:reader:dc:*:*:*:*:*:*:*",
			wantErr: true,
		},
		{
			name:    "comma inside nested parentheses",
			expr:    "OR(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:adobe:reader:dc:*:*:*:*:*:*:*), cpe:2.3:a:test:test:1:*:*:*:*:*:*:*",
			wantErr: false,
			count:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := splitExpressions(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("splitExpressions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && len(result) != tt.count {
				t.Errorf("splitExpressions() returned %d sub-expressions, want %d", len(result), tt.count)
			}
		})
	}
}

// TestParseExpressionExtended tests additional branches of ParseExpression
func TestParseExpressionExtended(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{
			name:    "whitespace trimmed expression",
			expr:    "  cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*  ",
			wantErr: false,
		},
		{
			name:    "AND prefix but no closing paren",
			expr:    "AND(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: true,
		},
		{
			name:    "OR prefix but no closing paren",
			expr:    "OR(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: true,
		},
		{
			name:    "NOT prefix but no closing paren",
			expr:    "NOT(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseExpression(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseExpression() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestFilterCPEs 测试过滤CPE
func TestFilterCPEs(t *testing.T) {
	// 创建一些CPE
	windows10 := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	windows11 := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "11",
	}

	office2019 := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "office",
		Version:     "2019",
	}

	reader := &CPE{
		Cpe23:       "cpe:2.3:a:adobe:reader:dc:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      "adobe",
		ProductName: "reader",
		Version:     "dc",
	}

	cpes := []*CPE{windows10, windows11, office2019, reader}

	// 测试简单CPE表达式
	expr1, _ := ParseExpression("cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*")
	filtered1 := FilterCPEs(cpes, expr1)

	if len(filtered1) != 2 {
		t.Errorf("FilterCPEs() with Windows wildcard expression returned %d results, want 2", len(filtered1))
	}

	// 测试AND表达式
	expr2, _ := ParseExpression("AND(cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*, NOT(cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*))")
	filtered2 := FilterCPEs(cpes, expr2)

	if len(filtered2) != 2 {
		t.Errorf("FilterCPEs() with AND expression returned %d results, want 2", len(filtered2))
	}

	// 测试OR表达式
	expr3, _ := ParseExpression("OR(cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*, cpe:2.3:a:adobe:*:*:*:*:*:*:*:*:*)")
	filtered3 := FilterCPEs(cpes, expr3)

	if len(filtered3) != 2 {
		t.Errorf("FilterCPEs() with OR expression returned %d results, want 2", len(filtered3))
	}

	// 测试NOT表达式
	expr4, _ := ParseExpression("NOT(cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*)")
	filtered4 := FilterCPEs(cpes, expr4)

	if len(filtered4) != 1 {
		t.Errorf("FilterCPEs() with NOT expression returned %d results, want 1", len(filtered4))
	}
}

// TestParseANDExpression_SplitError tests parseANDExpression when splitExpressions returns an error
func TestParseANDExpression_SplitError(t *testing.T) {
	// AND with unbalanced parentheses should cause splitExpressions to fail
	_, err := parseANDExpression("AND(cpe:2.3:a:apache:log4j:2.0, cpe:2.3:a:apache:log4j:(2.0)")
	if err == nil {
		t.Error("parseANDExpression should return error when splitExpressions fails")
	}
}

// TestParseORExpression_SplitError tests parseORExpression when splitExpressions returns an error
func TestParseORExpression_SplitError(t *testing.T) {
	// OR with unbalanced parentheses should cause splitExpressions to fail
	_, err := parseORExpression("OR(cpe:2.3:a:apache:log4j:2.0, cpe:2.3:a:apache:log4j:(2.0)")
	if err == nil {
		t.Error("parseORExpression should return error when splitExpressions fails")
	}
}

	// TestParseANDExpression_CoverageGap_SplitError tests parseANDExpression when splitExpressions fails
	func TestParseANDExpression_CoverageGap_SplitError(t *testing.T) {
		// Unmatched parentheses in the inner expression should cause splitExpressions to fail
		_, err := parseANDExpression("AND(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, OR(cpe:2.3:a:adobe:reader:*:*:*:*:*:*:*:*)")
		if err == nil {
			t.Error("parseANDExpression with unmatched parens should return error")
		}
	}

	// TestParseORExpression_CoverageGap_SplitError tests parseORExpression when splitExpressions fails
	func TestParseORExpression_CoverageGap_SplitError(t *testing.T) {
		// Unmatched parentheses in the inner expression should cause splitExpressions to fail
		_, err := parseORExpression("OR(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, AND(cpe:2.3:a:adobe:reader:*:*:*:*:*:*:*:*)")
		if err == nil {
			t.Error("parseORExpression with unmatched parens should return error")
		}
	}

package cpe

import (
	"errors"
	"strings"
)

// ExpressionType 表达式类型
type ExpressionType int

const (
	// ExpressionTypeCPE 单个CPE匹配表达式
	ExpressionTypeCPE ExpressionType = iota

	// ExpressionTypeAND 逻辑AND表达式
	ExpressionTypeAND

	// ExpressionTypeOR 逻辑OR表达式
	ExpressionTypeOR

	// ExpressionTypeNOT 逻辑NOT表达式
	ExpressionTypeNOT
)

/**
 * Expression CPE适用性语言表达式接口
 *
 * 这个接口定义了CPE适用性语言中表达式的共同行为。
 * 所有类型的表达式（单个CPE、AND、OR、NOT）都实现了这个接口，
 * 提供了获取表达式类型、评估表达式和字符串表示的方法。
 */
type Expression interface {
	/**
	 * Type 返回表达式的类型
	 *
	 * @return ExpressionType 表达式类型，可以是CPE、AND、OR或NOT
	 */
	Type() ExpressionType

	/**
	 * Evaluate 评估表达式是否匹配目标CPE
	 *
	 * @param target *CPE 要匹配的目标CPE
	 * @return bool 如果表达式匹配目标CPE返回true，否则返回false
	 */
	Evaluate(target *CPE) bool

	/**
	 * String 返回表达式的字符串表示
	 *
	 * @return string 表达式的字符串形式，可用于日志记录或调试
	 */
	String() string
}

// CPEExpression 表示单个CPE匹配表达式
type CPEExpression struct {
	CPE *CPE
}

// Type 返回表达式类型
func (e *CPEExpression) Type() ExpressionType {
	return ExpressionTypeCPE
}

// Evaluate 评估表达式是否匹配目标CPE
func (e *CPEExpression) Evaluate(target *CPE) bool {
	return e.CPE.Match(target)
}

// String 返回表达式的字符串表示
func (e *CPEExpression) String() string {
	return e.CPE.Cpe23
}

// ANDExpression 表示逻辑AND表达式
type ANDExpression struct {
	Expressions []Expression
}

// Type 返回表达式类型
func (e *ANDExpression) Type() ExpressionType {
	return ExpressionTypeAND
}

// Evaluate 评估表达式是否匹配目标CPE
func (e *ANDExpression) Evaluate(target *CPE) bool {
	for _, expr := range e.Expressions {
		if !expr.Evaluate(target) {
			return false
		}
	}
	return true
}

// String 返回表达式的字符串表示
func (e *ANDExpression) String() string {
	var parts []string
	for _, expr := range e.Expressions {
		parts = append(parts, expr.String())
	}
	return "AND(" + strings.Join(parts, ", ") + ")"
}

// ORExpression 表示逻辑OR表达式
type ORExpression struct {
	Expressions []Expression
}

// Type 返回表达式类型
func (e *ORExpression) Type() ExpressionType {
	return ExpressionTypeOR
}

// Evaluate 评估表达式是否匹配目标CPE
func (e *ORExpression) Evaluate(target *CPE) bool {
	for _, expr := range e.Expressions {
		if expr.Evaluate(target) {
			return true
		}
	}
	return false
}

// String 返回表达式的字符串表示
func (e *ORExpression) String() string {
	var parts []string
	for _, expr := range e.Expressions {
		parts = append(parts, expr.String())
	}
	return "OR(" + strings.Join(parts, ", ") + ")"
}

// NOTExpression 表示逻辑NOT表达式
type NOTExpression struct {
	Expression Expression
}

// Type 返回表达式类型
func (e *NOTExpression) Type() ExpressionType {
	return ExpressionTypeNOT
}

// Evaluate 评估表达式是否匹配目标CPE
func (e *NOTExpression) Evaluate(target *CPE) bool {
	return !e.Expression.Evaluate(target)
}

// String 返回表达式的字符串表示
func (e *NOTExpression) String() string {
	return "NOT(" + e.Expression.String() + ")"
}

/**
 * ParseExpression 解析CPE适用性语言表达式
 *
 * CPE适用性语言允许通过逻辑表达式组合多个CPE，表达复杂的匹配条件。
 * 支持的表达式类型包括:
 *   - 单个CPE表达式: "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
 *   - AND逻辑组合: "AND(expr1, expr2, ...)"
 *   - OR逻辑组合: "OR(expr1, expr2, ...)"
 *   - NOT逻辑求反: "NOT(expr)"
 *
 * @param expr 要解析的表达式字符串
 * @return (Expression, error) 成功时返回解析后的表达式对象，失败时返回nil和错误
 *
 * @error 当表达式格式无效时返回错误
 * @error 当子表达式解析失败时返回错误
 *
 * 示例:
 *   ```go
 *   // 解析单个CPE表达式
 *   expr1, err := cpe.ParseExpression("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
 *   if err != nil {
 *       log.Fatalf("解析表达式失败: %v", err)
 *   }
 *
 *   // 解析OR表达式
 *   orExpr, err := cpe.ParseExpression("OR(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*)")
 *   if err != nil {
 *       log.Fatalf("解析OR表达式失败: %v", err)
 *   }
 *
 *   // 解析AND表达式
 *   andExpr, err := cpe.ParseExpression("AND(cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*, cpe:2.3:a:*:windows:*:*:*:*:*:*:*:*)")
 *   if err != nil {
 *       log.Fatalf("解析AND表达式失败: %v", err)
 *   }
 *
 *   // 解析NOT表达式
 *   notExpr, err := cpe.ParseExpression("NOT(cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*)")
 *   if err != nil {
 *       log.Fatalf("解析NOT表达式失败: %v", err)
 *   }
 *
 *   // 评估表达式
 *   targetCPE, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*")
 *   fmt.Println("Windows 11匹配OR表达式:", orExpr.Evaluate(targetCPE))
 *   // 输出: Windows 11匹配OR表达式: true
 *   ```
 */
func ParseExpression(expr string) (Expression, error) {
	expr = strings.TrimSpace(expr)

	// 检查是否为复合表达式
	if strings.HasPrefix(expr, "AND(") && strings.HasSuffix(expr, ")") {
		return parseANDExpression(expr)
	} else if strings.HasPrefix(expr, "OR(") && strings.HasSuffix(expr, ")") {
		return parseORExpression(expr)
	} else if strings.HasPrefix(expr, "NOT(") && strings.HasSuffix(expr, ")") {
		return parseNOTExpression(expr)
	} else if strings.HasPrefix(expr, "cpe:") {
		return parseCPEExpression(expr)
	}

	return nil, errors.New("invalid expression format")
}

// parseANDExpression 解析AND表达式
func parseANDExpression(expr string) (Expression, error) {
	// 移除外层AND()
	inner := expr[4 : len(expr)-1]

	// 分割子表达式
	subExprs, err := splitExpressions(inner)
	if err != nil {
		return nil, err
	}

	// 解析每个子表达式
	var expressions []Expression
	for _, subExpr := range subExprs {
		parsedExpr, err := ParseExpression(subExpr)
		if err != nil {
			return nil, err
		}
		expressions = append(expressions, parsedExpr)
	}

	return &ANDExpression{Expressions: expressions}, nil
}

// parseORExpression 解析OR表达式
func parseORExpression(expr string) (Expression, error) {
	// 移除外层OR()
	inner := expr[3 : len(expr)-1]

	// 分割子表达式
	subExprs, err := splitExpressions(inner)
	if err != nil {
		return nil, err
	}

	// 解析每个子表达式
	var expressions []Expression
	for _, subExpr := range subExprs {
		parsedExpr, err := ParseExpression(subExpr)
		if err != nil {
			return nil, err
		}
		expressions = append(expressions, parsedExpr)
	}

	return &ORExpression{Expressions: expressions}, nil
}

// parseNOTExpression 解析NOT表达式
func parseNOTExpression(expr string) (Expression, error) {
	// 移除外层NOT()
	inner := expr[4 : len(expr)-1]

	// 解析子表达式
	parsedExpr, err := ParseExpression(inner)
	if err != nil {
		return nil, err
	}

	return &NOTExpression{Expression: parsedExpr}, nil
}

// parseCPEExpression 解析CPE表达式
func parseCPEExpression(expr string) (Expression, error) {
	// 移除前缀"cpe:"
	cpeStr := expr
	if strings.HasPrefix(expr, "cpe:") {
		cpeStr = expr[4:]
	}

	// 解析CPE字符串
	var cpe *CPE
	var err error

	if strings.HasPrefix(cpeStr, "/") {
		// CPE 2.2格式
		cpe, err = ParseCpe22("cpe:" + cpeStr)
	} else if strings.HasPrefix(cpeStr, "2.3:") {
		// CPE 2.3格式
		cpe, err = ParseCpe23("cpe:" + cpeStr)
	} else {
		return nil, errors.New("invalid CPE format")
	}

	if err != nil {
		return nil, err
	}

	return &CPEExpression{CPE: cpe}, nil
}

// splitExpressions 分割复合表达式的子表达式
func splitExpressions(expr string) ([]string, error) {
	var result []string
	var current strings.Builder
	var parenthesisCount int

	for _, char := range expr {
		switch char {
		case '(':
			parenthesisCount++
			current.WriteRune(char)
		case ')':
			parenthesisCount--
			current.WriteRune(char)
		case ',':
			if parenthesisCount == 0 {
				// 在顶层遇到逗号，表示子表达式的边界
				result = append(result, strings.TrimSpace(current.String()))
				current.Reset()
			} else {
				// 在嵌套表达式中的逗号
				current.WriteRune(char)
			}
		default:
			current.WriteRune(char)
		}
	}

	// 添加最后一个子表达式
	if current.Len() > 0 {
		result = append(result, strings.TrimSpace(current.String()))
	}

	// 检查括号是否匹配
	if parenthesisCount != 0 {
		return nil, errors.New("unmatched parentheses in expression")
	}

	return result, nil
}

// FilterCPEs 使用适用性语言表达式过滤CPE列表
func FilterCPEs(cpes []*CPE, expr Expression) []*CPE {
	var result []*CPE

	for _, cpe := range cpes {
		if expr.Evaluate(cpe) {
			result = append(result, cpe)
		}
	}

	return result
}

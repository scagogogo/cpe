package cpeskills

import (
	"strings"
)

// isAlphanumeric 判断字符是否为字母或数字
func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// isLogicalValue 判断字符串是否为CPE逻辑值(ANY或NA)
func isLogicalValue(value string) bool {
	return value == ValueANY || value == ValueNA
}

// hasUnquotedWildcard 检查字符串是否包含未转义的通配符
func hasUnquotedWildcard(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == '*' || value[i] == '?' {
			if i == 0 || value[i-1] != '\\' {
				return true
			}
		}
	}
	return false
}

// quotedCharToPercentEncode 将需要百分号编码的字符映射为编码值
// NISTIR 7695 表6-2: 绑定到URI时的特殊字符编码
var quotedCharToPercentEncode = map[byte]string{
	'!':  "%21",
	'"':  "%22",
	'#':  "%23",
	'$':  "%24",
	'%':  "%25",
	'&':  "%26",
	'\'': "%27",
	'(':  "%28",
	')':  "%29",
	'+':  "%2b",
	',':  "%2c",
	'-':  "%2d",
	'.':  "%2e",
	'/':  "%2f",
	':':  "%3a",
	';':  "%3b",
	'<':  "%3c",
	'=':  "%3d",
	'>':  "%3e",
	'@':  "%40",
	'[':  "%5b",
	'\\': "%5c",
	']':  "%5d",
	'^':  "%5e",
	'_':  "%5f",
	'`':  "%60",
	'{':  "%7b",
	'|':  "%7c",
	'}':  "%7d",
	'~':  "%7e",
}

// percentEncodeToQuotedChar 将百分号编码值映射回原始字符
var percentEncodeToQuotedChar = func() map[string]byte {
	m := make(map[string]byte, len(quotedCharToPercentEncode))
	for k, v := range quotedCharToPercentEncode {
		m[v] = k
	}
	return m
}()

// escapeForFS 按照NISTIR 7695规范将WFN属性值转义为FS格式
// FS格式使用反斜杠转义特殊字符
func escapeForFS(value string) string {
	if isLogicalValue(value) || value == "" {
		return value
	}

	var b strings.Builder
	b.Grow(len(value) + 4)

	for i := 0; i < len(value); i++ {
		c := value[i]
		switch c {
		case '.':
			b.WriteString("\\.")
		case '-':
			b.WriteString("\\-")
		case '_':
			b.WriteString("\\_")
		default:
			// 检查是否需要百分号编码（非字母数字且不是已处理的特殊字符）
			if !isAlphanumeric(c) && c != '\\' {
				if encoded, ok := quotedCharToPercentEncode[c]; ok {
					b.WriteString(encoded)
				} else {
					b.WriteByte(c)
				}
			} else {
				b.WriteByte(c)
			}
		}
	}

	return b.String()
}

// unescapeFromFS 按照NISTIR 7695规范将FS格式的值反转义为WFN属性值
func unescapeFromFS(value string) string {
	if isLogicalValue(value) || value == "" {
		return value
	}

	var b strings.Builder
	b.Grow(len(value))

	i := 0
	for i < len(value) {
		if value[i] == '\\' && i+1 < len(value) {
			// 反斜杠转义字符
			b.WriteByte(value[i+1])
			i += 2
		} else if value[i] == '%' && i+2 < len(value) {
			// 百分号编码
			code := strings.ToLower(value[i : i+3])
			if c, ok := percentEncodeToQuotedChar[code]; ok {
				b.WriteByte(c)
			} else {
				b.WriteString(value[i : i+3])
			}
			i += 3
		} else {
			b.WriteByte(value[i])
			i++
		}
	}

	return b.String()
}

// escapeForURI 按照NISTIR 7695规范将WFN属性值转义为URI格式
// URI格式对所有非字母数字字符使用百分号编码
func escapeForURI(value string) string {
	if isLogicalValue(value) || value == "" {
		return value
	}

	var b strings.Builder
	b.Grow(len(value) + 8)

	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\\' && i+1 < len(value) {
			// 转义序列：先写反斜杠，再写编码后的下一个字符
			b.WriteString("%5c")
			next := value[i+1]
			if encoded, ok := quotedCharToPercentEncode[next]; ok {
				b.WriteString(encoded)
			} else if isAlphanumeric(next) {
				b.WriteByte(next)
			} else {
				b.WriteString("%" + toHex(next))
			}
			i += 2
		} else if isAlphanumeric(c) {
			b.WriteByte(c)
		} else if encoded, ok := quotedCharToPercentEncode[c]; ok {
			b.WriteString(encoded)
		} else {
			b.WriteString("%" + toHex(c))
		}
	}

	return b.String()
}

// unescapeFromURI 按照NISTIR 7695规范将URI格式的值反转义为WFN属性值
func unescapeFromURI(value string) string {
	if isLogicalValue(value) || value == "" {
		return value
	}

	var b strings.Builder
	b.Grow(len(value))

	i := 0
	for i < len(value) {
		if value[i] == '%' && i+2 < len(value) {
			code := strings.ToLower(value[i : i+3])
			if c, ok := percentEncodeToQuotedChar[code]; ok {
				b.WriteByte(c)
			} else {
				b.WriteString(value[i : i+3])
			}
			i += 3
		} else {
			b.WriteByte(value[i])
			i++
		}
	}

	return b.String()
}

// toHex 将字节转换为十六进制表示
func toHex(c byte) string {
	const hexDigits = "0123456789abcdef"
	return string([]byte{hexDigits[c>>4], hexDigits[c&0x0f]})
}

// packExtendedAttributes 将扩展属性打包为CPE 2.2的波浪线分隔格式
func packExtendedAttributes(edition, language, swEdition, targetSw, targetHw, other string) string {
	parts := []string{edition, language, swEdition, targetSw, targetHw, other}
	// 移除末尾空值
	lastNonEmpty := -1
	for i, p := range parts {
		if p != "" && p != ValueANY {
			lastNonEmpty = i
		}
	}
	if lastNonEmpty == -1 {
		return ""
	}
	parts = parts[:lastNonEmpty+1]

	// 对于空的部分使用空字符串，对于ANY值使用空字符串
	result := make([]string, len(parts))
	for i, p := range parts {
		if p == ValueANY {
			result[i] = ""
		} else {
			result[i] = p
		}
	}
	return strings.Join(result, "~")
}

// unpackExtendedAttributes 从CPE 2.2的波浪线分隔格式解包扩展属性
func unpackExtendedAttributes(packed string) (edition, language, swEdition, targetSw, targetHw, other string) {
	if packed == "" {
		return "", "", "", "", "", ""
	}

	parts := strings.Split(packed, "~")

	get := func(idx int) string {
		if idx < len(parts) {
			v := parts[idx]
			if v == "" {
				return ValueANY
			}
			return v
		}
		return ValueANY
	}

	edition = get(0)
	language = get(1)
	swEdition = get(2)
	targetSw = get(3)
	targetHw = get(4)
	other = get(5)

	return
}

// quoteForWFN 为WFN字符串表示转义属性值中的特殊字符
func quoteForWFN(value string) string {
	if isLogicalValue(value) {
		return value
	}

	var b strings.Builder
	b.Grow(len(value) + 2)

	for i := 0; i < len(value); i++ {
		if value[i] == '"' {
			b.WriteString("\\\"")
		} else if value[i] == '\\' && i+1 < len(value) {
			b.WriteByte(value[i])
			b.WriteByte(value[i+1])
			i++
		} else {
			b.WriteByte(value[i])
		}
	}

	return b.String()
}

// unquoteFromWFN 从WFN字符串表示反转义属性值
func unquoteFromWFN(value string) string {
	var b strings.Builder
	b.Grow(len(value))

	i := 0
	for i < len(value) {
		if value[i] == '\\' && i+1 < len(value) {
			if value[i+1] == '"' {
				b.WriteByte('"')
				i += 2
			} else {
				b.WriteByte(value[i+1])
				i += 2
			}
		} else {
			b.WriteByte(value[i])
			i++
		}
	}

	return b.String()
}

// escapeValue 对CPE 2.3格式的值进行转义（向后兼容包装器）
// 按照 NISTIR 7695 规范实现 FS 格式转义
func escapeValue(value string) string {
	return escapeForFS(value)
}

// unescapeValue 对CPE 2.3格式的值进行反转义（向后兼容包装器）
// 按照 NISTIR 7695 规范实现 FS 格式反转义
func unescapeValue(value string) string {
	return unescapeFromFS(value)
}

// escapeValueForCpe22 对CPE 2.2格式的值进行转义（向后兼容包装器）
func escapeValueForCpe22(value string) string {
	return escapeForURI(value)
}

// unescapeValueForCpe22 对CPE 2.2格式的值进行反转义（向后兼容包装器）
func unescapeValueForCpe22(value string) string {
	return unescapeFromURI(value)
}

// escapeCpe22Value 对CPE 2.2格式的值进行转义（向后兼容包装器）
func escapeCpe22Value(value string) string {
	return escapeForURI(value)
}

// unescapeCpe22Value 对CPE 2.2格式的值进行反转义（向后兼容包装器）
func unescapeCpe22Value(value string) string {
	return unescapeFromURI(value)
}
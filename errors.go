package cpe

import (
	"fmt"
)

// ErrorType 表示CPE错误类型
type ErrorType int

const (
	// ErrorTypeParsingFailed 解析失败
	ErrorTypeParsingFailed ErrorType = iota

	// ErrorTypeInvalidFormat 无效格式
	ErrorTypeInvalidFormat

	// ErrorTypeInvalidPart 无效Part值
	ErrorTypeInvalidPart

	// ErrorTypeInvalidAttribute 无效属性值
	ErrorTypeInvalidAttribute

	// ErrorTypeNotFound 未找到
	ErrorTypeNotFound

	// ErrorTypeOperationFailed 操作失败
	ErrorTypeOperationFailed
)

// CPEError 表示CPE操作错误
type CPEError struct {
	// 错误类型
	Type ErrorType

	// 错误信息
	Message string

	// 相关CPE字符串
	CPEString string

	// 原始错误（可选）
	Err error
}

// Error 实现error接口
func (e *CPEError) Error() string {
	if e.CPEString != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.CPEString)
	}
	return e.Message
}

// Unwrap 解包原始错误
func (e *CPEError) Unwrap() error {
	return e.Err
}

// NewParsingError 创建解析错误
func NewParsingError(cpeString string, err error) *CPEError {
	return &CPEError{
		Type:      ErrorTypeParsingFailed,
		Message:   "failed to parse CPE string",
		CPEString: cpeString,
		Err:       err,
	}
}

// NewInvalidFormatError 创建无效格式错误
func NewInvalidFormatError(cpeString string) *CPEError {
	return &CPEError{
		Type:      ErrorTypeInvalidFormat,
		Message:   "invalid CPE format",
		CPEString: cpeString,
	}
}

// NewInvalidPartError 创建无效Part错误
func NewInvalidPartError(part string) *CPEError {
	return &CPEError{
		Type:    ErrorTypeInvalidPart,
		Message: fmt.Sprintf("invalid CPE part: %s", part),
	}
}

// NewInvalidAttributeError 创建无效属性错误
func NewInvalidAttributeError(attribute, value string) *CPEError {
	return &CPEError{
		Type:    ErrorTypeInvalidAttribute,
		Message: fmt.Sprintf("invalid value for attribute %s: %s", attribute, value),
	}
}

// NewNotFoundError 创建未找到错误
func NewNotFoundError(what string) *CPEError {
	return &CPEError{
		Type:    ErrorTypeNotFound,
		Message: fmt.Sprintf("%s not found", what),
	}
}

// NewOperationFailedError 创建操作失败错误
func NewOperationFailedError(operation string, err error) *CPEError {
	return &CPEError{
		Type:    ErrorTypeOperationFailed,
		Message: fmt.Sprintf("operation %s failed", operation),
		Err:     err,
	}
}

// IsParsingError 检查是否为解析错误
func IsParsingError(err error) bool {
	cpeErr, ok := err.(*CPEError)
	return ok && cpeErr.Type == ErrorTypeParsingFailed
}

// IsInvalidFormatError 检查是否为无效格式错误
func IsInvalidFormatError(err error) bool {
	cpeErr, ok := err.(*CPEError)
	return ok && cpeErr.Type == ErrorTypeInvalidFormat
}

// IsInvalidPartError 检查是否为无效Part错误
func IsInvalidPartError(err error) bool {
	cpeErr, ok := err.(*CPEError)
	return ok && cpeErr.Type == ErrorTypeInvalidPart
}

// IsInvalidAttributeError 检查是否为无效属性错误
func IsInvalidAttributeError(err error) bool {
	cpeErr, ok := err.(*CPEError)
	return ok && cpeErr.Type == ErrorTypeInvalidAttribute
}

// IsNotFoundError 检查是否为未找到错误
func IsNotFoundError(err error) bool {
	cpeErr, ok := err.(*CPEError)
	return ok && cpeErr.Type == ErrorTypeNotFound
}

// IsOperationFailedError 检查是否为操作失败错误
func IsOperationFailedError(err error) bool {
	cpeErr, ok := err.(*CPEError)
	return ok && cpeErr.Type == ErrorTypeOperationFailed
}

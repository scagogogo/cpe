package cpe

import (
	"fmt"
)

/**
 * ErrorType 表示CPE操作过程中可能出现的错误类型枚举
 *
 * 这个枚举用于区分不同种类的CPE错误，便于错误处理和日志记录。
 * 每种错误类型对应特定的错误情况，使用常量定义便于代码维护。
 */
type ErrorType int

const (
	// ErrorTypeParsingFailed 表示CPE字符串解析失败的错误类型
	ErrorTypeParsingFailed ErrorType = iota

	// ErrorTypeInvalidFormat 表示CPE格式无效的错误类型
	ErrorTypeInvalidFormat

	// ErrorTypeInvalidPart 表示CPE部件值无效的错误类型
	ErrorTypeInvalidPart

	// ErrorTypeInvalidAttribute 表示CPE属性值无效的错误类型
	ErrorTypeInvalidAttribute

	// ErrorTypeNotFound 表示未找到请求的资源或对象的错误类型
	ErrorTypeNotFound

	// ErrorTypeOperationFailed 表示CPE相关操作执行失败的错误类型
	ErrorTypeOperationFailed
)

/**
 * CPEError 提供统一的CPE错误处理结构
 *
 * 该结构封装了与CPE操作相关的所有错误信息，包括错误类型、
 * 错误消息、相关的CPE字符串以及可能的原始错误。这种设计
 * 使得错误处理和调试变得更加方便。
 *
 * 示例:
 *   ```go
 *   // 处理CPE错误
 *   func processCPE(cpeStr string) (*cpe.CPE, error) {
 *       cpeObj, err := cpe.Parse(cpeStr)
 *       if err != nil {
 *           if cpe.IsParsingError(err) {
 *               // 处理解析错误
 *               log.Printf("解析错误: %v", err)
 *           } else if cpe.IsInvalidFormatError(err) {
 *               // 处理格式错误
 *               log.Printf("格式错误: %v", err)
 *           }
 *           return nil, err
 *       }
 *       return cpeObj, nil
 *   }
 *   ```
 */
type CPEError struct {
	// Type 表示错误的类型，使用ErrorType枚举
	Type ErrorType

	// Message 包含人类可读的错误描述信息
	Message string

	// CPEString 保存与错误相关的CPE字符串
	CPEString string

	// Err 引用导致此错误的原始错误（如果有）
	Err error
}

/**
 * Error 实现Go标准错误接口
 *
 * 返回格式化的错误信息，如果有关联的CPE字符串，会将其包含在错误消息中。
 *
 * @return string 格式化的错误消息
 */
func (e *CPEError) Error() string {
	if e.CPEString != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.CPEString)
	}
	return e.Message
}

/**
 * Unwrap 实现错误解包，用于Go 1.13+的错误链
 *
 * 返回包装在CPEError中的原始错误，以支持errors.Is和errors.As功能。
 *
 * @return error 原始错误，如果不存在则返回nil
 */
func (e *CPEError) Unwrap() error {
	return e.Err
}

/**
 * NewParsingError 创建表示CPE字符串解析失败的错误
 *
 * @param cpeString string 无法解析的CPE字符串
 * @param err error 导致解析失败的原始错误
 * @return *CPEError 封装了解析错误信息的CPEError对象
 *
 * 示例:
 *   ```go
 *   // 尝试解析无效的CPE字符串
 *   cpeStr := "cpe:2.3:INVALID FORMAT"
 *   _, err := parseCPE(cpeStr)
 *   if err != nil {
 *       return cpe.NewParsingError(cpeStr, err)
 *   }
 *   ```
 */
func NewParsingError(cpeString string, err error) *CPEError {
	return &CPEError{
		Type:      ErrorTypeParsingFailed,
		Message:   "failed to parse CPE string",
		CPEString: cpeString,
		Err:       err,
	}
}

/**
 * NewInvalidFormatError 创建表示CPE格式无效的错误
 *
 * @param cpeString string 格式无效的CPE字符串
 * @return *CPEError 封装了格式错误信息的CPEError对象
 *
 * 示例:
 *   ```go
 *   // 检查CPE字符串格式
 *   if !isValidCPEFormat(cpeStr) {
 *       return nil, cpe.NewInvalidFormatError(cpeStr)
 *   }
 *   ```
 */
func NewInvalidFormatError(cpeString string) *CPEError {
	return &CPEError{
		Type:      ErrorTypeInvalidFormat,
		Message:   "invalid CPE format",
		CPEString: cpeString,
	}
}

/**
 * NewInvalidPartError 创建表示CPE部件值无效的错误
 *
 * @param part string 无效的CPE部件值
 * @return *CPEError 封装了部件错误信息的CPEError对象
 *
 * 示例:
 *   ```go
 *   // 验证CPE部件值
 *   if part != "a" && part != "o" && part != "h" {
 *       return cpe.NewInvalidPartError(part)
 *   }
 *   ```
 */
func NewInvalidPartError(part string) *CPEError {
	return &CPEError{
		Type:    ErrorTypeInvalidPart,
		Message: fmt.Sprintf("invalid CPE part: %s", part),
	}
}

/**
 * NewInvalidAttributeError 创建表示CPE属性值无效的错误
 *
 * @param attribute string 属性名称
 * @param value string 无效的属性值
 * @return *CPEError 封装了属性错误信息的CPEError对象
 *
 * 示例:
 *   ```go
 *   // 验证属性值
 *   if !isValidProductName(product) {
 *       return cpe.NewInvalidAttributeError("product", product)
 *   }
 *   ```
 */
func NewInvalidAttributeError(attribute, value string) *CPEError {
	return &CPEError{
		Type:    ErrorTypeInvalidAttribute,
		Message: fmt.Sprintf("invalid value for attribute %s: %s", attribute, value),
	}
}

/**
 * NewNotFoundError 创建表示资源未找到的错误
 *
 * @param what string 未找到的资源描述
 * @return *CPEError 封装了未找到错误信息的CPEError对象
 *
 * 示例:
 *   ```go
 *   // 在存储中查找CPE
 *   cpe, found := storage.Find(cpeID)
 *   if !found {
 *       return nil, cpe.NewNotFoundError(fmt.Sprintf("CPE with ID %s", cpeID))
 *   }
 *   ```
 */
func NewNotFoundError(what string) *CPEError {
	return &CPEError{
		Type:    ErrorTypeNotFound,
		Message: fmt.Sprintf("%s not found", what),
	}
}

/**
 * NewOperationFailedError 创建表示操作执行失败的错误
 *
 * @param operation string 失败操作的描述
 * @param err error 导致操作失败的原始错误
 * @return *CPEError 封装了操作失败错误信息的CPEError对象
 *
 * 示例:
 *   ```go
 *   // 保存CPE到存储
 *   if err := storage.Save(cpe); err != nil {
 *       return cpe.NewOperationFailedError("save CPE to storage", err)
 *   }
 *   ```
 */
func NewOperationFailedError(operation string, err error) *CPEError {
	return &CPEError{
		Type:    ErrorTypeOperationFailed,
		Message: fmt.Sprintf("operation %s failed", operation),
		Err:     err,
	}
}

/**
 * IsParsingError 检查错误是否为CPE解析错误
 *
 * @param err error 要检查的错误
 * @return bool 如果错误是CPE解析错误则返回true，否则返回false
 *
 * 示例:
 *   ```go
 *   if err != nil {
 *       if cpe.IsParsingError(err) {
 *           // 针对解析错误的特殊处理
 *           log.Printf("解析CPE时出错: %v", err)
 *       }
 *   }
 *   ```
 */
func IsParsingError(err error) bool {
	cpeErr, ok := err.(*CPEError)
	return ok && cpeErr.Type == ErrorTypeParsingFailed
}

/**
 * IsInvalidFormatError 检查错误是否为CPE格式无效错误
 *
 * @param err error 要检查的错误
 * @return bool 如果错误是CPE格式无效错误则返回true，否则返回false
 */
func IsInvalidFormatError(err error) bool {
	cpeErr, ok := err.(*CPEError)
	return ok && cpeErr.Type == ErrorTypeInvalidFormat
}

/**
 * IsInvalidPartError 检查错误是否为CPE部件无效错误
 *
 * @param err error 要检查的错误
 * @return bool 如果错误是CPE部件无效错误则返回true，否则返回false
 */
func IsInvalidPartError(err error) bool {
	cpeErr, ok := err.(*CPEError)
	return ok && cpeErr.Type == ErrorTypeInvalidPart
}

/**
 * IsInvalidAttributeError 检查错误是否为CPE属性无效错误
 *
 * @param err error 要检查的错误
 * @return bool 如果错误是CPE属性无效错误则返回true，否则返回false
 */
func IsInvalidAttributeError(err error) bool {
	cpeErr, ok := err.(*CPEError)
	return ok && cpeErr.Type == ErrorTypeInvalidAttribute
}

/**
 * IsNotFoundError 检查错误是否为资源未找到错误
 *
 * @param err error 要检查的错误
 * @return bool 如果错误是资源未找到错误则返回true，否则返回false
 */
func IsNotFoundError(err error) bool {
	cpeErr, ok := err.(*CPEError)
	return ok && cpeErr.Type == ErrorTypeNotFound
}

/**
 * IsOperationFailedError 检查错误是否为操作失败错误
 *
 * @param err error 要检查的错误
 * @return bool 如果错误是操作失败错误则返回true，否则返回false
 */
func IsOperationFailedError(err error) bool {
	cpeErr, ok := err.(*CPEError)
	return ok && cpeErr.Type == ErrorTypeOperationFailed
}

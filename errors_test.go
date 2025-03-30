package cpe

import (
	"errors"
	"testing"
)

// TestCPEError_Error 测试CPEError的Error方法
func TestCPEError_Error(t *testing.T) {
	tests := []struct {
		name     string
		cpeErr   *CPEError
		expected string
	}{
		{
			name: "带CPEString的错误",
			cpeErr: &CPEError{
				Type:      ErrorTypeParsingFailed,
				Message:   "failed to parse CPE string",
				CPEString: "cpe:/invalid",
			},
			expected: "failed to parse CPE string: cpe:/invalid",
		},
		{
			name: "不带CPEString的错误",
			cpeErr: &CPEError{
				Type:    ErrorTypeInvalidPart,
				Message: "invalid CPE part: x",
			},
			expected: "invalid CPE part: x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cpeErr.Error(); got != tt.expected {
				t.Errorf("CPEError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestCPEError_Unwrap 测试CPEError的Unwrap方法
func TestCPEError_Unwrap(t *testing.T) {
	originalErr := errors.New("original error")

	cpeErr := &CPEError{
		Type:    ErrorTypeOperationFailed,
		Message: "operation failed",
		Err:     originalErr,
	}

	if unwrapped := cpeErr.Unwrap(); unwrapped != originalErr {
		t.Errorf("CPEError.Unwrap() = %v, want %v", unwrapped, originalErr)
	}

	// 测试没有原始错误的情况
	cpeErrNoOriginal := &CPEError{
		Type:    ErrorTypeNotFound,
		Message: "not found",
	}

	if unwrapped := cpeErrNoOriginal.Unwrap(); unwrapped != nil {
		t.Errorf("CPEError.Unwrap() = %v, want nil", unwrapped)
	}
}

// TestNewParsingError 测试创建解析错误
func TestNewParsingError(t *testing.T) {
	cpeStr := "cpe:/invalid"
	originalErr := errors.New("unexpected format")

	cpeErr := NewParsingError(cpeStr, originalErr)

	if cpeErr.Type != ErrorTypeParsingFailed {
		t.Errorf("NewParsingError().Type = %v, want %v", cpeErr.Type, ErrorTypeParsingFailed)
	}

	if cpeErr.Message != "failed to parse CPE string" {
		t.Errorf("NewParsingError().Message = %v, want %v", cpeErr.Message, "failed to parse CPE string")
	}

	if cpeErr.CPEString != cpeStr {
		t.Errorf("NewParsingError().CPEString = %v, want %v", cpeErr.CPEString, cpeStr)
	}

	if cpeErr.Err != originalErr {
		t.Errorf("NewParsingError().Err = %v, want %v", cpeErr.Err, originalErr)
	}
}

// TestNewInvalidFormatError 测试创建无效格式错误
func TestNewInvalidFormatError(t *testing.T) {
	cpeStr := "cpe:/a:microsoft"

	cpeErr := NewInvalidFormatError(cpeStr)

	if cpeErr.Type != ErrorTypeInvalidFormat {
		t.Errorf("NewInvalidFormatError().Type = %v, want %v", cpeErr.Type, ErrorTypeInvalidFormat)
	}

	if cpeErr.Message != "invalid CPE format" {
		t.Errorf("NewInvalidFormatError().Message = %v, want %v", cpeErr.Message, "invalid CPE format")
	}

	if cpeErr.CPEString != cpeStr {
		t.Errorf("NewInvalidFormatError().CPEString = %v, want %v", cpeErr.CPEString, cpeStr)
	}
}

// TestNewInvalidPartError 测试创建无效Part错误
func TestNewInvalidPartError(t *testing.T) {
	part := "x"

	cpeErr := NewInvalidPartError(part)

	if cpeErr.Type != ErrorTypeInvalidPart {
		t.Errorf("NewInvalidPartError().Type = %v, want %v", cpeErr.Type, ErrorTypeInvalidPart)
	}

	expectedMessage := "invalid CPE part: x"
	if cpeErr.Message != expectedMessage {
		t.Errorf("NewInvalidPartError().Message = %v, want %v", cpeErr.Message, expectedMessage)
	}
}

// TestNewInvalidAttributeError 测试创建无效属性错误
func TestNewInvalidAttributeError(t *testing.T) {
	attribute := "version"
	value := "@invalid"

	cpeErr := NewInvalidAttributeError(attribute, value)

	if cpeErr.Type != ErrorTypeInvalidAttribute {
		t.Errorf("NewInvalidAttributeError().Type = %v, want %v", cpeErr.Type, ErrorTypeInvalidAttribute)
	}

	expectedMessage := "invalid value for attribute version: @invalid"
	if cpeErr.Message != expectedMessage {
		t.Errorf("NewInvalidAttributeError().Message = %v, want %v", cpeErr.Message, expectedMessage)
	}
}

// TestNewNotFoundError 测试创建未找到错误
func TestNewNotFoundError(t *testing.T) {
	what := "product"

	cpeErr := NewNotFoundError(what)

	if cpeErr.Type != ErrorTypeNotFound {
		t.Errorf("NewNotFoundError().Type = %v, want %v", cpeErr.Type, ErrorTypeNotFound)
	}

	expectedMessage := "product not found"
	if cpeErr.Message != expectedMessage {
		t.Errorf("NewNotFoundError().Message = %v, want %v", cpeErr.Message, expectedMessage)
	}
}

// TestNewOperationFailedError 测试创建操作失败错误
func TestNewOperationFailedError(t *testing.T) {
	operation := "update"
	originalErr := errors.New("failed to update database")

	cpeErr := NewOperationFailedError(operation, originalErr)

	if cpeErr.Type != ErrorTypeOperationFailed {
		t.Errorf("NewOperationFailedError().Type = %v, want %v", cpeErr.Type, ErrorTypeOperationFailed)
	}

	expectedMessage := "operation update failed"
	if cpeErr.Message != expectedMessage {
		t.Errorf("NewOperationFailedError().Message = %v, want %v", cpeErr.Message, expectedMessage)
	}

	if cpeErr.Err != originalErr {
		t.Errorf("NewOperationFailedError().Err = %v, want %v", cpeErr.Err, originalErr)
	}
}

// TestIsParsingError 测试检查是否为解析错误
func TestIsParsingError(t *testing.T) {
	parsingErr := NewParsingError("cpe:/invalid", errors.New("parse error"))
	formatErr := NewInvalidFormatError("cpe:/a:microsoft")
	genericErr := errors.New("generic error")

	if !IsParsingError(parsingErr) {
		t.Errorf("IsParsingError() on parsing error returned false, want true")
	}

	if IsParsingError(formatErr) {
		t.Errorf("IsParsingError() on format error returned true, want false")
	}

	if IsParsingError(genericErr) {
		t.Errorf("IsParsingError() on generic error returned true, want false")
	}

	if IsParsingError(nil) {
		t.Errorf("IsParsingError() on nil returned true, want false")
	}
}

// TestIsInvalidFormatError 测试检查是否为无效格式错误
func TestIsInvalidFormatError(t *testing.T) {
	formatErr := NewInvalidFormatError("cpe:/a:microsoft")
	partErr := NewInvalidPartError("x")
	genericErr := errors.New("generic error")

	if !IsInvalidFormatError(formatErr) {
		t.Errorf("IsInvalidFormatError() on format error returned false, want true")
	}

	if IsInvalidFormatError(partErr) {
		t.Errorf("IsInvalidFormatError() on part error returned true, want false")
	}

	if IsInvalidFormatError(genericErr) {
		t.Errorf("IsInvalidFormatError() on generic error returned true, want false")
	}

	if IsInvalidFormatError(nil) {
		t.Errorf("IsInvalidFormatError() on nil returned true, want false")
	}
}

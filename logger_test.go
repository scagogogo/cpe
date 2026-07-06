package cpeskills

import (
	"bytes"
	"strings"
	"testing"
)

func TestLogLevel_String(t *testing.T) {
	tests := []struct {
		level LogLevel
		want  string
	}{
		{LogLevelDebug, "DEBUG"},
		{LogLevelInfo, "INFO"},
		{LogLevelWarn, "WARN"},
		{LogLevelError, "ERROR"},
		{LogLevelOff, "OFF"},
		{LogLevel(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("LogLevel(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestDefaultLogger_Levels(t *testing.T) {
	var buf bytes.Buffer
	l := NewDefaultLogger(&buf, LogLevelInfo)
	l.Debug("debug-msg") // 低于 Info，不输出
	l.Info("info-msg", "key", "value")
	l.Warn("warn-msg")
	l.Error("error-msg")
	out := buf.String()
	if strings.Contains(out, "debug-msg") {
		t.Error("debug should be filtered at Info level")
	}
	if !strings.Contains(out, "[INFO] info-msg") {
		t.Errorf("expected info msg, got: %s", out)
	}
	if !strings.Contains(out, "key=value") {
		t.Errorf("expected key=value, got: %s", out)
	}
	if !strings.Contains(out, "[WARN]") || !strings.Contains(out, "[ERROR]") {
		t.Errorf("expected warn and error, got: %s", out)
	}
}

func TestDefaultLogger_MissingValue(t *testing.T) {
	var buf bytes.Buffer
	l := NewDefaultLogger(&buf, LogLevelDebug)
	l.Info("msg", "key") // 奇数个 keyvals
	if !strings.Contains(buf.String(), "key=(MISSING)") {
		t.Errorf("expected MISSING, got: %s", buf.String())
	}
}

func TestDefaultLogger_Off(t *testing.T) {
	var buf bytes.Buffer
	l := NewDefaultLogger(&buf, LogLevelOff)
	l.Error("should-not-appear")
	if buf.Len() != 0 {
		t.Errorf("expected no output at Off level, got: %s", buf.String())
	}
}

func TestDefaultLogger_With(t *testing.T) {
	var buf bytes.Buffer
	l := NewDefaultLogger(&buf, LogLevelInfo)
	l2 := l.With("component", "cpe")
	l2.Info("msg", "event", "parse")
	out := buf.String()
	if !strings.Contains(out, "component=cpe") {
		t.Errorf("expected prefix, got: %s", out)
	}
	if !strings.Contains(out, "event=parse") {
		t.Errorf("expected msg keyval, got: %s", out)
	}
}

func TestDefaultLogger_SetLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewDefaultLogger(&buf, LogLevelInfo)
	l.SetLevel(LogLevelError)
	l.Info("filtered")
	l.Error("kept")
	out := buf.String()
	if strings.Contains(out, "filtered") {
		t.Error("info should be filtered after SetLevel(Error)")
	}
	if !strings.Contains(out, "kept") {
		t.Errorf("expected error kept, got: %s", out)
	}
}

func TestSetLogger_Nil(t *testing.T) {
	orig := GetLogger()
	defer SetLogger(orig)
	SetLogger(nil)
	if GetLogger() == nil {
		t.Error("expected non-nil nop logger after SetLogger(nil)")
	}
	// 不应 panic
	LogInfo("test")
}

func TestSetLogger_Custom(t *testing.T) {
	orig := GetLogger()
	defer SetLogger(orig)
	var buf bytes.Buffer
	SetLogger(NewDefaultLogger(&buf, LogLevelInfo))
	LogInfo("global-msg", "k", "v")
	if !strings.Contains(buf.String(), "global-msg") {
		t.Errorf("expected global msg, got: %s", buf.String())
	}
}

func TestStdLogger(t *testing.T) {
	orig := GetLogger()
	defer SetLogger(orig)
	var buf bytes.Buffer
	SetLogger(NewDefaultLogger(&buf, LogLevelInfo))
	std := StdLogger()
	if std == nil {
		t.Fatal("expected non-nil *log.Logger")
	}
	std.Print("via-std-logger")
	if !strings.Contains(buf.String(), "via-std-logger") {
		t.Errorf("expected std logger output, got: %s", buf.String())
	}
}

func TestLoggerWriter_Write(t *testing.T) {
	orig := GetLogger()
	defer SetLogger(orig)
	var buf bytes.Buffer
	SetLogger(NewDefaultLogger(&buf, LogLevelInfo))
	w := &loggerWriter{}
	n, err := w.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Errorf("expected n=5, got %d", n)
	}
	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("expected hello, got: %s", buf.String())
	}
}

// 确保 nop logger 不 panic 且不输出
func TestNopLogger(t *testing.T) {
	l := NewNopLogger()
	l.Debug("x")
	l.Info("x")
	l.Warn("x")
	l.Error("x")
	l.SetLevel(LogLevelOff)
}

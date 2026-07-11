package cpeskills

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

// LogLevel represents the severity of a log message.
type LogLevel int

const (
	// LogLevelDebug detailed debug information
	LogLevelDebug LogLevel = iota

	// LogLevelInfo informational messages
	LogLevelInfo

	// LogLevelWarn warning messages
	LogLevelWarn

	// LogLevelError error messages
	LogLevelError

	// LogLevelOff disables all logging
	LogLevelOff
)

// String returns the string representation of the log level.
func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	case LogLevelOff:
		return "OFF"
	default:
		return "UNKNOWN"
	}
}

// Logger is the interface for structured logging in the cpe-skills library.
//
// This is a minimal interface designed to be compatible with Go's log/slog
// while remaining free of external dependencies. Users can plug in their own
// logger implementation (slog, zap, zerolog, logrus, etc.) or use the
// built-in default logger.
//
// All methods are concurrency-safe when using the default implementations.
type Logger interface {
	// Debug logs a debug message with optional key-value pairs.
	Debug(msg string, keyvals ...interface{})

	// Info logs an informational message with optional key-value pairs.
	Info(msg string, keyvals ...interface{})

	// Warn logs a warning message with optional key-value pairs.
	Warn(msg string, keyvals ...interface{})

	// Error logs an error message with optional key-value pairs.
	Error(msg string, keyvals ...interface{})

	// With returns a Logger with the given key-value pairs pre-populated.
	With(keyvals ...interface{}) Logger

	// SetLevel sets the minimum log level.
	SetLevel(level LogLevel)
}

// DefaultLogger is a basic logger implementation that writes to an io.Writer.
//
// It provides structured key=value formatting out of the box.
type DefaultLogger struct {
	mu     sync.Mutex
	writer io.Writer
	level  LogLevel
	prefix []interface{}
}

// NewDefaultLogger creates a new DefaultLogger writing to the given writer.
//
// Example:
//
//	logger := cpe.NewDefaultLogger(os.Stderr, cpe.LogLevelInfo)
func NewDefaultLogger(writer io.Writer, level LogLevel) *DefaultLogger {
	if writer == nil {
		writer = os.Stderr
	}
	return &DefaultLogger{
		writer: writer,
		level:  level,
		prefix: make([]interface{}, 0),
	}
}

// NewNopLogger creates a logger that discards all output.
//
// This is the default logger used when no logger is configured.
func NewNopLogger() Logger {
	return &DefaultLogger{
		writer: io.Discard,
		level:  LogLevelOff,
	}
}

// Debug logs a debug message.
func (l *DefaultLogger) Debug(msg string, keyvals ...interface{}) {
	l.log(LogLevelDebug, msg, keyvals...)
}

// Info logs an informational message.
func (l *DefaultLogger) Info(msg string, keyvals ...interface{}) {
	l.log(LogLevelInfo, msg, keyvals...)
}

// Warn logs a warning message.
func (l *DefaultLogger) Warn(msg string, keyvals ...interface{}) {
	l.log(LogLevelWarn, msg, keyvals...)
}

// Error logs an error message.
func (l *DefaultLogger) Error(msg string, keyvals ...interface{}) {
	l.log(LogLevelError, msg, keyvals...)
}

// With returns a logger with additional pre-populated key-value pairs.
func (l *DefaultLogger) With(keyvals ...interface{}) Logger {
	newPrefix := make([]interface{}, len(l.prefix)+len(keyvals))
	copy(newPrefix, l.prefix)
	copy(newPrefix[len(l.prefix):], keyvals)
	return &DefaultLogger{
		writer: l.writer,
		level:  l.level,
		prefix: newPrefix,
	}
}

// SetLevel sets the minimum log level.
func (l *DefaultLogger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// log writes a log message.
func (l *DefaultLogger) log(level LogLevel, msg string, keyvals ...interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Build the log line
	line := fmt.Sprintf("[%s] %s", level.String(), msg)

	// Add prefix key-value pairs
	if len(l.prefix) > 0 {
		for i := 0; i < len(l.prefix); i += 2 {
			if i+1 < len(l.prefix) {
				line += fmt.Sprintf(" %v=%v", l.prefix[i], l.prefix[i+1])
			}
		}
	}

	// Add message key-value pairs
	for i := 0; i < len(keyvals); i += 2 {
		if i+1 < len(keyvals) {
			line += fmt.Sprintf(" %v=%v", keyvals[i], keyvals[i+1])
		} else {
			line += fmt.Sprintf(" %v=(MISSING)", keyvals[i])
		}
	}

	line += "\n"
	l.writer.Write([]byte(line))
}

// SLogAdapter adapts Go's standard library log/slog logger to the cpe Logger interface.
//
// This is available for projects using Go 1.21+.
// Since this library targets Go 1.18, build tags are used (slog_adapter_go121.go).
type SLogAdapter struct {
	level LogLevel
	// The slog adapter is conditionally compiled for Go 1.21+
}

// globalLogger is the package-level logger used by all library components.
var globalLogger Logger = NewNopLogger()

// SetLogger sets the global logger for the entire cpe-skills library.
//
// Call this early in your application's initialization to capture all
// library log output. Pass nil to disable logging.
//
// Example:
//
//	cpe.SetLogger(cpe.NewDefaultLogger(os.Stderr, cpe.LogLevelInfo))
func SetLogger(l Logger) {
	if l == nil {
		l = NewNopLogger()
	}
	globalLogger = l
}

// GetLogger returns the current global logger.
func GetLogger() Logger {
	return globalLogger
}

// LogDebug logs a debug message using the global logger.
func LogDebug(msg string, keyvals ...interface{}) {
	globalLogger.Debug(msg, keyvals...)
}

// LogInfo logs an informational message using the global logger.
func LogInfo(msg string, keyvals ...interface{}) {
	globalLogger.Info(msg, keyvals...)
}

// LogWarn logs a warning message using the global logger.
func LogWarn(msg string, keyvals ...interface{}) {
	globalLogger.Warn(msg, keyvals...)
}

// LogError logs an error message using the global logger.
func LogError(msg string, keyvals ...interface{}) {
	globalLogger.Error(msg, keyvals...)
}

// StdLogger returns a *log.Logger that writes through the global Logger.
//
// This is useful for passing to third-party libraries that expect a *log.Logger.
func StdLogger() *log.Logger {
	return log.New(&loggerWriter{}, "", 0)
}

// loggerWriter adapts Logger to io.Writer for use with the standard log package.
type loggerWriter struct{}

func (w *loggerWriter) Write(p []byte) (n int, err error) {
	globalLogger.Info(string(p))
	return len(p), nil
}

package logger

import (
	"log"
)

// A Logger is an interface through which logging for this application is done.
// It is compatible with testing.T.
type Logger interface {
	Log(...interface{})
	Logf(string, ...interface{})
}

// LogAdapter is a wrapper around log.Logger to make it possible to use it as a
// Logger implementation.
type LogAdapter struct {
	*log.Logger
}

// Log the given arguments.
func (l *LogAdapter) Log(args ...interface{}) {
	l.Print(args...)
}

// Logf logs the given arguments in a Printf-like way.
func (l *LogAdapter) Logf(format string, args ...interface{}) {
	l.Printf(format, args...)
}

// NewAdapter returns a Logger instance that writes to the given log.Logger
func NewAdapter(l *log.Logger) Logger {
	return &LogAdapter{Logger: l}
}

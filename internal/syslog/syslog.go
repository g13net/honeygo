package syslog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Category string
type Level string

const (
	CategorySystem    Category = "SYSTEM"
	CategoryService   Category = "SERVICE"
	CategoryIsolation Category = "ISOLATION"
	CategoryCSS       Category = "CSS"
	CategoryDB        Category = "DATABASE"
	CategoryAlert     Category = "ALERT"
	CategoryWebUI     Category = "WEBUI"
	CategoryMISP      Category = "MISP"
)

const (
	LevelInfo  Level = "INFO"
	LevelWarn  Level = "WARN"
	LevelError Level = "ERROR"
	LevelDebug Level = "DEBUG"
)

type Entry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Category  Category  `json:"category"`
	Level     Level     `json:"level"`
	Message   string    `json:"message"`
}

var (
	mu          sync.RWMutex
	entries     []Entry
	nextID      int64 = 1
	maxEntries        = 2000
	writers            []io.Writer
	fileWriter         io.WriteCloser
	logFilePath        string
	infoLoggingEnabled bool = false
)

// SetInfoLogging enables or disables live informational log output to UI writers
func SetInfoLogging(enabled bool) {
	mu.Lock()
	defer mu.Unlock()
	infoLoggingEnabled = enabled
}

// IsInfoLoggingEnabled returns whether live informational log output is enabled
func IsInfoLoggingEnabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return infoLoggingEnabled
}

// ToggleInfoLogging toggles the informational logging state and returns the new state
func ToggleInfoLogging() bool {
	mu.Lock()
	defer mu.Unlock()
	infoLoggingEnabled = !infoLoggingEnabled
	return infoLoggingEnabled
}

// InfoWriter wraps an io.Writer and suppresses output unless info logging is enabled
type InfoWriter struct {
	w io.Writer
}

// NewInfoWriter creates an InfoWriter wrapping w
func NewInfoWriter(w io.Writer) io.Writer {
	if w == nil {
		return nil
	}
	if iw, ok := w.(*InfoWriter); ok {
		return iw
	}
	return &InfoWriter{w: w}
}

func (iw *InfoWriter) Write(p []byte) (n int, err error) {
	if !IsInfoLoggingEnabled() {
		return len(p), nil
	}
	return iw.w.Write(p)
}

// Init initializes the persistent log file
func Init(filePath string) error {
	mu.Lock()
	defer mu.Unlock()

	if filePath == "" {
		filePath = "honeygo.log"
	}
	logFilePath = filePath

	if fileWriter != nil {
		_ = fileWriter.Close()
	}

	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", filePath, err)
	}
	fileWriter = f
	return nil
}

// AddWriter registers an active output writer (such as TUI console window)
func AddWriter(w io.Writer) {
	if w == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	writers = append(writers, w)
}

// ClearWriters removes all registered UI output writers
func ClearWriters() {
	mu.Lock()
	defer mu.Unlock()
	writers = nil
}

// Log records a structured entry by category and level, streaming to UI writers only when info logging is enabled
func Log(cat Category, lvl Level, format string, a ...interface{}) {
	logInternal(cat, lvl, false, format, a...)
}

// LogAlways records a structured entry and writes to UI writers unconditionally
func LogAlways(cat Category, lvl Level, format string, a ...interface{}) {
	logInternal(cat, lvl, true, format, a...)
}

func logInternal(cat Category, lvl Level, always bool, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	now := time.Now()

	mu.Lock()
	entry := Entry{
		ID:        nextID,
		Timestamp: now,
		Category:  cat,
		Level:     lvl,
		Message:   msg,
	}
	nextID++

	entries = append(entries, entry)
	if len(entries) > maxEntries {
		entries = entries[len(entries)-maxEntries:]
	}

	// Write to persistent log file
	if fileWriter != nil {
		line := fmt.Sprintf("[%s] [%s] [%s] %s\n", now.Format(time.RFC3339), cat, lvl, msg)
		_, _ = fileWriter.Write([]byte(line))
	}

	// Write to active UI writers only if enabled or unconditionally required
	if always || infoLoggingEnabled {
		for _, w := range writers {
			if w != nil {
				color := "white"
				switch lvl {
				case LevelWarn:
					color = "yellow"
				case LevelError:
					color = "red"
				case LevelDebug:
					color = "grey"
				default:
					switch cat {
					case CategorySystem:
						color = "cyan"
					case CategoryService:
						color = "green"
					case CategoryIsolation:
						color = "magenta"
					case CategoryCSS:
						color = "blue"
					case CategoryAlert:
						color = "orange"
					}
				}
				tviewFormatted := fmt.Sprintf("[%s][%s] [%s] [%s][white] %s\n", color, now.Format("15:04:05"), cat, lvl, msg)
				_, _ = fmt.Fprint(w, tviewFormatted)
			}
		}
	}
	mu.Unlock()
}

func Info(cat Category, format string, a ...interface{}) {
	Log(cat, LevelInfo, format, a...)
}

func InfoAlways(cat Category, format string, a ...interface{}) {
	LogAlways(cat, LevelInfo, format, a...)
}

func Warn(cat Category, format string, a ...interface{}) {
	Log(cat, LevelWarn, format, a...)
}

func Error(cat Category, format string, a ...interface{}) {
	Log(cat, LevelError, format, a...)
}

func Debug(cat Category, format string, a ...interface{}) {
	Log(cat, LevelDebug, format, a...)
}

// GetEntries returns log entries filtered by category, level, and limit
func GetEntries(categoryFilter string, levelFilter string, limit int) []Entry {
	mu.RLock()
	defer mu.RUnlock()

	catFilter := strings.ToUpper(strings.TrimSpace(categoryFilter))
	lvlFilter := strings.ToUpper(strings.TrimSpace(levelFilter))

	var result []Entry
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if catFilter != "" && catFilter != "ALL" && string(e.Category) != catFilter {
			continue
		}
		if lvlFilter != "" && lvlFilter != "ALL" && string(e.Level) != lvlFilter {
			continue
		}
		result = append(result, e)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

// Package audit provides an append-only JSONL audit logger with SHA-256 hash chain.
package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

	dirPerm  os.FileMode = 0o750
	filePerm os.FileMode = 0o640
)

// Logger is an append-only, tamper-evident JSONL audit logger.
type Logger struct {
	mu           sync.Mutex
	path         string
	maxSizeBytes int64
	file         *os.File
	seq          uint64
	prevHash     string
}

// New creates a Logger writing to path.
// Creates parent directories if needed.
// maxSizeBytes: rotate when file exceeds this size (0 = no rotation).
func New(path string, maxSizeBytes int64) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, fmt.Errorf("audit: mkdir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, filePerm)
	if err != nil {
		return nil, fmt.Errorf("audit: open: %w", err)
	}

	return &Logger{
		path:         path,
		maxSizeBytes: maxSizeBytes,
		file:         f,
		prevHash:     zeroHash,
	}, nil
}

// Log appends an AuditEvent to the JSONL file.
// Fills in: ts, seq, prev_hash, self_hash automatically.
// Thread-safe.
func (l *Logger) Log(event AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.rotateIfNeeded(); err != nil {
		return err
	}

	l.seq++
	event.TS = time.Now().UTC().Format(time.RFC3339Nano)
	event.Seq = l.seq
	event.PrevHash = l.prevHash
	event.SelfHash = "" // exclude from hash input

	// Marshal without self_hash to produce the hash input.
	intermediate, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}

	sum := sha256.Sum256(append([]byte(l.prevHash), intermediate...))
	selfHash := fmt.Sprintf("%x", sum)

	event.SelfHash = selfHash

	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("audit: marshal final: %w", err)
	}
	line = append(line, '\n')

	if _, err := l.file.Write(line); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}

	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("audit: sync: %w", err)
	}

	l.prevHash = selfHash
	return nil
}

// Close flushes and closes the logger.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// rotateIfNeeded renames the current file to path+".1" and opens a fresh file.
// Must be called with l.mu held.
func (l *Logger) rotateIfNeeded() error {
	if l.maxSizeBytes <= 0 {
		return nil
	}
	info, err := l.file.Stat()
	if err != nil {
		return fmt.Errorf("audit: stat: %w", err)
	}
	if info.Size() < l.maxSizeBytes {
		return nil
	}

	if err := l.file.Close(); err != nil {
		return fmt.Errorf("audit: close for rotate: %w", err)
	}

	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return fmt.Errorf("audit: rename for rotate: %w", err)
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_RDWR, filePerm)
	if err != nil {
		return fmt.Errorf("audit: open after rotate: %w", err)
	}
	l.file = f
	l.prevHash = zeroHash
	l.seq = 0
	return nil
}

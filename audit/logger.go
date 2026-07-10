package audit

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// errLoggerFailed is returned by Log when the logger holds no valid file
// descriptor — either it was closed, or a rotation failed and could not recover.
var errLoggerFailed = errors.New("audit: logger has no open file (closed or rotation failed)")

// maxRotationGenerations caps the search for a free numbered segment name so a
// directory already full of generations fails loudly instead of looping forever.
const maxRotationGenerations = 100000

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

// New opens (or creates) the JSONL audit log at path in append mode, creating
// parent directories as needed, and returns a Logger ready for concurrent use.
// maxSizeBytes rotates the file aside once it exceeds that size; 0 disables
// rotation. The hash chain always starts fresh from zeroHash — New does not
// read an existing file's last record, so appending to a pre-existing log
// with a different Logger instance starts a new, disconnected chain segment.
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

// Log appends event to the JSONL file as one record, filling in TS, Seq,
// PrevHash, and SelfHash — any caller-supplied values in those fields are
// overwritten. Rotates the current segment first if it has grown past
// maxSizeBytes. fsyncs before returning, so a successful return means the
// record is durable on disk, not just buffered. Safe for concurrent use.
func (l *Logger) Log(event AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return errLoggerFailed
	}

	if err := l.rotateIfNeeded(); err != nil {
		return err
	}
	// rotateIfNeeded may have left the logger without a usable descriptor if a
	// rotation failed to reopen; guard again before writing.
	if l.file == nil {
		return errLoggerFailed
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

// Close closes the underlying file. Subsequent Log calls return
// errLoggerFailed rather than reopening it — Close is a terminal operation.
// Safe to call once; a nil-file Logger (already closed) returns nil.
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

// rotateIfNeeded rotates the current segment aside and opens a fresh one when it
// has reached maxSizeBytes. Must be called with l.mu held.
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
	return l.rotate()
}

// rotate moves the current segment to the next free numbered generation and
// opens a fresh file. It deliberately preserves l.prevHash and l.seq so the
// tamper-evident hash chain and sequence numbers stay continuous across the
// rotation boundary. On any failure it leaves l.file either usable (recovered)
// or nil (explicitly failed) — never a closed descriptor. Must hold l.mu.
func (l *Logger) rotate() error {
	dest, err := nextRotationName(l.path)
	if err != nil {
		return fmt.Errorf("audit: rotate name: %w", err)
	}

	if err := l.file.Close(); err != nil {
		l.recoverFile() // reopen so the logger stays usable
		return fmt.Errorf("audit: close for rotate: %w", err)
	}

	// Move the just-closed segment aside. nextRotationName guarantees dest does
	// not exist, so an older generation is never overwritten.
	if err := os.Rename(l.path, dest); err != nil {
		l.recoverFile() // the source still exists — reopen and keep appending
		return fmt.Errorf("audit: rename for rotate: %w", err)
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_RDWR, filePerm)
	if err != nil {
		l.file = nil // no valid descriptor: logger is explicitly failed
		return fmt.Errorf("audit: open after rotate: %w", err)
	}
	l.file = f
	// NOTE: l.prevHash and l.seq are intentionally NOT reset here — resetting
	// them would break the hash chain link and restart seq at each rotation.
	return nil
}

// nextRotationName returns the lowest-numbered "path.N" (N ≥ 1) that does not yet
// exist, so rotation never overwrites an existing generation.
func nextRotationName(path string) (string, error) {
	for n := 1; n <= maxRotationGenerations; n++ {
		candidate := fmt.Sprintf("%s.%d", path, n)
		_, err := os.Stat(candidate)
		if os.IsNotExist(err) {
			return candidate, nil
		}
		if err != nil {
			return "", fmt.Errorf("stat %s: %w", candidate, err)
		}
	}
	return "", fmt.Errorf("no free rotation generation below %s.%d", path, maxRotationGenerations)
}

// recoverFile reopens l.path in append mode after a failed rotation so the logger
// is not left holding a closed descriptor. If reopen fails, l.file is set to nil
// and subsequent Log calls return errLoggerFailed instead of panicking.
func (l *Logger) recoverFile() {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_RDWR, filePerm)
	if err != nil {
		l.file = nil
		return
	}
	l.file = f
}

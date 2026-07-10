package audit

import (
	"path/filepath"
	"testing"
)

// BenchmarkLogger_Log measures the full hot path a caller pays per audit
// record: marshal, hash, marshal again, write, and fsync. The fsync is
// deliberate — Log's durability contract (a successful return means the
// record is on disk) is the whole point of an audit trail, so a benchmark
// that skipped it would misrepresent the real cost.
func BenchmarkLogger_Log(b *testing.B) {
	dir := b.TempDir()
	logger, err := New(filepath.Join(dir, "audit.jsonl"), 0)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	b.Cleanup(func() { _ = logger.Close() })

	event := AuditEvent{
		CallerID: "bench-caller",
		Tool:     "nmap",
		Target:   "scanme.nmap.org",
		Profile:  "default",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := logger.Log(event); err != nil {
			b.Fatalf("Log: %v", err)
		}
	}
}

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestLogger_RotationPreservesSegmentsAndChain forces two rotations and asserts:
//   - both rotated generations survive with DISTINCT names (the 2nd rotation must
//     not overwrite the 1st), and
//   - the SHA-256 hash chain and seq numbers stay continuous ACROSS the rotation
//     boundary (new segment's first prev_hash == prior segment's last self_hash).
//
// Finding #3: the old rotateIfNeeded renamed unconditionally to path+".1"
// (overwriting older segments) and reset prevHash=zero / seq=0, breaking the
// chain link and losing tamper-evident history.
func TestLogger_RotationPreservesSegmentsAndChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// Threshold below the size of a single event forces a rotation on every Log
	// after the first, so 3 events yield exactly 2 rotations (.1 and .2).
	l, err := New(path, 100)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const nEvents = 3
	for i := range nEvents {
		if err := l.Log(makeEvent("nmap", fmt.Sprintf("target-%d", i))); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	seg1 := path + ".1"
	seg2 := path + ".2"
	if _, err := os.Stat(seg1); err != nil {
		t.Fatalf("rotated segment %s missing: %v", seg1, err)
	}
	if _, err := os.Stat(seg2); err != nil {
		t.Fatalf("rotated segment %s missing — 2nd rotation overwrote the 1st: %v", seg2, err)
	}

	// Oldest → newest: .1, .2, then the current file.
	var all []AuditEvent
	for _, seg := range []string{seg1, seg2, path} {
		all = append(all, readEvents(t, seg)...)
	}
	if len(all) != nEvents {
		t.Fatalf("expected %d events across all segments, got %d", nEvents, len(all))
	}
	assertContinuousChain(t, all)
}

// TestLogger_LogAfterCloseErrors verifies that logging after Close returns an
// error rather than panicking on a nil descriptor — the guard that also protects
// the logger if a rotation ever fails to reopen (finding #3c).
func TestLogger_LogAfterCloseErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.Log(makeEvent("nmap", "target")); err == nil {
		t.Error("Log after Close must return an error, got nil")
	}
}

// assertContinuousChain verifies that seq is monotonic (1-based) and the
// prev_hash/self_hash chain links every event to its predecessor, seeded with
// zeroHash — including across rotation boundaries.
func assertContinuousChain(t *testing.T, events []AuditEvent) {
	t.Helper()
	prev := zeroHash
	for i, e := range events {
		wantSeq := uint64(i + 1)
		if e.Seq != wantSeq {
			t.Errorf("event %d: seq = %d, want %d (seq must be monotonic across rotation)", i, e.Seq, wantSeq)
		}
		if e.PrevHash != prev {
			t.Errorf("event %d: prev_hash = %q, want %q (chain must link across rotation)", i, e.PrevHash, prev)
		}
		if err := verifyHash(e); err != nil {
			t.Errorf("event %d: hash invalid: %v", i, err)
		}
		prev = e.SelfHash
	}
}

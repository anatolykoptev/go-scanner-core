package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func makeEvent(tool, target string) AuditEvent {
	return AuditEvent{
		CallerID: "test-caller",
		Tool:     tool,
		Target:   target,
	}
}

// verifyHash recomputes the self_hash for e and returns an error if it doesn't match.
func verifyHash(e AuditEvent) error {
	want := e.SelfHash
	e.SelfHash = ""
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(append([]byte(e.PrevHash), data...))
	got := fmt.Sprintf("%x", sum)
	if got != want {
		return fmt.Errorf("want %s, got %s", want, got)
	}
	return nil
}

func readEvents(t *testing.T, path string) []AuditEvent {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Errorf("close %s: %v", path, err)
		}
	})

	var events []AuditEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		events = append(events, e)
	}
	return events
}

func TestLogger_NewError(t *testing.T) {
	// Use a temp file itself as "directory" — MkdirAll will fail on Linux.
	f, err := os.CreateTemp(t.TempDir(), "notadir")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = New(filepath.Join(f.Name(), "audit.jsonl"), 0)
	if err == nil {
		t.Fatal("expected error when path parent is a file, got nil")
	}
}

func TestLogger_CloseIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestLogger_AppendsJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := l.Log(makeEvent("nmap", "192.168.1.1")); err != nil {
		t.Fatalf("Log 1: %v", err)
	}
	if err := l.Log(makeEvent("dns", "example.com")); err != nil {
		t.Fatalf("Log 2: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	events := readEvents(t, path)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Tool != "nmap" {
		t.Errorf("event[0].Tool = %q, want nmap", events[0].Tool)
	}
	if events[1].Tool != "dns" {
		t.Errorf("event[1].Tool = %q, want dns", events[1].Tool)
	}
	if events[0].Seq != 1 {
		t.Errorf("event[0].Seq = %d, want 1", events[0].Seq)
	}
	if events[1].Seq != 2 {
		t.Errorf("event[1].Seq = %d, want 2", events[1].Seq)
	}
}

func TestLogger_HashChainLinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := l.Log(makeEvent("tls", "target1")); err != nil {
		t.Fatalf("Log 1: %v", err)
	}
	if err := l.Log(makeEvent("http", "target2")); err != nil {
		t.Fatalf("Log 2: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	events := readEvents(t, path)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].PrevHash != zeroHash {
		t.Errorf("event[0].PrevHash = %q, want zero hash", events[0].PrevHash)
	}
	if events[1].PrevHash != events[0].SelfHash {
		t.Errorf("chain broken: event[1].PrevHash=%q != event[0].SelfHash=%q",
			events[1].PrevHash, events[0].SelfHash)
	}
	for i, e := range events {
		if err := verifyHash(e); err != nil {
			t.Errorf("event[%d] hash invalid: %v", i, err)
		}
	}
}

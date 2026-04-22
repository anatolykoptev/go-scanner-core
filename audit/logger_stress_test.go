package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLogger_RotatesAtSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path, 200)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const maxAttempts = 50
	for i := range maxAttempts {
		if err := l.Log(makeEvent("nmap", fmt.Sprintf("target-%d", i))); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
		if _, err := os.Stat(path + ".1"); err == nil {
			break
		}
		if i == maxAttempts-1 {
			t.Fatal("rotation never happened")
		}
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("rotated file %s.1 not found: %v", path, err)
	}
}

func TestLogger_ConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const goroutines = 10
	const eventsEach = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := range goroutines {
		go func(g int) {
			defer wg.Done()
			for i := range eventsEach {
				ev := makeEvent("http", fmt.Sprintf("g%d-target%d", g, i))
				if err := l.Log(ev); err != nil {
					t.Errorf("goroutine %d Log %d: %v", g, i, err)
				}
			}
		}(g)
	}
	wg.Wait()

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	events := readEvents(t, path)
	for i, e := range events {
		if e.SelfHash == "" {
			t.Errorf("event %d: empty self_hash", i+1)
		}
	}
	if len(events) != goroutines*eventsEach {
		t.Errorf("expected %d events, got %d", goroutines*eventsEach, len(events))
	}
}

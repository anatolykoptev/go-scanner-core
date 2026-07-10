package audit_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anatolykoptev/go-scanner-core/audit"
)

// ExampleLogger writes two chained records, then independently re-derives
// the hash chain from the JSONL file — the check a consumer runs to prove
// the log has not been tampered with. It does not trust Logger's internals:
// it recomputes self_hash from each record's bytes and confirms prev_hash
// links match, which is exactly what an edited, reordered, or truncated
// record would break.
func ExampleLogger() {
	dir, err := os.MkdirTemp("", "audit-example")
	if err != nil {
		fmt.Println("mkdirtemp error:", err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, "audit.jsonl")
	logger, err := audit.New(path, 0)
	if err != nil {
		fmt.Println("new error:", err)
		return
	}

	if err := logger.Log(audit.AuditEvent{Tool: "nmap", Target: "scanme.nmap.org"}); err != nil {
		fmt.Println("log error:", err)
		return
	}
	if err := logger.Log(audit.AuditEvent{Tool: "nuclei", Target: "scanme.nmap.org"}); err != nil {
		fmt.Println("log error:", err)
		return
	}
	if err := logger.Close(); err != nil {
		fmt.Println("close error:", err)
		return
	}

	intact, err := verifyChain(path)
	if err != nil {
		fmt.Println("verify error:", err)
		return
	}
	fmt.Println("chain intact:", intact)
	// Output: chain intact: true
}

// verifyChain re-derives each record's self_hash and confirms the prev_hash
// links form one unbroken chain — the same check any consumer of the JSONL
// file should run before trusting it.
func verifyChain(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read: %w", err)
	}

	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	wantPrevHash := "" // unset for record 0: trust its stated genesis prev_hash
	for i, line := range lines {
		var event audit.AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return false, fmt.Errorf("record %d: unmarshal: %w", i, err)
		}

		if i > 0 && event.PrevHash != wantPrevHash {
			return false, nil
		}

		gotSelfHash := event.SelfHash
		event.SelfHash = ""
		recomputable, err := json.Marshal(event)
		if err != nil {
			return false, fmt.Errorf("record %d: remarshal: %w", i, err)
		}
		sum := sha256.Sum256(append([]byte(event.PrevHash), recomputable...))
		if fmt.Sprintf("%x", sum) != gotSelfHash {
			return false, nil
		}

		wantPrevHash = gotSelfHash
	}
	return true, nil
}

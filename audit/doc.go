// Package audit provides a tamper-evident, append-only audit trail for scan
// operations: what target was scanned, by whom, under which authz decision,
// and what happened.
//
// Every record is a JSON line in an append-only file, chained by SHA-256: each
// record's self_hash covers its own content plus the previous record's
// self_hash ([AuditEvent.PrevHash]). Deleting, editing, or reordering any
// earlier line breaks every hash after it — the chain does not prevent
// tampering, but it makes tampering detectable by recomputing the chain
// end-to-end and comparing. [Logger.Log] fills ts/seq/prev_hash/self_hash
// automatically; the caller supplies everything else.
//
// [Logger] rotates a segment aside once it exceeds a configured size
// (numbered path.1, path.2, …) without resetting the sequence counter or the
// hash chain — a verifier reading segment N+1 must still start from segment
// N's last self_hash, not from the chain's genesis zero-hash.
//
// audit does not verify its own chain; that is a read-side concern for
// whatever consumes the JSONL (see [ExampleLogger] for the shape of a
// verifier).
package audit

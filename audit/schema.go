package audit

// AuditEvent is a single tamper-evident audit record written to the JSONL log.
// Fields ts, seq, prev_hash, and self_hash are filled automatically by Logger.Log.
//
//nolint:revive // AuditEvent name is required by the external API contract (Appendix C.4).
type AuditEvent struct {
	TS               string `json:"ts"`  // RFC3339Nano
	Seq              uint64 `json:"seq"` // monotonic, 1-based
	CallerID         string `json:"caller_id"`
	Tool             string `json:"tool"`   // nmap|nuclei|tls|dns|http|censorship
	Target           string `json:"target"` // raw input
	TargetResolvedIP string `json:"target_resolved_ip"`
	Profile          string `json:"profile"`
	ParamsHash       string `json:"params_hash"` // sha256 of canonicalized params
	ScopeRuleMatched string `json:"scope_rule_matched"`
	AuthzTokenID     string `json:"authz_token_id"`
	BytesSent        int64  `json:"bytes_sent"`
	BytesReceived    int64  `json:"bytes_received"`
	DurationMs       int64  `json:"duration_ms"`
	ExitCode         int    `json:"exit_code"`
	ResultDigest     string `json:"result_digest"` // sha256 of output
	PrevHash         string `json:"prev_hash"`     // previous record's self_hash
	SelfHash         string `json:"self_hash"`     // sha256(prev_hash || record_json)
}

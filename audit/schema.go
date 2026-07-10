package audit

// AuditEvent is a single tamper-evident audit record written to the JSONL log.
// Fields ts, seq, prev_hash, and self_hash are filled automatically by Logger.Log.
//
//nolint:revive // AuditEvent name is required by the external API contract (Appendix C.4).
type AuditEvent struct {
	TS               string `json:"ts"`                 // RFC3339Nano, set by Logger.Log
	Seq              uint64 `json:"seq"`                // monotonic, 1-based, set by Logger.Log
	CallerID         string `json:"caller_id"`          // identity that requested the operation
	Tool             string `json:"tool"`               // nmap|nuclei|tls|dns|http|censorship
	Target           string `json:"target"`             // raw input, pre-normalization
	TargetResolvedIP string `json:"target_resolved_ip"` // IP the target actually resolved to
	Profile          string `json:"profile"`            // tool-specific profile/tag/template selector
	ParamsHash       string `json:"params_hash"`        // sha256 of canonicalized params
	ScopeRuleMatched string `json:"scope_rule_matched"` // which allow/deny rule authorized this
	AuthzTokenID     string `json:"authz_token_id"`     // caller's authorization token, for correlation
	BytesSent        int64  `json:"bytes_sent"`         // outbound payload size
	BytesReceived    int64  `json:"bytes_received"`     // inbound payload size
	DurationMs       int64  `json:"duration_ms"`        // wall-clock operation time
	ExitCode         int    `json:"exit_code"`          // subprocess exit code, 0 for non-subprocess tools
	ResultDigest     string `json:"result_digest"`      // sha256 of output
	PrevHash         string `json:"prev_hash"`          // previous record's self_hash, set by Logger.Log
	SelfHash         string `json:"self_hash"`          // sha256(prev_hash || record_json), set by Logger.Log
}

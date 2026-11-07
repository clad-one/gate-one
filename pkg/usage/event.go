// Package usage defines the versioned usage-event contract shared by
// Gate One and out-of-process extension plugins. Events are flat,
// auditable records: no tokens, no cookies, no raw query strings and no
// direct PII (email/username). The user is represented by an opaque
// subjectId derived with HMAC.
package usage

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// SchemaVersion is bumped when the JSON shape changes incompatibly.
const SchemaVersion = 1

// SubjectIDVersion prefixes subject IDs so the secret/derivation can be
// rotated without ambiguity.
const SubjectIDVersion = "v1"

// EventType is the canonical event taxonomy.
type EventType string

const (
	TypeRequest EventType = "request"
	TypeAuth    EventType = "auth"
	TypeError   EventType = "error"
	TypeBilling EventType = "billing"
	TypeAudit   EventType = "audit"
)

// UnitType is the billable/metered unit.
type UnitType string

const (
	UnitRequest UnitType = "request"
	UnitToken   UnitType = "token"
	UnitByte    UnitType = "byte"
	UnitMCPCall UnitType = "mcp_call"
)

// Durability is the delivery contract for an event type.
type Durability string

const (
	// BestEffort is fire-and-forget: bounded ring, drops counted.
	BestEffort Durability = "best_effort"
	// Window commits in batches every N milliseconds; a crash may lose
	// the current window.
	Window Durability = "window_ms"
	// ZeroLoss fsyncs before the response: the event is durable when
	// the request completes.
	ZeroLoss Durability = "zero_loss"
)

// Event is the flat usage record emitted to subscribers.
type Event struct {
	SchemaVersion  int       `json:"schemaVersion"`
	Type           EventType `json:"type"`
	Timestamp      time.Time `json:"ts"`
	InstanceID     string    `json:"instanceId"`
	Epoch          string    `json:"epoch"`
	Tenant         string    `json:"tenant,omitempty"`
	SubjectID      string    `json:"subjectId,omitempty"`
	Route          string    `json:"route,omitempty"`
	Host           string    `json:"host,omitempty"`
	Method         string    `json:"method,omitempty"`
	Status         int       `json:"status,omitempty"`
	DurationMS     int64     `json:"durationMs,omitempty"`
	Bytes          int64     `json:"bytes,omitempty"`
	AuthResult     string    `json:"authResult,omitempty"`
	MCPTool        string    `json:"mcpTool,omitempty"`
	Action         string    `json:"action,omitempty"`
	Detail         string    `json:"detail,omitempty"`
	SessionID      string    `json:"sessionId,omitempty"`
	Units          int64     `json:"units,omitempty"`
	UnitType       UnitType  `json:"unitType,omitempty"`
	RequestID      string    `json:"requestId,omitempty"`
	IdempotencyKey string    `json:"idempotencyKey,omitempty"`
}

// SubjectID derives the opaque, deployment-scoped user identifier:
//
//	v1.<base64url(HMAC-SHA256(secret, issuer "\x00" sub))>
//
// The issuer is included so the same sub under two issuers yields two
// IDs. The NUL separator makes the input unambiguous. The secret is
// held only by the producer (Gate One/broker), never by a plugin.
func SubjectID(secret []byte, issuer, sub string) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("usage: empty subject secret")
	}
	issuer = strings.TrimSpace(issuer)
	sub = strings.TrimSpace(sub)
	if issuer == "" || sub == "" {
		return "", fmt.Errorf("usage: issuer and sub are required")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(issuer))
	mac.Write([]byte{0})
	mac.Write([]byte(sub))
	sum := mac.Sum(nil)
	return SubjectIDVersion + "." +
		base64.RawURLEncoding.EncodeToString(sum), nil
}

// ValidEventType reports whether t is part of the taxonomy.
func ValidEventType(t EventType) bool {
	switch t {
	case TypeRequest, TypeAuth, TypeError, TypeBilling, TypeAudit:
		return true
	}
	return false
}

// ValidUnitType reports whether u is a known unit.
func ValidUnitType(u UnitType) bool {
	switch u {
	case UnitRequest, UnitToken, UnitByte, UnitMCPCall:
		return true
	}
	return false
}

// ValidDurability reports whether d is a known delivery contract.
func ValidDurability(d Durability) bool {
	switch d {
	case BestEffort, Window, ZeroLoss:
		return true
	}
	return false
}

// Validate checks the invariants an emitted event must satisfy. It does
// not inspect free-text fields for PII (the producer must redact).
func (e *Event) Validate() error {
	if e == nil {
		return fmt.Errorf("usage: nil event")
	}
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("usage: schemaVersion %d, want %d",
			e.SchemaVersion, SchemaVersion)
	}
	if !ValidEventType(e.Type) {
		return fmt.Errorf("usage: unknown type %q", e.Type)
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("usage: timestamp is required")
	}
	if strings.TrimSpace(e.InstanceID) == "" {
		return fmt.Errorf("usage: instanceId is required")
	}
	if strings.TrimSpace(e.Epoch) == "" {
		return fmt.Errorf("usage: epoch is required")
	}
	if e.Status < 0 || e.Status > 599 {
		return fmt.Errorf("usage: status %d out of range", e.Status)
	}
	if e.DurationMS < 0 || e.Bytes < 0 || e.Units < 0 {
		return fmt.Errorf("usage: negative duration/bytes/units")
	}
	if e.UnitType != "" && !ValidUnitType(e.UnitType) {
		return fmt.Errorf("usage: unknown unitType %q", e.UnitType)
	}
	return nil
}

// NewRequestID returns an opaque correlation id for one request.
func NewRequestID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

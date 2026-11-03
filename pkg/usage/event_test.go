package usage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSubjectIDDeterministic(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	a, err := SubjectID(secret, "https://auth.example.com/realms/mycompany", "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SubjectID(secret, "https://auth.example.com/realms/mycompany", "sub-1")
	if a != b {
		t.Fatalf("not deterministic: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "v1.") {
		t.Fatalf("missing version prefix: %q", a)
	}
	if strings.Contains(a, "sub-1") {
		t.Fatal("raw sub leaked in the subject id")
	}
	otherIssuer, _ := SubjectID(secret, "https://other.example.com", "sub-1")
	otherSub, _ := SubjectID(secret, "https://auth.example.com/realms/mycompany", "sub-2")
	otherSecret, _ := SubjectID([]byte("fedcba9876543210fedcba9876543210"),
		"https://auth.example.com/realms/mycompany", "sub-1")
	if a == otherIssuer || a == otherSub || a == otherSecret {
		t.Fatal("subject id collisions across issuer/sub/secret")
	}
}

func TestSubjectIDRejectsEmpty(t *testing.T) {
	if _, err := SubjectID(nil, "iss", "sub"); err == nil {
		t.Fatal("empty secret accepted")
	}
	if _, err := SubjectID([]byte("k"), "", "sub"); err == nil {
		t.Fatal("empty issuer accepted")
	}
	if _, err := SubjectID([]byte("k"), "iss", ""); err == nil {
		t.Fatal("empty sub accepted")
	}
}

func validEvent() *Event {
	return &Event{
		SchemaVersion:  SchemaVersion,
		Type:           TypeRequest,
		Timestamp:      time.Now(),
		InstanceID:     "gw-1",
		Epoch:          "epoch-1",
		Tenant:         "mycompany",
		SubjectID:      "v1.abc",
		Route:          "/api/process_stream",
		Method:         "POST",
		Status:         200,
		DurationMS:     12,
		Bytes:          42,
		AuthResult:     "ok",
		Units:          1,
		UnitType:       UnitRequest,
		RequestID:      "req-1",
		IdempotencyKey: "idem-1",
	}
}

func TestEventValidate(t *testing.T) {
	if err := validEvent().Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*Event)
	}{
		{"schema", func(e *Event) { e.SchemaVersion = 99 }},
		{"type", func(e *Event) { e.Type = "nope" }},
		{"timestamp", func(e *Event) { e.Timestamp = time.Time{} }},
		{"instance", func(e *Event) { e.InstanceID = "" }},
		{"epoch", func(e *Event) { e.Epoch = "" }},
		{"status", func(e *Event) { e.Status = 900 }},
		{"duration", func(e *Event) { e.DurationMS = -1 }},
		{"bytes", func(e *Event) { e.Bytes = -1 }},
		{"units", func(e *Event) { e.Units = -1 }},
		{"unitType", func(e *Event) { e.UnitType = "nope" }},
	}
	for _, c := range cases {
		e := validEvent()
		c.mut(e)
		if err := e.Validate(); err == nil {
			t.Errorf("%s: invalid event accepted", c.name)
		}
	}
}

func TestEventJSONHasNoPII(t *testing.T) {
	raw, err := json.Marshal(validEvent())
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, forbidden := range []string{"email", "username", "cookie", "token", "password"} {
		if strings.Contains(strings.ToLower(s), forbidden) {
			t.Errorf("event JSON contains %q: %s", forbidden, s)
		}
	}
}

func TestDurabilityAndUnits(t *testing.T) {
	for _, d := range []Durability{BestEffort, Window, ZeroLoss} {
		if !ValidDurability(d) {
			t.Errorf("%q rejected", d)
		}
	}
	if ValidDurability("nope") {
		t.Error("unknown durability accepted")
	}
	for _, u := range []UnitType{UnitRequest, UnitToken, UnitByte, UnitMCPCall} {
		if !ValidUnitType(u) {
			t.Errorf("%q rejected", u)
		}
	}
	if ValidUnitType("nope") {
		t.Error("unknown unit accepted")
	}
}

func TestNewRequestID(t *testing.T) {
	a, b := NewRequestID(), NewRequestID()
	if a == "" || b == "" || a == b {
		t.Fatalf("request ids: %q / %q", a, b)
	}
}

package signing

import "testing"

func TestPayloadJCS(t *testing.T) {
	// Keys are sorted, whitespace removed, and the signature member is
	// dropped (RFC 8785).
	got, err := Payload([]byte(`{"b": 1, "signature": {"value": "x"}, "a": 2}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":2,"b":1}` {
		t.Fatalf("payload = %q", got)
	}
}

func TestPayloadBinding(t *testing.T) {
	got, err := Payload([]byte(`{"a":1}`), "sha256:abc")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{\"a\":1}\nsha256:abc" {
		t.Fatalf("payload = %q", got)
	}
}

func TestPayloadNumbersPreserved(t *testing.T) {
	got, err := Payload([]byte(`{"size": 10485760, "rate": 1}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"rate":1,"size":10485760}` {
		t.Fatalf("payload = %q", got)
	}
}

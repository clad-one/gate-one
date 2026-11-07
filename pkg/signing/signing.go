// Package signing defines the canonical payload used to sign Gate One
// documents (plugin manifests, publisher feeds).
//
// The payload is the RFC 8785 (JCS) canonical form of the document with
// the "signature" member removed, optionally followed by a newline and a
// binding string (a plugin manifest binds to its artefact digest; a
// publisher feed has no separate artefact). Any language with a JCS
// implementation can reproduce it.
package signing

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// Payload returns the bytes to sign for the JSON document doc.
func Payload(doc []byte, binding string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	delete(obj, "signature")
	stripped, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	canonical, err := jcs.Transform(stripped)
	if err != nil {
		return nil, fmt.Errorf("signing: canonicalize: %w", err)
	}
	if binding == "" {
		return canonical, nil
	}
	return append(canonical, []byte("\n"+binding)...), nil
}

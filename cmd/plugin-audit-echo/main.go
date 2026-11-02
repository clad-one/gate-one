// Command plugin-audit-echo is the reference out-of-process extension
// plugin: it validates the host's signed assertion, decodes a batch of
// usage events and logs them. It is deliberately dependency-free: no
// Gate One internals, only the public event contract and assertion
// helper.
//
//	export GATE_ONE_PLUGIN_SECRET=...
//	go run ./cmd/plugin-audit-echo -addr :9100
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"cladone/gate-one/internal/pluginhost"
	"cladone/gate-one/pkg/usage"
)

type envelope struct {
	Offset int64       `json:"offset"`
	Event  usage.Event `json:"event"`
}

func main() {
	addr := flag.String("addr", ":9100", "listen address")
	name := flag.String("name", "com.cladone.audit",
		"plugin name (must match the assertion audience)")
	secretEnv := flag.String("secret-env", "GATE_ONE_PLUGIN_SECRET",
		"environment variable holding the assertion HMAC secret")
	maxBody := flag.Int64("max-body-bytes", 8<<20, "maximum request body")
	flag.Parse()

	secret := []byte(os.Getenv(*secretEnv))
	if len(secret) == 0 {
		log.Fatalf("environment variable %s is empty", *secretEnv)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, *maxBody))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := pluginhost.VerifyAssertion(
			secret, r.Header.Get("X-Gate-One-Assertion"),
			*name, len(body), time.Now(),
		); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		var batch []envelope
		if err := json.Unmarshal(body, &batch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, e := range batch {
			log.Printf(
				"event type=%s tenant=%q route=%q method=%q status=%d "+
					"auth=%q units=%d/%s subject=%q request=%q",
				e.Event.Type, e.Event.Tenant, e.Event.Route,
				e.Event.Method, e.Event.Status, e.Event.AuthResult,
				e.Event.Units, e.Event.UnitType, e.Event.SubjectID,
				e.Event.RequestID)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	log.Printf("audit-echo plugin %s listening on %s", *name, *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

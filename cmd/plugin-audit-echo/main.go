// Command plugin-audit-echo is the reference out-of-process extension
// plugin: it validates the host's signed assertion, decodes a batch of
// usage events and logs them. It is deliberately dependency-free: no
// Gate One internals, only the public event contract and assertion
// helper.
//
// It also serves a tiny live viewer: the last N events (default 20) in a
// fixed-height window, streamed to the browser with Server-Sent Events.
// The viewer is for local demonstration only; the plugin itself is an
// internal-network service.
//
//	export GATE_ONE_PLUGIN_SECRET=...
//	go run ./cmd/plugin-audit-echo -addr :9100
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"cladone/gate-one/internal/pluginhost"
	"cladone/gate-one/pkg/usage"
)

type envelope struct {
	Offset int64       `json:"offset"`
	Event  usage.Event `json:"event"`
}

// viewer keeps the last N rendered lines and streams new ones to the
// connected browsers (Server-Sent Events). Only N lines are kept in
// memory: the view is a window, not a store.
type viewer struct {
	mu    sync.Mutex
	lines []string
	max   int
	subs  map[chan string]struct{}
}

func newViewer(max int) *viewer {
	return &viewer{max: max, subs: map[chan string]struct{}{}}
}

func (v *viewer) add(line string) {
	v.mu.Lock()
	v.lines = append(v.lines, line)
	if len(v.lines) > v.max {
		v.lines = v.lines[len(v.lines)-v.max:]
	}
	subs := make([]chan string, 0, len(v.subs))
	for ch := range v.subs {
		subs = append(subs, ch)
	}
	v.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- line:
		default: // slow browser: drop this line rather than block the plugin
		}
	}
}

func (v *viewer) snapshot() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.lines...)
}

func (v *viewer) subscribe() chan string {
	ch := make(chan string, v.max)
	v.mu.Lock()
	v.subs[ch] = struct{}{}
	v.mu.Unlock()
	return ch
}

func (v *viewer) unsubscribe(ch chan string) {
	v.mu.Lock()
	delete(v.subs, ch)
	v.mu.Unlock()
}

// renderLine is one compact, single-line rendering of an event.
func renderLine(e usage.Event) string {
	line := fmt.Sprintf("%s %-7s %-6s %3d %s",
		e.Timestamp.Format("15:04:05"), e.Type, e.Method, e.Status, e.Route)
	if e.Tenant != "" {
		line += " tenant=" + e.Tenant
	}
	if e.AuthResult != "" {
		line += " auth=" + e.AuthResult
	}
	if e.Action != "" {
		line += " action=" + e.Action
	}
	if e.DurationMS > 0 {
		line += fmt.Sprintf(" %dms", e.DurationMS)
	}
	return line
}

const viewerHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gate One — live events</title>
<style>
:root{color-scheme:dark}
body{margin:0;background:#0e1512;color:#c3d8cd;
     font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace}
header{padding:.6rem 1rem;border-bottom:1px solid #2c4038;color:#a3b8ae}
#log{margin:0;padding:.6rem 1rem;height:28em;overflow:auto;
     white-space:pre;line-height:1.4}
</style>
</head>
<body>
<header>Gate One — last 20 events (live)</header>
<pre id="log"></pre>
<script>
var log=document.getElementById('log'),MAX=20,lines=[];
function render(){log.textContent=lines.join('\n');log.scrollTop=log.scrollHeight;}
function push(t){lines.push(t);if(lines.length>MAX)lines.shift();render();}
var es=new EventSource('/stream');
es.onmessage=function(e){push(e.data);};
es.onerror=function(){/* EventSource reconnects automatically */};
</script>
</body>
</html>`

func main() {
	addr := flag.String("addr", ":9100", "listen address")
	name := flag.String("name", "com.cladone.audit",
		"plugin name (must match the assertion audience)")
	secretEnv := flag.String("secret-env", "GATE_ONE_PLUGIN_SECRET",
		"environment variable holding the assertion HMAC secret")
	maxBody := flag.Int64("max-body-bytes", 8<<20, "maximum request body")
	viewerLines := flag.Int("viewer-lines", 20,
		"number of events kept in the live viewer window")
	flag.Parse()

	secret := []byte(os.Getenv(*secretEnv))
	if len(secret) == 0 {
		log.Fatalf("environment variable %s is empty", *secretEnv)
	}

	view := newViewer(*viewerLines)

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
			view.add(renderLine(e.Event))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, viewerHTML)
	})
	mux.HandleFunc("/tail", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(view.snapshot())
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Connection", "keep-alive")
		for _, line := range view.snapshot() {
			fmt.Fprintf(w, "data: %s\n\n", line)
		}
		flusher.Flush()
		ch := view.subscribe()
		defer view.unsubscribe(ch)
		for {
			select {
			case <-r.Context().Done():
				return
			case line := <-ch:
				fmt.Fprintf(w, "data: %s\n\n", line)
				flusher.Flush()
			}
		}
	})

	log.Printf("audit-echo plugin %s listening on %s (viewer: last %d events)",
		*name, *addr, *viewerLines)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

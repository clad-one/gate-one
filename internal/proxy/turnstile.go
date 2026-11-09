package proxy

// Cloudflare Turnstile: platform-wide form bot check.
//
// Two halves, both driven by the same top-level "turnstile" block:
//
//   - injection: a small script is added before </body> on matching
//     HTML pages. It renders the widget in every matching form and
//     keeps a hidden cf-turnstile-response input in sync. It also
//     attaches the token to same-origin mutating fetch calls, so SPA
//     forms work without application code.
//   - verification: every matching request is checked with Siteverify
//     BEFORE the backend. A missing/invalid token is a 403 (readable
//     page for a navigation, JSON otherwise); a Siteverify outage is a
//     503 (fail closed, never "you are a bot").
//
// The token is read from ctx.RawBody (BuildContext already buffers and
// restores the request body), or from the configured header for
// fetch/SPA clients. The token is never logged.
//
// LIMITATION (documented): this protects only traffic that passes
// through this Gate One instance. A second ingress that reaches the
// application directly bypasses it; network isolation remains the
// operator's responsibility.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cladone/gate-one/internal/core"
)

const (
	turnstileSiteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	turnstileTimeout       = 5 * time.Second
	turnstileMaxTokenLen   = 2048
)

// turnstileRuntime is the gateway-wide verifier and script factory.
type turnstileRuntime struct {
	cfg      *core.TurnstileConfig
	client   *http.Client
	endpoint string
	script   string
}

func newTurnstileRuntime(cfg *core.Config) *turnstileRuntime {
	if cfg == nil || !cfg.Turnstile.Active() {
		return nil
	}
	rt := &turnstileRuntime{
		cfg:      cfg.Turnstile,
		client:   &http.Client{Timeout: turnstileTimeout},
		endpoint: turnstileSiteverifyURL,
	}
	if rt.cfg.Endpoint != "" {
		rt.endpoint = rt.cfg.Endpoint
	}
	rt.script = buildTurnstileScript(rt.cfg)
	log.Printf(
		"TURNSTILE enabled hosts=%v paths=%v methods=%v forms=%d action=%q",
		rt.cfg.Hosts,
		rt.cfg.Paths,
		rt.cfg.Methods,
		len(rt.cfg.Forms),
		rt.cfg.Action,
	)
	return rt
}

// injectsRoute: whether the script may be added to this route's HTML.
// Path filtering happens per request; this only skips routes that can
// never serve a protected page (avoids forcing gzip for nothing).
func (t *turnstileRuntime) injectsRoute(route *core.Route) bool {
	if t == nil || route == nil || !route.Frontend {
		return false
	}
	if !t.cfg.MatchesHost(route.Host) {
		return false
	}
	if len(t.cfg.Paths) == 0 {
		return true
	}
	for _, p := range t.cfg.Paths {
		if core.PathsOverlap(route.Path, p) {
			return true
		}
	}
	return false
}

// applies: whether the request must be verified.
func (t *turnstileRuntime) applies(
	host, path, method string,
) bool {
	if t == nil {
		return false
	}
	return t.cfg.MatchesHost(host) &&
		t.cfg.MatchesPath(path) &&
		t.cfg.MatchesMethod(method)
}

// enforce verifies the token. It answers and returns true when the
// request must be rejected.
func (t *turnstileRuntime) enforce(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
) bool {
	if t == nil || ctx == nil || !t.applies(ctx.Host, ctx.Path, ctx.Method) {
		return false
	}

	token, ok := turnstileToken(r, ctx, t.cfg.TokenHeaderName())
	if !ok {
		log.Printf(
			"TURNSTILE host=%s path=%q result=missing", ctx.Host, ctx.Path)
		writeTurnstileFailed(w, r, "")
		return true
	}

	result, err := t.verify(r, token)
	if err != nil {
		log.Printf(
			"TURNSTILE host=%s path=%q result=unavailable: %v",
			ctx.Host, ctx.Path, err)
		writeTurnstileUnavailable(w, r)
		return true
	}
	if !result.Success {
		log.Printf(
			"TURNSTILE host=%s path=%q result=failed codes=%v",
			ctx.Host, ctx.Path, result.ErrorCodes)
		writeTurnstileFailed(w, r, turnstileReason(result.ErrorCodes))
		return true
	}
	if t.cfg.Hostname != "" &&
		!strings.EqualFold(result.Hostname, t.cfg.Hostname) {
		log.Printf(
			"TURNSTILE host=%s path=%q result=hostname_mismatch got=%q want=%q",
			ctx.Host, ctx.Path, result.Hostname, t.cfg.Hostname)
		writeTurnstileFailed(w, r, "hostname")
		return true
	}
	if t.cfg.Action != "" && result.Action != t.cfg.Action {
		log.Printf(
			"TURNSTILE host=%s path=%q result=action_mismatch got=%q want=%q",
			ctx.Host, ctx.Path, result.Action, t.cfg.Action)
		writeTurnstileFailed(w, r, "action")
		return true
	}
	log.Printf("TURNSTILE host=%s path=%q result=ok", ctx.Host, ctx.Path)
	// The token is single-use and consumed: do not forward it to the
	// backend (the form field, when present, stays as the application
	// sent it; Gate One is the only verifier).
	r.Header.Del(t.cfg.TokenHeaderName())
	return false
}

type turnstileResult struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
}

// verify calls Siteverify. A transport error or a non-200 answer is an
// outage (503 for the client), never an invalid token: telling a human
// "you are a bot" because Cloudflare is down would be wrong.
func (t *turnstileRuntime) verify(
	r *http.Request,
	token string,
) (*turnstileResult, error) {
	form := url.Values{}
	form.Set("secret", t.cfg.Secret)
	form.Set("response", token)
	if ip := clientIP(r); ip != "" {
		form.Set("remoteip", ip)
	}

	req, err := http.NewRequestWithContext(
		r.Context(), http.MethodPost, t.endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("siteverify: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("siteverify: status %d", resp.StatusCode)
	}
	var out turnstileResult
	if err := json.NewDecoder(
		io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("siteverify: decode: %w", err)
	}
	return &out, nil
}

// turnstileToken extracts the token from the configured header, then
// from the buffered body (form-urlencoded, JSON or multipart).
func turnstileToken(
	r *http.Request,
	ctx *RequestContext,
	header string,
) (string, bool) {
	if v := strings.TrimSpace(r.Header.Get(header)); v != "" {
		return v, validTurnstileToken(v)
	}
	body := ctx.RawBody
	if len(body) == 0 {
		return "", false
	}
	ct := r.Header.Get("Content-Type")
	mediaType, params, _ := mime.ParseMediaType(ct)

	switch mediaType {
	case "application/x-www-form-urlencoded":
		q, err := url.ParseQuery(string(body))
		if err != nil {
			return "", false
		}
		v := strings.TrimSpace(q.Get(core.TurnstileFormField))
		return v, validTurnstileToken(v)

	case "application/json":
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			return "", false
		}
		for _, key := range []string{
			core.TurnstileFormField, "cfTurnstileResponse",
		} {
			if v, ok := m[key].(string); ok {
				v = strings.TrimSpace(v)
				if validTurnstileToken(v) {
					return v, true
				}
			}
		}
		return "", false

	case "multipart/form-data":
		boundary := params["boundary"]
		if boundary == "" {
			return "", false
		}
		mr := multipart.NewReader(bytes.NewReader(body), boundary)
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				return "", false
			}
			if err != nil {
				return "", false
			}
			if part.FormName() != core.TurnstileFormField {
				_ = part.Close()
				continue
			}
			data, _ := io.ReadAll(io.LimitReader(part, 4096))
			_ = part.Close()
			v := strings.TrimSpace(string(data))
			return v, validTurnstileToken(v)
		}
	}
	return "", false
}

// validTurnstileToken: a bounded, control-free string. The real
// validation is Siteverify; this only avoids sending garbage upstream.
func validTurnstileToken(v string) bool {
	if v == "" || len(v) > turnstileMaxTokenLen {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// turnstileReason maps the first error code to a stable, non-sensitive
// page/JSON reason.
func turnstileReason(codes []string) string {
	if len(codes) == 0 {
		return "invalid"
	}
	switch codes[0] {
	case "timeout-or-duplicate":
		return "expired"
	case "missing-input-response", "invalid-input-response":
		return "invalid"
	default:
		return "failed"
	}
}

// writeTurnstileFailed: the token was missing or rejected. A
// navigation gets a readable page (the form data cannot be replayed),
// a fetch gets JSON.
func writeTurnstileFailed(
	w http.ResponseWriter,
	r *http.Request,
	reason string,
) {
	w.Header().Set("Cache-Control", "no-store")
	if isDocumentNavigation(r) || isBrowserRequest(r) {
		back := turnstileBackURL(r)
		msg := "The anti-robot verification is missing or has expired."
		if reason == "expired" {
			msg = "The anti-robot verification has expired."
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, turnstilePage(
			"Verification required",
			msg,
			"Go back, complete the verification, then submit again.",
			back,
		))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w,
		`{"error":"turnstile_failed","error_description":`+
			`"anti-robot verification required"}`)
}

// writeTurnstileUnavailable: Siteverify is unreachable. Fail closed,
// but with a distinct 503 so a human is not told they failed.
func writeTurnstileUnavailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "5")
	if isDocumentNavigation(r) || isBrowserRequest(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, turnstilePage(
			"Verification service unavailable",
			"The anti-robot verification service cannot be reached right now.",
			"Retry in a moment; this is not a problem with your submission.",
			turnstileBackURL(r),
		))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(w,
		`{"error":"turnstile_unavailable",`+
			`"error_description":"the anti-robot verification service is unreachable"}`)
}

// turnstileBackURL: the form page the user came from (same host only),
// so the 403 page offers a safe way back.
func turnstileBackURL(r *http.Request) string {
	ref := r.Header.Get("Referer")
	if ref == "" {
		return "/"
	}
	u, err := url.Parse(ref)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") ||
		!strings.EqualFold(u.Host, r.Host) {
		return "/"
	}
	return ref
}

func turnstilePage(title, message, hint, back string) string {
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + html.EscapeString(title) + `</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;
font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;
background:#f4f5f7;color:#1c1f23}
main{max-width:560px;padding:28px;background:#fff;border:1px solid #e2e6ea;
border-radius:14px}
h1{font-size:20px;margin:0 0 8px}p{margin:0 0 10px;color:#5c6470}
a.btn{display:inline-block;margin-top:6px;padding:8px 14px;border-radius:8px;
background:#2563eb;color:#fff;text-decoration:none;font-weight:600}
</style></head><body><main>
<h1>` + html.EscapeString(title) + `</h1>
<p>` + html.EscapeString(message) + `</p>
<p>` + html.EscapeString(hint) + `</p>
<a class="btn" href="` + html.EscapeString(back) + `">Go back</a>
</main></body></html>`
}

// turnstileInjector inserts the widget script before </body> on
// matching pages (streaming, like the custom injector).
type turnstileInjector struct {
	cfg    *core.TurnstileConfig
	script string
}

func (i *turnstileInjector) name() string { return "turnstile" }

func (i *turnstileInjector) modify(resp *http.Response) error {
	if !isHTMLResponse(resp) {
		return nil
	}
	path := requestPathOut(resp.Request)
	if !i.cfg.MatchesPath(path) {
		return nil
	}
	resp.Body = newInjectStream(resp.Body, i.script, "body-end")
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
	resp.ContentLength = -1
	return nil
}

// turnstileScriptTmpl: the injected script. __CFG__ is replaced by the
// ASCII-safe JSON configuration (never user input).
const turnstileScriptTmpl = `<script>
(function () {
  var CFG = __CFG__;
  if (window.__gateOneTurnstile) return;
  window.__gateOneTurnstile = true;
  var SRC = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
  var token = "";
  var state = { loading: false, queue: [] };

  function syncToken(v) {
    token = String(v || "");
  }

  function load(cb) {
    if (window.turnstile) return cb();
    if (!state.loading) {
      state.loading = true;
      var s = document.createElement("script");
      s.src = SRC;
      s.async = true;
      s.defer = true;
      s.onload = function () {
        state.loading = false;
        var q = state.queue.splice(0, state.queue.length);
        for (var i = 0; i < q.length; i++) { try { q[i](); } catch (e) {} }
      };
      s.onerror = function () {
        state.loading = false;
        if (window.console) console.warn("turnstile: api.js failed to load");
      };
      (document.head || document.documentElement).appendChild(s);
      return;
    }
    state.queue.push(cb);
  }

  function isPost(form) {
    var m = (form.getAttribute("method") || "get").toLowerCase();
    return m === "post";
  }

  function targetForms() {
    var list;
    if (CFG.forms && CFG.forms.length) {
      try { list = document.querySelectorAll(CFG.forms.join(",")); }
      catch (e) { list = []; }
    } else {
      list = document.querySelectorAll("form");
    }
    var out = [];
    for (var i = 0; i < list.length; i++) {
      var f = list[i];
      if (f.getAttribute("data-gtw-turnstile") === "off") continue;
      if (f.querySelector("[data-gtw-turnstile-widget]")) continue;
      if (!isPost(f)) continue;
      out.push(f);
    }
    return out;
  }

  // Turnstile injects its own hidden cf-turnstile-response input when
  // the widget is inside a form; reuse it (one input only), or create
  // one when that injection did not happen.
  function inputFor(form) {
    var i = form.querySelector('input[name="cf-turnstile-response"]');
    if (!i) {
      i = document.createElement("input");
      i.type = "hidden";
      i.name = "cf-turnstile-response";
      i.value = "";
      form.appendChild(i);
    }
    return i;
  }

  function widget(form) {
    var box = document.createElement("div");
    box.setAttribute("data-gtw-turnstile-widget", "1");
    var submit = form.querySelector(
      'button[type=submit],input[type=submit],button:not([type])');
    if (submit && submit.parentNode === form) {
      form.insertBefore(box, submit);
    } else {
      form.appendChild(box);
    }
    var opts = {
      sitekey: CFG.siteKey,
      callback: function (t) {
        inputFor(form).value = t;
        syncToken(t);
        box.removeAttribute("aria-busy");
      },
      "expired-callback": function () {
        inputFor(form).value = "";
        syncToken("");
      },
      "error-callback": function () {
        inputFor(form).value = "";
        syncToken("");
        if (window.console) console.warn("turnstile: widget error");
      }
    };
    if (CFG.action) opts.action = CFG.action;
    try {
      window.turnstile.render(box, opts);
    } catch (e) {
      if (window.console) console.warn("turnstile: render failed", e);
    }
    form.addEventListener("submit", function (ev) {
      if (inputFor(form).value) return;
      // api.js never loaded: do not trap the form. The server answers
      // the readable 403 page instead of a dead button.
      if (!window.turnstile) return;
      ev.preventDefault();
      box.setAttribute("aria-busy", "true");
      try { box.scrollIntoView({ block: "center" }); } catch (e) {}
    });
  }

  function scan() {
    var forms = targetForms();
    if (!forms.length) return;
    load(function () {
      for (var i = 0; i < forms.length; i++) {
        try { widget(forms[i]); } catch (e) {}
      }
    });
  }

  // SPA/dynamic forms: re-scan (debounced) when the DOM changes.
  var pending = 0;
  function schedule() {
    if (pending) return;
    pending = setTimeout(function () { pending = 0; scan(); }, 250);
  }
  try {
    new MutationObserver(schedule).observe(document.documentElement, {
      childList: true, subtree: true
    });
  } catch (e) {}

  // Same-origin mutating fetches carry the token automatically: an SPA
  // form needs no application code. A request with its own header wins.
  var methods = CFG.methods || ["POST"];
  if (window.fetch) {
    var origFetch = window.fetch;
    window.fetch = function (input, init) {
      try {
        if (!token) return origFetch.apply(this, arguments);
        var method = String(
          (init && init.method) ||
          (input && input.method) ||
          "GET").toUpperCase();
        if (methods.indexOf(method) === -1) {
          return origFetch.apply(this, arguments);
        }
        var here = location.origin;
        if (input && input.url) {
          var u = new URL(input.url, location.href);
          if (u.origin !== here) return origFetch.apply(this, arguments);
          var h = new Headers(input.headers || {});
          if (!h.has(CFG.header)) h.set(CFG.header, token);
          return origFetch.call(this, new Request(input, { headers: h }), init);
        }
        var u2 = new URL(String(input), location.href);
        if (u2.origin !== here) return origFetch.apply(this, arguments);
        var h2 = new Headers((init && init.headers) || {});
        if (!h2.has(CFG.header)) h2.set(CFG.header, token);
        var ni = {};
        for (var k in (init || {})) { ni[k] = init[k]; }
        ni.headers = h2;
        return origFetch.call(this, input, ni);
      } catch (e) {
        return origFetch.apply(this, arguments);
      }
    };
  }

  scan();
})();
</script>`

// buildTurnstileScript returns the exact script injected into pages.
func buildTurnstileScript(cfg *core.TurnstileConfig) string {
	type scriptConfig struct {
		SiteKey string   `json:"siteKey"`
		Action  string   `json:"action,omitempty"`
		Forms   []string `json:"forms,omitempty"`
		Methods []string `json:"methods"`
		Header  string   `json:"header"`
	}
	forms := append([]string(nil), cfg.Forms...)
	methods := append([]string(nil), cfg.Methods...)
	if len(methods) == 0 {
		methods = []string{"POST"}
	}
	raw := core.AsciiJSON(scriptConfig{
		SiteKey: cfg.SiteKey,
		Action:  cfg.Action,
		Forms:   forms,
		Methods: methods,
		Header:  cfg.TokenHeaderName(),
	}, `{"siteKey":""}`)
	return strings.Replace(turnstileScriptTmpl, "__CFG__", raw, 1)
}

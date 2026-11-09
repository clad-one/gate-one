package proxy

// Cloudflare Turnstile: platform-wide bot protection for form pages
// and whole applications.
//
// Two complementary modes, selected by turnstile.mode:
//
//   - forms: a small script is injected into matching pages, renders
//     the widget in matching forms and every matching POST is verified
//     with Siteverify before the backend.
//   - gate: the first request to a protected path is answered with a
//     gateway-served challenge page (at the original URL, no redirect);
//     solving it sets a signed clearance cookie, and the following
//     requests go through without another Siteverify call. The injected
//     script also pre-clears in the background and exchanges a 403
//     "turnstile_required" for a clearance + replay.
//   - both: gate AND form verification.
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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cladone/gate-one/internal/core"
)

const (
	turnstileSiteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	turnstileTimeout       = 5 * time.Second
	turnstileMaxTokenLen   = 2048

	// TurnstileVerifyPath is the reserved endpoint that exchanges a
	// token for a clearance cookie. It is intercepted before routing.
	TurnstileVerifyPath = "/__gate-one/turnstile/verify"

	// TurnstileGateHeader marks a 403 that only asks for a challenge
	// (the request never reached the backend).
	TurnstileGateHeader = "X-Gate-One-Turnstile"
	turnstileGateValue  = "required"

	turnstileClearanceCookie = "gate_one_turnstile"
	turnstileVerifyLimit     = 30 // Siteverify calls per IP per minute
)

// turnstileRuntime is the gateway-wide verifier, gate and script
// factory.
type turnstileRuntime struct {
	cfg           *core.TurnstileConfig
	client        *http.Client
	endpoint      string
	script        string
	verifyLimiter *limiter
}

func newTurnstileRuntime(cfg *core.Config) *turnstileRuntime {
	if cfg == nil || !cfg.Turnstile.Active() {
		return nil
	}
	rt := &turnstileRuntime{
		cfg:           cfg.Turnstile,
		client:        &http.Client{Timeout: turnstileTimeout},
		endpoint:      turnstileSiteverifyURL,
		verifyLimiter: newLimiter(time.Minute),
	}
	if rt.cfg.Endpoint != "" {
		rt.endpoint = rt.cfg.Endpoint
	}
	rt.script = buildTurnstileScript(rt.cfg)
	log.Printf(
		"TURNSTILE enabled mode=%s hosts=%v paths=%v methods=%v "+
			"forms=%d exempt=%v action=%q clearance=%s",
		rt.cfg.Mode,
		rt.cfg.Hosts,
		rt.cfg.Paths,
		rt.cfg.Methods,
		len(rt.cfg.Forms),
		rt.cfg.ExemptPaths,
		rt.cfg.Action,
		rt.cfg.ClearanceTTL(),
	)
	return rt
}

// injectsRoute: whether the script may be added to this route's HTML.
// Gate mode injects on every frontend page of a matching host (the
// challenge may be triggered by an API call from any page); forms mode
// only on pages overlapping the configured paths.
func (t *turnstileRuntime) injectsRoute(route *core.Route) bool {
	if t == nil || route == nil || !route.Frontend {
		return false
	}
	if !t.cfg.MatchesHost(route.Host) {
		return false
	}
	if t.cfg.GateEnabled() {
		return true
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

// appliesTo: whether the forms verification covers this request.
func (t *turnstileRuntime) appliesTo(
	host, path, method string,
) bool {
	if t == nil || !t.cfg.FormsEnabled() {
		return false
	}
	return t.cfg.MatchesHost(host) &&
		t.cfg.MatchesPath(path) &&
		t.cfg.MatchesMethod(method)
}

// gateApplies: whether the request must carry a clearance.
func (t *turnstileRuntime) gateApplies(host, path string) bool {
	if t == nil || !t.cfg.GateEnabled() {
		return false
	}
	if !t.cfg.AppliesTo(host, path) {
		return false
	}
	return !t.cfg.Exempt(path)
}

// ── clearance cookie ────────────────────────────────────────────────

func (t *turnstileRuntime) clearanceValue(host string, exp int64) string {
	payload := "v1|" + core.NormalizeHostPattern(host) +
		"|" + strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, t.cfg.ClearanceSecret)
	mac.Write([]byte(payload))
	return "v1." + strconv.FormatInt(exp, 10) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (t *turnstileRuntime) validClearance(host, value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return false
	}
	want := t.clearanceValue(host, exp)
	return hmac.Equal([]byte(want), []byte(value))
}

// cleared: the request carries a valid clearance for host.
func (t *turnstileRuntime) cleared(r *http.Request, host string) bool {
	if t == nil || !t.cfg.GateEnabled() || r == nil {
		return true
	}
	c, err := r.Cookie(turnstileClearanceCookie)
	if err != nil || c == nil {
		return false
	}
	return t.validClearance(host, c.Value)
}

func (t *turnstileRuntime) setClearance(
	w http.ResponseWriter, r *http.Request, host string,
) {
	ttl := t.cfg.ClearanceTTL()
	exp := time.Now().Add(ttl).Unix()
	http.SetCookie(w, &http.Cookie{
		Name:     turnstileClearanceCookie,
		Value:    t.clearanceValue(host, exp),
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   clientScheme(r) == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

// ── gate enforcement ────────────────────────────────────────────────

// gate answers the request and returns true when the caller must stop.
func (t *turnstileRuntime) gate(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
) bool {
	if t == nil || ctx == nil ||
		!t.gateApplies(ctx.Host, ctx.Path) {
		return false
	}
	if r.Method == http.MethodOptions {
		return false
	}
	if t.cleared(r, ctx.Host) {
		return false
	}
	if isDocumentNavigation(r) &&
		(r.Method == http.MethodGet || r.Method == http.MethodHead) {
		t.serveChallenge(w, r, requestReturnTo(r), "")
		return true
	}
	if isDocumentNavigation(r) {
		// A form POST without clearance: serving the challenge here
		// would lose the submitted data. A readable 403 lets the user
		// go back and complete the verification.
		writeTurnstileRequired(w, r)
		return true
	}
	w.Header().Set(TurnstileGateHeader, turnstileGateValue)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w,
		`{"error":"turnstile_required",`+
			`"error_description":"complete the anti-robot verification"}`)
	return true
}

// requestReturnTo: the original path and query, for the challenge
// form. The value is validated again on the way back.
func requestReturnTo(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	p := r.URL.EscapedPath()
	if p == "" {
		p = "/"
	}
	if r.URL.RawQuery != "" {
		p += "?" + r.URL.RawQuery
	}
	return p
}

// safeReturnTo refuses anything that is not a local absolute path.
func safeReturnTo(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v[0] != '/' || strings.HasPrefix(v, "//") ||
		strings.ContainsAny(v, "\\\r\n") {
		return "/"
	}
	return v
}

// ── challenge page ──────────────────────────────────────────────────

func (t *turnstileRuntime) serveChallenge(
	w http.ResponseWriter,
	r *http.Request,
	returnTo, errMsg string,
) {
	nonce := newCSPNonce()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; "+
			"script-src 'nonce-"+nonce+"' https://challenges.cloudflare.com; "+
			"frame-src https://challenges.cloudflare.com; "+
			"style-src 'nonce-"+nonce+"'; img-src data:; "+
			"form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, t.challengeHTML(returnTo, nonce, errMsg))
}

func (t *turnstileRuntime) challengeHTML(
	returnTo, nonce, errMsg string,
) string {
	cfg := core.AsciiJSON(map[string]string{
		"siteKey":    t.cfg.SiteKey,
		"action":     t.cfg.Action,
		"appearance": t.cfg.ChallengeAppearance(),
	}, `{"siteKey":""}`)
	errBlock := ""
	if errMsg != "" {
		errBlock = `<p class="err">` + html.EscapeString(errMsg) + `</p>`
	}
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verification required</title>
<style nonce="` + nonce + `">
body{margin:0;min-height:100vh;display:grid;place-items:center;
font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;
background:#f4f5f7;color:#1c1f23}
main{max-width:560px;padding:28px;background:#fff;border:1px solid #e2e6ea;
border-radius:14px}
h1{font-size:20px;margin:0 0 8px}p{margin:0 0 10px;color:#5c6470}
p.err{color:#a33;font-weight:600}
#w{min-height:65px}
</style>
<script nonce="` + nonce + `" async defer
 src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"></script>
</head><body><main>
<h1>Checking your browser</h1>
<p id="msg">This page protects the application from automated abuse.
The check runs automatically; no account is created.</p>
` + errBlock + `
<form id="f" method="post" action="` + TurnstileVerifyPath + `">
<input type="hidden" name="returnTo" value="` + html.EscapeString(returnTo) + `">
<input type="hidden" name="` + core.TurnstileFormField + `" id="tok" value="">
<div id="w"></div>
</form>
<noscript><p class="err">JavaScript is required for the verification.</p></noscript>
</main>
<script nonce="` + nonce + `">
(function () {
  var CFG = ` + cfg + `;
  var form = document.getElementById("f");
  var tok = document.getElementById("tok");
  var msg = document.getElementById("msg");
  function submit(t) { tok.value = t; form.submit(); }
  function render() {
    if (!window.turnstile) { setTimeout(render, 200); return; }
    try {
      turnstile.render(document.getElementById("w"), {
        sitekey: CFG.siteKey,
        action: CFG.action || undefined,
        appearance: CFG.appearance || "interaction-only",
        callback: submit,
        "expired-callback": function () {
          tok.value = "";
          if (msg) msg.textContent = "The check expired, retrying…";
        },
        "error-callback": function () {
          if (msg) msg.textContent =
            "The verification could not run. Reload to retry.";
        }
      });
    } catch (e) {
      if (msg) msg.textContent = "The verification could not start. Reload to retry.";
    }
  }
  render();
})();
</script>
</body></html>`
}

// ── verify endpoint ─────────────────────────────────────────────────

// serveVerify handles POST /__gate-one/turnstile/verify: token ->
// Siteverify -> clearance cookie -> 303 (navigation) or 204 (fetch).
func (t *turnstileRuntime) serveVerify(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
) {
	if t == nil || ctx == nil || !t.cfg.GateEnabled() ||
		!t.cfg.MatchesHost(ctx.Host) {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ok, wait := t.verifyLimiter.allow(
		"verify|"+clientIP(r), turnstileVerifyLimit); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(
			int(wait.Seconds())+1))
		http.Error(w, "too many verifications", http.StatusTooManyRequests)
		return
	}

	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			http.Error(w, "cross-origin verification refused",
				http.StatusForbidden)
			return
		}
	}

	navigation := isDocumentNavigation(r) || isBrowserRequest(r)
	returnTo := safeReturnTo(r.FormValue("returnTo"))

	token, ok := turnstileToken(r, ctx, t.cfg.TokenHeaderName())
	if !ok {
		t.verifyFailed(w, r, navigation, returnTo, "Verification missing or invalid.")
		return
	}

	result, err := t.verify(r, token)
	if err != nil {
		log.Printf("TURNSTILE verify host=%s result=unavailable: %v",
			ctx.Host, err)
		if navigation {
			t.serveChallenge(w, r, returnTo,
				"The verification service is unavailable. Retry in a moment.")
			return
		}
		w.Header().Set("Retry-After", "5")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w,
			`{"error":"turnstile_unavailable"}`)
		return
	}
	if !result.Success {
		log.Printf("TURNSTILE verify host=%s result=failed codes=%v",
			ctx.Host, result.ErrorCodes)
		t.verifyFailed(w, r, navigation, returnTo,
			"Verification failed or expired. Retry.")
		return
	}
	if t.cfg.Hostname != "" &&
		!strings.EqualFold(result.Hostname, t.cfg.Hostname) {
		log.Printf(
			"TURNSTILE verify host=%s result=hostname_mismatch got=%q want=%q",
			ctx.Host, result.Hostname, t.cfg.Hostname)
		t.verifyFailed(w, r, navigation, returnTo, "Verification refused.")
		return
	}
	if t.cfg.Action != "" && result.Action != t.cfg.Action {
		log.Printf(
			"TURNSTILE verify host=%s result=action_mismatch got=%q want=%q",
			ctx.Host, result.Action, t.cfg.Action)
		t.verifyFailed(w, r, navigation, returnTo, "Verification refused.")
		return
	}

	t.setClearance(w, r, ctx.Host)
	log.Printf("TURNSTILE gate granted host=%s path=%q", ctx.Host, returnTo)
	if navigation {
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (t *turnstileRuntime) verifyFailed(
	w http.ResponseWriter, r *http.Request, navigation bool,
	returnTo, msg string,
) {
	if navigation {
		t.serveChallenge(w, r, returnTo, msg)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w,
		`{"error":"turnstile_failed",`+
			`"error_description":"anti-robot verification required"}`)
}

// ── forms enforcement ───────────────────────────────────────────────

// enforce verifies a form POST. It answers and returns true when the
// request must be rejected.
func (t *turnstileRuntime) enforce(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
) bool {
	if t == nil || ctx == nil ||
		!t.appliesTo(ctx.Host, ctx.Path, ctx.Method) {
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
			core.TurnstileFormField, "cfTurnstileResponse", "token",
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

// writeTurnstileRequired: a gated form POST without clearance.
func writeTurnstileRequired(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(TurnstileGateHeader, turnstileGateValue)
	if isDocumentNavigation(r) || isBrowserRequest(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, turnstilePage(
			"Verification required",
			"Your browser has not completed the anti-robot verification.",
			"Go back, reload the page, complete the check, then submit again.",
			turnstileBackURL(r),
		))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w,
		`{"error":"turnstile_required",`+
			`"error_description":"complete the anti-robot verification"}`)
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

// turnstileInjector inserts the widget/preclearance script before
// </body> (streaming, like the custom injector).
type turnstileInjector struct {
	rt *turnstileRuntime
}

func (i *turnstileInjector) name() string { return "turnstile" }

func (i *turnstileInjector) modify(resp *http.Response) error {
	if !isHTMLResponse(resp) {
		return nil
	}
	path := requestPathOut(resp.Request)
	cfg := i.rt.cfg
	if !cfg.GateEnabled() && !cfg.MatchesPath(path) {
		return nil
	}
	host := requestHostOut(resp.Request)
	cleared := i.rt.cleared(resp.Request, host)
	formsOnPage := cfg.FormsEnabled() && cfg.MatchesPath(path)
	script := i.rt.scriptFor(cleared, formsOnPage)
	resp.Body = newInjectStream(resp.Body, script, "body-end")
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
	resp.ContentLength = -1
	return nil
}

// scriptFor adds per-request attributes to the static script. Only the
// attributes change: the script bytes hashed by the CSP stay identical.
func (t *turnstileRuntime) scriptFor(cleared, forms bool) string {
	attrs := ` data-gtw-turnstile-cleared="` +
		strconv.FormatBool(cleared) + `"`
	if forms {
		attrs += ` data-gtw-turnstile-forms="true"`
	} else {
		attrs += ` data-gtw-turnstile-forms="false"`
	}
	return strings.Replace(t.script, "<script>", "<script"+attrs+">", 1)
}

// turnstileScriptTmpl: the injected script. __CFG__ is replaced by the
// ASCII-safe JSON configuration (never user input).
const turnstileScriptTmpl = `<script>
(function () {
  var CFG = __CFG__;
  if (window.__gateOneTurnstile) return;
  window.__gateOneTurnstile = true;
  var SRC = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
  var el = document.currentScript;
  var cleared = el && el.getAttribute("data-gtw-turnstile-cleared") === "true";
  var formsOnPage = el && el.getAttribute("data-gtw-turnstile-forms") === "true";
  var token = "";
  var state = { loading: false, queue: [] };
  var gateBox = null, gateWidget = null, gateQueue = [];

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
      s.nonce = el && el.nonce ? el.nonce : "";
      (document.head || document.documentElement).appendChild(s);
      return;
    }
    state.queue.push(cb);
  }

  // ── gate: pre-clearance and 403 recovery ──
  function gateBoxEl() {
    if (!gateBox) {
      gateBox = document.createElement("div");
      gateBox.className = "cladone-turnstile-gate";
      document.body.appendChild(gateBox);
    }
    return gateBox;
  }

  function exchange(tokenValue) {
    return fetch(CFG.verify, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json",
                 "Accept": "application/json" },
      body: JSON.stringify({ "cf-turnstile-response": tokenValue })
    }).then(function (res) {
      if (res.ok) { cleared = true; flushGate(); return true; }
      return false;
    }).catch(function () { return false; });
  }

  function flushGate() {
    var q = gateQueue.splice(0, gateQueue.length);
    for (var i = 0; i < q.length; i++) {
      try { q[i].resolve(); } catch (e) {}
    }
    if (gateBox) {
      gateBox.textContent = "";
      gateBox = null;
      gateWidget = null;
    }
  }

  function ensureGate() {
    if (cleared || gateWidget) return;
    load(function () {
      var box = gateBoxEl();
      try {
        gateWidget = window.turnstile.render(box, {
          sitekey: CFG.siteKey,
          action: CFG.action || undefined,
          appearance: CFG.appearance || "interaction-only",
          callback: function (t) { exchange(t); },
          "error-callback": function () { gateWidget = null; },
          "expired-callback": function () {}
        });
      } catch (e) {
        if (window.console) console.warn("turnstile: gate render failed", e);
      }
    });
  }

  // ── forms: widget injection ──
  function syncToken(v) { token = String(v || ""); }

  function isPost(form) {
    return (form.getAttribute("method") || "get").toLowerCase() === "post";
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
      if (!window.turnstile) return;
      ev.preventDefault();
      box.setAttribute("aria-busy", "true");
      try { box.scrollIntoView({ block: "center" }); } catch (e) {}
    });
  }

  function scan() {
    if (!formsOnPage || !CFG.formsEnabled) return;
    var forms = targetForms();
    if (!forms.length) return;
    load(function () {
      for (var i = 0; i < forms.length; i++) {
        try { widget(forms[i]); } catch (e) {}
      }
    });
  }

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

  // ── fetch: pre-clearance recovery and form token header ──
  var origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function (input, init) {
      var args = [input, init];
      var replayable = true;
      if (input && typeof input === "object" && input.clone) {
        try { input = input.clone(); args = [input, init]; }
        catch (e) { replayable = false; }
      }
      try {
        if (token) {
          var method = String(
            (init && init.method) || (input && input.method) || "GET").toUpperCase();
          if ((CFG.methods || ["POST"]).indexOf(method) !== -1) {
            var here = location.origin;
            if (input && input.url) {
              var u = new URL(input.url, location.href);
              if (u.origin === here) {
                var h = new Headers(input.headers || {});
                if (!h.has(CFG.header)) h.set(CFG.header, token);
                input = new Request(input, { headers: h });
                args = [input, init];
              }
            } else {
              var u2 = new URL(String(input), location.href);
              if (u2.origin === here) {
                var h2 = new Headers((init && init.headers) || {});
                if (!h2.has(CFG.header)) h2.set(CFG.header, token);
                var ni = {};
                for (var k in (init || {})) { ni[k] = init[k]; }
                ni.headers = h2;
                args = [input, ni];
              }
            }
          }
        }
      } catch (e) {}
      return origFetch.apply(this, args).then(function (res) {
        if (!CFG.gate || cleared || !replayable) return res;
        if (res.status !== 403 ||
            res.headers.get(CFG.gateHeader) !== "required") {
          return res;
        }
        return new Promise(function (resolve) {
          gateQueue.push({ resolve: function () {
            resolve(origFetch.apply(window, args));
          }});
          ensureGate();
        });
      });
    };
  }

  if (CFG.gate && CFG.preclearance && !cleared) {
    ensureGate();
  }
  scan();
})();
</script>`

// buildTurnstileScript returns the exact script injected into pages.
func buildTurnstileScript(cfg *core.TurnstileConfig) string {
	type scriptConfig struct {
		SiteKey      string   `json:"siteKey"`
		Action       string   `json:"action,omitempty"`
		Forms        []string `json:"forms,omitempty"`
		Methods      []string `json:"methods"`
		Header       string   `json:"header"`
		Gate         bool     `json:"gate"`
		FormsEnabled bool     `json:"formsEnabled"`
		Preclearance bool     `json:"preclearance"`
		Appearance   string   `json:"appearance,omitempty"`
		Verify       string   `json:"verify"`
		GateHeader   string   `json:"gateHeader"`
	}
	forms := append([]string(nil), cfg.Forms...)
	methods := append([]string(nil), cfg.Methods...)
	if len(methods) == 0 {
		methods = []string{"POST"}
	}
	raw := core.AsciiJSON(scriptConfig{
		SiteKey:      cfg.SiteKey,
		Action:       cfg.Action,
		Forms:        forms,
		Methods:      methods,
		Header:       cfg.TokenHeaderName(),
		Gate:         cfg.GateEnabled(),
		FormsEnabled: cfg.FormsEnabled(),
		Preclearance: cfg.PreclearanceEnabled(),
		Appearance:   cfg.ChallengeAppearance(),
		Verify:       TurnstileVerifyPath,
		GateHeader:   TurnstileGateHeader,
	}, `{"siteKey":""}`)
	return strings.Replace(turnstileScriptTmpl, "__CFG__", raw, 1)
}

// Turnstile injected-script suite: widget placement, token field,
// submit gating and the fetch header — against the script RENDERED
// from internal/proxy/turnstile.go (never a stale excerpt).
import { readFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { JSDOM } from "jsdom";

let failures = 0;
const ok = (label) => console.log("OK  " + label);
const fail = (m) => { console.error("FAIL " + m); failures++; };

const SRC = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..", "..", "internal", "proxy", "turnstile.go"
);

function renderTurnstile(cfg) {
  const go = readFileSync(SRC, "utf8");
  const m = go.match(
    /const turnstileScriptTmpl = `([\s\S]*?)`\n\n\/\/ buildTurnstileScript/
  );
  if (!m) throw new Error("turnstile script template not found");
  return m[1]
    .replace(/^<script>/, "")
    .replace(/<\/script>$/, "")
    .replace("__CFG__", JSON.stringify(cfg));
}

const html = `<!DOCTYPE html><html><body>
<form id="contact" method="post" action="/contact/send">
  <input name="message"><button type="submit">Send</button>
</form>
<form id="search" method="get"><input name="q"></form>
<form id="skip" method="post" data-gtw-turnstile="off">
  <button type="submit">Skip</button>
</form>
<form id="other" method="post"><button type="submit">Other</button></form>
</body></html>`;

function mkWindow(script) {
  const dom = new JSDOM(html, {
    url: "http://app.test/contact/",
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });
  const w = dom.window;
  const state = { rendered: [], fetched: null };
  w.turnstile = {
    render: (el, opts) => { state.rendered.push({ el, opts }); },
  };
  w.fetch = async (input, init) => {
    state.fetched = { input, init };
    return { ok: true };
  };
  w.eval(script);
  return { w, state };
}

// ── default scope: every POST form except the opt-out, no GET form ──
{
  const script = renderTurnstile({
    siteKey: "1x00000000000000000000AA",
    action: "contact",
    forms: [],
    methods: ["POST"],
    header: "X-Turnstile-Response",
  });
  const { w, state } = mkWindow(script);

  state.rendered.length === 2
    ? ok("turnstile: widget rendered in the two eligible POST forms")
    : fail(`turnstile: rendered ${state.rendered.length} widgets (want 2)`);
  !w.document.querySelector("#search [data-gtw-turnstile-widget]")
    ? ok("turnstile: GET form skipped")
    : fail("turnstile: widget injected into a GET form");
  !w.document.querySelector("#skip [data-gtw-turnstile-widget]")
    ? ok("turnstile: data-gtw-turnstile=off skipped")
    : fail("turnstile: opt-out form received a widget");
  state.rendered[0].opts.sitekey === "1x00000000000000000000AA" &&
  state.rendered[0].opts.action === "contact"
    ? ok("turnstile: site key and action passed to render()")
    : fail("turnstile: render options missing the site key/action");

  // No token yet: the submit is blocked (the widget is visible).
  let ev = new w.Event("submit", { bubbles: true, cancelable: true });
  w.document.querySelector("#contact").dispatchEvent(ev);
  ev.defaultPrevented
    ? ok("turnstile: submit blocked before the token")
    : fail("turnstile: submit allowed without a token");

  // Callback fills the hidden field; the submit is then native.
  state.rendered[0].opts.callback("tok-1");
  const input = w.document.querySelector(
    "#contact input[name=cf-turnstile-response]");
  input && input.value === "tok-1"
    ? ok("turnstile: callback fills cf-turnstile-response")
    : fail("turnstile: hidden token input not filled");
  ev = new w.Event("submit", { bubbles: true, cancelable: true });
  w.document.querySelector("#contact").dispatchEvent(ev);
  !ev.defaultPrevented
    ? ok("turnstile: submit allowed after the token")
    : fail("turnstile: submit still blocked after the token");

  // Same-origin mutating fetch carries the token.
  await w.fetch("http://app.test/contact/send", { method: "POST", headers: {} });
  state.fetched.init.headers.get("X-Turnstile-Response") === "tok-1"
    ? ok("turnstile: same-origin POST carries the token header")
    : fail("turnstile: token header missing on a same-origin POST");

  // Cross-origin: untouched.
  state.fetched = null;
  await w.fetch("http://other.test/x", { method: "POST" });
  !(state.fetched.init && state.fetched.init.headers &&
    state.fetched.init.headers.get("X-Turnstile-Response"))
    ? ok("turnstile: cross-origin request untouched")
    : fail("turnstile: token leaked to a cross-origin request");

  // Only one hidden input (Turnstile's own input is reused/created once).
  const inputs = w.document.querySelectorAll(
    "#contact input[name=cf-turnstile-response]");
  inputs.length === 1
    ? ok("turnstile: exactly one response input per form")
    : fail(`turnstile: ${inputs.length} response inputs in one form`);
}

// ── selector scope: only the configured form ──
{
  const script = renderTurnstile({
    siteKey: "k",
    forms: ["form#contact"],
    methods: ["POST"],
    header: "X-Turnstile-Response",
  });
  const { w, state } = mkWindow(script);
  state.rendered.length === 1
    ? ok("turnstile: form selector limits the widget")
    : fail(`turnstile: selector rendered ${state.rendered.length} widgets`);

  // An invalid selector is ignored, not thrown.
  const bad = renderTurnstile({
    siteKey: "k",
    forms: ["###"],
    methods: ["POST"],
    header: "X-Turnstile-Response",
  });
  try {
    mkWindow(bad);
    ok("turnstile: invalid selector is ignored");
  } catch (e) {
    fail(`turnstile: invalid selector threw (${e.message})`);
  }
}

// ── api.js failure: the form is not trapped forever ──
{
  const script = renderTurnstile({
    siteKey: "k",
    forms: ["form#contact"],
    methods: ["POST"],
    header: "X-Turnstile-Response",
  });
  const dom = new JSDOM(html, {
    url: "http://app.test/contact/",
    runScripts: "outside-only",
  });
  const w = dom.window;
  // no window.turnstile: the loader fails, the submit stays native
  w.eval(script);
  const ev = new w.Event("submit", { bubbles: true, cancelable: true });
  w.document.querySelector("#contact").dispatchEvent(ev);
  !ev.defaultPrevented
    ? ok("turnstile: api.js failure does not trap the form")
    : fail("turnstile: form trapped when api.js never loaded");
}

console.log(
  failures === 0 ? "TURNSTILE SCRIPT OK" : `TURNSTILE SCRIPT: ${failures} failure(s)`
);
globalThis.__uiFailures = (globalThis.__uiFailures || 0) + failures;

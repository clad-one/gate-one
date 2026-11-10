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
  const full = Object.assign({
    gate: false,
    formsEnabled: true,
    preclearance: false,
    appearance: "always",
    verify: "/__gate-one/turnstile/verify",
    gateHeader: "X-Gate-One-Turnstile",
    methods: ["POST"],
    header: "X-Turnstile-Response",
  }, cfg);
  return m[1]
    .replace(/^<script>/, "")
    .replace(/<\/script>$/, "")
    .replace("__CFG__", JSON.stringify(full));
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

function mkWindow(script, opts = {}) {
  const dom = new JSDOM(html, {
    url: opts.url || "http://app.test/contact/",
    runScripts: "dangerously",
    pretendToBeVisual: true,
  });
  const w = dom.window;
  const state = { rendered: [], fetched: null, calls: [] };
  w.turnstile = {
    render: (el, opts) => { state.rendered.push({ el, opts }); return state.rendered.length; },
  };
  w.fetch = async (input, init) => {
    state.fetched = { input, init };
    state.calls.push(String(input));
    if (opts.fetch) return opts.fetch(input, init);
    return { ok: true, status: 200, headers: { get: () => null } };
  };
  const s = w.document.createElement("script");
  s.setAttribute("data-gtw-turnstile-cleared", opts.cleared ? "true" : "false");
  s.setAttribute("data-gtw-turnstile-forms", opts.forms === false ? "false" : "true");
  s.textContent = script;
  w.document.body.appendChild(s);
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

// ── gate: pre-clearance at page load ──
{
  const script = renderTurnstile({
    siteKey: "k",
    forms: [],
    gate: true,
    formsEnabled: false,
    preclearance: true,
    appearance: "interaction-only",
  });
  let verified = false;
  const { w, state } = mkWindow(script, {
    cleared: false,
    forms: false,
    url: "http://app.test/app",
    fetch: async (input) => {
      if (String(input) === "/__gate-one/turnstile/verify") {
        verified = true;
        return { ok: true, status: 204, headers: { get: () => null } };
      }
      return { ok: true, status: 200, headers: { get: () => null } };
    },
  });
  state.rendered.length === 1
    ? ok("turnstile gate: preclearance widget rendered at page load")
    : fail(`turnstile gate: ${state.rendered.length} preclearance widgets`);
  const box = w.document.querySelector(".cladone-turnstile-gate");
  box
    ? ok("turnstile gate: fixed gate container present")
    : fail("turnstile gate: gate container missing");
  state.rendered[0].opts.appearance === "interaction-only"
    ? ok("turnstile gate: interaction-only appearance")
    : fail("turnstile gate: appearance not passed");
  state.rendered[0].opts.callback("gate-token");
  await new Promise((r) => setTimeout(r, 30));
  verified
    ? ok("turnstile gate: token exchanged for a clearance")
    : fail("turnstile gate: verify endpoint not called");
}

// ── gate: 403 turnstile_required is queued and replayed ──
{
  const script = renderTurnstile({
    siteKey: "k",
    forms: [],
    gate: true,
    formsEnabled: false,
    preclearance: false,
    appearance: "interaction-only",
  });
  let cleared = false;
  let apiCalls = 0;
  const { w, state } = mkWindow(script, {
    cleared: false,
    forms: false,
    url: "http://app.test/app",
    fetch: async (input) => {
      if (String(input) === "/__gate-one/turnstile/verify") {
        cleared = true;
        return { ok: true, status: 204, headers: { get: () => null } };
      }
      if (String(input) === "/api/process") {
        apiCalls++;
        if (!cleared) {
          return { status: 403, ok: false, headers: { get: (h) =>
            h === "X-Gate-One-Turnstile" ? "required" : null } };
        }
        return { status: 200, ok: true, headers: { get: () => null } };
      }
      return { status: 200, ok: true, headers: { get: () => null } };
    },
  });
  const pending = w.fetch("/api/process", { method: "POST", body: "{}" });
  await new Promise((r) => setTimeout(r, 30));
  state.rendered.length === 1
    ? ok("turnstile gate: 403 opens the challenge widget")
    : fail(`turnstile gate: no challenge for 403 (${state.rendered.length})`);
  state.rendered[0].opts.callback("gate-token");
  const res = await pending;
  res.status === 200
    ? ok("turnstile gate: request replayed after clearance")
    : fail(`turnstile gate: replay status ${res.status}`);
  apiCalls === 2
    ? ok("turnstile gate: backend path attempted exactly twice")
    : fail(`turnstile gate: api calls = ${apiCalls}`);
}

// ── gate: a stale "cleared" page recovers from a 403 ──
{
  const script = renderTurnstile({
    siteKey: "k",
    forms: [],
    gate: true,
    formsEnabled: false,
    preclearance: false,
    appearance: "interaction-only",
  });
  let verified = false;
  let apiCalls = 0;
  const { w, state } = mkWindow(script, {
    cleared: true, // page served with a clearance that has since expired
    forms: false,
    url: "http://app.test/app",
    fetch: async (input) => {
      if (String(input) === "/__gate-one/turnstile/verify") {
        verified = true;
        return { ok: true, status: 204, headers: { get: () => null } };
      }
      if (String(input) === "/api/process") {
        apiCalls++;
        if (!verified) {
          return { status: 403, ok: false, headers: { get: (h) =>
            h === "X-Gate-One-Turnstile" ? "required" : null } };
        }
        return { status: 200, ok: true, headers: { get: () => null } };
      }
      return { status: 200, ok: true, headers: { get: () => null } };
    },
  });
  const pending = w.fetch("/api/process", { method: "POST", body: "{}" });
  await new Promise((r) => setTimeout(r, 30));
  state.rendered.length === 1
    ? ok("turnstile gate: stale clearance triggers the widget")
    : fail("turnstile gate: stale clearance did not trigger the widget");
  state.rendered[0].opts.callback("gate-token");
  const res = await pending;
  res.status === 200 && verified && apiCalls === 2
    ? ok("turnstile gate: stale clearance re-verified and replayed")
    : fail(`turnstile gate: stale clearance (status ${res.status}, calls ${apiCalls})`);
}

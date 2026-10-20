// Behavioral harness of the guard script — WITHOUT a manually
// extracted file: the script is rendered from guard/guard.js.tmpl at
// every run (impossible to test something stale).
//
//   node run.mjs            → full matrix (guard rendered, neutral)
//   node run.mjs --served   → behavioral smoke against the DEPLOYED
//                             page (URL: GATEWAY_UI_URL or
//                             https://vers.cladone.com/)
import { readFileSync } from "fs";
import { JSDOM } from "jsdom";
import { fileURLToPath } from "url";
import path from "path";

const GUARD_TMPL = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..", "..", "internal", "proxy", "guard", "guard.js.tmpl"
);
const SERVED_URL = process.env.GATEWAY_UI_URL || "https://vers.cladone.com/";

// rendering of guardScript: the 6 Sprintf verbs (loginUrl, authState,
// uiGate[], userBadge, rewrite DTO, bundle patch[])
export function renderGuard(opts = {}) {
  const tmpl = readFileSync(GUARD_TMPL, "utf8");
  const loginUrl = opts.loginUrl || "https://login.cladone.com/login";
  const authState = opts.authState || "/__gate-one/auth";
  const uiGate = opts.uiGate || "[]";
  const userBadge = opts.userBadge || "null";
  const rewrite = opts.rewrite || "null";
  const patch = opts.patch || "[]";
  const rendered = tmpl
    .replace("%[1]s", loginUrl)
    .replace("%[2]s", authState)
    .replace("%[3]s", uiGate)
    .replace("%[4]s", userBadge)
    .replace("%[5]s", rewrite)
    .replace("%[6]s", patch);
  if (rendered.includes("%[")) {
    throw new Error("residual % verb in the rendered script");
  }
  return rendered
    .replace(/^<script>/, "")
    .replace(/\s*<\/script>\s*$/, "");
}

// extraction of the script injected into a SERVED page
export function extractGuardFromHtml(html) {
  const m = html.match(
    /<script>\s*\(function\(\)[\s\S]*?__cladoneAuthGuard[\s\S]*?<\/script>/
  );
  if (!m) throw new Error("guard missing from the served page");
  return m[0].replace(/^<script>/, "").replace(/<\/script>$/, "");
}

export const tick = (ms = 30) => new Promise(r => setTimeout(r, ms));

// test window: jsdom + shims (probe/requests fetch, counted
// window.open, captured message listeners)
export async function mkWindow(guard, html, sessionPayload, uiGate = "[]") {
  const dom = new JSDOM(html, {
    url: "https://vers.cladone.com/",
    runScripts: "outside-only",
  });
  const w = dom.window;
  const st = { openCalls: 0, lastTab: null, msgListeners: [], navs: [] };
  w.fetch = async (url) => {
    if (url === "/__gate-one/auth") {
      return sessionPayload
        ? new w.Response(JSON.stringify(sessionPayload), { status: 200 })
        : new w.Response('{"error":"authentication_required"}', { status: 401 });
    }
    return new w.Response('{"error":"authentication_required"}', { status: 401 });
  };
  w.Request = class extends Request {
    constructor(i, init) {
      if (typeof i === "string" && !i.startsWith("http")) {
        i = new URL(i, "https://vers.cladone.com").href;
      }
      super(i, init);
    }
  };
  w.Response = Response;
  w.open = () => {
    st.openCalls++;
    st.lastTab = { closed: false, focus() {}, close() { this.closed = true; } };
    return st.lastTab;
  };
  const oael = w.addEventListener.bind(w);
  w.addEventListener = (t, fn, o) => {
    if (t === "message") st.msgListeners.push(fn);
    return oael(t, fn, o);
  };
  // captures navigations (location.href) via the jsdom error
  w.__navCapture = st.navs;
  const patched = guard
    // the guard assigns location.href for logout: we log instead
    // (jsdom cannot navigate)
    .replace(
      /location\.href = LOGOUT_URL \+ "\?returnTo=" \+\s*encodeURIComponent\(location\.href\);/g,
      'console.log("NAV:" + LOGOUT_URL + "?returnTo=" + encodeURIComponent(location.href));'
    );
  w.console = { log: (...a) => { const s = a.join(" "); if (s.startsWith("NAV:")) st.navs.push(s.slice(4)); }, warn: () => {}, error: () => {} };
  // re-evaluates with the instrumented console
  const dom2 = { eval: (code) => w.eval(code) };
  dom2.eval(patched);
  // jsdom artifact: DOMContentLoaded does not fire in outside-only
  w.document.dispatchEvent(new w.Event("DOMContentLoaded", { bubbles: true }));
  await tick();
  return {
    w,
    doc: w.document,
    st,
    click: (el) =>
      el.dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true })),
    banner: () => w.document.body.textContent.includes("Sign-in required"),
  };
}

// Harnais comportemental du script de garde — SANS fichier extrait à
// la main : le script est rendu depuis guard.go à chaque exécution
// (impossible de tester du périmé).
//
//   node run.mjs            → matrice complète (garde rendue, neutre)
//   node run.mjs --served   → smoke comportemental contre la page
//                             DÉPLOYÉE (URL: GATEWAY_UI_URL ou
//                             https://vers.cladone.com/)
import { readFileSync } from "fs";
import { JSDOM } from "jsdom";
import { fileURLToPath } from "url";
import path from "path";

const GUARD_GO = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..", "..", "internal", "proxy", "guard.go"
);
const SERVED_URL = process.env.GATEWAY_UI_URL || "https://vers.cladone.com/";

// rendu du guardScript : les 4 verbes Sprintf (loginUrl, authState,
// uiGate[], userBadge)
export function renderGuard(opts = {}) {
  const src = readFileSync(GUARD_GO, "utf8");
  const m = src.match(/const guardScript = `([\s\S]*?)`/);
  if (!m) throw new Error("guardScript introuvable dans guard.go");
  const loginUrl = opts.loginUrl || "https://login.cladone.com/login";
  const authState = opts.authState || "/__gateway/auth";
  const uiGate = opts.uiGate || "[]";
  const userBadge = opts.userBadge || "null";
  const rendered = m[1]
    .replace("%[1]s", loginUrl)
    .replace("%[2]s", authState)
    .replace("%[3]s", uiGate)
    .replace("%[4]s", userBadge);
  if (rendered.includes("%")) {
    throw new Error("verbe % résiduel dans le script rendu");
  }
  return rendered
    .replace(/^<script>/, "")
    .replace(/<\/script>$/, "");
}

// extraction du script injecté dans une page SERVIE
export function extractGuardFromHtml(html) {
  const m = html.match(
    /<script>\s*\(function\(\)[\s\S]*?__cladoneAuthGuard[\s\S]*?<\/script>/
  );
  if (!m) throw new Error("garde absente de la page servie");
  return m[0].replace(/^<script>/, "").replace(/<\/script>$/, "");
}

export const tick = (ms = 30) => new Promise(r => setTimeout(r, ms));

// fenêtre de test : jsdom + shims (fetch sonde/requêtes, window.open
// compté, listeners message capturés)
export async function mkWindow(guard, html, sessionPayload, uiGate = "[]") {
  const dom = new JSDOM(html, {
    url: "https://vers.cladone.com/",
    runScripts: "outside-only",
  });
  const w = dom.window;
  const st = { openCalls: 0, lastTab: null, msgListeners: [], navs: [] };
  w.fetch = async (url) => {
    if (url === "/__gateway/auth") {
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
  // capte les navigations (location.href) via l'erreur jsdom
  w.__navCapture = st.navs;
  const patched = guard
    // le garde attribue location.href pour logout : on logue au lieu
    // (jsdom ne sait pas naviguer)
    .replace(
      /location\.href = LOGOUT_URL \+ "\?returnTo=" \+\s*encodeURIComponent\(location\.href\);/g,
      'console.log("NAV:" + LOGOUT_URL + "?returnTo=" + encodeURIComponent(location.href));'
    );
  w.console = { log: (...a) => { const s = a.join(" "); if (s.startsWith("NAV:")) st.navs.push(s.slice(4)); }, warn: () => {}, error: () => {} };
  // ré-évalue avec le console instrumenté
  const dom2 = { eval: (code) => w.eval(code) };
  dom2.eval(patched);
  // artefact jsdom : DOMContentLoaded ne feu pas en outside-only
  w.document.dispatchEvent(new w.Event("DOMContentLoaded", { bubbles: true }));
  await tick();
  return {
    w,
    doc: w.document,
    st,
    click: (el) =>
      el.dispatchEvent(new w.MouseEvent("click", { bubbles: true, cancelable: true })),
    banner: () => w.document.body.textContent.includes("Connexion requise"),
  };
}

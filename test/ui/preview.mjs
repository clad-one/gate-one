// Local visual preview of the guard against controls.html.
//
//   npm run preview          (default http://127.0.0.1:8787/)
//   PORT=9000 npm run preview
//
// The guard is rendered from guard.js.tmpl at startup (never a stale
// copy), injected into the fixture page, and the local server also
// provides a demo auth endpoint + login page:
//
//   GET /__gate-one/auth    401 anonymous / 200 demo session (cookie)
//   GET /__gate-one/preview/session?on=1|off=1
//                           set/clear the cookie, 204 (no redirect):
//                           authenticate, Reset demo session and
//                           the user-card logout refresh in place
//   GET /login              demo auth-bridge: sets the cookie, returns
//                           to the opener, posts "cladone-auth:ok"
//   GET /logout             clears the cookie and returns to /
//   GET /?authed=1          force the demo session (manual shortcut,
//                           reloads the page)
//
// The page itself is test/ui/controls.html; the behavioural assertions
// remain in controls.mjs (npm test). This server is only for seeing the
// controls and the login/gating flow in a real browser.
import { createServer } from "http";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";
import { renderGuard } from "./harness.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const CONTROLS = readFileSync(path.join(here, "controls.html"), "utf8");
const PORT = Number(process.env.PORT || 8787);
const LISTEN = process.env.HOST || "127.0.0.1";

const DEMO_SESSION = {
  roles: ["offline_access"],
  scopes: ["profile"],
  claims: {
    preferred_username: "demo",
    email: "demo@example.test",
    email_verified: true,
  },
};

const TOOLBAR = `
<div id="gtw-preview-bar" style="position:sticky;top:0;z-index:2147483000;display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:10px 23em 10px 14px;background:#20242e;color:#fff;font:14px/1.4 system-ui,sans-serif;border-bottom:1px solid #444">
  <strong>Gate One — controls preview</strong>
  <span id="gtw-preview-status" style="padding:2px 9px;border-radius:999px;background:#6b2f2f;color:#fff">…</span>
  <button type="button" id="gtw-preview-auth" style="border:0;border-radius:6px;padding:5px 10px;cursor:pointer;font:inherit;background:#2f6b45;color:#fff">Authenticate</button>
  <button type="button" id="gtw-preview-reset" style="border:0;border-radius:6px;padding:5px 10px;cursor:pointer;font:inherit;background:#4a4f5c;color:#fff">Reset demo session</button>
  <span style="opacity:.7">Gated control → login tab → “Sign in (demo)”. Badge top right: click the handle for compact, click again for extended.</span>
</div>`;

const APP = `<script>
(function () {
  var status = document.getElementById("gtw-preview-status");
  var reset = document.getElementById("gtw-preview-reset");
  var authBtn = document.getElementById("gtw-preview-auth");

  function refreshStatus() {
    if (!window.__cladoneAuth) return;
    window.__cladoneAuth.state().then(function (ok) {
      if (!status) return;
      status.textContent = ok ? "authenticated (demo)" : "anonymous";
      status.style.background = ok ? "#2f6b45" : "#6b2f2f";
    });
  }

  // Set/clear the demo cookie server-side, then re-probe the guard in
  // place: no redirect, no reload, scroll/focus preserved.
  function previewSession(on) {
    return fetch("/__gate-one/preview/session?" + (on ? "on=1" : "off=1"), {
      cache: "no-store"
    }).then(function () {
      return window.__cladoneAuth.refresh(
        on ? {} : { quiet: true, sessionDeath: false }
      );
    }).then(refreshStatus);
  }

  refreshStatus();
  new MutationObserver(refreshStatus).observe(document.documentElement, {
    attributes: true, attributeFilter: ["class"]
  });

  if (authBtn) authBtn.addEventListener("click", function () {
    previewSession(true);
  });
  if (reset) reset.addEventListener("click", function () {
    previewSession(false);
  });

  // Demo logout: clear the local cookie and refresh in place. The
  // production default (window.__cladoneAuth.logout) still navigates
  // to the OIDC end_session URL.
  if (window.__cladoneAuth) {
    window.__cladoneAuth.logout = function () {
      return previewSession(false);
    };
  }

  // The app side of the aria toggles: the guard lets this listener run
  // only when the click is an allowed activation/deactivation.
  ["aria-pressed", "aria-checked", "aria-expanded"].forEach(function (attr) {
    document.querySelectorAll("[" + attr + "]").forEach(function (el) {
      el.addEventListener("click", function () {
        el.setAttribute(attr, el.getAttribute(attr) === "true" ? "false" : "true");
      });
    });
  });
  var form = document.getElementById("form");
  if (form) form.addEventListener("submit", function (ev) {
    ev.preventDefault(); // demo: never navigate away
    console.log("preview: form submit prevented (demo)");
  });
})();
</script>`;

function validHost(h) {
  return typeof h === "string" &&
    /^(127\.0\.0\.1|localhost):[0-9]+$/.test(h);
}

function page(req) {
  const host = validHost(req.headers.host) ? req.headers.host : LISTEN + ":" + PORT;
  const base = "http://" + host;
  const guard = renderGuard({
    loginUrl: base + "/login",
    userBadge: JSON.stringify({
      position: "right",
      claims: ["preferred_username", "email", "email_verified"],
      roles: true,
      scopes: true,
      logoutLabel: "Log out (demo)",
      loginBadge: true,
    }),
  });
  let html = CONTROLS;
  html = html.replace(/<body([^>]*)>/, function (m, attrs) {
    return "<body" + attrs + ">" + TOOLBAR;
  });
  html = html.replace("</body>",
    "<script>\n" + guard + "\n</script>\n" + APP + "\n</body>");
  return html;
}

function loginPage() {
  return `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Gate One — demo login</title></head>
<body style="font:16px/1.5 system-ui,sans-serif;max-width:40em;margin:4em auto;padding:0 1em">
<h1>Gate One — demo login</h1>
<p>This local page simulates the auth-bridge. It sets a demo session
cookie and returns to the opener.</p>
<button id="go" style="font:inherit;padding:.6em 1.2em;border:0;border-radius:6px;background:#4a7c59;color:#fff;cursor:pointer">Sign in (demo)</button>
<p id="hint" style="opacity:.7"></p>
<script>
document.getElementById("go").onclick = function () {
  document.cookie = "preview_authed=1; Path=/; SameSite=Lax";
  var q = new URLSearchParams(location.search);
  var ret = q.get("returnTo");
  location.href = ret || "/";
};
if (!window.opener) {
  document.getElementById("hint").textContent =
    "Opened directly: the demo session is set and you return to the page.";
}
</script>
</body></html>`;
}

function donePage() {
  return `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Gate One — demo login done</title></head>
<body style="font:16px/1.5 system-ui,sans-serif;max-width:40em;margin:4em auto;padding:0 1em">
<h1>Authenticated (demo)</h1>
<p>This tab can close.</p>
<script>
var q = new URLSearchParams(location.search);
var origin = q.get("origin");
if (window.opener && origin) {
  try { window.opener.postMessage("cladone-auth:ok", origin); } catch (e) {}
}
setTimeout(function () { window.close(); }, 400);
</script>
</body></html>`;
}

function sendHtml(res, body) {
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function sendJson(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(body));
}

function setAuthed(res) {
  res.setHeader("Set-Cookie", "preview_authed=1; Path=/; SameSite=Lax");
}
function clearAuthed(res) {
  res.setHeader("Set-Cookie", "preview_authed=; Max-Age=0; Path=/; SameSite=Lax");
}

const server = createServer(function (req, res) {
  const url = new URL(req.url, "http://" + (req.headers.host || LISTEN + ":" + PORT));
  const authed = /(?:^|;\s*)preview_authed=1(?:;|$)/.test(req.headers.cookie || "");

  if (url.pathname === "/__gate-one/preview/session") {
    // No redirect: the preview changes the demo session in place and
    // calls window.__cladoneAuth.refresh().
    if (url.searchParams.get("on") === "1") setAuthed(res);
    else if (url.searchParams.get("off") === "1") clearAuthed(res);
    res.writeHead(204, { "Cache-Control": "no-store" });
    res.end();
    return;
  }
  if (url.pathname === "/__gate-one/auth") {
    if (authed) sendJson(res, 200, DEMO_SESSION);
    else sendJson(res, 401, { error: "authentication_required" });
    return;
  }
  if (url.pathname === "/login") {
    sendHtml(res, loginPage());
    return;
  }
  if (url.pathname === "/auth/popup-done") {
    sendHtml(res, donePage());
    return;
  }
  if (url.pathname === "/logout") {
    clearAuthed(res);
    res.writeHead(302, { Location: "/" });
    res.end();
    return;
  }
  if (url.pathname === "/favicon.ico") {
    res.writeHead(204);
    res.end();
    return;
  }
  if (url.pathname === "/" || url.pathname === "/index.html") {
    if (url.searchParams.get("authed") === "1") {
      setAuthed(res);
      res.writeHead(302, { Location: "/" });
      res.end();
      return;
    }
    if (url.searchParams.get("anon") === "1") {
      clearAuthed(res);
      res.writeHead(302, { Location: "/" });
      res.end();
      return;
    }
    sendHtml(res, page(req));
    return;
  }
  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("not found\n");
});

server.listen(PORT, LISTEN, function () {
  console.log("Gate One controls preview: http://" + LISTEN + ":" + PORT + "/");
  console.log("Click a gated control → login tab → “Sign in (demo)”.");
  console.log("Force authenticated / Reset demo session / user-card logout are in place (no reload).");
  console.log("Manual shortcuts: /?authed=1 (reload), /logout.");
});

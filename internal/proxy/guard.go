package proxy

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strconv"

	"cladone/gateway/internal/core"
)

// LoginPageURL is the public auth-bridge login page. Shared by the
// server-side redirect for page routes (proxy.go) and the injected
// 401/403 guard script (this file).
const LoginPageURL = "https://login.cladone.com/login"

// AuthStatePath is the gateway-served session probe: 204 when the
// caller holds a valid session (Bearer header or cookies), 401
// otherwise. Never proxied. Consumed by the injected guard script
// for the declarative [data-cladone-auth] gating. MUST match the
// path hardcoded in guardScript below.
const AuthStatePath = "/__gateway/auth"

// guardScript is injected into HTML responses of frontend routes. It
// wraps window.fetch so that a 401/403 answer (session expired, the
// gateway answers JSON 401 on API routes) triggers a login flow that
// does NOT reload the application:
//
//   - every fetch is cloned before being sent (a Request body can
//     only be read once), keeping a replayable copy ;
//   - on 401/403 the failed request is queued and a DISMISSABLE
//     banner ("Se connecter" / ×) is shown: mid-flow 401s never open
//     a tab automatically (a background 401 must not steal focus).
//     The tab opens only on an explicit click: a
//     data-cladone-auth="login" element (locked padlock) or the
//     banner button. Dismissing resolves the pending requests with
//     their original 401 response (the app continues anonymously,
//     retryable later) and login() promises resolve false ;
//   - when the tab opens from the banner button, the click is a
//     genuine user gesture, so no popup-blocker issue ; if the tab
//     were opened programmatically on a stale activation, the
//     banner is the reliable path. No code in the app ;
//   - auth-bridge /auth/popup-done (same origin as the login page)
//     postMessages "cladone-auth:ok" to this page and closes the
//     tab. Queued requests are replayed and the ORIGINAL fetch
//     promises resolve with the replayed responses: the application
//     code never sees the authentication happen ;
//   - if the tab is closed without completing (user, blocker), the
//     banner reappears — still dismissable: abandoning must never
//     lock the user out of the page ;
//   - the banner is closable without any login action: ×, click
//     anywhere outside it, or Escape. Closing it closes the linked
//     login tab (if open) at the same time, resolves pending
//     requests with their original 401 and login() with false ;
//   - fallback to the historical full-page redirect when the request
//     cannot be cloned (streaming bodies) or window.open is
//     unavailable.
//
// Declarative gating (opt-in, zero app code): pages may mark elements
// with data-cladone-auth — hidden while anonymous, shown once the
// session is active — and data-cladone-auth="login" — shown while
// anonymous, click opens the login tab, hidden once authed. The
// attribute is the only tab trigger: while anonymous, any other
// click inside a <label> holding a gated control (padding, unmarked
// element) shows the banner and neutralizes the click (label
// activation would otherwise silently toggle the display:none
// control). Pages using no attribute
// make no probe request and stay fully transparent (auth handled
// mid-flow by the wrapper, with the banner as login affordance).
//
// Notes:
//   - only fetch() calls are wrapped; document navigations are already
//     redirected server-side for page routes
//   - answers from the login page itself are ignored (no redirect loop)
//   - window.__cladoneAuth.login() exposes the same flow to apps that
//     want to trigger authentication from their own UI (opt-in; the
//     zero-code-change contract holds for everyone else)
const guardScript = `<script>
(function(){
  if (window.__cladoneAuthGuard) return;
  window.__cladoneAuthGuard = true;

  var LOGIN = "%[1]s";
  var AUTH_STATE = "%[2]s";
  var LOGIN_ORIGIN = "";
  try { LOGIN_ORIGIN = new URL(LOGIN).origin; } catch (e) {}

  // auth-bridge end page: notifies this page via postMessage then
  // closes the tab.
  var DONE_URL = LOGIN_ORIGIN + "/auth/popup-done?origin=" +
    encodeURIComponent(location.origin);

  var orig = window.fetch;
  if (!orig) return;

  // Requests waiting for replay after login. Each entry carries a
  // Request cloned BEFORE the initial call (a body is single-read)
  // plus the resolve/reject of the promise handed to the app.
  var queue = [];
  var loginTab = null;
  var banner = null;
  var watching = false;

  function buildReplay(input, init) {
    try {
      if (input instanceof Request) return input.clone();
      return new Request(input, init);
    } catch (e) {
      return null; // non-replayable body (stream, ...)
    }
  }

  function fullRedirect() {
    hideBanner();
    location.href = LOGIN + "?returnTo=" +
      encodeURIComponent(location.href);
  }

  function tabUrl() {
    return LOGIN + "?returnTo=" + encodeURIComponent(DONE_URL);
  }

  function tryOpenTab() {
    try {
      // No features argument: opens a regular tab, which renders
      // better than a popup inside installed PWAs.
      var w = window.open(tabUrl(), "cladone_login");
      if (w) { try { w.focus(); } catch (e) {} }
      return w;
    } catch (e) {
      return null;
    }
  }

  function showBanner() {
    if (banner || !document.body) return;
    banner = document.createElement("div");
    banner.style.cssText =
      "position:fixed;left:0;right:0;bottom:20px;margin:0 auto;" +
      "width:fit-content;z-index:2147483647;display:flex;gap:12px;" +
      "align-items:center;background:#20242e;color:#fff;" +
      "padding:10px 14px;border-radius:10px;" +
      "box-shadow:0 8px 30px rgba(0,0,0,0.35);" +
      "font:14px/1.4 system-ui,sans-serif";
    var msg = document.createElement("span");
    msg.textContent = "Connexion requise pour continuer.";
    var btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "Se connecter";
    btn.style.cssText =
      "border:0;border-radius:6px;padding:6px 14px;cursor:pointer;" +
      "font:inherit;color:#fff;background:#4a7c59";
    btn.onclick = function () {
      hideBanner();
      ensureLogin(); // user gesture: the tab opens reliably
    };
    banner.appendChild(msg);
    banner.appendChild(btn);
    var no = document.createElement("button");
    no.type = "button";
    no.title = "Fermer";
    no.textContent = "×";
    no.style.cssText =
      "border:0;background:transparent;color:#aab;cursor:pointer;" +
      "font:20px/1 system-ui,sans-serif;padding:0 2px";
    no.onclick = dismiss;
    banner.appendChild(no);
    document.body.appendChild(banner);
  }

  function hideBanner() {
    if (banner) { banner.remove(); banner = null; }
  }

  // Abandon (×, clic hors bannière, Échap) : les requêtes en attente
  // reçoivent leur réponse 401 d'origine (l'application continue en
  // anonyme, retentable plus tard), les promesses login() résolvent
  // false, et l'onglet de login lié — s'il est ouvert — se referme en
  // même temps. Rester bloqué derrière une bannière indémissible est
  // une impasse UX.
  function dismiss() {
    hideBanner();
    if (loginTab && !loginTab.closed) loginTab.close();
    loginTab = null;
    var pending = queue.splice(0, queue.length);
    pending.forEach(function (entry) {
      if (entry.barrier) { entry.resolve(false); return; }
      entry.resolve(entry.res401);
    });
  }

  function ensureLogin() {
    if (LOGIN_ORIGIN === "") { fullRedirect(); return; }
    if (loginTab && !loginTab.closed) {
      try { loginTab.focus(); } catch (e) {}
      return;
    }
    hideBanner();
    loginTab = tryOpenTab();
    if (!loginTab) showBanner(); // blocker: banner click will open it
    watchTab();
  }

  // If the tab is closed without a success message (user, blocker),
  // show the banner again: requests stay pending, the page is kept
  // alive (same contract as the historical never-resolving promise).
  function watchTab() {
    if (watching) return;
    watching = true;
    var iv = setInterval(function () {
      if (loginTab && !loginTab.closed) return;
      clearInterval(iv);
      watching = false;
      loginTab = null;
      if (queue.length > 0) showBanner();
    }, 400);
  }

  function flushQueue() {
    var pending = queue.splice(0, queue.length);
    pending.forEach(function (entry) {
      if (entry.barrier) { entry.resolve(true); return; }
      orig(entry.req).then(entry.resolve, entry.reject);
    });
  }

  window.addEventListener("message", function (ev) {
    if (ev.origin !== LOGIN_ORIGIN) return;
    if (ev.data !== "cladone-auth:ok") return;
    if (loginTab && !loginTab.closed) loginTab.close();
    loginTab = null;
    hideBanner();
    settleState(true);
    flushQueue();
  });

  // == Declarative gating: [data-cladone-auth] ========================
  //   bare attribute (any value but "login"): hidden while anonymous,
  //     shown once the session is active ;
  //   data-cladone-auth="login": shown while anonymous, click opens
  //     the login tab ; hidden once authed.
  // Zero app code: applications DECLARE gated elements, the gateway
  // toggles them. Applications using no attribute are fully
  // transparent: authentication happens mid-flow through the fetch
  // wrapper above, nothing is hidden.
  var authed = false;
  var probeDone = false;
  var stateWaiters = [];

  function settleState(v) {
    // Une session acquise (login réussi, message popup-done) ne doit
    // jamais être rétrogradée par une réponse de sonde arrivant en
    // retard (connexion lente) : l'état ne descend pas de true à false.
    if (authed && !v) return;
    probeDone = true;
    authed = v;
    if (v) {
      document.documentElement.classList.add("cladone-authed");
    }
    var waiters = stateWaiters.splice(0, stateWaiters.length);
    waiters.forEach(function (r) { r(v); });
  }

  try {
    var css = document.createElement("style");
    css.textContent =
      "html:not(.cladone-authed) [data-cladone-auth]" +
      "{display:none !important}" +
      "html.cladone-authed [data-cladone-auth='login']" +
      "{display:none !important}" +
      "[data-cladone-auth='login']{cursor:pointer}";
    (document.head || document.documentElement).appendChild(css);
  } catch (e) { /* never break the page over gating */ }

  // Session probe (Bearer header or cookie session), gateway-served,
  // never cached by the PWA service worker ("auth" exclude pattern).
  // AUTH_STATE is injected from AuthStatePath (guard.go). Runs at
  // DOMContentLoaded so pages without any gated element make no
  // request at all.
  function probeSession() {
    if (!document.querySelector("[data-cladone-auth]")) {
      return; // no gating declared: no probe, fully transparent
    }
    orig(AUTH_STATE, { cache: "no-store" }).then(function (res) {
      settleState(res.status === 204);
    }).catch(function () {
      settleState(false); // offline / SW error: stay anonymous
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", probeSession);
  } else {
    probeSession();
  }

  // Click handling while anonymous (capture phase, so the app never
  // sees these clicks). The ATTRIBUTE is the only tab trigger:
  //   - click on a data-cladone-auth="login" element → login tab
  //     opens directly (explicit affordance) ;
  //   - click anywhere else inside a <label> holding a gated control
  //     (padding, unmarked lock…) → BANNER only: label activation
  //     would otherwise silently toggle the display:none control, so
  //     the default is neutralized and the banner offers "Se
  //     connecter" — same rule as every non-affordance element.
  document.addEventListener("click", function (ev) {
    if (authed) return;
    var t = ev.target;
    if (!t || !t.closest) return;
    var el = t.closest("[data-cladone-auth='login']");
    if (el) {
      ev.preventDefault();
      ev.stopPropagation();
      window.__cladoneAuth.login();
      return;
    }
    var lbl = t.closest("label");
    if (!lbl || !lbl.querySelector("[data-cladone-auth]")) return;
    ev.preventDefault();
    ev.stopPropagation();
    showBanner();
  }, true);

  // La bannière se referme sans action d'authentification : clic
  // n'importe où en dehors d'elle, ou Échap — et l'onglet de login
  // lié se ferme avec elle (cf. dismiss). Enregistrés APRÈS le
  // handler d'affordance ci-dessus : un clic sur un élément de
  // login (ou sur un bouton de la bannière) gagne toujours.
  document.addEventListener("click", function (ev) {
    if (banner && !banner.contains(ev.target)) dismiss();
  }, true);

  document.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape" && banner) dismiss();
  }, true);

  // Opt-in API for apps willing to trigger the same no-reload login
  // from their own UI, or to know the session state. login() opens
  // the tab directly (explicit user intent) and resolves true once
  // the gateway session is active, false if abandoned (×). state()
  // resolves to the current session state (probe result).
  window.__cladoneAuth = {
    login: function () {
      return new Promise(function (resolve, reject) {
        queue.push({ barrier: true, resolve: resolve, reject: reject });
        ensureLogin();
      });
    },
    state: function () {
      return new Promise(function (resolve) {
        if (probeDone) { resolve(authed); return; }
        stateWaiters.push(resolve);
      });
    }
  };

  window.fetch = function (input, init) {

    // Clone BEFORE the call: a Request body can be read only once,
    // the copy is kept for the post-login replay.
    var replay = buildReplay(input, init);

    return orig.apply(this, arguments).then(function (res) {

      if (!res ||
          (res.status !== 401 && res.status !== 403) ||
          res.url.startsWith(LOGIN)) {
        return res;
      }

      if (!replay || LOGIN_ORIGIN === "") {
        // Cannot replay: historical fallback, full-page redirect
        // (the app reloads and re-issues the request itself).
        setTimeout(fullRedirect, 0);
        return new Promise(function () {}); // navigation takes over
      }

      return new Promise(function (resolve, reject) {
        // 401 en flux (clic hors affordance de login) : bannière
        // ONLY — jamais d'onglet en ouverture automatique, un 401
        // de fond ne doit pas voler le focus. L'onglet ne s'ouvre
        // que sur un clic explicite (cadenas, bouton de la
        // bannière). Bannière refermable (×) : les requêtes
        // repartent avec leur 401 d'origine, l'app continue.
        queue.push({ req: replay, res401: res, resolve: resolve, reject: reject });
        showBanner();
      });
    });
  };
})();
</script>`

var headOpen = regexp.MustCompile(`(?i)<head[^>]*>`)

// maxGuardBody bounds the HTML body read during injection (1 MiB is
// far above the current frontend pages; larger pages skip injection).
const maxGuardBody = 1 << 20

// guardEnabledFor resolves the route's authGuard policy: active by
// default on frontend routes, opt-out via {"enabled": false}, no-op on
// non-frontend routes.
func guardEnabledFor(route *core.Route) bool {
	if route.Frontend != true {
		return false
	}
	if route.AuthGuard == nil {
		return true
	}
	if route.AuthGuard.Enabled != nil {
		return *route.AuthGuard.Enabled
	}
	return true
}

// guardLoginURL returns the login URL configured for the guard, if any.
func guardLoginURL(route *core.Route) string {
	if route.AuthGuard != nil && route.AuthGuard.LoginURL != "" {
		return route.AuthGuard.LoginURL
	}
	return LoginPageURL
}

// injectGuardScript inserts the guard <script> right after the opening
// <head> tag (or at the very start when no <head> is found) and fixes
// Content-Length. The response body must already be uncompressed.
func injectGuardScript(resp *http.Response, script string) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGuardBody))
	closeErr := resp.Body.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}

	var out []byte
	if idx := headOpen.FindIndex(body); idx != nil {
		out = append(out, body[:idx[1]]...)
		out = append(out, []byte(script)...)
		out = append(out, body[idx[1]:]...)
	} else {
		out = append([]byte(script), body...)
	}

	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(out)), 10))
	// The body was re-serialized by the transport if it was
	// compressed; make sure no stale encoding header survives.
	resp.Header.Del("Content-Encoding")
	return nil
}

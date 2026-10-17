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
// 401 guard script (this file).
const LoginPageURL = "https://login.cladone.com/login"

// AuthStatePath is the gateway-served session probe: 200 + JSON
// {roles, scopes, claims} when the caller holds a valid session
// (Bearer header or cookies), 401 otherwise. Never proxied. Consumed
// by the injected guard script for the declarative [data-gtw-auth] /
// [data-gtw-auth-hidden] / [data-gtw-roles] / [data-gtw-scopes] /
// [data-gtw-claims] gating. MUST match the path hardcoded in
// guardScript below.
const AuthStatePath = "/__gateway/auth"

// guardScript is injected into HTML responses of frontend routes. It
// wraps window.fetch so that a 401 answer (session expired or
// identity conditions not met, the gateway answers JSON 401 on API
// routes) triggers a login flow that does NOT reload the application:
//
//   - every fetch is cloned before being sent (a Request body can
//     only be read once), keeping a replayable copy ;
//   - on 401 the failed request is queued and a DISMISSABLE
//     banner ("Se connecter" / ×) is shown: mid-flow 401s never open
//     a tab automatically (a background 401 must not steal focus).
//     The tab opens only on an explicit click: a
//     data-gtw-auth="before" element or the banner button. Dismissing resolves the pending requests with
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
//   - if the tab is closed without completing (user, blocker):
//     explicit login() promises resolve false silently (« not now ») ;
//     the banner reappears only when real requests are frozen — it is
//     their exit surface (Se connecter or ×) ;
//   - the banner is closable without any login action: ×, click
//     anywhere outside it, or Escape. Closing it closes the linked
//     login tab (if open) at the same time, resolves pending
//     requests with their original 401 and login() with false ;
//   - fallback to the historical full-page redirect when the request
//     cannot be cloned (streaming bodies) or window.open is
//     unavailable.
//
// Declarative gating (opt-in, zero app code) — two orthogonal
// dimensions:
//
//   data-gtw-auth — when auth happens:
//     "after"  : native click preserved, auth enforced at the request
//       level (401 → queued → replayed after login) ; the login tab
//       opens on click as an invitation ;
//     "before" : the click is neutralized (no native request) and the
//       login tab opens directly — authenticate first, act after ;
//     absent   : fully transparent — first 401 → dismissable banner
//       (never an auto-opened tab).
//
//   data-gtw-auth-hidden — visibility:
//     "before" : hidden while anonymous, shown once authed (silent
//       gate — never a trigger; activating clicks are neutralized and
//       show the banner) ;
//     "after"  : visible while anonymous, hidden once authed (pure
//       affordance, composable with gtw-auth="before" for padlocks) ;
//     absent   : always visible.
//
// Pages using no attribute make no probe request and stay fully
// transparent (auth handled mid-flow by the wrapper, with the
// banner as login affordance).
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
  // Règles uiGate de la route (gating UI par config, pour les fronts
  // non modifiables) — sérialisées depuis api-routes.json ; un
  // élément portant un attribut data-gtw-* ignore ces règles
  // (précédence : le markup gagne).
  var UIGATE = %[3]s;
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
  var shownBy = null; // le clic à l'origine de l'affichage : ne doit
                      // pas être requalifié en « clic extérieur »
                      // par l'handler de dismiss (même dispatch)
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

  function showBanner(ev) {
    if (banner || !document.body) return;
    shownBy = ev || null;
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

  // Onglet refermé sans succès (utilisateur, bloqueur) — Option C :
  //   - les promesses login() explicites sont résolues false en
  //     silence : l'utilisateur vient de dire « pas maintenant », pas
  //     la peine de re-insister ;
  //   - seules les requêtes réellement gelées conservent la bannière
  //     — leur unique surface de sortie (Se connecter ou ×) ; sans
  //     elle l'application resterait figée sans explication.
  function watchTab() {
    if (watching) return;
    watching = true;
    var iv = setInterval(function () {
      if (loginTab && !loginTab.closed) return;
      clearInterval(iv);
      watching = false;
      loginTab = null;
      var kept = [];
      queue.forEach(function (entry) {
        if (entry.barrier) { entry.resolve(false); return; }
        kept.push(entry);
      });
      queue = kept;
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
    fetchSession(); // rôles/scopes/claims post-login (re-sonde)
    flushQueue();
  });

  // == Declarative gating: [data-gtw-auth] + [data-gtw-auth-hidden] ==
  //   Two orthogonal dimensions (see the click handler below for the
  //   behavior matrix). Zero app code: applications DECLARE, the
  //   gateway toggles. Applications using no attribute are fully
  //   transparent: authentication happens mid-flow through the fetch
  //   wrapper above, nothing is hidden.
  var authed = false;
  var probeDone = false;
  var stateWaiters = [];
  var sessionRoles = [];
  var sessionScopes = [];
  var sessionClaims = {};

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
    var cssText =
      "html:not(.cladone-authed) [data-gtw-auth-hidden='before']" +
      "{display:none !important}" +
      "html.cladone-authed [data-gtw-auth-hidden='after']" +
      "{display:none !important}" +
      // éléments à condition d'identité (rôles/scopes/claims) :
      // masqués par défaut (anti-FOUC), révélés après évaluation JS
      "html:not(.cladone-evaluated) [data-gtw-roles]," +
      "html:not(.cladone-evaluated) [data-gtw-scopes]," +
      "html:not(.cladone-evaluated) [data-gtw-claims]" +
      "{display:none !important}" +
      "html:not(.cladone-authed) [data-gtw-auth]{cursor:pointer}";
    // voile anti-FOUC des règles uiGate : une règle CSS PAR
    // sélecteur (un sélecteur invalide ne doit tuer que son propre
    // masquage, pas celui des autres)
    for (var gi = 0; gi < UIGATE.length; gi++) {
      cssText += "html:not(.cladone-evaluated) " +
        UIGATE[gi].selector + "{display:none !important}";
    }
    var css = document.createElement("style");
    css.textContent = cssText;
    (document.head || document.documentElement).appendChild(css);
  } catch (e) { /* never break the page over gating */ }

  // Gating par rôles/scopes/claims : un élément n'est visible que si
  // TOUTES ses conditions d'identité passent (OU au sein d'un
  // attribut, ET entre attributs). Anonyme = aucun rôle/scope/claim
  // → masqué (l'authentification est implicite). Confort UI
  // uniquement : l'interdiction réelle reste côté endpoint
  // (auth.when.roles/scopes/claims) ou backend.
  function applyRoleGating() {
    var nodes = document.querySelectorAll(
      "[data-gtw-roles],[data-gtw-scopes],[data-gtw-claims]"
    );
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      var ok = true;
      var rl = n.getAttribute("data-gtw-roles");
      if (ok && rl) {
        ok = rl.split(/\s+/).filter(Boolean).some(function (r) {
          return sessionRoles.indexOf(r) !== -1;
        });
      }
      if (ok) {
        var sc = n.getAttribute("data-gtw-scopes");
        if (sc) {
          ok = sc.split(/\s+/).filter(Boolean).some(function (s) {
            return sessionScopes.indexOf(s) !== -1;
          });
        }
      }
      if (ok) {
        var cl = n.getAttribute("data-gtw-claims");
        if (cl) {
          try {
            var spec = JSON.parse(cl);
            for (var k in spec) {
              var want = spec[k];
              var have = sessionClaims[k];
              if (want === "*") {
                if (have === undefined) { ok = false; break; }
              } else if (String(have) !== want) {
                ok = false; break;
              }
            }
          } catch (e) { ok = false; }
        }
      }
      if (!ok) {
        n.style.display = "none";
        n.setAttribute("data-gtw-gated-off", "1");
      } else if (n.getAttribute("data-gtw-gated-off")) {
        n.removeAttribute("data-gtw-gated-off");
        n.style.display = "";
      }
    }
    applyRuleGating();
    // l'évaluation est faite : lever le voile anti-FOUC (les
    // masquages inline des non-conformes restent en place)
    document.documentElement.classList.add("cladone-evaluated");
  }

  // Gating par règles uiGate (config) : mêmes mécanismes que les
  // attributs markup, mais les éléments sont désignés par sélecteur
  // CSS. Un élément portant un attribut data-gtw-* est IGNORÉ par
  // les règles (précédence : le markup gagne). Plusieurs règles sur
  // un même élément se cumulent en ET. Sélecteur invalide = règle
  // ignorée, jamais d'erreur visible.
  function rulePasses(rule) {
    var ok = true;
    if (ok && rule.roles && rule.roles.length) {
      ok = rule.roles.some(function (r) {
        return sessionRoles.indexOf(r) !== -1;
      });
    }
    if (ok && rule.scopes && rule.scopes.length) {
      ok = rule.scopes.some(function (s) {
        return sessionScopes.indexOf(s) !== -1;
      });
    }
    if (ok && rule.claims) {
      for (var k in rule.claims) {
        var want = rule.claims[k];
        var have = sessionClaims[k];
        if (want === "*") {
          if (have === undefined) { ok = false; break; }
        } else if (String(have) !== want) {
          ok = false; break;
        }
      }
    }
    return ok;
  }

  function applyRuleGating() {
    for (var i = 0; i < UIGATE.length; i++) {
      var rule = UIGATE[i];
      if (!rule || !rule.selector) continue;
      var nodes;
      try {
        nodes = document.querySelectorAll(rule.selector);
      } catch (e) {
        continue; // sélecteur invalide : règle ignorée
      }
      for (var j = 0; j < nodes.length; j++) {
        var n = nodes[j];
        if (n.hasAttribute("data-gtw-auth") ||
            n.hasAttribute("data-gtw-auth-hidden") ||
            n.hasAttribute("data-gtw-roles") ||
            n.hasAttribute("data-gtw-scopes") ||
            n.hasAttribute("data-gtw-claims")) {
          continue; // précédence : le markup gagne
        }
        var ok = rulePasses(rule);
        if (!ok) {
          n.style.display = "none";
          n.setAttribute("data-gtw-gated-off", "1");
        } else if (n.getAttribute("data-gtw-gated-off")) {
          n.removeAttribute("data-gtw-gated-off");
          n.style.display = "";
        }
      }
    }
  }

  function fetchSession() {
    orig(AUTH_STATE, { cache: "no-store" }).then(function (res) {
      if (res.status !== 200) {
        sessionRoles = [];
        sessionScopes = [];
        sessionClaims = {};
        applyRoleGating();
        settleState(false);
        return;
      }
      res.json().then(function (s) {
        sessionRoles = s.roles || [];
        sessionScopes = s.scopes || [];
        sessionClaims = s.claims || {};
        applyRoleGating();
        settleState(true);
      }).catch(function () {
        applyRoleGating();
        settleState(false);
      });
    }).catch(function () {
      // réseau/SW en erreur : fail-closed — pas de révélation des
      // éléments à condition d'identité
      settleState(false);
    });
  }

  function probeSession() {
    if (!document.querySelector(
      "[data-gtw-auth],[data-gtw-auth-hidden]," +
      "[data-gtw-roles],[data-gtw-scopes],[data-gtw-claims]"
    ) && !UIGATE.length) {
      return; // no gating declared: no probe, fully transparent
    }
    fetchSession();
  }

  // Session probe (Bearer header or cookie session), gateway-served,
  // never cached by the PWA service worker ("auth" exclude pattern).
  // AUTH_STATE is injected from AuthStatePath (guard.go). Runs at
  // DOMContentLoaded so pages without any gated element make no
  // request at all.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", probeSession);
  } else {
    probeSession();
  }

  // Click handling while anonymous (capture phase). Two attributes,
  // two orthogonal dimensions:
  //
  //   data-gtw-auth — WHEN auth happens:
  //     "after"  : native click preserved (no preventDefault) — the
  //                auth is enforced at the request level (401 queued,
  //                replayed after login) ; the tab opens on click as
  //                an invitation ;
  //     "before" : the click is neutralized (no native request) and
  //                the login tab opens directly — authenticate
  //                first, act after.
  //
  //   data-gtw-auth-hidden — visibility:
  //     "before" : hidden while anonymous — activating clicks
  //                (direct, synthetic label activation) are
  //                neutralized: never a silent pre-tick, the banner
  //                offers "Se connecter" ;
  //     "after"  : no click interception (pure affordance hiding,
  //                composable with gtw-auth="before" for padlocks).
  document.addEventListener("click", function (ev) {
    if (authed) return;
    var t = ev.target;
    if (!t || !t.closest) return;
    var before = t.closest('[data-gtw-auth="before"]');
    if (before) {
      ev.preventDefault();
      ev.stopPropagation();
      window.__cladoneAuth.login();
      return;
    }
    var after = t.closest('[data-gtw-auth="after"]');
    if (after) {
      // l'action native procede (cocher la case…) ; la requete 401
      // qui en resulte est mise en file puis rejouee apres login
      window.__cladoneAuth.login();
      return;
    }
    var hiddenPre = t.closest('[data-gtw-auth-hidden="before"]');
    if (hiddenPre) {
      ev.preventDefault();
      ev.stopPropagation();
      showBanner(ev);
      return;
    }

    // règles uiGate (config) : auth et masquage pré-auth — mêmes
    // sémantiques que les attributs markup ; un élément markup a
    // déjà court-circuité ci-dessus (précédence)
    for (var gi = 0; gi < UIGATE.length; gi++) {
      var rule = UIGATE[gi];
      if (!rule || !rule.selector) continue;
      var hit = null;
      try {
        hit = t.closest(rule.selector);
      } catch (e) {
        continue; // sélecteur invalide : règle ignorée (comme dans
                  // applyRuleGating) — jamais d'exception visible
      }
      if (!hit) continue;
      if (rule.hidden === "before") {
        // contrôle masqué en anonyme : tout clic qui l'atteint est
        // synthétique (activation label) — jamais de pré-cochage
        ev.preventDefault();
        ev.stopPropagation();
        showBanner(ev);
        return;
      }
      if (rule.auth) {
        if (rule.auth === "before") {
          ev.preventDefault();
          ev.stopPropagation();
        }
        // "after" : l'action native procède, la 401 sera rejouée
        window.__cladoneAuth.login();
        return;
      }
    }

    var lbl = t.closest("label");
    if (lbl && lbl.querySelector('[data-gtw-auth-hidden="before"]')) {
      ev.preventDefault();
      ev.stopPropagation();
      showBanner(ev);
    }
  }, true);

  // La bannière se referme sans action d'authentification : clic
  // n'importe où en dehors d'elle, ou Échap — et l'onglet de login
  // lié se ferme avec elle (cf. dismiss). Enregistrés APRÈS le
  // handler d'affordance ci-dessus : un clic sur un élément de
  // login (ou sur un bouton de la bannière) gagne toujours.
  document.addEventListener("click", function (ev) {
    if (!banner) return;
    if (banner.contains(ev.target)) return;
    if (shownBy === ev) return; // le clic qui a affiché la bannière
    dismiss();
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
    },
    // Session détaillée (opt-in) : {roles, scopes, claims} une fois
    // la sonde passée (ou null si anonyme). Pour les applications qui
    // veulent filtrer en JS sans relire un token.
    session: function () {
      return new Promise(function (resolve) {
        var snap = function (ok) {
          resolve(ok ? {
            roles: sessionRoles.slice(),
            scopes: sessionScopes.slice(),
            claims: sessionClaims
          } : null);
        };
        if (probeDone) { snap(authed); return; }
        stateWaiters.push(snap);
      });
    }
  };

  window.fetch = function (input, init) {

    // Clone BEFORE the call: a Request body can be read only once,
    // the copy is kept for the post-login replay.
    var replay = buildReplay(input, init);

    return orig.apply(this, arguments).then(function (res) {

      // 401 SEULEMENT : c'est le signal « authentifie-toi ». Un 403
      // (authentifié mais droits insuffisants — when.roles/scopes/
      // claims) traverse vers l'application : offrir un login sur un
      // refus de droits produirait une boucle.
      if (!res || res.status !== 401 || res.url.startsWith(LOGIN)) {
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
        // un onglet de login deja ouvert EST l'invitation : pas de
        // banniere redondante a cote
        if (!(loginTab && !loginTab.closed)) showBanner();
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

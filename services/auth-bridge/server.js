import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import path from "node:path";
import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from "jose";
import { createRevocationStore } from "./revocation.js";

const app = express();

app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

const PORT = Number(process.env.PORT) || 3000;

/**
 * CONFIG — EVERYTHING is externalized into environment variables
 * (compose/.env): the code contains NO platform value (the gateway is
 * deployable by others, for other sites, with other rights — only the
 * config and the env change). REQUIRED variables: missing at boot =
 * exit(1) with the list of missing ones (mirror of the gateway's
 * ${VAR} philosophy: never start on a silently partial config).
 *
 * Expected keys (see compose/.env.example):
 *   KEYCLOAK_BASE_URL       — Keycloak IdP base (…/realms derived)
 *   KEYCLOAK_REALM          — realm name
 *   KEYCLOAK_CLIENT_ID      — the application's OIDC client
 *   KEYCLOAK_CLIENT_SECRET  — client secret (code exchange,
 *                             refresh) — MANDATORY, never in git
 *   PUBLIC_AUTH_URL         — public URL of THIS service (login.*)
 *   COOKIE_DOMAIN           — domain of the session cookies
 *   DEFAULT_APP_URL         — fallback redirect (error return)
 *   LOGOUT_URL              — redirect after /logout
 *   MCP_RESOURCE            — protected MCP resource(s) (audience);
 *                             comma-separated for several endpoints
 *   MCP_SCOPE               — default MCP scope (when a route does
 *                             not declare one; default "mcp-tools")
 */

const REQUIRED_ENV = [
  "KEYCLOAK_BASE_URL",
  "KEYCLOAK_REALM",
  "KEYCLOAK_CLIENT_ID",
  "KEYCLOAK_CLIENT_SECRET",
  "PUBLIC_AUTH_URL",
  "COOKIE_DOMAIN",
  "DEFAULT_APP_URL",
  "LOGOUT_URL",
  "MCP_RESOURCE",
];

// checkRequiredEnv: returns the list of missing variables
// (exported for tests — boot runs exit(1) on it).
export function checkRequiredEnv(env = process.env) {
  return REQUIRED_ENV.filter((k) => !env[k]);
}

const KEYCLOAK_BASE_URL = process.env.KEYCLOAK_BASE_URL;
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM;
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID;
const KEYCLOAK_CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET;

const ISSUER = `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}`;
const JWKS_URL = `${ISSUER}/protocol/openid-connect/certs`;
const TOKEN_URL = `${ISSUER}/protocol/openid-connect/token`;
const AUTHZ_URL = `${ISSUER}/protocol/openid-connect/auth`;
const LOGOUT_ENDPOINT = `${ISSUER}/protocol/openid-connect/logout`;

const PUBLIC_AUTH_URL = process.env.PUBLIC_AUTH_URL;
const REDIRECT_URI = `${PUBLIC_AUTH_URL}/auth/callback`;

const APP_URL = process.env.DEFAULT_APP_URL;
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN;
const LOGOUT_URL = process.env.LOGOUT_URL;
const MCP_RESOURCE = process.env.MCP_RESOURCE;
// MCP_RESOURCE may list several protected resources (comma-separated):
// each MCP endpoint advertises its own resource, and Keycloak's audience
// list grows per endpoint. A single value keeps the historical behaviour.
const MCP_RESOURCES = String(MCP_RESOURCE || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// resolveMCPAudience: per-endpoint audience selection. An empty target
// accepts any declared resource (historical single-resource behaviour);
// a target must be one of the declared resources (fail-closed → null).
// Exported for tests.
export function resolveMCPAudience(target, resources = MCP_RESOURCES) {
  if (target) {
    return resources.includes(target) ? target : null;
  }
  return resources;
}

const MCP_SCOPE = process.env.MCP_SCOPE || "mcp-tools";

// Revocation state (back-channel logout sids). The list must survive a
// restart: an in-memory list restarts empty and a session revoked before
// the restart would be accepted again (session reactivation). Default:
// ./auth-bridge-state.json; Docker compose mounts a volume and sets
// REVOCATION_STATE_FILE=/app/state/auth-bridge-state.json.
const REVOCATION_STATE_FILE =
  process.env.REVOCATION_STATE_FILE ||
  path.join(process.cwd(), "auth-bridge-state.json");

let revocationStore;
try {
  revocationStore = createRevocationStore({ file: REVOCATION_STATE_FILE });
} catch (err) {
  console.error(`auth-bridge: revocation store: ${err.message}`);
  process.exit(1);
}

// Token broker (delegated upstream credentials). Optional: when no
// shared secret is configured, the /connections and /connect routes
// answer 503 instead of breaking a normal deploy.
const TOKEN_BROKER_URL = (
  process.env.TOKEN_BROKER_URL || "http://token-broker:4000"
).replace(/\/+$/, "");
const TOKEN_BROKER_SHARED_SECRET =
  process.env.TOKEN_BROKER_SHARED_SECRET || "";

const JWKS = createRemoteJWKSet(new URL(JWKS_URL));

// ── PKCE (RFC 7636) — durcissement du code d'autorisation ────────
// auth-bridge garde les sessions dans les cookies (stateless) ; le
// code_verifier voyage entre /login et /auth/callback dans un cookie
// HttpOnly court, signé HMAC-SHA256 (oidc_tx). Le verifier ne doit
// JAMAIS transiter par l'URL : le paramètre `state` est réfléchi au
// navigateur, un intercepteur du redirect lirait le verifier et PKCE
// ne servirait à rien. Le même cookie porte un `state` aléatoire
// (nonce) vérifié au retour : la liaison navigateur↔callback couvre
// aussi le CSRF de callback.
const PKCE_TX_COOKIE = "oidc_tx";
const PKCE_TX_PATH = "/auth/callback";
const PKCE_TX_TTL_MS = 5 * 60 * 1000;

// pkcePair: verifier RFC 7636 (43 chars base64url) + challenge S256.
// Exporté pour les tests.
export function pkcePair() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");
  return { verifier, challenge };
}

function signTx(body) {
  return crypto
    .createHmac("sha256", KEYCLOAK_CLIENT_SECRET)
    .update(body)
    .digest("base64url");
}

// sealTx: `body.signature` (base64url). Exporté pour les tests.
export function sealTx(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${body}.${signTx(body)}`;
}

// readTx: vérifie la signature HMAC et la fraîcheur, renvoie le
// payload ou null (altéré / expiré / malformé). Exporté pour les tests.
export function readTx(raw) {
  if (typeof raw !== "string" || !raw) return null;
  const dot = raw.lastIndexOf(".");
  if (dot <= 0) return null;
  const body = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  const expected = signTx(body);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!p || typeof p.v !== "string" || typeof p.n !== "string") return null;
    if (typeof p.t !== "number" || Date.now() - p.t > PKCE_TX_TTL_MS) {
      return null;
    }
    return p;
  } catch {
    return null;
  }
}

const authCache = new Map();
const CACHE_TTL_MS = 60 * 1000; // 1 minute

// Allowed returns: only an HTTPS subdomain of the cookie domain
// (derived from COOKIE_DOMAIN — for cladone: *.cladone.com).
// returnTo no longer travels through the OIDC `state` parameter (now a
// random nonce): it is carried by the signed oidc_tx cookie, but stays
// validated here — a tampered/forged returnTo would be an open
// redirect at /auth/callback.
const COOKIE_DOMAIN_HOST = COOKIE_DOMAIN.replace(/^\./, "");

function safeReturnTo(raw, fallback) {
  if (!raw) return fallback;
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:") return fallback;
    // LINEAR check of the hostname — never a nested-quantifier
    // regex: the old one, with wildcard dots (backslashes swallowed
    // by JS strings), went into catastrophic backtracking on hosts
    // with two sub-levels (2026-10-17 incident:
    // correspondances.jacquelot.cladone.com = 99% CPU,
    // event loop frozen, the whole service dead).
    const host = u.hostname; // without port
    if (
      host === COOKIE_DOMAIN_HOST ||
      host.endsWith("." + COOKIE_DOMAIN_HOST)
    ) {
      return u.href;
    }
  } catch {
    // malformed URL → fallback
  }
  return fallback;
}

function getCached(token) {
  const entry = authCache.get(token);
  if (!entry) return null;

  if (entry.exp < Date.now()) {
    authCache.delete(token);
    return null;
  }

  return entry.payload;
}

function setCache(token, payload) {
  const exp = payload.exp ? payload.exp * 1000 : Date.now() + CACHE_TTL_MS;
  const iat = payload.iat ? payload.iat * 1000 : Date.now();

  authCache.set(token, {
    payload,
    exp,
    iat,
  });
}

// Map<refreshTokenValue, Promise<tokens>>
// Ensures concurrent requests sharing the same expired access_token
// trigger only ONE Keycloak refresh call, instead of racing and
// invalidating each other's rotated refresh_token.
const inFlightRefreshes = new Map();

async function refreshAccessTokenDeduped(refreshToken) {
  const existing = inFlightRefreshes.get(refreshToken);
  if (existing) {
    return existing;
  }

  const promise = refreshAccessToken(refreshToken).finally(() => {
    // Only clean up if this is still the promise we registered
    // (avoids removing a newer entry in edge-case orderings).
    if (inFlightRefreshes.get(refreshToken) === promise) {
      inFlightRefreshes.delete(refreshToken);
    }
  });

  inFlightRefreshes.set(refreshToken, promise);
  return promise;
}


/**
 * Exchange a refresh_token for a new access_token (+ rotated refresh_token).
 * Throws if Keycloak rejects it (expired / revoked / reused).
 */
async function refreshAccessToken(refreshToken) {
  const tokenResponse = await fetch(
    TOKEN_URL,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: KEYCLOAK_CLIENT_ID,
        client_secret: KEYCLOAK_CLIENT_SECRET,
        refresh_token: refreshToken,
      }),
    }
  );

  if (!tokenResponse.ok) {
    const errText = await tokenResponse.text();
    throw new Error(`refresh failed: ${tokenResponse.status} ${errText}`);
  }

  return tokenResponse.json(); // { access_token, refresh_token, expires_in, ... }
}

function setAuthCookies(res, tokens) {
  res.cookie("access_token", tokens.access_token, {
    domain: COOKIE_DOMAIN,
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: tokens.expires_in * 1000,
  });
  if (tokens.refresh_token) {
    res.cookie("refresh_token", tokens.refresh_token, {
      domain: COOKIE_DOMAIN,
      path: "/",
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 30 * 24 * 3600 * 1000,
    });
  }
}

/**
 * Resolve the Keycloak user id for browser-facing token-broker routes.
 *
 * Mirrors the session verification of /auth (access_token cookie,
 * silent refresh, revoked sid / azp checks) but returns only the
 * subject. Returns null when the visitor must be sent to /login.
 */
async function resolveSessionUserId(req, res) {
  let token = req.cookies.access_token;

  if (!token && req.cookies.refresh_token) {
    try {
      const tokens = await refreshAccessTokenDeduped(req.cookies.refresh_token);
      setAuthCookies(res, tokens);
      token = tokens.access_token;
    } catch {
      return null;
    }
  }

  if (!token) return null;

  let payload = getCached(token);

  if (!payload) {
    try {
      payload = (await jwtVerify(token, JWKS, { issuer: ISSUER })).payload;
      setCache(token, payload);
    } catch (err) {
      if (err instanceof joseErrors.JWTExpired && req.cookies.refresh_token) {
        try {
          const tokens = await refreshAccessTokenDeduped(
            req.cookies.refresh_token
          );
          setAuthCookies(res, tokens);
          token = tokens.access_token;
          payload = (await jwtVerify(token, JWKS, { issuer: ISSUER })).payload;
          setCache(token, payload);
        } catch {
          return null;
        }
      } else {
        return null;
      }
    }
  }

  if (isSidRevoked(payload.sid)) return null;
  if (payload.azp !== KEYCLOAK_CLIENT_ID) return null;
  if (!payload.sub) return null;

  return String(payload.sub);
}

function tokenBrokerConfigured() {
  return Boolean(TOKEN_BROKER_SHARED_SECRET);
}

function tokenBrokerUnavailable(res) {
  res.setHeader("Cache-Control", "no-store");
  return res.status(503).json({ error: "token_broker_not_configured" });
}

/**
 * Proxy a browser request to the internal broker. The broker owns the
 * OAuth flow and the HTML; auth-bridge only proves the user's session
 * and adds the internal headers. The browser never reaches the broker.
 */
async function proxyTokenBroker(req, res, userId = null) {
  const headers = { "x-broker-secret": TOKEN_BROKER_SHARED_SECRET };
  if (userId) headers["x-user-id"] = userId;
  if (req.get("accept")) headers.accept = req.get("accept");

  let upstream;
  try {
    upstream = await fetch(`${TOKEN_BROKER_URL}${req.originalUrl}`, {
      method: req.method,
      headers,
      redirect: "manual",
      signal: AbortSignal.timeout(15_000),
    });
  } catch (err) {
    console.error("token-broker proxy failed:", err.message);
    res.setHeader("Cache-Control", "no-store");
    return res.status(502).json({ error: "token_broker_unavailable" });
  }

  res.status(upstream.status);
  for (const header of [
    "location",
    "content-type",
    "cache-control",
    "content-security-policy",
    "referrer-policy",
    "x-content-type-options",
  ]) {
    const value = upstream.headers.get(header);
    if (value) res.setHeader(header, value);
  }

  return res.send(Buffer.from(await upstream.arrayBuffer()));
}

function loginReturnUrl(req) {
  return `${PUBLIC_AUTH_URL}/login?returnTo=${encodeURIComponent(
    `${PUBLIC_AUTH_URL}${req.originalUrl}`
  )}`;
}


/**
 * ForwardAuth endpoint used by Traefik
 */
app.get("/auth", async (req, res) => {
  try {
    let token;
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith("Bearer ")) {
      token = authHeader.substring(7).trim();
    } else if (req.cookies.access_token) {
      token = req.cookies.access_token;
    }

    const host = req.headers["x-forwarded-host"] || APP_URL.replace("https://", "");
    const uri  = req.headers["x-forwarded-uri"] || "/";
    const returnTo = `https://${host}${uri}`;

    async function verify(t) {
      const { payload } = await jwtVerify(t, JWKS, {
        issuer: ISSUER,
      });
      return payload;
    }

    let payload;
    if (!token) {
      // No access token at all — try silent refresh before giving up.
      if (req.cookies.refresh_token) {
        const tokens = await refreshAccessTokenDeduped(req.cookies.refresh_token);
        setAuthCookies(res, tokens);
        payload = await verify(tokens.access_token);
        setCache(tokens.access_token, payload);
      } else {
        return res.redirect(
          `${PUBLIC_AUTH_URL}/login?returnTo=${encodeURIComponent(returnTo)}`
        );
      }
    } else {
      payload = getCached(token);
      if (!payload) {
        try {
          payload = await verify(token);
          setCache(token, payload);
        } catch (err) {
          // Only attempt silent refresh for a genuinely expired token.
          if (err instanceof joseErrors.JWTExpired && req.cookies.refresh_token) {
            const tokens = await refreshAccessTokenDeduped(req.cookies.refresh_token);
            setAuthCookies(res, tokens);
            payload = await verify(tokens.access_token);
            setCache(tokens.access_token, payload);
          } else {
            throw err;
          }
        }
      }
    }

    // Revoked SSO session (backchannel logout): treat as
    // unauthenticated — the gateway will redirect to login, signing
    // in again produces a new sid.
    if (isSidRevoked(payload.sid)) {
      return res.status(401).end();
    }

    if (payload.azp !== KEYCLOAK_CLIENT_ID) {
      return res.status(401).end();
    }

    res.setHeader("X-User-Id", payload.sub);
    res.setHeader("X-Username", payload.preferred_username ?? "");
    res.setHeader("X-Email", payload.email ?? "");
    const roles = [
      ...(payload.realm_access?.roles ?? []),
      ...(payload.resource_access
          ? Object.values(payload.resource_access).flatMap(c => c.roles ?? [])
          : [])
    ];
    res.setHeader("X-Roles", [...new Set(roles)].join(","));

    // Granted scopes (token `scope` claim, space-separated).
    res.setHeader(
      "X-Scopes",
      String(payload.scope ?? "").split(/\s+/).filter(Boolean).join(",")
    );

    // Claims: full payload as base64-JSON (ASCII-safe header) —
    // consumed by the gateway's when.claims conditions and the
    // /__gate-one/auth probe. The gateway↔auth-bridge link is internal.
    res.setHeader(
      "X-Claims",
      Buffer.from(JSON.stringify(payload)).toString("base64")
    );

    res.setHeader("X-Auth-Expires", String(payload.exp));
    return res.sendStatus(200);
  } catch (err) {
    console.error(err);
    const host = req.headers["x-forwarded-host"] || APP_URL.replace("https://", "");
    const uri  = req.headers["x-forwarded-uri"] || "/";
    const returnTo = `https://${host}${uri}`;
    return res.redirect(
      `${PUBLIC_AUTH_URL}/login?returnTo=${encodeURIComponent(returnTo)}`
    );
  }
});


/**
 * Root: the login host has no "/" page. Keycloak's "back to
 * application" link targets the client's baseUrl (login.cladone.com),
 * and any stray visit to the root used to answer Express' bare
 * "Cannot GET /". Send the browser to the application instead; its
 * guard will start the login flow if needed.
 */
app.get("/", (req, res) => res.redirect(APP_URL));

/**
 * Redirect user to Keycloak login page
 */
app.get("/login", (req, res) => {

  const returnTo = safeReturnTo(req.query.returnTo, APP_URL);

  // PKCE: verifier kept server-side (signed cookie), challenge sent to
  // Keycloak; `state` is a random nonce echoed back and checked at the
  // callback (see the PKCE block above).
  const { verifier, challenge } = pkcePair();
  const nonce = crypto.randomBytes(16).toString("base64url");

  res.cookie(
    PKCE_TX_COOKIE,
    sealTx({ v: verifier, r: returnTo, n: nonce, t: Date.now() }),
    {
      path: PKCE_TX_PATH,
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: PKCE_TX_TTL_MS,
    }
  );

  //URLSearchParams is actually encoding
  const params = new URLSearchParams({
    client_id: KEYCLOAK_CLIENT_ID,
    response_type: "code",
    scope: "openid",
    redirect_uri: REDIRECT_URI,
    state: nonce,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });

  const loginUrl =
    `${AUTHZ_URL}?${params.toString()}`;

  console.log("LOGIN URL =", loginUrl);

  return res.redirect(loginUrl);
});

/**
 * OAuth callback
 *
 * TEMP VERSION:
 * We fake authentication success for now.
 *
 * Later:
 * - exchange code for token
 * - validate token
 * - extract roles
 */
 app.get("/auth/callback", async (req, res) => {

  try {

    const code = req.query.code;
    const state = req.query.state;

    // PKCE transaction: consume the signed cookie (one-shot) and bind
    // the callback to the login request through the state nonce.
    const tx = readTx(req.cookies[PKCE_TX_COOKIE]);
    res.clearCookie(PKCE_TX_COOKIE, { path: PKCE_TX_PATH });

    if (!tx || !state || state !== tx.n) {
      console.error("oauth callback: missing or invalid PKCE transaction");
      return res.redirect(APP_URL);
    }

    const returnTo = safeReturnTo(tx.r, APP_URL);

    if (!code) {
      console.error("missing oauth code");
      return res.redirect(APP_URL);
    }

    /**
     * Exchange authorization code for tokens
     */
    const tokenResponse = await fetch(
      TOKEN_URL,
      {
        method: "POST",

        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },

        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: KEYCLOAK_CLIENT_ID,
          client_secret: KEYCLOAK_CLIENT_SECRET,
          code,
          redirect_uri: `${PUBLIC_AUTH_URL}/auth/callback`,
          code_verifier: tx.v
        })
      }
    );

    if (!tokenResponse.ok) {

      const errorText = await tokenResponse.text();

      console.error("token exchange failed:");
      console.error(errorText);

      return res.redirect(APP_URL);
    }

    /**
     * Parse tokens
     */
    const tokens = await tokenResponse.json();
    console.log("TOKENS =", {
      expires_in: tokens.expires_in,
      has_access_token: !!tokens.access_token,
      has_id_token: !!tokens.id_token,
    });
    /**
     * Decode JWT payload
     */
    const { payload } = await jwtVerify(tokens.access_token, JWKS, {
        issuer: ISSUER,
    });
    setCache(tokens.access_token, payload);
    console.log("TOKEN PAYLOAD =", payload);

    /**
     * Build user session
     */
    const user = {
      id:
        payload.preferred_username ||
        payload.email ||
        payload.sub,

      email:
        payload.email,

      roles:
        payload.realm_access?.roles || []
    };

    console.log("AUTH USER =", user);


    /**
     * id_token: required for RP-initiated logout (end_session with
     * id_token_hint) — logout must also kill the Keycloak SSO
     * session, otherwise SSO silently signs the user back in.
     */
    if (tokens.id_token) {
      res.cookie(
        "id_token",
        tokens.id_token,
        {
          domain: COOKIE_DOMAIN,
          path: "/",
          httpOnly: true,
          secure: true,
          sameSite: "lax",
          // same lifetime as the refresh_token: the id_token serves
          // as the logout (end_session) HINT — Keycloak only
          // requires signature validity, not non-expiry; a short
          // cookie made the KC interstitial appear when signing out
          // more than a few minutes after login
          maxAge: 30 * 24 * 3600 * 1000,
        }
      );
    }

    /**
     * access token cookie
     * lets the /auth middleware find the JWT
     */
    res.cookie(
        "access_token",
        tokens.access_token,
        {
            domain: COOKIE_DOMAIN,
            path: "/",
            httpOnly: true,
            secure: true,
            sameSite: "lax",
            maxAge: tokens.expires_in * 1000,
        }
    );

    /**
     * Create session cookie
    res.cookie(
      "session",
      JSON.stringify(user),
      {
        domain: COOKIE_DOMAIN,
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge: 24 * 60 * 60 * 1000
      }
    );
     */
    //used when the access_token expires, without sending the user back to Keycloak.
    res.cookie(
        "refresh_token",
        tokens.refresh_token,
        {
            domain: COOKIE_DOMAIN,
            path: "/",
            httpOnly: true,
            secure: true,
            sameSite: "lax",
            maxAge: 30 * 24 * 3600 * 1000,
        }
    );

    /**
     * Back to app
     */
    return res.redirect(returnTo || APP_URL);

  } catch (err) {

    console.error("callback error:", err);

    return res.redirect(APP_URL);
  }
});

/**
 * End of login in a separate tab/popup (the gateway's guard script):
 * notifies the calling page via postMessage then closes itself. The
 * origin passed in the query is validated (*.cladone.com).
 */
app.get("/auth/popup-done", (req, res) => {
  const origin = safeReturnTo(req.query.origin, null);

  if (!origin) {
    return res.status(400).send("origin not allowed");
  }

  // JSON.stringify makes the origin safe to embed in the script.
  const target = JSON.stringify(origin);

  res.setHeader("Cache-Control", "no-store");
  res.type("html").send(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Sign-in</title></head>
<body>
<p>Sign-in complete. You can close this window.</p>
<script>
(function(){
  try {
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage("cladone-auth:ok", ${target});
    }
  } catch (e) {}
  window.close();
})();
</script>
</body>
</html>`);
});

/**
 * Front-channel logout: iframe placed by Keycloak on its logout page
 * (frontchannelLogout: true). The browser loads it WITH its
 * .cladone.com cookies — the only channel able to clear them (the
 * backchannel is server-to-server: with no server-side state, it
 * could not know which browser sessions to kill). Clears and answers
 * minimally, WITHOUT redirect: idempotent, never a loop.
 */
app.get("/frontchannel-logout", (req, res) => {
  res.clearCookie("access_token", { domain: COOKIE_DOMAIN, path: "/" });
  res.clearCookie("refresh_token", { domain: COOKIE_DOMAIN, path: "/" });
  res.clearCookie("id_token", { domain: COOKIE_DOMAIN, path: "/" });
  res.clearCookie("session", { domain: COOKIE_DOMAIN, path: "/" });
  res.setHeader("Cache-Control", "no-store");
  res.type("html").send("<!DOCTYPE html><html><body></body></html>");
});

// ── Single logout: session revocation by `sid` ──────────────────
// auth-bridge keeps sessions stateless (browser cookies); the ONE piece
// of server state is the revocation list below. So that the death of a
// Keycloak SSO session (global logout, admin revocation, end_session
// from another site) ALSO kills the gateway session immediately,
// Keycloak posts a signed logout_token here whose `sid` claim is added
// to the revocation store, consulted on every /auth and /auth/mcp
// (OIDC Backchannel Logout 1.0).
//
// The store is PERSISTENT (revocation.js): an in-memory list restarts
// empty and would reactivate a revoked session after a restart. The
// file is written atomically before the 200 answer.
const LOGOUT_TOKEN_EVENT =
  "http://schemas.openid.net/event/backchannel-logout";

// validLogoutClaims: OIDC Back-Channel Logout 1.0 claims. The event
// claim is `events` (PLURAL), not `event`: Keycloak and every spec
// implementation send {"events":{"http://schemas...": {}}}. An old
// singular check rejected every real Keycloak logout token.
// Exported for tests.
export function validLogoutClaims(
  payload,
  nowSec = Math.floor(Date.now() / 1000)
) {
  return Boolean(
    payload &&
      payload.events &&
      payload.events[LOGOUT_TOKEN_EVENT] &&
      !payload.nonce &&
      payload.sid &&
      (!payload.iat || Math.abs(nowSec - payload.iat) <= 300)
  );
}

function isSidRevoked(sid) {
  return revocationStore.isRevoked(sid);
}

app.post("/backchannel-logout", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const logoutToken = req.body && req.body.logout_token;
    if (!logoutToken) {
      return res.status(400).json({ error: "missing logout_token" });
    }
    // Same JWKS/issuer as access tokens: Keycloak signature.
    const { payload } = await jwtVerify(logoutToken, JWKS, {
      issuer: ISSUER,
    });
    // logout_token constraints (spec): backchannel-logout event
    // required, nonce FORBIDDEN, sid required here (revocation can
    // only be done per session), fresh iat.
    if (!validLogoutClaims(payload)) {
      return res
        .status(400)
        .json({ error: "invalid logout_token claims" });
    }
    try {
      revocationStore.revoke(payload.sid);
    } catch (err) {
      // The session is revoked in memory; durability failed. 503 so
      // Keycloak retries (never a false 200).
      console.error("backchannel logout store failed:", err.message);
      return res
        .status(503)
        .json({ error: "revocation store unavailable" });
    }
    return res.sendStatus(200);
  } catch (err) {
    console.error("backchannel logout failed:", err.message);
    return res.status(400).json({ error: "invalid logout_token" });
  }
});

/**
 * Logout
 */
app.get("/logout", (req, res) => {

  const returnTo = safeReturnTo(req.query.returnTo, APP_URL);

  res.clearCookie("access_token", { domain: COOKIE_DOMAIN, path: "/" });
  res.clearCookie("refresh_token", { domain: COOKIE_DOMAIN, path: "/" });
  res.clearCookie("id_token", { domain: COOKIE_DOMAIN, path: "/" });
  res.clearCookie("session", { domain: COOKIE_DOMAIN, path: "/" });

  // Also ends the Keycloak SSO session (OIDC end_session): without
  // it, SSO would silently sign the user back in. Keycloak may
  // reject a post_logout_redirect_uri not registered on the client
  // and show its interstitial — the SSO session is destroyed
  // nonetheless.
  //
  // post_logout_redirect_uri is sent whenever a returnTo is known,
  // NOT only when the id_token cookie is present: the hint is only
  // an optimisation (Keycloak 25 accepts client_id + a registered
  // post-logout URI). Without it, a session whose id_token cookie is
  // gone lands on KC's "You are logged out" page, whose "back" link
  // is the client's baseUrl (login.cladone.com) — a 404. Logout must
  // always bring the user back to the app (2026-10-25 incident).
  const params = new URLSearchParams();
  if (req.cookies.id_token) {
    params.set("id_token_hint", req.cookies.id_token);
  }
  if (returnTo) {
    params.set("post_logout_redirect_uri", returnTo);
  }
  params.set("client_id", KEYCLOAK_CLIENT_ID);

  return res.redirect(`${LOGOUT_ENDPOINT}?${params.toString()}`);
});

/**
 * Health check
 */
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// ── Token broker browser routes ──────────────────────────────────
// The broker is internal-only; these routes are the only public
// surface. /oauth/.../callback is intentionally session-less: the
// broker binds the callback to the user through its one-time state.

app.get("/connections", async (req, res) => {
  if (!tokenBrokerConfigured()) return tokenBrokerUnavailable(res);

  const userId = await resolveSessionUserId(req, res);
  if (!userId) return res.redirect(loginReturnUrl(req));

  return proxyTokenBroker(req, res, userId);
});

app.get("/connect", async (req, res) => {
  if (!tokenBrokerConfigured()) return tokenBrokerUnavailable(res);
  return res.redirect("/connections");
});

app.get("/connect/:provider", async (req, res) => {
  if (!tokenBrokerConfigured()) return tokenBrokerUnavailable(res);

  const userId = await resolveSessionUserId(req, res);
  if (!userId) return res.redirect(loginReturnUrl(req));

  return proxyTokenBroker(req, res, userId);
});

app.get("/oauth/:provider/callback", async (req, res) => {
  if (!tokenBrokerConfigured()) return tokenBrokerUnavailable(res);
  return proxyTokenBroker(req, res);
});

app.post("/connections/:provider/disconnect", async (req, res) => {
  if (!tokenBrokerConfigured()) return tokenBrokerUnavailable(res);

  const userId = await resolveSessionUserId(req, res);
  if (!userId) return res.redirect(loginReturnUrl(req));

  return proxyTokenBroker(req, res, userId);
});

export { safeReturnTo, isSidRevoked, LOGOUT_TOKEN_EVENT };
export default app;

// Listens only when executed directly (tests import the module and
// mount the app on a random port).
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  // Fail-fast: missing required variables = refuse to start (never
  // a service that believes it is on another domain).
  const missing = checkRequiredEnv();
  if (missing.length) {
    console.error(
      "auth-bridge: missing environment variables: " +
        missing.join(", ") +
        " (cf. compose/.env.example)"
    );
    process.exit(1);
  }
  app.listen(PORT, () => {
    console.log(`auth-bridge listening on ${PORT}`);
  });
}

const MCP_ISSUER = ISSUER;
// URL of the OAuth Protected Resource metadata (RFC 9728) served by
// the gateway for an MCP resource. Returned in the WWW-Authenticate
// challenge of 401 and 403 responses (MCP 2026-07-28).
function mcpResourceMetadataURL(resource) {
  const r = resource || MCP_RESOURCES[0];
  return r
    ? new URL(r).origin + "/.well-known/oauth-protected-resource"
    : null;
}

app.get("/auth/mcp", async (req, res) => {
  try {
    const requiredScope = (req.get("x-mcp-scope") || MCP_SCOPE).trim();

    // Per-endpoint audience: the gateway passes the protected resource
    // identifier of the endpoint it is gating (X-MCP-Resource). It must
    // be one of the declared resources (fail-closed); absent, we accept
    // any declared audience (historical single-resource behaviour).
    const target = (req.get("x-mcp-resource") || "").trim();
    const audience = resolveMCPAudience(target);
    if (!audience) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Unknown MCP resource"
      });
    }

    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Bearer token required"
      });
    }

    const token = authorization.substring("Bearer ".length).trim();

    if (!token) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Bearer token required"
      });
    }

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: MCP_ISSUER,
      audience
    });

    if (!payload.sub) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Token has no subject"
      });
    }

    // Session revoked via backchannel logout: same treatment as an
    // invalid token (no-op if the token has no sid).
    if (isSidRevoked(payload.sid)) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Session revoked"
      });
    }

    const scopes = String(payload.scope || "")
      .split(/\s+/)
      .filter(Boolean);

    if (!scopes.includes(requiredScope)) {
      res.setHeader(
        "WWW-Authenticate",
        `Bearer error="insufficient_scope", scope="${requiredScope}", resource_metadata="${mcpResourceMetadataURL(target)}"`
      );

      return res.status(403).json({
        error: "insufficient_scope",
        error_description: `${requiredScope} scope required`
      });
    }

    res.setHeader("X-User-Id", String(payload.sub));
    res.setHeader(
      "X-Username",
      String(payload.preferred_username || "")
    );
    res.setHeader(
      "X-Email",
      String(payload.email || "")
    );

    const roles = Array.isArray(payload.realm_access?.roles)
      ? payload.realm_access.roles
      : [];

    res.setHeader("X-Roles", roles.join(","));

    if (payload.exp) {
      res.setHeader("X-Auth-Expires", String(payload.exp));
    }

    return res.status(200).end();

  } catch (err) {
    console.error("MCP authentication failed:", err);

    return res.status(401).json({
      error: "invalid_token",
      error_description: "Invalid or expired access token"
    });
  }
});
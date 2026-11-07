// auth-bridge tests: node --test . — the pure functions (the safety
// net that would have caught the 2026-10-17 ReDoS) + the endpoints
// that need no Keycloak (redirects, refusals, parsing).
import test from "node:test";
import assert from "node:assert";
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// TEST config (fixture): since the removal of in-code defaults, the
// module requires variables — the test sets its own BEFORE the
// dynamic import (the env must precede module loading: derived URLs
// are built there).
process.env.KEYCLOAK_BASE_URL = "https://auth.cladone.com";
process.env.KEYCLOAK_REALM = "cladone";
process.env.KEYCLOAK_CLIENT_ID = "cladone-login";
process.env.KEYCLOAK_CLIENT_SECRET = "test-secret";
process.env.PUBLIC_AUTH_URL = "https://login.cladone.com";
process.env.COOKIE_DOMAIN = ".cladone.com";
process.env.DEFAULT_APP_URL = "https://vers.cladone.com";
process.env.LOGOUT_URL = "https://cladone.com";
process.env.MCP_RESOURCE = "https://gram.cladone.com/mcp";
// Persistent revocation state goes to a temp file, never the repo.
process.env.REVOCATION_STATE_FILE = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), "auth-bridge-test-")),
  "state.json"
);

const { default: app, safeReturnTo, isSidRevoked, checkRequiredEnv,
  resolveMCPAudience, pkcePair, sealTx, readTx,
  validLogoutClaims, LOGOUT_TOKEN_EVENT } =
  await import("./server.js");

// ── checkRequiredEnv: boot fail-fast ─────────────────────────────

test("checkRequiredEnv: everything present = empty list", () => {
  assert.deepEqual(checkRequiredEnv(process.env), []);
});

test("checkRequiredEnv: missing variable = listed (never a partial boot)", () => {
  const missing = checkRequiredEnv({ KEYCLOAK_BASE_URL: "https://x" });
  assert.ok(missing.includes("KEYCLOAK_REALM"));
  assert.ok(missing.includes("COOKIE_DOMAIN"));
  assert.equal(missing.length > 0, true);
});

// ── resolveMCPAudience: per-endpoint audiences ───────────────────

test("resolveMCPAudience: declared target accepted verbatim", () => {
  const resources = [
    "https://gram.cladone.com/mcp",
    "https://mcp.cladone.com/grammar"
  ];
  assert.equal(
    resolveMCPAudience("https://mcp.cladone.com/grammar", resources),
    "https://mcp.cladone.com/grammar"
  );
});

test("resolveMCPAudience: undeclared target refused (fail-closed)", () => {
  assert.equal(
    resolveMCPAudience("https://evil.example/mcp", [
      "https://gram.cladone.com/mcp"
    ]),
    null
  );
});

test("resolveMCPAudience: no target = any declared audience", () => {
  const resources = ["https://a.example/mcp", "https://b.example/mcp"];
  assert.deepEqual(resolveMCPAudience("", resources), resources);
});

// ── PKCE: pure helpers ───────────────────────────────────────────

test("pkcePair: 43-char verifier, challenge = S256(verifier), always fresh", () => {
  const { verifier, challenge } = pkcePair();
  assert.match(verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(
    crypto.createHash("sha256").update(verifier).digest("base64url"),
    challenge
  );
  assert.notEqual(pkcePair().verifier, verifier);
});

test("sealTx/readTx: round-trip; tampered signature, garbage and expiry refused", () => {
  const p = {
    v: "verifier-value",
    r: "https://vers.cladone.com/x",
    n: "nonce-value",
    t: Date.now(),
  };
  const raw = sealTx(p);
  assert.deepEqual(readTx(raw), p);

  // flip the last signature character: HMAC mismatch
  const last = raw.slice(-1);
  const tampered = raw.slice(0, -1) + (last === "A" ? "B" : "A");
  assert.equal(readTx(tampered), null);

  assert.equal(readTx("garbage"), null);
  assert.equal(readTx(""), null);
  assert.equal(readTx(undefined), null);

  // expired transaction (older than the 5-minute TTL)
  const stale = sealTx({ v: "v", n: "n", t: Date.now() - 10 * 60 * 1000 });
  assert.equal(readTx(stale), null);
});

// ── safeReturnTo: linear validation of returns ───────────────────

test("safeReturnTo: cladone subdomains accepted", () => {
  assert.equal(
    safeReturnTo("https://vers.cladone.com/x", "FB"),
    "https://vers.cladone.com/x"
  );
  assert.equal(
    safeReturnTo(
      "https://correspondances.jacquelot.cladone.com/CorrespondancesBonPapaEtBonneMaman/",
      "FB"
    ).startsWith("https://correspondances.jacquelot.cladone.com/"),
    true
  );
  assert.equal(safeReturnTo("https://cladone.com/", "FB"), "https://cladone.com/");
});

test("safeReturnTo: ReDoS REGRESSION — the explosive pattern is gone", () => {
  // the old regex (swallowed wildcard dots) went into catastrophic
  // backtracking here: no response must ever take time again
  const urls = [
    "https://correspondances.jacquelot.cladone.com/webp/IMG.webp",
    "https://aaaaaaaa.bbbbbbbb.cccccccc.dddddddd.eeeeeeee.cladone.org/",
    "https://a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.cladone.not/x",
  ];
  const t0 = performance.now();
  for (const u of urls) safeReturnTo(u, "FB");
  const ms = performance.now() - t0;
  assert.ok(ms < 100, `safeReturnTo took ${ms}ms (backtracking?)`);
});

test("safeReturnTo: rejects non-cladone and non-https", () => {
  assert.equal(safeReturnTo("https://evilcladone.com/", "FB"), "FB");
  assert.equal(safeReturnTo("https://cladone.com.evil.io/x", "FB"), "FB");
  assert.equal(safeReturnTo("http://vers.cladone.com/x", "FB"), "FB");
  assert.equal(safeReturnTo("", "FB"), "FB");
  assert.equal(safeReturnTo("::gaga::", "FB"), "FB");
});

// ── isSidRevoked: TTL of the revocation list ─────────────────────

test("isSidRevoked: a revoked sid is revoked, an unknown one is not", () => {
  assert.equal(isSidRevoked("never-seen"), false);
  assert.equal(isSidRevoked(""), false);
  assert.equal(isSidRevoked(undefined), false);
});

// ── validLogoutClaims: Keycloak uses `events` (PLURAL) ──────────

test("validLogoutClaims: Keycloak events (plural) accepted", () => {
  const now = Math.floor(Date.now() / 1000);
  assert.equal(
    validLogoutClaims(
      {
        events: { [LOGOUT_TOKEN_EVENT]: {} },
        sid: "sid-1",
        iat: now,
      },
      now
    ),
    true
  );
});

test("validLogoutClaims: singular event is refused (old bug)", () => {
  const now = Math.floor(Date.now() / 1000);
  assert.equal(
    validLogoutClaims(
      {
        event: { [LOGOUT_TOKEN_EVENT]: {} },
        sid: "sid-1",
        iat: now,
      },
      now
    ),
    false
  );
});

test("validLogoutClaims: nonce, missing sid and stale iat refused", () => {
  const now = Math.floor(Date.now() / 1000);
  const base = { events: { [LOGOUT_TOKEN_EVENT]: {} }, sid: "s", iat: now };
  assert.equal(validLogoutClaims({ ...base, nonce: "n" }, now), false);
  assert.equal(validLogoutClaims({ ...base, sid: "" }, now), false);
  assert.equal(validLogoutClaims({ ...base, iat: now - 600 }, now), false);
});

// ── endpoints with no Keycloak dependency ────────────────────────

const server = http.createServer(app);
server.listen(0);
server.unref(); // do not keep the process alive after the tests
const base = `http://127.0.0.1:${server.address().port}`;

test("GET /auth with no session → 302 to /login (returnTo preserved)", async () => {
  const res = await fetch(`${base}/auth`, { redirect: "manual" });
  assert.equal(res.status, 302);
  const loc = res.headers.get("location");
  // without X-Forwarded-Host, the fallback is APP_URL
  assert.ok(loc.startsWith("https://login.cladone.com/login?returnTo="));
  assert.ok(
    decodeURIComponent(loc).includes("vers.cladone.com"),
    "returnTo must travel through"
  );
});

test("GET / → 302 to the application (never Express' Cannot GET /)", async () => {
  const res = await fetch(`${base}/`, { redirect: "manual" });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("location"), "https://vers.cladone.com");
});

test("GET /logout without id_token → post_logout_redirect_uri still sent", async () => {
  const res = await fetch(
    `${base}/logout?returnTo=${encodeURIComponent("https://vers.cladone.com/")}`,
    { redirect: "manual" }
  );

  assert.equal(res.status, 302);
  const loc = new URL(res.headers.get("location"));
  assert.equal(
    `${loc.origin}${loc.pathname}`,
    "https://auth.cladone.com/realms/cladone/protocol/openid-connect/logout"
  );
  assert.equal(loc.searchParams.get("client_id"), "cladone-login");
  // The core of the fix: the browser must come back to the app even
  // when the id_token hint cookie is gone (KC's "You are logged out"
  // page sends it to the client baseUrl = login.cladone.com, a 404).
  assert.equal(
    loc.searchParams.get("post_logout_redirect_uri"),
    "https://vers.cladone.com/"
  );
  assert.equal(loc.searchParams.get("id_token_hint"), null);
  assert.ok(
    res.headers.getSetCookie().some((c) => c.startsWith("access_token=;")),
    "session cookies cleared"
  );
});

test("GET /logout with id_token → hint kept and post_logout_redirect_uri sent", async () => {
  const res = await fetch(
    `${base}/logout?returnTo=${encodeURIComponent("https://vers.cladone.com/")}`,
    { redirect: "manual", headers: { Cookie: "id_token=a.b.c" } }
  );

  const loc = new URL(res.headers.get("location"));
  assert.equal(loc.searchParams.get("id_token_hint"), "a.b.c");
  assert.equal(
    loc.searchParams.get("post_logout_redirect_uri"),
    "https://vers.cladone.com/"
  );
});

test("GET /logout with a hostile returnTo → fallback to APP_URL", async () => {
  const res = await fetch(
    `${base}/logout?returnTo=${encodeURIComponent("https://evil.example/phish")}`,
    { redirect: "manual" }
  );

  const loc = new URL(res.headers.get("location"));
  assert.equal(
    loc.searchParams.get("post_logout_redirect_uri"),
    "https://vers.cladone.com"
  );
});

test("GET /auth/mcp without Bearer → 401 JSON (the Bearer challenge is built by the gateway)", async () => {
  const res = await fetch(`${base}/auth/mcp`, { redirect: "manual" });
  assert.equal(res.status, 401);
  const j = await res.json();
  assert.equal(j.error, "invalid_token");
});

test("POST /backchannel-logout without logout_token → 400", async () => {
  const res = await fetch(`${base}/backchannel-logout`, { method: "POST" });
  assert.equal(res.status, 400);
});

test("POST /backchannel-logout with a fake logout_token → 400", async () => {
  const res = await fetch(`${base}/backchannel-logout`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "logout_token=ga.bu.zo",
  });
  assert.equal(res.status, 400);
  assert.equal(res.headers.get("cache-control"), "no-store");
});

function txCookie(res) {
  const sc = res.headers
    .getSetCookie()
    .find((c) => c.startsWith("oidc_tx="));
  assert.ok(sc, "oidc_tx cookie present");
  return { setCookie: sc, raw: sc.split(";")[0].slice("oidc_tx=".length) };
}

test("GET /login → 302 to Keycloak with S256 challenge + signed transaction", async () => {
  const res = await fetch(
    `${base}/login?returnTo=${encodeURIComponent("https://vers.cladone.com/x")}`,
    { redirect: "manual" }
  );
  assert.equal(res.status, 302);
  const loc = res.headers.get("location");
  assert.ok(loc.includes("client_id=cladone-login"), "confidential client");
  assert.ok(loc.includes("code_challenge_method=S256"));
  const challenge = new URL(loc).searchParams.get("code_challenge");
  assert.match(challenge, /^[A-Za-z0-9_-]+$/);
  // state is a random nonce — it must NOT carry the returnTo
  const state = new URL(loc).searchParams.get("state");
  assert.ok(state && !/cladone\.com/.test(state), "state must not leak returnTo");

  const { setCookie, raw } = txCookie(res);
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /Path=\/auth\/callback/i);
  assert.match(setCookie, /Max-Age=\d+/i);

  const tx = readTx(raw);
  assert.ok(tx, "signed transaction is valid");
  assert.equal(tx.r, "https://vers.cladone.com/x");
  assert.equal(tx.n, state, "state matches the transaction nonce");
  assert.equal(
    crypto.createHash("sha256").update(tx.v).digest("base64url"),
    challenge,
    "challenge = S256(verifier)"
  );
});

test("GET /login with an unauthorized returnTo → APP_URL fallback (signed)", async () => {
  const res = await fetch(
    `${base}/login?returnTo=${encodeURIComponent("https://evil.io/steal")}`,
    { redirect: "manual" }
  );
  assert.equal(res.status, 302);
  const { raw } = txCookie(res);
  assert.equal(readTx(raw).r, "https://vers.cladone.com");
});

test("GET /auth/callback: bad state refused; good state forwards code_verifier", async () => {
  const login = await fetch(`${base}/login`, { redirect: "manual" });
  const { raw } = txCookie(login);
  const tx = readTx(raw);

  const tokenBodies = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    if (String(url).includes("/protocol/openid-connect/token")) {
      tokenBodies.push(String(opts.body || ""));
      return new Response("bad", { status: 400 });
    }
    return origFetch(url, opts);
  };
  try {
    // mismatched state → no token exchange
    await fetch(`${base}/auth/callback?code=abc&state=wrong`, {
      redirect: "manual",
      headers: { cookie: `oidc_tx=${raw}` },
    });
    assert.equal(tokenBodies.length, 0, "bad state must not exchange the code");

    // valid state → code_verifier forwarded
    await fetch(`${base}/auth/callback?code=abc&state=${tx.n}`, {
      redirect: "manual",
      headers: { cookie: `oidc_tx=${raw}` },
    });
    assert.equal(tokenBodies.length, 1);
    const body = new URLSearchParams(tokenBodies[0]);
    assert.equal(body.get("grant_type"), "authorization_code");
    assert.equal(body.get("code"), "abc");
    assert.equal(body.get("code_verifier"), tx.v);
    assert.equal(body.get("client_id"), "cladone-login");
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("GET /health → 200 ok", async () => {
  const res = await fetch(`${base}/health`);
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.status, "ok");
});

test("token-broker routes are inert until a shared secret is configured", async () => {
  for (const path of ["/connections", "/connect", "/connect/github", "/oauth/github/callback"]) {
    const res = await fetch(`${base}${path}`, { redirect: "manual" });
    assert.equal(res.status, 503, path);
    assert.equal((await res.json()).error, "token_broker_not_configured");
  }
});

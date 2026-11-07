// Token-broker proxy routes: with a shared secret configured, the
// browser routes must prove a Keycloak session (or redirect to login)
// and the callback must reach the internal broker.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

process.env.KEYCLOAK_BASE_URL = "https://auth.cladone.com";
process.env.KEYCLOAK_REALM = "cladone";
process.env.KEYCLOAK_CLIENT_ID = "versifier";
process.env.KEYCLOAK_CLIENT_SECRET = "test-secret";
process.env.PUBLIC_AUTH_URL = "https://login.cladone.com";
process.env.COOKIE_DOMAIN = ".cladone.com";
process.env.DEFAULT_APP_URL = "https://vers.cladone.com";
process.env.LOGOUT_URL = "https://cladone.com";
process.env.MCP_RESOURCE = "https://gram.cladone.com/mcp";
process.env.TOKEN_BROKER_SHARED_SECRET = "broker-secret";
process.env.TOKEN_BROKER_URL = "http://127.0.0.1:1";
process.env.REVOCATION_STATE_FILE = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), "auth-bridge-broker-test-")),
  "state.json"
);

const { default: app } = await import("./server.js");

const server = http.createServer(app);
server.listen(0);
server.unref();
const base = `http://127.0.0.1:${server.address().port}`;

test("GET /connections without a session redirects to login with returnTo", async () => {
  const res = await fetch(`${base}/connections`, { redirect: "manual" });
  assert.equal(res.status, 302);
  const location = new URL(res.headers.get("location"));
  assert.equal(location.origin, "https://login.cladone.com");
  assert.equal(location.pathname, "/login");
  assert.equal(
    location.searchParams.get("returnTo"),
    "https://login.cladone.com/connections"
  );
});

test("GET /connect/:provider without a session redirects to login", async () => {
  const res = await fetch(`${base}/connect/github?returnTo=%2Fconnections`, {
    redirect: "manual",
  });
  assert.equal(res.status, 302);
  const returnTo = new URL(res.headers.get("location")).searchParams.get(
    "returnTo"
  );
  assert.match(returnTo, /^https:\/\/login\.cladone\.com\/connect\/github\?/);
});

test("an invalid access_token is treated as no session", async () => {
  const res = await fetch(`${base}/connections`, {
    headers: { Cookie: "access_token=not-a-jwt" },
    redirect: "manual",
  });
  assert.equal(res.status, 302);
  assert.ok(res.headers.get("location").includes("/login?returnTo="));
});

test("the callback does not require a session but reaches the broker", async () => {
  const res = await fetch(`${base}/oauth/github/callback?code=x&state=y`, {
    redirect: "manual",
  });
  assert.equal(res.status, 502);
  assert.equal((await res.json()).error, "token_broker_unavailable");
});

test("GET /connect is a shortcut to /connections", async () => {
  const res = await fetch(`${base}/connect`, { redirect: "manual" });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("location"), "/connections");
});

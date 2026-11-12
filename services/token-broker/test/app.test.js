import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { createApp } from "../src/app.js";
import { ProviderRegistry } from "../src/providers.js";
import { TokenStore } from "../src/store.js";
import { TokenService } from "../src/token-service.js";
import { startFakeProvider } from "./helpers/fake-oauth-provider.js";

const BROKER_SECRET = "broker-secret";
const USER = "user-1";

function auth(extra = {}) {
  return {
    "x-broker-secret": BROKER_SECRET,
    "x-user-id": USER,
    ...extra,
  };
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

async function setup(t, { providerOverrides = {}, configOverrides = {} } = {}) {
  const fake = await startFakeProvider();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "token-broker-app-"));
  const providersFile = path.join(directory, "providers.json");

  fs.writeFileSync(
    providersFile,
    JSON.stringify({
      providers: {
        mock: {
          display_name: "Mock",
          type: "oauth2",
          authorization_endpoint: `${fake.baseUrl}/authorize`,
          token_endpoint: `${fake.baseUrl}/token`,
          revocation_endpoint: `${fake.baseUrl}/revoke`,
          client_id: "client-1",
          client_secret_env: "MOCK_SECRET",
          scopes: ["read", "write"],
          pkce: true,
          refresh: true,
          ...providerOverrides,
        },
      },
    })
  );

  const config = {
    port: 0,
    databasePath: path.join(directory, "broker.db"),
    providersFile,
    sharedSecret: BROKER_SECRET,
    encryptionKey: crypto.randomBytes(32),
    publicBaseUrl: "http://127.0.0.1",
    returnToHosts: ["app.example", "127.0.0.1"],
    stateTtlMs: 60_000,
    refreshSkewMs: 60_000,
    httpTimeoutMs: 5_000,
    ...configOverrides,
  };

  const providers = new ProviderRegistry({
    file: providersFile,
    env: { MOCK_SECRET: "secret-1" },
  });
  const store = new TokenStore({
    filename: config.databasePath,
    encryptionKey: config.encryptionKey,
  });
  const tokenService = new TokenService({
    store,
    config,
    logger: { warn() {} },
  });
  const app = createApp({ config, providers, store, tokenService });
  const server = http.createServer(app);
  const port = await listen(server);

  t.after(async () => {
    await closeServer(server);
    store.close();
    await fake.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });

  return {
    base: `http://127.0.0.1:${port}`,
    fake,
    store,
    tokenService,
    config,
  };
}

function csrfFrom(html) {
  const meta = html.match(/name="csrf-token" content="([^"]+)"/);
  if (meta) return meta[1];
  const input = html.match(/name="_csrf" value="([^"]+)"/);
  assert.ok(input, "the connections page must carry a CSRF token");
  return input[1];
}

async function beginConnect(base, returnTo = "https://app.example/welcome") {
  const res = await fetch(
    `${base}/connect/mock?returnTo=${encodeURIComponent(returnTo)}`,
    { headers: auth(), redirect: "manual" }
  );

  assert.equal(res.status, 302);
  return new URL(res.headers.get("location"));
}

test("full authorization-code flow: connect, callback, token, disconnect", async (t) => {
  const { base, fake, store } = await setup(t);

  const authorize = await beginConnect(base);
  assert.equal(`${authorize.origin}${authorize.pathname}`, `${fake.baseUrl}/authorize`);
  assert.equal(authorize.searchParams.get("client_id"), "client-1");
  assert.equal(authorize.searchParams.get("response_type"), "code");
  assert.equal(authorize.searchParams.get("scope"), "read write");
  assert.equal(
    authorize.searchParams.get("redirect_uri"),
    "http://127.0.0.1/oauth/mock/callback"
  );
  assert.ok(authorize.searchParams.get("state"));
  assert.ok(authorize.searchParams.get("code_challenge"));

  fake.state.expectedRedirectUri = authorize.searchParams.get("redirect_uri");
  fake.state.expectedChallenge = authorize.searchParams.get("code_challenge");

  const state = authorize.searchParams.get("state");
  const callback = await fetch(
    `${base}/oauth/mock/callback?code=${encodeURIComponent(
      fake.state.validCode
    )}&state=${encodeURIComponent(state)}`,
    {
      headers: { "x-broker-secret": BROKER_SECRET },
      redirect: "manual",
    }
  );

  assert.equal(callback.status, 302);
  assert.equal(
    callback.headers.get("location"),
    "https://app.example/welcome?connected=mock"
  );

  assert.equal(fake.state.tokenRequests.length, 1);
  assert.equal(fake.state.tokenRequests[0].grant_type, "authorization_code");
  assert.equal(fake.state.tokenRequests[0].code_verifier.length > 20, true);
  assert.equal(fake.state.tokenRequests[0].client_secret, "secret-1");

  const token = await fetch(`${base}/token/mock`, { headers: auth() });
  assert.equal(token.status, 200);
  const tokenBody = await token.json();
  assert.equal(tokenBody.access_token, "access-1");
  assert.equal(tokenBody.token_type, "Bearer");
  assert.equal(tokenBody.provider, "mock");
  assert.deepEqual(tokenBody.scopes, ["read", "write"]);
  assert.equal("refresh_token" in tokenBody, false);

  const stored = store.getToken(USER, "mock");
  assert.equal(stored.refreshToken, "refresh-1");

  const connections = await fetch(`${base}/connections`, {
    headers: auth({ accept: "application/json" }),
  });
  assert.equal(connections.status, 200);
  const connectionsBody = await connections.json();
  assert.equal(connectionsBody.providers[0].connected, true);
  assert.equal(JSON.stringify(connectionsBody).includes("access-1"), false);

  const html = await fetch(`${base}/connections`, { headers: auth() });
  assert.equal(html.status, 200);
  const page = await html.text();
  assert.match(page, /Mock/);
  assert.match(page, /Connected/);
  assert.equal(page.includes("access-1"), false);

  const disconnected = await fetch(`${base}/token/mock`, {
    method: "DELETE",
    headers: auth(),
  });
  assert.equal(disconnected.status, 204);

  // Local deletion only: the provider is never contacted.
  assert.equal(fake.state.revokeRequests.length, 0);

  const missing = await fetch(`${base}/token/mock`, { headers: auth() });
  assert.equal(missing.status, 404);
  assert.equal((await missing.json()).error, "not_connected");
});

test("provider denial is redirected back with an explicit error", async (t) => {
  const { base, fake } = await setup(t);
  const authorize = await beginConnect(base);
  const state = authorize.searchParams.get("state");

  const callback = await fetch(
    `${base}/oauth/mock/callback?error=access_denied&error_description=denied&state=${encodeURIComponent(
      state
    )}`,
    {
      headers: { "x-broker-secret": BROKER_SECRET },
      redirect: "manual",
    }
  );

  assert.equal(callback.status, 302);
  const location = new URL(callback.headers.get("location"));
  assert.equal(location.origin, "https://app.example");
  assert.equal(location.searchParams.get("error"), "access_denied");
  assert.equal(location.searchParams.get("error_description"), "denied");
  assert.equal(fake.state.tokenRequests.length, 0);
});

test("expired access tokens are refreshed and rotated", async (t) => {
  const { base, fake, store } = await setup(t);

  store.upsertToken({
    userId: USER,
    provider: "mock",
    token: {
      accessToken: "old-access",
      refreshToken: "refresh-1",
      tokenType: "Bearer",
      scopes: ["read"],
      expiresAt: Date.now() - 1_000,
      refreshExpiresAt: Date.now() + 60_000,
    },
  });

  const res = await fetch(`${base}/token/mock`, { headers: auth() });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.access_token, "access-2");

  assert.equal(fake.state.tokenRequests.length, 1);
  assert.equal(fake.state.tokenRequests[0].grant_type, "refresh_token");
  assert.equal(fake.state.tokenRequests[0].refresh_token, "refresh-1");

  const stored = store.getToken(USER, "mock");
  assert.equal(stored.accessToken, "access-2");
  assert.equal(stored.refreshToken, "refresh-2");
});

test("concurrent calls share a single refresh", async (t) => {
  const { base, fake, store } = await setup(t);
  fake.state.refreshDelayMs = 100;

  store.upsertToken({
    userId: USER,
    provider: "mock",
    token: {
      accessToken: "old-access",
      refreshToken: "refresh-1",
      tokenType: "Bearer",
      scopes: ["read"],
      expiresAt: Date.now() - 1_000,
      refreshExpiresAt: Date.now() + 60_000,
    },
  });

  const [first, second] = await Promise.all([
    fetch(`${base}/token/mock`, { headers: auth() }),
    fetch(`${base}/token/mock`, { headers: auth() }),
  ]);

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal((await first.json()).access_token, "access-2");
  assert.equal((await second.json()).access_token, "access-2");
  assert.equal(
    fake.state.tokenRequests.filter((request) => request.grant_type === "refresh_token")
      .length,
    1
  );
});

test("a rejected refresh deletes the credential and asks for reauthorization", async (t) => {
  const { base, fake, store } = await setup(t);
  fake.state.failRefresh = true;

  store.upsertToken({
    userId: USER,
    provider: "mock",
    token: {
      accessToken: "old-access",
      refreshToken: "refresh-1",
      tokenType: "Bearer",
      scopes: ["read"],
      expiresAt: Date.now() - 1_000,
      refreshExpiresAt: Date.now() + 60_000,
    },
  });

  const first = await fetch(`${base}/token/mock`, { headers: auth() });
  assert.equal(first.status, 409);
  assert.equal((await first.json()).error, "reauthorization_required");
  assert.equal(store.getToken(USER, "mock"), null);

  const second = await fetch(`${base}/token/mock`, { headers: auth() });
  assert.equal(second.status, 404);
});

test("a provider outage does not delete a still-refreshable credential", async (t) => {
  const { base, fake, store } = await setup(t);
  fake.state.failRefresh = true;
  fake.state.refreshErrorStatus = 503;

  store.upsertToken({
    userId: USER,
    provider: "mock",
    token: {
      accessToken: "old-access",
      refreshToken: "refresh-1",
      tokenType: "Bearer",
      scopes: ["read"],
      expiresAt: Date.now() - 1_000,
      refreshExpiresAt: Date.now() + 60_000,
    },
  });

  const res = await fetch(`${base}/token/mock`, { headers: auth() });
  assert.equal(res.status, 502);
  assert.equal((await res.json()).error, "upstream_unavailable");
  assert.equal(store.getToken(USER, "mock").refreshToken, "refresh-1");
});

test("the broker secret, user header and provider name are enforced", async (t) => {
  const { base } = await setup(t);

  assert.equal((await fetch(`${base}/token/mock`)).status, 401);
  assert.equal(
    (await fetch(`${base}/token/mock`, {
      headers: { "x-broker-secret": "wrong", "x-user-id": USER },
    })).status,
    401
  );
  assert.equal(
    (await fetch(`${base}/token/mock`, {
      headers: { "x-broker-secret": BROKER_SECRET },
    })).status,
    401
  );
  assert.equal(
    (await fetch(`${base}/connect/mock`, {
      headers: { "x-broker-secret": BROKER_SECRET },
      redirect: "manual",
    })).status,
    401
  );
  assert.equal(
    (await fetch(`${base}/token/unknown`, { headers: auth() })).status,
    404
  );

  const invalidState = await fetch(`${base}/oauth/mock/callback?state=bogus`, {
    headers: { "x-broker-secret": BROKER_SECRET },
    redirect: "manual",
  });
  assert.equal(invalidState.status, 400);
  assert.match(await invalidState.text(), /Invalid authorization/);
});

test("the callback state is bound to the user", async (t) => {
  const { base } = await setup(t);
  const authorize = await beginConnect(base);
  const state = authorize.searchParams.get("state");

  const res = await fetch(
    `${base}/oauth/mock/callback?code=code-1&state=${encodeURIComponent(state)}`,
    {
      headers: {
        "x-broker-secret": BROKER_SECRET,
        "x-user-id": "someone-else",
      },
      redirect: "manual",
    }
  );

  assert.equal(res.status, 400);
});

test("connections page escapes provider-controlled strings", async (t) => {
  const { base } = await setup(t, {
    providerOverrides: { display_name: '<script>alert("x")</script>' },
  });

  const res = await fetch(`${base}/connections`, { headers: auth() });
  const page = await res.text();

  assert.equal(page.includes('<script>alert("x")</script>'), false);
  assert.equal(page.includes("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"), true);
});

test("health and providers endpoints expose no credentials", async (t) => {
  const { base } = await setup(t);

  const health = await fetch(`${base}/health`);
  assert.equal(health.status, 200);
  assert.equal((await health.json()).status, "ok");

  const providers = await fetch(`${base}/providers`, { headers: auth() });
  assert.equal(providers.status, 200);
  const body = await providers.json();
  assert.equal(body.providers[0].name, "mock");
  assert.equal(body.providers[0].connected, false);
  assert.equal(JSON.stringify(body).includes("secret-1"), false);
  assert.equal(JSON.stringify(body).includes("client-1"), false);
});

async function login(base, fake) {
  const authorize = await beginConnect(base);
  fake.state.expectedRedirectUri = authorize.searchParams.get("redirect_uri");
  fake.state.expectedChallenge = authorize.searchParams.get("code_challenge");
  const state = authorize.searchParams.get("state");
  const callback = await fetch(
    `${base}/oauth/mock/callback?code=${encodeURIComponent(
      fake.state.validCode
    )}&state=${encodeURIComponent(state)}`,
    {
      headers: { "x-broker-secret": BROKER_SECRET },
      redirect: "manual",
    }
  );
  assert.equal(callback.status, 302);
}

function formHeaders(extra = {}) {
  return auth({
    "content-type": "application/x-www-form-urlencoded",
    ...extra,
  });
}

test("disconnect pauses, connect resumes, erase deletes without provider calls", async (t) => {
  const { base, fake, store } = await setup(t);
  await login(base, fake);

  const page = await (await fetch(`${base}/connections`, { headers: auth() })).text();
  const csrf = csrfFrom(page);

  let res = await fetch(`${base}/token/mock`, { headers: auth() });
  assert.equal(res.status, 200);

  // Disconnect = pause: the row and the token stay.
  res = await fetch(`${base}/connections/mock/disconnect`, {
    method: "POST",
    headers: formHeaders(),
    body: `_csrf=${encodeURIComponent(csrf)}`,
    redirect: "manual",
  });
  assert.equal(res.status, 303);
  assert.ok(store.getToken(USER, "mock"));
  assert.equal((await fetch(`${base}/token/mock`, { headers: auth() })).status, 403);
  const pausedBody = await (
    await fetch(`${base}/token/mock`, { headers: auth() })
  ).json();
  assert.equal(pausedBody.error, "delegation_disabled");
  assert.ok(pausedBody.connect_url);

  // Connect = resume: the same credential is used, no new OAuth flow.
  res = await fetch(`${base}/connections/mock/connect`, {
    method: "POST",
    headers: formHeaders(),
    body: `_csrf=${encodeURIComponent(csrf)}`,
    redirect: "manual",
  });
  assert.equal(res.status, 303);
  assert.equal((await fetch(`${base}/token/mock`, { headers: auth() })).status, 200);
  assert.equal(fake.state.tokenRequests.length, 1);

  // Erase: local only.
  res = await fetch(`${base}/connections/mock/erase`, {
    method: "POST",
    headers: formHeaders(),
    body: `_csrf=${encodeURIComponent(csrf)}`,
    redirect: "manual",
  });
  assert.equal(res.status, 303);
  assert.equal(store.getToken(USER, "mock"), null);
  assert.equal(fake.state.revokeRequests.length, 0);
  assert.equal((await fetch(`${base}/token/mock`, { headers: auth() })).status, 404);
});

test("a stored credential for a removed provider is listed and eraseable", async (t) => {
  const { base, store } = await setup(t);
  store.upsertToken({
    userId: USER,
    provider: "gone",
    token: {
      accessToken: "old-access",
      refreshToken: "old-refresh",
      tokenType: "Bearer",
      scopes: [],
      expiresAt: null,
      refreshExpiresAt: null,
    },
  });

  const connections = await (
    await fetch(`${base}/connections`, { headers: auth({ accept: "application/json" }) })
  ).json();
  const gone = connections.providers.find((p) => p.name === "gone");
  assert.ok(gone, "removed provider must still be listed");
  assert.equal(gone.connected, true);
  assert.equal(gone.orphan, true);

  const page = await (await fetch(`${base}/connections`, { headers: auth() })).text();
  const csrf = csrfFrom(page);
  const res = await fetch(`${base}/connections/gone/erase`, {
    method: "POST",
    headers: formHeaders(),
    body: `_csrf=${encodeURIComponent(csrf)}`,
    redirect: "manual",
  });
  assert.equal(res.status, 303);
  assert.equal(store.getToken(USER, "gone"), null);
});

test("state-changing requests require the CSRF token and same origin", async (t) => {
  const { base } = await setup(t);
  const missing = await fetch(`${base}/connections/mock/disconnect`, {
    method: "POST",
    headers: formHeaders(),
    body: "_csrf=bad",
    redirect: "manual",
  });
  assert.equal(missing.status, 403);

  const page = await (await fetch(`${base}/connections`, { headers: auth() })).text();
  const csrf = csrfFrom(page);
  const cross = await fetch(`${base}/connections/erase-all`, {
    method: "POST",
    headers: formHeaders({
      origin: "https://evil.example",
    }),
    body: `_csrf=${encodeURIComponent(csrf)}`,
    redirect: "manual",
  });
  assert.equal(cross.status, 403);
});

test("the CSRF origin gate accepts the browser's legitimate variants", async (t) => {
  const { base, fake } = await setup(t);
  await login(base, fake);

  const page = await (await fetch(`${base}/connections`, { headers: auth() })).text();
  const csrf = csrfFrom(page);
  const body = `_csrf=${encodeURIComponent(csrf)}`;
  const post = (headers) =>
    fetch(`${base}/connections/mock/disconnect`, {
      method: "POST",
      headers: formHeaders(headers),
      body,
      redirect: "manual",
    });

  // The configured public host is http://127.0.0.1 (see setup).
  const matched = "http://127.0.0.1";

  // 1. Same origin, normal fetch metadata.
  assert.equal((await post({ origin: matched, "sec-fetch-site": "same-origin" })).status, 303);
  // 2. "same-site" on a same-origin POST: the false negative that broke
  //    Disconnect. The matching Origin is authoritative.
  assert.equal((await post({ origin: matched, "sec-fetch-site": "same-site" })).status, 303);
  // 3. Opaque origin ("null") + same-origin metadata.
  assert.equal((await post({ origin: "null", "sec-fetch-site": "same-origin" })).status, 303);
  // 4. Legacy browser: neither header.
  assert.equal((await post({})).status, 303);

  // Still refused: a foreign origin…
  let res = await post({ origin: "https://evil.example", "sec-fetch-site": "same-origin" });
  assert.equal(res.status, 403);
  assert.equal((await res.json()).error, "csrf_origin");
  // …and a cross-site request with no Origin to compare.
  res = await post({ "sec-fetch-site": "cross-site" });
  assert.equal(res.status, 403);
  assert.equal((await res.json()).error, "csrf_origin");
});

test("operator API lists, pauses, resumes and deletes without exposing tokens", async (t) => {
  const { base, store } = await setup(t, {
    configOverrides: { adminSecret: "admin-secret" },
  });
  store.upsertToken({
    userId: USER,
    provider: "mock",
    token: {
      accessToken: "access-1",
      refreshToken: "refresh-1",
      tokenType: "Bearer",
      scopes: ["read"],
      expiresAt: null,
      refreshExpiresAt: null,
    },
  });

  const admin = { "x-broker-admin-secret": "admin-secret" };

  const users = await fetch(`${base}/admin/users`, { headers: admin });
  assert.equal(users.status, 200);
  const usersBody = await users.json();
  assert.equal(usersBody.users[0].userId, USER);
  assert.equal(JSON.stringify(usersBody).includes("access-1"), false);

  const detail = await fetch(`${base}/admin/users/${USER}`, { headers: admin });
  assert.equal(detail.status, 200);
  const detailBody = await detail.json();
  assert.equal(detailBody.connections[0].provider, "mock");
  assert.equal(JSON.stringify(detailBody).includes("access-1"), false);

  let res = await fetch(`${base}/admin/users/${USER}/mock/pause`, {
    method: "POST",
    headers: admin,
  });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).paused, 1);

  res = await fetch(`${base}/admin/users/${USER}/mock/resume`, {
    method: "POST",
    headers: admin,
  });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).resumed, 1);

  res = await fetch(`${base}/admin/users/${USER}`, {
    method: "DELETE",
    headers: admin,
  });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).erased, 1);
  assert.equal(store.getToken(USER, "mock"), null);
});

test("the operator API is disabled without an admin secret", async (t) => {
  const { base } = await setup(t);
  const res = await fetch(`${base}/admin/users`, {
    headers: { "x-broker-admin-secret": "anything" },
  });
  assert.equal(res.status, 404);
});

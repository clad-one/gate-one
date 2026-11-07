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

  assert.equal(fake.state.revokeRequests.length, 2);
  assert.equal(fake.state.revokeRequests[0].token_type_hint, "refresh_token");
  assert.equal(fake.state.revokeRequests[1].token_type_hint, "access_token");

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

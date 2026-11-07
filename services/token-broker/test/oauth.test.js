import test from "node:test";
import assert from "node:assert/strict";
import { exchangeCode, normalizeTokenResponse } from "../src/oauth.js";

function provider(overrides = {}) {
  return {
    name: "mock",
    clientId: "client-1",
    clientSecret: "secret-1",
    tokenAuthMethod: "client_secret_post",
    tokenEndpoint: "https://provider.test/token",
    scopes: ["read"],
    ...overrides,
  };
}

test("expires_in=0 means the token is already expired", () => {
  const before = Date.now();
  const token = normalizeTokenResponse(
    { access_token: "a", expires_in: 0 },
    provider()
  );

  assert.notEqual(token.expiresAt, null);
  assert.ok(token.expiresAt >= before && token.expiresAt <= Date.now() + 1000);
});

test("expires_in is converted to an absolute expiry", () => {
  const token = normalizeTokenResponse(
    { access_token: "a", expires_in: 3600, refresh_token_expires_in: 7200 },
    provider()
  );

  assert.ok(token.expiresAt > Date.now() + 3_000_000);
  assert.ok(token.refreshExpiresAt > token.expiresAt);
});

test("a missing expires_in means no local expiry", () => {
  const token = normalizeTokenResponse({ access_token: "a" }, provider());
  assert.equal(token.expiresAt, null);
});

test("the code exchange never replays a secret through a redirect", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return new Response(
      JSON.stringify({ access_token: "access-1", token_type: "bearer" }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  };

  const token = await exchangeCode(provider(), {
    code: "code-1",
    redirectUri: "https://login.cladone.com/oauth/mock/callback",
    fetchImpl,
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(calls[0].options.method, "POST");
  assert.equal(token.accessToken, "access-1");
});

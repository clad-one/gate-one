import test from "node:test";
import assert from "node:assert/strict";
import { TokenService } from "../src/token-service.js";

function serviceWithSummary(summary) {
  const store = {
    listTokenSummaries: () => (summary ? [summary] : []),
  };
  return new TokenService({ store, config: {} });
}

const provider = { name: "mock", displayName: "Mock", scopes: ["read"] };

test("an expired refresh token is surfaced as reauth_required", () => {
  const now = Date.now();
  const service = serviceWithSummary({
    provider: "mock",
    scopes: ["read"],
    expiresAt: now + 60_000,
    refreshExpiresAt: now - 1_000,
    hasRefreshToken: true,
    updatedAt: now,
  });

  const [connection] = service.listConnections("user-1", [provider]);
  assert.equal(connection.connected, true);
  assert.equal(connection.reauth_required, true);
});

test("an expired access token with a live refresh token is not reauth_required", () => {
  const now = Date.now();
  const service = serviceWithSummary({
    provider: "mock",
    scopes: ["read"],
    expiresAt: now - 1_000,
    refreshExpiresAt: now + 60_000,
    hasRefreshToken: true,
    updatedAt: now,
  });

  const [connection] = service.listConnections("user-1", [provider]);
  assert.equal(connection.reauth_required, false);
});

test("an expired access token without a refresh token is reauth_required", () => {
  const now = Date.now();
  const service = serviceWithSummary({
    provider: "mock",
    scopes: ["read"],
    expiresAt: now - 1_000,
    refreshExpiresAt: null,
    hasRefreshToken: false,
    updatedAt: now,
  });

  const [connection] = service.listConnections("user-1", [provider]);
  assert.equal(connection.reauth_required, true);
});

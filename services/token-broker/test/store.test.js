import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { TokenStore } from "../src/store.js";

function tempStore() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "token-broker-store-"));
  const filename = path.join(directory, "broker.db");
  const store = new TokenStore({
    filename,
    encryptionKey: crypto.randomBytes(32),
  });

  return {
    directory,
    filename,
    store,
    cleanup() {
      store.close();
      fs.rmSync(directory, { recursive: true, force: true });
    },
  };
}

test("tokens round-trip and are encrypted at rest", (t) => {
  const { filename, store, cleanup } = tempStore();
  t.after(cleanup);

  store.upsertToken({
    userId: "user-1",
    provider: "mock",
    token: {
      accessToken: "access-token-plain-1",
      refreshToken: "refresh-token-plain-1",
      tokenType: "Bearer",
      scopes: ["read", "write"],
      expiresAt: Date.now() + 3_600_000,
      refreshExpiresAt: Date.now() + 7_200_000,
    },
  });

  const row = store.getToken("user-1", "mock");
  assert.equal(row.accessToken, "access-token-plain-1");
  assert.equal(row.refreshToken, "refresh-token-plain-1");
  assert.deepEqual(row.scopes, ["read", "write"]);

  const files = [filename, `${filename}-wal`, `${filename}-shm`]
    .filter((file) => fs.existsSync(file))
    .map((file) => fs.readFileSync(file).toString("latin1"))
    .join("");

  assert.equal(files.includes("access-token-plain-1"), false);
  assert.equal(files.includes("refresh-token-plain-1"), false);
});

test("upsert replaces the token but keeps created_at", (t) => {
  const { store, cleanup } = tempStore();
  t.after(cleanup);

  store.upsertToken({
    userId: "user-1",
    provider: "mock",
    token: {
      accessToken: "one",
      refreshToken: "r1",
      tokenType: "Bearer",
      scopes: ["read"],
      expiresAt: 1,
      refreshExpiresAt: 2,
    },
  });
  const first = store.getToken("user-1", "mock");

  store.upsertToken({
    userId: "user-1",
    provider: "mock",
    token: {
      accessToken: "two",
      refreshToken: null,
      tokenType: "Bearer",
      scopes: ["read", "write"],
      expiresAt: 3,
      refreshExpiresAt: null,
    },
  });
  const second = store.getToken("user-1", "mock");

  assert.equal(second.accessToken, "two");
  assert.equal(second.refreshToken, null);
  assert.deepEqual(second.scopes, ["read", "write"]);
  assert.equal(second.createdAt, first.createdAt);
});

test("listTokenSummaries never exposes token values", (t) => {
  const { store, cleanup } = tempStore();
  t.after(cleanup);

  store.upsertToken({
    userId: "user-1",
    provider: "mock",
    token: {
      accessToken: "secret-access",
      refreshToken: "secret-refresh",
      tokenType: "Bearer",
      scopes: ["read"],
      expiresAt: 123,
      refreshExpiresAt: 456,
    },
  });

  const summaries = store.listTokenSummaries("user-1");
  assert.equal(summaries.length, 1);
  assert.equal(summaries[0].provider, "mock");
  assert.equal(summaries[0].hasRefreshToken, true);
  assert.equal("accessToken" in summaries[0], false);
  assert.equal(JSON.stringify(summaries).includes("secret-access"), false);
});

test("deleteToken is idempotent", (t) => {
  const { store, cleanup } = tempStore();
  t.after(cleanup);

  store.upsertToken({
    userId: "user-1",
    provider: "mock",
    token: {
      accessToken: "a",
      refreshToken: null,
      tokenType: "Bearer",
      scopes: [],
      expiresAt: null,
      refreshExpiresAt: null,
    },
  });

  assert.equal(store.deleteToken("user-1", "mock"), true);
  assert.equal(store.deleteToken("user-1", "mock"), false);
  assert.equal(store.getToken("user-1", "mock"), null);
});

test("authorization states are one-time and expire", (t) => {
  const { store, cleanup } = tempStore();
  t.after(cleanup);

  store.createState({
    state: "state-1",
    userId: "user-1",
    provider: "mock",
    codeVerifier: "verifier-1",
    returnTo: "https://app.example/connections",
    ttlMs: 60_000,
  });

  const first = store.consumeState("state-1");
  assert.equal(first.userId, "user-1");
  assert.equal(first.codeVerifier, "verifier-1");
  assert.equal(store.consumeState("state-1"), null);

  store.createState({
    state: "state-expired",
    userId: "user-1",
    provider: "mock",
    codeVerifier: null,
    returnTo: "https://app.example/",
    ttlMs: -1,
  });
  assert.equal(store.consumeState("state-expired"), null);

  store.createState({
    state: "state-expired-2",
    userId: "user-1",
    provider: "mock",
    codeVerifier: null,
    returnTo: "https://app.example/",
    ttlMs: -1,
  });
  assert.equal(store.purgeExpiredStates(), 1);
});

test("pause keeps the credential and resume restores the delegation", (t) => {
  const { store, cleanup } = tempStore();
  t.after(cleanup);

  store.upsertToken({
    userId: "user-1",
    provider: "mock",
    token: {
      accessToken: "a",
      refreshToken: "r",
      tokenType: "Bearer",
      scopes: [],
      expiresAt: null,
      refreshExpiresAt: null,
    },
  });

  assert.equal(store.getToken("user-1", "mock").delegationEnabled, true);
  assert.equal(store.setDelegation("user-1", "mock", false), true);
  const paused = store.getToken("user-1", "mock");
  assert.equal(paused.delegationEnabled, false);
  assert.equal(paused.accessToken, "a");
  assert.ok(paused.pausedAt > 0);

  assert.equal(store.setDelegation("user-1", "mock", true), true);
  const resumed = store.getToken("user-1", "mock");
  assert.equal(resumed.delegationEnabled, true);
  assert.equal(resumed.pausedAt, null);
});

test("a fresh consent re-enables a paused delegation", (t) => {
  const { store, cleanup } = tempStore();
  t.after(cleanup);

  const token = {
    accessToken: "a",
    refreshToken: "r",
    tokenType: "Bearer",
    scopes: [],
    expiresAt: null,
    refreshExpiresAt: null,
  };
  store.upsertToken({ userId: "u", provider: "p", token });
  store.setDelegation("u", "p", false);
  store.upsertToken({ userId: "u", provider: "p", token: { ...token, accessToken: "b" }, enable: true });
  const row = store.getToken("u", "p");
  assert.equal(row.delegationEnabled, true);
  assert.equal(row.accessToken, "b");
});

test("retention purges paused rows only", (t) => {
  const { store, cleanup } = tempStore();
  t.after(cleanup);

  const token = {
    accessToken: "a",
    refreshToken: null,
    tokenType: "Bearer",
    scopes: [],
    expiresAt: null,
    refreshExpiresAt: null,
  };
  store.upsertToken({ userId: "u", provider: "active", token });
  store.upsertToken({ userId: "u", provider: "paused", token });
  store.setDelegation("u", "paused", false);

  // Old pause: force paused_at into the past.
  store.db
    .prepare("UPDATE tokens SET paused_at = ? WHERE provider = 'paused'")
    .run(Date.now() - 10 * 24 * 3600 * 1000);

  const removed = store.purgePausedBefore(
    Date.now() - 5 * 24 * 3600 * 1000
  );
  assert.equal(removed, 1);
  assert.ok(store.getToken("u", "active"));
  assert.equal(store.getToken("u", "paused"), null);
});

test("operator aggregates list users and provider names without tokens", (t) => {
  const { store, cleanup } = tempStore();
  t.after(cleanup);

  const token = {
    accessToken: "secret",
    refreshToken: null,
    tokenType: "Bearer",
    scopes: [],
    expiresAt: null,
    refreshExpiresAt: null,
  };
  store.upsertToken({ userId: "u1", provider: "p", token });
  store.upsertToken({ userId: "u1", provider: "gone", token });
  store.setDelegation("u1", "gone", false);

  const users = store.listUsers();
  assert.equal(users.length, 1);
  assert.equal(users[0].userId, "u1");
  assert.equal(users[0].connections, 2);
  assert.equal(users[0].paused, 1);
  assert.equal(JSON.stringify(users).includes("secret"), false);

  assert.deepEqual(store.providerNames().sort(), ["gone", "p"]);
  const stats = store.stats();
  assert.equal(stats.users, 1);
  assert.equal(stats.tokens, 2);
  assert.equal(stats.paused, 1);
});

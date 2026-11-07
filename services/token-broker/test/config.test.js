import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { loadConfig } from "../src/config.js";

function env(overrides = {}) {
  return {
    TOKEN_BROKER_SHARED_SECRET: "secret",
    TOKEN_BROKER_ENCRYPTION_KEY: crypto.randomBytes(32).toString("base64"),
    TOKEN_BROKER_PUBLIC_BASE_URL: "https://login.cladone.com",
    ...overrides,
  };
}

test("loadConfig applies secure defaults", () => {
  const config = loadConfig(env());

  assert.equal(config.port, 4000);
  assert.equal(config.publicBaseUrl, "https://login.cladone.com");
  assert.deepEqual(config.returnToHosts, ["login.cladone.com"]);
  assert.equal(config.databasePath, "/data/token-broker.db");
  assert.equal(config.stateTtlMs, 600_000);
  assert.equal(config.refreshSkewMs, 60_000);
});

test("loadConfig requires the shared secret and a 32-byte key", () => {
  assert.throws(() => loadConfig({}), /TOKEN_BROKER_SHARED_SECRET/);
  assert.throws(
    () =>
      loadConfig(
        env({ TOKEN_BROKER_ENCRYPTION_KEY: Buffer.from("short").toString("base64") })
      ),
    /32 bytes/
  );
});

test("loadConfig rejects an insecure public base URL", () => {
  assert.throws(
    () => loadConfig(env({ TOKEN_BROKER_PUBLIC_BASE_URL: "http://login.cladone.com" })),
    /https/
  );
  assert.equal(
    loadConfig(env({ TOKEN_BROKER_PUBLIC_BASE_URL: "http://127.0.0.1:4000" }))
      .publicBaseUrl,
    "http://127.0.0.1:4000"
  );
});

test("loadConfig rejects a public base URL with userinfo", () => {
  assert.throws(
    () =>
      loadConfig(
        env({
          TOKEN_BROKER_PUBLIC_BASE_URL: "https://user:pass@login.cladone.com",
        })
      ),
    /userinfo/
  );
});

test("loadConfig parses returnTo host suffixes and rejects malformed entries", () => {
  assert.deepEqual(
    loadConfig(
      env({ TOKEN_BROKER_RETURN_TO_HOSTS: ".cladone.com, app.example" })
    ).returnToHosts,
    [".cladone.com", "app.example"]
  );

  assert.throws(
    () =>
      loadConfig(
        env({ TOKEN_BROKER_RETURN_TO_HOSTS: "https://app.example/" })
      ),
    /comma-separated/
  );
});

test("loadConfig validates numeric bounds", () => {
  assert.throws(() => loadConfig(env({ PORT: "70000" })), /PORT/);
  assert.throws(
    () => loadConfig(env({ TOKEN_BROKER_STATE_TTL_SECONDS: "0" })),
    /STATE_TTL/
  );
});

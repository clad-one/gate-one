import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ProviderConfigError, ProviderRegistry } from "../src/providers.js";

function registryFile(document) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "token-broker-providers-"));
  const file = path.join(directory, "providers.json");
  fs.writeFileSync(file, JSON.stringify(document));
  return {
    file,
    cleanup() {
      fs.rmSync(directory, { recursive: true, force: true });
    },
  };
}

function provider(overrides = {}) {
  return {
    display_name: "Mock",
    type: "oauth2",
    authorization_endpoint: "http://127.0.0.1:9999/authorize",
    token_endpoint: "http://127.0.0.1:9999/token",
    client_id: "client-1",
    client_secret_env: "MOCK_SECRET",
    scopes: ["read", "read", "write"],
    ...overrides,
  };
}

test("loads enabled providers and normalizes scopes", (t) => {
  const { file, cleanup } = registryFile({ providers: { mock: provider() } });
  t.after(cleanup);

  const registry = new ProviderRegistry({
    file,
    env: { MOCK_SECRET: "secret" },
  });
  const mock = registry.getEnabled("mock");

  assert.equal(mock.name, "mock");
  assert.equal(mock.displayName, "Mock");
  assert.deepEqual(mock.scopes, ["read", "write"]);
  assert.equal(mock.pkce, true);
  assert.equal(mock.refresh, true);
  assert.equal(registry.listEnabled().length, 1);
  assert.equal(registry.publicInfo(mock).client_secret_env, undefined);
});

test("disabled providers may omit their secret and are not advertised", (t) => {
  const { file, cleanup } = registryFile({
    providers: { github: provider({ enabled: false }) },
  });
  t.after(cleanup);

  const registry = new ProviderRegistry({ file, env: {} });
  assert.equal(registry.get("github").enabled, false);
  assert.equal(registry.getEnabled("github"), null);
  assert.deepEqual(registry.listEnabled(), []);
});

test("an enabled provider with an empty secret refuses to load", (t) => {
  const { file, cleanup } = registryFile({ providers: { mock: provider() } });
  t.after(cleanup);

  assert.throws(
    () => new ProviderRegistry({ file, env: {} }),
    /MOCK_SECRET/
  );
});

test("token_auth_method none does not require a secret", (t) => {
  const { file, cleanup } = registryFile({
    providers: {
      public: provider({
        client_secret_env: undefined,
        token_auth_method: "none",
      }),
    },
  });
  t.after(cleanup);

  const registry = new ProviderRegistry({ file, env: {} });
  assert.equal(registry.getEnabled("public").clientSecret, null);
});

test("external plain-http endpoints are rejected", (t) => {
  const { file, cleanup } = registryFile({
    providers: {
      bad: provider({ token_endpoint: "http://evil.example/token" }),
    },
  });
  t.after(cleanup);

  assert.throws(() => new ProviderRegistry({ file, env: { MOCK_SECRET: "s" } }), /https/);
});

test("provider endpoints must not contain userinfo", (t) => {
  const { file, cleanup } = registryFile({
    providers: {
      bad: provider({ token_endpoint: "https://user:pass@evil.example/token" }),
    },
  });
  t.after(cleanup);

  assert.throws(
    () => new ProviderRegistry({ file, env: { MOCK_SECRET: "s" } }),
    /userinfo/
  );
});

test("authorization_params cannot override protocol parameters", (t) => {
  const { file, cleanup } = registryFile({
    providers: {
      bad: provider({ authorization_params: { state: "attacker" } }),
    },
  });
  t.after(cleanup);

  assert.throws(
    () => new ProviderRegistry({ file, env: { MOCK_SECRET: "s" } }),
    /must not override "state"/
  );
});

test("unknown types and malformed documents are rejected", (t) => {
  const a = registryFile({ providers: { mock: provider({ type: "saml" }) } });
  const b = registryFile({ providers: [] });
  t.after(() => {
    a.cleanup();
    b.cleanup();
  });

  assert.throws(
    () => new ProviderRegistry({ file: a.file, env: { MOCK_SECRET: "s" } }),
    /unsupported type/
  );
  assert.throws(
    () => new ProviderRegistry({ file: b.file, env: {} }),
    /providers/
  );
});

test("a direct provider map is accepted for simple registries", (t) => {
  const { file, cleanup } = registryFile({ mock: provider() });
  t.after(cleanup);

  const registry = new ProviderRegistry({
    file,
    env: { MOCK_SECRET: "secret" },
  });
  assert.equal(registry.getEnabled("mock").name, "mock");
});

test("missing registry file is a configuration error", () => {
  assert.throws(
    () => new ProviderRegistry({ file: "/definitely/not/here.json" }),
    ProviderConfigError
  );
});

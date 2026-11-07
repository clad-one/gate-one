import test from "node:test";
import assert from "node:assert/strict";
import {
  appendQuery,
  callbackUrl,
  connectUrl,
  resolveReturnTo,
} from "../src/urls.js";

const config = {
  publicBaseUrl: "https://login.cladone.com",
  returnToHosts: [".cladone.com"],
};

test("returnTo accepts the apex and subdomains of an allowed suffix", () => {
  assert.equal(
    resolveReturnTo("https://vers.cladone.com/x", config),
    "https://vers.cladone.com/x"
  );
  assert.equal(
    resolveReturnTo("https://cladone.com/", config),
    "https://cladone.com/"
  );
  assert.equal(
    resolveReturnTo("/connections", config),
    "https://login.cladone.com/connections"
  );
});

test("returnTo rejects other hosts, lookalikes, http and credentials", () => {
  const fallback = "https://login.cladone.com/connections";

  assert.equal(resolveReturnTo("https://evil.example/", config), fallback);
  assert.equal(resolveReturnTo("https://cladone.com.evil.io/", config), fallback);
  assert.equal(resolveReturnTo("https://evilcladone.com/", config), fallback);
  assert.equal(resolveReturnTo("http://vers.cladone.com/", config), fallback);
  assert.equal(
    resolveReturnTo("https://user:pass@vers.cladone.com/", config),
    fallback
  );
  assert.equal(
    resolveReturnTo("::garbage::", config),
    "https://login.cladone.com/::garbage::"
  );
});

test("returnTo defaults to the public host when no allow-list is set", () => {
  const local = {
    publicBaseUrl: "http://127.0.0.1:4000",
    returnToHosts: ["127.0.0.1"],
  };
  assert.equal(
    resolveReturnTo("http://127.0.0.1:4000/ok", local),
    "http://127.0.0.1:4000/ok"
  );
  assert.equal(
    resolveReturnTo("http://localhost:4000/no", local),
    "http://127.0.0.1:4000/connections"
  );
});

test("appendQuery preserves existing parameters and skips empty values", () => {
  assert.equal(
    appendQuery("https://app.example/cb?x=1", {
      connected: "github",
      error: "",
      error_description: undefined,
    }),
    "https://app.example/cb?x=1&connected=github"
  );
});

test("callback and connect URLs are built from the public base", () => {
  assert.equal(
    callbackUrl(config, "github"),
    "https://login.cladone.com/oauth/github/callback"
  );
  assert.equal(
    connectUrl(config, "github", "https://vers.cladone.com/"),
    "https://login.cladone.com/connect/github?returnTo=https%3A%2F%2Fvers.cladone.com%2F"
  );
});

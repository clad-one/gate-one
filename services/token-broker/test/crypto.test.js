import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  decrypt,
  encrypt,
  parseEncryptionKey,
  pkceChallenge,
  randomToken,
  secretsEqual,
} from "../src/crypto.js";

const KEY = crypto.randomBytes(32);

test("parseEncryptionKey accepts exactly 32 base64 bytes", () => {
  assert.equal(parseEncryptionKey(KEY.toString("base64")).length, 32);
  assert.throws(() => parseEncryptionKey(""), /required/);
  assert.throws(() => parseEncryptionKey(Buffer.from("short").toString("base64")), /32 bytes/);
});

test("encrypt/decrypt round-trip and random IV", () => {
  const a = encrypt(KEY, "access-token");
  const b = encrypt(KEY, "access-token");

  assert.notEqual(a, b);
  assert.equal(decrypt(KEY, a), "access-token");
  assert.equal(decrypt(KEY, b), "access-token");
});

test("tampered ciphertext is rejected by GCM", () => {
  const payload = encrypt(KEY, "access-token");
  const parts = payload.split(".");
  parts[3] = Buffer.from("tampered").toString("base64url");

  assert.throws(() => decrypt(KEY, parts.join(".")));
});

test("decrypting with another key fails", () => {
  const payload = encrypt(KEY, "access-token");
  const other = crypto.randomBytes(32);
  assert.throws(() => decrypt(other, payload));
});

test("secretsEqual is constant-time friendly and length-agnostic", () => {
  assert.equal(secretsEqual("abc", "abc"), true);
  assert.equal(secretsEqual("abc", "abd"), false);
  assert.equal(secretsEqual("abc", "abcdef"), false);
  assert.equal(secretsEqual(undefined, "abc"), false);
});

test("randomToken and PKCE produce URL-safe values", () => {
  const verifier = randomToken(32);
  assert.match(verifier, /^[A-Za-z0-9_-]+$/);
  assert.equal(pkceChallenge(verifier), pkceChallenge(verifier));
  assert.match(pkceChallenge(verifier), /^[A-Za-z0-9_-]+$/);
});

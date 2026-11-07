// revocation.js tests: persistence is the fix for the auth-bridge
// restart reactivation bug (an in-memory sid list restarts empty).
import test from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRevocationStore } from "./revocation.js";

function tmpFile() {
  return path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), "auth-bridge-rev-")),
    "state.json"
  );
}

test("revocation persists across a store restart", () => {
  const file = tmpFile();
  const now = 1_700_000_000_000;
  const first = createRevocationStore({ file, now: () => now });
  first.revoke("sid-1");
  assert.equal(first.isRevoked("sid-1"), true);
  assert.equal(first.isRevoked("sid-2"), false);

  const second = createRevocationStore({ file, now: () => now });
  assert.equal(second.isRevoked("sid-1"), true);
  assert.equal(second.size(), 1);
});

test("expired revocations are pruned at load", () => {
  const file = tmpFile();
  const now = 1_700_000_000_000;
  createRevocationStore({ file, now: () => now }).revoke("old");
  const later = now + 25 * 3600 * 1000;
  const reopened = createRevocationStore({ file, now: () => later });
  assert.equal(reopened.isRevoked("old"), false);
  assert.equal(reopened.size(), 0);
});

test("isRevoked expires without a restart", () => {
  const file = tmpFile();
  let now = 1_700_000_000_000;
  const store = createRevocationStore({ file, now: () => now });
  store.revoke("sid");
  assert.equal(store.isRevoked("sid"), true);
  now += 25 * 3600 * 1000;
  assert.equal(store.isRevoked("sid"), false);
});

test("a corrupt state file is a startup error (never an empty list)", () => {
  const file = tmpFile();
  fs.writeFileSync(file, "not json");
  assert.throws(
    () => createRevocationStore({ file }),
    /cannot read\/parse/
  );
});

test("an unexpected state shape is a startup error", () => {
  const file = tmpFile();
  fs.writeFileSync(file, JSON.stringify({ sids: ["not-an-object"] }));
  assert.throws(
    () => createRevocationStore({ file }),
    /unexpected shape/
  );
});

test("memory-only mode works without a file", () => {
  const store = createRevocationStore({ file: null });
  store.revoke("sid");
  assert.equal(store.isRevoked("sid"), true);
  assert.equal(store.file, null);
});

test("an empty sid is refused", () => {
  const store = createRevocationStore({ file: null });
  assert.throws(() => store.revoke(""), /empty sid/);
});

test("the state file is mode 0600 and valid JSON", () => {
  const file = tmpFile();
  const store = createRevocationStore({ file });
  store.revoke("sid");
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  const data = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(data.version, 1);
  assert.equal(typeof data.sids.sid, "number");
});

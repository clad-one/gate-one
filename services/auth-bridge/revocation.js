// Persistent revocation state for auth-bridge.
//
// auth-bridge is stateless (sessions live in browser cookies), but the
// back-channel logout `sid` list is the one piece that MUST survive a
// restart: an in-memory list restarts empty, so a session revoked
// before the restart could be accepted again once the process is back
// (session reactivation). This store keeps the list in a small JSON
// file, written atomically (tmp + fsync + rename).
//
// One writer only: auth-bridge is a single process. For HA, a shared
// backend (Redis) will replace this file; the interface is the same.
import fs from "node:fs";
import path from "node:path";

export const REVOCATION_TTL_MS = 24 * 3600 * 1000;

/**
 * createRevocationStore: load (or create) the state file and return the
 * in-memory view used on every /auth and /auth/mcp check.
 *
 * file = null → memory-only (tests / explicit ephemeral mode).
 * A missing file is created empty at boot (this also checks writability:
 * an unwritable path is a startup error, never a silent memory-only
 * fallback). A corrupt file is an error too: fail-closed, never start
 * with an empty revocation list.
 */
export function createRevocationStore({
  file = null,
  ttlMs = REVOCATION_TTL_MS,
  now = Date.now,
} = {}) {
  const sids = new Map(); // sid -> revocation timestamp (ms)

  function prune() {
    const t = now();
    for (const [sid, ts] of sids) {
      if (t - ts > ttlMs) sids.delete(sid);
    }
  }

  function load() {
    if (!file || !fs.existsSync(file)) return;
    let data;
    try {
      data = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (err) {
      throw new Error(
        `revocation state ${file}: cannot read/parse (${err.message})`
      );
    }
    if (
      !data ||
      typeof data !== "object" ||
      !data.sids ||
      typeof data.sids !== "object" ||
      Array.isArray(data.sids)
    ) {
      throw new Error(`revocation state ${file}: unexpected shape`);
    }
    for (const [sid, ts] of Object.entries(data.sids)) {
      if (
        typeof sid !== "string" ||
        sid === "" ||
        typeof ts !== "number" ||
        !Number.isFinite(ts)
      ) {
        throw new Error(`revocation state ${file}: invalid entry`);
      }
      if (now() - ts <= ttlMs) sids.set(sid, ts);
    }
  }

  function persist() {
    if (!file) return;
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const body = JSON.stringify({
      version: 1,
      sids: Object.fromEntries(sids),
    });
    const tmp = `${file}.tmp`;
    const fd = fs.openSync(tmp, "w", 0o600);
    try {
      fs.writeSync(fd, body);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, file);
  }

  load();
  prune();
  persist(); // fail-fast on an unwritable path, and persist the pruned state

  return {
    file,
    isRevoked(sid) {
      if (!sid) return false;
      const ts = sids.get(sid);
      if (ts === undefined) return false;
      if (now() - ts > ttlMs) {
        sids.delete(sid);
        return false;
      }
      return true;
    },
    revoke(sid) {
      if (!sid) throw new Error("revocation: empty sid");
      sids.set(sid, now());
      prune();
      persist();
    },
    prune,
    size() {
      return sids.size;
    },
  };
}

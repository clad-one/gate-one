import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { decrypt, encrypt } from "./crypto.js";

const SCHEMA_VERSION = 2;

export class TokenDecryptionError extends Error {}

const MIGRATIONS = [
  {
    version: 1,
    sql: `
      CREATE TABLE tokens (
        user_id             TEXT NOT NULL,
        provider            TEXT NOT NULL,
        access_token_enc    TEXT NOT NULL,
        refresh_token_enc   TEXT,
        token_type          TEXT NOT NULL DEFAULT 'Bearer',
        scopes              TEXT NOT NULL DEFAULT '',
        expires_at          INTEGER,
        refresh_expires_at  INTEGER,
        created_at          INTEGER NOT NULL,
        updated_at          INTEGER NOT NULL,
        PRIMARY KEY (user_id, provider)
      );

      CREATE TABLE oauth_states (
        state          TEXT PRIMARY KEY,
        user_id        TEXT NOT NULL,
        provider       TEXT NOT NULL,
        code_verifier  TEXT,
        return_to      TEXT NOT NULL,
        created_at     INTEGER NOT NULL,
        expires_at     INTEGER NOT NULL
      );

      CREATE INDEX oauth_states_expires_at
        ON oauth_states (expires_at);
    `,
  },
  {
    version: 2,
    sql: `
      ALTER TABLE tokens
        ADD COLUMN delegation_enabled INTEGER NOT NULL DEFAULT 1;
      ALTER TABLE tokens ADD COLUMN paused_at INTEGER;
      ALTER TABLE tokens ADD COLUMN last_used_at INTEGER;
    `,
  },
];

function splitScopes(raw) {
  return String(raw || "")
    .split(/\s+/)
    .filter(Boolean);
}

export class TokenStore {
  constructor({ filename, encryptionKey }) {
    if (!filename) throw new Error("database filename is required");
    if (!encryptionKey) throw new Error("encryption key is required");

    this.filename = filename;
    this.key = encryptionKey;

    if (filename !== ":memory:") {
      const directory = path.dirname(filename);
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      try {
        fs.chmodSync(directory, 0o700);
      } catch {
        // A pre-existing volume may not be owned by us; the container
        // user must still be able to write, so do not make this fatal.
      }
    }

    this.db = new Database(filename);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = FULL");
    this.db.pragma("busy_timeout = 5000");
    this.db.pragma("foreign_keys = ON");

    this.migrate();

    if (filename !== ":memory:") {
      try {
        fs.chmodSync(filename, 0o600);
      } catch {
        // Best effort; the parent directory is 0700.
      }
    }
  }

  migrate() {
    let version = this.db.pragma("user_version", { simple: true });

    if (version > SCHEMA_VERSION) {
      throw new Error(
        `database schema version ${version} is newer than this broker (${SCHEMA_VERSION})`
      );
    }

    for (const migration of MIGRATIONS) {
      if (version >= migration.version) continue;

      const run = this.db.transaction(() => {
        this.db.exec(migration.sql);
        this.db.pragma(`user_version = ${migration.version}`);
      });
      run();
      version = migration.version;
    }
  }

  ping() {
    this.db.prepare("SELECT 1").get();
    return true;
  }

  upsertToken({ userId, provider, token, enable = false }) {
    const now = Date.now();
    const encryptedAccess = encrypt(this.key, token.accessToken);
    const encryptedRefresh = token.refreshToken
      ? encrypt(this.key, token.refreshToken)
      : null;

    this.db
      .prepare(
        `
        INSERT INTO tokens (
          user_id, provider, access_token_enc, refresh_token_enc,
          token_type, scopes, expires_at, refresh_expires_at,
          created_at, updated_at, delegation_enabled, paused_at
        ) VALUES (
          @userId, @provider, @accessTokenEnc, @refreshTokenEnc,
          @tokenType, @scopes, @expiresAt, @refreshExpiresAt,
          @now, @now, 1, NULL
        )
        ON CONFLICT(user_id, provider) DO UPDATE SET
          access_token_enc   = excluded.access_token_enc,
          refresh_token_enc  = excluded.refresh_token_enc,
          token_type         = excluded.token_type,
          scopes             = excluded.scopes,
          expires_at         = excluded.expires_at,
          refresh_expires_at = excluded.refresh_expires_at,
          updated_at         = excluded.updated_at,
          -- A fresh consent (enable=true) resumes the delegation; a
          -- refresh keeps the current pause state.
          delegation_enabled = CASE WHEN @enable THEN 1
                                    ELSE tokens.delegation_enabled END,
          paused_at = CASE WHEN @enable THEN NULL ELSE tokens.paused_at END
        `
      )
      .run({
        userId,
        provider,
        accessTokenEnc: encryptedAccess,
        refreshTokenEnc: encryptedRefresh,
        tokenType: token.tokenType || "Bearer",
        scopes: (token.scopes || []).join(" "),
        expiresAt: token.expiresAt ?? null,
        refreshExpiresAt: token.refreshExpiresAt ?? null,
        now,
        enable: enable ? 1 : 0,
      });
  }

  getToken(userId, provider) {
    const row = this.db
      .prepare(
        `
        SELECT user_id, provider, access_token_enc, refresh_token_enc,
               token_type, scopes, expires_at, refresh_expires_at,
               created_at, updated_at, delegation_enabled, paused_at,
               last_used_at
        FROM tokens
        WHERE user_id = ? AND provider = ?
        `
      )
      .get(userId, provider);

    if (!row) return null;

    try {
      return {
        userId: row.user_id,
        provider: row.provider,
        accessToken: decrypt(this.key, row.access_token_enc),
        refreshToken: row.refresh_token_enc
          ? decrypt(this.key, row.refresh_token_enc)
          : null,
        tokenType: row.token_type,
        scopes: splitScopes(row.scopes),
        expiresAt: row.expires_at,
        refreshExpiresAt: row.refresh_expires_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        delegationEnabled: Boolean(row.delegation_enabled),
        pausedAt: row.paused_at,
        lastUsedAt: row.last_used_at,
      };
    } catch (err) {
      throw new TokenDecryptionError(
        `cannot decrypt stored token for ${provider}: ${err.message}`
      );
    }
  }

  listTokenSummaries(userId) {
    const rows = this.db
      .prepare(
        `
        SELECT provider, scopes, expires_at, refresh_expires_at,
               refresh_token_enc IS NOT NULL AS has_refresh_token,
               updated_at, created_at, delegation_enabled, paused_at,
               last_used_at
        FROM tokens
        WHERE user_id = ?
        `
      )
      .all(userId);

    return rows.map((row) => ({
      provider: row.provider,
      scopes: splitScopes(row.scopes),
      expiresAt: row.expires_at,
      refreshExpiresAt: row.refresh_expires_at,
      hasRefreshToken: Boolean(row.has_refresh_token),
      updatedAt: row.updated_at,
      createdAt: row.created_at,
      delegationEnabled: Boolean(row.delegation_enabled),
      pausedAt: row.paused_at,
      lastUsedAt: row.last_used_at,
    }));
  }

  deleteToken(userId, provider) {
    const result = this.db
      .prepare("DELETE FROM tokens WHERE user_id = ? AND provider = ?")
      .run(userId, provider);
    return result.changes > 0;
  }

  deleteAllTokens(userId) {
    return this.db
      .prepare("DELETE FROM tokens WHERE user_id = ?")
      .run(userId).changes;
  }

  setDelegation(userId, provider, enabled) {
    const result = this.db
      .prepare(
        `
        UPDATE tokens
        SET delegation_enabled = ?, paused_at = ?
        WHERE user_id = ? AND provider = ?
        `
      )
      .run(enabled ? 1 : 0, enabled ? null : Date.now(), userId, provider);
    return result.changes > 0;
  }

  setDelegationAll(userId, enabled) {
    return this.db
      .prepare(
        `
        UPDATE tokens
        SET delegation_enabled = ?, paused_at = ?
        WHERE user_id = ?
        `
      )
      .run(enabled ? 1 : 0, enabled ? null : Date.now(), userId).changes;
  }

  markUsed(userId, provider) {
    // Throttled: /token is called for every delegated upstream request;
    // one write per minute is enough for the "last used" display and
    // keeps the SQLite write rate bounded.
    const now = Date.now();
    this.db
      .prepare(
        `
        UPDATE tokens SET last_used_at = ?
        WHERE user_id = ? AND provider = ?
          AND (last_used_at IS NULL OR last_used_at < ?)
        `
      )
      .run(now, userId, provider, now - 60_000);
  }

  // listUsers feeds the operator API: one row per user, no token and no
  // provider detail.
  listUsers() {
    return this.db
      .prepare(
        `
        SELECT user_id,
               COUNT(*) AS connections,
               SUM(CASE WHEN delegation_enabled = 0 THEN 1 ELSE 0 END)
                 AS paused,
               MAX(COALESCE(last_used_at, updated_at, created_at))
                 AS last_activity
        FROM tokens
        GROUP BY user_id
        ORDER BY last_activity DESC
        `
      )
      .all()
      .map((row) => ({
        userId: row.user_id,
        connections: row.connections,
        paused: row.paused,
        lastActivity: row.last_activity,
      }));
  }

  // purgePausedBefore enforces the optional retention: paused rows only,
  // never an active delegation.
  purgePausedBefore(cutoff) {
    return this.db
      .prepare(
        `
        DELETE FROM tokens
        WHERE delegation_enabled = 0
          AND paused_at IS NOT NULL
          AND paused_at <= ?
        `
      )
      .run(cutoff).changes;
  }

  providerNames() {
    return this.db
      .prepare("SELECT DISTINCT provider FROM tokens ORDER BY provider")
      .all()
      .map((row) => row.provider);
  }

  stats() {
    const row = this.db
      .prepare(
        `
        SELECT COUNT(*) AS tokens,
               COUNT(DISTINCT user_id) AS users,
               SUM(CASE WHEN delegation_enabled = 0 THEN 1 ELSE 0 END)
                 AS paused
        FROM tokens
        `
      )
      .get();
    return {
      tokens: row.tokens || 0,
      users: row.users || 0,
      paused: row.paused || 0,
    };
  }

  createState({
    state,
    userId,
    provider,
    codeVerifier,
    returnTo,
    ttlMs,
  }) {
    const now = Date.now();
    this.db
      .prepare(
        `
        INSERT INTO oauth_states (
          state, user_id, provider, code_verifier, return_to,
          created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `
      )
      .run(
        state,
        userId,
        provider,
        codeVerifier ?? null,
        returnTo,
        now,
        now + ttlMs
      );
  }

  consumeState(state) {
    if (typeof state !== "string" || state === "") return null;

    const consume = this.db.transaction((value) => {
      const row = this.db
        .prepare(
          `
          SELECT state, user_id, provider, code_verifier, return_to,
                 created_at, expires_at
          FROM oauth_states
          WHERE state = ?
          `
        )
        .get(value);

      if (!row) return null;

      this.db.prepare("DELETE FROM oauth_states WHERE state = ?").run(value);
      return row;
    });

    const row = consume(state);
    if (!row) return null;
    if (row.expires_at <= Date.now()) return null;

    return {
      state: row.state,
      userId: row.user_id,
      provider: row.provider,
      codeVerifier: row.code_verifier,
      returnTo: row.return_to,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
    };
  }

  purgeExpiredStates(now = Date.now()) {
    return this.db
      .prepare("DELETE FROM oauth_states WHERE expires_at <= ?")
      .run(now).changes;
  }

  close() {
    this.db.close();
  }
}

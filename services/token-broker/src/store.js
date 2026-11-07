import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { decrypt, encrypt } from "./crypto.js";

const SCHEMA_VERSION = 1;

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

  upsertToken({ userId, provider, token }) {
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
          created_at, updated_at
        ) VALUES (
          @userId, @provider, @accessTokenEnc, @refreshTokenEnc,
          @tokenType, @scopes, @expiresAt, @refreshExpiresAt,
          @now, @now
        )
        ON CONFLICT(user_id, provider) DO UPDATE SET
          access_token_enc   = excluded.access_token_enc,
          refresh_token_enc  = excluded.refresh_token_enc,
          token_type         = excluded.token_type,
          scopes             = excluded.scopes,
          expires_at         = excluded.expires_at,
          refresh_expires_at = excluded.refresh_expires_at,
          updated_at         = excluded.updated_at
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
      });
  }

  getToken(userId, provider) {
    const row = this.db
      .prepare(
        `
        SELECT user_id, provider, access_token_enc, refresh_token_enc,
               token_type, scopes, expires_at, refresh_expires_at,
               created_at, updated_at
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
               updated_at
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
    }));
  }

  deleteToken(userId, provider) {
    const result = this.db
      .prepare("DELETE FROM tokens WHERE user_id = ? AND provider = ?")
      .run(userId, provider);
    return result.changes > 0;
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

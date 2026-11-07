import crypto from "node:crypto";

/**
 * Token encryption helpers.
 *
 * Tokens are encrypted by the application before they reach SQLite:
 * the database file (and its WAL) only ever contains ciphertext. The
 * key lives in the environment / Docker secret, never in the volume.
 *
 * Ciphertext format:
 *   v1.<iv base64url>.<tag base64url>.<ciphertext base64url>
 *
 * The version prefix leaves room for a future key rotation / format
 * change without guessing from the blob length.
 */

const VERSION = "v1";
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export class CryptoConfigError extends Error {}

export function parseEncryptionKey(raw) {
  if (!raw || typeof raw !== "string") {
    throw new CryptoConfigError(
      "TOKEN_BROKER_ENCRYPTION_KEY is required (32 bytes, base64)"
    );
  }

  let key;
  try {
    key = Buffer.from(raw.trim(), "base64");
  } catch {
    throw new CryptoConfigError(
      "TOKEN_BROKER_ENCRYPTION_KEY is not valid base64"
    );
  }

  if (key.length !== KEY_BYTES) {
    throw new CryptoConfigError(
      `TOKEN_BROKER_ENCRYPTION_KEY must decode to ${KEY_BYTES} bytes (got ${key.length})`
    );
  }

  return key;
}

export function encrypt(key, plaintext) {
  if (typeof plaintext !== "string" || plaintext.length === 0) {
    throw new TypeError("plaintext must be a non-empty string");
  }

  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return [
    VERSION,
    iv.toString("base64url"),
    tag.toString("base64url"),
    ciphertext.toString("base64url"),
  ].join(".");
}

export function decrypt(key, payload) {
  if (typeof payload !== "string") {
    throw new TypeError("ciphertext must be a string");
  }

  const parts = payload.split(".");
  if (parts.length !== 4 || parts[0] !== VERSION) {
    throw new Error("unsupported ciphertext format");
  }

  const iv = Buffer.from(parts[1], "base64url");
  const tag = Buffer.from(parts[2], "base64url");
  const ciphertext = Buffer.from(parts[3], "base64url");

  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new Error("invalid ciphertext components");
  }

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
}

/**
 * Constant-time comparison of two secrets of arbitrary length.
 * Hashing first avoids leaking the expected length through an early
 * return (a normal `timingSafeEqual` throws on different lengths).
 */
export function secretsEqual(provided, expected) {
  if (typeof provided !== "string" || typeof expected !== "string") {
    return false;
  }

  const a = crypto.createHash("sha256").update(provided).digest();
  const b = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function pkceChallenge(verifier) {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

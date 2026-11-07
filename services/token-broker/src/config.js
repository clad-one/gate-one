import { parseEncryptionKey, CryptoConfigError } from "./crypto.js";

const DEFAULT_PUBLIC_BASE_URL = "https://login.cladone.com";
const DEFAULT_STATE_TTL_SECONDS = 10 * 60;
const DEFAULT_REFRESH_SKEW_SECONDS = 60;
const DEFAULT_HTTP_TIMEOUT_SECONDS = 15;

export class ConfigError extends Error {}

export function isLoopbackHostname(hostname) {
  const host = String(hostname).toLowerCase();
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

export function assertHttpUrl(raw, label) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError(`${label} is not a valid URL`);
  }

  if (url.username || url.password) {
    throw new ConfigError(`${label} must not contain userinfo`);
  }

  if (url.protocol === "https:") return url;
  if (url.protocol === "http:" && isLoopbackHostname(url.hostname)) return url;

  throw new ConfigError(`${label} must use https (http is only allowed on loopback)`);
}

function integerEnv(env, key, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = env[key];
  if (raw === undefined || raw === "") return fallback;

  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new ConfigError(`${key} must be an integer between ${min} and ${max}`);
  }

  return value;
}

function parseReturnToHosts(raw, fallbackHost) {
  const hosts = String(raw || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);

  if (hosts.length === 0) {
    return [fallbackHost.toLowerCase()];
  }

  for (const host of hosts) {
    if (
      host.includes("/") ||
      host.includes(":") ||
      host.includes("@") ||
      host === "." ||
      (host.startsWith(".") && host.length === 1)
    ) {
      throw new ConfigError(
        "TOKEN_BROKER_RETURN_TO_HOSTS must be a comma-separated list of hosts or .suffixes"
      );
    }
  }

  return [...new Set(hosts)];
}

export function loadConfig(env = process.env) {
  const missing = [
    "TOKEN_BROKER_SHARED_SECRET",
    "TOKEN_BROKER_ENCRYPTION_KEY",
  ].filter((key) => !env[key]);

  if (missing.length > 0) {
    throw new ConfigError(
      `missing required environment variables: ${missing.join(", ")}`
    );
  }

  const publicBaseUrl = (
    env.TOKEN_BROKER_PUBLIC_BASE_URL || DEFAULT_PUBLIC_BASE_URL
  ).replace(/\/+$/, "");
  const publicUrl = assertHttpUrl(
    publicBaseUrl,
    "TOKEN_BROKER_PUBLIC_BASE_URL"
  );

  if (publicUrl.search || publicUrl.hash) {
    throw new ConfigError(
      "TOKEN_BROKER_PUBLIC_BASE_URL must not contain a query string or fragment"
    );
  }

  let encryptionKey;
  try {
    encryptionKey = parseEncryptionKey(env.TOKEN_BROKER_ENCRYPTION_KEY);
  } catch (err) {
    if (err instanceof CryptoConfigError) {
      throw new ConfigError(err.message);
    }
    throw err;
  }

  return {
    port: integerEnv(env, "PORT", 4000, { max: 65535 }),
    databasePath:
      env.TOKEN_BROKER_DB_PATH || "/data/token-broker.db",
    providersFile:
      env.TOKEN_BROKER_PROVIDERS_FILE || "/app/providers.json",
    sharedSecret: env.TOKEN_BROKER_SHARED_SECRET,
    encryptionKey,
    publicBaseUrl,
    returnToHosts: parseReturnToHosts(
      env.TOKEN_BROKER_RETURN_TO_HOSTS,
      publicUrl.hostname
    ),
    stateTtlMs:
      integerEnv(env, "TOKEN_BROKER_STATE_TTL_SECONDS", DEFAULT_STATE_TTL_SECONDS, {
        max: 3600,
      }) * 1000,
    refreshSkewMs:
      integerEnv(env, "TOKEN_BROKER_REFRESH_SKEW_SECONDS", DEFAULT_REFRESH_SKEW_SECONDS, {
        max: 3600,
      }) * 1000,
    httpTimeoutMs:
      integerEnv(env, "TOKEN_BROKER_HTTP_TIMEOUT_SECONDS", DEFAULT_HTTP_TIMEOUT_SECONDS, {
        max: 120,
      }) * 1000,
  };
}

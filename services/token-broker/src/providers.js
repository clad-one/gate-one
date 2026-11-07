import fs from "node:fs";

const PROVIDER_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const TOKEN_AUTH_METHODS = new Set([
  "client_secret_post",
  "client_secret_basic",
  "none",
]);
const RESERVED_AUTHZ_PARAMS = new Set([
  "client_id",
  "redirect_uri",
  "response_type",
  "scope",
  "state",
  "code_challenge",
  "code_challenge_method",
]);

export class ProviderConfigError extends Error {}

function assertProviderUrl(raw, label) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new ProviderConfigError(`${label} is not a valid URL`);
  }

  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "::1";

  if (url.username || url.password) {
    throw new ProviderConfigError(`${label} must not contain userinfo`);
  }

  if (url.protocol === "https:" || (url.protocol === "http:" && loopback)) {
    return url.toString();
  }

  throw new ProviderConfigError(
    `${label} must use https (http is only allowed on loopback)`
  );
}

function stringArray(raw, label) {
  if (raw === undefined) return [];

  if (!Array.isArray(raw) || raw.some((value) => typeof value !== "string")) {
    throw new ProviderConfigError(`${label} must be an array of strings`);
  }

  return [...new Set(raw.map((value) => value.trim()).filter(Boolean))];
}

function normalizeProvider(name, raw, env) {
  if (!PROVIDER_NAME.test(name)) {
    throw new ProviderConfigError(`invalid provider name: ${name}`);
  }

  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ProviderConfigError(`provider "${name}" must be an object`);
  }

  const type = raw.type || "oauth2";
  if (type !== "oauth2") {
    throw new ProviderConfigError(
      `provider "${name}": unsupported type "${type}" (only oauth2)`
    );
  }

  const enabled = raw.enabled !== false;
  const displayName =
    typeof raw.display_name === "string" && raw.display_name.trim()
      ? raw.display_name.trim()
      : name;

  const authorizationEndpoint = assertProviderUrl(
    raw.authorization_endpoint,
    `provider "${name}".authorization_endpoint`
  );
  const tokenEndpoint = assertProviderUrl(
    raw.token_endpoint,
    `provider "${name}".token_endpoint`
  );

  if (typeof raw.client_id !== "string" || raw.client_id.trim() === "") {
    throw new ProviderConfigError(
      `provider "${name}".client_id must be a non-empty string`
    );
  }

  const tokenAuthMethod = raw.token_auth_method || "client_secret_post";
  if (!TOKEN_AUTH_METHODS.has(tokenAuthMethod)) {
    throw new ProviderConfigError(
      `provider "${name}".token_auth_method must be one of ${[
        ...TOKEN_AUTH_METHODS,
      ].join(", ")}`
    );
  }

  const pkce = raw.pkce !== false;
  const refresh = raw.refresh !== false;
  const scopes = stringArray(raw.scopes, `provider "${name}".scopes`);

  const revocationEndpoint = raw.revocation_endpoint
    ? assertProviderUrl(
        raw.revocation_endpoint,
        `provider "${name}".revocation_endpoint`
      )
    : null;

  const revocationAuthMethod =
    raw.revocation_auth_method || tokenAuthMethod;
  if (!TOKEN_AUTH_METHODS.has(revocationAuthMethod)) {
    throw new ProviderConfigError(
      `provider "${name}".revocation_auth_method is invalid`
    );
  }

  const needsClientSecret =
    tokenAuthMethod !== "none" ||
    (revocationEndpoint !== null && revocationAuthMethod !== "none");

  let clientSecret = null;
  let clientSecretEnv = null;

  if (needsClientSecret) {
    clientSecretEnv = raw.client_secret_env;
    if (typeof clientSecretEnv !== "string" || clientSecretEnv.trim() === "") {
      throw new ProviderConfigError(
        `provider "${name}".client_secret_env is required`
      );
    }

    clientSecretEnv = clientSecretEnv.trim();
    clientSecret = env[clientSecretEnv] || null;

    if (enabled && !clientSecret) {
      throw new ProviderConfigError(
        `provider "${name}" is enabled but ${clientSecretEnv} is empty`
      );
    }
  }

  const authorizationParams = raw.authorization_params || {};
  if (
    !authorizationParams ||
    typeof authorizationParams !== "object" ||
    Array.isArray(authorizationParams)
  ) {
    throw new ProviderConfigError(
      `provider "${name}".authorization_params must be an object`
    );
  }

  const cleanAuthorizationParams = {};
  for (const [key, value] of Object.entries(authorizationParams)) {
    if (RESERVED_AUTHZ_PARAMS.has(key)) {
      throw new ProviderConfigError(
        `provider "${name}".authorization_params must not override "${key}"`
      );
    }
    if (typeof value !== "string") {
      throw new ProviderConfigError(
        `provider "${name}".authorization_params.${key} must be a string`
      );
    }
    cleanAuthorizationParams[key] = value;
  }

  return Object.freeze({
    name,
    enabled,
    displayName,
    type,
    authorizationEndpoint,
    tokenEndpoint,
    clientId: raw.client_id.trim(),
    clientSecret,
    clientSecretEnv,
    tokenAuthMethod,
    pkce,
    refresh,
    scopes,
    revocationEndpoint,
    revocationAuthMethod,
    authorizationParams: Object.freeze(cleanAuthorizationParams),
  });
}

export class ProviderRegistry {
  constructor({ file, env = process.env }) {
    let document;
    try {
      document = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (err) {
      throw new ProviderConfigError(
        `cannot load provider registry ${file}: ${err.message}`
      );
    }

    const rawProviders =
      document && typeof document === "object" && !Array.isArray(document)
        ? document.providers ?? document
        : null;

    if (
      !rawProviders ||
      typeof rawProviders !== "object" ||
      Array.isArray(rawProviders)
    ) {
      throw new ProviderConfigError(
        "provider registry must contain an object under \"providers\""
      );
    }

    const providers = new Map();
    for (const [name, raw] of Object.entries(rawProviders)) {
      providers.set(name, normalizeProvider(name, raw, env));
    }

    this.providers = providers;
  }

  get(name) {
    return this.providers.get(name) || null;
  }

  getEnabled(name) {
    const provider = this.get(name);
    return provider && provider.enabled ? provider : null;
  }

  listEnabled() {
    return [...this.providers.values()].filter((provider) => provider.enabled);
  }

  publicInfo(provider) {
    return {
      name: provider.name,
      display_name: provider.displayName,
      scopes: [...provider.scopes],
      pkce: provider.pkce,
      refresh: provider.refresh,
    };
  }
}

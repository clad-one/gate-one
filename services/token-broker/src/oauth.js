import { pkceChallenge, randomToken } from "./crypto.js";

const DEFAULT_TIMEOUT_MS = 15_000;

export class OAuthError extends Error {
  constructor(message, { code = "oauth_error", description = "", upstreamStatus = null } = {}) {
    super(message);
    this.name = "OAuthError";
    this.code = code;
    this.description = description;
    this.upstreamStatus = upstreamStatus;
  }
}

export function isInvalidGrantError(err) {
  if (!(err instanceof OAuthError)) return false;
  if (err.upstreamStatus === 401) return true;
  return new Set([
    "invalid_grant",
    "invalid_token",
    "expired_token",
    "bad_refresh_token",
    "bad_verification_code",
    "unauthorized_client",
  ]).has(err.code);
}

function parseBody(text) {
  const trimmed = text.trim();
  if (!trimmed) return {};

  if (trimmed.startsWith("{")) {
    try {
      return JSON.parse(trimmed);
    } catch {
      return {};
    }
  }

  return Object.fromEntries(new URLSearchParams(trimmed));
}

async function postForm(
  url,
  params,
  { fetchImpl = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS, headers = {} } = {}
) {
  let response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        ...headers,
      },
      body: new URLSearchParams(params),
      // Never replay a client secret in a request body to a redirect
      // target chosen by the provider.
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    throw new OAuthError(`token endpoint request failed: ${err.message}`, {
      code: "network_error",
    });
  }

  const text = await response.text();
  const body = parseBody(text);

  if (!response.ok) {
    throw new OAuthError(
      `token endpoint returned ${response.status}`,
      {
        code: String(body.error || "token_endpoint_error"),
        description: String(body.error_description || ""),
        upstreamStatus: response.status,
      }
    );
  }

  if (body.error) {
    throw new OAuthError("token endpoint returned an OAuth error", {
      code: String(body.error),
      description: String(body.error_description || ""),
      upstreamStatus: response.status,
    });
  }

  return body;
}

function clientAuth(provider, method = provider.tokenAuthMethod) {
  if (method === "client_secret_basic") {
    const encoded = Buffer.from(
      `${provider.clientId}:${provider.clientSecret}`
    ).toString("base64");
    return { headers: { Authorization: `Basic ${encoded}` }, body: {} };
  }

  if (method === "client_secret_post") {
    return {
      headers: {},
      body: { client_secret: provider.clientSecret },
    };
  }

  return { headers: {}, body: {} };
}

function normalizeScopes(raw, fallback) {
  if (Array.isArray(raw)) {
    return [...new Set(raw.map(String).map((value) => value.trim()).filter(Boolean))];
  }
  if (typeof raw === "string" && raw.trim()) {
    return [...new Set(raw.trim().split(/[\s,]+/).filter(Boolean))];
  }
  return [...fallback];
}

function secondsToEpoch(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds < 0) return null;
  // expires_in=0 means "expires now", not "never expires".
  return Date.now() + Math.round(seconds * 1000);
}

export function normalizeTokenResponse(body, provider) {
  if (typeof body.access_token !== "string" || body.access_token === "") {
    throw new OAuthError("token endpoint response has no access_token", {
      code: "invalid_token_response",
    });
  }

  return {
    accessToken: body.access_token,
    refreshToken:
      typeof body.refresh_token === "string" && body.refresh_token
        ? body.refresh_token
        : null,
    tokenType: body.token_type ? String(body.token_type) : "Bearer",
    scopes: normalizeScopes(body.scope, provider.scopes),
    expiresAt: secondsToEpoch(body.expires_in),
    refreshExpiresAt: secondsToEpoch(body.refresh_token_expires_in),
  };
}

export function buildAuthorizationUrl(provider, { redirectUri, state, codeChallenge }) {
  const url = new URL(provider.authorizationEndpoint);
  url.searchParams.set("client_id", provider.clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);

  if (provider.scopes.length > 0) {
    url.searchParams.set("scope", provider.scopes.join(" "));
  }

  if (codeChallenge) {
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
  }

  for (const [key, value] of Object.entries(provider.authorizationParams)) {
    url.searchParams.set(key, value);
  }

  return url.toString();
}

export function newPkcePair() {
  const verifier = randomToken(32);
  return { verifier, challenge: pkceChallenge(verifier) };
}

export async function exchangeCode(
  provider,
  { code, redirectUri, codeVerifier, fetchImpl, timeoutMs }
) {
  const auth = clientAuth(provider);
  const body = {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: provider.clientId,
    ...auth.body,
  };

  if (codeVerifier) body.code_verifier = codeVerifier;

  const response = await postForm(provider.tokenEndpoint, body, {
    fetchImpl,
    timeoutMs,
    headers: auth.headers,
  });

  return normalizeTokenResponse(response, provider);
}

export async function refreshAccessToken(
  provider,
  { refreshToken, fetchImpl, timeoutMs }
) {
  const auth = clientAuth(provider);
  const response = await postForm(
    provider.tokenEndpoint,
    {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: provider.clientId,
      ...auth.body,
    },
    { fetchImpl, timeoutMs, headers: auth.headers }
  );

  return normalizeTokenResponse(response, provider);
}

export async function revokeToken(
  provider,
  { token, tokenTypeHint = "access_token", fetchImpl, timeoutMs }
) {
  if (!provider.revocationEndpoint) return false;

  const auth = clientAuth(provider, provider.revocationAuthMethod);
  const response = await postForm(
    provider.revocationEndpoint,
    {
      token,
      token_type_hint: tokenTypeHint,
      client_id: provider.clientId,
      ...auth.body,
    },
    { fetchImpl, timeoutMs, headers: auth.headers }
  );

  // RFC 7009 says a successful revocation is 200 (or 204). postForm
  // returns the parsed body; an error field would already have thrown.
  void response;
  return true;
}

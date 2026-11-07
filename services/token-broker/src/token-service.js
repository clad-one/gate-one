import { randomToken } from "./crypto.js";
import {
  buildAuthorizationUrl,
  exchangeCode,
  isInvalidGrantError,
  newPkcePair,
  OAuthError,
  refreshAccessToken,
  revokeToken,
} from "./oauth.js";
import { callbackUrl, connectUrl } from "./urls.js";

export class NotConnectedError extends Error {
  constructor(provider) {
    super(`no token stored for ${provider}`);
    this.name = "NotConnectedError";
    this.provider = provider;
  }
}

export class ReauthorizationRequiredError extends Error {
  constructor(provider, cause = null) {
    super(`reauthorization required for ${provider}`);
    this.name = "ReauthorizationRequiredError";
    this.provider = provider;
    this.cause = cause;
  }
}

export class UpstreamError extends Error {
  constructor(provider, cause = null) {
    super(`upstream provider unavailable for ${provider}`);
    this.name = "UpstreamError";
    this.provider = provider;
    this.cause = cause;
  }
}

export class InvalidStateError extends Error {
  constructor(message = "invalid or expired authorization state") {
    super(message);
    this.name = "InvalidStateError";
  }
}

export class OAuthCallbackError extends Error {
  constructor({ provider, code, description = "", returnTo }) {
    super(`authorization failed for ${provider}: ${code}`);
    this.name = "OAuthCallbackError";
    this.provider = provider;
    this.code = code;
    this.description = description;
    this.returnTo = returnTo;
  }
}

export class TokenService {
  constructor({ store, config, fetchImpl = globalThis.fetch, logger = console }) {
    this.store = store;
    this.config = config;
    this.fetchImpl = fetchImpl;
    this.logger = logger;
    this.inflightRefreshes = new Map();
  }

  beginConnect({ userId, provider, returnTo }) {
    const state = randomToken(32);
    const pkce = provider.pkce ? newPkcePair() : null;

    this.store.createState({
      state,
      userId,
      provider: provider.name,
      codeVerifier: pkce ? pkce.verifier : null,
      returnTo,
      ttlMs: this.config.stateTtlMs,
    });

    const url = buildAuthorizationUrl(provider, {
      redirectUri: callbackUrl(this.config, provider.name),
      state,
      codeChallenge: pkce ? pkce.challenge : null,
    });

    return { url, state };
  }

  async completeConnect({ provider, query, headerUserId = null }) {
    const stateRow = this.store.consumeState(query.state);
    if (!stateRow) throw new InvalidStateError();

    if (stateRow.provider !== provider.name) {
      throw new InvalidStateError("authorization state does not match provider");
    }

    if (headerUserId && headerUserId !== stateRow.userId) {
      throw new InvalidStateError("authorization state does not match user");
    }

    if (query.error) {
      throw new OAuthCallbackError({
        provider: provider.name,
        code: String(query.error),
        description: query.error_description ? String(query.error_description) : "",
        returnTo: stateRow.returnTo,
      });
    }

    if (typeof query.code !== "string" || query.code === "") {
      throw new OAuthCallbackError({
        provider: provider.name,
        code: "missing_code",
        description: "the provider did not return an authorization code",
        returnTo: stateRow.returnTo,
      });
    }

    let token;
    try {
      token = await exchangeCode(provider, {
        code: query.code,
        redirectUri: callbackUrl(this.config, provider.name),
        codeVerifier: stateRow.codeVerifier,
        fetchImpl: this.fetchImpl,
        timeoutMs: this.config.httpTimeoutMs,
      });
    } catch (err) {
      const code = err instanceof OAuthError ? err.code : "token_exchange_failed";
      const description = err instanceof OAuthError ? err.description : "";
      throw new OAuthCallbackError({
        provider: provider.name,
        code,
        description,
        returnTo: stateRow.returnTo,
      });
    }

    this.store.upsertToken({
      userId: stateRow.userId,
      provider: provider.name,
      token,
    });

    return { userId: stateRow.userId, returnTo: stateRow.returnTo };
  }

  async getAccessToken({ userId, provider }) {
    const row = this.store.getToken(userId, provider.name);
    if (!row) throw new NotConnectedError(provider.name);

    if (!this.#needsRefresh(row)) return row;

    if (!provider.refresh || !row.refreshToken) {
      throw new ReauthorizationRequiredError(provider.name);
    }

    return this.#refreshWithSingleFlight({ userId, provider, row });
  }

  async #refreshWithSingleFlight({ userId, provider, row }) {
    const key = `${userId}\u0000${provider.name}`;
    const existing = this.inflightRefreshes.get(key);
    if (existing) return existing;

    const promise = this.#refresh({ userId, provider, row }).finally(() => {
      if (this.inflightRefreshes.get(key) === promise) {
        this.inflightRefreshes.delete(key);
      }
    });

    this.inflightRefreshes.set(key, promise);
    return promise;
  }

  async #refresh({ userId, provider, row }) {
    // Another request may have refreshed while we were waiting for the
    // single-flight slot; re-read before spending the refresh token.
    const latest = this.store.getToken(userId, provider.name);
    if (!latest) throw new NotConnectedError(provider.name);
    if (!this.#needsRefresh(latest)) return latest;
    if (!latest.refreshToken) {
      throw new ReauthorizationRequiredError(provider.name);
    }

    let refreshed;
    try {
      refreshed = await refreshAccessToken(provider, {
        refreshToken: latest.refreshToken,
        fetchImpl: this.fetchImpl,
        timeoutMs: this.config.httpTimeoutMs,
      });
    } catch (err) {
      if (isInvalidGrantError(err)) {
        // The upstream says the refresh token can never work again.
        // Drop it so the next call asks for a new authorization
        // instead of looping on a dead credential.
        this.store.deleteToken(userId, provider.name);
        throw new ReauthorizationRequiredError(provider.name, err);
      }

      if (err instanceof OAuthError) {
        throw new UpstreamError(provider.name, err);
      }

      throw new UpstreamError(provider.name, err);
    }

    const merged = {
      accessToken: refreshed.accessToken,
      // Some providers rotate refresh tokens and return a new one;
      // keep the old one when they do not.
      refreshToken: refreshed.refreshToken || latest.refreshToken,
      tokenType: refreshed.tokenType || latest.tokenType,
      scopes:
        refreshed.scopes.length > 0 ? refreshed.scopes : latest.scopes,
      expiresAt: refreshed.expiresAt,
      refreshExpiresAt:
        refreshed.refreshExpiresAt ?? latest.refreshExpiresAt,
    };

    this.store.upsertToken({
      userId,
      provider: provider.name,
      token: merged,
    });

    return {
      ...latest,
      ...merged,
      updatedAt: Date.now(),
    };
  }

  #needsRefresh(row) {
    if (row.expiresAt === null || row.expiresAt === undefined) return false;
    return row.expiresAt <= Date.now() + this.config.refreshSkewMs;
  }

  async disconnect({ userId, provider }) {
    const row = this.store.getToken(userId, provider.name);
    if (!row) return false;

    if (provider.revocationEndpoint) {
      // Revocation is best effort: not every provider exposes a
      // revocation endpoint, and a provider outage must not prevent a
      // local disconnect.
      if (row.refreshToken) {
        try {
          await revokeToken(provider, {
            token: row.refreshToken,
            tokenTypeHint: "refresh_token",
            fetchImpl: this.fetchImpl,
            timeoutMs: this.config.httpTimeoutMs,
          });
        } catch (err) {
          this.logger.warn(
            `token revocation failed for provider ${provider.name}: ${err.message}`
          );
        }
      }

      try {
        await revokeToken(provider, {
          token: row.accessToken,
          tokenTypeHint: "access_token",
          fetchImpl: this.fetchImpl,
          timeoutMs: this.config.httpTimeoutMs,
        });
      } catch (err) {
        this.logger.warn(
          `token revocation failed for provider ${provider.name}: ${err.message}`
        );
      }
    }

    return this.store.deleteToken(userId, provider.name);
  }

  listConnections(userId, providers) {
    const summaries = new Map(
      this.store
        .listTokenSummaries(userId)
        .map((summary) => [summary.provider, summary])
    );
    const now = Date.now();

    return providers
      .map((provider) => {
        const summary = summaries.get(provider.name);
        const connected = Boolean(summary);

        return {
          name: provider.name,
          display_name: provider.displayName,
          scopes: summary?.scopes?.length ? summary.scopes : [...provider.scopes],
          connected,
          expires_at: summary?.expiresAt ?? null,
          refresh_expires_at: summary?.refreshExpiresAt ?? null,
          has_refresh_token: summary?.hasRefreshToken ?? false,
          updated_at: summary?.updatedAt ?? null,
          reauth_required: Boolean(
            summary &&
              ((summary.expiresAt &&
                summary.expiresAt <= now &&
                !summary.hasRefreshToken) ||
                (summary.refreshExpiresAt &&
                  summary.refreshExpiresAt <= now))
          ),
          connect_url: connectUrl(this.config, provider.name),
        };
      })
      .sort((a, b) => a.display_name.localeCompare(b.display_name));
  }

  connectUrl(provider, returnTo) {
    return connectUrl(this.config, provider.name, returnTo);
  }
}

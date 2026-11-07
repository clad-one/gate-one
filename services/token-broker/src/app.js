import express from "express";
import { secretsEqual } from "./crypto.js";
import { appendQuery, resolveReturnTo } from "./urls.js";
import {
  InvalidStateError,
  NotConnectedError,
  OAuthCallbackError,
  ReauthorizationRequiredError,
  UpstreamError,
} from "./token-service.js";

const CSP =
  "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; " +
  "form-action 'self'; frame-ancestors 'none'";

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatDate(value) {
  if (!value) return "never";
  return new Date(value).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}

function wantsJson(req) {
  return (
    (req.get("accept") || "").includes("application/json") ||
    req.path.startsWith("/token") ||
    req.path.startsWith("/providers")
  );
}

function asyncRoute(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function renderErrorPage(status, title, detail = "") {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:38rem;margin:3rem auto;padding:0 1rem;color:#1f2937}
h1{font-size:1.35rem}p{line-height:1.5}a{color:#1d4ed8}
</style></head>
<body><h1>${escapeHtml(title)}</h1>${
    detail ? `<p>${escapeHtml(detail)}</p>` : ""
  }<p><a href="/connections">Back to connections</a></p></body></html>`;
}

function renderConnectionsPage({ connections, query }) {
  const banners = [];

  if (typeof query.connected === "string" && query.connected) {
    banners.push(
      `<p class="banner ok">Connected to ${escapeHtml(query.connected)}.</p>`
    );
  }

  if (typeof query.disconnected === "string" && query.disconnected) {
    banners.push(
      `<p class="banner ok">Disconnected from ${escapeHtml(query.disconnected)}.</p>`
    );
  }

  if (typeof query.error === "string" && query.error) {
    const description =
      typeof query.error_description === "string" && query.error_description
        ? ` — ${query.error_description.slice(0, 200)}`
        : "";
    banners.push(
      `<p class="banner error">Authorization failed: ${escapeHtml(
        query.error
      )}${escapeHtml(description)}.</p>`
    );
  }

  const cards = connections
    .map((connection) => {
      const status = !connection.connected
        ? "Not connected"
        : connection.reauth_required
          ? "Reauthorization required"
          : "Connected";

      const classes = connection.connected
        ? connection.reauth_required
          ? "state warn"
          : "state ok"
        : "state";

      const details = connection.connected
        ? `<p>Scopes: ${escapeHtml(
            connection.scopes.length ? connection.scopes.join(", ") : "none"
          )}</p>
             <p>Token expiry: ${escapeHtml(
               formatDate(connection.expires_at)
             )}</p>`
        : "";

      const disconnect = connection.connected
        ? `<form method="post" action="/connections/${encodeURIComponent(
            connection.name
          )}/disconnect">
             <button class="danger" type="submit">Disconnect</button>
           </form>`
        : "";

      const label = connection.connected ? "Reconnect" : "Connect";

      return `<article class="card">
        <div class="card-head"><h2>${escapeHtml(
          connection.display_name
        )}</h2><span class="${classes}">${escapeHtml(status)}</span></div>
        ${details}
        <div class="actions">
          <a class="button" href="${escapeHtml(
            connection.connect_url
          )}">${label}</a>
          ${disconnect}
        </div>
      </article>`;
    })
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Service connections</title>
<style>
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;max-width:46rem;margin:2.5rem auto;padding:0 1rem;line-height:1.45;color:#111827;background:#f8fafc}
h1{font-size:1.5rem;margin-bottom:.25rem}.sub{color:#4b5563;margin-top:0}
.banner{border-radius:.5rem;padding:.7rem .9rem;margin:1rem 0;font-size:.95rem}
.banner.ok{background:#ecfdf5;border:1px solid #a7f3d0;color:#065f46}
.banner.error{background:#fef2f2;border:1px solid #fecaca;color:#991b1b}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:.75rem;padding:1rem 1.1rem;margin:1rem 0;box-shadow:0 1px 2px rgb(0 0 0 / .04)}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:1rem}
h2{font-size:1.1rem;margin:0}
p{margin:.4rem 0;color:#374151;font-size:.93rem}
.state{font-size:.78rem;font-weight:600;border-radius:999px;padding:.2rem .55rem;background:#f3f4f6;color:#4b5563}
.state.ok{background:#dcfce7;color:#166534}.state.warn{background:#fef3c7;color:#92400e}
.actions{display:flex;gap:.6rem;align-items:center;margin-top:.9rem;flex-wrap:wrap}
.button,button{font:inherit;font-size:.9rem;border-radius:.45rem;padding:.45rem .8rem;cursor:pointer;text-decoration:none}
.button{background:#1d4ed8;color:#fff;border:1px solid #1d4ed8}
button.danger{background:#fff;color:#b91c1c;border:1px solid #fca5a5}
.actions form{margin:0}
</style></head>
<body>
<h1>Service connections</h1>
<p class="sub">Allow Gate One to act on your behalf on external services.</p>
${banners.join("\n")}
${cards || '<p>No provider is configured.</p>'}
</body></html>`;
}

export function createApp({ config, providers, store, tokenService }) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", false);

  app.use(express.urlencoded({ extended: false, limit: "16kb" }));

  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  function requireBrokerSecret(req, res, next) {
    const provided = req.get("x-broker-secret") || "";
    if (!secretsEqual(provided, config.sharedSecret)) {
      return res.status(401).json({ error: "unauthorized" });
    }
    next();
  }

  function requireUser(req, res, next) {
    const userId = req.get("x-user-id");
    if (typeof userId !== "string" || userId.trim() === "" || userId.length > 256) {
      return res.status(401).json({ error: "unauthorized" });
    }
    req.userId = userId;
    next();
  }

  function loadProvider(req, res, next) {
    const provider = providers.getEnabled(req.params.provider);
    if (!provider) {
      return res.status(404).json({ error: "unknown_provider" });
    }
    req.provider = provider;
    next();
  }

  app.get("/health", (req, res) => {
    try {
      store.ping();
      res.json({
        status: "ok",
        providers: providers.listEnabled().length,
      });
    } catch {
      res.status(503).json({ status: "error" });
    }
  });

  app.get("/", (req, res) => {
    res.type("text/plain").send("token-broker");
  });

  app.get("/providers", requireBrokerSecret, (req, res) => {
    const userId = req.get("x-user-id") || null;
    res.json({
      providers: tokenService.listConnections(userId, providers.listEnabled()),
    });
  });

  app.get(
    "/connections",
    requireBrokerSecret,
    requireUser,
    (req, res) => {
      const connections = tokenService.listConnections(
        req.userId,
        providers.listEnabled()
      );

      if ((req.get("accept") || "").includes("application/json")) {
        return res.json({ providers: connections });
      }

      res.setHeader("Content-Security-Policy", CSP);
      return res
        .type("html")
        .send(renderConnectionsPage({ connections, query: req.query }));
    }
  );

  app.post(
    "/connections/:provider/disconnect",
    requireBrokerSecret,
    requireUser,
    loadProvider,
    asyncRoute(async (req, res) => {
      await tokenService.disconnect({
        userId: req.userId,
        provider: req.provider,
      });

      if ((req.get("accept") || "").includes("application/json")) {
        return res.status(204).end();
      }

      return res.redirect(
        303,
        `/connections?disconnected=${encodeURIComponent(req.provider.name)}`
      );
    })
  );

  app.get(
    "/connect/:provider",
    requireBrokerSecret,
    requireUser,
    loadProvider,
    (req, res) => {
      const returnTo = resolveReturnTo(req.query.returnTo, config);
      const { url } = tokenService.beginConnect({
        userId: req.userId,
        provider: req.provider,
        returnTo,
      });

      return res.redirect(302, url);
    }
  );

  app.get(
    "/oauth/:provider/callback",
    requireBrokerSecret,
    loadProvider,
    asyncRoute(async (req, res) => {
      try {
        const result = await tokenService.completeConnect({
          provider: req.provider,
          query: req.query,
          headerUserId: req.get("x-user-id") || null,
        });

        return res.redirect(
          302,
          appendQuery(result.returnTo, { connected: req.provider.name })
        );
      } catch (err) {
        if (err instanceof InvalidStateError) {
          res.setHeader("Content-Security-Policy", CSP);
          return res
            .status(400)
            .type("html")
            .send(
              renderErrorPage(
                400,
                "Invalid authorization",
                "The request has expired or was already used. Start again from the connections page."
              )
            );
        }

        if (err instanceof OAuthCallbackError) {
          const returnTo =
            err.returnTo || `${config.publicBaseUrl}/connections`;
          return res.redirect(
            302,
            appendQuery(returnTo, {
              error: err.code,
              error_description: err.description.slice(0, 200),
              provider: req.provider.name,
            })
          );
        }

        throw err;
      }
    })
  );

  app.get(
    "/token/:provider",
    requireBrokerSecret,
    requireUser,
    loadProvider,
    asyncRoute(async (req, res) => {
      try {
        const token = await tokenService.getAccessToken({
          userId: req.userId,
          provider: req.provider,
        });

        return res.json({
          provider: req.provider.name,
          access_token: token.accessToken,
          token_type: token.tokenType,
          expires_at: token.expiresAt,
          scopes: token.scopes,
        });
      } catch (err) {
        if (err instanceof NotConnectedError) {
          return res.status(404).json({
            error: "not_connected",
            provider: req.provider.name,
            connect_url: tokenService.connectUrl(req.provider),
          });
        }

        if (err instanceof ReauthorizationRequiredError) {
          return res.status(409).json({
            error: "reauthorization_required",
            provider: req.provider.name,
            connect_url: tokenService.connectUrl(req.provider),
          });
        }

        if (err instanceof UpstreamError) {
          return res.status(502).json({
            error: "upstream_unavailable",
            provider: req.provider.name,
          });
        }

        throw err;
      }
    })
  );

  app.delete(
    "/token/:provider",
    requireBrokerSecret,
    requireUser,
    loadProvider,
    asyncRoute(async (req, res) => {
      await tokenService.disconnect({
        userId: req.userId,
        provider: req.provider,
      });
      return res.status(204).end();
    })
  );

  app.use((req, res) => {
    if (wantsJson(req)) {
      return res.status(404).json({ error: "not_found" });
    }

    res.setHeader("Content-Security-Policy", CSP);
    return res
      .status(404)
      .type("html")
      .send(renderErrorPage(404, "Page not found"));
  });

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);

    if (err?.name === "TokenDecryptionError") {
      console.error("token-broker: stored token cannot be decrypted");
    } else {
      console.error(`token-broker: ${err?.name || "Error"}: ${err?.message || err}`);
    }

    if (wantsJson(req)) {
      return res.status(500).json({ error: "internal_error" });
    }

    res.setHeader("Content-Security-Policy", CSP);
    return res
      .status(500)
      .type("html")
      .send(
        renderErrorPage(
          500,
          "Internal error",
          "The broker could not process the request. Please try again later."
        )
      );
  });

  return app;
}

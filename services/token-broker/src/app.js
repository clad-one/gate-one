import crypto from "node:crypto";
import fs from "node:fs";
import express from "express";
import { secretsEqual } from "./crypto.js";
import { appendQuery, resolveReturnTo } from "./urls.js";
import {
  DelegationDisabledError,
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

// CSRF: a signed token bound to the authenticated user. The broker has
// no session of its own, so the token travels in the form and is
// verified against a key derived from the shared secret. State-changing
// requests also check Origin / Sec-Fetch-Site when the browser sends
// them.
function csrfToken(config, userId) {
  const nonce = crypto.randomBytes(16).toString("base64url");
  const sig = crypto
    .createHmac("sha256", config.sharedSecret)
    .update(`csrf\0${userId}\0${nonce}`)
    .digest("base64url");
  return `${nonce}.${sig}`;
}

function csrfValid(config, userId, value) {
  if (typeof value !== "string") return false;
  const dot = value.indexOf(".");
  if (dot <= 0) return false;
  const nonce = value.slice(0, dot);
  const sig = value.slice(dot + 1);
  const want = crypto
    .createHmac("sha256", config.sharedSecret)
    .update(`csrf\0${userId}\0${nonce}`)
    .digest("base64url");
  return secretsEqual(sig, want);
}

function sameOrigin(req, config) {
  const site = req.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") return false;
  const origin = req.get("origin");
  if (!origin) return true;
  try {
    return new URL(origin).host === new URL(config.publicBaseUrl).host;
  } catch {
    return false;
  }
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

function renderConnectionsPage({ connections, query, csrf }) {
  const banners = [];
  const banner = (ok, text) =>
    banners.push(
      `<p class="banner ${ok ? "ok" : "error"}">${escapeHtml(text)}</p>`
    );

  for (const key of ["connected", "paused", "resumed", "erased"]) {
    if (typeof query[key] === "string" && query[key]) {
      banner(
        true,
        `${key === "paused" ? "Delegation paused for" : key === "resumed" ? "Delegation resumed for" : key === "erased" ? "Credentials erased for" : "Connected to"} ${query[key]}.`
      );
    }
  }
  if (typeof query.erased_all === "string" && query.erased_all) {
    banner(true, "All your stored credentials have been erased.");
  }
  if (typeof query.error === "string" && query.error) {
    const description =
      typeof query.error_description === "string" && query.error_description
        ? ` — ${query.error_description.slice(0, 200)}`
        : "";
    banner(
      false,
      `Authorization failed: ${query.error}${description}.`
    );
  }

  const csrfInput = `<input type="hidden" name="_csrf" value="${escapeHtml(csrf)}">`;

  const actionForm = (name, action, label, extra = "") => `
    <form method="post" action="/connections/${encodeURIComponent(name)}/${action}">
      ${csrfInput}
      <button type="submit"${extra}>${label}</button>
    </form>`;

  const cards = connections
    .map((c) => {
      let status;
      let classes = "state";
      if (!c.connected) {
        status = "Not connected";
      } else if (c.orphan) {
        status = "Provider unavailable";
        classes = "state warn";
      } else if (c.paused && c.reauth_required) {
        status = "Delegation paused · reauthorization required";
        classes = "state warn";
      } else if (c.paused) {
        status = "Delegation paused";
        classes = "state warn";
      } else if (c.reauth_required) {
        status = "Reauthorization required";
        classes = "state warn";
      } else {
        status = "Connected";
        classes = "state ok";
      }

      const details = [];
      if (c.connected) {
        details.push(
          `<p>Scopes: ${escapeHtml(
            c.scopes.length ? c.scopes.join(", ") : "none"
          )}</p>`
        );
        details.push(`<p>Token expiry: ${escapeHtml(formatDate(c.expires_at))}</p>`);
        if (c.last_used_at) {
          details.push(`<p>Last used: ${escapeHtml(formatDate(c.last_used_at))}</p>`);
        }
        if (c.paused_at) {
          details.push(`<p>Paused since: ${escapeHtml(formatDate(c.paused_at))}</p>`);
        }
        if (c.orphan) {
          details.push(
            "<p>This provider is no longer configured. The stored credential can only be erased.</p>"
          );
        }
      }

      const actions = [];
      if (!c.connected) {
        if (c.connect_url) {
          actions.push(
            `<a class="button" href="${escapeHtml(c.connect_url)}">Connect</a>`
          );
        }
      } else if (c.orphan) {
        actions.push(
          `<a class="button danger" href="/connections/${encodeURIComponent(c.name)}/erase">Erase…</a>`
        );
      } else if (c.paused) {
        actions.push(actionForm(c.name, "connect", "Connect"));
        actions.push(
          `<a class="button danger" href="/connections/${encodeURIComponent(c.name)}/erase">Erase…</a>`
        );
      } else if (c.reauth_required) {
        actions.push(
          `<a class="button" href="${escapeHtml(c.connect_url)}">Connect</a>`
        );
        actions.push(
          `<a class="button danger" href="/connections/${encodeURIComponent(c.name)}/erase">Erase…</a>`
        );
      } else {
        actions.push(actionForm(c.name, "disconnect", "Disconnect"));
        actions.push(
          `<a class="button danger" href="/connections/${encodeURIComponent(c.name)}/erase">Erase…</a>`
        );
      }

      return `<article class="card">
        <div class="card-head"><h2>${escapeHtml(c.display_name)}</h2><span class="${classes}">${escapeHtml(status)}</span></div>
        ${details.join("\n")}
        <div class="actions">${actions.join("\n")}</div>
      </article>`;
    })
    .join("\n");

  const anyConnected = connections.some((c) => c.connected);

  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="${escapeHtml(csrf)}">
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
.button,button{font:inherit;font-size:.9rem;border-radius:.45rem;padding:.45rem .8rem;cursor:pointer;text-decoration:none;display:inline-block}
.button{background:#1d4ed8;color:#fff;border:1px solid #1d4ed8}
.button.danger,button.danger{background:#fff;color:#b91c1c;border:1px solid #fca5a5}
button{background:#fff;color:#111827;border:1px solid #cbd5e1}
.actions form{margin:0}
.eraseall{margin-top:2rem;padding-top:1rem;border-top:1px solid #e5e7eb}
footer{margin-top:2rem;font-size:.8rem;color:#6b7280}
</style></head>
<body>
<h1>Service connections</h1>
<p class="sub">Allow Gate One to act on your behalf on external services. Disconnect pauses the delegation; it does not delete the credential.</p>
${banners.join("\n")}
${cards || '<p>No provider is configured.</p>'}
${anyConnected ? `<div class="eraseall"><a class="button danger" href="/connections/erase-all">Erase all my data…</a></div>` : ""}
<footer>Erasing removes the stored credential from Gate One only; the provider is never contacted, so the same credential can still be used elsewhere.</footer>
</body></html>`;
}

function renderConfirmPage({ title, message, action, csrf, label }) {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:38rem;margin:3rem auto;padding:0 1rem;color:#1f2937}
h1{font-size:1.35rem}p{line-height:1.5;color:#374151}
.actions{display:flex;gap:.7rem;margin-top:1.5rem;align-items:center}
button,.button{font:inherit;font-size:.9rem;border-radius:.45rem;padding:.5rem .9rem;cursor:pointer;text-decoration:none}
button.danger{background:#b91c1c;color:#fff;border:1px solid #b91c1c}
.button{background:#fff;color:#111827;border:1px solid #cbd5e1}
form{margin:0}
</style></head>
<body>
<h1>${escapeHtml(title)}</h1>
<p>${escapeHtml(message)}</p>
<div class="actions">
  <form method="post" action="${escapeHtml(action)}">
    <input type="hidden" name="_csrf" value="${escapeHtml(csrf)}">
    <button class="danger" type="submit">${escapeHtml(label)}</button>
  </form>
  <a class="button" href="/connections">Cancel</a>
</div>
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

  function requireCsrf(req, res, next) {
    if (!sameOrigin(req, config)) {
      return res.status(403).json({ error: "csrf_origin" });
    }
    if (!csrfValid(config, req.userId, req.body?._csrf)) {
      return res.status(403).json({ error: "csrf_token" });
    }
    next();
  }

  function requireAdmin(req, res, next) {
    if (!config.adminSecret) {
      return res.status(404).json({ error: "not_found" });
    }
    const provided = req.get("x-broker-admin-secret") || "";
    if (!secretsEqual(provided, config.adminSecret)) {
      return res.status(401).json({ error: "unauthorized" });
    }
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
        .send(
          renderConnectionsPage({
            connections,
            query: req.query,
            csrf: csrfToken(config, req.userId),
          })
        );
    }
  );

  // Disconnect = pause. It never deletes the credential and never
  // touches the provider; Connect resumes the same credential.
  app.post(
    "/connections/:provider/disconnect",
    requireBrokerSecret,
    requireUser,
    requireCsrf,
    (req, res) => {
      const paused = tokenService.pause({
        userId: req.userId,
        provider: req.params.provider,
      });
      if (!paused) {
        return res.status(404).json({ error: "not_connected" });
      }
      if (wantsJson(req)) return res.status(204).end();
      return res.redirect(
        303,
        `/connections?paused=${encodeURIComponent(req.params.provider)}`
      );
    }
  );

  // Connect resumes a paused delegation. When the stored credential is
  // no longer usable (expired without refresh, refresh rejected), fall
  // back to the authorization-code flow.
  app.post(
    "/connections/:provider/connect",
    requireBrokerSecret,
    requireUser,
    requireCsrf,
    loadProvider,
    asyncRoute(async (req, res) => {
      const resumed = tokenService.resume({
        userId: req.userId,
        provider: req.provider.name,
      });

      const startOAuth = () => {
        const returnTo = resolveReturnTo(null, config);
        const { url } = tokenService.beginConnect({
          userId: req.userId,
          provider: req.provider,
          returnTo,
        });
        return res.redirect(302, url);
      };

      if (!resumed) return startOAuth();

      try {
        await tokenService.getAccessToken({
          userId: req.userId,
          provider: req.provider,
        });
      } catch (err) {
        if (
          err instanceof ReauthorizationRequiredError ||
          err instanceof NotConnectedError
        ) {
          return startOAuth();
        }
        if (!(err instanceof UpstreamError)) throw err;
        // Provider down: the delegation is resumed; the next call
        // retries the refresh.
      }

      if (wantsJson(req)) return res.status(204).end();
      return res.redirect(
        303,
        `/connections?resumed=${encodeURIComponent(req.provider.name)}`
      );
    })
  );

  // Erase is local only: the provider is never contacted (the same
  // credential may be used elsewhere).
  app.get(
    "/connections/:provider/erase",
    requireBrokerSecret,
    requireUser,
    (req, res) => {
      res.setHeader("Content-Security-Policy", CSP);
      return res
        .type("html")
        .send(
          renderConfirmPage({
            title: "Erase stored credentials",
            message:
              `Erase the stored credential for ${req.params.provider} from Gate One? ` +
              "The provider is not contacted: the same credential can still be used elsewhere.",
            action: `/connections/${encodeURIComponent(req.params.provider)}/erase`,
            csrf: csrfToken(config, req.userId),
            label: "Erase",
          })
        );
    }
  );

  app.post(
    "/connections/:provider/erase",
    requireBrokerSecret,
    requireUser,
    requireCsrf,
    (req, res) => {
      tokenService.erase({
        userId: req.userId,
        provider: req.params.provider,
      });
      if (wantsJson(req)) return res.status(204).end();
      return res.redirect(
        303,
        `/connections?erased=${encodeURIComponent(req.params.provider)}`
      );
    }
  );

  app.get(
    "/connections/erase-all",
    requireBrokerSecret,
    requireUser,
    (req, res) => {
      res.setHeader("Content-Security-Policy", CSP);
      return res
        .type("html")
        .send(
          renderConfirmPage({
            title: "Erase all my data",
            message:
              "Erase every credential Gate One stores for you? " +
              "The providers are not contacted.",
            action: "/connections/erase-all",
            csrf: csrfToken(config, req.userId),
            label: "Erase everything",
          })
        );
    }
  );

  app.post(
    "/connections/erase-all",
    requireBrokerSecret,
    requireUser,
    requireCsrf,
    (req, res) => {
      const erased = tokenService.eraseAll({ userId: req.userId });
      if (wantsJson(req)) return res.json({ erased });
      return res.redirect(303, "/connections?erased_all=1");
    }
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

        if (err instanceof DelegationDisabledError) {
          return res.status(403).json({
            error: "delegation_disabled",
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

  // Internal delete: local only, works even when the provider is
  // disabled or removed (the row is still the user's data).
  app.delete(
    "/token/:provider",
    requireBrokerSecret,
    requireUser,
    (req, res) => {
      tokenService.erase({
        userId: req.userId,
        provider: req.params.provider,
      });
      return res.status(204).end();
    }
  );

  // Security posture: redacted, for the operator and for Gate One's
  // doctor. No secret and no token value is ever returned.
  app.get("/security", requireBrokerSecret, (req, res) => {
    const enabled = providers.listEnabled();
    const enabledNames = new Set(enabled.map((p) => p.name));
    const stored = store.providerNames();
    const stats = store.stats();
    let dbMode = null;
    try {
      dbMode = (fs.statSync(config.databasePath).mode & 0o777)
        .toString(8)
        .padStart(4, "0");
    } catch {
      dbMode = null;
    }
    return res.json({
      status: "ok",
      public_base_url: config.publicBaseUrl,
      return_to_hosts: config.returnToHosts,
      encryption_key: true,
      admin_api: Boolean(config.adminSecret),
      retention_days: config.retentionDays,
      database: { path: config.databasePath, mode: dbMode },
      providers: enabled.map((p) => ({
        name: p.name,
        pkce: p.pkce,
        refresh: p.refresh,
        token_auth_method: p.tokenAuthMethod,
        https:
          new URL(p.authorizationEndpoint).protocol === "https:" &&
          new URL(p.tokenEndpoint).protocol === "https:",
      })),
      tokens: {
        users: stats.users,
        tokens: stats.tokens,
        paused: stats.paused,
        orphans: stored.filter((name) => !enabledNames.has(name)).length,
      },
    });
  });

  function adminUserID(req, res) {
    const id = req.params.id;
    if (typeof id !== "string" || id.trim() === "" || id.length > 256) {
      res.status(400).json({ error: "invalid_user_id" });
      return null;
    }
    return id;
  }

  function audit(action, userId, provider = "") {
    console.log(
      `token-broker admin: ${action} user=${JSON.stringify(userId)}` +
        (provider ? ` provider=${JSON.stringify(provider)}` : "")
    );
  }

  app.get("/admin/users", requireAdmin, (req, res) => {
    res.json({ users: store.listUsers() });
  });

  app.get("/admin/users/:id", requireAdmin, (req, res) => {
    const id = adminUserID(req, res);
    if (!id) return;
    res.json({
      user_id: id,
      connections: tokenService.listAllConnections(
        id,
        providers.listEnabled()
      ),
    });
  });

  app.post("/admin/users/:id/pause", requireAdmin, (req, res) => {
    const id = adminUserID(req, res);
    if (!id) return;
    const paused = tokenService.pauseAll({ userId: id });
    audit("pause-all", id);
    res.json({ paused });
  });

  app.post("/admin/users/:id/resume", requireAdmin, (req, res) => {
    const id = adminUserID(req, res);
    if (!id) return;
    const resumed = tokenService.resumeAll({ userId: id });
    audit("resume-all", id);
    res.json({ resumed });
  });

  app.post(
    "/admin/users/:id/:provider/pause",
    requireAdmin,
    (req, res) => {
      const id = adminUserID(req, res);
      if (!id) return;
      const paused = tokenService.pause({
        userId: id,
        provider: req.params.provider,
      });
      audit("pause", id, req.params.provider);
      res.json({ paused: paused ? 1 : 0 });
    }
  );

  app.post(
    "/admin/users/:id/:provider/resume",
    requireAdmin,
    (req, res) => {
      const id = adminUserID(req, res);
      if (!id) return;
      const resumed = tokenService.resume({
        userId: id,
        provider: req.params.provider,
      });
      audit("resume", id, req.params.provider);
      res.json({ resumed: resumed ? 1 : 0 });
    }
  );

  app.delete("/admin/users/:id/:provider", requireAdmin, (req, res) => {
    const id = adminUserID(req, res);
    if (!id) return;
    const erased = tokenService.erase({
      userId: id,
      provider: req.params.provider,
    });
    audit("erase", id, req.params.provider);
    res.json({ erased: erased ? 1 : 0 });
  });

  app.delete("/admin/users/:id", requireAdmin, (req, res) => {
    const id = adminUserID(req, res);
    if (!id) return;
    const erased = tokenService.eraseAll({ userId: id });
    audit("erase-all", id);
    res.json({ erased });
  });

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

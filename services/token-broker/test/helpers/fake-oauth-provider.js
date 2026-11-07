import http from "node:http";
import crypto from "node:crypto";

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function json(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function pkceChallenge(verifier) {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

/**
 * Minimal OAuth 2.0 provider used by the broker tests. It implements
 * only the token and revocation endpoints: the authorization step is
 * a redirect whose URL the test inspects.
 */
export async function startFakeProvider({
  clientId = "client-1",
  clientSecret = "secret-1",
  validCode = "code-1",
} = {}) {
  const state = {
    clientId,
    clientSecret,
    validCode,
    expectedRedirectUri: null,
    expectedChallenge: null,
    tokenRequests: [],
    revokeRequests: [],
    failRefresh: false,
    refreshErrorStatus: 400,
    refreshDelayMs: 0,
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");

    if (req.method === "POST" && url.pathname === "/token") {
      const params = new URLSearchParams(await readBody(req));
      const body = Object.fromEntries(params);
      state.tokenRequests.push(body);

      const basic = req.headers.authorization?.startsWith("Basic ")
        ? Buffer.from(req.headers.authorization.slice(6), "base64")
            .toString("utf8")
            .split(":")
        : null;

      const providedId = basic ? basic[0] : body.client_id;
      const providedSecret = basic ? basic.slice(1).join(":") : body.client_secret;

      if (providedId !== state.clientId || providedSecret !== state.clientSecret) {
        return json(res, 401, { error: "invalid_client" });
      }

      if (params.get("grant_type") === "authorization_code") {
        if (body.code !== state.validCode) {
          return json(res, 400, { error: "bad_verification_code" });
        }
        if (
          state.expectedRedirectUri &&
          body.redirect_uri !== state.expectedRedirectUri
        ) {
          return json(res, 400, { error: "redirect_uri_mismatch" });
        }
        if (
          state.expectedChallenge &&
          pkceChallenge(body.code_verifier || "") !== state.expectedChallenge
        ) {
          return json(res, 400, { error: "invalid_grant" });
        }

        return json(res, 200, {
          access_token: "access-1",
          refresh_token: "refresh-1",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token_expires_in: 7200,
          scope: "read write",
        });
      }

      if (params.get("grant_type") === "refresh_token") {
        if (state.refreshDelayMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, state.refreshDelayMs));
        }
        if (state.failRefresh || body.refresh_token !== "refresh-1") {
          return json(res, state.refreshErrorStatus, {
            error: state.refreshErrorStatus >= 500 ? "server_error" : "invalid_grant",
          });
        }

        return json(res, 200, {
          access_token: "access-2",
          refresh_token: "refresh-2",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token_expires_in: 7200,
          scope: "read write",
        });
      }

      return json(res, 400, { error: "unsupported_grant_type" });
    }

    if (req.method === "POST" && url.pathname === "/revoke") {
      const params = new URLSearchParams(await readBody(req));
      state.revokeRequests.push(Object.fromEntries(params));
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end("{}");
    }

    return json(res, 404, { error: "not_found" });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  return {
    state,
    baseUrl: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

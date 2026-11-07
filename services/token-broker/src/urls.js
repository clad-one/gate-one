import { isLoopbackHostname } from "./config.js";

function hostAllowed(hostname, allowedHosts) {
  const host = hostname.toLowerCase();

  return allowedHosts.some((entry) => {
    if (entry.startsWith(".")) {
      return host === entry.slice(1) || host.endsWith(entry);
    }
    return host === entry;
  });
}

/**
 * Resolve a user-supplied returnTo against the allow-list.
 *
 * A missing or rejected value falls back to the broker's own
 * /connections page. Relative paths are resolved against the public
 * base URL, never against the incoming Host header.
 */
export function resolveReturnTo(raw, config, fallbackPath = "/connections") {
  const fallback = new URL(fallbackPath, `${config.publicBaseUrl}/`).href;

  if (raw === undefined || raw === null || raw === "") return fallback;
  if (typeof raw !== "string") return fallback;

  let url;
  try {
    url = new URL(raw, `${config.publicBaseUrl}/`);
  } catch {
    return fallback;
  }

  const protocolOk =
    url.protocol === "https:" ||
    (url.protocol === "http:" && isLoopbackHostname(url.hostname));

  if (!protocolOk) return fallback;
  if (url.username || url.password) return fallback;
  if (!hostAllowed(url.hostname, config.returnToHosts)) return fallback;

  return url.href;
}

export function appendQuery(rawUrl, params) {
  const url = new URL(rawUrl);
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    url.searchParams.set(key, String(value));
  }
  return url.toString();
}

export function callbackUrl(config, providerName) {
  return `${config.publicBaseUrl}/oauth/${encodeURIComponent(providerName)}/callback`;
}

export function connectUrl(config, providerName, returnTo) {
  const target = returnTo || `${config.publicBaseUrl}/connections`;
  const params = new URLSearchParams({ returnTo: target });
  return `${config.publicBaseUrl}/connect/${encodeURIComponent(providerName)}?${params.toString()}`;
}

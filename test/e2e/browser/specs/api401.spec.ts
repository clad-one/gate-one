import { test, expect } from "@playwright/test";

// Regression: an unauthenticated fetch/XHR under a page route must get
// the API 401 (not a 302 to the login host). Following the redirect
// cross-origin fails CORS and the app sees "Failed to fetch"; the
// guard, which only intercepts 401, never shows its banner.
test("fetch on a page route gets 401 and shows the guard banner", async ({
  page,
  context,
}) => {
  const errors: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") errors.push(m.text());
  });
  page.on("requestfailed", (r) => {
    errors.push(`${r.url()} ${r.failure()?.errorText}`);
  });

  await page.goto("/");
  await expect(page.locator("body")).toContainText("alice@mycompany.test");

  // Drop the RP session cookie: the next request is anonymous.
  await context.clearCookies({ name: "gate_one_mycompany" });

  const result = await page.evaluate(async () => {
    const p = fetch("/api/process_stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    })
      .then((r) => ({ status: r.status }))
      .catch((e) => ({ error: String(e) }));
    const t = new Promise((res) =>
      setTimeout(() => res({ timeout: true }), 3000),
    );
    return Promise.race([p, t]);
  });

  // The guard queues the 401 and waits for a login: the request must
  // not resolve with an error, and no CORS/redirect failure is logged.
  expect(result).toEqual({ timeout: true });
  await expect(page.locator("[data-gtw-auth-banner]")).toBeVisible({
    timeout: 5_000,
  });
  const joined = errors.join("\n");
  expect(joined).not.toContain("Failed to fetch");
  expect(joined).not.toContain("CORS");
  expect(joined).not.toContain("net::ERR_FAILED");
});

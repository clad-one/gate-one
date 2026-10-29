import { test, expect } from "@playwright/test";

test("login via fake Google and SSO across two Gate One instances", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.locator("body")).toContainText("alice@acme.test");
  await expect(page.locator("body")).toContainText("X-User-Id");
  await expect(page.locator("body")).toContainText("X-Roles");

  // Second Gate One instance, same RP cookie on acme.localhost and
  // shared Redis: no second login.
  await page.goto("http://app2.acme.localhost:8090/");
  await expect(page.locator("body")).toContainText("alice@acme.test");
});

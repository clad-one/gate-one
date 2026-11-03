import { test, expect } from "@playwright/test";

test("logout invalidates the RP session", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("body")).toContainText("alice@mycompany.test");

  await page.goto("http://login.mycompany.localhost:8080/logout");

  const resp = await page.request.get("http://app.mycompany.localhost:8080/", {
    maxRedirects: 0,
  });
  expect(resp.status()).toBe(302);
  expect(resp.headers()["location"]).toContain(
    "login.mycompany.localhost:8080/login",
  );
});

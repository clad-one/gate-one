import { test, expect } from "@playwright/test";

test("logout in one tab probes the other tab through the storage event", async ({
  context,
  request,
}) => {
  // The previous test may have logged out less than a second ago; the
  // broker's sub revocation is stored with second granularity.
  await new Promise((resolve) => setTimeout(resolve, 1100));

  const tabA = await context.newPage();
  await tabA.goto("/");
  await expect(tabA.locator("body")).toContainText("alice@mycompany.test");

  const tabB = await context.newPage();
  await tabB.goto("/");
  await expect(tabB.locator("body")).toContainText("alice@mycompany.test");

  // The fake Google auto-consents; without this, tab A would silently
  // log in again while following the post-logout redirect, and tab B
  // could pick up the new cookie before its probe. Blocking the token
  // exchange keeps the logout observable (test-stack only).
  const fail = await request.post(
    "http://idp.mycompany.localhost:9000/__control/fail?token=1",
  );
  expect(fail.ok()).toBeTruthy();

  try {
    // Trigger the guard's own logout: it writes localStorage
    // (cladone:logout) then navigates to the login host.
    await tabA
      .evaluate(() => (window as any).__cladoneAuth.logout())
      .catch(() => {});

    // Tab B receives the storage event, probes immediately, gets 401
    // and switches the badge to the sign-in invitation.
    await expect(tabB.locator(".cladone-userbadge-login")).toBeVisible({
      timeout: 10_000,
    });
  } finally {
    await request.post(
      "http://idp.mycompany.localhost:9000/__control/fail?token=0",
    );
  }
});

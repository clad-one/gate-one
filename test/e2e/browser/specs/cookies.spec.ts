import { test, expect } from "@playwright/test";

test("session cookies: RP domain-wide, broker host-only, SameSite=Lax", async ({
  page,
  context,
}) => {
  await page.goto("/");
  await expect(page.locator("body")).toContainText("alice@mycompany.test");

  const cookies = await context.cookies();
  const rp = cookies.find((c) => c.name === "gate_one_mycompany");
  expect(rp, JSON.stringify(cookies)).toBeTruthy();
  expect(rp!.domain.replace(/^\./, "")).toBe("mycompany.localhost");
  expect(rp!.path).toBe("/");
  expect(rp!.httpOnly).toBe(true);
  expect(rp!.sameSite).toBe("Lax");
  expect(rp!.secure).toBe(false); // local stack is HTTP

  const broker = cookies.find((c) => c.name === "cladone_broker_sid");
  expect(broker, JSON.stringify(cookies)).toBeTruthy();
  expect(broker!.domain.replace(/^\./, "")).toBe("auth.mycompany.localhost");
  expect(broker!.path).toBe("/t/mycompany");
  expect(broker!.httpOnly).toBe(true);
  expect(broker!.sameSite).toBe("Lax");
  expect(broker!.secure).toBe(false);
});

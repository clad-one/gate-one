import { test, expect } from "@playwright/test";

test("session cookies: RP domain-wide, IAM host-only, SameSite=Lax", async ({
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

  const iam = cookies.find((c) => c.name === "cladone_iam_sid");
  expect(iam, JSON.stringify(cookies)).toBeTruthy();
  expect(iam!.domain.replace(/^\./, "")).toBe("auth.mycompany.localhost");
  expect(iam!.path).toBe("/t/mycompany");
  expect(iam!.httpOnly).toBe(true);
  expect(iam!.sameSite).toBe("Lax");
  expect(iam!.secure).toBe(false);
});

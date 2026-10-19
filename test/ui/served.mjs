// POST-DEPLOY behavioral smoke: runs the matrix against the guard
// extracted from the DEPLOYED PAGE (not the source) — detects
// regressions the server smoke (curl) cannot see.
//
//   node served.mjs          (URL: GATEWAY_UI_URL or vers.cladone.com)
import { readFileSync } from "fs";
import { renderGuard, extractGuardFromHtml, mkWindow, tick } from "./harness.mjs";

const SERVED_URL = process.env.GATEWAY_UI_URL || "https://vers.cladone.com/";

let failures = 0;
const ok = (label) => console.log("OK  " + label);
const fail = (m) => { console.error("FAIL " + m); failures++; };

// 1. the page is served with the guard
const html = await (await fetch(SERVED_URL)).text();
let servedGuard;
try {
  servedGuard = extractGuardFromHtml(html);
  ok("guard injected into the served page (" + servedGuard.length + " bytes)");
} catch (e) {
  console.error("FAIL " + e.message);
  process.exit(1);
}

// 2. the served guard is the source's one (anti-stale): re-render
// the source with the SAME arguments as the page (real config)
// then compare — a gap = stale code deployed.
const arg = (re) => (servedGuard.match(re) || [])[1];
const servedArgs = {
  loginUrl: arg(/var LOGIN = "(.*)";/),
  authState: arg(/var AUTH_STATE = "(.*)";/),
  uiGate: arg(/var UIGATE = (.*);/) || "[]",
  userBadge: arg(/var USERBADGE = (.*);/) || "null",
};
const sourceGuard = renderGuard(servedArgs);
if (servedGuard === sourceGuard) {
  ok("served guard = source guard (same arguments — nothing stale)");
} else {
  fail("served guard DIFFERENT from the source (same arguments) — deploy behind or divergent");
}

// 3. behavior: anonymous → before click → login called
{
  const x = await mkWindow(servedGuard, html, null);
  const coupes = x.doc.querySelector('[data-gtw-auth="before"]');
  if (!coupes) {
    fail("no data-gtw-auth=before element in the served page");
  } else {
    x.click(coupes);
    await tick();
    x.st.openCalls === 1
      ? ok("anonymous: Coupes click → login tab (server + client checked)")
      : fail(`anonymous: Coupes click without effect (openCalls=${x.st.openCalls}) — behavioral regression`);
  }
  x.click(x.doc.querySelector("#btn_process") || x.doc.body);
}

// 4. behavior: authenticated → badge + logout navigates
{
  const x = await mkWindow(servedGuard, html, {
    roles: ["offline_access"],
    scopes: ["profile"],
    claims: { preferred_username: "alice", email: "a@b.c", email_verified: false },
  });
  const badge = x.doc.querySelector(".cladone-userbadge");
  badge
    ? ok("authenticated: user badge created")
    : fail("badge expected once authenticated (userBadge config)");
  if (badge) {
    x.click(badge.querySelector("button"));
    await tick();
    x.st.navs.length
      ? ok("badge: Log out → /logout?returnTo=… navigation")
      : fail("badge: the logout button does not navigate");
  }
}

console.log(
  failures === 0
    ? "\nUI SMOKE (served page): all OK"
    : `\nUI SMOKE: ${failures} failure(s)`
);
process.exit(failures === 0 ? 0 : 1);

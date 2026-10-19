// Behavioral matrix of the guard script (run against the guard
// RENDERED from guard.go — never against a stale excerpt).
import { renderGuard, mkWindow, tick } from "./harness.mjs";

let failures = 0;
const ok = (label) => console.log("OK  " + label);
const fail = (m) => { console.error("FAIL " + m); failures++; };

const html = `<!DOCTYPE html><html><head></head><body>
<div class="cesure-options">
  <label id="coupes_label">
    <span id="coupes_lock" data-gtw-auth-hidden="after">🔒</span>
    <input type="checkbox" id="opt_coupes" data-gtw-auth="before">
    <span id="coupes_text">Cuts</span>
  </label>
  <label id="liaison_label">
    <input type="checkbox" id="opt_liaisons" data-gtw-auth="after">
    <span>Ligatures</span>
  </label>
  <label id="prehide_label">
    <input type="checkbox" id="prehide" data-gtw-auth-hidden="before">
    <span>Hidden</span>
  </label>
  <span id="role_gate" data-gtw-roles="admin">Admin</span>
  <span id="claim_gate" data-gtw-claims='{"email_verified":"true"}'>Verified</span>
  <span id="claim_present" data-gtw-claims='{"email":"*"}'>Email present</span>
  <button id="logout_btn" data-gtw-logout>Log out</button>
  <button id="btn_process">Segment</button>
  <span id="bystander"></span>
</div>
</body></html>`;

const guard = renderGuard();
const SESSION = {
  roles: ["offline_access"],
  scopes: ["openid", "profile"],
  claims: { preferred_username: "alice", email: "a@b.c", email_verified: false },
};

// ── 1. anonymous: before click → tab, nothing ticked ──
{
  const x = await mkWindow(guard, html, null);
  x.click(x.doc.getElementById("opt_coupes"));
  await tick();
  x.st.openCalls === 1
    ? ok("anonymous: before click → login tab")
    : fail(`anonymous before: openCalls=${x.st.openCalls} (want 1)`);
  x.doc.getElementById("opt_coupes").checked
    ? fail("anonymous before: box ticked (click not neutralized)")
    : ok("anonymous: before click neutralized (no pre-tick)");
  if (x.banner()) fail("anonymous before: unexpected banner");
}

// ── 2. anonymous: after click → tab + native action ──
{
  const x = await mkWindow(guard, html, null);
  x.click(x.doc.getElementById("opt_liaisons"));
  await tick();
  x.st.openCalls === 1
    ? ok("anonymous: after click → tab + native action")
    : fail(`anonymous after: openCalls=${x.st.openCalls} (want 1)`);
  x.doc.getElementById("opt_liaisons").checked
    ? ok("anonymous: after preserves the native action")
    : fail("anonymous after: native action lost");
}

// ── 3. anonymous: 401 without affordance → banner, never a tab ──
{
  const x = await mkWindow(guard, html, null);
  let rs = null;
  x.w.fetch("/api/process_stream", { method: "POST", body: "{}" })
    .then(r => { rs = r.status; });
  await tick();
  x.banner()
    ? ok("anonymous: mid-flow 401 → banner")
    : fail("anonymous mid-flow: banner expected");
  x.st.openCalls === 0
    ? ok("anonymous: never an automatic tab")
    : fail(`anonymous mid-flow: openCalls=${x.st.openCalls} (want 0)`);
  x.click([...x.doc.querySelectorAll("button")].find(b => b.textContent === "×"));
  await tick();
  rs === 401
    ? ok("dismiss × → request resolved with its 401 (the app continues)")
    : fail(`dismiss: request ${rs} (want 401)`);
}

// ── 4. anonymous: hidden=before → neutralized + banner ──
{
  const x = await mkWindow(guard, html, null);
  x.click(x.doc.getElementById("prehide"));
  await tick();
  x.doc.getElementById("prehide").checked
    ? fail("hidden=before: pre-ticking of a hidden control!")
    : ok("anonymous: hidden=before neutralized (no pre-tick)");
  x.banner()
    ? ok("anonymous: hidden=before → banner")
    : fail("hidden=before: banner expected");
}

// ── 5. identity: data-gtw-roles / claims (implicit auth) ──
{
  const x = await mkWindow(guard, html, SESSION);
  const vis = (id) => x.doc.getElementById(id).style.display !== "none";
  // data-gtw-roles="admin" + session WITHOUT admin → hidden
  vis("role_gate")
    ? fail("role_gate visible without the admin role")
    : ok("role absent → hidden (data-gtw-roles, implicit auth)");
  vis("claim_gate")
    ? fail("claim_gate visible with email_verified=false")
    : ok("non-conforming claim → hidden (email_verified:true required)");
  vis("claim_present")
    ? ok("presence (*) → visible (email present)")
    : fail("claim_present should be visible");
}

// ── 6. authenticated: full passthrough + badge + logout navigates ──
{
  const guardBadge = renderGuard({
    userBadge:
      '{"position":"right","claims":["preferred_username","email","email_verified"],"roles":true,"scopes":true,"logoutLabel":"Log out"}',
  });
  const x = await mkWindow(guardBadge, html, SESSION);
  if (!x.doc.querySelector(".cladone-userbadge")) fail("badge expected (authenticated + userBadge configured)");
  const badge = x.doc.querySelector(".cladone-userbadge");
  const tab = badge.querySelector(".cladone-userbadge-tab");
  tab.textContent.startsWith("👤") && tab.textContent.includes("alice")
    ? ok("badge: first line = 👤 + username")
    : fail("badge: the handle must show 👤 + the user's name");
  if (!badge.classList.contains("cladone-userbadge-reveal"))
    fail("badge: brief manifestation expected at login (reveal class)");
  await tick(2200);
  badge.classList.contains("cladone-userbadge-reveal")
    ? fail("badge: not hidden away after 2 s")
    : ok("badge: hidden away after the 2 s manifestation");
  const body = badge.querySelector(".cladone-userbadge-body").textContent;
  !body.includes("alice") && body.includes("email_verified: false")
    ? ok("badge: body = claims (no duplicate of the name)")
    : fail("badge: the body must carry the claims without repeating the name");
  body.includes("roles:") && body.includes("offline_access")
    ? ok("badge: roles listed (chip per session role)")
    : fail("badge: roles:true must list the session roles");
  body.includes("scopes:") && body.includes("profile")
    ? ok("badge: scopes listed (chip per granted scope)")
    : fail("badge: scopes:true must list the granted scopes");

  // ── 6b. badge switches in LIST form: filtering ──
  {
    const guardList = renderGuard({
      userBadge:
        '{"claims":true,"roles":["admin","offline_access"],"scopes":["profile"]}',
    });
    const y = await mkWindow(guardList, html, SESSION);
    const b2 = y.doc.querySelector(".cladone-userbadge-body").textContent;
    b2.includes("email: a@b.c") && b2.includes("email_verified: false")
      ? ok("badge: claims:true lists every claim of the session")
      : fail("badge: claims:true must list every session claim");
    b2.includes("offline_access") && !b2.includes("admin")
      ? ok("badge: roles list → held ones only (admin absent, omitted)")
      : fail("badge: roles list must filter to the held roles");
    b2.includes("scopes:") && !b2.includes("openid")
      ? ok("badge: scopes list → profile only (openid omitted)")
      : fail("badge: scopes list must filter to the selected scopes");
  }

  x.click(x.doc.getElementById("logout_btn"));
  await tick();
  x.st.navs.some(n => n.startsWith("https://login.cladone.com/logout?returnTo="))
    ? ok("authenticated logout → /logout?returnTo=… navigation")
    : fail("logout: navigation expected toward LOGIN_ORIGIN + /logout");
  x.st.openCalls === 0
    ? ok("logout: no login tab (direct navigation)")
    : fail("logout: a tab opened?!");
}

// ── 7. authenticated: silent tab abandonment (option C) ──
{
  const x = await mkWindow(guard, html, SESSION);
  x.w.__cladoneAuth.login().then(() => {});
  await tick();
  x.st.lastTab.closed = true;
  await tick(600);
  x.banner()
    ? fail("affordance abandonment: the banner must not come back (option C)")
    : ok("affordance abandonment → silence (option C)");
}

console.log(
  failures === 0 ? "UI MATRIX OK" : `UI MATRIX: ${failures} failure(s)`
);
globalThis.__uiFailures = (globalThis.__uiFailures || 0) + failures;

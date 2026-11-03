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

// ── 1b. anonymous: unchecking a checked before box → native, no login ──
{
  const x = await mkWindow(guard, html, null);
  const cb = x.doc.getElementById("opt_coupes");
  cb.checked = true; // programmatic check (the app's applyUI does this)
  x.click(cb);
  await tick();
  x.st.openCalls === 0
    ? ok("anonymous: unchecking a before box → no login")
    : fail(`anonymous uncheck: openCalls=${x.st.openCalls} (want 0)`);
  cb.checked
    ? fail("anonymous uncheck: the box stayed checked")
    : ok("anonymous: unchecking a before box → native uncheck");
}

// ── 1c. anonymous: unchecking via the wrapping label → no login ──
{
  const x = await mkWindow(guard, html, null);
  const cb = x.doc.getElementById("opt_coupes");
  cb.checked = true;
  x.click(x.doc.getElementById("coupes_label"));
  await tick();
  x.st.openCalls === 0
    ? ok("anonymous: unchecking via the label → no login")
    : fail(`anonymous label uncheck: openCalls=${x.st.openCalls} (want 0)`);
  cb.checked
    ? fail("anonymous label uncheck: the box stayed checked")
    : ok("anonymous: unchecking via the label → native uncheck");
}

// ── 1d. the attribute may sit on the label itself ──
{
  const labelHtml = `<!DOCTYPE html><html><head></head><body>
<label id="gated_label" data-gtw-auth="before">Cuts
  <input type="checkbox" id="gated_box" checked></label>
</body></html>`;

  // checked → label click unchecks without login
  const x = await mkWindow(guard, labelHtml, null);
  const cb = x.doc.getElementById("gated_box");
  x.click(x.doc.getElementById("gated_label"));
  await tick();
  x.st.openCalls === 0
    ? ok("anonymous: label-gated checked box → no login")
    : fail(`label-gated uncheck: openCalls=${x.st.openCalls} (want 0)`);
  cb.checked
    ? fail("label-gated uncheck: the box stayed checked")
    : ok("anonymous: label-gated checked box → native uncheck");

  // unchecked → label click still gates
  const y = await mkWindow(guard, labelHtml, null);
  const cb2 = y.doc.getElementById("gated_box");
  cb2.checked = false;
  y.click(y.doc.getElementById("gated_label"));
  await tick();
  y.st.openCalls === 1
    ? ok("anonymous: label-gated unchecked box → login tab")
    : fail(`label-gated activation: openCalls=${y.st.openCalls} (want 1)`);
  cb2.checked
    ? fail("label-gated activation: the box was ticked")
    : ok("anonymous: label-gated unchecked box → no pre-tick");
}

// ── 1e. programmatic check alone fires no event (documented limit) ──
{
  const x = await mkWindow(guard, html, null);
  x.doc.getElementById("opt_coupes").checked = true;
  await tick();
  x.st.openCalls === 0
    ? ok("programmatic check alone → no login (no DOM event)")
    : fail(`programmatic check: openCalls=${x.st.openCalls} (want 0)`);
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

// ── 2b. anonymous: unchecking an after box → no login ──
{
  const x = await mkWindow(guard, html, null);
  const cb = x.doc.getElementById("opt_liaisons");
  cb.checked = true;
  x.click(cb);
  await tick();
  x.st.openCalls === 0
    ? ok("anonymous: unchecking an after box → no login")
    : fail(`anonymous after uncheck: openCalls=${x.st.openCalls} (want 0)`);
  cb.checked
    ? fail("anonymous after uncheck: the box stayed checked")
    : ok("anonymous: unchecking an after box → native uncheck");
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
  const ab = x.doc.querySelector("[data-gtw-auth-banner]");
  ab && ab.classList.contains("cladone-banner")
    ? ok("auth banner: class-based styling (strict CSP)")
    : fail("auth banner: cladone-banner class expected");
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
  const vis = (id) =>
    !x.doc.getElementById(id).hasAttribute("data-gtw-gated-off");
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
  const cssText = x.doc.querySelector("style").textContent;
  badge.classList.contains("cladone-userbadge") &&
  badge.classList.contains("cladone-userbadge-right") &&
  cssText.includes("border:1px solid #fff;border-top:0")
    ? ok("badge: class-based outline except the top window edge")
    : fail("badge: white outline class expected except the top edge");
  const tab = badge.querySelector(".cladone-userbadge-tab");
  tab.textContent.startsWith("👤") && tab.textContent.includes("alice")
    ? ok("badge: first line = 👤 + username")
    : fail("badge: the handle must show 👤 + the user's name");
  if (!badge.classList.contains("cladone-userbadge-reveal"))
    fail("badge: transient one-line handle expected at login");
  await tick(2200);
  badge.classList.contains("cladone-userbadge-reveal")
    ? fail("badge: transient handle not hidden after 2 s")
    : ok("badge: handle hidden after the transient reveal");
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

// ── 6c. licence indicator: icon in the handle, details at the bottom ──
{
  const badgeCfg =
    '{"claims":false,"roles":false,"scopes":false,"logoutLabel":"Log out"}';

  // eval / personal
  const gEval = renderGuard({
    userBadge: badgeCfg,
    license:
      '{"state":"eval","reason":"missing","url":"https://example.test/pricing"}',
  });
  const xe = await mkWindow(gEval, html, SESSION);
  const be = xe.doc.querySelector(".cladone-userbadge");
  const ie = be.querySelector(".cladone-userbadge-tab button");
  ie && ie.textContent.includes("⚖")
    ? ok("licence eval: ⚖ icon in the handle")
    : fail("licence eval: icon expected in the tab");
  const boxE = be.querySelector(".cladone-badge-license");
  boxE && !boxE.classList.contains("cladone-license-visible")
    ? ok("licence eval: details hidden until click")
    : fail("licence eval: details must start hidden");
  xe.click(ie);
  await tick();
  be.classList.contains("cladone-userbadge-open")
    ? ok("licence eval: click unfolds the badge")
    : fail("licence eval: click must unfold the badge");
  boxE.classList.contains("cladone-license-visible") &&
  boxE.textContent.includes("eval / personal license")
    ? ok("licence eval: details = eval / personal")
    : fail("licence eval: details text missing");
  boxE.querySelector("a")
    ? ok("licence eval: registration link shown")
    : fail("licence eval: link expected");

  // registered
  const gReg = renderGuard({
    userBadge: badgeCfg,
    license:
      '{"state":"registered","reason":"ok","org":"MYCOMPANY","email":"ops@mycompany.fr",' +
      '"plan":"pro","exp":"2027-10-24","domains":["mycompany.fr"],"features":["sso"]}',
  });
  const xr = await mkWindow(gReg, html, SESSION);
  const br = xr.doc.querySelector(".cladone-userbadge");
  const ir = br.querySelector(".cladone-userbadge-tab button");
  ir && ir.textContent.includes("🔑")
    ? ok("licence registered: 🔑 icon in the handle")
    : fail("licence registered: key icon expected");
  const boxR = br.querySelector(".cladone-badge-license");
  xr.click(ir);
  await tick();
  boxR.textContent.includes("registered to:") &&
  boxR.textContent.includes("MYCOMPANY") &&
  boxR.textContent.includes("ops@mycompany.fr") &&
  boxR.textContent.includes("plan: pro")
    ? ok("licence registered: details = registered to + signed claims")
    : fail("licence registered: details missing claims");
}

// ── 6d. badge: proximity handle, hover compact (CSS), click full ──
{
  const guardBadge = renderGuard({
    userBadge:
      '{"position":"right","claims":["preferred_username"],' +
      '"roles":true,"scopes":true,"links":[' +
      '{"label":"Account","url":"https://idp.test/account"}],' +
      '"logoutLabel":"Log out"}',
  });
  const x = await mkWindow(guardBadge, html, SESSION);
  const badge = x.doc.querySelector(".cladone-userbadge");
  const tab = badge.querySelector(".cladone-userbadge-tab");
  await tick(2200); // transient reveal over

  !badge.classList.contains("cladone-userbadge-reveal") &&
  !badge.classList.contains("cladone-userbadge-near")
    ? ok("badge: hidden after the transient handle")
    : fail("badge: handle still visible after the transient reveal");

  x.w.dispatchEvent(new x.w.MouseEvent("mousemove", {
    bubbles: true, clientX: 100, clientY: 20,
  }));
  await tick();
  badge.classList.contains("cladone-userbadge-near")
    ? ok("badge: mouse approach → one-line handle")
    : fail("badge: handle not revealed on mouse approach");

  x.w.dispatchEvent(new x.w.MouseEvent("mousemove", {
    bubbles: true, clientX: 100, clientY: 200,
  }));
  await tick();
  !badge.classList.contains("cladone-userbadge-near")
    ? ok("badge: handle hidden after moving away")
    : fail("badge: handle kept after moving away");

  x.click(tab);
  badge.classList.contains("cladone-userbadge-open")
    ? ok("badge: click → full view")
    : fail("badge: click did not open the full view");

  const link = x.doc.querySelector(".cladone-badge-link");
  x.click(link);
  badge.classList.contains("cladone-userbadge-open")
    ? ok("badge: link click does not toggle the full view")
    : fail("badge: link click collapsed the full view");

  x.click(x.doc.body);
  !badge.classList.contains("cladone-userbadge-open")
    ? ok("badge: outside click collapses the full view")
    : fail("badge: outside click left the full view open");

  const cssText = x.doc.querySelector("style").textContent;
  cssText.includes(":hover:not(.cladone-userbadge-open)") &&
  cssText.includes("max-height:6.6em") &&
  cssText.includes(".cladone-userbadge-open .cladone-badge-row{white-space:normal")
    ? ok("badge: hover compact CSS + full view without ellipsis")
    : fail("badge: compact/full CSS rules missing");
}

// ── 6e. refresh(): in-place session changes, no reload ──
{
  const x = await mkWindow(guard, html, null);
  const off = await x.w.__cladoneAuth.refresh();
  off === false
    ? ok("refresh: anonymous → false")
    : fail(`refresh anonymous: got ${off} (want false)`);
  x.st.session = SESSION;
  const on = await x.w.__cladoneAuth.refresh();
  on === true
    ? ok("refresh: session acquired in place")
    : fail(`refresh session: got ${on} (want true)`);
  x.doc.documentElement.classList.contains("cladone-authed")
    ? ok("refresh: cladone-authed applied")
    : fail("refresh: cladone-authed missing");
  x.st.session = null;
  const dead = await x.w.__cladoneAuth.refresh({
    quiet: true, sessionDeath: false,
  });
  dead === false
    ? ok("refresh: deliberate logout → false")
    : fail(`refresh logout: got ${dead} (want false)`);
  !x.banner()
    ? ok("refresh: quiet deliberate logout → no banner")
    : fail("refresh: quiet deliberate logout showed the banner");
  !x.doc.documentElement.classList.contains("cladone-authed")
    ? ok("refresh: cladone-authed removed")
    : fail("refresh: cladone-authed still present");
}
{
  const x = await mkWindow(guard, html, SESSION);
  x.st.session = null;
  const dead = await x.w.__cladoneAuth.refresh();
  dead === false
    ? ok("refresh: authoritative 401 → false")
    : fail(`refresh 401: got ${dead} (want false)`);
  x.banner()
    ? ok("refresh: session death → reconnection banner")
    : fail("refresh: session death banner expected");
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

// ── 8. userBadge.links: final list rendered as anchors ──
{
  const guardLinks = renderGuard({
    userBadge:
      '{"claims":["preferred_username"],"links":[' +
      '{"label":"Account","url":"https://idp.test/account","target":"_blank"},' +
      '{"label":"Status","url":"/status","target":"_self"}]}',
  });
  const x = await mkWindow(guardLinks, html, SESSION);
  const links = [...x.doc.querySelectorAll(".cladone-badge-link")];
  links.length === 2 &&
  links[0].textContent === "Account" &&
  links[0].target === "_blank" &&
  links[0].rel.includes("noopener") &&
  links[1].textContent === "Status" &&
  links[1].target === "_self"
    ? ok("badge links: final list rendered (target/rel)")
    : fail(
        "badge links: " +
        links.map((a) => `${a.textContent}|${a.target}|${a.rel}`).join(",")
      );
}

// ── 9. strict CSP: the runtime <style> carries the script nonce ──
{
  const x = await mkWindow(guard, html, SESSION, "[]", { nonce: "n-test" });
  const styles = [...x.doc.querySelectorAll("style")];
  styles.some((s) => s.nonce === "n-test")
    ? ok("CSP: guard <style> carries the response nonce")
    : fail(`CSP: style nonce missing (${styles.map((s) => s.nonce).join(",")})`);
}

console.log(
  failures === 0 ? "UI MATRIX OK" : `UI MATRIX: ${failures} failure(s)`
);
globalThis.__uiFailures = (globalThis.__uiFailures || 0) + failures;

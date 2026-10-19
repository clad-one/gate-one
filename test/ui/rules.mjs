// uiGate suite: config rules (selector + identity + auth/hidden),
// markup precedence > config, AND across rules, invalid-safe.
import { renderGuard, mkWindow, tick } from "./harness.mjs";

let failures = 0;
const ok = (label) => console.log("OK  " + label);
const fail = (m) => { console.error("FAIL " + m); failures++; };

const html = `<!DOCTYPE html><html><head></head><body>
<div>
  <span id="legend">Legend</span>
  <span id="both" data-gtw-roles="admin">Both</span>
  <input type="checkbox" id="rule_before">
  <input type="checkbox" id="rule_hidden">
  <label id="rule_hidden_label">Secret <input type="checkbox" id="rule_hidden_box"></label>
  <span id="bystander"></span>
</div>
</body></html>`;

const RULES = [
  { selector: "#legend", roles: ["offline_access"] },
  { selector: "#legend", scopes: ["profile"] },          // 2nd rule → AND
  { selector: "#both", roles: ["gold"] },                // markup precedence
  { selector: "#rule_before", auth: "before" },
  { selector: "#rule_hidden", hidden: "before" },
  { selector: "#rule_hidden_box", hidden: "before" },
  { selector: "###invalid", roles: ["admin"] },          // invalid-safe
];

const GUARD = renderGuard({ uiGate: JSON.stringify(RULES) });

// ── 1. conforming: legend visible (role ✓ AND scope ✓); precedence; invalid-safe ──
{
  const x = await mkWindow(GUARD, html, {
    roles: ["offline_access"], scopes: ["profile"], claims: {},
  });
  x.doc.getElementById("legend").style.display !== "none"
    ? ok("uiGate conforming → visible (rules in AND)")
    : fail("legend should be visible (offline_access ✓ + profile ✓)");
  x.doc.getElementById("both").style.display !== "none"
    ? fail("both visible without admin (the data-gtw-roles markup must win over the gold rule)")
    : ok("markup precedence: data-gtw-roles wins over the uiGate rule");
  x.doc.getElementById("bystander").style.display !== "none"
    ? ok("untargeted element unchanged")
    : fail("bystander wrongly hidden");
  x.doc.documentElement.classList.contains("cladone-evaluated")
    ? ok("evaluation set (cladone-evaluated)")
    : fail("cladone-evaluated missing");
}

// ── 2. non-conforming: legend hidden ──
{
  const x = await mkWindow(GUARD, html, { roles: [], scopes: [], claims: {} });
  x.doc.getElementById("legend").style.display !== "none"
    ? fail("legend visible without the conditions")
    : ok("uiGate non-conforming → hidden");
}

// ── 3. auth=before rule: click neutralized + tab (anonymous) ──
{
  const x = await mkWindow(GUARD, html, null);
  x.click(x.doc.getElementById("rule_before"));
  await tick();
  x.st.openCalls === 1
    ? ok("auth=before rule → direct tab")
    : fail(`auth=before rule: openCalls=${x.st.openCalls} (want 1)`);
  x.doc.getElementById("rule_before").checked
    ? fail("auth=before rule: the box was ticked (click not neutralized)")
    : ok("auth=before rule → click neutralized");
}

// ── 4. hidden=before rule: neutralization + banner, never a tab ──
{
  const x = await mkWindow(GUARD, html, null);
  x.click(x.doc.getElementById("rule_hidden"));
  await tick();
  x.doc.getElementById("rule_hidden").checked
    ? fail("hidden=before: pre-ticking of the hidden control!")
    : ok("hidden=before: no pre-tick");
  x.banner()
    ? ok("hidden=before → banner")
    : fail("hidden=before: banner expected");
  x.st.openCalls === 0
    ? ok("hidden=before: never a tab")
    : fail(`hidden=before: openCalls=${x.st.openCalls} (want 0)`);
  // via label (synthetic activation) → same neutralization
  x.click(x.doc.getElementById("rule_hidden_label"));
  await tick();
  x.doc.getElementById("rule_hidden_box").checked
    ? fail("hidden=before: the label's box was ticked via label activation")
    : ok("hidden=before via label → neutralized too");
}

// ── 5. authenticated: rules go into native passthrough ──
{
  const x = await mkWindow(GUARD, html, {
    roles: ["offline_access"], scopes: ["profile"], claims: {},
  });
  const before = x.st.openCalls;
  x.click(x.doc.getElementById("rule_before"));
  await tick();
  x.st.openCalls === before
    ? ok("authenticated: rules no longer trigger anything (passthrough)")
    : fail("authenticated: a rule opened a tab");
  x.doc.getElementById("rule_before").checked
    ? ok("authenticated: native clicks")
    : fail("authenticated: the native click did not happen");
}

console.log(
  failures === 0 ? "UIGATE SUITE OK" : `UIGATE SUITE: ${failures} failure(s)`
);
globalThis.__uiFailures = (globalThis.__uiFailures || 0) + failures;

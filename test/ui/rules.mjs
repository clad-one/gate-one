// Suite uiGate : règles config (sélecteur + identité + auth/hidden),
// précédence markup > config, ET entre règles, invalid-safe.
import { renderGuard, mkWindow, tick } from "./harness.mjs";

let failures = 0;
const ok = (label) => console.log("OK  " + label);
const fail = (m) => { console.error("ÉCHEC " + m); failures++; };

const html = `<!DOCTYPE html><html><head></head><body>
<div>
  <span id="legend">Légende</span>
  <span id="both" data-gtw-roles="admin">Both</span>
  <input type="checkbox" id="rule_before">
  <input type="checkbox" id="rule_hidden">
  <label id="rule_hidden_label">Secret <input type="checkbox" id="rule_hidden_box"></label>
  <span id="bystander"></span>
</div>
</body></html>`;

const RULES = [
  { selector: "#legend", roles: ["offline_access"] },
  { selector: "#legend", scopes: ["profile"] },          // 2e règle → ET
  { selector: "#both", roles: ["gold"] },                // précédence markup
  { selector: "#rule_before", auth: "before" },
  { selector: "#rule_hidden", hidden: "before" },
  { selector: "#rule_hidden_box", hidden: "before" },
  { selector: "###invalid", roles: ["admin"] },          // invalid-safe
];

const GUARD = renderGuard({ uiGate: JSON.stringify(RULES) });

// ── 1. conforme : legend visible (rôle ✓ ET scope ✓) ; précédence ; invalid-safe ──
{
  const x = await mkWindow(GUARD, html, {
    roles: ["offline_access"], scopes: ["profile"], claims: {},
  });
  x.doc.getElementById("legend").style.display !== "none"
    ? ok("uiGate conforme → visible (règles en ET)")
    : fail("legend devrait être visible (offline_access ✓ + profile ✓)");
  x.doc.getElementById("both").style.display !== "none"
    ? fail("both visible sans admin (le markup data-gtw-roles doit gagner sur la règle gold)")
    : ok("précédence markup : data-gtw-roles gagne sur la règle uiGate");
  x.doc.getElementById("bystander").style.display !== "none"
    ? ok("élément non visé inchangé")
    : fail("bystander masqué à tort");
  x.doc.documentElement.classList.contains("cladone-evaluated")
    ? ok("évaluation posée (cladone-evaluated)")
    : fail("cladone-evaluated absent");
}

// ── 2. non conforme : legend masquée ──
{
  const x = await mkWindow(GUARD, html, { roles: [], scopes: [], claims: {} });
  x.doc.getElementById("legend").style.display !== "none"
    ? fail("legend visible sans les conditions")
    : ok("uiGate non conforme → masqué");
}

// ── 3. règle auth=before : clic neutralisé + onglet (anonyme) ──
{
  const x = await mkWindow(GUARD, html, null);
  x.click(x.doc.getElementById("rule_before"));
  await tick();
  x.st.openCalls === 1
    ? ok("règle auth=before → onglet direct")
    : fail(`règle auth=before: openCalls=${x.st.openCalls} (want 1)`);
  x.doc.getElementById("rule_before").checked
    ? fail("règle auth=before: la case a été cochée (clic non neutralisé)")
    : ok("règle auth=before → clic neutralisé");
}

// ── 4. règle hidden=before : neutralisation + bannière, jamais d'onglet ──
{
  const x = await mkWindow(GUARD, html, null);
  x.click(x.doc.getElementById("rule_hidden"));
  await tick();
  x.doc.getElementById("rule_hidden").checked
    ? fail("hidden=before: pré-cochage du contrôle masqué !")
    : ok("hidden=before : pas de pré-cochage");
  x.banner()
    ? ok("hidden=before → bannière")
    : fail("hidden=before: bannière attendue");
  x.st.openCalls === 0
    ? ok("hidden=before : jamais d'onglet")
    : fail(`hidden=before: openCalls=${x.st.openCalls} (want 0)`);
  // via label (activation synthétique) → même neutralisation
  x.click(x.doc.getElementById("rule_hidden_label"));
  await tick();
  x.doc.getElementById("rule_hidden_box").checked
    ? fail("hidden=before: la box du label a été cochée via activation label")
    : ok("hidden=before via label → neutralisé aussi");
}

// ── 5. authentifié : les règles passent en passthrough natif ──
{
  const x = await mkWindow(GUARD, html, {
    roles: ["offline_access"], scopes: ["profile"], claims: {},
  });
  const before = x.st.openCalls;
  x.click(x.doc.getElementById("rule_before"));
  await tick();
  x.st.openCalls === before
    ? ok("authentifié : les règles ne déclenchent plus rien (passthrough)")
    : fail("authentifié: une règle a ouvert un onglet");
  x.doc.getElementById("rule_before").checked
    ? ok("authentifié : clics natifs")
    : fail("authentifié: le clic natif n'a pas eu lieu");
}

console.log(
  failures === 0 ? "SUITE UIGATE OK" : `SUITE UIGATE : ${failures} échec(s)`
);
globalThis.__uiFailures = (globalThis.__uiFailures || 0) + failures;

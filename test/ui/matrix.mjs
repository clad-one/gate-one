// Matrice comportementale du script de garde (exécutée contre la
// garde RENDUE depuis guard.go — jamais contre un extrait périmé).
import { renderGuard, mkWindow, tick } from "./harness.mjs";

let failures = 0;
const ok = (label) => console.log("OK  " + label);
const fail = (m) => { console.error("ÉCHEC " + m); failures++; };

const html = `<!DOCTYPE html><html><head></head><body>
<div class="cesure-options">
  <label id="coupes_label">
    <span id="coupes_lock" data-gtw-auth-hidden="after">🔒</span>
    <input type="checkbox" id="opt_coupes" data-gtw-auth="before">
    <span id="coupes_text">Coupes</span>
  </label>
  <label id="liaison_label">
    <input type="checkbox" id="opt_liaisons" data-gtw-auth="after">
    <span>Liaisons</span>
  </label>
  <label id="prehide_label">
    <input type="checkbox" id="prehide" data-gtw-auth-hidden="before">
    <span>Masqué</span>
  </label>
  <span id="role_gate" data-gtw-roles="admin">Admin</span>
  <span id="claim_gate" data-gtw-claims='{"email_verified":"true"}'>Vérifié</span>
  <span id="claim_present" data-gtw-claims='{"email":"*"}'>Email présent</span>
  <button id="logout_btn" data-gtw-logout>Déconnexion</button>
  <button id="btn_process">Segmenter</button>
  <span id="bystander"></span>
</div>
</body></html>`;

const guard = renderGuard();
const SESSION = {
  roles: ["offline_access"],
  scopes: ["openid", "profile"],
  claims: { preferred_username: "alice", email: "a@b.c", email_verified: false },
};

// ── 1. anonyme : clic before → onglet, rien de coché ──
{
  const x = await mkWindow(guard, html, null);
  x.click(x.doc.getElementById("opt_coupes"));
  await tick();
  x.st.openCalls === 1
    ? ok("anonyme : clic before → onglet de login")
    : fail(`anonyme before: openCalls=${x.st.openCalls} (want 1)`);
  x.doc.getElementById("opt_coupes").checked
    ? fail("anonyme before: case cochée (clic non neutralisé)")
    : ok("anonyme : clic before neutralisé (pas de pré-cochage)");
  if (x.banner()) fail("anonyme before: bannière inattendue");
}

// ── 2. anonyme : clic after → onglet + action native ──
{
  const x = await mkWindow(guard, html, null);
  x.click(x.doc.getElementById("opt_liaisons"));
  await tick();
  x.st.openCalls === 1
    ? ok("anonyme : clic after → onglet + action native")
    : fail(`anonyme after: openCalls=${x.st.openCalls} (want 1)`);
  x.doc.getElementById("opt_liaisons").checked
    ? ok("anonyme : after préserve l'action native")
    : fail("anonyme after: action native perdue");
}

// ── 3. anonyme : 401 sans affordance → bannière, jamais d'onglet ──
{
  const x = await mkWindow(guard, html, null);
  let rs = null;
  x.w.fetch("/api/process_stream", { method: "POST", body: "{}" })
    .then(r => { rs = r.status; });
  await tick();
  x.banner()
    ? ok("anonyme : 401 mid-flow → bannière")
    : fail("anonyme mid-flow: bannière attendue");
  x.st.openCalls === 0
    ? ok("anonyme : jamais d'onglet automatique")
    : fail(`anonyme mid-flow: openCalls=${x.st.openCalls} (want 0)`);
  x.click([...x.doc.querySelectorAll("button")].find(b => b.textContent === "×"));
  await tick();
  rs === 401
    ? ok("dismiss × → requête résolue avec son 401 (l'app continue)")
    : fail(`dismiss: requête ${rs} (want 401)`);
}

// ── 4. anonyme : hidden=before → neutralisé + bannière ──
{
  const x = await mkWindow(guard, html, null);
  x.click(x.doc.getElementById("prehide"));
  await tick();
  x.doc.getElementById("prehide").checked
    ? fail("hidden=before: pré-cochage d'un contrôle masqué !")
    : ok("anonyme : hidden=before neutralisé (pas de pré-cochage)");
  x.banner()
    ? ok("anonyme : hidden=before → bannière")
    : fail("hidden=before: bannière attendue");
}

// ── 5. identité : data-gtw-roles / claims (auth implicite) ──
{
  const x = await mkWindow(guard, html, SESSION);
  const vis = (id) => x.doc.getElementById(id).style.display !== "none";
  // data-gtw-roles="admin" + session SANS admin → masqué
  vis("role_gate")
    ? fail("role_gate visible sans le rôle admin")
    : ok("rôle absent → masqué (data-gtw-roles, auth implicite)");
  vis("claim_gate")
    ? fail("claim_gate visible avec email_verified=false")
    : ok("claim non conforme → masqué (email_verified:true exigé)");
  vis("claim_present")
    ? ok("présence (*) → visible (email présent)")
    : fail("claim_present devrait être visible");
}

// ── 6. authentifié : passthrough total + badge + logout navigue ──
{
  const guardBadge = renderGuard({
    userBadge:
      '{"position":"right","claims":["preferred_username","email","email_verified"],"logoutLabel":"Déconnexion"}',
  });
  const x = await mkWindow(guardBadge, html, SESSION);
  if (!x.doc.querySelector(".cladone-userbadge")) fail("badge attendu (authentifié + userBadge configuré)");
  const badge = x.doc.querySelector(".cladone-userbadge");
  badge.querySelector(".cladone-userbadge-tab").textContent === "👤"
    ? ok("badge : poignée 👤 discrète (le nom n'apparaît qu'au dépliage)")
    : fail("badge: la poignée doit être l'icône seule");
  if (!badge.classList.contains("cladone-userbadge-reveal"))
    fail("badge: manifestation brève attendue au login (classe reveal)");
  await tick(2200);
  badge.classList.contains("cladone-userbadge-reveal")
    ? fail("badge: non escamoté après 2 s")
    : ok("badge : escamoté après la manifestation de 2 s");
  const body = badge.querySelector(".cladone-userbadge-body").textContent;
  body.includes("alice") && !body.match(/alice.*alice/)
    ? ok("badge : identité en tête, sans doublon")
    : fail("badge: identité absente ou en double");

  x.click(x.doc.getElementById("logout_btn"));
  await tick();
  x.st.navs.some(n => n.startsWith("https://login.cladone.com/logout?returnTo="))
    ? ok("logout authentifié → navigation /logout?returnTo=…")
    : fail("logout: navigation attendue vers LOGIN_ORIGIN + /logout");
  x.st.openCalls === 0
    ? ok("logout : pas d'onglet de login (navigation directe)")
    : fail("logout: un onglet s'est ouvert ?!");
}

// ── 7. authentifié : abandon d'onglet silencieux (option C) ──
{
  const x = await mkWindow(guard, html, SESSION);
  x.w.__cladoneAuth.login().then(() => {});
  await tick();
  x.st.lastTab.closed = true;
  await tick(600);
  x.banner()
    ? fail("abandon affordance: la bannière ne doit pas revenir (option C)")
    : ok("abandon affordance → silence (option C)");
}

console.log(
  failures === 0 ? "MATRICE UI OK" : `MATRICE UI : ${failures} échec(s)`
);
globalThis.__uiFailures = (globalThis.__uiFailures || 0) + failures;

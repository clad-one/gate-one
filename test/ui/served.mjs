// Smoke comportemental POST-DEPLOY : exécute la matrice contre la
// garde extraite de la PAGE DÉPLOYÉE (pas du source) — détecte les
// régressions que le smoke serveur (curl) ne voit pas.
//
//   node served.mjs          (URL: GATEWAY_UI_URL ou vers.cladone.com)
import { readFileSync } from "fs";
import { renderGuard, extractGuardFromHtml, mkWindow, tick } from "./harness.mjs";

const SERVED_URL = process.env.GATEWAY_UI_URL || "https://vers.cladone.com/";

let failures = 0;
const ok = (label) => console.log("OK  " + label);
const fail = (m) => { console.error("ÉCHEC " + m); failures++; };

// 1. la page est servie avec la garde
const html = await (await fetch(SERVED_URL)).text();
let servedGuard;
try {
  servedGuard = extractGuardFromHtml(html);
  ok("garde injectée dans la page servie (" + servedGuard.length + " octets)");
} catch (e) {
  console.error("ÉCHEC " + e.message);
  process.exit(1);
}

// 2. la garde servie est celle du source (anti périmé) : on ré-rend
// le source avec les MÊMES arguments que la page (config réelle)
// puis on compare — un écart = code périmé déployé.
const arg = (re) => (servedGuard.match(re) || [])[1];
const servedArgs = {
  loginUrl: arg(/var LOGIN = "(.*)";/),
  authState: arg(/var AUTH_STATE = "(.*)";/),
  uiGate: arg(/var UIGATE = (.*);/) || "[]",
  userBadge: arg(/var USERBADGE = (.*);/) || "null",
};
const sourceGuard = renderGuard(servedArgs);
if (servedGuard === sourceGuard) {
  ok("garde servie = garde du source (mêmes arguments — pas de périmé)");
} else {
  fail("garde servie DIFFÉRENTE du source (mêmes arguments) — deploy en retard ou divergent");
}

// 3. comportement : anonyme → clic before → login appelé
{
  const x = await mkWindow(servedGuard, html, null);
  const coupes = x.doc.querySelector('[data-gtw-auth="before"]');
  if (!coupes) {
    fail("aucun élément data-gtw-auth=before dans la page servie");
  } else {
    x.click(coupes);
    await tick();
    x.st.openCalls === 1
      ? ok("anonyme : clic Coupes → onglet de login (serveur + client vérifiés)")
      : fail(`anonyme: clic Coupes sans effet (openCalls=${x.st.openCalls}) — régression comportementale`);
  }
  x.click(x.doc.querySelector("#btn_process") || x.doc.body);
}

// 4. comportement : authentifié → badge + logout navigue
{
  const x = await mkWindow(servedGuard, html, {
    roles: ["offline_access"],
    scopes: ["profile"],
    claims: { preferred_username: "alice", email: "a@b.c", email_verified: false },
  });
  const badge = x.doc.querySelector(".cladone-userbadge");
  badge
    ? ok("authentifié : badge utilisateur créé")
    : fail("badge attendu une fois authentifié (config userBadge)");
  if (badge) {
    x.click(badge.querySelector("button"));
    await tick();
    x.st.navs.length
      ? ok("badge : Déconnexion → navigation /logout?returnTo=…")
      : fail("badge: le bouton de déconnexion ne navigue pas");
  }
}

console.log(
  failures === 0
    ? "\nSMOKE UI (page servie) : tout est OK"
    : `\nSMOKE UI : ${failures} échec(s)`
);
process.exit(failures === 0 ? 0 : 1);

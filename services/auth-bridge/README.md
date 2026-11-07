# auth-bridge

Le relais OIDC de la plateforme : **un client Keycloak confidentiel
dédié** (`cladone-login`) au service de tous les sites `*.cladone.com`
— les sites sont des `returnTo`, l'identité vit dans des cookies de
session (domaine `.cladone.com`, `httpOnly`, `secure`). Le client
`versifier` (public) appartient désormais à versifier2 uniquement : un
client ne peut pas être à la fois public et confidentiel.

## Flux

- **login** : `/login?returnTo=…` → Keycloak (**authorization code +
  PKCE S256**) → `/auth/callback` (échange du code avec
  `code_verifier`, cookies posés) → retour au `returnTo` (validé :
  https + `*.cladone.com` uniquement — anti open-redirect, la
  validation est **linéaire**, voir l'incident ReDoS ci-dessous).
- **PKCE** : le `code_verifier` ne transite **jamais par l'URL** (le
  `state` est renvoyé par le navigateur : y loger le verifier
  annulerait PKCE). Il voyage dans un cookie `oidc_tx` **HttpOnly
  signé HMAC-SHA256** (`KEYCLOAK_CLIENT_SECRET`), `Secure`,
  `SameSite=Lax`, `Path=/auth/callback`, 5 min, **one-shot**. Le même
  cookie porte un `state` aléatoire (nonce) vérifié au retour : la
  liaison navigateur↔callback couvre aussi le CSRF de callback.
- **vérification** : `GET /auth` — appelé par la gateway à chaque
  requête authentifiée (cookies + `Authorization` transmis) ; répond
  l'identité en en-têtes `X-User-Id/X-Username/X-Email/X-Roles/
  X-Scopes/X-Claims` (base64-JSON) ; **silent refresh** si le token
  est expiré (les cookies renouvelés sont propagés au navigateur par
  la gateway).
- **MCP** : `GET /auth/mcp` (bearer seul, vérifie le scope demandé via
  l'en-tête interne `X-MCP-Scope`).
- **logout** : `/logout` (efface les cookies + `end_session` OIDC avec
  `id_token_hint`) ; retour via `post_logout_redirect_uri` (les URIs
  valides sont dans le realm : attribut `post.logout.redirect.uris`
  du client — **chaque URI doit finir par `/*`**, le joker de HOST
  n'est pas honoré par KC 25).

## Single logout (mort de la session SSO)

Deux mécanismes **complémentaires** (attributs des clients
`cladone-login` et `versifier`) :

- **front-channel** (`frontchannel.logout.url` → `/frontchannel-logout`)
  : iframe posée par Keycloak sur sa page de logout, chargée **avec les
  cookies** — le seul canal qui sait les effacer (les sessions restent
  dans les cookies ; seule la liste de révocation est persistée).
- **backchannel** (`backchannel.logout.url` → `/backchannel-logout`,
  POST `logout_token` signé) : le `sid` de la session est ajouté à une
  liste de révocation **persistée** (24 h) consultée par `/auth` et
  `/auth/mcp` — un token d'une session SSO tuée est immédiatement
  « non authentifié », même après un redémarrage.

### Persistance des révocations

La liste des `sid` révoqués est **persistée** dans un fichier JSON
(`REVOCATION_STATE_FILE`, défaut `./auth-bridge-state.json`), chargé au
démarrage et écrit atomiquement (fichier temporaire + `fsync` +
`rename`, mode 0600) avant la réponse 200 à Keycloak.

C'est la correction du bug de **réactivation de session** : avec une
liste uniquement en mémoire, un redémarrage repartait vide et une
session révoquée avant le redémarrage pouvait être acceptée à nouveau.
Le fichier est obligatoire pour la persistance : un chemin non
accessible en écriture ou un fichier corrompu **refuse le démarrage**
(fail-closed), jamais un démarrage avec une liste vide.

En Docker, le compose monte `auth_bridge_data:/app/state` et définit
`REVOCATION_STATE_FILE=/app/state/auth-bridge-state.json`. Le volume
`auth_bridge_data` fait donc partie des sauvegardes. En HA (plusieurs
instances), un backend partagé (Redis) remplacera ce fichier ; chaque
instance doit alors voir la même liste.

## Endpoints

| route | rôle |
|---|---|
| `GET /login` | redirect vers Keycloak (PKCE S256, `state` = nonce) |
| `GET /auth/callback` | vérifie le nonce, échange le code (+ `code_verifier`), cookies, retour |
| `GET /logout` | clear cookies + end_session SSO |
| `GET /auth` | vérification de session (→ identité en en-têtes) |
| `GET /auth/mcp` | vérification bearer MCP (scope) |
| `GET /auth/popup-done` | page du flow login-popup du script de garde |
| `GET /frontchannel-logout` | iframe KC : efface les cookies |
| `POST /backchannel-logout` | logout_token → révocation du `sid` |
| `GET /health` | sonde de vie |
| `GET /connections` | page des connexions déléguées (proxy token-broker) |
| `GET /connect/{provider}` | démarre l'autorisation OAuth du fournisseur |
| `GET /oauth/{provider}/callback` | retour du fournisseur (proxy token-broker) |
| `POST /connections/{provider}/disconnect` | supprime le jeton local |

## Connexions déléguées (token-broker)

Les routes `/connections`, `/connect/*` et `/oauth/*/callback` sont un
**proxy** vers le service interne `token-broker` : le navigateur ne
l'atteint jamais. Seul `auth-bridge` connaît le secret partagé et
ajoute `X-User-Id` après vérification de la session Keycloak. Le
callback est volontairement sans session : le `state` one-shot du
broker lie le retour à l'utilisateur.

Variables optionnelles (sans `TOKEN_BROKER_SHARED_SECRET`, ces routes
répondent `503`) : `TOKEN_BROKER_URL` (défaut
`http://token-broker:4000`) et `TOKEN_BROKER_SHARED_SECRET`.

## Config (tout par env, défauts cladone dans le code)

`KEYCLOAK_BASE_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`
(`cladone-login`, client **confidentiel** PKCE S256 du realm),
`KEYCLOAK_CLIENT_SECRET` (obligatoire), `PUBLIC_AUTH_URL`,
`COOKIE_DOMAIN`, `DEFAULT_APP_URL`, `LOGOUT_URL`, `MCP_RESOURCE`,
`MCP_SCOPE`, `REVOCATION_STATE_FILE` (fichier JSON persistant des
révocations, défaut `./auth-bridge-state.json`) — voir
`../.env.example`.

## Tests

```
node --test                     # tous les tests (server + revocation)
node --test server.test.js      # ou make test (racine)
node --test revocation.test.js  # persistance/rejeu/expiration
```

Couvre : `safeReturnTo` (dont la **régression ReDoS** — l'ancienne
regex, aux backslashes avalés par les chaînes JS, entrait en
backtracking catastrophique sur les hosts à deux sous-niveaux et
gelait tout le service à 99% CPU), les redirections/refus des
endpoints sans dépendance Keycloak, et la persistance de la liste de
révocation (redémarrage, expiration, fichier corrompu).

## Gotchas

- **le realm vivant est la source de vérité** : `--import-realm` saute
  les realms existants — un changement d'attribut client se fait dans
  la console, le ré-export du deploy le ramène dans git (vérifier le
  `git diff`) ;
- le mot de passe `KEYCLOAK_ADMIN_PASSWORD` du `.env` ne re-synchronise
  PAS un admin master déjà existant (bootstrap one-shot) ;
- Keycloak exige un `id_token_hint` valable pour honorer
  `post_logout_redirect_uri` — sinon `/logout` l'omet (page « logged
  out » standard au lieu d'une erreur).

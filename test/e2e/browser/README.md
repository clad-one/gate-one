# Playwright browser E2E

Runs against the local Compose stack (fake Google + brokers + Gate One):

```bash
cd ~/proj/2026/gate-one-src
make e2e-up
```

Install once:

```bash
cd test/e2e/browser
npm install
npx playwright install chromium
```

Run:

```bash
cd test/e2e/browser
npm test
# or from the repo root:
make test-browser
```

Tests:

| File | Covers |
|---|---|
| `login.spec.ts` | fake Google login, SSO across `gate-one-1`/`gate-one-2` |
| `cookies.spec.ts` | RP cookie domain-wide, broker cookie host-only, HttpOnly, SameSite=Lax |
| `logout.spec.ts` | logout invalidates the RP session (`302` to login) |
| `storage.spec.ts` | logout in one tab triggers the storage event + immediate probe in another tab |

The stack is HTTP, so `Secure=false` here. The production canary uses
HTTPS and is validated separately.

All hosts are `*.localhost` (loopback). Run the browser on the same
machine as Docker; with Docker Desktop/WSL integration this is the WSL
distro.

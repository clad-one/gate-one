# Turnstile demo (gate mode)

Shows the **gate** protection on a page with no form: the visitor is
challenged once, a signed clearance cookie is set, and the next
requests go through. Cloudflare's **test keys** are used, so nothing
has to be created in a Cloudflare account. Internet is required
(`api.js` and Siteverify are real).

## Run

```bash
./run.sh gate   # the whole page is gated    (paths: ["/*"])
./run.sh api    # only the action is gated   (paths: ["/api/*"])
```

Then open <http://app.demo.localhost:3000/>.

### `gate` mode

- `GET /` without a clearance is answered with a "Checking your
  browser" page served **at the same URL** (no redirect);
- the invisible test widget solves the challenge and posts the token to
  `/__gate-one/turnstile/verify`;
- Gate One calls Siteverify, sets `gate_one_turnstile` (30 min) and
  redirects to `/`;
- the application page is then served; the backend was called once.

### `api` mode

- the page is public (indexable); the injected script pre-clears in the
  background;
- a `POST /api/submit` without clearance is answered
  `403 {"error":"turnstile_required"}` with `X-Gate-One-Turnstile:
  required`;
- the injected script opens the challenge, exchanges the token and
  replays the request; the application sees one call, with a cookie.

## What to look at

- the initial `403` challenge page in `gate` mode;
- `Set-Cookie: gate_one_turnstile=...; HttpOnly; Max-Age=1800`;
- the Gate One logs: `TURNSTILE gate granted host=... path=...`;
- in `api` mode, the page loads before the challenge; the submit
  completes after the clearance (or is replayed automatically);
- the backend log: one request per action, never the rejected one.

## Test keys

| Key | Value |
|---|---|
| Site key | `1x00000000000000000000AA` (always passes) |
| Secret | `1x0000000000000000000000000000000AA` (always passes) |

Override `TURNSTILE_SECRET` to use a real widget. The `action` is
omitted in the demo because the test token does not carry one; a real
widget can use `action` (both sides must match).

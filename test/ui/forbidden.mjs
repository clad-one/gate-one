// Identity-403 banner suite (authGuard.forbidden.banner): the guard
// shows a dismissable hint ONLY on the gateway's OWN rights refusal
// (marked 403 + JSON) — never on a backend 403, never when disabled,
// never on the HTML navigation page, and at most once per page load.
import { renderGuard, mkWindow, tick } from "./harness.mjs";

let failures = 0;
const ok = (label) => console.log("OK  " + label);
const fail = (m) => { console.error("FAIL " + m); failures++; };

const html = `<!DOCTYPE html><html><head></head><body>
<button id="go">Go</button>
</body></html>`;

const GUARD_ON = renderGuard({ forbidden: "true" });
const GUARD_OFF = renderGuard(); // FORBIDDEN = null (default)

// ── 1. gateway identity 403 (marked JSON) → banner, app keeps its 403 ──
{
  const x = await mkWindow(GUARD_ON, html, null, "[]", {
    forbidden: { path: "/api/denied" },
  });
  let status = null;
  x.w.fetch("/api/denied", { method: "POST", body: "{}" })
    .then(r => { status = r.status; });
  await tick();
  x.forbiddenBanner()
    ? ok("gateway 403 (marked JSON) → banner")
    : fail("gateway 403: banner expected");
  status === 403
    ? ok("app still receives its 403 (response untouched)")
    : fail(`app status = ${status} (want 403)`);
  x.st.openCalls === 0
    ? ok("forbidden banner never opens a login tab")
    : fail(`a tab opened (openCalls=${x.st.openCalls})`);
  !x.banner()
    ? ok("forbidden banner is distinct from the 401 banner")
    : fail("the 401 'Sign-in required' banner must not show");
}

// ── 2. backend 403 (no gateway marker) → NO banner ──
{
  const x = await mkWindow(GUARD_ON, html, null, "[]", {
    forbidden: { path: "/api/denied", marked: false },
  });
  x.w.fetch("/api/denied", { method: "POST", body: "{}" }).then(() => {});
  await tick();
  x.forbiddenBanner()
    ? fail("backend 403 (no marker) must NOT trigger the banner")
    : ok("backend 403 → no banner");
}

// ── 3. marker present but banner disabled (default) → NO banner ──
{
  const x = await mkWindow(GUARD_OFF, html, null, "[]", {
    forbidden: { path: "/api/denied" },
  });
  x.w.fetch("/api/denied", { method: "POST", body: "{}" }).then(() => {});
  await tick();
  x.forbiddenBanner()
    ? fail("banner shown while authGuard.forbidden.banner is off")
    : ok("banner disabled → no banner");
}

// ── 4. marked 403 but HTML (navigation page fetched) → NO banner ──
{
  const x = await mkWindow(GUARD_ON, html, null, "[]", {
    forbidden: { path: "/api/denied", contentType: "text/html; charset=utf-8" },
  });
  x.w.fetch("/api/denied").then(() => {});
  await tick();
  x.forbiddenBanner()
    ? fail("HTML navigation 403 must not trigger the fetch banner")
    : ok("HTML (navigation) 403 → no banner");
}

// ── 5. several marked 403s → ONE banner per page load ──
{
  const x = await mkWindow(GUARD_ON, html, null, "[]", {
    forbidden: { path: "/api/denied" },
  });
  x.w.fetch("/api/denied", { method: "POST", body: "{}" }).then(() => {});
  x.w.fetch("/api/denied", { method: "POST", body: "{}" }).then(() => {});
  await tick();
  x.forbiddenBannerCount() === 1
    ? ok("banner shown at most once per page load")
    : fail(`banner count = ${x.forbiddenBannerCount()} (want 1)`);
}

console.log(
  failures === 0 ? "FORBIDDEN SUITE OK" : `FORBIDDEN SUITE: ${failures} failure(s)`
);
globalThis.__uiFailures = (globalThis.__uiFailures || 0) + failures;

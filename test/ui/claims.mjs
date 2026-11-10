// Claim conditions: one accepted value, or a list (OR / anyOf on the
// same claim); array-valued token claims; markup and uiGate rules.
import { renderGuard, mkWindow } from "./harness.mjs";

let failures = 0;
const ok = (label) => console.log("OK  " + label);
const fail = (m) => { console.error("FAIL " + m); failures++; };

const html = `<!DOCTYPE html><html><head></head><body>
<div>
  <span id="one" data-gtw-claims='{"email":"a@b.c"}'>one</span>
  <span id="any" data-gtw-claims='{"email":["x@y","a@b.c"]}'>any</span>
  <span id="none" data-gtw-claims='{"email":["x@y","z@w"]}'>none</span>
  <span id="presence" data-gtw-claims='{"email":["*"]}'>presence</span>
  <span id="array" data-gtw-claims='{"groups":"admin"}'>array</span>
  <span id="array_list" data-gtw-claims='{"groups":["nope","user"]}'>array list</span>
  <span id="array_none" data-gtw-claims='{"groups":"nope"}'>array none</span>
  <span id="and" data-gtw-claims='{"email":["a@b.c"],"email_verified":"false"}'>and</span>
  <span id="and_fail" data-gtw-claims='{"email":["a@b.c"],"email_verified":"true"}'>and fail</span>
  <span id="bad" data-gtw-claims='not json'>bad</span>
  <span id="rule_any">rule any</span>
  <span id="rule_none">rule none</span>
  <span id="rule_array">rule array</span>
</div>
</body></html>`;

const RULES = [
  { selector: "#rule_any", claims: { email: ["x@y", "a@b.c"] } },
  { selector: "#rule_none", claims: { email: ["x@y", "z@w"] } },
  { selector: "#rule_array", claims: { groups: "admin" } },
];
const GUARD = renderGuard({ uiGate: JSON.stringify(RULES) });

const SESSION = {
  roles: [],
  scopes: [],
  claims: {
    email: ["a@b.c", "c@d.e"],
    groups: ["admin", "user"],
    email_verified: false,
  },
};

const x = await mkWindow(GUARD, html, SESSION);
const hidden = (id) =>
  x.doc.getElementById(id).hasAttribute("data-gtw-gated-off");

!hidden("one") ? ok("claims: single string still matches")
  : fail("single string claim hidden");
!hidden("any") ? ok("claims: list = OR (one value matches)")
  : fail("list claim hidden although one value matches");
hidden("none") ? ok("claims: list = OR (no value matches)")
  : fail("list claim visible although no value matches");
!hidden("presence") ? ok("claims: \"*\" in a list = presence")
  : fail("presence-in-list claim hidden");
!hidden("array") ? ok("claims: array-valued token claim (one element)")
  : fail("array-valued claim hidden");
!hidden("array_list") ? ok("claims: array token claim + list condition")
  : fail("array token claim with a list condition hidden");
hidden("array_none") ? ok("claims: array token claim, no element matches")
  : fail("array token claim visible without a matching element");
!hidden("and") ? ok("claims: keys combine with AND")
  : fail("AND claim hidden");
hidden("and_fail") ? ok("claims: AND fails on one key")
  : fail("AND claim visible with a failing key");
hidden("bad") ? ok("claims: invalid JSON is refused (hidden)")
  : fail("invalid claims JSON visible");

!hidden("rule_any") ? ok("uiGate claims: list OR (rule)")
  : fail("uiGate list claim hidden");
hidden("rule_none") ? ok("uiGate claims: list OR, no match (rule)")
  : fail("uiGate list claim visible without a match");
!hidden("rule_array") ? ok("uiGate claims: array token claim (rule)")
  : fail("uiGate array-valued claim hidden");

console.log(
  failures === 0 ? "CLAIMS OK" : `CLAIMS: ${failures} failure(s)`
);
globalThis.__uiFailures = (globalThis.__uiFailures || 0) + failures;

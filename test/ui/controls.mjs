// Form-control generalization suite: activation vs deactivation for
// every control family the guard supports.
//
//   click = action  : checkbox, radio, details/summary, aria-*,
//                     reset (always free), submit/button/file
//   change = action : select, range, date/time/color (data-gtw-auth-off
//                     marks the OFF value; default value otherwise)
//   click = focus   : text/textarea/number (never gated)
//
// The page is a real HTML fixture (controls.html); the guard is
// rendered from guard.js.tmpl at every run, so this suite can never
// test a stale script.
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";
import { renderGuard, mkWindow, tick } from "./harness.mjs";

const HTML = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), "controls.html"),
  "utf8"
);

const guard = renderGuard();

let failures = 0;
const ok = (label) => console.log("OK  " + label);
const fail = (m) => { console.error("FAIL " + m); failures++; };
const want = (cond, label, detail) =>
  cond ? ok(label) : fail(detail ? `${label}: ${detail}` : label);

// ── helpers ────────────────────────────────────────────────────────
const click = (x, el) => x.click(el);

// pointerdown before click: the guard records a radio's pre-click
// checkedness there (click alone is already post-toggle in browsers).
const pointerClick = (x, el) => {
  el.dispatchEvent(new x.w.Event("pointerdown", { bubbles: true }));
  return x.click(el);
};

// focusin + value assignment + change: the guard records the pre-change
// value on focusin/pointerdown, then gates the change event.
const change = (x, el, value) => {
  el.dispatchEvent(new x.w.Event("focusin", { bubbles: true }));
  el.value = value;
  el.dispatchEvent(new x.w.Event("change", { bubbles: true }));
};

const countClicks = (x, el) => {
  const st = { n: 0 };
  el.addEventListener("click", () => { st.n++; });
  return st;
};

const countChanges = (x, el) => {
  const st = { n: 0 };
  el.addEventListener("change", () => { st.n++; });
  return st;
};

const toggleAria = (el, attr) => {
  el.addEventListener("click", () => {
    el.setAttribute(attr, el.getAttribute(attr) === "true" ? "false" : "true");
  });
};

// ── 1. checkbox ────────────────────────────────────────────────────
{
  const x = await mkWindow(guard, HTML, null);
  const cb = x.doc.getElementById("cb_before");
  click(x, cb);
  await tick();
  want(x.st.openCalls === 1, "checkbox before: checking → login",
       `openCalls=${x.st.openCalls}`);
  want(!cb.checked, "checkbox before: checking neutralized");
}
{
  const x = await mkWindow(guard, HTML, null);
  const cb = x.doc.getElementById("cb_before");
  cb.checked = true;
  click(x, cb);
  await tick();
  want(x.st.openCalls === 0, "checkbox before: unchecking → no login",
       `openCalls=${x.st.openCalls}`);
  want(!cb.checked, "checkbox before: unchecking is native");
}
{
  const x = await mkWindow(guard, HTML, null);
  const cb = x.doc.getElementById("cb_before");
  cb.checked = true;
  click(x, x.doc.getElementById("cb_before_label"));
  await tick();
  want(x.st.openCalls === 0, "checkbox before: unchecking via label → no login",
       `openCalls=${x.st.openCalls}`);
  want(!cb.checked, "checkbox before: unchecking via label is native");
}
{
  const x = await mkWindow(guard, HTML, null);
  const cb = x.doc.getElementById("cb_after");
  click(x, cb);
  await tick();
  want(x.st.openCalls === 1, "checkbox after: checking → login",
       `openCalls=${x.st.openCalls}`);
  want(cb.checked, "checkbox after: native check preserved");
}
{
  const x = await mkWindow(guard, HTML, null);
  const cb = x.doc.getElementById("cb_after");
  cb.checked = true;
  click(x, cb);
  await tick();
  want(x.st.openCalls === 0, "checkbox after: unchecking → no login",
       `openCalls=${x.st.openCalls}`);
  want(!cb.checked, "checkbox after: unchecking is native");
}
{
  const x = await mkWindow(guard, HTML, null);
  x.doc.getElementById("cb_before").checked = true;
  await tick();
  want(x.st.openCalls === 0,
       "checkbox: programmatic check alone → no login (no DOM event)",
       `openCalls=${x.st.openCalls}`);
}

// ── 2. radio (pre-click state tracked on pointerdown) ──────────────
{
  const x = await mkWindow(guard, HTML, null);
  const a = x.doc.getElementById("r_a");
  pointerClick(x, x.doc.getElementById("r_a_label"));
  await tick();
  want(x.st.openCalls === 0, "radio: already selected → no login",
       `openCalls=${x.st.openCalls}`);
  want(a.checked, "radio: already selected stays selected");
}
{
  const x = await mkWindow(guard, HTML, null);
  const b = x.doc.getElementById("r_b");
  pointerClick(x, x.doc.getElementById("r_b_label"));
  await tick();
  want(x.st.openCalls === 1, "radio: selecting another → login",
       `openCalls=${x.st.openCalls}`);
  want(!b.checked, "radio: selecting another neutralized");
}
{
  const x = await mkWindow(guard, HTML, null);
  const a = x.doc.getElementById("rl_a");
  pointerClick(x, x.doc.getElementById("rl_a_label"));
  await tick();
  want(x.st.openCalls === 0,
       "radio label-gated: already selected → no login",
       `openCalls=${x.st.openCalls}`);
  want(a.checked, "radio label-gated: already selected stays selected");
}
{
  const x = await mkWindow(guard, HTML, null);
  const b = x.doc.getElementById("rl_b");
  pointerClick(x, x.doc.getElementById("rl_b_label"));
  await tick();
  want(x.st.openCalls === 1,
       "radio label-gated: selecting another → login",
       `openCalls=${x.st.openCalls}`);
  want(!b.checked, "radio label-gated: selecting another neutralized");
}

// ── 3. select (change = action, click = open) ──────────────────────
{
  const x = await mkWindow(guard, HTML, null);
  const sel = x.doc.getElementById("sel_before");
  const ch = countChanges(x, sel);
  click(x, sel);
  await tick();
  want(x.st.openCalls === 0, "select: click (open) → no login",
       `openCalls=${x.st.openCalls}`);
  change(x, sel, "a");
  await tick();
  want(x.st.openCalls === 1, "select before: non-off change → login",
       `openCalls=${x.st.openCalls}`);
  want(sel.value === "", "select before: value reverted", `value=${sel.value}`);
  want(ch.n === 0, "select before: app change handler not run",
       `changes=${ch.n}`);
  change(x, sel, "");
  await tick();
  want(x.st.openCalls === 1, "select before: off change → no login",
       `openCalls=${x.st.openCalls}`);
  want(sel.value === "", "select before: off value kept", `value=${sel.value}`);
  want(ch.n === 1, "select before: app change handler run on off",
       `changes=${ch.n}`);
}
{
  const x = await mkWindow(guard, HTML, null);
  const sel = x.doc.getElementById("sel_after");
  const ch = countChanges(x, sel);
  click(x, sel);
  await tick();
  want(x.st.openCalls === 0, "select after: click (open) → no login",
       `openCalls=${x.st.openCalls}`);
  change(x, sel, "a");
  await tick();
  want(x.st.openCalls === 1, "select after: non-off change → login",
       `openCalls=${x.st.openCalls}`);
  want(sel.value === "a", "select after: value kept", `value=${sel.value}`);
  want(ch.n === 1, "select after: app change handler run", `changes=${ch.n}`);
  change(x, sel, "");
  await tick();
  want(x.st.openCalls === 1, "select after: off change → no login",
       `openCalls=${x.st.openCalls}`);
  want(ch.n === 2, "select after: app change handler run on off",
       `changes=${ch.n}`);
}
{
  const x = await mkWindow(guard, HTML, null);
  const sel = x.doc.getElementById("sel_default");
  change(x, sel, "y");
  await tick();
  want(x.st.openCalls === 1, "select: default value is the off value",
       `openCalls=${x.st.openCalls}`);
  want(sel.value === "x", "select: reverted to default", `value=${sel.value}`);
  change(x, sel, "x");
  await tick();
  want(x.st.openCalls === 1, "select: returning to default → no login",
       `openCalls=${x.st.openCalls}`);
}
{
  const x = await mkWindow(guard, HTML, null);
  const sel = x.doc.getElementById("sel_override");
  change(x, sel, "y");
  await tick();
  want(x.st.openCalls === 0, "select: explicit off value → no login",
       `openCalls=${x.st.openCalls}`);
  want(sel.value === "y", "select: explicit off kept", `value=${sel.value}`);
  change(x, sel, "x");
  await tick();
  want(x.st.openCalls === 1, "select: leaving explicit off → login",
       `openCalls=${x.st.openCalls}`);
  want(sel.value === "y", "select: reverted to explicit off",
       `value=${sel.value}`);
}
{
  const x = await mkWindow(guard, HTML, null);
  const sel = x.doc.getElementById("sel_for");
  click(x, x.doc.getElementById("sel_for_label"));
  await tick();
  want(x.st.openCalls === 0, "select label[for]: click → no login",
       `openCalls=${x.st.openCalls}`);
  change(x, sel, "a");
  await tick();
  want(x.st.openCalls === 1, "select label[for]: change → login",
       `openCalls=${x.st.openCalls}`);
  want(sel.value === "", "select label[for]: value reverted",
       `value=${sel.value}`);
}
{
  const x = await mkWindow(guard, HTML, null);
  const sel = x.doc.getElementById("wsel");
  click(x, sel);
  await tick();
  want(x.st.openCalls === 0, "select wrapper: click → no login",
       `openCalls=${x.st.openCalls}`);
  change(x, sel, "a");
  await tick();
  want(x.st.openCalls === 1, "select wrapper: change → login",
       `openCalls=${x.st.openCalls}`);
  want(sel.value === "", "select wrapper: value reverted",
       `value=${sel.value}`);
}

// ── 4. range ───────────────────────────────────────────────────────
{
  const x = await mkWindow(guard, HTML, null);
  const r = x.doc.getElementById("range_before");
  const ch = countChanges(x, r);
  click(x, r);
  await tick();
  want(x.st.openCalls === 0, "range: click → no login",
       `openCalls=${x.st.openCalls}`);
  change(x, r, "5");
  await tick();
  want(x.st.openCalls === 1, "range before: non-off change → login",
       `openCalls=${x.st.openCalls}`);
  want(r.value === "0", "range before: value reverted", `value=${r.value}`);
  want(ch.n === 0, "range before: app change handler not run",
       `changes=${ch.n}`);
  change(x, r, "0");
  await tick();
  want(x.st.openCalls === 1, "range before: off change → no login",
       `openCalls=${x.st.openCalls}`);
  want(ch.n === 1, "range before: app change handler run on off",
       `changes=${ch.n}`);
}
{
  const x = await mkWindow(guard, HTML, null);
  const r = x.doc.getElementById("range_default");
  change(x, r, "7");
  await tick();
  want(x.st.openCalls === 1, "range: default value is the off value",
       `openCalls=${x.st.openCalls}`);
  want(r.value === "5", "range: reverted to default", `value=${r.value}`);
  change(x, r, "5");
  await tick();
  want(x.st.openCalls === 1, "range: returning to default → no login",
       `openCalls=${x.st.openCalls}`);
}

// ── 5. date (same value-control path) ──────────────────────────────
{
  const x = await mkWindow(guard, HTML, null);
  const d = x.doc.getElementById("date_before");
  click(x, d);
  await tick();
  want(x.st.openCalls === 0, "date: click → no login",
       `openCalls=${x.st.openCalls}`);
  change(x, d, "2026-01-01");
  await tick();
  want(x.st.openCalls === 1, "date before: non-off change → login",
       `openCalls=${x.st.openCalls}`);
  want(d.value === "", "date before: value reverted", `value=${d.value}`);
  change(x, d, "");
  await tick();
  want(x.st.openCalls === 1, "date before: off change → no login",
       `openCalls=${x.st.openCalls}`);
}

// ── 6. passive click controls: focus, never gated ──────────────────
{
  const x = await mkWindow(guard, HTML, null);
  const text = x.doc.getElementById("text_before");
  const ta = x.doc.getElementById("textarea_before");
  const num = x.doc.getElementById("number_before");
  const ct = countClicks(x, text);
  const ca = countClicks(x, ta);
  const cn = countClicks(x, num);
  click(x, text);
  click(x, ta);
  click(x, num);
  await tick();
  want(x.st.openCalls === 0, "text/textarea/number: click → no login",
       `openCalls=${x.st.openCalls}`);
  want(ct.n === 1 && ca.n === 1 && cn.n === 1,
       "text/textarea/number: native click preserved",
       `handlers=${ct.n}/${ca.n}/${cn.n}`);
}

// ── 7. activation click controls ───────────────────────────────────
{
  const x = await mkWindow(guard, HTML, null);
  const f = x.doc.getElementById("file_before");
  const c = countClicks(x, f);
  click(x, f);
  await tick();
  want(x.st.openCalls === 1, "file: click → login",
       `openCalls=${x.st.openCalls}`);
  want(c.n === 0, "file: native click neutralized", `handlers=${c.n}`);
}
{
  const x = await mkWindow(guard, HTML, null);
  const b = x.doc.getElementById("btn_before");
  const c = countClicks(x, b);
  click(x, b);
  await tick();
  want(x.st.openCalls === 1, "button: click → login",
       `openCalls=${x.st.openCalls}`);
  want(c.n === 0, "button: native click neutralized", `handlers=${c.n}`);
}
{
  const x = await mkWindow(guard, HTML, null);
  const s = x.doc.getElementById("submit_before");
  const c = countClicks(x, s);
  click(x, s);
  await tick();
  want(x.st.openCalls === 1, "submit: click → login",
       `openCalls=${x.st.openCalls}`);
  want(c.n === 0, "submit: native click neutralized", `handlers=${c.n}`);
}
{
  const x = await mkWindow(guard, HTML, null);
  const r = x.doc.getElementById("reset_before");
  const c = countClicks(x, r);
  click(x, r);
  await tick();
  want(x.st.openCalls === 0, "reset: click → no login",
       `openCalls=${x.st.openCalls}`);
  want(c.n === 1, "reset: native click preserved", `handlers=${c.n}`);
}

// ── 8. details/summary ─────────────────────────────────────────────
{
  const x = await mkWindow(guard, HTML, null);
  const det = x.doc.getElementById("det_before");
  const sum = x.doc.getElementById("det_sum");
  click(x, sum);
  await tick();
  want(x.st.openCalls === 1, "details before: opening → login",
       `openCalls=${x.st.openCalls}`);
  want(!det.open, "details before: opening neutralized");
  det.open = true;
  click(x, sum);
  await tick();
  want(x.st.openCalls === 1, "details before: closing → no login",
       `openCalls=${x.st.openCalls}`);
  want(!det.open, "details before: closing is native");
}
{
  const x = await mkWindow(guard, HTML, null);
  const det = x.doc.getElementById("det_after");
  const sum = x.doc.getElementById("det_sum_after");
  click(x, sum);
  await tick();
  want(x.st.openCalls === 1, "details after: opening → login",
       `openCalls=${x.st.openCalls}`);
  want(det.open, "details after: native open preserved");
  click(x, sum);
  await tick();
  want(x.st.openCalls === 1, "details after: closing → no login",
       `openCalls=${x.st.openCalls}`);
  want(!det.open, "details after: closed");
}

// ── 9. aria toggles (pre-state read from the attribute) ────────────
{
  const x = await mkWindow(guard, HTML, null);
  const b = x.doc.getElementById("aria_before");
  toggleAria(b, "aria-pressed");
  click(x, b);
  await tick();
  want(x.st.openCalls === 1, "aria-pressed before: off → login",
       `openCalls=${x.st.openCalls}`);
  want(b.getAttribute("aria-pressed") === "false",
       "aria-pressed before: stayed off");
  b.setAttribute("aria-pressed", "true");
  click(x, b);
  await tick();
  want(x.st.openCalls === 1, "aria-pressed before: on → no login",
       `openCalls=${x.st.openCalls}`);
  want(b.getAttribute("aria-pressed") === "false",
       "aria-pressed before: turned off");
}
{
  const x = await mkWindow(guard, HTML, null);
  const b = x.doc.getElementById("aria_after");
  toggleAria(b, "aria-pressed");
  click(x, b);
  await tick();
  want(x.st.openCalls === 1, "aria-pressed after: off → login",
       `openCalls=${x.st.openCalls}`);
  want(b.getAttribute("aria-pressed") === "true",
       "aria-pressed after: turned on");
  click(x, b);
  await tick();
  want(x.st.openCalls === 1, "aria-pressed after: on → no login",
       `openCalls=${x.st.openCalls}`);
  want(b.getAttribute("aria-pressed") === "false",
       "aria-pressed after: turned off");
}
{
  const x = await mkWindow(guard, HTML, null);
  const b = x.doc.getElementById("switch_before");
  toggleAria(b, "aria-checked");
  click(x, b);
  await tick();
  want(x.st.openCalls === 1, "aria-checked before: off → login",
       `openCalls=${x.st.openCalls}`);
  want(b.getAttribute("aria-checked") === "false",
       "aria-checked before: stayed off");
  b.setAttribute("aria-checked", "true");
  click(x, b);
  await tick();
  want(x.st.openCalls === 1, "aria-checked before: on → no login",
       `openCalls=${x.st.openCalls}`);
  want(b.getAttribute("aria-checked") === "false",
       "aria-checked before: turned off");
}
{
  const x = await mkWindow(guard, HTML, null);
  const b = x.doc.getElementById("menu_before");
  toggleAria(b, "aria-expanded");
  click(x, b);
  await tick();
  want(x.st.openCalls === 1, "aria-expanded before: closed → login",
       `openCalls=${x.st.openCalls}`);
  want(b.getAttribute("aria-expanded") === "false",
       "aria-expanded before: stayed closed");
  b.setAttribute("aria-expanded", "true");
  click(x, b);
  await tick();
  want(x.st.openCalls === 1, "aria-expanded before: open → no login",
       `openCalls=${x.st.openCalls}`);
  want(b.getAttribute("aria-expanded") === "false",
       "aria-expanded before: closed");
}

// ── 10. hidden=before: deactivation stays free ─────────────────────
{
  const x = await mkWindow(guard, HTML, null);
  const cb = x.doc.getElementById("cb_hidden");
  click(x, x.doc.getElementById("cb_hidden_label"));
  await tick();
  want(x.st.openCalls === 0, "hidden before: unchecking via label → no login",
       `openCalls=${x.st.openCalls}`);
  want(!cb.checked, "hidden before: unchecked");
  want(!x.banner(), "hidden before: no banner on uncheck");
}
{
  const x = await mkWindow(guard, HTML, null);
  const cb = x.doc.getElementById("cb_hidden");
  cb.checked = false;
  click(x, x.doc.getElementById("cb_hidden_label"));
  await tick();
  want(x.st.openCalls === 0, "hidden before: checking via label → no tab",
       `openCalls=${x.st.openCalls}`);
  want(!cb.checked, "hidden before: checking neutralized");
  want(x.banner(), "hidden before: banner on activation");
}

// ── 11. label[for] and wrapper ─────────────────────────────────────
{
  const x = await mkWindow(guard, HTML, null);
  const cb = x.doc.getElementById("for_box");
  click(x, x.doc.getElementById("for_label"));
  await tick();
  want(x.st.openCalls === 0, "label[for] checkbox: unchecking → no login",
       `openCalls=${x.st.openCalls}`);
  want(!cb.checked, "label[for] checkbox: unchecked");
}
{
  const x = await mkWindow(guard, HTML, null);
  const cb = x.doc.getElementById("for_box");
  cb.checked = false;
  click(x, x.doc.getElementById("for_label"));
  await tick();
  want(x.st.openCalls === 1, "label[for] checkbox: checking → login",
       `openCalls=${x.st.openCalls}`);
  want(!cb.checked, "label[for] checkbox: checking neutralized");
}
{
  const x = await mkWindow(guard, HTML, null);
  const cb = x.doc.getElementById("wcb");
  cb.checked = true;
  click(x, cb);
  await tick();
  want(x.st.openCalls === 0, "wrapper checkbox: unchecking → no login",
       `openCalls=${x.st.openCalls}`);
  want(!cb.checked, "wrapper checkbox: unchecked");
}
{
  const x = await mkWindow(guard, HTML, null);
  const cb = x.doc.getElementById("wcb");
  click(x, cb);
  await tick();
  want(x.st.openCalls === 1, "wrapper checkbox: checking → login",
       `openCalls=${x.st.openCalls}`);
  want(!cb.checked, "wrapper checkbox: checking neutralized");
}

// ── 12. uiGate rules on the generalized controls ───────────────────
const RULE_HTML = `<!DOCTYPE html><html><head></head><body>
<select id="rule_select" data-gtw-auth-off="">
  <option value="" selected>Off</option><option value="a">A</option>
</select>
<input type="text" id="rule_text">
<button type="reset" id="rule_reset">Reset</button>
<button type="submit" id="rule_submit">Send</button>
</body></html>`;
const ruleGuard = renderGuard({
  uiGate: JSON.stringify([
    { selector: "#rule_select", auth: "before" },
    { selector: "#rule_text", auth: "before" },
    { selector: "#rule_reset", auth: "before" },
    { selector: "#rule_submit", auth: "before" },
  ]),
});
{
  const x = await mkWindow(ruleGuard, RULE_HTML, null);
  const sel = x.doc.getElementById("rule_select");
  click(x, sel);
  await tick();
  want(x.st.openCalls === 0, "uiGate select: click → no login",
       `openCalls=${x.st.openCalls}`);
  change(x, sel, "a");
  await tick();
  want(x.st.openCalls === 1, "uiGate select: change → login",
       `openCalls=${x.st.openCalls}`);
  want(sel.value === "", "uiGate select: value reverted", `value=${sel.value}`);
  change(x, sel, "");
  await tick();
  want(x.st.openCalls === 1, "uiGate select: off → no login",
       `openCalls=${x.st.openCalls}`);
}
{
  const x = await mkWindow(ruleGuard, RULE_HTML, null);
  click(x, x.doc.getElementById("rule_text"));
  await tick();
  want(x.st.openCalls === 0, "uiGate text: click → no login",
       `openCalls=${x.st.openCalls}`);
}
{
  const x = await mkWindow(ruleGuard, RULE_HTML, null);
  click(x, x.doc.getElementById("rule_reset"));
  await tick();
  want(x.st.openCalls === 0, "uiGate reset: click → no login",
       `openCalls=${x.st.openCalls}`);
}
{
  const x = await mkWindow(ruleGuard, RULE_HTML, null);
  click(x, x.doc.getElementById("rule_submit"));
  await tick();
  want(x.st.openCalls === 1, "uiGate submit: click → login",
       `openCalls=${x.st.openCalls}`);
}

console.log(
  failures === 0 ? "CONTROLS SUITE OK" : `CONTROLS SUITE: ${failures} failure(s)`
);
globalThis.__uiFailures = (globalThis.__uiFailures || 0) + failures;

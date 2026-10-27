// UI harness entry point:
//   node run.mjs            → local matrix + uiGate suite (guard
//                             rendered from the source, never stale)
//   node run.mjs --served   → behavioral smoke against the deployed page
import { pathToFileURL } from "url";
import path from "path";

const here = path.dirname(new URL(import.meta.url).pathname);
const served = process.argv.includes("--served");
if (served) {
  await import(pathToFileURL(path.join(here, "served.mjs")).href);
} else {
  await import(pathToFileURL(path.join(here, "matrix.mjs")).href);
  await import(pathToFileURL(path.join(here, "rules.mjs")).href);
  await import(pathToFileURL(path.join(here, "controls.mjs")).href);
  await import(pathToFileURL(path.join(here, "forbidden.mjs")).href);
  console.log(
    globalThis.__uiFailures === 0
      ? "\nUI HARNESS: all OK"
      : `\nUI HARNESS: ${globalThis.__uiFailures} failure(s) total`
  );
  process.exit(globalThis.__uiFailures === 0 ? 0 : 1);
}

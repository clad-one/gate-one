// Point d'entrée du harnais UI :
//   node run.mjs            → matrice locale + suite uiGate (garde
//                             rendue du source, jamais du périmé)
//   node run.mjs --served   → smoke comportemental contre la page déployée
import { pathToFileURL } from "url";
import path from "path";

const here = path.dirname(new URL(import.meta.url).pathname);
const served = process.argv.includes("--served");
if (served) {
  await import(pathToFileURL(path.join(here, "served.mjs")).href);
} else {
  await import(pathToFileURL(path.join(here, "matrix.mjs")).href);
  await import(pathToFileURL(path.join(here, "rules.mjs")).href);
  console.log(
    globalThis.__uiFailures === 0
      ? "\nHARNAIS UI : tout est OK"
      : `\nHARNAIS UI : ${globalThis.__uiFailures} échec(s) au total`
  );
  process.exit(globalThis.__uiFailures === 0 ? 0 : 1);
}

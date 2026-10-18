// Harnais de parité pour le SW de réécriture — lancé par
// TestRewriteParityWithServiceWorkerJS (rewrite_test.go) :
//
//	node rewrite_parity_harness.cjs sw.js cases.txt results.txt
//
// Il exécute le SW généré dans un contexte vm avec des stubs minimes
// (addEventListener capturé, fetch factice qui révèle l'URL demandée),
// puis pour chaque requête absolue imprime l'URL réellement fetchée —
// NO-INTERCEPT quand le SW n'appelle pas respondWith (requête laissée
// au réseau : équivalent « passe telle quelle »).
const fs = require('fs');
const vm = require('vm');

const [swPath, casesPath, outPath] = process.argv.slice(2);
const swText = fs.readFileSync(swPath, 'utf8');
const cases = fs.readFileSync(casesPath, 'utf8').split('\n').filter(Boolean);

const listeners = {};
const self = {
  addEventListener: (n, f) => { (listeners[n] = listeners[n] || []).push(f); },
  skipWaiting: () => {},
  clients: { claim: () => Promise.resolve() },
};
const sandbox = {
  self,
  URL,
  Request,
  // fetch factice : révèle l'URL de la requête REÉCRITE sans réseau.
  fetch: (req) => Promise.resolve({
    __url: req && req.url ? req.url : String(req),
    ok: true,
  }),
};
vm.createContext(sandbox);
vm.runInContext(swText, sandbox, { filename: 'sw.js' });

if (!listeners['fetch']) {
  console.error('le SW généré ne registre aucun listener fetch');
  process.exit(1);
}

(async () => {
  const out = [];
  for (const u of cases) {
    let urlP = null;
    const ev = {
      request: new Request(u),
      respondWith: (p) => { urlP = p; },
    };
    for (const f of listeners['fetch']) {
      f(ev);
    }
    let got = 'NO-INTERCEPT';
    if (urlP) {
      const r = await urlP.catch((e) => ({ __error: String(e) }));
      got = r.__url || r.__error || '';
    }
    out.push(got);
  }
  fs.writeFileSync(outPath, out.join('\n') + '\n');
})();

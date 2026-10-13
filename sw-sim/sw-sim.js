#!/usr/bin/env node
// sw-sim.js — exécute le service worker généré par la gateway dans Node
// pour reproduire/valider le comportement de cache offline.
//
// Le SW utilise : self, caches, fetch, Request, Response, Blob,
// workbox (importScripts). On stubbe tout ce qu'il faut :
//  - caches : mini-implémentation CacheStorage/Cache (clé = URL+méthode)
//  - fetch  : backend contrôlé par le test
//  - importScripts/workbox : stubs minimals (registerRoute capture les
//    routes ; ExpirationPlugin est un no-op qui compte les purges)
//
// Usage : node sw-sim.js <chemin sw.js> <fichier de test>
// (le fichier de test exporte run({routes, caches, fetchCtrl}))
const fs = require('fs');
const vm = require('vm');

async function loadSW(swPath) {
  const code = fs.readFileSync(swPath, 'utf8');

  // ---- stubs ----
  const routes = [];
  const cacheStore = new Map(); // nom -> Map(requestKey -> Response)
  const requestKey = (req) => req.method + ' ' + req.url;

  class Cache {
    constructor(name) { this.name = name; this.map = new Map(); }
    async match(req) {
      const hit = this.map.get(requestKey(req));
      return hit ? hit.clone() : undefined;
    }
    async put(req, resp) {
      if (req.method !== 'GET') {
        // comme le vrai Cache Storage : les POST ne sont pas refusés
        // mais la clé ignore le corps (c'est le bug qu'on veut démontrer)
      }
      this.map.set(requestKey(req), resp.clone());
    }
    async keys() { return [...this.map.keys()]; }
    async delete(req) { return this.map.delete(requestKey(req)); }
  }

  const caches = {
    async open(name) {
      if (!cacheStore.has(name)) cacheStore.set(name, new Cache(name));
      return cacheStore.get(name);
    },
    async keys() { return [...cacheStore.keys()]; },
    async delete(name) { return cacheStore.delete(name); },
    _store: cacheStore,
  };

  const swGlobals = {
    skipWaitingCalled: false,
    activated: false,
    deletedCaches: [],
  };

  const self = {
    addEventListener(ev, fn) {
      if (ev === 'activate') swGlobals._activate = fn;
    },
    skipWaiting() { swGlobals.skipWaitingCalled = true; return Promise.resolve(); },
    clients: { async claim() { return []; } },
  };

  let backend = async () => new Response('default', { status: 404 });
  const fetchCtrl = {
    set(fn) { backend = fn; },
    calls: [],
  };
  const fetchFn = async (req) => {
    fetchCtrl.calls.push(req);
    return backend(req);
  };

  function importScripts() {}
  const workbox = {
    setConfig() {},
    routing: {
      registerRoute(match, handler) {
        routes.push({ match, handler });
      },
    },
    strategies: {
      NetworkFirst: class { constructor(opts) { this.opts = opts; } },
      NetworkOnly: class { constructor(opts) { this.opts = opts; } },
    },
    expiration: {
      ExpirationPlugin: class {
        constructor(opts) { this.opts = opts; swGlobals.expiration = this; }
        async cacheDidUpdate() { swGlobals.purges = (swGlobals.purges || 0) + 1; }
      },
    },
  };

  const ctx = vm.createContext({
    self, importScripts, workbox, caches, fetch: fetchFn,
    Request, Response, Blob, ReadableStream, TextEncoder, TextDecoder,
    URL, console, Promise, crypto: require('crypto').webcrypto,
    setTimeout, clearTimeout, setInterval, clearInterval,
  });
  vm.runInContext(code, ctx, { filename: swPath });

  return { routes, caches, fetchCtrl, swGlobals, self: ctx.self };
}

// exécute la route qui matche la requête, comme le ferait le navigateur
async function dispatch(routes, req) {
  for (const r of routes) {
    const url = new URL(req.url);
    let ok = false;
    try { ok = r.match({ request: req, url, event: { request: req, waitUntil: () => {} } }); }
    catch (e) { ok = false; }
    if (ok) {
      // waitUntil: capture les promesses comme un vrai SW (le handler
      // doit impérativement y passer son travail de fond, sinon le
      // navigateur suspend le SW avant la fin — bug que la sim doit
      // pouvoir détecter)
      const extended = [];
      const event = {
        request: req,
        waitUntil: (p) => extended.push(Promise.resolve(p)),
      };
      const result = await r.handler({ event, request: req });
      event._extended = extended;
      return result;
    }
  }
  throw new Error('no route matched ' + req.url);
}

module.exports = { loadSW, dispatch };

// ---- CLI: quick reproduction of the Obélisque bug ----
if (require.main === module) {
  const swPath = process.argv[2] || './sw.js';
  console.log('SIM BOOT', swPath);
  (async () => {
    const { routes, caches, fetchCtrl } = await loadSW(swPath);

    // backend : SSE stream qui ne se ferme jamais (keep-alive SSE),
    // réponse différente par corps de requête
    fetchCtrl.set(async (req) => {
      const body = await req.clone().text();
      const enc = new TextEncoder();
      const stream = new ReadableStream({
        start(c) {
          c.enqueue(enc.encode('data: {"poesie":"' + body.slice(0, 40) + '"}\n\n'));
          if (process.env.SSE_CLOSE === '1') c.close(); // backend qui ferme
          // sinon: la connexion reste ouverte (keep-alive SSE)
        },
      });
      return new Response(stream, { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
    });

    // 1. segmentation Obélisque — avec timeout : si le flux SSE sans
    // fermeture bloque la consommation, on le documente (c'est le bug
    // recherché) et on passe à l'inspection des caches.
    const req1 = new Request('https://vers.cladone.com/api/process_stream', {
      method: 'POST', body: 'poesie=Obelisque',
    });
    const resp1 = await dispatch(routes, req1);
    const consumed = await Promise.race([
      resp1.clone().text().then(() => true),
      new Promise((r) => setTimeout(() => r(false), 3000)),
    ]);
    if (!consumed) {
      console.error('STREAM-NEVER-ENDS: la consommation du flux SSE (sans fermeture serveur) ne se termine jamais — storeCompleteResponse ne peut pas atteindre done => rien n\'est jamais caché');
    }
    await new Promise((r) => setTimeout(r, 100));

    // 2. segmentation d'une autre poésie
    const req2 = new Request('https://vers.cladone.com/api/process_stream', {
      method: 'POST', body: 'poesie=Antigone',
    });
    const resp2 = await dispatch(routes, req2);
    const consumed2 = await Promise.race([resp2.clone().text().then(() => true), new Promise((r) => setTimeout(() => r(false), 3000))]);
    if (!consumed2) console.error("STREAM-NEVER-ENDS (2e segmentation)");
    await new Promise((r) => setTimeout(r, 100));

    // 3. inspection des caches
    const names = await caches.keys();
    console.log('caches présents:', names); console.error('DEBUG names.length=' + names.length);
    for (const name of names.filter((n) => n.includes('api'))) {
      const c = await caches.open(name);
      const keys = await c.keys();
      console.log(`cache ${name}: ${keys.length} entrée(s) ->`, keys);
    }
    const anyApi = names.find((n) => n.includes('api'));
    if (!anyApi) {
      console.log('\nRÉSULTAT: AUCUN cache API — bug reproduit (le flux SSE sans fermeture + requête POST non-cachable => rien n\'est stocké)');
      process.stdout.write('EXIT-2\n'); process.exit(2);
    }
    const c = await caches.open(anyApi);
    const n = (await c.keys()).length;
    console.log(`\nRÉSULTAT: ${n} entrée(s) dans ${anyApi}`);
    if (n === 0) { console.log('=> bug reproduit: rien de caché'); process.stdout.write('EXIT-2\n'); process.exit(2); }
    if (n === 1) {
      const hit = await c.match(new Request('https://vers.cladone.com/api/process_stream', { method: 'POST', body: 'poesie=Obelisque' }));
      console.log('match Obélisque:', hit ? 'OUI (mais clé body-aveugle: risque de rejouer une autre poésie!)' : 'non');
      console.log('=> clés écrasées mutuellement (body ignoré par Cache Storage) => bug de clé reproduit');
      process.stdout.write('EXIT-3\n'); process.exit(3);
    }
    process.stdout.write('EXIT-0\n'); process.exit(0);
  })().catch((e) => { console.error(e); process.exit(1); });
}
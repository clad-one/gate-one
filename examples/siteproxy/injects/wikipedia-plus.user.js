// =============================================================================
// Wikipedia+ — a userscript installed ON THE GATEWAY (examples/siteproxy/injects/).
// =============================================================================
// Base: "Wikipedia Dark Theme Automatic" v1.0.0
//       by Elio (ImElio) — https://github.com/ImElio/wikipedia-dark-theme-automatic
// License: MIT (free for commercial use) — full text at the bottom; the
// original copyright notice is preserved as the license requires.
//
// Adaptations for the cladone gateway demo (2026-10, MIT as well):
//   + floating dark/light toggle, reading-time badge with the exact
//     prose word count
//   - the ?vectornightmode / ?minervanightmode URL rewriting was dropped:
//     the gateway re-injects this script into EVERY page, so the official
//     theme class + the stored preference are enough;
//   - the data-mw-dynamic-theme link rewriting was dropped for the same
//     reason (the official class drives the theme on Vector/Minerva);
//   - the scroll progress bar of earlier adaptations was dropped:
//     a 3 px fixed line at the viewport top proved invisible in
//     practice (Vector 2022's own sticky header area) — dead weight.
//
// Provenance, import steps: https://clad-one.github.io/gate-one-doc/docs/examples/siteproxy/
//
// NOTE: inside the gateway the @match below is inert — the ROUTE decides
// where the plugin runs (host), the bundle's "when" decides which pages.
//
// ==UserScript==
// @name        Wikipedia+ (gateway plugin)
// @namespace   https://github.com/ImElio/wikipedia-dark-theme-automatic
// @version     1.2.0
// @description Dark/light toggle and reading time for Wikipedia — injected by the gateway, no extension needed.
// @author      Elio (ImElio), adapted by the gateway demo
// @license     MIT
// @homepageURL https://github.com/ImElio/wikipedia-dark-theme-automatic
// @match       *://*.wikipedia.org/*
// @run-at      document-start
// @grant       none
// ==/UserScript==

(function () {
  'use strict';

  // —— theme engine (adapted from the original) ———————————————
  var DARK_CLASS = 'skin-theme-clientpref-night'; // MediaWiki's official night class
  var PREF_KEY = 'wikipedia-plus-theme';          // our stored choice: 'dark' | 'light'
  var PREF_DEFAULT = 'dark';

  var antiFlashStyle = null;

  function storedTheme() {
    try {
      var t = localStorage.getItem(PREF_KEY);
      return t === 'light' || t === 'dark' ? t : PREF_DEFAULT;
    } catch (e) {
      return PREF_DEFAULT;
    }
  }

  function storeTheme(t) {
    try { localStorage.setItem(PREF_KEY, t); } catch (e) { /* private mode */ }
  }

  function isDark() {
    return document.documentElement.classList.contains(DARK_CLASS);
  }

  function applyDark() {
    document.documentElement.classList.add(DARK_CLASS);
    try { localStorage.setItem('wikimedia-ui-theme', 'dark'); } catch (e) {}
    if (!antiFlashStyle) {
      // anti-flash: applied at document-start, before MediaWiki's CSS decides
      antiFlashStyle = document.createElement('style');
      antiFlashStyle.textContent =
        ':root{color-scheme:dark !important}' +
        'html,body{background:#111 !important;color:#ddd !important}' +
        'a{color:#9dc1ff !important}';
      document.documentElement.appendChild(antiFlashStyle);
    }
  }

  function applyLight() {
    document.documentElement.classList.remove(DARK_CLASS);
    try { localStorage.setItem('wikimedia-ui-theme', 'light'); } catch (e) {}
    if (antiFlashStyle && antiFlashStyle.parentNode) {
      antiFlashStyle.parentNode.removeChild(antiFlashStyle);
    }
    antiFlashStyle = null;
  }

  function applyTheme(t) {
    if (t === 'dark') { applyDark(); } else { applyLight(); }
  }

  // document-start + "head" target: the theme is decided before first paint
  var theme = storedTheme();
  applyTheme(theme);

  // Keep the stored theme when something else flips the class
  // (MediaWiki's own night button, a gadget…). Delete this observer
  // to let Wikipedia's native control win.
  new MutationObserver(function () {
    var want = storedTheme() === 'dark';
    if (isDark() !== want) { applyTheme(want ? 'dark' : 'light'); }
  }).observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

  // —— floating panel: theme toggle + reading time ———————————————
  function onReady(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn);
    } else {
      fn();
    }
  }

  onReady(function () {
    // the panel never prints
    var css = document.createElement('style');
    css.textContent = '@media print{' +
      '#wikipedia-plus-panel{display:none !important}}';
    document.head.appendChild(css);

    var panel = document.createElement('div');
    panel.id = 'wikipedia-plus-panel';
    panel.style.cssText =
      'position:fixed;right:16px;bottom:16px;z-index:9999;' +
      'display:flex;align-items:center;gap:10px;' +
      'padding:8px 14px;border-radius:999px;' +
      'font:13px/1.2 sans-serif;color:#eee;' +
      'background:rgba(32,33,36,.88);' +
      'border:1px solid rgba(255,255,255,.25);' +
      'box-shadow:0 2px 8px rgba(0,0,0,.35);';

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.style.cssText = 'all:unset;cursor:pointer;font-size:16px;line-height:1;';
    function paintBtn() {
      // the icon shows the CURRENT state (moon = dark)
      var dark = isDark();
      btn.textContent = dark ? '\uD83C\uDF19' : '\u2600\uFE0F';
      btn.title = dark ? 'Dark mode on — click for light'
                       : 'Light mode on — click for dark';
    }
    btn.addEventListener('click', function () {
      theme = isDark() ? 'light' : 'dark';
      storeTheme(theme);
      applyTheme(theme);
      paintBtn();
    });

    var badge = document.createElement('span');
    badge.title = 'Estimated reading time (200 words/min)';
    // Reading time must count PROSE ONLY. textContent of the raw
    // parser output also carries the bibliography (.reflist — often
    // the largest chunk), navboxes, hatnotes, metadata banners,
    // category links, footnote markers and any embedded style/script:
    // none of it is read linearly. Measured on frwiki "Château de
    // Versailles" (2026-10): 24 815 raw tokens vs 18 490 prose words
    // — a raw count inflates the estimate by ~34 %.
    var SKIP_PROSE = 'style,script,sup.reference,.mw-cite-backlink,' +
      '.reflist,.references,.mw-references,.navbox,.metadata,.ambox,' +
      '.catlinks,.mw-editsection,.hatnote,.infobox,.sidebar,.toc,#toc,' +
      '.printfooter';
    function paintBadge() {
      // the ARTICLE body — the first .mw-parser-output on the page is
      // NOT it: corner indicators (the "good article" star, other
      // mw-indicators) are tiny .mw-parser-output divs too and would
      // read "≈ 1 min". Anchor to the stable article container.
      var article = document.querySelector(
        '#mw-content-text .mw-parser-output');
      if (!article) { badge.textContent = ''; return; }
      var clone = article.cloneNode(true);
      clone.querySelectorAll(SKIP_PROSE).forEach(function (el) {
        el.remove();
      });
      var words = (clone.textContent || '').trim()
        .split(/\s+/).filter(Boolean).length;
      // badge: minutes + the EXACT counted words (reader's locale)
      badge.textContent = '\u2248 ' +
        Math.max(1, Math.round(words / 200)) + ' min read \u00B7 ' +
        words.toLocaleString() + ' words';
      badge.title = 'Estimated from ' + words.toLocaleString() +
        ' prose words at 200 words/min';
    }

    panel.appendChild(btn);
    panel.appendChild(badge);
    document.body.appendChild(panel);

    paintBtn();
    paintBadge();
  });

})();

/*
MIT License

Original "Wikipedia Dark Theme Automatic":
Copyright (c) 2025 Elio (ImElio)

Adaptation ("Wikipedia+", gateway plugin):
Copyright (c) 2026 the cladone gateway demo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package proxy

// Injector registry — the single extension point for modifications
// made to PROXIFIED RESPONSES. Each feature (decompression, stripPrefix
// response paths, 401/403 guard, body rewrite, upstream adjustments,
// PWA, custom injections) implements the interface; the chain is built
// once per route at
// config load, in execution order. End of wiring through nested
// closures in proxy.go: adding a feature = adding an injector.
//
// Execution order (the slice order) — strict equivalent of the
// historical chaining, proven by unchanged tests:
//
//	gzip → pathRewrite → guard → rewriteBody → upstream(headers) → pwa → custom
//
// Headers only or a streaming resp.Body wrapper: both mechanisms go
// through the same interface — no buffering, memory stays O(1)
// regardless of the page size (a single HTML tag is rewritten in
// place).

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/license"
	"cladone/gate-one/internal/pwa"
)

// injector: one response modification applied to the routes eligible
// for it.
type injector interface {
	name() string
	// modify applies its modification (headers, streaming body
	// wrapper, insertion…). Returning errStopChain stops the chain
	// WITHOUT an error (response served as-is).
	modify(resp *http.Response) error
}

// errStopChain: the response must not be manipulated further (e.g.
// undecodable encoding) — it is served as-is, without an error
// (documented fail-open).
var errStopChain = errors.New("injection: chain stopped — response served as-is")

// isHTMLResponse: body injectors only touch HTML 200s (assets, JSON,
// PDF, 30x… never modified).
func isHTMLResponse(resp *http.Response) bool {
	return resp.StatusCode == http.StatusOK &&
		strings.Contains(resp.Header.Get("Content-Type"), "text/html")
}

// buildInjectors: a route's injection chain, in execution order.
// u = backend URL; rwPlan = compiled rewriteBody policy (nil when
// absent); injectsBody = a body injection is expected (upstream gzip
// forcing already decided).
func buildInjectors(
	cfg *core.Config,
	route *core.Route,
	u *url.URL,
	rwPlan *rewritePlan,
	pathPlan *pathRewritePlan,
	injectsBody bool,
	ts *turnstileRuntime,
) []injector {

	injectors := make([]injector, 0, 7)

	// injectedHTML: every static HTML fragment the gateway adds to the
	// document. The CSP layer hashes their inline scripts at compile
	// time (a strict origin policy must not block what the gateway
	// itself injects).
	var injectedHTML []string
	// guardStylesheet: the exact CSS given to the guard (static
	// classes + uiGate rules). Its hash is added to the CSP so a
	// strict origin style-src accepts the guard's <style>.
	var guardStylesheet string

	if injectsBody {
		injectors = append(injectors, &gzipDecodeInjector{host: route.Host})
	}

	if pathPlan != nil {
		log.Printf(
			"PATH rewrite enabled host=%s public=%s backend=%s",
			route.Host,
			pathPlan.publicPrefix,
			pathPlan.backendBase,
		)
		injectors = append(injectors, &pathRewriteInjector{plan: pathPlan})
	}

	if guardEnabledFor(route) {
		log.Printf(
			"GUARD enabled host=%s path=%s loginUrl=%s", route.Host,
			route.Path,
			cfg.LoginURLFor(route),
		)
		var script string
		script, guardStylesheet = buildGuardScript(cfg, route, u)
		injectors = append(injectors, &guardInjector{
			host:   route.Host,
			script: script,
		})
		injectedHTML = append(injectedHTML, script)
	}

	// Client-side rewriting needs a REGISTERED service worker. A guard
	// registers it itself, and so does the PWA injection; a proxified
	// route with NEITHER (frontend:false or authGuard disabled) would
	// otherwise keep the worker unreachable and dynamic JS URLs
	// unrewritten. Inject the registration here — same worker, same
	// third-party protection, no cache role.
	if rwPlan != nil && route.ClientSideRewrite() &&
		!guardEnabledFor(route) &&
		!(route.PWA != nil && route.PWA.Enabled) {
		frag := pwa.RewriteRegistrationHTML()
		injectors = append(injectors, &headScriptInjector{script: frag})
		injectedHTML = append(injectedHTML, frag)
		log.Printf(
			"CLIENT SW registration injected host=%s (no guard, no PWA)",
			route.Host)
	}

	if rwPlan != nil {
		log.Printf(
			"UPSTREAM rewriteBody enabled host=%s origins=%v target=%s except=%d",
			route.Host,
			rwPlan.origins,
			rwPlan.pub,
			len(rwPlan.except),
		)
		injectors = append(injectors, &rewriteBodyInjector{plan: rwPlan})
	}

	if route.Upstream != nil {
		log.Printf(
			"UPSTREAM enabled host=%s path=%s backend=%s",
			route.Host,
			route.Path,
			route.Backend,
		)
		injectors = append(injectors, &upstreamAdjustInjector{
			modifyResponse: upstreamResponseModifier(route, u),
		})
	}

	if route.PWA != nil && route.PWA.Enabled {
		injectors = append(injectors, &pwaInjector{})
		injectedHTML = append(injectedHTML, pwa.InjectedHeadHTML())
	}

	if bundle := route.InjectionBundle(); bundle != nil {
		log.Printf(
			"CUSTOM inject enabled host=%s path=%s entries=%d patch=%d",
			route.Host,
			route.Path,
			len(bundle.Contents),
			len(bundle.Patch),
		)
		injectors = append(injectors, &customInjector{
			host:   route.Host,
			bundle: bundle,
		})
		for j := range bundle.Contents {
			injectedHTML = append(injectedHTML, bundle.Contents[j].Content)
		}
	}

	// Turnstile: the widget script is added before </body> on matching
	// pages. The block is global; the injector re-checks the request
	// path (a route may serve several page prefixes).
	var cspExtra *cspExtraSources
	if ts != nil && ts.injectsRoute(route) && ts.script != "" {
		injectors = append(injectors, &turnstileInjector{rt: ts})
		injectedHTML = append(injectedHTML, ts.script)
		cspExtra = turnstileCSPSources()
	}

	// CSP: installed LAST so the nonce stamper sees the bytes the
	// other injectors added (guard, PWA, custom, Turnstile) — no
	// per-feature nonce plumbing. The hashes of the gateway's own
	// inline scripts are computed once here, at route compile time.
	if csp := route.CSP; csp != nil && csp.Mode != "off" {
		var hashes []string
		for _, frag := range injectedHTML {
			hashes = append(hashes, inlineScriptHashes([]byte(frag))...)
		}
		hashes = dedupeStrings(hashes)
		var styles []string
		if guardStylesheet != "" {
			styles = append(styles, inlineStyleHash(guardStylesheet))
		}
		log.Printf(
			"CSP enabled host=%s mode=%s reportOnly=%v own=%v "+
				"stamp=%q scriptHashes=%d styleHashes=%d",
			route.Host,
			csp.Mode,
			csp.ReportOnly,
			csp.Own,
			csp.StampScripts,
			len(hashes),
			len(styles),
		)
		if csp.Own {
			log.Printf(
				"CSP own: ORIGIN POLICY REMOVED host=%s path=%s "+
					"(the route's policy is the only one)",
				route.Host, route.Path,
			)
		}
		injectors = append(injectors, &cspInjector{
			policy: csp,
			hashes: hashes,
			styles: styles,
			extra:  cspExtra,
		})
	}

	return injectors
}

// licenseJSON: the licence status embedded in the guard script (offline
// signed token; absent/invalid/expired = evaluation). Never fails.
func licenseJSON(cfg *core.Config) string {
	var st license.Status
	if cfg == nil {
		st = license.Eval(nil, time.Now())
	} else {
		st = license.Eval(cfg.License, time.Now())
	}
	b, err := json.Marshal(license.ClientStatus(st))
	if err != nil {
		return `{"state":"eval","reason":"invalid"}`
	}
	return string(b)
}

// chainInjectors: the generic ModifyResponse — each injector passes
// the baton in order; errStopChain = the rest of the chain is
// skipped, the response goes out as-is.
func chainInjectors(items []injector) func(*http.Response) error {
	return func(resp *http.Response) error {
		for _, in := range items {
			if err := in.modify(resp); err != nil {
				if errors.Is(err, errStopChain) {
					return nil
				}
				return err
			}
		}
		return nil
	}
}

// gzipDecodeInjector: STREAMING decompression of gzip HTML before
// any manipulation (the Go stdlib decodes neither brotli nor zstd —
// 2026-10-17 incident). An undecodable encoding that got past the
// upstream forcing = response served as-is, without injection.
type gzipDecodeInjector struct {
	host string
}

func (i *gzipDecodeInjector) name() string { return "gzip" }

func (i *gzipDecodeInjector) modify(resp *http.Response) error {
	if !isHTMLResponse(resp) {
		return nil
	}

	switch enc := resp.Header.Get("Content-Encoding"); enc {
	case "", "identity":
		// already plain
	case "gzip":
		if err := decodeGzipBody(resp); err != nil {
			log.Printf("GUNZIP failed host=%s: %v", i.host, err)
			return err
		}
	default:
		log.Printf(
			"INJECTION skipped host=%s: Content-Encoding %q undecodable — response served as-is",
			i.host,
			enc,
		)
		return errStopChain
	}
	return nil
}

// guardInjector: the 401/403 guard script (auth without reload,
// declarative gating, badge, runtime rewrite) inserted in streaming
// mode after <head>/charset meta. The script is built ONCE at route
// compile time.
type guardInjector struct {
	host   string
	script string
}

func (i *guardInjector) name() string { return "guard" }

func (i *guardInjector) modify(resp *http.Response) error {
	if !isHTMLResponse(resp) {
		return nil
	}
	// STREAMING injection: it does not read the body here (no
	// buffering) — transport errors surface during the copy.
	injectHeadScript(resp, i.script)
	return nil
}

// buildGuardScript renders the route's guard script and its
// stylesheet. Single source of truth: the injection chain and the
// tests that measure an injected page both call it (a duplicated
// Sprintf list silently drifts when an argument is added).
func buildGuardScript(
	cfg *core.Config, route *core.Route, backend *url.URL,
) (script, stylesheet string) {
	stylesheet = buildGuardCSS(route)
	script = fmt.Sprintf(
		guardScript,
		cfg.LoginURLFor(route),
		AuthStatePath,
		uiGateJSON(route),
		userBadgeJSON(route),
		rewriteGuardJSON(route, backend),
		patchJSONFor(route),
		forbiddenBannerJSON(route),
		licenseJSON(cfg),
		core.AsciiJSON(stylesheet, `""`),
		clientSideFlag(route),
	)
	return script, stylesheet
}

// clientSideFlag: guard-script argument telling it whether to
// register the client rewriting worker (upstream.rewriteBody.clientSide).
func clientSideFlag(route *core.Route) string {
	if route != nil && route.ClientSideRewrite() {
		return "true"
	}
	return "false"
}

// headScriptInjector injects a static HTML fragment right after
// <head> (streaming, O(1) memory — see injectHeadScript). Used for the
// client-rewriting service worker registration when no guard and no
// PWA policy inject it.
type headScriptInjector struct {
	script string
}

func (i *headScriptInjector) name() string { return "headScript" }

func (i *headScriptInjector) modify(resp *http.Response) error {
	if !isHTMLResponse(resp) {
		return nil
	}
	injectHeadScript(resp, i.script)
	return nil
}

// rewriteBodyInjector: rewriting of origin URLs in the HTML body
// (upstream.rewriteBody), streaming.
type rewriteBodyInjector struct {
	plan *rewritePlan
}

func (i *rewriteBodyInjector) name() string { return "rewriteBody" }

func (i *rewriteBodyInjector) modify(resp *http.Response) error {
	if !isHTMLResponse(resp) {
		return nil
	}
	// STREAMING rewrite like guardStream: no buffering,
	// Content-Length removed (chunked, flush per write because
	// ContentLength is -1). The rewritten URLs' scheme follows the
	// request (https in production, http in demo).
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
	resp.ContentLength = -1
	resp.Body = newRewriteStreamForRequest(
		resp.Body, i.plan, requestSchemeOut(resp.Request),
		requestHostOut(resp.Request))
	return nil
}

// upstreamAdjustInjector: adjustments to the backend's RESPONSE —
// rewriting of absolute Locations, set/remove headers, translation
// of Set-Cookies (upstream.rewriteCookies).
type upstreamAdjustInjector struct {
	modifyResponse func(*http.Response) error
}

func (i *upstreamAdjustInjector) name() string { return "upstream" }

func (i *upstreamAdjustInjector) modify(resp *http.Response) error {
	return i.modifyResponse(resp)
}

// pwaInjector: manifest link + service worker registration injected
// into the <head> of HTML 200s.
type pwaInjector struct{}

func (i *pwaInjector) name() string { return "pwa" }

func (i *pwaInjector) modify(resp *http.Response) error {
	return pwa.InjectResponse(resp)
}

// customInjector: the injections declared by the route's bundle
// (upstream "inject" — HTML/JS/CSS by named target), streaming.
type customInjector struct {
	host   string
	bundle *core.InjectBundle
}

func (i *customInjector) name() string { return "custom" }

func (i *customInjector) modify(resp *http.Response) error {
	if !isHTMLResponse(resp) {
		return nil
	}
	// Entries are chained in DESCENDING order: each pass inserts
	// AFTER the previous pass's marker — the final document order
	// follows the ascending Order.
	items := i.bundle.Contents
	for j := len(items) - 1; j >= 0; j-- {
		item := &items[j]
		// per-page targeting (when.path) is decided per request:
		// the request path went through the director without being
		// rewritten (only the Host changes)
		if !itemMatchesPath(item, resp.Request) {
			continue
		}
		resp.Body = newInjectStream(resp.Body, item.Content, item.Target)
		resp.Header.Del("Content-Length")
		resp.Header.Del("Content-Encoding")
		resp.ContentLength = -1
	}
	return nil
}

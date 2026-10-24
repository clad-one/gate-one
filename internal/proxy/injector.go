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
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"cladone/gate-one/internal/core"
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
) []injector {

	injectors := make([]injector, 0, 6)

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
			"GUARD enabled host=%s path=%s loginUrl=%s",
			route.Host,
			route.Path,
			cfg.LoginURLFor(route),
		)
		script := fmt.Sprintf(
			guardScript,
			cfg.LoginURLFor(route),
			AuthStatePath,
			uiGateJSON(route),
			userBadgeJSON(route),
			rewriteGuardJSON(route, u),
			patchJSONFor(route),
			forbiddenBannerJSON(route),
		)
		injectors = append(injectors, &guardInjector{
			host:   route.Host,
			script: script,
		})
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
	}

	return injectors
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
	injectGuardScript(resp, i.script)
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

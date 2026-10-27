package proxy

import (
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

// The guard must not set element.style / a style attribute: style
// attributes cannot be nonced, so under a strict style-src they would
// be blocked. All dynamic styling is expressed with classes (the one
// runtime <style> element is nonced from document.currentScript).
func TestGuardUsesClassesNotInlineStyles(t *testing.T) {
	for _, bad := range []string{
		".style.cssText",
		".style.display",
		".style.cursor",
		`setAttribute("style"`,
		`setAttribute('style'`,
	} {
		if strings.Contains(guardScript, bad) {
			t.Errorf("guard still uses %q (inline style): strict CSP would block it", bad)
		}
	}

	for _, want := range []string{
		"document.currentScript.nonce",
		"css.nonce = CSP_NONCE",
		"GUARD_CSS",
	} {
		if !strings.Contains(guardScript, want) {
			t.Errorf("guard missing %q", want)
		}
	}

	css := buildGuardCSS(nil)
	for _, want := range []string{
		"[data-gtw-gated-off]",
		".cladone-userbadge-fs-11",
		".cladone-banner",
		".cladone-forbidden",
		".cladone-badge-logout",
		".cladone-badge-links",
		".cladone-badge-link",
		"white-space:normal",
		"overflow-y:auto",
		"max-width:min(90vw,30em)",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("guard stylesheet missing %q", want)
		}
	}
}

func TestBuildGuardCSSIncludesUIGate(t *testing.T) {
	route := &core.Route{UIGate: []*core.UIGateRule{
		{Selector: ".legend"},
		nil,
		{Selector: ""},
	}}
	css := buildGuardCSS(route)
	if !strings.Contains(css, ".legend{display:none !important}") {
		t.Errorf("uiGate selector absent from guard CSS: %s", css)
	}
	if strings.Count(css, "[data-gtw-gated-off]") != 1 {
		t.Errorf("gating rule duplicated or missing")
	}
	if inlineStyleHash(css) == "" {
		t.Error("empty style hash")
	}
}

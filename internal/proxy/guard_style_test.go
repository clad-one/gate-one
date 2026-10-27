package proxy

import (
	"strings"
	"testing"
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
		"[data-gtw-gated-off]",
		".cladone-userbadge-fs-11",
		".cladone-banner",
		".cladone-forbidden",
		".cladone-badge-logout",
	} {
		if !strings.Contains(guardScript, want) {
			t.Errorf("guard missing %q", want)
		}
	}
}

package iam

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

// writeChooser renders the IdP chooser when /authorize is called
// without an `idp` hint and more than one login method is enabled.
// Every button re-enters the same authorize URL with `idp=<key>`, so
// the OAuth parameters (state, PKCE, redirect_uri) are preserved.
func (b *IAM) writeChooser(
	w http.ResponseWriter, r *http.Request, rt *tenantRuntime,
	methods []string,
) {
	if len(methods) == 0 {
		writeAccountPage(w, http.StatusBadRequest, "Sign-in unavailable",
			"No sign-in method is configured for this service.")
		return
	}

	type link struct{ label, url string }
	links := make([]link, 0, len(methods))
	for _, id := range methods {
		label := id
		switch id {
		case "local":
			label = "Local account (email / password)"
		default:
			if up, ok := rt.cfg.Upstreams[id]; ok && up.DisplayName != "" {
				label = up.DisplayName
			}
		}
		u := *r.URL
		q := u.Query()
		q.Set("idp", id)
		u.RawQuery = q.Encode()
		links = append(links, link{label: label, url: u.String()})
	}

	var buttons strings.Builder
	for _, l := range links {
		fmt.Fprintf(&buttons,
			"<a class=\"btn\" href=\"%s\">%s</a>\n",
			html.EscapeString(l.url), html.EscapeString(l.label))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f4f5f7;color:#1c1f26;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{width:100%%;max-width:24em;margin:2rem;padding:2rem 2.25rem;background:#fff;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.08)}
h1{margin:0 0 .4rem;font-size:1.3rem}
p{margin:0 0 1.2rem;color:#555;font-size:.95rem}
a.btn{display:block;margin:.55rem 0;padding:.65rem 1rem;border-radius:8px;border:1px solid #c9ced8;background:#fff;color:#1c1f26;text-decoration:none;font-weight:600;text-align:center}
a.btn:hover{background:#f0f4ff;border-color:#2563eb}
a.btn:first-of-type{background:#2563eb;border-color:#2563eb;color:#fff}
a.btn:first-of-type:hover{background:#1d4ed8}
@media (prefers-color-scheme:dark){body{background:#16181d;color:#eef0f3}main{background:#20242e}p{color:#aab2c0}a.btn{background:#20242e;border-color:#3a4150;color:#eef0f3}a.btn:hover{background:#2a3550}a.btn:first-of-type{background:#3b82f6;border-color:#3b82f6;color:#fff}}
</style>
</head>
<body>
<main>
<h1>Sign in</h1>
<p>Choose your sign-in method.</p>
%s</main>
</body>
</html>`, buttons.String())
}

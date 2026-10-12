package proxy

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strconv"

	"cladone/gateway/internal/core"
)

// LoginPageURL is the public auth-bridge login page. Shared by the
// server-side redirect for page routes (proxy.go) and the injected
// 401/403 guard script (this file).
const LoginPageURL = "https://login.cladone.com/login"

// guardScript is injected into HTML responses of frontend routes. It
// wraps window.fetch so that a 401/403 answer (session expired, the
// gateway answers JSON 401 on API routes) triggers a full-page
// redirect to the login page. Centralized equivalent of the per-app
// "redirect to auth" handling — no code in the frontends themselves.
//
// Notes:
//   - only fetch() calls are wrapped; document navigations are already
//     redirected server-side for page routes
//   - answers from the login page itself are ignored (no redirect loop)
//   - the returned promise never resolves: the navigation interrupts
//     the calling code cleanly (stream readers, try/catch, ...)
const guardScript = `<script>
(function(){
  if (window.__cladoneAuthGuard) return;
  window.__cladoneAuthGuard = true;
  var LOGIN = "%[1]s";
  var orig = window.fetch;
  if (!orig) return;
  window.fetch = function(){
    var p = orig.apply(this, arguments);
    return p.then(function(res){
      if ((res.status === 401 || res.status === 403)
          && !res.url.startsWith(LOGIN)) {
        setTimeout(function(){
          location.href = LOGIN + "?returnTo="
            + encodeURIComponent(location.href);
        }, 0);
        return new Promise(function(){ /* navigation takes over */ });
      }
      return res;
    });
  };
})();
</script>`

var headOpen = regexp.MustCompile(`(?i)<head[^>]*>`)

// maxGuardBody bounds the HTML body read during injection (1 MiB is
// far above the current frontend pages; larger pages skip injection).
const maxGuardBody = 1 << 20

// guardEnabledFor resolves the route's authGuard policy: active by
// default on frontend routes, opt-out via {"enabled": false}, no-op on
// non-frontend routes.
func guardEnabledFor(route *core.Route) bool {
	if route.Frontend != true {
		return false
	}
	if route.AuthGuard == nil {
		return true
	}
	if route.AuthGuard.Enabled != nil {
		return *route.AuthGuard.Enabled
	}
	return true
}

// guardLoginURL returns the login URL configured for the guard, if any.
func guardLoginURL(route *core.Route) string {
	if route.AuthGuard != nil && route.AuthGuard.LoginURL != "" {
		return route.AuthGuard.LoginURL
	}
	return LoginPageURL
}

// injectGuardScript inserts the guard <script> right after the opening
// <head> tag (or at the very start when no <head> is found) and fixes
// Content-Length. The response body must already be uncompressed.
func injectGuardScript(resp *http.Response, script string) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGuardBody))
	closeErr := resp.Body.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}

	var out []byte
	if idx := headOpen.FindIndex(body); idx != nil {
		out = append(out, body[:idx[1]]...)
		out = append(out, []byte(script)...)
		out = append(out, body[idx[1]:]...)
	} else {
		out = append([]byte(script), body...)
	}

	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(out)), 10))
	// The body was re-serialized by the transport if it was
	// compressed; make sure no stale encoding header survives.
	resp.Header.Del("Content-Encoding")
	return nil
}

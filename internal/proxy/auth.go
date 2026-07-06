package proxy

import (
    "strings"
    "errors"
    "net/http"
)

var ErrRedirect = errors.New("auth redirect")

func splitRoles(s string) []string {
    if s == "" {
        return nil
    }

    parts := strings.Split(s, ",")
    out := make([]string, 0, len(parts))

    for _, p := range parts {
        p = strings.TrimSpace(p)
        if p != "" {
            out = append(out, p)
        }
    }

    return out
}

func (g *Gateway) checkAuth(
    w http.ResponseWriter,
    r *http.Request,
    ctx *RequestContext,
) (*RequestContext, error) {
    req, err := http.NewRequest(
        http.MethodGet,
        "http://auth-bridge:3000/auth",
        nil,
    )
    if err != nil {
        return nil, err
    }
    if auth := r.Header.Get("Authorization"); auth != "" {
        req.Header.Set("Authorization", auth)
    }
    for _, c := range r.Cookies() {
        req.AddCookie(c)
    }
    req.Header.Set("X-Forwarded-Host", r.Host)
    req.Header.Set("X-Forwarded-Uri", r.RequestURI)
    req.Header.Set("X-Forwarded-Method", r.Method)

    resp, err := g.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // Propagate any cookies auth-bridge issued (e.g. a silently
    // refreshed access_token/refresh_token) back to the browser,
    // regardless of whether auth ultimately succeeded or not.
    for _, c := range resp.Header["Set-Cookie"] {
        w.Header().Add("Set-Cookie", c)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, errors.New("authentication failed")
    }
    ctx.UserID = resp.Header.Get("X-User-Id")
    ctx.Username = resp.Header.Get("X-Username")
    ctx.Email = resp.Header.Get("X-Email")
    ctx.Roles = splitRoles(resp.Header.Get("X-Roles"))
    return ctx, nil
}
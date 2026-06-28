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
    r *http.Request,
    ctx *RequestContext,
) (*RequestContext, error) {

    req, err := http.NewRequest(
        "GET",
        "http://auth-bridge:3000/auth",
        nil,
    )
    if err != nil {
        return nil, err
    }

    // forward auth
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

    // IMPORTANT: DO NOT FOLLOW REDIRECTS (must be set in client, see below)

    // 🔴 REDIRECT CASE
    if resp.StatusCode == http.StatusFound ||
       resp.StatusCode == http.StatusSeeOther ||
       resp.StatusCode == http.StatusTemporaryRedirect {

        return nil, ErrRedirect
    }

    // ❌ AUTH FAILED
    if resp.StatusCode != http.StatusOK {
        return nil, errors.New("auth failed")
    }

    ctx.UserID = resp.Header.Get("X-User-Id")
    ctx.Username = resp.Header.Get("X-Username")
    ctx.Email = resp.Header.Get("X-Email")

    roles := resp.Header.Get("X-Roles")
    ctx.Roles = splitRoles(roles)

    return ctx, nil
}

/*
func (g *Gateway) checkAuth(
    r *http.Request,
    ctx *RequestContext,
) (*RequestContext, error) {

    req, err := http.NewRequest(
        "GET",
        "http://auth-bridge:3000/auth",
        nil,
    )
    if err != nil {
        return nil, err
    }

    // Forward Authorization header (API clients)
    if auth := r.Header.Get("Authorization"); auth != "" {
        req.Header.Set("Authorization", auth)
    }

    // Forward browser cookies
    for _, c := range r.Cookies() {
        req.AddCookie(c)
    }

    // Forward headers used by auth-bridge
    req.Header.Set("Accept", r.Header.Get("Accept"))

    if v := r.Header.Get("Sec-Fetch-Dest"); v != "" {
        req.Header.Set("Sec-Fetch-Dest", v)
    }

    req.Header.Set("X-Forwarded-Host", r.Host)
    req.Header.Set("X-Forwarded-Uri", r.RequestURI)
    req.Header.Set("X-Forwarded-Method", r.Method)

    resp, err := g.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("auth bridge returned %d", resp.StatusCode)
    }

    ctx.UserID = resp.Header.Get("X-User-Id")
    ctx.Username = resp.Header.Get("X-Username")
    ctx.Email = resp.Header.Get("X-Email")

    if roles := resp.Header.Get("X-Roles"); roles != "" {
        ctx.Roles = strings.Split(roles, ",")
    }

    return ctx, nil
}*/
package proxy

import (
//    "log"
    "net/http"
    "errors"
    "fmt"
    "strings"
)

func (g *Gateway) checkAuth(
    r *http.Request,
    ctx *RequestContext,
) (*RequestContext, error) {

    token := r.Header.Get("Authorization")

    if token == "" {
        return nil, errors.New("missing authorization header")
    }

    req, err := http.NewRequest(
        "GET",
        "http://auth-bridge:3000/auth",
        nil,
    )

    if err != nil {
        return nil, err
    }

    req.Header.Set("Authorization", token)

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

    roles := resp.Header.Get("X-Roles")

    if roles != "" {
        ctx.Roles = strings.Split(roles, ",")
    }

    return ctx, nil
}
/*
func (g *Gateway) checkAuth(r *http.Request) bool {

    log.Printf("AUTH HEADER: %s", r.Header.Get("Authorization"))

    req, err := http.NewRequest(
        "GET",
        "http://auth-bridge:3000/auth",
        nil,
    )

    if err != nil {
        return false
    }

    //
    // recopie les cookies
    //

    for _, c := range r.Cookies() {
        req.AddCookie(c)
    }

    //
    // Authorization: Bearer ...
    //

    if h := r.Header.Get("Authorization"); h != "" {
        req.Header.Set("Authorization", h)
    }

    //
    // X-Forwarded-*
    //

    req.Header.Set("X-Forwarded-Host", r.Host)
    req.Header.Set("X-Forwarded-Uri", r.RequestURI)
    req.Header.Set("X-Forwarded-Method", r.Method)

    resp, err := g.client.Do(req)

    if err != nil {
        return false
    }

    defer resp.Body.Close()

    return resp.StatusCode == http.StatusOK
}*/
package proxy

import (
    "log"
    "net/http"
)

func (g *Gateway) checkAuth(r *http.Request) bool {

    token := r.Header.Get("Authorization")
    if token == "" {
        return false
    }

    req, err := http.NewRequest("GET", "http://auth-bridge:3000/auth", nil)
    if err != nil {
        return false
    }

    req.Header.Set("Authorization", token)

    resp, err := g.client.Do(req)
    if err != nil {
        log.Println("AUTH BRIDGE ERROR:", err)
        return false
    }
    defer resp.Body.Close()

    log.Println("AUTH BRIDGE STATUS:", resp.StatusCode)

    return resp.StatusCode == http.StatusOK
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
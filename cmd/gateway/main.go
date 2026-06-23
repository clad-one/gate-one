package main

import (
    "log"
    "net/http"

    "cladone/gateway/internal/config"
    "cladone/gateway/internal/proxy"
)

func main() {

    cfg := config.Load()

    r, err := proxy.NewRouter(cfg.Routes)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Gateway listening on :3000")

    log.Fatal(http.ListenAndServe(":3000", r))
}
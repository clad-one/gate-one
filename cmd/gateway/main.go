package main

import (
    "log"
    "net/http"

    "cladone/gateway/internal/core"
    "cladone/gateway/internal/proxy"
)

func main() {

    cfg, err := core.Load("api-routes.json")

    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Loaded %d routes", len(cfg.Routes))

    gw, err := proxy.New(cfg)

    if err != nil {
        log.Fatal(err)
    }

    log.Println("Gateway listening on :3000")

    log.Fatal(http.ListenAndServe(":3000", gw))
}
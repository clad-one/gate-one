package main

import (
	"flag"
	"log"
	"net/http"

	"cladone/gateway/internal/core"
	"cladone/gateway/internal/proxy"
)

func main() {

	configPath := flag.String(
		"config",
		"api-routes.json",
		"chemin du fichier de routes",
	)
	addr := flag.String(
		"addr",
		":3000",
		"adresse d'écoute",
	)
	flag.Parse()

	cfg, err := core.Load(*configPath)

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Loaded %d routes", len(cfg.Routes))

	gw, err := proxy.New(cfg)

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Gateway listening on %s", *addr)

	log.Fatal(http.ListenAndServe(*addr, gw))
}

package main

import (
	"log"
	"net/http"

	"cladone/gateway/internal/proxy"
)

func main() {

	routes := map[string]string{
		"vers2.cladone.com": "http://versifier2:9292",
	}

	router, err := proxy.NewRouter(routes)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Gateway listening on :3000")

	log.Fatal(http.ListenAndServe(":3000", router))
}
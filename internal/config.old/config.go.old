package config

import (
    "encoding/json"
    "log"
    "os"
)

type Config struct {
    Routes map[string]string
}

func Load() Config {

    cfg := Config{
        Routes: map[string]string{},
    }

    raw := os.Getenv("ROUTES")

    if raw == "" {
        log.Fatal("ROUTES environment variable is empty")
    }

    if err := json.Unmarshal([]byte(raw), &cfg.Routes); err != nil {
        log.Fatal(err)
    }

    return cfg
}
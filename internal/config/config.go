package config

import "os"

type Config struct {
    Routes map[string]string
}

func Load() Config {

    return Config{
        Routes: map[string]string{
            "vers2.cladone.com": getenv("VERSIFIER2_URL", "http://versifier2:9292"),
            "vers.cladone.com":  getenv("VERSIFIER_URL", "http://versifier:9292"),
        },
    }
}

func getenv(name, def string) string {

    v := os.Getenv(name)

    if v == "" {
        return def
    }

    return v
}
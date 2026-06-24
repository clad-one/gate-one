package core

import (
    "encoding/json"
    "os"
)

type Service struct {
    URL string `json:"url"`
}

type Host struct {
    Service string `json:"service"`

    Auth bool `json:"auth,omitempty"`

    Roles []string `json:"roles,omitempty"`

    RateLimit int `json:"rateLimit,omitempty"`

    Quota int `json:"quota,omitempty"`
}

type Config struct {
    Services map[string]Service `json:"services"`
    Hosts map[string]Host `json:"hosts"`
}

func Load(path string) (*Config, error) {

    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var cfg Config

    err = json.Unmarshal(data, &cfg)

    if err != nil {
        return nil, err
    }

    return &cfg, nil
}
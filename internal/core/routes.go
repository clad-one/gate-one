package core

import (
	"encoding/json"
	"os"
)
/*
type Service struct {
	URL string `json:"url"`
}

type Host struct {
	Service string `json:"service"`
}

type AuthWhen struct {
	Query map[string]string `json:"query"`
}

type AuthWhen struct {

    Method string `json:"method,omitempty"`

    Query map[string]string `json:"query,omitempty"`

    Header map[string]string `json:"header,omitempty"`

    Body map[string]any `json:"body,omitempty"`
}

type Auth struct {
	Required bool      `json:"required"`
	When     *AuthWhen `json:"when,omitempty"`
}*/
/*
type Route struct {
	Host      string `json:"host"`
	Path      string `json:"path"`
	Service   string `json:"service,omitempty"`

	Auth      *Auth  `json:"auth,omitempty"`

	Quota     string `json:"quota,omitempty"`

	RateLimit string `json:"rateLimit,omitempty"`
}*/
type Match struct {

    Method string `json:"method,omitempty"`

    Query map[string]string `json:"query,omitempty"`

    Header map[string]string `json:"header,omitempty"`

    Body map[string]any `json:"body,omitempty"`

    Roles []string `json:"roles,omitempty"`

    User string `json:"user,omitempty"`
}
type RateLimitPolicy struct {
    Requests int    `json:"requests"`
    Period      string `json:"period"`

    When *Match `json:"when,omitempty"`
}

type QuotaPolicy struct {
    Limit  int    `json:"limit"`
    Period string `json:"period"`

    When *Match `json:"when,omitempty"`
}
type AuthPolicy struct {

    //Required bool `json:"required"`

    When *Match `json:"when,omitempty"`

    //Roles []string `json:"roles,omitempty"`
}

type Route struct {
    Host string `json:"host"`
    Path string `json:"path"`

    Backend string `json:"backend"`

    Auth      *AuthPolicy      `json:"auth,omitempty"`
    RateLimit *RateLimitPolicy `json:"rateLimit,omitempty"`
    Quota     *QuotaPolicy     `json:"quota,omitempty"`
}

type Config struct {

//	Services map[string]Service `json:"services"`

//	Hosts map[string]Host `json:"hosts"`

	Routes []Route `json:"routes"`
}

func Load(path string) (*Config, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config

	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
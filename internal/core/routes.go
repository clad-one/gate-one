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
}

/*type AuthWhen struct {
	Query map[string]string `json:"query"`
}*/

type AuthWhen struct {

    Method string `json:"method,omitempty"`

    Query map[string]string `json:"query,omitempty"`

    Header map[string]string `json:"header,omitempty"`

    Body map[string]any `json:"body,omitempty"`
}

type Auth struct {
	Required bool      `json:"required"`
	When     *AuthWhen `json:"when,omitempty"`
}

type Route struct {
	Host      string `json:"host"`
	Path      string `json:"path"`
	Service   string `json:"service,omitempty"`

	Auth      *Auth  `json:"auth,omitempty"`

	Quota     string `json:"quota,omitempty"`

	RateLimit string `json:"rateLimit,omitempty"`
}

type Config struct {
	Services map[string]Service `json:"services"`

	Hosts map[string]Host `json:"hosts"`

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
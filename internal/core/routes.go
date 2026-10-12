package core

import (
	"encoding/json"
	"fmt"
	"os"
)

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
	Period   string `json:"period"`

	When *Match `json:"when,omitempty"`
}

type QuotaPolicy struct {
	Limit  int    `json:"limit"`
	Period string `json:"period"`

	When *Match `json:"when,omitempty"`
}

type AuthPolicy struct {
	When *Match `json:"when,omitempty"`

	//Roles []string `json:"roles,omitempty"`
}

type OpenAPIPolicy struct {
	URL    string `json:"url"`
	Public bool   `json:"public,omitempty"`
}

// AuthGuardPolicy controls the injection of the gateway's 401/403 guard
// script into HTML responses of frontend routes. Unlike the AuthPolicy
// (which enforces authentication on a route), the guard only reacts to
// 401/403 answers already produced: when the injected script sees a
// fetch() answer 401/403 it redirects the browser to the login page.
// Absent policy = guard active on frontend routes, no-op elsewhere.
type AuthGuardPolicy struct {
	Enabled  *bool  `json:"enabled,omitempty"`  // false = opt-out
	LoginURL string `json:"loginUrl,omitempty"` // default: shared constant
}

type MCPOperation struct {
	Name        string `json:"name"`
	OperationID string `json:"operationId"`
}

type MCPPolicy struct {
	Enabled    bool           `json:"enabled"`
	Path       string         `json:"path,omitempty"`
	Operations []MCPOperation `json:"operations"`
}

// PWAPolicy declares, per frontend route, the gateway-managed PWA wrap:
// virtual endpoints under /__gateway_pwa/ (manifest, service worker,
// self-hosted Workbox runtime) and <head> injection on HTML responses.
type PWAPolicy struct {
	Enabled    bool   `json:"enabled"`
	Name       string `json:"name,omitempty"`
	ShortName  string `json:"shortName,omitempty"`
	ThemeColor string `json:"themeColor,omitempty"`
	// Icons are paths on the same host, referenced from the generated
	// manifest, not proxied. Chrome requires 192x192 and 512x512 PNG
	// for a fully installable app. Legacy single "icon" is still read.
	Icon  string   `json:"icon,omitempty"`
	Icons []string `json:"icons,omitempty"`
}

type Route struct {
	Host string `json:"host"`
	Path string `json:"path"`

	Frontend bool   `json:"frontend,omitempty"`
	Backend  string `json:"backend"`

	AutoHead bool `json:"headFallback,omitempty"`

	Auth      *AuthPolicy      `json:"auth,omitempty"`
	RateLimit *RateLimitPolicy `json:"rateLimit,omitempty"`
	Quota     *QuotaPolicy     `json:"quota,omitempty"`

	OpenAPI *OpenAPIPolicy `json:"openapi,omitempty"`
	MCP     *MCPPolicy     `json:"mcp,omitempty"`
	PWA     *PWAPolicy     `json:"pwa,omitempty"`

	AuthGuard *AuthGuardPolicy `json:"authGuard,omitempty"`
}

type Config struct {
	Routes []Route `json:"routes"`
}

func Load(path string) (*Config, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config

	if err := json.Unmarshal(data, &cfg); err != nil {

		if se, ok := err.(*json.SyntaxError); ok {

			line := 1
			col := 1

			for i := 0; i < int(se.Offset)-1 && i < len(data); i++ {
				if data[i] == '\n' {
					line++
					col = 1
				} else {
					col++
				}
			}

			return nil, fmt.Errorf(
				"%s:%d:%d: %v",
				path,
				line,
				col,
				err,
			)
		}

		return nil, err
	}

	return &cfg, nil
}

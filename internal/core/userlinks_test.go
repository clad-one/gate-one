package core

import (
	"strings"
	"testing"
)

func TestUserLinksLoadAndDefaults(t *testing.T) {
	cfg, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "http",
			"loginUrl": "https://login.example.com/login",
			"issuer": "https://auth.example.com/realms/example",
			"links": {
				"account": {"url": "https://auth.example.com/realms/example/account/"}
			}
		},
		"tokenBroker": {
			"links": {"services": {"url": "https://login.example.com/connections"}}
		},
		"routes": [{
			"host": "app.example.com", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1",
			"userBadge": {"links": [
				{"label": "Status", "url": "/status", "target": "_self"}
			]}
		}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthProvider.Links == nil ||
		cfg.AuthProvider.Links.Account == nil {
		t.Fatal("authProvider.links.account not parsed")
	}
	if cfg.TokenBroker.Links == nil ||
		cfg.TokenBroker.Links.Services == nil {
		t.Fatal("tokenBroker.links.services not parsed")
	}
	if got := cfg.Routes[0].UserBadge.Links; len(got) != 1 ||
		got[0].Label != "Status" || got[0].Target != "_self" {
		t.Errorf("userBadge.links = %+v", got)
	}
}

func TestUserLinksRejectsJavaScriptURL(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "http",
			"loginUrl": "https://login.example.com/login",
			"links": {"account": {"url": "javascript:alert(1)"}}
		},
		"routes": [{"host": "app.test", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "must be an http(s) URL") {
		t.Fatalf("err = %v, want URL refusal", err)
	}
}

func TestUserLinksRequiresAppLabel(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "http",
			"loginUrl": "https://login.example.com/login"
		},
		"routes": [{
			"host": "app.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1",
			"userBadge": {"links": [{"url": "/status"}]}
		}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "label is required") {
		t.Fatalf("err = %v, want label refusal", err)
	}
}

func TestUserLinksRejectsUnknownKey(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "http",
			"loginUrl": "https://login.example.com/login",
			"links": {"foo": {"url": "https://x"}}
		},
		"routes": [{"host": "app.test", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err == nil {
		t.Fatal("unknown authProvider.links key accepted")
	}
}

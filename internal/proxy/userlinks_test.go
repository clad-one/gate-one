package proxy

import (
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

func testLinksConfig() *core.Config {
	return &core.Config{
		AuthProvider: &core.AuthProviderConfig{
			Type: "http-bridge",
			Links: &core.AuthProviderLinks{
				Account: &core.UserLink{
					Label: "Account",
					URL:   "https://idp.test/account/",
				},
			},
		},
		TokenBroker: &core.TokenBrokerConfig{
			Links: &core.TokenBrokerLinks{
				Services: &core.UserLink{
					URL: "https://login.test/connections",
				},
			},
		},
	}
}

func TestBaseUserLinksAlwaysShowsServices(t *testing.T) {
	cfg := testLinksConfig()

	// The Services page is the user's control surface (pause/resume and
	// erase); it must stay reachable even when no route delegates.
	links := baseUserLinks(cfg)
	if len(links) != 2 {
		t.Fatalf("links = %+v, want account+services", links)
	}
	if links[0].Label != "Account" || links[0].Target != "_blank" {
		t.Errorf("account defaults = %+v", links[0])
	}
	if links[1].Label != "Services" || links[1].Target != "_blank" {
		t.Errorf("services defaults = %+v", links[1])
	}
}

func TestMergeUserLinksOrderAndDedup(t *testing.T) {
	base := []core.UserLink{
		{Label: "Account", URL: "https://idp.test/account/", Target: "_blank"},
		{Label: "Services", URL: "https://login.test/connections", Target: "_blank"},
	}
	app := []core.UserLink{
		// duplicate of account (same URL, with a trailing slash
		// difference), must be dropped: the connector wins
		{Label: "My account", URL: "https://IDP.test/account", Target: "_self"},
		{Label: "Status", URL: "/status"},
	}
	merged, err := mergeUserLinks(base, app)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 3 {
		t.Fatalf("merged = %+v, want 3", merged)
	}
	if merged[0].Label != "Account" ||
		merged[1].Label != "Services" ||
		merged[2].Label != "Status" {
		t.Errorf("order = %+v", merged)
	}
	if merged[2].Target != "_blank" {
		t.Errorf("app target default = %q, want _blank", merged[2].Target)
	}
}

func TestMergeUserLinksBounds(t *testing.T) {
	base := []core.UserLink{{Label: "Account", URL: "https://idp.test/account"}}
	app := make([]core.UserLink, 0, maxMergedUserLinks)
	for i := 0; i < maxMergedUserLinks; i++ {
		app = append(app, core.UserLink{
			Label: "L",
			URL:   "/l" + strings.Repeat("x", i+1),
		})
	}
	if _, err := mergeUserLinks(base, app); err == nil {
		t.Fatal("merge over the limit accepted")
	}
}

func TestGatewayMergesUserBadgeLinks(t *testing.T) {
	t.Setenv("TOKEN_BROKER_SHARED_SECRET", "s3cret")
	cfg := loadForTest(t, `{
		"authProvider": {
			"type": "http-bridge",
			"loginUrl": "https://login.test/login",
			"issuer": "https://auth.test/realms/test",
			"links": {"account": {"url": "https://idp.test/account/"}}
		},
		"tokenBroker": {
			"secretEnv": "TOKEN_BROKER_SHARED_SECRET",
			"links": {"services": {"url": "https://login.test/connections"}}
		},
		"routes": [{
			"host": "app.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1",
			"userBadge": {"links": [
				{"label": "Status", "url": "/status"}
			]}
		}]
	}`)
	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	links := gw.routes[0].route.UserBadge.Links
	// No delegated route in this config: the Services link must still
	// be present (the page is the user's pause/resume/erase surface).
	if len(links) != 3 ||
		links[0].Label != "Account" ||
		links[1].Label != "Services" ||
		links[2].Label != "Status" {
		t.Fatalf("merged links = %+v, want account+services+status", links)
	}
}

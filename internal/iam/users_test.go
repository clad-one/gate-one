package iam

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestEffectiveRightsMappingsAndUserGrants(t *testing.T) {
	google := newFakeGoogle(t)
	cfg := testIAMConfig(google)
	cfg.Tenants[0].AdminEmails = []string{"admin@mycompany.test"}
	cfg.Tenants[0].Mappings = []MappingRule{
		{
			Claim:  "groups",
			Values: []string{"admins"},
			Roles:  []string{"admin"},
		},
		{
			Claim:  "realm_access.roles",
			Values: []string{"offline_access"},
			Roles:  []string{"offline"},
		},
		{
			Claim:  "department",
			Scopes: []string{"read:things"},
			Claims: map[string]any{"department": "support"},
		},
	}
	b := &IAM{cfg: cfg, now: nil}
	_ = b
	rt := &tenantRuntime{cfg: cfg.Tenants[0]}
	u := &User{
		Email:  "alice@mycompany.test",
		Roles:  []string{"support"},
		Scopes: []string{"write:things"},
		Claims: map[string]any{"team": "a"},
	}
	claims := map[string]any{
		"groups":       []any{"admins"},
		"realm_access": map[string]any{"roles": []any{"offline_access"}},
		"department":   "support",
	}
	got := rt.effectiveRights(u, claims)
	for _, role := range []string{"user", "admin", "offline", "support"} {
		if !containsString(got.Roles, role) {
			t.Errorf("missing role %q in %v", role, got.Roles)
		}
	}
	if !containsString(got.Scopes, "read:things") ||
		!containsString(got.Scopes, "write:things") {
		t.Errorf("scopes = %v", got.Scopes)
	}
	if got.Claims["department"] != "support" || got.Claims["team"] != "a" {
		t.Errorf("claims = %v", got.Claims)
	}
}

func TestDirectoryLocalAndFederatedGrants(t *testing.T) {
	google := newFakeGoogle(t)
	cfg := testIAMConfig(google)
	ctx := context.Background()
	d, err := OpenDirectory(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	local, err := d.CreateUser(ctx, &User{
		Tenant: "mycompany",
		Kind:   "local",
		Email:  "local@mycompany.test",
		Roles:  []string{"support"},
	}, "long-enough-password")
	if err != nil {
		t.Fatal(err)
	}
	if local.ID == "" || local.PasswordHash == "" {
		t.Fatalf("local user = %+v", local)
	}
	got, err := d.GetUserByEmail(ctx, "mycompany", "local@mycompany.test")
	if err != nil || got.ID != local.ID {
		t.Fatalf("local lookup = %+v, %v", got, err)
	}

	fed, err := d.CreateUser(ctx, &User{
		Tenant:  "mycompany",
		Kind:    "federated",
		Email:   "alice@mycompany.test",
		Issuer:  "https://idp.test",
		Subject: "sub-1",
		Roles:   []string{"user"},
		Scopes:  []string{"read:things"},
		Claims:  map[string]any{"department": "support"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err = d.GetUserByIdentity(ctx, "mycompany", "https://idp.test", "sub-1")
	if err != nil || got.ID != fed.ID {
		t.Fatalf("federated lookup = %+v, %v", got, err)
	}
	list, err := d.ListUsers(ctx, "mycompany")
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if err := d.DeleteUser(ctx, "mycompany", fed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetUserByIdentity(ctx, "mycompany", "https://idp.test", "sub-1"); err == nil {
		t.Fatal("deleted identity still resolves")
	}
}

func TestWriteTokensCarriesScopesAndAssignedClaims(t *testing.T) {
	google := newFakeGoogle(t)
	b, _ := newTestIAM(t, google)
	rt := b.tenants["mycompany"]
	rec := httptest.NewRecorder()
	b.writeTokens(
		context.Background(), rec, rt, "sub-1", "alice",
		"alice@mycompany.test", []string{"user"},
		[]string{"read:things"}, map[string]any{"department": "support"},
		"sid-1", "openid profile", "https://mcp.mycompany.test",
		"", "cladone-go", true, true,
	)
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatal("missing access token")
	}
	claims := verifyJWT(t, rt.activeKey().pub, access)
	if claims["department"] != "support" {
		t.Fatalf("department = %v", claims["department"])
	}
	scope, _ := claims["scope"].(string)
	if !scopeHas(scope, "openid") || !scopeHas(scope, "read:things") {
		t.Fatalf("scope = %q", scope)
	}
	if !containsString(claimStrings(claims["roles"]), "user") {
		t.Fatalf("roles = %v", claims["roles"])
	}
}

func TestMappingValidationRejectsReservedClaim(t *testing.T) {
	err := validateMappingRules([]MappingRule{{
		Claim:  "groups",
		Values: []string{"admins"},
		Claims: map[string]any{"sub": "evil"},
	}})
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("err = %v", err)
	}
}

func TestUpsertFederatedUserKeepsSingleIdentity(t *testing.T) {
	google := newFakeGoogle(t)
	b, _ := newTestIAM(t, google)
	rt := b.tenants["mycompany"]
	ctx := context.Background()
	first, err := b.upsertFederatedUser(ctx, rt,
		"https://idp.test", "sub-1", "alice@mycompany.test", "Alice",
		map[string]any{"email_verified": true})
	if err != nil {
		t.Fatal(err)
	}
	first.Roles = []string{"support"}
	if err := b.accounts.PutUser(ctx, first); err != nil {
		t.Fatal(err)
	}
	second, err := b.upsertFederatedUser(ctx, rt,
		"https://idp.test", "sub-1", "alice2@mycompany.test", "Alice 2",
		map[string]any{"email_verified": true})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("identity created a second user: %s != %s", second.ID, first.ID)
	}
	if !containsString(second.Roles, "support") {
		t.Fatalf("admin grants lost on login: %v", second.Roles)
	}
	if second.Email != "alice2@mycompany.test" {
		t.Fatalf("email not refreshed: %q", second.Email)
	}
}

func TestRedisUsersSingleIdentityAndLocalEmail(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	a := &redisAccounts{client: client, prefix: "test:accounts:"}
	ctx := context.Background()

	local := &User{ID: "local-1", Tenant: "t", Kind: "local",
		Email: "same@example.test", PasswordHash: "hash"}
	if err := a.PutUser(ctx, local); err != nil {
		t.Fatal(err)
	}
	fed := &User{ID: "fed-1", Tenant: "t", Kind: "federated",
		Email: "same@example.test", Issuer: "https://idp.test", Subject: "sub-1"}
	if err := a.PutUser(ctx, fed); err != nil {
		t.Fatal(err)
	}
	got, err := a.GetUserByEmail(ctx, "t", "same@example.test")
	if err != nil || got.ID != local.ID {
		t.Fatalf("local email lookup = %+v, %v", got, err)
	}
	got, err = a.GetUserByIdentity(ctx, "t", "https://idp.test", "sub-1")
	if err != nil || got.ID != fed.ID {
		t.Fatalf("identity lookup = %+v, %v", got, err)
	}
	fed.Issuer = "https://idp2.test"
	fed.Subject = "sub-2"
	if err := a.PutUser(ctx, fed); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetUserByIdentity(ctx, "t", "https://idp.test", "sub-1"); err == nil {
		t.Fatal("old identity key still resolves")
	}
	if got, err := a.GetUserByIdentity(ctx, "t", "https://idp2.test", "sub-2"); err != nil ||
		got.ID != fed.ID {
		t.Fatalf("relinked identity = %+v, %v", got, err)
	}
}

func TestConfigRejectsReservedMappingClaim(t *testing.T) {
	google := newFakeGoogle(t)
	cfg := testIAMConfig(google)
	cfg.Tenants[0].Mappings = []MappingRule{{
		Claim:  "groups",
		Values: []string{"admins"},
		Claims: map[string]any{"sub": "evil"},
	}}
	if err := cfg.Validate(); err == nil ||
		!strings.Contains(err.Error(), "reserved") {
		t.Fatalf("err = %v", err)
	}
}

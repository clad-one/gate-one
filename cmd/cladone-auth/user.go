package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"cladone/gate-one/internal/iam"
)

func runUser(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: cladone-auth user <list|show|create|set|delete> [options]")
		return 2
	}
	switch args[0] {
	case "list":
		return userList(args[1:])
	case "show":
		return userShow(args[1:])
	case "create":
		return userCreate(args[1:])
	case "set":
		return userSet(args[1:])
	case "delete":
		return userDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown user command %q\n", args[0])
		return 2
	}
}

func userFlags(name string) (*flag.FlagSet, *string, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	config := fs.String("config", "cladone-auth.json", "IAM config path")
	tenant := fs.String("tenant", "", "tenant id")
	return fs, config, tenant
}

func openDirectory(configPath string) (*iam.Directory, error) {
	cfg, err := iam.Load(configPath)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return iam.OpenDirectory(ctx, cfg)
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseClaims(raw string) (map[string]any, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		return nil, fmt.Errorf("invalid claims JSON: %w", err)
	}
	return claims, nil
}

func printUser(u *iam.User) error {
	cp := *u
	cp.PasswordHash = "" // never print credential material
	raw, err := json.MarshalIndent(&cp, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(raw))
	return nil
}

func userList(args []string) int {
	fs, config, tenant := userFlags("user list")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tenant == "" {
		fmt.Fprintln(os.Stderr, "user list: -tenant is required")
		return 2
	}
	d, err := openDirectory(*config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user list:", err)
		return 1
	}
	defer d.Close()
	users, err := d.ListUsers(context.Background(), *tenant)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user list:", err)
		return 1
	}
	for _, u := range users {
		if err := printUser(u); err != nil {
			fmt.Fprintln(os.Stderr, "user list:", err)
			return 1
		}
	}
	return 0
}

func userSelector(fs *flag.FlagSet) (*string, *string, *string, *string) {
	return fs.String("id", "", "IAM user id"),
		fs.String("email", "", "local user email"),
		fs.String("issuer", "", "federated issuer"),
		fs.String("sub", "", "federated subject")
}

func lookupUser(
	d *iam.Directory, tenant, id, email, issuer, sub string,
) (*iam.User, error) {
	ctx := context.Background()
	switch {
	case id != "":
		return d.GetUserByID(ctx, tenant, id)
	case email != "":
		return d.GetUserByEmail(ctx, tenant, email)
	case issuer != "" && sub != "":
		return d.GetUserByIdentity(ctx, tenant, issuer, sub)
	default:
		return nil, fmt.Errorf("one of -id, -email, or -issuer/-sub is required")
	}
}

func userShow(args []string) int {
	fs, config, tenant := userFlags("user show")
	id, email, issuer, sub := userSelector(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tenant == "" {
		fmt.Fprintln(os.Stderr, "user show: -tenant is required")
		return 2
	}
	d, err := openDirectory(*config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user show:", err)
		return 1
	}
	defer d.Close()
	u, err := lookupUser(d, *tenant, *id, *email, *issuer, *sub)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user show:", err)
		return 1
	}
	if err := printUser(u); err != nil {
		fmt.Fprintln(os.Stderr, "user show:", err)
		return 1
	}
	return 0
}

func userCreate(args []string) int {
	fs, config, tenant := userFlags("user create")
	kind := fs.String("kind", "local", "local or federated")
	email := fs.String("email", "", "email (local required)")
	name := fs.String("name", "", "display name")
	password := fs.String("password", "", "local password")
	issuer := fs.String("issuer", "", "federated issuer")
	sub := fs.String("sub", "", "federated subject")
	roles := fs.String("roles", "", "comma-separated roles")
	scopes := fs.String("scopes", "", "comma-separated scopes")
	claims := fs.String("claims", "", "JSON object of assigned claims")
	verified := fs.Bool("verified", true, "email is verified")
	disabled := fs.Bool("disabled", false, "disable the user")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tenant == "" {
		fmt.Fprintln(os.Stderr, "user create: -tenant is required")
		return 2
	}
	normalized := strings.TrimSpace(*email)
	if normalized != "" {
		var err error
		normalized, err = iam.NormalizeEmail(normalized)
		if err != nil {
			fmt.Fprintln(os.Stderr, "user create:", err)
			return 1
		}
	}
	parsedClaims, err := parseClaims(*claims)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user create:", err)
		return 1
	}
	d, err := openDirectory(*config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user create:", err)
		return 1
	}
	defer d.Close()
	u, err := d.CreateUser(context.Background(), &iam.User{
		Tenant:        *tenant,
		Kind:          *kind,
		Email:         normalized,
		Name:          strings.TrimSpace(*name),
		EmailVerified: *verified,
		Issuer:        strings.TrimSpace(*issuer),
		Subject:       strings.TrimSpace(*sub),
		Roles:         splitList(*roles),
		Scopes:        splitList(*scopes),
		Claims:        parsedClaims,
		Disabled:      *disabled,
	}, *password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user create:", err)
		return 1
	}
	if err := printUser(u); err != nil {
		fmt.Fprintln(os.Stderr, "user create:", err)
		return 1
	}
	return 0
}

func userSet(args []string) int {
	fs, config, tenant := userFlags("user set")
	id, email, issuer, sub := userSelector(fs)
	name := fs.String("name", "", "display name")
	roles := fs.String("roles", "", "comma-separated roles (replaces)")
	scopes := fs.String("scopes", "", "comma-separated scopes (replaces)")
	claims := fs.String("claims", "", "JSON claims object (replaces)")
	disabled := fs.Bool("disabled", false, "disable the user")
	enabled := fs.Bool("enabled", false, "enable the user")
	newIssuer := fs.String("new-issuer", "", "relink a federated user to this issuer")
	newSub := fs.String("new-sub", "", "relink a federated user to this subject")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tenant == "" {
		fmt.Fprintln(os.Stderr, "user set: -tenant is required")
		return 2
	}
	provided := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	d, err := openDirectory(*config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user set:", err)
		return 1
	}
	defer d.Close()
	u, err := lookupUser(d, *tenant, *id, *email, *issuer, *sub)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user set:", err)
		return 1
	}
	if provided["name"] {
		u.Name = strings.TrimSpace(*name)
	}
	if provided["roles"] {
		u.Roles = splitList(*roles)
	}
	if provided["scopes"] {
		u.Scopes = splitList(*scopes)
	}
	if provided["claims"] {
		parsed, err := parseClaims(*claims)
		if err != nil {
			fmt.Fprintln(os.Stderr, "user set:", err)
			return 1
		}
		u.Claims = parsed
	}
	if *newIssuer != "" || *newSub != "" {
		if *newIssuer == "" || *newSub == "" {
			fmt.Fprintln(os.Stderr, "user set: -new-issuer and -new-sub are required together")
			return 2
		}
		if u.Kind != "federated" {
			fmt.Fprintln(os.Stderr, "user set: relink is only valid for federated users")
			return 2
		}
		u.Issuer = strings.TrimSpace(*newIssuer)
		u.Subject = strings.TrimSpace(*newSub)
	}
	if *disabled {
		u.Disabled = true
	}
	if *enabled {
		u.Disabled = false
	}
	if err := d.PutUser(context.Background(), u); err != nil {
		fmt.Fprintln(os.Stderr, "user set:", err)
		return 1
	}
	if err := printUser(u); err != nil {
		fmt.Fprintln(os.Stderr, "user set:", err)
		return 1
	}
	return 0
}

func userDelete(args []string) int {
	fs, config, tenant := userFlags("user delete")
	id, email, issuer, sub := userSelector(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tenant == "" {
		fmt.Fprintln(os.Stderr, "user delete: -tenant is required")
		return 2
	}
	d, err := openDirectory(*config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user delete:", err)
		return 1
	}
	defer d.Close()
	u, err := lookupUser(d, *tenant, *id, *email, *issuer, *sub)
	if err != nil {
		fmt.Fprintln(os.Stderr, "user delete:", err)
		return 1
	}
	if err := d.DeleteUser(context.Background(), *tenant, u.ID); err != nil {
		fmt.Fprintln(os.Stderr, "user delete:", err)
		return 1
	}
	fmt.Printf("deleted user %s (%s)\n", u.ID, u.Email)
	return 0
}

package proxy

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"cladone/gate-one/internal/authn"
	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/license"
	"cladone/gate-one/internal/pluginhost"
	"cladone/gate-one/internal/usagewal"
	"cladone/gate-one/pkg/pluginmanifest"
	"cladone/gate-one/pkg/usage"
)

// usageMaxRecordBytes is the per-event admission reservation. Events
// are bounded (the schema caps the free-text fields); a record larger
// than this is refused by the WAL.
const usageMaxRecordBytes = 4096

type usageRuntime struct {
	store         *usagewal.Store
	host          *pluginhost.Host
	subs          []usageSub
	subjectSecret []byte
	nodeID        string
	epoch         string
	types         map[usage.EventType]bool
}

type usageSub struct {
	typ     usage.EventType
	filters *core.UsageFilters
}

type usageAdmission struct {
	tickets map[usage.EventType]*usagewal.Ticket
}

func newUsageRuntime(
	cfg *core.UsageConfig, licCfg *license.Config,
) (*usageRuntime, error) {
	if cfg == nil {
		return nil, nil
	}
	types := map[usage.EventType]usagewal.TypeConfig{}
	hasType := map[usage.EventType]bool{}
	for name, tc := range cfg.Types {
		typ := usage.EventType(name)
		mode := usagewal.FsyncNone
		switch tc.Fsync {
		case "window_ms":
			mode = usagewal.FsyncWindow
		case "always":
			mode = usagewal.FsyncAlways
		}
		types[typ] = usagewal.TypeConfig{
			ShareBytes:   tc.ShareBytes,
			Fsync:        mode,
			WindowMS:     tc.WindowMS,
			SegmentBytes: tc.SegmentBytes,
		}
		hasType[typ] = true
	}
	store, err := usagewal.Open(usagewal.Config{
		Dir:         cfg.Dir,
		BudgetBytes: cfg.BudgetBytes,
		Types:       types,
	})
	if err != nil {
		return nil, fmt.Errorf("usage: %w", err)
	}
	st := license.Eval(licCfg, time.Now())
	host, err := pluginhost.New(pluginhost.Config{
		WAL:    store,
		Secret: cfg.PluginSecret,
		Allow: func(feature string) bool {
			return license.HasFeature(st, feature)
		},
	})
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("usage: %w", err)
	}
	u := &usageRuntime{
		store:         store,
		host:          host,
		subjectSecret: cfg.SubjectSecret,
		nodeID:        cfg.NodeID,
		epoch:         time.Now().UTC().Format(time.RFC3339Nano),
		types:         hasType,
	}
	for _, pc := range cfg.Plugins {
		name := pc.Name
		types := pc.Types
		filters := pc.Filters
		maxLag := pc.MaxLagBytes
		onMaxLag := pc.OnMaxLag
		feature := pc.LicenseFeature
		if pc.Manifest != "" {
			raw, err := os.ReadFile(pc.Manifest)
			if err != nil {
				_ = u.close()
				return nil, fmt.Errorf("usage: %s: manifest: %w",
					pc.Name, err)
			}
			m, err := pluginmanifest.Parse(raw)
			if err != nil {
				_ = u.close()
				return nil, fmt.Errorf("usage: %s: %w", pc.Name, err)
			}
			artifact, err := os.ReadFile(pc.Artifact)
			if err != nil {
				_ = u.close()
				return nil, fmt.Errorf("usage: %s: artifact: %w",
					pc.Name, err)
			}
			if err := m.Verify(cfg.Trust, raw, artifact); err != nil {
				_ = u.close()
				return nil, fmt.Errorf("usage: %s: %w", pc.Name, err)
			}
			if name != "" && name != m.Name {
				_ = u.close()
				return nil, fmt.Errorf(
					"usage: plugin name %q != manifest name %q",
					name, m.Name)
			}
			name = m.Name
			if m.Events == nil {
				_ = u.close()
				return nil, fmt.Errorf(
					"usage: %s: manifest has no events subscription",
					name)
			}
			types = append([]string(nil), m.Events.Types...)
			filters = coreFilters(m.Events.Filters)
			maxLag = m.Events.MaxLagBytes
			onMaxLag = m.Events.OnMaxLag
			feature = m.LicenseFeature
		}
		var pts []usage.EventType
		for _, t := range types {
			typ := usage.EventType(t)
			if !u.types[typ] {
				_ = u.close()
				return nil, fmt.Errorf(
					"usage: %s: type %q is not configured in usage.types",
					name, t)
			}
			pts = append(pts, typ)
		}
		if len(pts) == 0 {
			_ = u.close()
			return nil, fmt.Errorf(
				"usage: %s: at least one event type is required", name)
		}
		var hostFilters *pluginhost.Filters
		if filters != nil {
			hostFilters = &pluginhost.Filters{
				Routes:        filters.Routes,
				Tenants:       filters.Tenants,
				Methods:       filters.Methods,
				StatusClasses: filters.StatusClasses,
			}
		}
		if err := host.Register(pluginhost.Plugin{
			Name:           name,
			URL:            pc.URL,
			Types:          pts,
			Filters:        hostFilters,
			MaxLagBytes:    maxLag,
			OnMaxLag:       onMaxLag,
			LicenseFeature: feature,
		}); err != nil {
			_ = u.close()
			return nil, fmt.Errorf("usage: %w", err)
		}
		for _, typ := range pts {
			u.subs = append(u.subs, usageSub{typ: typ, filters: filters})
		}
	}
	return u, nil
}

func (u *usageRuntime) close() error {
	if u == nil {
		return nil
	}
	var first error
	if u.host != nil {
		if err := u.host.Close(); err != nil {
			first = err
		}
	}
	if u.store != nil {
		if err := u.store.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (u *usageRuntime) subjectID(issuer, sub string) string {
	if u == nil || len(u.subjectSecret) == 0 ||
		strings.TrimSpace(sub) == "" {
		return ""
	}
	sid, err := usage.SubjectID(u.subjectSecret, issuer, sub)
	if err != nil {
		return ""
	}
	return sid
}

// setSubjectHeader overwrites any client-supplied value after auth.
func (u *usageRuntime) setSubjectHeader(
	r *http.Request, ctx *RequestContext, p *providerEntry,
) {
	if u == nil || r == nil {
		return
	}
	r.Header.Del("X-Gate-One-Subject")
	if ctx == nil || ctx.UserID == "" {
		return
	}
	if sid := u.subjectID(providerIssuer(p), ctx.UserID); sid != "" {
		r.Header.Set("X-Gate-One-Subject", sid)
	}
}

// admit reserves WAL space for the durable events this request may
// produce. It runs before auth/backend so a full share can be answered
// with a 503 instead of silently losing an event.
func (u *usageRuntime) admit(
	route *core.Route, ctx *RequestContext, p *providerEntry,
) (*usageAdmission, usage.EventType) {
	if u == nil || route == nil || ctx == nil {
		return nil, ""
	}
	tenant := tenantFor(route, p)
	adm := &usageAdmission{tickets: map[usage.EventType]*usagewal.Ticket{}}
	for _, typ := range []usage.EventType{usage.TypeRequest, usage.TypeError} {
		if !u.types[typ] {
			continue
		}
		if !u.match(typ, tenant, ctx.Path, ctx.Method, 0) {
			continue
		}
		tk, err := u.store.Reserve(typ, usageMaxRecordBytes)
		if err != nil {
			for t, ticket := range adm.tickets {
				u.store.Release(ticket)
				delete(adm.tickets, t)
			}
			if !errors.Is(err, usagewal.ErrFull) {
				log.Printf("usage: reserve %s: %v", typ, err)
			}
			return nil, typ
		}
		adm.tickets[typ] = tk
	}
	if len(adm.tickets) == 0 {
		return nil, ""
	}
	return adm, ""
}

// emit releases unused reservations and appends the matching events.
func (u *usageRuntime) emit(
	adm *usageAdmission,
	route *core.Route,
	ctx *RequestContext,
	p *providerEntry,
	status int,
	dur time.Duration,
	bytes int64,
	requestID string,
) {
	if u == nil || adm == nil || route == nil || ctx == nil {
		return
	}
	if status == 0 {
		status = http.StatusOK
	}
	tenant := tenantFor(route, p)
	routeName := normalizedRoute(route, ctx.Path)
	for typ, tk := range adm.tickets {
		if typ == usage.TypeError && status < 400 {
			u.store.Release(tk)
			continue
		}
		if !u.match(typ, tenant, ctx.Path, ctx.Method, status) {
			u.store.Release(tk)
			continue
		}
		ev := usage.Event{
			SchemaVersion: usage.SchemaVersion,
			Type:          typ,
			Timestamp:     time.Now().UTC(),
			InstanceID:    u.nodeID,
			Epoch:         u.epoch,
			Tenant:        tenant,
			SubjectID:     u.subjectID(providerIssuer(p), ctx.UserID),
			Route:         routeName,
			Method:        ctx.Method,
			Status:        status,
			DurationMS:    dur.Milliseconds(),
			Bytes:         bytes,
			AuthResult:    authResultFor(status, ctx.UserID),
			Units:         1,
			UnitType:      usage.UnitRequest,
			RequestID:     requestID,
		}
		if _, err := u.store.Append(tk, &ev); err != nil {
			log.Printf("usage: append %s: %v", typ, err)
			u.store.Release(tk)
		}
	}
}

// authEvent appends an authentication lifecycle event. A successful
// login calls this before creating the session (fail-closed); logout
// and backchannel paths log and continue.
func (u *usageRuntime) authEvent(
	providerID, issuer string, ev authn.AuthEvent,
) error {
	if u == nil {
		return nil
	}
	if !u.types[usage.TypeAuth] {
		return nil
	}
	if !u.match(usage.TypeAuth, providerID, "", "", 0) {
		return nil
	}
	tk, err := u.store.Reserve(usage.TypeAuth, usageMaxRecordBytes)
	if err != nil {
		return err
	}
	status := http.StatusOK
	switch ev.Result {
	case "failed":
		status = http.StatusUnauthorized
	case "denied":
		status = http.StatusForbidden
	}
	result := ev.Result
	if result == "no_session" {
		result = "ok"
	}
	ts := ev.At
	if ts.IsZero() {
		ts = time.Now()
	}
	out := usage.Event{
		SchemaVersion: usage.SchemaVersion,
		Type:          usage.TypeAuth,
		Timestamp:     ts.UTC(),
		InstanceID:    u.nodeID,
		Epoch:         u.epoch,
		Tenant:        providerID,
		SubjectID:     u.subjectID(issuer, ev.UserID),
		Action:        ev.Action,
		SessionID:     ev.SessionID,
		Status:        status,
		AuthResult:    result,
	}
	if _, err := u.store.Append(tk, &out); err != nil {
		u.store.Release(tk)
		return err
	}
	return nil
}

func (g *Gateway) authEventSink(
	providerID, issuer string,
) authn.EventSink {
	return func(ev authn.AuthEvent) error {
		if g.usage == nil {
			return nil
		}
		return g.usage.authEvent(providerID, issuer, ev)
	}
}

func coreFilters(
	f *pluginmanifest.EventFilters,
) *core.UsageFilters {
	if f == nil {
		return nil
	}
	return &core.UsageFilters{
		Routes:        f.Routes,
		Tenants:       f.Tenants,
		Methods:       f.Methods,
		StatusClasses: f.StatusClasses,
		SampleRate:    f.SampleRate,
	}
}

func (u *usageRuntime) match(
	typ usage.EventType, tenant, reqPath, method string, status int,
) bool {
	for _, s := range u.subs {
		if s.typ != typ {
			continue
		}
		if matchUsageFilters(s.filters, tenant, reqPath, method, status) {
			return true
		}
	}
	return false
}

func matchUsageFilters(
	f *core.UsageFilters, tenant, reqPath, method string, status int,
) bool {
	if f == nil {
		return true
	}
	if len(f.Tenants) > 0 && !containsFoldExact(f.Tenants, tenant) {
		return false
	}
	if len(f.Methods) > 0 && !containsFoldExact(f.Methods, method) {
		return false
	}
	if len(f.Routes) > 0 && !matchUsageRoute(f.Routes, reqPath) {
		return false
	}
	if status > 0 && len(f.StatusClasses) > 0 &&
		!matchUsageStatus(f.StatusClasses, status) {
		return false
	}
	return true
}

func containsFoldExact(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func matchUsageRoute(patterns []string, reqPath string) bool {
	for _, p := range patterns {
		if p == reqPath {
			return true
		}
		if ok, _ := path.Match(p, reqPath); ok {
			return true
		}
		if strings.HasSuffix(p, "*") &&
			strings.HasPrefix(reqPath, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}

func matchUsageStatus(classes []string, status int) bool {
	for _, c := range classes {
		if len(c) == 3 && c[1:] == "xx" &&
			c[0] == byte('0'+status/100) {
			return true
		}
	}
	return false
}

func tenantFor(route *core.Route, p *providerEntry) string {
	if route != nil && route.Auth != nil && route.Auth.Provider != "" {
		return route.Auth.Provider
	}
	if p != nil {
		return p.id
	}
	return ""
}

func providerIssuer(p *providerEntry) string {
	if p == nil {
		return ""
	}
	if p.issuer != "" {
		return p.issuer
	}
	return p.id
}

func normalizedRoute(route *core.Route, reqPath string) string {
	if route != nil && route.Path != "" && route.Path != "/*" {
		return route.Path
	}
	return reqPath
}

func authResultFor(status int, userID string) string {
	switch {
	case status == http.StatusUnauthorized:
		return "anonymous"
	case status == http.StatusForbidden:
		return "denied"
	case status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable:
		return "unavailable"
	case userID != "":
		return "ok"
	default:
		return "anonymous"
	}
}

// writeUsageUnavailable answers a request whose durable event cannot
// be stored. It is a 503 distinct from the auth-provider outage: the
// auth probe and health endpoints never reach this path.
func writeUsageUnavailable(
	w http.ResponseWriter, r *http.Request, pageRoute bool, typ usage.EventType,
) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "5")
	log.Printf("USAGE WAL full type=%s", typ)
	if pageRoute && isDocumentNavigation(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Service temporarily unavailable</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;
font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;
background:#f4f5f7;color:#1c1f23}
main{max-width:560px;padding:28px;background:#fff;border:1px solid #e2e6ea;
border-radius:14px}
h1{font-size:20px;margin:0 0 8px}p{margin:0;color:#5c6470}
</style></head><body><main>
<h1>Service temporarily unavailable</h1>
<p>Usage storage is full for this service. This is not a sign-in
problem: retry in a moment.</p>
</main></body></html>`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = fmt.Fprintf(w, `{"error":"usage_unavailable","type":%q}`,
		string(typ))
}

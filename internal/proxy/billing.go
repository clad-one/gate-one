package proxy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/credit"
	"cladone/gate-one/internal/license"
	"cladone/gate-one/internal/metering"
	"cladone/gate-one/internal/outbox"
	"cladone/gate-one/internal/sink"
	"cladone/gate-one/pkg/pluginmanifest"
)

// billingRuntime authorises the billable routes: it rates one measure
// (quantity 1 for a discrete route metric), reserves the amount on the
// budget BEFORE the backend call, and settles afterwards.
//
// Lot 2 scope: the budget is backed by a signed allowance (airgap
// profile). The online ledger lease plugs into the same credit.Budget
// interface without touching this file.
type billingRuntime struct {
	reg    *meteringRegistry
	budget credit.Budget
	ttl    time.Duration
	box    *outbox.Store
	pusher *sink.Pusher
	cancel context.CancelFunc
}

func (b *billingRuntime) close() {
	if b == nil {
		return
	}
	if b.cancel != nil {
		b.cancel()
	}
	if b.pusher != nil {
		_ = b.pusher.Close()
	}
	if b.box != nil {
		_ = b.box.Close()
	}
}

// meteringRegistry is the subset of pricing.Registry used here, kept as a
// tiny interface so the proxy does not depend on the pricing package in
// its tests.
type meteringRegistry struct {
	rate   func(m metering.Measure) (metering.Decision, error)
	metric func(code string) (metering.Metric, bool)
}

// FeatureBillingBYO gates the "bring your own billing backend" paths
// (airgap profile, external sink). The managed path is the default; BYO
// is a paid licence feature because it bypasses the settlement split.
const FeatureBillingBYO = "billing-byo"

func newBillingRuntime(
	u *core.UsageConfig, lic *license.Config, region string,
) (*billingRuntime, error) {
	if u == nil || u.Metering == nil {
		return nil, nil
	}
	// The managed path keeps the settlement split; any path that bypasses
	// it (airgap today, external sink later) requires the licence feature.
	byo := u.Profile == "airgap"
	if byo && !license.HasFeature(license.Eval(lic, time.Now()), FeatureBillingBYO) {
		return nil, fmt.Errorf(
			"usage.profile airgap requires the %q licence feature: "+
				"the managed profile keeps the settlement split, BYO is a paid option",
			FeatureBillingBYO)
	}
	reg := &meteringRegistry{
		rate:   u.Metering.Rate,
		metric: u.Metering.Metric,
	}

	if u.AllowancePublicKey == "" || len(u.AllowanceJSON) == 0 {
		// No allowance provisioned: metering is configured but cannot
		// authorise. Refuse startup rather than serve unbilled traffic.
		return nil, fmt.Errorf(
			"usage.%s: metering requires a signed allowance "+
				"(usage.allowanceFile or usage.allowanceEnv) and usage.allowancePublicKey",
			region)
	}
	pub, err := pluginmanifest.DecodePublicKey(u.AllowancePublicKey)
	if err != nil {
		return nil, fmt.Errorf("usage.allowancePublicKey: %w", err)
	}
	a, err := credit.VerifyAllowance(u.AllowanceJSON, pub)
	if err != nil {
		return nil, fmt.Errorf("usage allowance: %w", err)
	}
	maxAge, err := time.ParseDuration(u.Outbox.MaxAge)
	if err != nil {
		return nil, fmt.Errorf("usage.outbox.maxAge: %w", err)
	}
	box, err := outbox.Open(outbox.Config{
		Dir:        u.Outbox.Dir,
		MaxAge:     maxAge,
		MaxBytes:   u.Outbox.MaxBytes,
		MaxRecords: u.Outbox.MaxRecords,
		OnFull:     u.Outbox.OnFull,
	})
	if err != nil {
		return nil, fmt.Errorf("usage.outbox: %w", err)
	}
	seed, err := base64.RawURLEncoding.DecodeString(string(u.SinkSigningSeed))
	if err != nil || len(seed) != ed25519.SeedSize {
		_ = box.Close()
		return nil, fmt.Errorf(
			"usage.sink.signingKeyEnv: expected a base64url 32-byte seed")
	}
	pusher, err := sink.New(box, sink.Config{
		URL:          u.Sink.URL,
		Secret:       string(u.SinkSecret),
		NodeID:       u.NodeID,
		SigningKey:   ed25519.NewKeyFromSeed(seed),
		BatchRecords: u.Sink.BatchRecords,
		BatchBytes:   u.Sink.BatchBytes,
		BatchWait:    time.Duration(u.Sink.BatchWaitMS) * time.Millisecond,
		ExportDir:    u.Sink.ExportDir,
		ExportAfter:  time.Duration(u.Sink.ExportAfterSeconds) * time.Second,
	})
	if err != nil {
		_ = box.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	go pusher.Run(ctx)
	return &billingRuntime{
		reg:    reg,
		budget: credit.NewAllocationBudget([]credit.Allowance{a}),
		ttl:    5 * time.Minute,
		box:    box,
		pusher: pusher,
		cancel: cancel,
	}, nil
}

// billingAdmission is the hold for one request.
type billingAdmission struct {
	res      credit.Reservation
	metric   string
	scale    int
	measure  metering.Measure
	decision metering.Decision
}

// admit rates and reserves the request. A non-nil error means the caller
// must refuse the request (402 when the budget is short).
func (b *billingRuntime) admit(
	ctx context.Context,
	route *core.Route,
	tenant, requestID string,
	r *http.Request,
) (*billingAdmission, error) {
	m, ok := b.reg.metric(route.Metric)
	if !ok {
		return nil, fmt.Errorf("route metric %q is not configured", route.Metric)
	}
	measure := metering.Measure{
		Tenant:      tenant,
		Metric:      m.Code,
		Quantity:    1, // discrete route metric: one unit per request
		Dimensions:  routeDimensions(m, route, r),
		Idempotency: "req:" + requestID,
		At:          time.Now().UTC(),
	}
	decision, err := b.reg.rate(measure)
	if err != nil {
		return nil, fmt.Errorf("rate %s: %w", m.Code, err)
	}
	if decision.AmountMicro <= 0 {
		// Free metric: nothing to reserve, nothing to bill.
		return nil, nil
	}
	res, err := b.budget.Reserve(
		ctx, tenant, m.Code, decision.AmountMicro, b.ttl)
	if err != nil {
		return nil, err
	}
	return &billingAdmission{
		res: res, metric: m.Code, scale: m.Scale,
		measure: measure, decision: decision,
	}, nil
}

// routeDimensions fills the dimensions the metric declares and the
// gateway can know before the call.
func routeDimensions(m metering.Metric, route *core.Route, r *http.Request) map[string]string {
	out := map[string]string{}
	for name := range m.Dimensions {
		switch name {
		case "route":
			out[name] = route.Path
		case "host":
			out[name] = route.Host
		case "method":
			out[name] = r.Method
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// settle captures the reservation. A 5xx releases it: the customer does
// not pay for a backend failure.
func (b *billingRuntime) settle(adm *billingAdmission, status int) {
	if adm == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if status >= http.StatusInternalServerError {
		if err := b.budget.Release(ctx, adm.res); err != nil {
			log.Printf("billing: release %s: %v", adm.metric, err)
		}
		b.record(adm, "released", status)
		return
	}
	if err := b.budget.Settle(ctx, adm.res, adm.res.AmountMicro); err != nil {
		log.Printf("billing: settle %s: %v", adm.metric, err)
	}
	b.record(adm, "settled", status)
}

// record appends the priced measure to the outbox. Delivery (and its
// acknowledgement) is the pusher's job, never the request path.
func (b *billingRuntime) record(adm *billingAdmission, settlement string, status int) {
	if b.box == nil {
		return
	}
	rec := struct {
		SchemaVersion  int               `json:"schemaVersion"`
		Tenant         string            `json:"tenant"`
		Metric         string            `json:"metric"`
		Quantity       int64             `json:"quantity"`
		Scale          int               `json:"scale"`
		Dimensions     map[string]string `json:"dimensions,omitempty"`
		IdempotencyKey string            `json:"idempotencyKey"`
		At             time.Time         `json:"at"`
		RequestID      string            `json:"requestId,omitempty"`
		AmountMicro    int64             `json:"amountMicro"`
		Currency       string            `json:"currency"`
		PriceVersion   string            `json:"priceVersion"`
		EngineVersion  string            `json:"engineVersion"`
		InputsHash     string            `json:"inputsHash"`
		Settlement     string            `json:"settlement"`
		Status         int               `json:"status"`
	}{
		SchemaVersion: 1, Tenant: adm.measure.Tenant, Metric: adm.metric,
		Quantity: adm.measure.Quantity, Scale: adm.scale,
		Dimensions:     adm.measure.Dimensions,
		IdempotencyKey: adm.measure.Idempotency, At: adm.measure.At,
		RequestID:   adm.measure.RequestID,
		AmountMicro: adm.decision.AmountMicro, Currency: adm.decision.Currency,
		PriceVersion:  adm.decision.PriceVersion,
		EngineVersion: adm.decision.EngineVersion,
		InputsHash:    adm.decision.InputsHash,
		Settlement:    settlement, Status: status,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		log.Printf("billing: record: %v", err)
		return
	}
	if _, err := b.box.Append(raw); err != nil {
		log.Printf("billing: outbox append: %v", err)
	}
}

// writeBillingError answers a request that cannot be authorised.
func writeBillingError(w http.ResponseWriter, r *http.Request, page bool, err error) {
	code := http.StatusServiceUnavailable
	reason := "billing_unavailable"
	switch {
	case errors.Is(err, credit.ErrInsufficient):
		code, reason = http.StatusPaymentRequired, "insufficient_allowance"
	case errors.Is(err, credit.ErrAllowanceExpired):
		code, reason = http.StatusPaymentRequired, "allowance_expired"
	case errors.Is(err, credit.ErrNoAllowance):
		code, reason = http.StatusPaymentRequired, "no_allowance"
	case errors.Is(err, outbox.ErrFull):
		code, reason = http.StatusServiceUnavailable, "billing_buffer_full"
	}
	if page && isDocumentNavigation(r) {
		http.Error(w, "payment required: "+reason, code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":"` + reason + `"}`))
}

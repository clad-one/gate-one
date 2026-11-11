package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/credit"
	"cladone/gate-one/internal/metering"
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
}

// meteringRegistry is the subset of pricing.Registry used here, kept as a
// tiny interface so the proxy does not depend on the pricing package in
// its tests.
type meteringRegistry struct {
	rate   func(m metering.Measure) (metering.Decision, error)
	metric func(code string) (metering.Metric, bool)
}

func newBillingRuntime(
	u *core.UsageConfig, region string,
) (*billingRuntime, error) {
	if u == nil || u.Metering == nil {
		return nil, nil
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
	return &billingRuntime{
		reg:    reg,
		budget: credit.NewAllocationBudget([]credit.Allowance{a}),
		ttl:    5 * time.Minute,
	}, nil
}

// billingAdmission is the hold for one request.
type billingAdmission struct {
	res    credit.Reservation
	metric string
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
	return &billingAdmission{res: res, metric: m.Code}, nil
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
		return
	}
	if err := b.budget.Settle(ctx, adm.res, adm.res.AmountMicro); err != nil {
		log.Printf("billing: settle %s: %v", adm.metric, err)
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
	}
	if page && isDocumentNavigation(r) {
		http.Error(w, "payment required: "+reason, code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":"` + reason + `"}`))
}

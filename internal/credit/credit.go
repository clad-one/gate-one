// Package credit authorises spending before a billable action runs.
//
// Two profiles are supported by the same interface:
//
//   - online: a lease refilled from the managed ledger (the ledger stays
//     off the hot path);
//   - airgap: a signed allowance loaded from a file, valid for a period
//     (the ledger is unreachable, so the allowance is the authority).
//
// A reservation is a hold: it reduces the available capacity immediately
// and is either settled (actual amount, remainder released) or released.
package credit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrInsufficient means the available capacity is below the request.
	ErrInsufficient = errors.New("credit: insufficient allowance")
	// ErrAllowanceExpired means the signed allowance is no longer valid.
	ErrAllowanceExpired = errors.New("credit: allowance expired")
	// ErrNoAllowance means no allowance covers this tenant/metric.
	ErrNoAllowance = errors.New("credit: no allowance")
	// ErrBadSignature means the allowance was not signed by the issuer.
	ErrBadSignature = errors.New("credit: invalid allowance signature")
	// ErrOverSettle means a settlement exceeds its reservation.
	ErrOverSettle = errors.New("credit: settlement exceeds reservation")
	// ErrNotFound means the reservation is unknown (expired or settled).
	ErrNotFound = errors.New("credit: reservation not found")
)

// Reservation is a hold on a budget.
type Reservation struct {
	ID          string
	Tenant      string
	Metric      string
	AmountMicro int64
	ExpiresAt   time.Time
}

// Budget authorises and settles spending.
type Budget interface {
	Reserve(ctx context.Context, tenant, metric string, amountMicro int64, ttl time.Duration) (Reservation, error)
	Release(ctx context.Context, r Reservation) error
	Settle(ctx context.Context, r Reservation, actualMicro int64) error
	Available(ctx context.Context, tenant, metric string) (int64, error)
}

// Allowance is a signed, period-scoped spending authorisation. Metric "*"
// covers every metric of the tenant.
type Allowance struct {
	Tenant         string    `json:"tenant"`
	Metric         string    `json:"metric"`
	AllowanceMicro int64     `json:"allowanceMicro"`
	Currency       string    `json:"currency"`
	Period         string    `json:"period,omitempty"`
	ExpiresAt      time.Time `json:"expiresAt"`
	Signature      string    `json:"signature,omitempty"`
}

// AllowancePayload is the canonical bytes covered by the signature: the
// allowance with an empty signature member.
func AllowancePayload(a Allowance) ([]byte, error) {
	a.Signature = ""
	return json.Marshal(a)
}

// SignAllowance signs an allowance (issuer side).
func SignAllowance(a Allowance, priv ed25519.PrivateKey) (Allowance, error) {
	payload, err := AllowancePayload(a)
	if err != nil {
		return a, err
	}
	a.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(priv, payload))
	return a, nil
}

// VerifyAllowance parses and verifies a signed allowance document.
func VerifyAllowance(raw []byte, pub ed25519.PublicKey) (Allowance, error) {
	var a Allowance
	if err := json.Unmarshal(raw, &a); err != nil {
		return Allowance{}, fmt.Errorf("credit: allowance: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(a.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Allowance{}, ErrBadSignature
	}
	payload, err := AllowancePayload(a)
	if err != nil {
		return Allowance{}, err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return Allowance{}, ErrBadSignature
	}
	if strings.TrimSpace(a.Tenant) == "" {
		return Allowance{}, fmt.Errorf("credit: allowance: tenant is required")
	}
	if strings.TrimSpace(a.Metric) == "" {
		a.Metric = "*"
	}
	if a.AllowanceMicro < 0 {
		return Allowance{}, fmt.Errorf("credit: allowance: negative amount")
	}
	if a.ExpiresAt.IsZero() {
		return Allowance{}, fmt.Errorf("credit: allowance: expiresAt is required")
	}
	return a, nil
}

// AllocationBudget spends a signed allowance. It implements the airgap
// profile: no network, no ledger, fail-closed at the allowance limit.
type AllocationBudget struct {
	mu    sync.Mutex
	now   func() time.Time
	spent map[string]*allowanceState // key tenant|metric
	holds map[string]Reservation
}

type allowanceState struct {
	remaining int64
	expires   time.Time
	currency  string
	period    string
}

var reservationSeq atomic.Uint64

func newReservationID() string {
	return fmt.Sprintf("res-%d-%d", time.Now().UnixNano(), reservationSeq.Add(1))
}

// NewAllocationBudget builds a budget from verified allowances.
func NewAllocationBudget(allowances []Allowance) *AllocationBudget {
	b := &AllocationBudget{
		now:   time.Now,
		spent: map[string]*allowanceState{},
		holds: map[string]Reservation{},
	}
	for _, a := range allowances {
		b.spent[allowanceKey(a.Tenant, a.Metric)] = &allowanceState{
			remaining: a.AllowanceMicro,
			expires:   a.ExpiresAt,
			currency:  a.Currency,
			period:    a.Period,
		}
	}
	return b
}

// WithClock replaces the clock (tests).
func (b *AllocationBudget) WithClock(now func() time.Time) *AllocationBudget {
	b.now = now
	return b
}

func allowanceKey(tenant, metric string) string {
	return strings.ToLower(tenant) + "|" + metric
}

// stateFor returns the allowance covering tenant/metric, preferring an
// exact metric over the wildcard.
func (b *AllocationBudget) stateFor(tenant, metric string) (*allowanceState, string) {
	if st, ok := b.spent[allowanceKey(tenant, metric)]; ok {
		return st, allowanceKey(tenant, metric)
	}
	if st, ok := b.spent[allowanceKey(tenant, "*")]; ok {
		return st, allowanceKey(tenant, "*")
	}
	return nil, ""
}

// Reserve holds amountMicro against the allowance.
func (b *AllocationBudget) Reserve(
	_ context.Context, tenant, metric string, amountMicro int64, ttl time.Duration,
) (Reservation, error) {
	if amountMicro < 0 {
		return Reservation{}, fmt.Errorf("credit: negative reservation")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.releaseExpiredLocked(now)

	st, _ := b.stateFor(tenant, metric)
	if st == nil {
		return Reservation{}, ErrNoAllowance
	}
	if !now.Before(st.expires) {
		return Reservation{}, ErrAllowanceExpired
	}
	if st.remaining < amountMicro {
		return Reservation{}, ErrInsufficient
	}
	st.remaining -= amountMicro
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	r := Reservation{
		ID:          newReservationID(),
		Tenant:      tenant,
		Metric:      metric,
		AmountMicro: amountMicro,
		ExpiresAt:   now.Add(ttl),
	}
	b.holds[r.ID] = r
	return r, nil
}

// Release returns the whole hold.
func (b *AllocationBudget) Release(_ context.Context, r Reservation) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	held, ok := b.holds[r.ID]
	if !ok {
		return ErrNotFound
	}
	delete(b.holds, r.ID)
	if st, _ := b.stateFor(held.Tenant, held.Metric); st != nil {
		st.remaining += held.AmountMicro
	}
	return nil
}

// Settle consumes actualMicro and releases the difference.
func (b *AllocationBudget) Settle(_ context.Context, r Reservation, actualMicro int64) error {
	if actualMicro < 0 {
		return fmt.Errorf("credit: negative settlement")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	held, ok := b.holds[r.ID]
	if !ok {
		return ErrNotFound
	}
	if actualMicro > held.AmountMicro {
		return ErrOverSettle
	}
	delete(b.holds, r.ID)
	if st, _ := b.stateFor(held.Tenant, held.Metric); st != nil {
		st.remaining += held.AmountMicro - actualMicro
	}
	return nil
}

// Available returns the unspent allowance for tenant/metric.
func (b *AllocationBudget) Available(_ context.Context, tenant, metric string) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.releaseExpiredLocked(now)
	st, _ := b.stateFor(tenant, metric)
	if st == nil {
		return 0, ErrNoAllowance
	}
	if !now.Before(st.expires) {
		return 0, ErrAllowanceExpired
	}
	return st.remaining, nil
}

// releaseExpiredLocked releases holds whose TTL elapsed (a crash must not
// keep capacity frozen forever).
func (b *AllocationBudget) releaseExpiredLocked(now time.Time) {
	for id, held := range b.holds {
		if now.Before(held.ExpiresAt) {
			continue
		}
		delete(b.holds, id)
		if st, _ := b.stateFor(held.Tenant, held.Metric); st != nil {
			st.remaining += held.AmountMicro
		}
	}
}

// Source grants capacity to a lease (the managed ledger in production,
// a stub in tests).
type Source interface {
	// Take moves up to amount from the tenant's balance into the lease and
	// returns the granted amount.
	Take(ctx context.Context, tenant, metric string, amount int64) (int64, error)
}

// LeaseBudget implements the online profile: a local lease refilled from
// a Source, so the ledger is not on the request path.
type LeaseBudget struct {
	mu        sync.Mutex
	src       Source
	now       func() time.Time
	chunk     int64
	threshold float64 // refill when the lease falls below chunk*threshold
	lease     map[string]int64
	holds     map[string]Reservation
}

// NewLeaseBudget builds an online budget.
func NewLeaseBudget(src Source, chunk int64) *LeaseBudget {
	if chunk <= 0 {
		chunk = 1_000_000 // 1 currency unit in micro
	}
	return &LeaseBudget{
		src:       src,
		now:       time.Now,
		chunk:     chunk,
		threshold: 0.3,
		lease:     map[string]int64{},
		holds:     map[string]Reservation{},
	}
}

// WithClock replaces the clock (tests).
func (b *LeaseBudget) WithClock(now func() time.Time) *LeaseBudget {
	b.now = now
	return b
}

func (b *LeaseBudget) Reserve(
	ctx context.Context, tenant, metric string, amountMicro int64, ttl time.Duration,
) (Reservation, error) {
	if amountMicro < 0 {
		return Reservation{}, fmt.Errorf("credit: negative reservation")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key := allowanceKey(tenant, metric)
	if b.lease[key] < amountMicro {
		need := b.chunk
		if amountMicro > need {
			need = amountMicro
		}
		granted, err := b.src.Take(ctx, tenant, metric, need)
		if err != nil {
			return Reservation{}, err
		}
		b.lease[key] += granted
	}
	if b.lease[key] < amountMicro {
		return Reservation{}, ErrInsufficient
	}
	b.lease[key] -= amountMicro
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	r := Reservation{
		ID:          newReservationID(),
		Tenant:      tenant,
		Metric:      metric,
		AmountMicro: amountMicro,
		ExpiresAt:   b.now().Add(ttl),
	}
	b.holds[r.ID] = r
	return r, nil
}

func (b *LeaseBudget) Release(_ context.Context, r Reservation) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	held, ok := b.holds[r.ID]
	if !ok {
		return ErrNotFound
	}
	delete(b.holds, r.ID)
	b.lease[allowanceKey(held.Tenant, held.Metric)] += held.AmountMicro
	return nil
}

func (b *LeaseBudget) Settle(_ context.Context, r Reservation, actualMicro int64) error {
	if actualMicro < 0 {
		return fmt.Errorf("credit: negative settlement")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	held, ok := b.holds[r.ID]
	if !ok {
		return ErrNotFound
	}
	if actualMicro > held.AmountMicro {
		return ErrOverSettle
	}
	delete(b.holds, r.ID)
	b.lease[allowanceKey(held.Tenant, held.Metric)] += held.AmountMicro - actualMicro
	return nil
}

func (b *LeaseBudget) Available(_ context.Context, tenant, metric string) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lease[allowanceKey(tenant, metric)], nil
}

// HashAllowance is a convenience for logs (never logs the allowance).
func HashAllowance(a Allowance) string {
	payload, _ := AllowancePayload(a)
	sum := sha256.Sum256(payload)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

package credit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func signedAllowance(t *testing.T, a Allowance) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignAllowance(a, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw, pub
}

func TestVerifyAllowance(t *testing.T) {
	raw, pub := signedAllowance(t, Allowance{
		Tenant: "company", Metric: "*", AllowanceMicro: 1_000_000,
		Currency: "EUR", ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	a, err := VerifyAllowance(raw, pub)
	if err != nil {
		t.Fatalf("valid allowance rejected: %v", err)
	}
	if a.AllowanceMicro != 1_000_000 {
		t.Fatalf("allowance = %+v", a)
	}
	// Tampering must fail.
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	doc["allowanceMicro"] = float64(999_999_999)
	tampered, _ := json.Marshal(doc)
	if _, err := VerifyAllowance(tampered, pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered allowance: %v", err)
	}
	// Wrong key must fail.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyAllowance(raw, otherPub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong key: %v", err)
	}
}

func testBudget(t *testing.T, amount int64) *AllocationBudget {
	t.Helper()
	return NewAllocationBudget([]Allowance{{
		Tenant: "company", Metric: "*", AllowanceMicro: amount,
		Currency: "EUR", ExpiresAt: time.Now().Add(time.Hour),
	}})
}

func TestAllocationReserveSettleRelease(t *testing.T) {
	ctx := context.Background()
	b := testBudget(t, 1000)

	r, err := b.Reserve(ctx, "company", "api", 300, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Available(ctx, "company", "api"); got != 700 {
		t.Fatalf("available = %d, want 700", got)
	}
	if err := b.Settle(ctx, r, 120); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Available(ctx, "company", "api"); got != 880 {
		t.Fatalf("available after settle = %d, want 880", got)
	}

	r, err = b.Reserve(ctx, "company", "api", 500, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Release(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Available(ctx, "company", "api"); got != 880 {
		t.Fatalf("available after release = %d, want 880", got)
	}
}

func TestAllocationInsufficient(t *testing.T) {
	ctx := context.Background()
	b := testBudget(t, 100)
	if _, err := b.Reserve(ctx, "company", "api", 101, time.Minute); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("expected insufficient, got %v", err)
	}
	if _, err := b.Reserve(ctx, "other", "api", 1, time.Minute); !errors.Is(err, ErrNoAllowance) {
		t.Fatalf("expected no allowance, got %v", err)
	}
}

func TestAllocationExpired(t *testing.T) {
	now := time.Now()
	b := NewAllocationBudget([]Allowance{{
		Tenant: "company", Metric: "*", AllowanceMicro: 100,
		Currency: "EUR", ExpiresAt: now.Add(-time.Minute),
	}}).WithClock(func() time.Time { return now })
	if _, err := b.Reserve(context.Background(), "company", "api", 1, time.Minute); !errors.Is(err, ErrAllowanceExpired) {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestAllocationHoldExpiry(t *testing.T) {
	now := time.Now()
	b := testBudget(t, 100).WithClock(func() time.Time { return now })
	if _, err := b.Reserve(context.Background(), "company", "api", 100, time.Minute); err != nil {
		t.Fatal(err)
	}
	// Move past the TTL: the hold is released on the next call.
	now = now.Add(2 * time.Minute)
	if got, _ := b.Available(context.Background(), "company", "api"); got != 100 {
		t.Fatalf("available after TTL = %d, want 100", got)
	}
}

func TestAllocationOverSettle(t *testing.T) {
	ctx := context.Background()
	b := testBudget(t, 100)
	r, err := b.Reserve(ctx, "company", "api", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Settle(ctx, r, 11); !errors.Is(err, ErrOverSettle) {
		t.Fatalf("expected over-settle, got %v", err)
	}
}

func TestAllocationConcurrentNeverOverspends(t *testing.T) {
	ctx := context.Background()
	b := testBudget(t, 1000)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := b.Reserve(ctx, "company", "api", 10, time.Minute); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 100 {
		t.Fatalf("%d reservations succeeded, want 100", ok)
	}
	if got, _ := b.Available(ctx, "company", "api"); got != 0 {
		t.Fatalf("available = %d, want 0", got)
	}
}

type stubSource struct {
	mu       sync.Mutex
	balance  int64
	requests int
}

func (s *stubSource) Take(_ context.Context, _, _ string, amount int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	grant := amount
	if grant > s.balance {
		grant = s.balance
	}
	s.balance -= grant
	return grant, nil
}

func TestLeaseRefillsAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	src := &stubSource{balance: 250}
	b := NewLeaseBudget(src, 100)

	// Première réservation : refill de 100.
	if _, err := b.Reserve(ctx, "t", "m", 80, time.Minute); err != nil {
		t.Fatal(err)
	}
	// Deuxième : le bail contient 20, il faut un nouveau chunk.
	if _, err := b.Reserve(ctx, "t", "m", 80, time.Minute); err != nil {
		t.Fatal(err)
	}
	// Le solde source est épuisé : au-delà, refus.
	if _, err := b.Reserve(ctx, "t", "m", 100, time.Minute); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("expected insufficient, got %v", err)
	}
	if src.requests < 2 {
		t.Fatalf("source requests = %d", src.requests)
	}
}

func TestLeaseSettleReturnsToLease(t *testing.T) {
	ctx := context.Background()
	src := &stubSource{balance: 1000}
	b := NewLeaseBudget(src, 100)
	r, err := b.Reserve(ctx, "t", "m", 100, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Settle(ctx, r, 40); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Available(ctx, "t", "m"); got != 60 {
		t.Fatalf("available = %d, want 60", got)
	}
}

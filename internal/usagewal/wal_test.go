package usagewal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cladone/gate-one/pkg/usage"
)

func testEvent(typ usage.EventType, n int) *usage.Event {
	return &usage.Event{
		SchemaVersion:  usage.SchemaVersion,
		Type:           typ,
		Timestamp:      time.Now().UTC(),
		InstanceID:     "gw-test",
		Epoch:          "epoch-1",
		Tenant:         "mycompany",
		SubjectID:      "v1.abcdef",
		Route:          "/api/process_stream",
		Method:         "POST",
		Status:         200,
		DurationMS:     int64(n),
		Bytes:          10,
		AuthResult:     "ok",
		Units:          1,
		UnitType:       usage.UnitRequest,
		RequestID:      "req-" + string(rune('a'+n)),
		IdempotencyKey: "idem-" + string(rune('a'+n)),
	}
}

func openTest(t *testing.T, cfg Config) *Store {
	t.Helper()
	cfg.Dir = t.TempDir()
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func appendEvent(t *testing.T, s *Store, typ usage.EventType, n int) (int64, int64) {
	t.Helper()
	ticket, err := s.Reserve(typ, 4096)
	if err != nil {
		t.Fatal(err)
	}
	off, err := s.Append(ticket, testEvent(typ, n))
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.Tail(typ)
	if err != nil {
		t.Fatal(err)
	}
	return off, next
}

func TestWALAppendReadAckTruncate(t *testing.T) {
	s := openTest(t, Config{
		BudgetBytes: 1 << 20,
		Types: map[usage.EventType]TypeConfig{
			usage.TypeAudit: {ShareBytes: 1 << 20, SegmentBytes: 64},
		},
	})
	sub := "audit-plugin"
	if _, err := s.Register(usage.TypeAudit, sub); err != nil {
		t.Fatal(err)
	}
	var lastNext int64
	for i := 0; i < 5; i++ {
		_, next := appendEvent(t, s, usage.TypeAudit, i)
		lastNext = next
	}
	recs, err := s.Read(usage.TypeAudit, sub, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 5 {
		t.Fatalf("records = %d, want 5", len(recs))
	}
	for i := 1; i < len(recs); i++ {
		if recs[i].Offset <= recs[i-1].Offset {
			t.Fatalf("offsets not increasing: %v", recs)
		}
	}
	if err := s.Ack(usage.TypeAudit, sub, lastNext); err != nil {
		t.Fatal(err)
	}
	recs, err = s.Read(usage.TypeAudit, sub, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("records after ack = %d, want 0", len(recs))
	}
}

func TestReserveFullAndRelease(t *testing.T) {
	s := openTest(t, Config{
		BudgetBytes: 100,
		Types: map[usage.EventType]TypeConfig{
			usage.TypeAudit: {ShareBytes: 100},
		},
	})
	tk, err := s.Reserve(usage.TypeAudit, 80)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserve(usage.TypeAudit, 30); !errors.Is(err, ErrFull) {
		t.Fatalf("second reserve = %v, want ErrFull", err)
	}
	s.Release(tk)
	if _, err := s.Reserve(usage.TypeAudit, 30); err != nil {
		t.Fatalf("reserve after release: %v", err)
	}
}

func TestBudgetSharesIndependent(t *testing.T) {
	s := openTest(t, Config{
		BudgetBytes: 200,
		Types: map[usage.EventType]TypeConfig{
			usage.TypeAudit: {ShareBytes: 100},
			usage.TypeError: {ShareBytes: 100},
		},
	})
	ta, err := s.Reserve(usage.TypeAudit, 80)
	if err != nil {
		t.Fatal(err)
	}
	te, err := s.Reserve(usage.TypeError, 80)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserve(usage.TypeAudit, 30); !errors.Is(err, ErrFull) {
		t.Fatalf("audit share not isolated: %v", err)
	}
	s.Release(ta)
	s.Release(te)
}

func TestDropByLag(t *testing.T) {
	s := openTest(t, Config{
		BudgetBytes: 1 << 20,
		Types: map[usage.EventType]TypeConfig{
			usage.TypeAudit: {ShareBytes: 1 << 20, SegmentBytes: 64},
		},
	})
	sub := "audit-plugin"
	if _, err := s.Register(usage.TypeAudit, sub); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		appendEvent(t, s, usage.TypeAudit, i)
	}
	cur, err := s.DropSubscriber(usage.TypeAudit, sub, 150)
	if err != nil {
		t.Fatal(err)
	}
	if cur == 0 {
		t.Fatal("cursor was not moved")
	}
	lag, err := s.Lag(usage.TypeAudit, sub)
	if err != nil {
		t.Fatal(err)
	}
	if lag > 150 {
		t.Fatalf("lag = %d, want <= 150", lag)
	}
	recs, err := s.Read(usage.TypeAudit, sub, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Offset < cur {
			t.Fatalf("record %d before lag cursor %d", r.Offset, cur)
		}
	}
}

func TestReopenPersistsCursors(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Dir:         dir,
		BudgetBytes: 1 << 20,
		Types: map[usage.EventType]TypeConfig{
			usage.TypeAudit: {ShareBytes: 1 << 20},
		},
	}
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sub := "audit-plugin"
	if _, err := s.Register(usage.TypeAudit, sub); err != nil {
		t.Fatal(err)
	}
	var firstNext int64
	for i := 0; i < 3; i++ {
		_, next := appendEvent(t, s, usage.TypeAudit, i)
		if i == 0 {
			firstNext = next
		}
	}
	if err := s.Ack(usage.TypeAudit, sub, firstNext); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	cur, err := s2.Cursor(usage.TypeAudit, sub)
	if err != nil {
		t.Fatal(err)
	}
	if cur != firstNext {
		t.Fatalf("cursor after reopen = %d, want %d", cur, firstNext)
	}
	recs, err := s2.Read(usage.TypeAudit, sub, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("records after reopen = %d, want 2", len(recs))
	}
}

func TestTornTailTruncated(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Dir:         dir,
		BudgetBytes: 1 << 20,
		Types: map[usage.EventType]TypeConfig{
			usage.TypeAudit: {ShareBytes: 1 << 20},
		},
	}
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sub := "audit-plugin"
	if _, err := s.Register(usage.TypeAudit, sub); err != nil {
		t.Fatal(err)
	}
	appendEvent(t, s, usage.TypeAudit, 0)
	appendEvent(t, s, usage.TypeAudit, 1)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	segs, err := filepath.Glob(filepath.Join(dir, "audit", "*.seg"))
	if err != nil || len(segs) == 0 {
		t.Fatalf("no segment: %v", err)
	}
	f, err := os.OpenFile(segs[len(segs)-1], os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("garbage")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	s2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	recs, err := s2.Read(usage.TypeAudit, sub, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("records after torn tail = %d, want 2", len(recs))
	}
}

func TestAppendTooLargeTicket(t *testing.T) {
	s := openTest(t, Config{
		BudgetBytes: 1 << 20,
		Types: map[usage.EventType]TypeConfig{
			usage.TypeAudit: {ShareBytes: 1 << 20},
		},
	})
	tk, err := s.Reserve(usage.TypeAudit, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(tk, testEvent(usage.TypeAudit, 0)); !errors.Is(
		err, ErrEventTooLarge,
	) {
		t.Fatalf("err = %v, want ErrEventTooLarge", err)
	}
	s.Release(tk)
}

package outbox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T, cfg Config) *Store {
	t.Helper()
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAppendReadCommit(t *testing.T) {
	dir := t.TempDir()
	s := open(t, Config{Dir: dir})

	o1, err := s.Append([]byte(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append([]byte(`{"n":2}`)); err != nil {
		t.Fatal(err)
	}
	o3, err := s.Append([]byte(`{"n":3}`))
	if err != nil {
		t.Fatal(err)
	}

	recs, next, err := s.Read(0, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || recs[0].Offset != o1 || recs[2].Offset != o3 {
		t.Fatalf("records = %+v", recs)
	}
	if next != s.Head() {
		t.Fatalf("next = %d, head = %d", next, s.Head())
	}

	// Commit the first two: a read from 0 resumes after the marker.
	if err := s.Commit(recs[1].Offset + int64(len(recs[1].Payload)+8)); err != nil {
		t.Fatal(err)
	}
	recs, _, err = s.Read(0, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || string(recs[0].Payload) != `{"n":3}` {
		t.Fatalf("after commit: %+v", recs)
	}
	if r, _, _, _ := s.Stats(); r != 1 {
		t.Fatalf("records = %d, want 1", r)
	}
}

func TestCommitPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append([]byte(`a`)); err != nil {
		t.Fatal(err)
	}
	recs, next, _ := s.Read(0, 10, 0)
	if err := s.Commit(next); err != nil {
		t.Fatal(err)
	}
	head := s.Head()
	_ = s.Close()

	s2, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.CommitOffset() != next || s2.Head() != head {
		t.Fatalf("commit=%d head=%d, want %d/%d",
			s2.CommitOffset(), s2.Head(), next, head)
	}
	if _, err := s2.Append([]byte(`b`)); err != nil {
		t.Fatal(err)
	}
	recs, _, _ = s2.Read(next, 10, 0)
	if len(recs) != 1 || string(recs[0].Payload) != `b` {
		t.Fatalf("after reopen: %+v", recs)
	}
	_ = recs
	_ = os.Remove(filepath.Join(dir, commitFile))
}

func TestBoundsBlockAndDrop(t *testing.T) {
	s := open(t, Config{Dir: t.TempDir(), MaxRecords: 1})
	if _, err := s.Append([]byte(`a`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append([]byte(`b`)); !errors.Is(err, ErrFull) {
		t.Fatalf("err = %v, want ErrFull", err)
	}

	d := open(t, Config{Dir: t.TempDir(), MaxRecords: 1, OnFull: "drop"})
	if _, err := d.Append([]byte(`a`)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Append([]byte(`b`)); err != nil {
		t.Fatalf("drop mode returned %v", err)
	}
	if _, _, _, dropped := d.Stats(); dropped != 1 {
		t.Fatalf("dropped = %d", dropped)
	}
}

func TestMaxAge(t *testing.T) {
	s := open(t, Config{Dir: t.TempDir(), MaxAge: time.Millisecond})
	if _, err := s.Append([]byte(`a`)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := s.Append([]byte(`b`)); !errors.Is(err, ErrFull) {
		t.Fatalf("err = %v, want ErrFull", err)
	}
}

func TestCorruptPayload(t *testing.T) {
	dir := t.TempDir()
	s := open(t, Config{Dir: dir})
	if _, err := s.Append([]byte(`hello`)); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	entries, _ := os.ReadDir(dir)
	var seg string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == segSuffix {
			seg = filepath.Join(dir, e.Name())
		}
	}
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	raw[recordHeader] ^= 0xff // corrupt the payload
	if err := os.WriteFile(seg, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, _, err := s2.Read(0, 10, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

func TestRotation(t *testing.T) {
	s := open(t, Config{Dir: t.TempDir(), SegmentBytes: 40})
	for i := 0; i < 10; i++ {
		if _, err := s.Append([]byte(`0123456789`)); err != nil {
			t.Fatal(err)
		}
	}
	recs, _, err := s.Read(0, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 10 {
		t.Fatalf("records = %d, want 10", len(recs))
	}
	segs, _ := s.segments()
	if len(segs) < 2 {
		t.Fatalf("expected rotation, got %d segment(s)", len(segs))
	}
}

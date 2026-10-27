package authn

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBoltStorePersistsRevocations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	ctx := context.Background()

	s, err := OpenBoltStore(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	if err := s.Revoke(ctx, "https://idp.test", "sid-1", "", exp); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "https://idp.test", "", "user-1", exp); err != nil {
		t.Fatal(err)
	}
	key, id := s.SessionKey(), s.StoreID()
	if len(key) != 32 || id == "" {
		t.Fatalf("session key/store id = %d/%q", len(key), id)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: revocations, key and store id must survive.
	s, err = OpenBoltStore(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !bytes.Equal(s.SessionKey(), key) || s.StoreID() != id {
		t.Error("session key or store id not persisted")
	}
	revoked, err := s.IsRevoked(ctx, "https://idp.test", "sid-1", "")
	if err != nil || !revoked {
		t.Errorf("sid revocation lost: %v, %v", revoked, err)
	}
	revoked, err = s.IsRevoked(ctx, "https://idp.test", "", "user-1")
	if err != nil || !revoked {
		t.Errorf("sub revocation lost: %v, %v", revoked, err)
	}
	revoked, err = s.IsRevoked(ctx, "https://idp.test", "sid-2", "user-2")
	if err != nil || revoked {
		t.Errorf("unexpected revocation: %v, %v", revoked, err)
	}
}

func TestBoltStoreExpiredRevocation(t *testing.T) {
	s, err := OpenBoltStore(
		filepath.Join(t.TempDir(), "state.db"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Revoke(
		ctx, "iss", "old", "", time.Now().Add(-time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	revoked, err := s.IsRevoked(ctx, "iss", "old", "")
	if err != nil || revoked {
		t.Errorf("expired revocation still active: %v, %v", revoked, err)
	}
}

func TestBoltStoreJTIReplay(t *testing.T) {
	s, err := OpenBoltStore(
		filepath.Join(t.TempDir(), "state.db"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	fresh, err := s.UseJTI(ctx, "iss", "jti-1", time.Now().Add(time.Minute))
	if err != nil || !fresh {
		t.Fatalf("first UseJTI = %v, %v", fresh, err)
	}
	fresh, err = s.UseJTI(ctx, "iss", "jti-1", time.Now().Add(time.Minute))
	if err != nil || fresh {
		t.Fatalf("replayed UseJTI = %v, %v", fresh, err)
	}

	// An expired jti can be reused (the replay window is over).
	if _, err := s.UseJTI(
		ctx, "iss", "jti-old", time.Now().Add(-time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	fresh, err = s.UseJTI(ctx, "iss", "jti-old", time.Now().Add(time.Minute))
	if err != nil || !fresh {
		t.Fatalf("expired jti not reusable: %v, %v", fresh, err)
	}
}

func TestBoltStoreRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(path, []byte("not a bbolt file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBoltStore(path, time.Hour); err == nil {
		t.Fatal("corrupt store accepted")
	}
}

func TestBoltStoreSingleWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	first, err := OpenBoltStore(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	if _, err := OpenBoltStore(path, time.Hour); err == nil {
		t.Fatal("second writer accepted the same bbolt file")
	}
}

func TestMemoryStoreRevokeAndJTI(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if err := s.Revoke(
		ctx, "iss", "sid", "sub", time.Now().Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.IsRevoked(ctx, "iss", "sid", ""); !ok {
		t.Error("sid not revoked")
	}
	if ok, _ := s.IsRevoked(ctx, "iss", "", "sub"); !ok {
		t.Error("sub not revoked")
	}
	if err := s.Revoke(ctx, "iss", "", "", time.Now()); err == nil {
		t.Error("empty revocation accepted")
	}
	if _, err := s.UseJTI(ctx, "iss", "", time.Now()); err == nil {
		t.Error("empty jti accepted")
	}
}

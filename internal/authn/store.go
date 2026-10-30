package authn

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// RevocationStore is the RP-side state behind back-channel logout and
// RP-initiated logout. The identity provider owns the SSO session and
// its revocation; this store is how the relying party enforces a
// revocation on ITS OWN cookie, which the IdP cannot delete.
//
// Entries are keyed by issuer + sid (one session) or issuer + sub (all
// sessions of a user), with an expiry: a revocation only has to live
// as long as the session/token it kills.
type RevocationStore interface {
	// Revoke records a revoked session (sid) and/or a global user
	// revocation (sub) until expires. A sub revocation applies only to
	// sessions/tokens issued before revokedAt (now).
	Revoke(ctx context.Context, issuer, sid, sub string, expires time.Time) error
	// RevokeSubject records a global logout timestamp for sub.
	RevokeSubject(
		ctx context.Context, issuer, sub string,
		revokedAt, expires time.Time,
	) error
	// IsRevoked reports whether the sid is revoked (sub is kept for
	// compatibility and treated as an all-sessions revocation).
	IsRevoked(ctx context.Context, issuer, sid, sub string) (bool, error)
	// CheckRevoked reports whether the session (sid) or the user (sub,
	// for tokens issued at or before issuedAt) is revoked. It is on the
	// per-request hot path: stores that can answer both questions in a
	// single round trip SHOULD implement it that way.
	CheckRevoked(
		ctx context.Context, issuer, sid, sub string,
		issuedAt time.Time,
	) (bool, error)
	// IsSubjectRevoked reports whether sub was globally revoked after
	// issuedAt. issuedAt zero is fail-closed.
	IsSubjectRevoked(
		ctx context.Context, issuer, sub string, issuedAt time.Time,
	) (bool, error)
	// UseJTI atomically marks a logout-token jti as used. It returns
	// false when the jti was already seen (replay).
	UseJTI(ctx context.Context, issuer, jti string, expires time.Time) (bool, error)
	Close() error
}

// SessionKeyStore is implemented by stores that can persist the cookie
// signing key and a store identity (invalidating old cookies if the
// backing file is lost and recreated).
type SessionKeyStore interface {
	SessionKey() []byte
	StoreID() string
}

const (
	revocationTTLDefault  = 24 * time.Hour
	revocationGCInterval  = 5 * time.Minute
	storeBucketMeta       = "meta"
	storeBucketRevoked    = "revoked"
	storeBucketSubRevoked = "subrevoked"
	storeBucketJTI        = "jti"
	storeKeySession       = "session_key"
	storeKeyID            = "store_id"
)

func revKey(kind, issuer, value string) string {
	// \x00 cannot appear in an issuer URL or a JWT sid/sub/jti, so the
	// key is unambiguous.
	return kind + "\x00" + issuer + "\x00" + value
}

func encodeExpiry(t time.Time) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(t.Unix()))
	return b
}

func decodeExpiry(b []byte) int64 {
	if len(b) != 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b))
}

func encodeSub(revokedAt, expires time.Time) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[:8], uint64(revokedAt.Unix()))
	binary.BigEndian.PutUint64(b[8:], uint64(expires.Unix()))
	return b
}

func decodeSub(b []byte) (revokedAt, expires int64, ok bool) {
	if len(b) != 16 {
		return 0, 0, false
	}
	return int64(binary.BigEndian.Uint64(b[:8])),
		int64(binary.BigEndian.Uint64(b[8:])), true
}

// revokeLegacySubKeys migrates old bbolt entries where a subject
// revocation was stored in the sid bucket without a revokedAt.
func revokeLegacySubKeys(
	revoked, sub *bolt.Bucket, now int64,
) error {
	var legacy [][]byte
	if err := revoked.ForEach(func(k, v []byte) error {
		if strings.HasPrefix(string(k), "sub\x00") {
			legacy = append(legacy, append([]byte(nil), k...))
		}
		return nil
	}); err != nil {
		return err
	}
	for _, k := range legacy {
		exp := decodeExpiry(revoked.Get(k))
		if err := sub.Put(k, encodeSub(
			time.Unix(now, 0), time.Unix(exp, 0))); err != nil {
			return err
		}
		if err := revoked.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// BoltStore is the default, single-instance revocation store: bbolt on
// disk for durability, an in-memory map for the hot read path. bbolt
// locks the file: a second Gate One process cannot open the same file
// (by design — use Redis for HA).
type BoltStore struct {
	db   *bolt.DB
	path string
	ttl  time.Duration

	mu         sync.RWMutex
	revoked    map[string]int64 // sid key -> unix expiry
	subRevoked map[string]subRevocation

	key     []byte
	storeID string

	stop chan struct{}
	done chan struct{}
	jti  sync.Mutex
}

// OpenBoltStore opens (or creates) the state file. A corrupt or
// unreadable file is a startup error: never start with an empty
// revocation list (fail-closed).
func OpenBoltStore(path string, ttl time.Duration) (*BoltStore, error) {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return nil, fmt.Errorf("sessionStore.path is required")
	}
	if dir := filepath.Dir(path); dir != "." && dir != "/" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("sessionStore: create %s: %w", dir, err)
		}
	}
	if ttl <= 0 {
		ttl = revocationTTLDefault
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf(
			"sessionStore: open %s: %w (another Gate One instance may "+
				"hold the file; use redis for HA)", path, err)
	}
	_ = os.Chmod(path, 0o600)

	s := &BoltStore{
		db:         db,
		path:       path,
		ttl:        ttl,
		revoked:    map[string]int64{},
		subRevoked: map[string]subRevocation{},
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}

	now := time.Now().Unix()
	err = db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists([]byte(storeBucketMeta))
		if err != nil {
			return err
		}
		revoked, err := tx.CreateBucketIfNotExists([]byte(storeBucketRevoked))
		if err != nil {
			return err
		}
		subRevoked, err := tx.CreateBucketIfNotExists([]byte(storeBucketSubRevoked))
		if err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(storeBucketJTI)); err != nil {
			return err
		}

		s.key = append([]byte(nil), meta.Get([]byte(storeKeySession))...)
		if len(s.key) == 0 {
			s.key = make([]byte, 32)
			if _, err := rand.Read(s.key); err != nil {
				return err
			}
			if err := meta.Put([]byte(storeKeySession), s.key); err != nil {
				return err
			}
		}
		s.storeID = string(meta.Get([]byte(storeKeyID)))
		if s.storeID == "" {
			buf := make([]byte, 16)
			if _, err := rand.Read(buf); err != nil {
				return err
			}
			s.storeID = hex.EncodeToString(buf)
			if err := meta.Put([]byte(storeKeyID), []byte(s.storeID)); err != nil {
				return err
			}
		}

		if err := revokeLegacySubKeys(revoked, subRevoked, now); err != nil {
			return err
		}
		if err := revoked.ForEach(func(k, v []byte) error {
			exp := decodeExpiry(v)
			if exp > now {
				s.revoked[string(k)] = exp
			} else if err := revoked.Delete(k); err != nil {
				return err
			}
			return nil
		}); err != nil {
			return err
		}
		return subRevoked.ForEach(func(k, v []byte) error {
			revokedAt, exp, ok := decodeSub(v)
			if !ok || exp <= now {
				return subRevoked.Delete(k)
			}
			s.subRevoked[string(k)] = subRevocation{
				revokedAt: revokedAt, expires: exp,
			}
			return nil
		})
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sessionStore: init %s: %w", path, err)
	}

	go s.gcLoop()
	return s, nil
}

func (s *BoltStore) Close() error {
	select {
	case <-s.stop:
	default:
		close(s.stop)
		<-s.done
	}
	return s.db.Close()
}

func (s *BoltStore) SessionKey() []byte {
	return append([]byte(nil), s.key...)
}

func (s *BoltStore) StoreID() string { return s.storeID }

func (s *BoltStore) Revoke(
	_ context.Context,
	issuer, sid, sub string,
	expires time.Time,
) error {
	if sid == "" && sub == "" {
		return errors.New("sessionStore: empty sid and sub")
	}
	if expires.IsZero() {
		expires = time.Now().Add(s.ttl)
	}
	if sid != "" {
		if err := s.revokeSID(issuer, sid, expires); err != nil {
			return err
		}
	}
	if sub != "" {
		if err := s.RevokeSubject(
			context.Background(), issuer, sub, time.Now(), expires,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *BoltStore) revokeSID(issuer, sid string, expires time.Time) error {
	key := revKey("sid", issuer, sid)
	s.mu.Lock()
	s.revoked[key] = expires.Unix()
	s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(storeBucketRevoked))
		if b == nil {
			return errors.New("sessionStore: revoked bucket missing")
		}
		return b.Put([]byte(key), encodeExpiry(expires))
	})
}

func (s *BoltStore) RevokeSubject(
	_ context.Context, issuer, sub string,
	revokedAt, expires time.Time,
) error {
	if sub == "" {
		return errors.New("sessionStore: empty sub")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now()
	}
	if expires.IsZero() {
		expires = revokedAt.Add(s.ttl)
	}
	key := revKey("sub", issuer, sub)
	s.mu.Lock()
	s.subRevoked[key] = subRevocation{
		revokedAt: revokedAt.Unix(), expires: expires.Unix(),
	}
	s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(storeBucketSubRevoked))
		if b == nil {
			return errors.New("sessionStore: subrevoked bucket missing")
		}
		return b.Put([]byte(key), encodeSub(revokedAt, expires))
	})
}

func (s *BoltStore) IsRevoked(
	_ context.Context,
	issuer, sid, sub string,
) (bool, error) {
	now := time.Now().Unix()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sid != "" {
		if exp, ok := s.revoked[revKey("sid", issuer, sid)]; ok && exp > now {
			return true, nil
		}
	}
	if sub != "" {
		return s.isSubjectRevokedLocked(issuer, sub, time.Time{})
	}
	return false, nil
}

func (s *BoltStore) IsSubjectRevoked(
	_ context.Context, issuer, sub string, issuedAt time.Time,
) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isSubjectRevokedLocked(issuer, sub, issuedAt)
}

// CheckRevoked answers the sid and sub questions under one lock.
func (s *BoltStore) CheckRevoked(
	_ context.Context, issuer, sid, sub string, issuedAt time.Time,
) (bool, error) {
	now := time.Now().Unix()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sid != "" {
		if exp, ok := s.revoked[revKey("sid", issuer, sid)]; ok && exp > now {
			return true, nil
		}
	}
	if sub == "" {
		return false, nil
	}
	return s.isSubjectRevokedLocked(issuer, sub, issuedAt)
}

func (s *BoltStore) isSubjectRevokedLocked(
	issuer, sub string, issuedAt time.Time,
) (bool, error) {
	now := time.Now().Unix()
	e, ok := s.subRevoked[revKey("sub", issuer, sub)]
	if !ok || e.expires <= now {
		return false, nil
	}
	if issuedAt.IsZero() {
		return true, nil
	}
	return issuedAt.Unix() <= e.revokedAt, nil
}

func (s *BoltStore) UseJTI(
	_ context.Context,
	issuer, jti string,
	expires time.Time,
) (bool, error) {
	if jti == "" {
		return false, errors.New("sessionStore: empty jti")
	}
	s.jti.Lock()
	defer s.jti.Unlock()

	key := revKey("jti", issuer, jti)
	now := time.Now().Unix()
	used := false

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(storeBucketJTI))
		if v := b.Get([]byte(key)); v != nil {
			if decodeExpiry(v) > now {
				used = true
				return nil
			}
		}
		return b.Put([]byte(key), encodeExpiry(expires))
	})
	if err != nil {
		return false, err
	}
	return !used, nil
}

func (s *BoltStore) gcLoop() {
	t := time.NewTicker(revocationGCInterval)
	defer func() {
		t.Stop()
		close(s.done)
	}()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.gc()
		}
	}
}

func (s *BoltStore) gc() {
	now := time.Now().Unix()

	s.mu.Lock()
	expired := make([]string, 0)
	for k, exp := range s.revoked {
		if exp <= now {
			delete(s.revoked, k)
			expired = append(expired, k)
		}
	}
	expiredSub := make([]string, 0)
	for k, e := range s.subRevoked {
		if e.expires <= now {
			delete(s.subRevoked, k)
			expiredSub = append(expiredSub, k)
		}
	}
	s.mu.Unlock()

	_ = s.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket([]byte(storeBucketRevoked)); b != nil {
			for _, k := range expired {
				_ = b.Delete([]byte(k))
			}
		}
		if b := tx.Bucket([]byte(storeBucketSubRevoked)); b != nil {
			for _, k := range expiredSub {
				_ = b.Delete([]byte(k))
			}
		}
		if b := tx.Bucket([]byte(storeBucketJTI)); b != nil {
			var stale [][]byte
			_ = b.ForEach(func(k, v []byte) error {
				if decodeExpiry(v) <= now {
					stale = append(stale, append([]byte(nil), k...))
				}
				return nil
			})
			for _, k := range stale {
				_ = b.Delete(k)
			}
		}
		return nil
	})
}

// MemoryStore is the in-process implementation used by tests and by
// the dev provider. It is not exposed in the configuration: production
// single-instance uses bbolt, HA uses redis.
type subRevocation struct {
	revokedAt int64
	expires   int64
}

type MemoryStore struct {
	mu         sync.RWMutex
	revoked    map[string]int64
	subRevoked map[string]subRevocation
	jti        map[string]int64
	key        []byte
	storeID    string
}

func NewMemoryStore() *MemoryStore {
	key := make([]byte, 32)
	id := make([]byte, 16)
	_, _ = rand.Read(key)
	_, _ = rand.Read(id)
	return &MemoryStore{
		revoked:    map[string]int64{},
		subRevoked: map[string]subRevocation{},
		jti:        map[string]int64{},
		key:        key,
		storeID:    hex.EncodeToString(id),
	}
}

func (s *MemoryStore) SessionKey() []byte {
	return append([]byte(nil), s.key...)
}
func (s *MemoryStore) StoreID() string { return s.storeID }
func (s *MemoryStore) Close() error    { return nil }

func (s *MemoryStore) Revoke(
	_ context.Context,
	issuer, sid, sub string,
	expires time.Time,
) error {
	if sid == "" && sub == "" {
		return errors.New("sessionStore: empty sid and sub")
	}
	if expires.IsZero() {
		expires = time.Now().Add(revocationTTLDefault)
	}
	exp := expires.Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	if sid != "" {
		s.revoked[revKey("sid", issuer, sid)] = exp
	}
	if sub != "" {
		s.subRevoked[revKey("sub", issuer, sub)] = subRevocation{
			revokedAt: time.Now().Unix(), expires: exp,
		}
	}
	return nil
}

func (s *MemoryStore) RevokeSubject(
	_ context.Context, issuer, sub string,
	revokedAt, expires time.Time,
) error {
	if sub == "" {
		return errors.New("sessionStore: empty sub")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now()
	}
	if expires.IsZero() {
		expires = revokedAt.Add(revocationTTLDefault)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subRevoked[revKey("sub", issuer, sub)] = subRevocation{
		revokedAt: revokedAt.Unix(), expires: expires.Unix(),
	}
	return nil
}

func (s *MemoryStore) IsRevoked(
	_ context.Context,
	issuer, sid, sub string,
) (bool, error) {
	now := time.Now().Unix()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sid != "" {
		if exp, ok := s.revoked[revKey("sid", issuer, sid)]; ok && exp > now {
			return true, nil
		}
	}
	if sub != "" {
		rev, err := s.IsSubjectRevoked(
			context.Background(), issuer, sub, time.Time{})
		if err != nil || rev {
			return rev, err
		}
	}
	return false, nil
}

func (s *MemoryStore) IsSubjectRevoked(
	_ context.Context, issuer, sub string, issuedAt time.Time,
) (bool, error) {
	if sub == "" {
		return false, nil
	}
	now := time.Now().Unix()
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.subRevoked[revKey("sub", issuer, sub)]
	if !ok || e.expires <= now {
		return false, nil
	}
	if issuedAt.IsZero() {
		return true, nil // fail-closed for legacy/unknown issue time
	}
	return issuedAt.Unix() <= e.revokedAt, nil
}

// CheckRevoked answers the sid and sub questions under one lock.
func (s *MemoryStore) CheckRevoked(
	_ context.Context, issuer, sid, sub string, issuedAt time.Time,
) (bool, error) {
	now := time.Now().Unix()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sid != "" {
		if exp, ok := s.revoked[revKey("sid", issuer, sid)]; ok && exp > now {
			return true, nil
		}
	}
	if sub == "" {
		return false, nil
	}
	e, ok := s.subRevoked[revKey("sub", issuer, sub)]
	if !ok || e.expires <= now {
		return false, nil
	}
	if issuedAt.IsZero() {
		return true, nil
	}
	return issuedAt.Unix() <= e.revokedAt, nil
}

func (s *MemoryStore) UseJTI(
	_ context.Context,
	issuer, jti string,
	expires time.Time,
) (bool, error) {
	if jti == "" {
		return false, errors.New("sessionStore: empty jti")
	}
	key := revKey("jti", issuer, jti)
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, ok := s.jti[key]; ok && exp > now {
		return false, nil
	}
	s.jti[key] = expires.Unix()
	return true, nil
}

// boltStores shares one open bbolt file across SIGHUP reloads: the old
// gateway may still serve in-flight requests while the new one starts,
// and bbolt forbids a second open of the same file. The store lives for
// the process lifetime.
var (
	boltStoresMu sync.Mutex
	boltStores   sync.Map // absolute path -> *BoltStore
)

func OpenBoltShared(path string, ttl time.Duration) (*BoltStore, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	boltStoresMu.Lock()
	defer boltStoresMu.Unlock()
	if v, ok := boltStores.Load(abs); ok {
		return v.(*BoltStore), nil
	}
	st, err := OpenBoltStore(abs, ttl)
	if err != nil {
		return nil, err
	}
	boltStores.Store(abs, st)
	return st, nil
}

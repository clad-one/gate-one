package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// remoteKeySet is a small JWKS cache with an explicit error taxonomy:
// a fetch/network failure marks the request status unavailable (502),
// while a bad signature/unknown key after a successful fetch is a
// token failure (401). go-oidc's built-in RemoteKeySet does not expose
// that distinction.
type remoteKeySet struct {
	url    string
	client *http.Client
	algs   []jose.SignatureAlgorithm
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	keys    map[string]jose.JSONWebKey
	fetched time.Time
}

var errKeySetUnavailable = errors.New("jwks: unavailable")

type keyStatusKey struct{}

type keySetStatus struct {
	unavailable bool
}

func statusFrom(ctx context.Context) *keySetStatus {
	st, _ := ctx.Value(keyStatusKey{}).(*keySetStatus)
	return st
}

func withKeyStatus(ctx context.Context) (context.Context, *keySetStatus) {
	st := &keySetStatus{}
	return context.WithValue(ctx, keyStatusKey{}, st), st
}

func newRemoteKeySet(
	jwksURL string, client *http.Client,
	algs []string, ttl time.Duration, now func() time.Time,
) *remoteKeySet {
	if now == nil {
		now = time.Now
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	salgs := make([]jose.SignatureAlgorithm, 0, len(algs))
	for _, a := range algs {
		salgs = append(salgs, jose.SignatureAlgorithm(a))
	}
	if len(salgs) == 0 {
		salgs = []jose.SignatureAlgorithm{jose.EdDSA}
	}
	return &remoteKeySet{
		url:    jwksURL,
		client: client,
		algs:   salgs,
		ttl:    ttl,
		now:    now,
		keys:   map[string]jose.JSONWebKey{},
	}
}

func (k *remoteKeySet) VerifySignature(
	ctx context.Context, raw string,
) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, k.algs)
	if err != nil {
		// Malformed token/signature: not a provider outage.
		return nil, fmt.Errorf("jwks: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("jwks: %d signatures (expected 1)",
			len(jws.Signatures))
	}
	kid := jws.Signatures[0].Header.KeyID

	key, err := k.key(ctx, kid)
	if err != nil {
		if errors.Is(err, errKeySetUnavailable) {
			if st := statusFrom(ctx); st != nil {
				st.unavailable = true
			}
		}
		return nil, err
	}
	payload, err := jws.Verify(key.Key)
	if err != nil {
		return nil, fmt.Errorf("jwks: signature: %w", err)
	}
	return payload, nil
}

func (k *remoteKeySet) key(
	ctx context.Context, kid string,
) (jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.fresh() {
		if key, ok := k.lookupLocked(kid); ok {
			return key, nil
		}
	}
	// Unknown kid or stale cache: one refresh. A failure here is an
	// upstream outage, not an invalid token.
	if err := k.refreshLocked(ctx); err != nil {
		return jose.JSONWebKey{}, err
	}
	if key, ok := k.lookupLocked(kid); ok {
		return key, nil
	}
	return jose.JSONWebKey{}, fmt.Errorf("jwks: unknown kid %q", kid)
}

func (k *remoteKeySet) fresh() bool {
	return len(k.keys) > 0 && k.now().Before(k.fetched.Add(k.ttl))
}

func (k *remoteKeySet) lookupLocked(kid string) (jose.JSONWebKey, bool) {
	if key, ok := k.keys[kid]; ok {
		return key, true
	}
	// A single-key JWKS may omit kid (common for small IdPs). JWT
	// provider callers additionally require kid at the token level.
	if kid == "" && len(k.keys) == 1 {
		for _, key := range k.keys {
			return key, true
		}
	}
	return jose.JSONWebKey{}, false
}

func (k *remoteKeySet) refreshLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", errKeySetUnavailable, err)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", errKeySetUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", errKeySetUnavailable, resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(
		resp.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("%w: %v", errKeySetUnavailable, err)
	}
	if len(set.Keys) == 0 {
		return fmt.Errorf("%w: empty key set", errKeySetUnavailable)
	}
	keys := make(map[string]jose.JSONWebKey, len(set.Keys))
	for _, key := range set.Keys {
		if key.KeyID == "" {
			continue
		}
		keys[key.KeyID] = key
	}
	if len(keys) == 0 {
		// A key set without any kid is usable only if it has exactly
		// one key; index it under the empty id for lookup.
		if len(set.Keys) == 1 {
			keys[""] = set.Keys[0]
		} else {
			return fmt.Errorf("%w: no key id", errKeySetUnavailable)
		}
	}
	k.keys = keys
	k.fetched = k.now()
	return nil
}

// refresh forces a JWKS fetch (Health).
func (k *remoteKeySet) refresh(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.refreshLocked(ctx)
}

// oidcKeySet adapts remoteKeySet to the go-oidc KeySet interface (it
// already implements it; this assertion keeps the intent explicit).
var _ oidc.KeySet = (*remoteKeySet)(nil)

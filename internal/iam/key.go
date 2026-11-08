package iam

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// signingKey is one tenant Ed25519 key.
type signingKey struct {
	kid  string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func loadSigningKey(tenantID, path string) (*signingKey, error) {
	var priv ed25519.PrivateKey
	if strings.TrimSpace(path) != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("tenant %s: keyFile: %w", tenantID, err)
		}
		body := strings.TrimSpace(string(raw))
		b, err := base64.RawURLEncoding.DecodeString(body)
		if err != nil {
			b, err = base64.StdEncoding.DecodeString(body)
		}
		if err != nil {
			return nil, fmt.Errorf("tenant %s: keyFile: invalid base64: %w", tenantID, err)
		}
		switch len(b) {
		case ed25519.SeedSize:
			priv = ed25519.NewKeyFromSeed(b)
		case ed25519.PrivateKeySize:
			priv = ed25519.PrivateKey(append([]byte(nil), b...))
		default:
			return nil, fmt.Errorf(
				"tenant %s: keyFile: %d bytes (expected 32-byte seed or 64-byte key)",
				tenantID, len(b))
		}
	} else {
		_, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		priv = p
	}
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	kid := tenantID + "-" + hex.EncodeToString(sum[:4])
	return &signingKey{kid: kid, priv: priv, pub: pub}, nil
}

func (k *signingKey) jwks() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       k.pub,
		KeyID:     k.kid,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}}}
}

func (k *signingKey) sign(claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: k.priv},
		(&jose.SignerOptions{}).WithHeader("kid", k.kid),
	)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// keyIDForTest exposes the deterministic kid in tests.
func (k *signingKey) keyID() string { return k.kid }

// newEphemeralKey is used by tests that do not want a key file.
func newEphemeralKey(tenantID string) (*signingKey, error) {
	return loadSigningKey(tenantID, "")
}

// mergeJWKS publishes every active key during a rotation overlap.
func mergeJWKS(keys []*signingKey) jose.JSONWebKeySet {
	var set jose.JSONWebKeySet
	for _, k := range keys {
		if k == nil {
			continue
		}
		set.Keys = append(set.Keys, k.jwks().Keys...)
	}
	return set
}

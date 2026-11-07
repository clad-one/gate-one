package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cladone/gate-one/pkg/signing"
)

// keyFile is the on-disk key material produced by `gate-one keygen`.
type keyFile struct {
	KeyID     string `json:"keyId"`
	Seed      string `json:"seed"`      // base64 raw URL, Ed25519 seed (32 bytes)
	PublicKey string `json:"publicKey"` // base64 raw URL, Ed25519 public key
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func runKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "output key file (JSON: keyId, seed, publicKey)")
	keyID := fs.String("keyId", "", "signing key id (default: output file basename)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "keygen: -out is required")
		return 2
	}
	id := strings.TrimSpace(*keyID)
	if id == "" {
		id = strings.TrimSuffix(filepath.Base(*out), filepath.Ext(*out))
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		return 1
	}
	body, err := json.MarshalIndent(keyFile{
		KeyID:     id,
		Seed:      b64(priv.Seed()),
		PublicKey: b64(pub),
	}, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		return 1
	}
	body = append(body, '\n')
	if dir := filepath.Dir(*out); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, "keygen:", err)
			return 1
		}
	}
	if err := os.WriteFile(*out, body, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		return 1
	}
	fmt.Printf("private key: %s\n", *out)
	fmt.Printf("keyId:       %s\n", id)
	fmt.Printf("public key:  %s\n", b64(pub))
	fmt.Println("add the public key to the trust store under this keyId")
	return 0
}

func loadKeyFile(path string) (keyFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return keyFile{}, err
	}
	var k keyFile
	if err := json.Unmarshal(raw, &k); err != nil {
		return keyFile{}, err
	}
	return k, nil
}

func seedOf(k keyFile) (ed25519.PrivateKey, error) {
	seed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(k.Seed))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("key: invalid seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func pubOf(k keyFile) (ed25519.PublicKey, error) {
	if s := strings.TrimSpace(k.PublicKey); s != "" {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key: invalid public key")
		}
		return ed25519.PublicKey(b), nil
	}
	priv, err := seedOf(k)
	if err != nil {
		return nil, err
	}
	return priv.Public().(ed25519.PublicKey), nil
}

// readDoc parses a JSON document preserving number literals.
func readDoc(path string) (map[string]any, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, err
	}
	return doc, raw, nil
}

func writeDoc(path string, doc map[string]any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(buf.Bytes())
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// artifactDigest reads the artefact and returns sha256:<hex> + size.
func artifactDigest(path string) (string, int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), len(raw), nil
}

func docBinding(doc map[string]any) string {
	art, ok := doc["artifact"].(map[string]any)
	if !ok {
		return ""
	}
	d, _ := art["digest"].(string)
	return d
}

func runSign(args []string) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	in := fs.String("in", "", "document to sign (manifest or feed JSON)")
	keyPath := fs.String("key", "", "private key file from `gate-one keygen`")
	artifact := fs.String("artifact", "", "artefact whose digest is bound into the signature")
	out := fs.String("out", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "sign: -in and -key are required")
		return 2
	}
	k, err := loadKeyFile(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		return 1
	}
	priv, err := seedOf(k)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		return 1
	}
	doc, _, err := readDoc(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		return 1
	}
	binding := ""
	if *artifact != "" {
		digest, size, err := artifactDigest(*artifact)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sign:", err)
			return 1
		}
		art, _ := doc["artifact"].(map[string]any)
		if art == nil {
			art = map[string]any{}
			doc["artifact"] = art
		}
		art["digest"] = digest
		art["size"] = size
		binding = digest
		fmt.Fprintf(os.Stderr, "artifact: %s (%d bytes)\n", digest, size)
	} else {
		binding = docBinding(doc)
	}
	doc["signature"] = map[string]any{
		"alg":   "ed25519",
		"keyId": k.KeyID,
		"value": "",
	}
	body, err := json.Marshal(doc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		return 1
	}
	payload, err := signing.Payload(body, binding)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		return 1
	}
	sig := ed25519.Sign(priv, payload)
	doc["signature"].(map[string]any)["value"] = b64(sig)
	if err := writeDoc(*out, doc); err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		return 1
	}
	return 0
}

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	in := fs.String("in", "", "signed document")
	keyPath := fs.String("key", "", "key file (public key or seed)")
	pubB64 := fs.String("pubkey", "", "base64 raw URL Ed25519 public key")
	artifact := fs.String("artifact", "", "artefact to check against the bound digest")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" {
		fmt.Fprintln(os.Stderr, "verify: -in is required")
		return 2
	}
	var pub ed25519.PublicKey
	switch {
	case *pubB64 != "":
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(*pubB64))
		if err != nil || len(b) != ed25519.PublicKeySize {
			fmt.Fprintln(os.Stderr, "verify: invalid -pubkey")
			return 2
		}
		pub = ed25519.PublicKey(b)
	case *keyPath != "":
		k, err := loadKeyFile(*keyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			return 1
		}
		pub, err = pubOf(k)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			return 1
		}
	default:
		fmt.Fprintln(os.Stderr, "verify: -key or -pubkey is required")
		return 2
	}
	doc, _, err := readDoc(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		return 1
	}
	sigObj, _ := doc["signature"].(map[string]any)
	value, _ := sigObj["value"].(string)
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(sig) != ed25519.SignatureSize {
		fmt.Fprintln(os.Stderr, "verify: missing or malformed signature")
		return 1
	}
	binding := docBinding(doc)
	if *artifact != "" {
		digest, _, err := artifactDigest(*artifact)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			return 1
		}
		if digest != binding {
			fmt.Fprintf(os.Stderr,
				"verify: artifact digest %s != manifest digest %s\n",
				digest, binding)
			return 1
		}
		binding = digest
	}
	body, err := json.Marshal(doc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		return 1
	}
	payload, err := signing.Payload(body, binding)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		return 1
	}
	if !ed25519.Verify(pub, payload, sig) {
		fmt.Fprintln(os.Stderr, "verify: signature INVALID")
		return 1
	}
	fmt.Println("verify: signature OK")
	return 0
}

// Package httpbinding exposes an IdentityAdapter over HTTP/JSON. It is
// the portable binding for adapters written in another language; the
// same contract can later be exposed over gRPC.
package httpbinding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"cladone/gate-one/pkg/identityadapter"
)

// Server returns an http.Handler exposing the adapter.
func Server(a identityadapter.Adapter) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.Manifest())
	})
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		var req identityadapter.Request
		if err := decode(r, &req); err != nil {
			writeErr(w, identityadapter.ErrInvalidRequest)
			return
		}
		step, err := a.Start(r.Context(), req)
		respondStep(w, step, err)
	})
	mux.HandleFunc("/continue", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Request identityadapter.Request `json:"request"`
			State   []byte                  `json:"state"`
		}
		if err := decode(r, &body); err != nil {
			writeErr(w, identityadapter.ErrInvalidRequest)
			return
		}
		step, err := a.Continue(r.Context(), body.Request, body.State)
		respondStep(w, step, err)
	})
	mux.HandleFunc("/enrich", func(w http.ResponseWriter, r *http.Request) {
		var a1 identityadapter.Assertion
		if err := decode(r, &a1); err != nil {
			writeErr(w, identityadapter.ErrInvalidRequest)
			return
		}
		out, err := a.Enrich(r.Context(), a1)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Health(r.Context()); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

func respondStep(
	w http.ResponseWriter, step identityadapter.Step, err error,
) {
	if err != nil {
		writeErr(w, err)
		return
	}
	if step.Kind == "" {
		writeErr(w, identityadapter.ErrInvalidRequest)
		return
	}
	writeJSON(w, http.StatusOK, step)
}

func decode(r *http.Request, v any) error {
	if r.Method != http.MethodPost {
		return fmt.Errorf("POST required")
	}
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	code := "invalid_request"
	switch {
	case errors.Is(err, identityadapter.ErrUnauthenticated):
		status, code = http.StatusUnauthorized, "unauthenticated"
	case errors.Is(err, identityadapter.ErrInvalidRequest):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, identityadapter.ErrProviderUnavailable):
		status, code = http.StatusBadGateway, "provider_unavailable"
	}
	writeJSON(w, status, map[string]string{
		"error": code, "error_description": err.Error(),
	})
}

// Client implements IdentityAdapter against a remote HTTP binding.
type Client struct {
	base   string
	client *http.Client
	m      identityadapter.Manifest
}

// NewClient fetches the manifest and returns the remote adapter.
func NewClient(baseURL string, hc *http.Client) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("httpbinding: empty base URL")
	}
	if hc == nil {
		hc = &http.Client{}
	}
	c := &Client{base: base, client: hc}
	resp, err := hc.Get(base + "/manifest")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpbinding: manifest HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&c.m); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) Manifest() identityadapter.Manifest { return c.m }

func (c *Client) Start(
	ctx context.Context, req identityadapter.Request,
) (identityadapter.Step, error) {
	var step identityadapter.Step
	if err := c.post(ctx, "/start", req, &step); err != nil {
		return identityadapter.Step{}, err
	}
	return step, nil
}

func (c *Client) Continue(
	ctx context.Context, req identityadapter.Request, state []byte,
) (identityadapter.Step, error) {
	var step identityadapter.Step
	body := map[string]any{"request": req, "state": state}
	if err := c.post(ctx, "/continue", body, &step); err != nil {
		return identityadapter.Step{}, err
	}
	return step, nil
}

func (c *Client) Enrich(
	ctx context.Context, a identityadapter.Assertion,
) (identityadapter.Assertion, error) {
	var out identityadapter.Assertion
	if err := c.post(ctx, "/enrich", a, &out); err != nil {
		return identityadapter.Assertion{}, err
	}
	return out, nil
}

func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, c.base+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", identityadapter.ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", identityadapter.ErrProviderUnavailable, resp.StatusCode)
	}
	return nil
}

func (c *Client) post(
	ctx context.Context, path string, in, out any,
) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", identityadapter.ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&e)
		switch e.Error {
		case "unauthenticated":
			return identityadapter.ErrUnauthenticated
		case "invalid_request":
			return identityadapter.ErrInvalidRequest
		case "provider_unavailable":
			return identityadapter.ErrProviderUnavailable
		default:
			return fmt.Errorf("httpbinding: HTTP %d", resp.StatusCode)
		}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

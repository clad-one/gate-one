package pwa

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// injection sniffs successful HTML responses and injects the PWA
// wiring (manifest link + service worker registration) into <head>.
const injection = `<link rel="manifest" href="/__gateway_pwa/manifest.json">` +
	`<script>navigator.serviceWorker.register('/__gateway_pwa/sw.js',{scope:'/'})</script>`

// InjectResponse modifies an upstream HTML response in place, adding
// the PWA tags. Non-HTML or non-200 responses pass through untouched.
func InjectResponse(resp *http.Response) error {

	ct := resp.Header.Get("Content-Type")
	if resp.StatusCode != http.StatusOK ||
		!strings.Contains(ct, "text/html") {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	head := indexFold(body, "<head")
	var updated []byte

	if head >= 0 {
		// Insert right after the "<head ...>" opening tag.
		gt := bytes.IndexByte(body[head:], '>')
		if gt < 0 {
			updated = body
		} else {
			pos := head + gt + 1
			updated = splice(body, pos, []byte(injection))
		}
	} else if h := indexFold(body, "<html"); h >= 0 {
		// Degraded fallback: inject right after <html ...>.
		gt := bytes.IndexByte(body[h:], '>')
		if gt < 0 {
			updated = body
		} else {
			updated = splice(body, h+gt+1, []byte(injection))
		}
	} else {
		// Not recognisable HTML: leave untouched rather than corrupt.
		log.Printf("PWA INJECT: no <head> found, skipping")
		updated = body
	}

	resp.Body = io.NopCloser(bytes.NewReader(updated))
	resp.ContentLength = int64(len(updated))
	resp.Header.Set("Content-Length", strconv.Itoa(len(updated)))

	return nil
}

// indexFold is a case-insensitive bytes.Index.
func indexFold(b []byte, sub string) int {
	return bytes.Index(
		bytes.ToLower(b),
		[]byte(strings.ToLower(sub)),
	)
}

// splice inserts ins into b at pos.
func splice(b []byte, pos int, ins []byte) []byte {
	out := make([]byte, 0, len(b)+len(ins))
	out = append(out, b[:pos]...)
	out = append(out, ins...)
	out = append(out, b[pos:]...)
	return out
}

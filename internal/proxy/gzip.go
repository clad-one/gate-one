package proxy

import (
	"compress/gzip"
	"io"
	"net/http"
)

// decodeGzipBody installs STREAMING DECOMPRESSION of a gzip body
// (Content-Encoding: gzip). The injectors (401/403 guard, future
// tags) operate on PLAIN HTML: a compressed body manipulated then
// served with its Content-Encoding removed produces an unreadable
// page in the browser (2026-10-17 incident: Cloudflare answered
// brotli to the browser, the injector prefixed the compressed
// bytes).
//
// Like the guard injection (2026-10-18), decompression is streaming:
// the lazy gzip.Reader flows the body through as it arrives — NEVER
// a whole resident body (the book's 6 MB page recently crossed
// memory: two simultaneous copies, compressed + decompressed).
// Content-Encoding and Content-Length are removed — the body changes
// size, ReverseProxy re-chunks and flushes every write
// (ContentLength -1).
func decodeGzipBody(resp *http.Response) error {

	src := resp.Body
	zr, err := gzip.NewReader(src)
	if err != nil {
		// no gzip (empty body, broken header): 502 by
		// ModifyResponse — nothing has been written to the client
		// yet.
		resp.Body.Close()
		return err
	}

	resp.Body = &gunzipStream{zr: zr, src: src}
	resp.ContentLength = -1
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")

	return nil
}

// gunzipStream: lazy gzip.Reader + origin close.
// gz.Reader reads all members of a multi-member stream (same calls
// as the old ReadAll — identical behavior); mid-stream corruption
// surfaces during the copy (truncation as seen by the client,
// streaming version of the same scenario) instead of a pre-content
// 502: the standard trade-off of any streamed response.
type gunzipStream struct {
	zr  *gzip.Reader
	src io.ReadCloser
}

func (g *gunzipStream) Read(p []byte) (int, error) {
	return g.zr.Read(p)
}

func (g *gunzipStream) Close() error {
	gzErr := g.zr.Close()
	srcErr := g.src.Close()
	if gzErr != nil {
		return gzErr
	}
	return srcErr
}

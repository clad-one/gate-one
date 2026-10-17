package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
)

// decodeGzipBody décompresse sur place le corps gzip d'une réponse
// (Content-Encoding: gzip). Les injecteurs (garde 401/403, PWA,
// futures balises) opèrent sur du HTML EN CLAIR : un corps compressé
// manipulé puis servi avec son Content-Encoding supprimé produit une
// page illisible dans le navigateur (incident 2026-10-17 :
// Cloudflare répondait brotli au navigateur, l'injecteur préfixait
// les octets comprimés). Content-Encoding et Content-Length sont
// retirés — le corps change de taille, ReverseProxy re-chunke et les
// injecteurs recalculent la longueur après modification.
func decodeGzipBody(resp *http.Response) error {

	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		resp.Body.Close()
		return err
	}

	body, readErr := io.ReadAll(zr)
	zr.Close()
	resp.Body.Close()
	if readErr != nil {
		return readErr
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = -1
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")

	return nil
}

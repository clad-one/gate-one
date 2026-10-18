package proxy

import (
	"compress/gzip"
	"io"
	"net/http"
)

// decodeGzipBody installe la DÉCOMPRESSION EN FLUX d'un corps gzip
// (Content-Encoding: gzip). Les injecteurs (garde 401/403, futures
// balises) opèrent sur du HTML EN CLAIR : un corps compressé manipulé
// puis servi avec son Content-Encoding supprimé produit une page
// illisible dans le navigateur (incident 2026-10-17 : Cloudflare
// répondait brotli au navigateur, l'injecteur préfixait les octets
// comprimés).
//
// Comme l'injection de la garde (2026-10-18), la décompression est en
// flux : l'o gzip.Reader paresseux traverse le corps au fur et à
// mesure de l'arrivée — JAMAIS de corps entier résident (la page de
// 6 Mo du livre traversait il y a peu en mémoire : deux copies
// compressée + décompressée simultanées). Content-Encoding et
// Content-Length sont retirés — le corps change de taille,
// ReverseProxy re-chunke et flusse chaque write (ContentLength -1).
func decodeGzipBody(resp *http.Response) error {

	src := resp.Body
	zr, err := gzip.NewReader(src)
	if err != nil {
		// pas de gzip (corps vide, en-tête cassé) : 502 par
		// ModifyResponse — rien n'a encore été écrit au client.
		resp.Body.Close()
		return err
	}

	resp.Body = &gunzipStream{zr: zr, src: src}
	resp.ContentLength = -1
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")

	return nil
}

// gunzipStream : gzip.Reader paresseux + fermeture de l'origine.
// gz.Reader lit tous les membres d'un flux multi-membres
// (mêmes appels que l'ancien ReadAll — comportement identique) ; une
// corruption en cours de flux surfes pendant la copie (truncation
// vue du client, version streaming du même scénario) au lieu d'un
// 502 pré-content : le compromis standard de toute réponse streamée.
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

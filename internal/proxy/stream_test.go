package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// Kit de tests du refactor injection EN FLUX. Pilier : la PARITÉ
// entre la décision en flux et l'algorithme bufferisé historique (un
// point d'insertion divergent = garde au mauvais endroit ou jamais —
// et les incidents encoding/troncature de 2026-10-17 ont tous leur
// racine ici).

// guardBufferedReference : réplique EXACTE de l'algorithme bufferisé
// d'avant le streaming (2026-10-18) — la référence de parité.
func guardBufferedReference(body []byte, script string) string {
	var out []byte
	if idx := headOpen.FindIndex(body); idx != nil {
		injectAt := idx[1]
		sniff := body
		if len(sniff) > encodingSniffWindow {
			sniff = sniff[:encodingSniffWindow]
		}
		if m := charsetMeta.FindIndex(sniff); m != nil && m[1] > injectAt {
			injectAt = m[1]
		}
		out = append(out, body[:injectAt]...)
		out = append(out, []byte(script)...)
		out = append(out, body[injectAt:]...)
	} else {
		out = append([]byte(script), body...)
	}
	return string(out)
}

// sizedReader : au plus n octets par Read (1 = pire cas : la balise
// <head> scindée EN PLEIN MILIEU d'un Read — le flux doit quand même
// tomber au point d'insertion exact ; l'ancien algorithme ne voyait
// que des corps entiers, jamais ce découpage).
type sizedReader struct {
	src io.Reader
	n   int
}

func (r *sizedReader) Read(p []byte) (int, error) {
	if len(p) > r.n {
		p = p[:r.n]
	}
	return r.src.Read(p)
}

var streamCases = []string{
	"<html><head><title>t</title></head><body>x</body></html>",
	// meta charset placé APRÈS <head> mais dans la fenêtre :
	// l'injection se fait après LUI (incident mojibake)
	"<html><head><meta charset=\"utf-8\"><title>t</title></head>" +
		"<body>méta-presque-tôt</body></html>",
	// pas de head du tout : fallback historique (script en tête)
	"pas du html du tout",
	// head multi-lignes avec attribut + meta derrière
	"<!DOCTYPE html>\n<html lang=\"fr\">\n<head data-x=\"1\">" +
		"<meta charset=\"utf-8\">suite",
	// head juste avant la fin de la fenêtre de sniff (1024)
	strings.Repeat("z", 995) + "<html><head>meta-late</head>",
	// head APRÈS la fenêtre de sniff mais DANS la fenêtre de scan :
	// l'algo bufferisé cherchait <head> dans le corps entier et
	// injectait après lui — le flux doit en faire autant
	strings.Repeat("z", 4096) + "<html><head>late-head</head>",
	// page SANS head plus grande que la fenêtre de scan : fallback,
	// identique au bufferisé (lui aussi préfixait)
	strings.Repeat("f", 70*1024),
	// page AVEC head bien plus grande que tout : prise de décision
	// vers l'octet 1024, le reste passe SANS relecture
	"<html><head><meta charset=\"utf-8\"><title>big</title></head>" +
		"<body>" + strings.Repeat("b", 300*1024) + "</body></html>",
}

func TestGuardStreamMatchesBufferedInjection(t *testing.T) {
	script := "<script>var GUARD=1;</script>"

	for ci, doc := range streamCases {
		want := guardBufferedReference([]byte(doc), script)
		for _, chunk := range []int{1, 2, 3, 4096, 64 << 10} {
			gs := newGuardStream(
				io.NopCloser(&sizedReader{
					src: strings.NewReader(doc),
					n:   chunk,
				}),
				script,
			)
			got, err := io.ReadAll(gs)
			if err != nil {
				t.Fatalf("case %d chunk %d: %v", ci, chunk, err)
			}
			if string(got) != want {
				t.Errorf(
					"case %d chunk %d: le flux diverge de l'algo bufferisé",
					ci, chunk,
				)
			}
		}
	}
}

// head placé APRÈS la fenêtre de scan (document malformé) : le flux
// retombe sur le fallback (script en tête) — DIVERGENCE DOCUMENTÉE
// avec le bufferisé (qui cherchait head dans tout le corps), testée
// pour rester consciente de son existence ; le document reste entier.
func TestGuardStreamHeadBeyondWindowFallsBack(t *testing.T) {
	script := "<script>var GUARD=2;</script>"
	doc := strings.Repeat("w", 70*1024) + "<html><head>very late</head>"

	gs := newGuardStream(
		io.NopCloser(&sizedReader{src: strings.NewReader(doc), n: 4096}),
		script,
	)
	got, err := io.ReadAll(gs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), script) {
		t.Error("fallback attendu : script en tête du document")
	}
	// le document entier suit le script à l'identique (jamais tronqué)
	if !strings.HasSuffix(string(got), doc) {
		t.Error("le corps d'origine doit suivre le script à l'identique")
	}
}

// decodeGzipBody en flux : le corps décompressé sort au fur et à
// mesure, quelles que soient les tailles de chunk de l'origine.
func TestGunzipStreamsHugeBody(t *testing.T) {
	plain := "<html><head><title>huge</title></head><body>" +
		strings.Repeat("g", 2<<20) + "</body></html>"

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	zw.Close()

	resp := &http.Response{
		Header: http.Header{
			"Content-Encoding": {"gzip"},
			"Content-Length":   {strconv.Itoa(gz.Len())},
		},
		ContentLength: int64(gz.Len()),
		Body:          io.NopCloser(bytes.NewReader(gz.Bytes())),
	}
	if err := decodeGzipBody(resp); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if string(got) != plain {
		t.Errorf("corps décompressé = %d octets, want %d (dégâts ?)",
			len(got), len(plain))
	}
	if resp.ContentLength != -1 ||
		resp.Header.Get("Content-Encoding") != "" ||
		resp.Header.Get("Content-Length") != "" {
		t.Error("en-têtes gzip/Content-Length non nettoyés — page illisible")
	}
}

// Bout en bout à travers la gateway : une page gzip ÉNORME (2 Mo) est
// servie DÉCOMPRIMÉE et INJECTÉE, intègre, chunked — le gunzip
// paresseux et le guardStream s'enchaînent sans buffering.
func TestGunzipAndGuardStreamHugePageThroughGateway(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND"
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/hugegz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != hugeGzPageLen+guardInjectedLen(t) {
		t.Errorf("body = %d octets, want %d (gunzip + injection en flux)",
			len(raw), hugeGzPageLen+guardInjectedLen(t))
	}
	head := string(raw[:2048])
	if !strings.Contains(string(raw), "huge-gz-title") {
		t.Error("contenu du head perdu par le gunzip en flux")
	}
	if !strings.Contains(head, "__cladoneAuthGuard") {
		t.Error("garde non injectée sur la page gzip de 2 Mo")
	}
	if resp.Header.Get("Content-Length") != "" {
		t.Error("Content-Length doit disparaître sur une page injectée en flux")
	}
}

// Une erreur transport EN COURS de flux (origine coupée) : les octets
// déjà écrits sont servis puis l'erreur est PROPAGÉE — elle n'est
// jamais avalée silencieusement (sinon : page moitié-morte sans
// trace côté gateway).
func TestGuardStreamPropagatesTransportError(t *testing.T) {
	script := "<script>var GUARD=3;</script>"
	srcErr := io.ErrUnexpectedEOF
	// origine : servo 60 o du head puis une erreur
	head := "<html><head><title>t</title></head>"
	src := io.MultiReader(
		strings.NewReader(head),
		&errorReader{srcErr},
	)

	gs := newGuardStream(io.NopCloser(src), script)
	out, firstErr := io.ReadAll(gs)
	// ReadAll retourne data + err : l'erreur est propagée…
	if firstErr != srcErr {
		t.Fatalf("erreur transport avalée : %v (want %v)", firstErr, srcErr)
	}
	// … et les octets arrivés tiennent tout dans l'ordre : le
	// fallback du scan (EOF forcé) a inséré le script après <head>.
	got := string(out)
	if !strings.HasPrefix(got, "<html><head>") ||
		!strings.HasSuffix(got, "<title>t</title></head>") {
		t.Errorf("octets d'origine perdus sur transport error: %q", got)
	}
	if len(out) != len(head)+len(script) {
		t.Errorf("longueur = %d, want %d (octets mal servis)",
			len(out), len(head)+len(script))
	}
}

// erreurReader : sert l'erreur immédiatement — pour forcer le chemin
// erreur-en-cours-de-flux d'un guardStream.
type errorReader struct{ err error }

func (r *errorReader) Read(p []byte) (int, error) {
	return 0, r.err
}

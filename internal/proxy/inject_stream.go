package proxy

// Flux d'insertion des injections CUSTOM (bundle d'une route) — la
// mécanique de la garde généralisée aux cibles nommées. Deux machines
// O(1) :
//
//   - cible "head" (défaut) : après <head> et après le meta charset de
//     la fenêtre de détection — même décision que la garde, MAIS
//     fail-open sans <head> : le snippet est sauti (un contenu custom
//     ne doit jamais précéder <!doctype : pas de fallback « tout en
//     tête » de la garde, qui est infrastructure) ;
//   - cible "body-end" : avant </body> — la décision peut arriver
//     après des Mo (le livre) : rétention d'une queue bornée (jamais
//     le corps entier), le reste passe sans relecture ; à EOF sans
//     marqueur le contenu part en toute fin (document sans </body>).

import (
	"io"
	"net/http"
	"regexp"
	"strings"

	"cladone/gateway/internal/core"
)

var bodyCloseTag = regexp.MustCompile(`(?i)</body`)

// tailHold : octets retenus pour la détection d'un marqueur qui
// chevauche le bord de lecture (</body> = 7 octets).
const tailHold = 8

// newInjectStream : le flux d'insertion selon la cible.
func newInjectStream(src io.ReadCloser, content, target string) io.ReadCloser {
	if target == "body-end" {
		return &tailInjectStream{
			src:     src,
			content: content,
			scratch: make([]byte, 4096),
		}
	}
	// "head" (défaut) : décision précoce, mécanique guardStream —
	// sans fallback « tout en tête » : pas de head dans la fenêtre =
	// snippet sauti (fail-open).
	return &guardStream{
		src:     src,
		script:  content,
		skipNF:  true, // no-head : skip, jamais de préfixe forcé
		scratch: make([]byte, 4096),
	}
}

// tailInjectStream : insertion avant </body> — chaque chunk est
// scanné, seul un compact tail est retenu pour les marqueurs qui
// chevauchent le bord de lecture. O(1) quelle que soit la page.
type tailInjectStream struct {
	src     io.ReadCloser
	content string

	scratch  []byte
	tail     []byte // last tailHold bytes (marqueurs à cheval)
	pend     []byte // sortie en attente d'émision
	pendOff  int
	inserted bool
	err      error
	eof      bool
}

func (t *tailInjectStream) Read(p []byte) (int, error) {

	for t.pendOff >= len(t.pend) {
		t.pend = t.pend[:0]
		t.pendOff = 0

		if t.eof {
			if t.err != nil {
				return 0, t.err
			}
			return t.src.Read(p)
		}

		n, rerr := t.src.Read(t.scratch)
		chunk := t.scratch[:n]
		if rerr != nil && rerr != io.EOF {
			if t.err == nil {
				t.err = rerr
			}
			t.eof = true
		}

		data := append(t.tail, chunk...)
		if rerr == io.EOF {
			t.eof = true
		}

		if idx := bodyCloseTag.FindIndex(data); idx != nil {
			// avant </body> : le reste du flux suit tel quel
			t.pend = append(t.pend, data[:idx[0]]...)
			t.pend = append(t.pend, t.content...)
			t.pend = append(t.pend, data[idx[0]:]...)
			t.inserted = true
			t.tail = nil
			// la suite du src est relayée sans relecture
			t.eof = true
			t.pendOff = 0
			break
		}

		if t.eof {
			// pas de </body> : le contenu part en toute fin (jamais
			// d'octet perdu ni dupliqué)
			t.pend = append(t.pend, data...)
			if !t.inserted {
				t.pend = append(t.pend, t.content...)
				t.inserted = true
			}
			t.tail = nil
			break
		}

		// pas de marqueur : tout émettre sauf la queue (un marqueur
		// à cheval sur le bord de lecture reste détectable)
		keep := tailHold
		if len(data) < keep {
			keep = len(data)
		}
		t.pend = append(t.pend, data[:len(data)-keep]...)
		t.tail = append(t.tail[:0], data[len(data)-keep:]...)
	}

	n := copy(p, t.pend[t.pendOff:])
	t.pendOff += n
	return n, nil
}

func (t *tailInjectStream) Close() error { return t.src.Close() }

// itemMatchesPath : le ciblage par page du bundle — préfixe de chemin
// (même grammaire que route.path : "/*" = tout le host). La requête
// garde son chemin dans resp.Request (le director ne réécrit que le
// Host).
func itemMatchesPath(item *core.InjectContent, req *http.Request) bool {
	if item.WhenPath == "" || item.WhenPath == "/*" || req == nil {
		return true
	}
	p := "/"
	if req.URL != nil && req.URL.Path != "" {
		p = req.URL.Path
	}
	return strings.HasPrefix(p, strings.TrimSuffix(item.WhenPath, "*"))
}

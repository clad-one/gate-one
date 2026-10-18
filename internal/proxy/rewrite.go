package proxy

import (
	"bytes"
	"io"
	"net/url"

	"cladone/gateway/internal/core"
	"cladone/gateway/internal/pwa"
)

//
// Réécriture du corps HTML (upstream.rewriteBody) — moteur EN FLUX.
//
// Le site externe proxifié cite ses propres URLs dans ses pages
// ("https://origine/…", "//origine/…") : sans réécriture, le
// navigateur quitte le proxy dès la première occurrence (session,
// instrumentations perdues). La gateway réécrit ces occurrences vers
// le host PUBLIC de la route sans bufferiser le corps (comme
// guardStream : l'octet d'entrée ressort vite, mémoire O(1) quelle
// que soit la taille de la page).
//
// Sémantique partagée avec le SW client (pwa.Handler) et la couche
// patch du script de garde : les trois couches implémentent la MÊME
// politique (origins × except × target) — la parité est testée dans
// rewrite_test.go sur la même liste de cas.
//
// Formes réécrites : "https://HOST…", "http://HOST…", "//HOST…" (HOST
// = hostname d'origine de la route, sans port ; un port explicite
// ":digits" fait partie du préfixe réécrit et est PERDU — la cible
// publique est servie en port standard). Chemin, query et fragment
// suivent tels quels. Exceptions : préfixe de chemin le plus long
// gagne (tri décroissant) ; entrée chaîne = rester à l'origine,
// entrée {path,to} = base de remplacement "to".
//
// Fenêtre glissante bornée : le moteur n'attend jamais plus que
// "https://" + host le plus long + préfixe d'exception le plus long
// (config : ≤ 256 octets par préfixe) ; plus le port explicite
// éventuel, résolu en attente aux bords de fenêtre. Une URL n'est
// JAMAIS réécrite partiellement : si une décision manque de contexte,
// les octets concernés sont retenus jusqu'à résolution ; faute de
// candidat, tout s'émet sauf les derniers `hold` octets (un motif plus
// petit que ça ne peut jamais chevaucher le bord de fenêtre). Fin de
// flux : tout est résolu/émis ; erreur transport : buf part brut puis
// l'erreur se propage (jamais silencieuse), conformément à
// guardStream.
//

// rewritePlan : politique de réécriture compilée d'une route,
// partagée entre le moteur en flux (Go) et le SW client (pwa).
type rewritePlan struct {
	// hosts d'origine dont les URLs absolues sont réécrits — hostname
	// sans port, minuscules (self-référencements plausibles du HTML
	// d'origine : host du backend + hostOverride éventuel).
	origins []string
	// pub : base de remplacement par défaut, "https://host.public".
	pub string
	// except : exceptions triées par longueur décroissante (préfixe
	// le plus long gagne) ; To vide = rester à l'origine.
	except []core.RewriteExcept
	// hold : fragments max retenus en fin de fenêtre — "https://" +
	// host le plus long (aucun motif ne peut chevaucher au-delà).
	hold int
	// maxExcept : préfixe d'exception le plus long (contexte droit
	// nécessaire à une décision).
	maxExcept int
}

// rewritePlanFor compile la politique rewriteBody de la route ; nil
// quand la route n'en a pas (absente ou désactivée).
func rewritePlanFor(route *core.Route, backend *url.URL) *rewritePlan {
	rb := route.UpstreamRewriteBody()
	if rb == nil {
		return nil
	}

	up := route.Upstream
	origins := make([]string, 0, 2)
	addOrigin := func(h string) {
		h = normalizeHost(h)
		for _, have := range origins {
			if have == h {
				return
			}
		}
		origins = append(origins, h)
	}
	addOrigin(backend.Hostname())
	if up.HostOverride != "" {
		addOrigin(up.HostOverride)
	}

	maxHost := 0
	for _, h := range origins {
		if len(h) > maxHost {
			maxHost = len(h)
		}
	}

	// exceptions : préfixe le plus long d'abord (le premier match
	// gagne, côté Go comme côté SW client).
	except := make([]core.RewriteExcept, len(rb.Except))
	copy(except, rb.Except)
	for i := 1; i < len(except); i++ {
		for j := i; j > 0 && len(except[j].Path) > len(except[j-1].Path); j-- {
			except[j], except[j-1] = except[j-1], except[j]
		}
	}

	maxExcept := 0
	for _, e := range except {
		if len(e.Path) > maxExcept {
			maxExcept = len(e.Path)
		}
	}

	return &rewritePlan{
		origins:   origins,
		pub:       "https://" + normalizeHost(route.Host),
		except:    except,
		hold:      len("https://") + maxHost,
		maxExcept: maxExcept,
	}
}

// clientSpec : adapté pour le SW client (pwa.RewriteSpec).
func (p *rewritePlan) clientSpec() *pwa.RewriteSpec {
	return &pwa.RewriteSpec{
		Origins: p.origins,
		Target:  p.pub,
		Except:  p.except,
	}
}

// rewriteGuardDTO : sérialisé dans le script de garde, pour
// l'enregistrement du SW (paramétré comme le SW ci-dessus) et le
// patch des appels runtime (fetch/XHR/…). Le payload traverse le
// moteur de réécriture : les hosts d'origine y figurent SANS scheme —
// jamais sous une forme "scheme://origin" qui serait réécrite dans
// son propre transport.
type rewriteGuardDTO struct {
	Sw      string               `json:"sw"`
	Target  string               `json:"target"`
	Origins []string             `json:"origins"`
	Except  []core.RewriteExcept `json:"except"`
}

// rewriteGuardDTOFor : version pour le script de garde ; nil quand la
// route n'a pas de rewriteBody.
func rewriteGuardDTOFor(route *core.Route, backend *url.URL) *rewriteGuardDTO {
	plan := rewritePlanFor(route, backend)
	if plan == nil {
		return nil
	}
	return &rewriteGuardDTO{
		Sw:      pwa.SwURL,
		Target:  plan.pub,
		Origins: plan.origins,
		Except:  plan.except,
	}
}

//
// Moteur en flux.
//
//	buf : octets reçus, pas encore émis (borné par hold, plus le
//	      besoin droit éventuel d'un candidat en attente de contexte).
//	out : octets résolus, prêts à ressortir.
//

type rewriteStream struct {
	src io.ReadCloser
	cfg *rewritePlan

	scratch  []byte
	buf      []byte
	out      []byte
	outOff   int
	lastByte byte // dernier octet déjà émis (contexte gauche d'un candidat en tête de buf)
	emitted  bool
	done     bool
	err      error
}

func newRewriteStream(src io.ReadCloser, cfg *rewritePlan) *rewriteStream {
	return &rewriteStream{
		src:     src,
		cfg:     cfg,
		scratch: make([]byte, 4096),
	}
}

func (s *rewriteStream) Read(p []byte) (int, error) {
	for {
		if s.outOff < len(s.out) {
			n := copy(p, s.out[s.outOff:])
			s.outOff += n
			if s.outOff == len(s.out) {
				s.out = s.out[:0]
				s.outOff = 0
			}
			return n, nil
		}
		if s.done {
			if s.err != nil {
				return 0, s.err
			}
			return s.src.Read(p)
		}
		s.step()
	}
}

func (s *rewriteStream) step() {
	n, rerr := s.src.Read(s.scratch)
	if n > 0 {
		s.buf = append(s.buf, s.scratch[:n]...)
	}
	if rerr != nil && rerr != io.EOF {
		// erreur transport : buf part BRUT (un corps coupé ne doit
		// pas être semi-réécrit), l'erreur surfacera après — comme
		// guardStream, jamais avalée.
		if s.err == nil {
			s.err = rerr
		}
		s.done = true
		s.emit(len(s.buf))
		return
	}
	if rerr == io.EOF {
		s.done = true
	}
	s.resolve()
}

// resolve applique les décisions de réécriture sur buf et déplace ce
// qui est tranché vers out.
func (s *rewriteStream) resolve() {

	scan := 0
	for {
		h, hostLen := s.findHost(scan)
		if h < 0 {
			// plus aucune occurrence entière (= également au-delà) :
			if s.done {
				// fin de flux → tout partir (les candidats tranchés
				// ci-dessus ont déjà épuisé leurs remplacements)
				s.emit(len(s.buf))
			} else {
				// émettre jusqu'au point sûr : les derniers hold
				// octets peuvent chevaucher un futur motif
				safe := len(s.buf) - s.cfg.hold
				if safe > 0 {
					s.emit(safe)
				}
			}
			return
		}

		m := s.evaluate(h, hostLen)
		switch m.state {
		case candInvalid:
			// pas une URL de l'origine (frontières) : chercher la
			// suivante — un autre host peut coïncider ici, la plus
			// longue ayant déjà été retenue par findHost
			scan = h + 1
		case candPending:
			// contexte (gauche/droit) insuffisant : attendre des
			// octets. Ce qui précède le motif est résolu.
			if s.done {
				replacement, keep := s.decision(m)
				s.applyCandidate(m, replacement, keep)
				scan = rescan(scan, m.portEnd)
				continue
			}
			s.emit(m.formStart)
			return
		default:
			replacement, keep := s.decision(m)
			s.applyCandidate(m, replacement, keep)
			// buf a été tronqué de buf[:portEnd] : les index du scan
			// se décalent d'autant (les skips invalides antérieurs,
			// sous portEnd, sont partis en émission — terminés).
			scan = rescan(scan, m.portEnd)
		}
	}
}

// rescan : index de reprise du scan après une troncature de
// buf[:cut] — un scan stale pointerait dans le mauvais buf et rate
// toute occurrence retenue en aval (bug découvert par la trace E2E :
// un skip invalide suivi d'un candidat tranché gelait le moteur).
func rescan(scan, cut int) int {
	if scan > cut {
		return scan - cut
	}
	return 0
}

// findHost : première occurrence (index min) d'un host d'origine dans
// buf[from:] ; à index égal, le host le plus long gagne (ex. deux
// origins dont l'une est suffixe de l'autre). Retourne (index, len).
// Une occurrence PLUS LONGUE que buf (host coupé au bord) n'existe
// pas pour Index : elle sera vue quand plus d'octets arriveront —
// les derniers `hold` octets de buf ne sont donc jamais émis hors
// "done".
func (s *rewriteStream) findHost(from int) (int, int) {
	best, blen := -1, 0
	for _, host := range s.cfg.origins {
		i := bytes.Index(s.buf[from:], []byte(host))
		if i < 0 {
			continue
		}
		i += from
		switch {
		case best < 0 || i < best:
			best, blen = i, len(host)
		case i == best && len(host) > blen:
			blen = len(host)
		}
	}
	return best, blen
}

type candKind int

const (
	candInvalid candKind = iota
	candPending
	candDecided
)

type cand struct {
	state     candKind
	formStart int // début du motif (https:// … ou //)
	formEnd   int // fin d'host (exclusive) = début du chemin
	portEnd   int // après le port optionnel (:digits) — sinon formEnd
}

var (
	httpsPrefix = []byte("https://")
	httpPrefix  = []byte("http://")
	slashPrefix = []byte("//")
)

// evaluate détermine le candidat à l'index h (host) : forme URL
// (https:// | http:// | //) avec frontières gauche + droite
// vérifiées, puis disponibilité du contexte droit (chemin pour les
// exceptions).
func (s *rewriteStream) evaluate(h, hostLen int) cand {

	formLen := 0
	switch {
	case h >= len(httpsPrefix) && bytes.Equal(s.buf[h-len(httpsPrefix):h], httpsPrefix):
		formLen = len(httpsPrefix)
	case h >= len(httpPrefix) && bytes.Equal(s.buf[h-len(httpPrefix):h], httpPrefix):
		formLen = len(httpPrefix)
	case h >= len(slashPrefix) && bytes.Equal(s.buf[h-len(slashPrefix):h], slashPrefix):
		formLen = len(slashPrefix)
	default:
		return cand{state: candInvalid}
	}

	formStart := h - formLen

	// frontière gauche : le caractère avant le motif ne fait pas
	// partie d'un token plus long (wss://, xhttps://, mail@…).
	bound := byte(0)
	switch {
	case formStart == 0 && !s.emitted:
		// début du document : frontière de fait
	case formStart == 0:
		bound = s.lastByte
	default:
		bound = s.buf[formStart-1]
	}
	if formStart > 0 || s.emitted {
		if formLen == len(slashPrefix) {
			// //host : après une quote, parenthèse, espace… — pas
			// après ':' (exclusion des autres schemes, wss://…)
			if !isRelBoundary(bound) {
				return cand{state: candInvalid}
			}
		} else {
			// http(s):// : pas collé à un caractère d'host
			if isHostChar(bound) {
				return cand{state: candInvalid}
			}
		}
	}

	formEnd := h + hostLen

	// port optionnel ":digits" — l'URL d'origine peut citer un port
	// explicite (origin en port non standard, tests). Le port
	// qualifie l'host : il appartient au préfixe réécrit et est
	// ABSENT des remplacements (la cible publique est servie en
	// standard).
	portEnd := formEnd
	if portEnd < len(s.buf) && s.buf[portEnd] == ':' {
		k := portEnd + 1
		for k < len(s.buf) && s.buf[k] >= '0' && s.buf[k] <= '9' {
			k++
		}
		switch {
		case k == portEnd+1 && !s.done:
			// ':' sans chiffre encore : un port peut suivre
			return cand{state: candPending, formStart: formStart, formEnd: formEnd, portEnd: portEnd}
		case k == portEnd+1:
			// ':' suivi de non-chiffre (":/x") : pas une forme cible
			return cand{state: candInvalid}
		case k >= len(s.buf) && !s.done:
			// port tronqué au bord de fenêtre : attendre
			return cand{state: candPending, formStart: formStart, formEnd: formEnd, portEnd: portEnd}
		}
		portEnd = k
	}

	// frontière droite : le host ne se poursuit pas (a.b au sein
	// d'un a.b.c plus long).
	if portEnd < len(s.buf) {
		if isHostChar(s.buf[portEnd]) {
			return cand{state: candInvalid}
		}
	} else if !s.done {
		// au moins un octet après l'host est requis pour trancher la
		// frontière droite ; rien ici : attendre.
		return cand{state: candPending, formStart: formStart, formEnd: formEnd, portEnd: portEnd}
	}

	// contexte droit : chemin (pour les exceptions)
	pathStart := portEnd
	stop := -1
	for i := pathStart; i < len(s.buf) && i < pathStart+s.cfg.maxExcept; i++ {
		if isPathStop(s.buf[i]) {
			stop = i
			break
		}
	}
	if !s.done && stop < 0 && len(s.buf)-pathStart < s.cfg.maxExcept {
		return cand{state: candPending, formStart: formStart, formEnd: formEnd, portEnd: portEnd}
	}

	return cand{state: candDecided, formStart: formStart, formEnd: formEnd, portEnd: portEnd}
}

// decision : verdict du candidat m — selon les exceptions (préfixe
// le plus long gagne, tri décroissant). keep=true : le texte original
// (port inclus) passe tel quel. replacement : texte qui remplace
// scheme://host[:port] (le chemin, qui commence à portEnd, suit).
func (s *rewriteStream) decision(m cand) (replacement string, keep bool) {

	pathStart := m.portEnd
	end := len(s.buf)
	if end > pathStart {
		// au premier terminateur (fin du chemin)
		for i := pathStart; i < end; i++ {
			if isPathStop(s.buf[i]) {
				end = i
				break
			}
		}
	}
	if end-pathStart > s.cfg.maxExcept {
		end = pathStart + s.cfg.maxExcept
	}

	for _, e := range s.cfg.except {
		if len(e.Path) <= end-pathStart &&
			bytes.HasPrefix(s.buf[pathStart:], []byte(e.Path)) {
			if e.To != "" {
				return e.To, false // host public alternatif
			}
			return "", true // exception : rester à l'origine
		}
	}
	return s.cfg.pub, false // réécriture standard
}

// applyCandidate émet buf[:formStart] puis (original inchangé ou
// remplacement), et retire le préfixe (jusqu'au port inclus) de la
// fenêtre ; le chemin reste, rescané ensuite normalement.
func (s *rewriteStream) applyCandidate(m cand, replacement string, keep bool) {
	s.out = append(s.out, s.buf[:m.formStart]...)
	if keep {
		s.out = append(s.out, s.buf[m.formStart:m.portEnd]...)
	} else if replacement != "" {
		s.out = append(s.out, replacement...)
	}
	s.rememberLast()
	s.buf = append([]byte(nil), s.buf[m.portEnd:]...)
}

// emit : buf[:n] part vers out (retenir rien de plus).
func (s *rewriteStream) emit(n int) {
	if n <= 0 {
		return
	}
	s.out = append(s.out, s.buf[:n]...)
	s.rememberLast()
	s.buf = append([]byte(nil), s.buf[n:]...)
}

func (s *rewriteStream) rememberLast() {
	if len(s.out) > 0 {
		s.lastByte = s.out[len(s.out)-1]
		s.emitted = true
	}
}

// isHostChar : lettres/chiffres + '.' '-' '_' — caractères d'host ;
// vrai de part et d'autre du motif, l'occurrence ne fait pas partie
// d'un token voisin (wss://, sous-domaine plus long…).
func isHostChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '.', b == '-', b == '_':
		return true
	}
	return false
}

// isRelBoundary : frontière valide avant un "//host" relatif au
// protocole (':' exclus — tous les autres schemes, wss://…).
func isRelBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '"', '\'', '(', '=', '<', ',', ';', '{', '[':
		return true
	}
	return false
}

// isPathStop : fin de chemin (juridique : avant ce terminateur on
// compare les préfixes d'exception ; les octets passent tel quel).
func isPathStop(b byte) bool {
	switch b {
	case '"', '\'', '<', '>', ' ', '\t', '\n', '\r', '?', '#', '&',
		'(', ')', ',', ';', '{', '}', '[', ']', '\\':
		return true
	}
	return false
}

func (s *rewriteStream) Close() error {
	return s.src.Close()
}

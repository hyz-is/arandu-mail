package dkim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hyz-is/arandu-mail/internal/puny"
)

// RecommendedHeaders is the list of header fields RFC 6376 section 5.4.1
// suggests signing, in lowercase. A field is signed only when the message has
// it.
var RecommendedHeaders = []string{
	"from", "reply-to", "subject", "date", "to", "cc",
	"resent-date", "resent-from", "resent-to", "resent-cc",
	"in-reply-to", "references", "list-id", "list-help", "list-unsubscribe",
	"list-subscribe", "list-post", "list-owner", "list-archive",
	"list-unsubscribe-post",
	"mime-version", "content-type", "content-transfer-encoding", "content-id",
	"content-description", "message-id", "sender",
}

// DefaultOversigned are the fields signed once more than the message has them,
// so that adding a second From, To or Subject in transit invalidates the
// signature.
var DefaultOversigned = []string{"from", "to", "subject"}

// Errors returned by NewSigner and Sign.
var (
	// ErrNoFrom reports a message without a From field, which DKIM must sign.
	ErrNoFrom = errors.New("dkim: the message has no From header field")
	// ErrNoBody reports an input that is not a message.
	ErrNoBody = errors.New("dkim: the input is empty")
	// ErrMalformed reports a message that starts with a continuation line, which
	// would be read as part of the signature field put in front of it.
	ErrMalformed = errors.New("dkim: the message starts with white space")
)

// Config describes a Signer.
type Config struct {
	// Domain is the signing domain, the "d=" tag. A Unicode domain is converted
	// to Punycode.
	Domain string
	// Selector is the "s=" tag: the key lives at Selector._domainkey.Domain.
	Selector string
	// Key signs. It is an RSA key of at least 1024 bits or an Ed25519 key.
	Key crypto.Signer
	// HeaderCanon and BodyCanon default to Relaxed.
	HeaderCanon, BodyCanon Canon
	// Headers lists the fields to sign, in order. Empty means
	// RecommendedHeaders. A name repeated in the list is signed once more for
	// each repetition, which is how RFC 8463 writes an oversigned list.
	Headers []string
	// Oversign lists fields signed once more than the message has them. Empty
	// means DefaultOversigned; NoOversign turns it off.
	Oversign []string
	// NoOversign signs only the fields that exist.
	NoOversign bool
	// Identity is the "i=" tag, such as "@example.com". Empty leaves it out.
	Identity string
	// Expiration, when positive, sets the "x=" tag that long after signing.
	Expiration time.Duration
	// Now returns the signing time. Default time.Now.
	Now func() time.Time
}

// Signer signs messages for one domain and selector. It is safe for concurrent
// use.
type Signer struct {
	domain, selector, identity string
	key                        crypto.Signer
	alg                        Algorithm
	hc, bc                     Canon
	headers                    []string // lowercase, with the repetitions the caller wrote
	oversign                   map[string]bool
	expiration                 time.Duration
	now                        func() time.Time
	counts                     map[string]int
	tags                       []string // the tags that never change, as tokens
}

// NewSigner checks the configuration and returns a Signer.
func NewSigner(cfg Config) (*Signer, error) {
	if cfg.Domain == "" || cfg.Selector == "" || cfg.Key == nil {
		return nil, errors.New("dkim: Domain, Selector and Key are required")
	}
	domain, err := puny.ToASCII(strings.TrimSuffix(cfg.Domain, "."))
	if err != nil {
		return nil, fmt.Errorf("dkim: domain %q: %w", cfg.Domain, err)
	}
	if !validSelector(cfg.Selector) {
		return nil, fmt.Errorf("dkim: invalid selector %q", cfg.Selector)
	}
	s := &Signer{domain: domain, selector: cfg.Selector, identity: cfg.Identity, key: cfg.Key,
		hc: cfg.HeaderCanon, bc: cfg.BodyCanon, expiration: cfg.Expiration, now: cfg.Now}
	switch pub := cfg.Key.Public().(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 1024 {
			return nil, errors.New("dkim: RSA keys under 1024 bits are not accepted by verifiers")
		}
		s.alg = RSASHA256
	case ed25519.PublicKey:
		s.alg = Ed25519SHA256
	default:
		return nil, ErrUnsupportedKey
	}
	if s.hc == "" {
		s.hc = Relaxed
	}
	if s.bc == "" {
		s.bc = Relaxed
	}
	if (s.hc != Simple && s.hc != Relaxed) || (s.bc != Simple && s.bc != Relaxed) {
		return nil, errors.New("dkim: canonicalization must be simple or relaxed")
	}
	if s.now == nil {
		s.now = time.Now
	}
	names := cfg.Headers
	if len(names) == 0 {
		names = RecommendedHeaders
	}
	for _, n := range names {
		if !validHeaderName(n) {
			return nil, fmt.Errorf("dkim: invalid header name %q", n)
		}
		s.headers = append(s.headers, strings.ToLower(n))
	}
	if !contains(s.headers, "from") {
		return nil, errors.New("dkim: the header list must include from")
	}
	s.oversign = map[string]bool{}
	if !cfg.NoOversign {
		over := cfg.Oversign
		if len(over) == 0 {
			over = DefaultOversigned
		}
		for _, n := range over {
			n = strings.ToLower(n)
			s.oversign[n] = true
			if !contains(s.headers, n) {
				s.headers = append(s.headers, n)
			}
		}
	}
	s.counts = map[string]int{}
	for _, n := range s.headers {
		s.counts[n]++
	}
	s.tags = []string{"v=1;", "a=" + string(s.alg) + ";", "c=" + string(s.hc) + "/" + string(s.bc) + ";",
		"d=" + s.domain + ";", "s=" + s.selector + ";"}
	return s, nil
}

// Algorithm returns the algorithm the signer uses.
func (s *Signer) Algorithm() Algorithm { return s.alg }

func validSelector(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return s[0] != '.' && s[len(s)-1] != '.'
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 32 || c >= 127 || c == ':' || c == ';' {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Sign returns the DKIM-Signature header field for msg, ending in CRLF, to be
// put at the top of the message.
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	return s.AppendSignature(make([]byte, 0, 640), msg)
}

// SignMessage returns msg with the DKIM-Signature field added at the top.
func (s *Signer) SignMessage(msg []byte) ([]byte, error) {
	out, err := s.AppendSignature(make([]byte, 0, len(msg)+640), msg)
	if err != nil {
		return nil, err
	}
	return append(out, msg...), nil
}

// AppendSignature appends the DKIM-Signature field for msg to dst.
func (s *Signer) AppendSignature(dst, msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return dst, ErrNoBody
	}
	if isWSP(msg[0]) {
		return dst, ErrMalformed
	}
	var stack [48]field
	fields, body := splitMessage(msg, stack[:0])

	// Which message fields go into the signature, in order.
	var usedStack [48]bool
	var used []bool
	if len(fields) > len(usedStack) {
		used = make([]bool, len(fields))
	} else {
		used = usedStack[:len(fields)]
	}
	var picksStack [40]pick
	picks := picksStack[:0]
	for _, name := range s.headers {
		if s.counts[name] > 1 {
			// A name the caller wrote several times takes one instance per
			// repetition, and an instance the message lacks is signed as absent.
			picks = append(picks, pick{name, lastUnused(fields, used, name)})
			if last := picks[len(picks)-1]; last.index >= 0 {
				used[last.index] = true
			}
			continue
		}
		for {
			idx := lastUnused(fields, used, name)
			if idx < 0 {
				break
			}
			used[idx] = true
			picks = append(picks, pick{name, idx})
		}
		if s.oversign[name] {
			picks = append(picks, pick{name, -1})
		}
	}
	hasFrom := false
	for _, p := range picks {
		if p.name == "from" && p.index >= 0 {
			hasFrom = true
		}
	}
	if !hasFrom {
		return dst, ErrNoFrom
	}

	bh := bodyHash(body, s.bc, -1)
	now := s.now()

	start := len(dst)
	dst = append(dst, "DKIM-Signature:"...)
	w := sigWriter{dst: dst, lineStart: start}
	for _, tok := range s.tags {
		w.token(tok)
	}
	if s.identity != "" {
		w.token("i=" + s.identity + ";")
	}
	w.token("t=" + strconv.FormatInt(now.Unix(), 10) + ";")
	if s.expiration > 0 {
		w.token("x=" + strconv.FormatInt(now.Add(s.expiration).Unix(), 10) + ";")
	}
	for i, p := range picks {
		tok := p.name
		if i == 0 {
			tok = "h=" + tok
		}
		if i == len(picks)-1 {
			tok += ";"
		} else {
			tok += ":"
		}
		if i == 0 {
			w.token(tok)
		} else {
			w.glue(tok)
		}
	}
	w.token("bh=" + base64.StdEncoding.EncodeToString(bh) + ";")
	w.token("b=")
	dst = w.dst

	// The hash covers the signed fields, bottom up, then the signature field
	// itself with an empty b=.
	h := getHasher()
	for _, p := range picks {
		if p.index < 0 {
			continue
		}
		f := fields[p.index]
		h.buf = appendHeader(h.buf, s.hc, f.raw, f.colon, true)
		h.maybeFlush()
	}
	sigField := dst[start:]
	h.buf = appendHeader(h.buf, s.hc, sigField, len("DKIM-Signature"), false)
	digest := h.sum()
	h.release()

	var sig []byte
	var err error
	switch s.alg {
	case RSASHA256:
		sig, err = s.key.Sign(rand.Reader, digest, crypto.SHA256)
	default:
		sig, err = s.key.Sign(nil, digest, crypto.Hash(0))
	}
	if err != nil {
		return dst[:start], fmt.Errorf("dkim: signing: %w", err)
	}

	enc := base64.StdEncoding.EncodeToString(sig)
	w = sigWriter{dst: dst, lineStart: lineStartOf(dst, start)}
	w.fillBase64(enc)
	dst = append(w.dst, '\r', '\n')
	return dst, nil
}

func lineStartOf(dst []byte, floor int) int {
	for i := len(dst) - 1; i >= floor; i-- {
		if dst[i] == '\n' {
			return i + 1
		}
	}
	return floor
}

func lastUnused(fields []field, used []bool, name string) int {
	for i := len(fields) - 1; i >= 0; i-- {
		if !used[i] && equalFoldName(fields[i].name, name) {
			return i
		}
	}
	return -1
}

// sigWriter lays out the tags of the signature field, folding at about 76
// columns with a tab.
type sigWriter struct {
	dst       []byte
	lineStart int
}

func (w *sigWriter) token(s string) {
	if len(w.dst)-w.lineStart+1+len(s) > 76 {
		w.dst = append(w.dst, '\r', '\n', '\t')
		w.lineStart = len(w.dst) - 1
	} else {
		w.dst = append(w.dst, ' ')
	}
	w.dst = append(w.dst, s...)
}

// glue appends s to the previous token, folding first when it would not fit.
func (w *sigWriter) glue(s string) {
	if len(w.dst)-w.lineStart+len(s) > 76 {
		w.dst = append(w.dst, '\r', '\n', '\t')
		w.lineStart = len(w.dst) - 1
	}
	w.dst = append(w.dst, s...)
}

// fillBase64 appends the b= value, breaking it into lines.
func (w *sigWriter) fillBase64(enc string) {
	for len(enc) > 0 {
		room := 76 - (len(w.dst) - w.lineStart)
		if room < 8 {
			w.dst = append(w.dst, '\r', '\n', '\t')
			w.lineStart = len(w.dst) - 1
			room = 76 - 8
		}
		n := min(room, len(enc))
		w.dst = append(w.dst, enc[:n]...)
		enc = enc[n:]
	}
}

// pick is one entry of the "h=" list: a header name and the field it stands
// for, or -1 for an instance the message does not have.
type pick struct {
	name  string
	index int
}

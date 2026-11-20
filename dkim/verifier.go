package dkim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Resolver looks up the TXT records that hold DKIM keys. A *net.Resolver
// satisfies it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Status is the outcome of verifying one signature.
type Status string

// The outcomes. TempError means the answer may change on a retry (the DNS did
// not answer); every other failure is final for that message.
const (
	Pass      Status = "pass"
	Fail      Status = "fail"
	TempError Status = "temperror"
	PermError Status = "permerror"
)

// Result is the verification of one DKIM-Signature field.
type Result struct {
	Status Status
	// Err explains a status other than Pass.
	Err error
	// Domain, Selector and Identity are the "d=", "s=" and "i=" tags.
	Domain, Selector, Identity string
	// Algorithm is the "a=" tag.
	Algorithm Algorithm
	// HeaderCanon and BodyCanon are the "c=" tag.
	HeaderCanon, BodyCanon Canon
	// Testing is true when the key record is marked as a test ("t=y"); a
	// receiver should treat the message as unsigned.
	Testing bool
	// BodyLimited is true when the signature covers only part of the body
	// ("l="), which lets a third party append content.
	BodyLimited bool
}

// Verification failures. Result.Err wraps them.
var (
	ErrNoKey             = errors.New("dkim: no key record")
	ErrKeyRevoked        = errors.New("dkim: the key record is revoked (empty p=)")
	ErrBadKey            = errors.New("dkim: the key record is not valid")
	ErrWeakKey           = errors.New("dkim: the RSA key is too short")
	ErrBadSignature      = errors.New("dkim: malformed DKIM-Signature field")
	ErrBodyHash          = errors.New("dkim: body hash did not verify")
	ErrSignatureMismatch = errors.New("dkim: signature did not verify")
	ErrExpired           = errors.New("dkim: the signature has expired")
	ErrFromNotSigned     = errors.New("dkim: the From field is not signed")
	ErrIdentity          = errors.New("dkim: the identity is not in the signing domain")
)

// Verifier checks the DKIM signatures of a message. It is safe for concurrent
// use.
type Verifier struct {
	// Resolver finds the key records. Required.
	Resolver Resolver
	// MinRSABits is the shortest RSA key accepted. Default 1024 (RFC 8301).
	MinRSABits int
	// MaxSignatures bounds the signatures checked in one message; the others are
	// ignored, which stops a message from asking for unlimited DNS lookups.
	// Default 10.
	MaxSignatures int
	// Now returns the time used to check "x=". Default time.Now.
	Now func() time.Time
}

// Verify checks every DKIM-Signature field of msg and returns one Result for
// each, in order. A message with no signature yields no result.
func (v *Verifier) Verify(ctx context.Context, msg []byte) []Result {
	var stack [48]field
	fields, body := splitMessage(msg, stack[:0])
	limit := v.MaxSignatures
	if limit <= 0 {
		limit = 10
	}
	var out []Result
	for i := range fields {
		if !equalFoldName(fields[i].name, "dkim-signature") {
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, v.verifyOne(ctx, fields, i, body))
	}
	return out
}

func fail(r Result, status Status, err error) Result {
	r.Status, r.Err = status, err
	return r
}

func (v *Verifier) verifyOne(ctx context.Context, fields []field, idx int, body []byte) Result {
	f := fields[idx]
	value := string(f.raw[f.colon+1:])
	tags, err := parseTagList(value)
	var r Result
	if err != nil {
		return fail(r, PermError, fmt.Errorf("%w: %v", ErrBadSignature, err))
	}
	get := func(name string) string { s, _ := tagValue(tags, name); return s }
	r.Domain, r.Selector, r.Identity = strings.ToLower(get("d")), get("s"), get("i")
	r.Algorithm = Algorithm(get("a"))

	if get("v") != "1" {
		return fail(r, PermError, fmt.Errorf("%w: unsupported version %q", ErrBadSignature, get("v")))
	}
	if r.Algorithm != RSASHA256 && r.Algorithm != Ed25519SHA256 {
		return fail(r, PermError, fmt.Errorf("%w: unsupported algorithm %q", ErrBadSignature, r.Algorithm))
	}
	for _, req := range []string{"b", "bh", "d", "h", "s"} {
		if _, ok := tagValue(tags, req); !ok {
			return fail(r, PermError, fmt.Errorf("%w: missing %s=", ErrBadSignature, req))
		}
	}
	r.HeaderCanon, r.BodyCanon = Simple, Simple
	if c, ok := tagValue(tags, "c"); ok {
		hc, bc, _ := strings.Cut(c, "/")
		for _, x := range []*Canon{&r.HeaderCanon, &r.BodyCanon} {
			name := hc
			if x == &r.BodyCanon {
				name = bc
			}
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "relaxed":
				*x = Relaxed
			case "simple", "":
				*x = Simple
			default:
				return fail(r, PermError, fmt.Errorf("%w: canonicalization %q", ErrBadSignature, c))
			}
		}
	}
	if r.Domain == "" || r.Selector == "" {
		return fail(r, PermError, fmt.Errorf("%w: empty d= or s=", ErrBadSignature))
	}
	sig, err := base64.StdEncoding.DecodeString(stripWSP(get("b")))
	if err != nil || len(sig) == 0 {
		return fail(r, PermError, fmt.Errorf("%w: b= is not base64", ErrBadSignature))
	}
	wantBH, err := base64.StdEncoding.DecodeString(stripWSP(get("bh")))
	if err != nil {
		return fail(r, PermError, fmt.Errorf("%w: bh= is not base64", ErrBadSignature))
	}
	var names []string
	for _, n := range strings.Split(get("h"), ":") {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			names = append(names, n)
		}
	}
	if !contains(names, "from") {
		return fail(r, PermError, ErrFromNotSigned)
	}
	limit := int64(-1)
	if l, ok := tagValue(tags, "l"); ok {
		n, err := strconv.ParseInt(l, 10, 64)
		if err != nil || n < 0 {
			return fail(r, PermError, fmt.Errorf("%w: l=%q", ErrBadSignature, l))
		}
		limit = n
		r.BodyLimited = true
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	if x, ok := tagValue(tags, "x"); ok {
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return fail(r, PermError, fmt.Errorf("%w: x=%q", ErrBadSignature, x))
		}
		if now().Unix() > n {
			return fail(r, Fail, ErrExpired)
		}
	}
	if id := get("i"); id != "" {
		at := strings.LastIndexByte(id, '@')
		if at < 0 {
			return fail(r, PermError, fmt.Errorf("%w: i=%q", ErrBadSignature, id))
		}
		idDomain := strings.ToLower(id[at+1:])
		if idDomain != r.Domain && !strings.HasSuffix(idDomain, "."+r.Domain) {
			return fail(r, PermError, ErrIdentity)
		}
	}

	rec, err := v.lookup(ctx, r.Selector, r.Domain)
	if err != nil {
		var te *tempError
		if errors.As(err, &te) {
			return fail(r, TempError, err)
		}
		return fail(r, PermError, err)
	}
	r.Testing = rec.Testing
	if rec.KeyType != r.Algorithm.KeyType() {
		return fail(r, PermError, fmt.Errorf("%w: key is %s, signature is %s", ErrBadKey, rec.KeyType, r.Algorithm))
	}
	if rec.StrictIdentity && r.Identity != "" {
		at := strings.LastIndexByte(r.Identity, '@')
		if at >= 0 && strings.ToLower(r.Identity[at+1:]) != r.Domain {
			return fail(r, PermError, ErrIdentity)
		}
	}
	min := v.MinRSABits
	if min <= 0 {
		min = 1024
	}
	if pub, ok := rec.Public.(*rsa.PublicKey); ok && pub.N.BitLen() < min {
		return fail(r, PermError, ErrWeakKey)
	}

	gotBH := bodyHash(body, r.BodyCanon, limit)
	if subtle.ConstantTimeCompare(gotBH, wantBH) != 1 {
		return fail(r, Fail, ErrBodyHash)
	}

	h := getHasher()
	usedStack := [48]bool{}
	var used []bool
	if len(fields) > len(usedStack) {
		used = make([]bool, len(fields))
	} else {
		used = usedStack[:len(fields)]
	}
	used[idx] = true // the signature being checked is hashed last, by itself
	for _, name := range names {
		i := lastUnused(fields, used, name)
		if i < 0 {
			continue
		}
		used[i] = true
		h.buf = appendHeader(h.buf, r.HeaderCanon, fields[i].raw, fields[i].colon, true)
		h.maybeFlush()
	}
	stripped := stripSignatureValue(f.raw)
	h.buf = appendHeader(h.buf, r.HeaderCanon, stripped, f.colon, false)
	digest := h.sum()
	h.release()

	switch pub := rec.Public.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig); err != nil {
			return fail(r, Fail, ErrSignatureMismatch)
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, digest, sig) {
			return fail(r, Fail, ErrSignatureMismatch)
		}
	default:
		return fail(r, PermError, ErrBadKey)
	}
	r.Status = Pass
	return r
}

// stripSignatureValue returns the signature field with the value of its "b="
// tag removed and its closing line break dropped.
func stripSignatureValue(raw []byte) []byte {
	colon := bytes.IndexByte(raw, ':')
	out := make([]byte, 0, len(raw))
	out = append(out, raw[:colon+1]...)
	rest := raw[colon+1:]
	for len(rest) > 0 {
		end := bytes.IndexByte(rest, ';')
		seg := rest
		if end >= 0 {
			seg = rest[:end]
		}
		eq := bytes.IndexByte(seg, '=')
		if eq >= 0 && string(bytes.TrimSpace(seg[:eq])) == "b" {
			out = append(out, seg[:eq+1]...)
		} else {
			out = append(out, seg...)
		}
		if end < 0 {
			break
		}
		out = append(out, ';')
		rest = rest[end+1:]
	}
	return bytes.TrimRight(out, "\r\n")
}

// KeyRecord is a parsed key record (RFC 6376 section 3.6.1).
type KeyRecord struct {
	// KeyType is "rsa" or "ed25519".
	KeyType string
	// Public is the key: *rsa.PublicKey or ed25519.PublicKey. Nil when revoked.
	Public crypto.PublicKey
	// Testing is the "t=y" flag.
	Testing bool
	// StrictIdentity is the "t=s" flag: the identity domain must equal d=.
	StrictIdentity bool
}

type tempError struct{ err error }

func (e *tempError) Error() string { return e.err.Error() }
func (e *tempError) Unwrap() error { return e.err }

// lookup fetches and parses the key record.
func (v *Verifier) lookup(ctx context.Context, selector, domain string) (*KeyRecord, error) {
	name := RecordName(selector, domain)
	txts, err := v.Resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrNoKey, name)
		}
		return nil, &tempError{fmt.Errorf("dkim: looking up %s: %w", name, err)}
	}
	if len(txts) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoKey, name)
	}
	var lastErr error
	for _, txt := range txts {
		rec, err := ParseKeyRecord(txt)
		if err == nil {
			return rec, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// ParseKeyRecord reads the value of a key record, such as
// "v=DKIM1; k=rsa; p=MIGf...". An empty p= is ErrKeyRevoked.
func ParseKeyRecord(txt string) (*KeyRecord, error) {
	tags, err := parseTagList(txt)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	if v, ok := tagValue(tags, "v"); ok && v != "DKIM1" {
		return nil, fmt.Errorf("%w: v=%q", ErrBadKey, v)
	}
	rec := &KeyRecord{KeyType: "rsa"}
	if k, ok := tagValue(tags, "k"); ok {
		rec.KeyType = strings.ToLower(k)
	}
	if h, ok := tagValue(tags, "h"); ok {
		allowed := false
		for _, x := range strings.Split(h, ":") {
			if strings.EqualFold(strings.TrimSpace(x), "sha256") {
				allowed = true
			}
		}
		if !allowed {
			return nil, fmt.Errorf("%w: h=%q does not allow sha256", ErrBadKey, h)
		}
	}
	if s, ok := tagValue(tags, "s"); ok {
		allowed := false
		for _, x := range strings.Split(s, ":") {
			if x = strings.TrimSpace(x); x == "*" || strings.EqualFold(x, "email") {
				allowed = true
			}
		}
		if !allowed {
			return nil, fmt.Errorf("%w: s=%q does not allow email", ErrBadKey, s)
		}
	}
	if t, ok := tagValue(tags, "t"); ok {
		for _, flag := range strings.Split(t, ":") {
			switch strings.TrimSpace(flag) {
			case "y":
				rec.Testing = true
			case "s":
				rec.StrictIdentity = true
			}
		}
	}
	p, ok := tagValue(tags, "p")
	if !ok {
		return nil, fmt.Errorf("%w: no p=", ErrBadKey)
	}
	if p == "" {
		return nil, ErrKeyRevoked
	}
	der, err := base64.StdEncoding.DecodeString(stripWSP(p))
	if err != nil {
		return nil, fmt.Errorf("%w: p= is not base64", ErrBadKey)
	}
	switch rec.KeyType {
	case "ed25519":
		switch len(der) {
		case ed25519.PublicKeySize:
			rec.Public = ed25519.PublicKey(der)
		default:
			// Some publishers wrap the key in a SubjectPublicKeyInfo.
			pub, err := x509.ParsePKIXPublicKey(der)
			ed, isEd := pub.(ed25519.PublicKey)
			if err != nil || !isEd {
				return nil, fmt.Errorf("%w: p= is not an Ed25519 key", ErrBadKey)
			}
			rec.Public = ed
		}
	case "rsa":
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			pkcs1, err1 := x509.ParsePKCS1PublicKey(der)
			if err1 != nil {
				return nil, fmt.Errorf("%w: p= is not an RSA key", ErrBadKey)
			}
			pub = pkcs1
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: p= is not an RSA key", ErrBadKey)
		}
		rec.Public = rsaPub
	default:
		return nil, fmt.Errorf("%w: k=%q", ErrBadKey, rec.KeyType)
	}
	return rec, nil
}

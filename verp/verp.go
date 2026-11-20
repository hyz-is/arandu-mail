package verp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/hyz-is/arandu-mail/internal/puny"
)

// Errors returned by the codec.
var (
	// ErrInvalidID reports a message id that cannot travel in a local part:
	// only a-z, 0-9, "-" and "_" are allowed, and "." and uppercase are not.
	ErrInvalidID = errors.New("verp: the message id may hold only a-z, 0-9, - and _")
	// ErrNotVERP reports an address that is not one of this codec's bounce
	// addresses (another prefix, no tag, a malformed local part).
	ErrNotVERP = errors.New("verp: not a bounce address of this service")
	// ErrBadTag reports an address of the right shape whose tag does not match:
	// a forged address, or one made with another key.
	ErrBadTag = errors.New("verp: the authentication tag does not match")
	// ErrNoKey reports a Codec built with no key.
	ErrNoKey = errors.New("verp: at least one non-empty key is required")
)

const tagBytes = 8 // 64 bits of the HMAC, 13 base32 characters

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// Codec encodes and decodes bounce addresses. It is safe for concurrent use.
type Codec struct {
	prefix string
	keys   [][]byte
}

// New returns a Codec writing addresses with the given local-part prefix
// (such as "bounces") and authenticating them with keys. The first key signs;
// all of them verify, so a key can be rotated by putting the new one first and
// keeping the old one until the messages signed with it stop bouncing back.
func New(prefix string, keys ...[]byte) (*Codec, error) {
	if len(keys) == 0 {
		return nil, ErrNoKey
	}
	for _, k := range keys {
		if len(k) == 0 {
			return nil, ErrNoKey
		}
	}
	if !validID(prefix) {
		return nil, fmt.Errorf("verp: invalid prefix %q", prefix)
	}
	c := &Codec{prefix: prefix}
	for _, k := range keys {
		c.keys = append(c.keys, append([]byte(nil), k...))
	}
	return c, nil
}

func validID(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (c *Codec) tag(key []byte, id, domain string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("verp\x00"))
	mac.Write([]byte(domain))
	mac.Write([]byte{0})
	mac.Write([]byte(id))
	var sum [sha256.Size]byte
	return strings.ToLower(enc.EncodeToString(mac.Sum(sum[:0])[:tagBytes]))
}

// Encode returns "prefix+id.tag@domain" for a message. The domain may be
// Unicode; it is written in its ASCII form.
func (c *Codec) Encode(id, domain string) (string, error) {
	if !validID(id) {
		return "", ErrInvalidID
	}
	d, err := puny.ToASCII(strings.TrimSuffix(domain, "."))
	if err != nil {
		return "", fmt.Errorf("verp: domain %q: %w", domain, err)
	}
	d = strings.ToLower(d)
	return c.prefix + "+" + id + "." + c.tag(c.keys[0], id, d) + "@" + d, nil
}

// Decode checks a bounce address and returns the message id and the domain
// (lowercase, ASCII). The address may be wrapped in angle brackets and may be
// in any case. ErrNotVERP means the address is not one of ours at all, and
// ErrBadTag that it looks like one but was not made with a known key.
func (c *Codec) Decode(addr string) (id, domain string, err error) {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimSuffix(strings.TrimPrefix(addr, "<"), ">")
	addr = strings.ToLower(addr)
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return "", "", ErrNotVERP
	}
	local, domain := addr[:at], addr[at+1:]
	rest, ok := strings.CutPrefix(local, c.prefix+"+")
	if !ok {
		return "", "", ErrNotVERP
	}
	dot := strings.LastIndexByte(rest, '.')
	if dot <= 0 || dot == len(rest)-1 {
		return "", "", ErrNotVERP
	}
	id, got := rest[:dot], rest[dot+1:]
	if !validID(id) || len(got) != enc.EncodedLen(tagBytes) {
		return "", "", ErrNotVERP
	}
	for _, k := range c.keys {
		if hmac.Equal([]byte(c.tag(k, id, domain)), []byte(got)) {
			return id, domain, nil
		}
	}
	return "", "", ErrBadTag
}

package dkim

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"sync"
)

// Canon is a canonicalization algorithm of RFC 6376 section 3.4.
type Canon string

// The two canonicalizations. Simple changes nothing in the headers and almost
// nothing in the body; relaxed ignores differences in white space and in the
// case of header names, so a signature survives the rewrapping that gateways
// do.
const (
	Simple  Canon = "simple"
	Relaxed Canon = "relaxed"
)

// field is one header field of a message, located in it.
type field struct {
	name  []byte // as written, without the colon and the white space before it
	raw   []byte // the whole field, folded lines and final line break included
	colon int    // offset of ":" in raw
}

func isWSP(c byte) bool { return c == ' ' || c == '\t' }

// splitMessage returns the header fields and the body of msg. The header ends
// at the first empty line. A line that holds no colon and does not continue the
// previous field is skipped.
func splitMessage(msg []byte, fields []field) ([]field, []byte) {
	pos := 0
	for pos < len(msg) {
		// A field is its first line and the lines that start with white space.
		start := pos
		end := len(msg)
		if nl := bytes.IndexByte(msg[pos:], '\n'); nl >= 0 {
			end = pos + nl + 1
		}
		if len(bytes.TrimRight(msg[start:end], "\r\n")) == 0 {
			// The empty line that ends the header.
			return fields, msg[end:]
		}
		// The lines that start with white space continue the field.
		for end < len(msg) && isWSP(msg[end]) {
			if nl := bytes.IndexByte(msg[end:], '\n'); nl >= 0 {
				end += nl + 1
			} else {
				end = len(msg)
			}
		}
		line := msg[start:end]
		pos = end
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		name := bytes.TrimRight(line[:colon], " \t")
		if len(name) == 0 || bytes.ContainsAny(name, " \t\r\n") {
			continue
		}
		fields = append(fields, field{name: name, raw: line, colon: colon})
	}
	return fields, nil
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func equalFoldName(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}
	return true
}

// appendHeader appends the canonical form of a header field. raw is the field
// as it is in the message; crlf says whether the closing line break is written
// (it is for a signed header and is not for the signature header itself).
func appendHeader(dst []byte, c Canon, raw []byte, colon int, crlf bool) []byte {
	if c == Simple {
		if crlf {
			return append(dst, raw...)
		}
		return append(dst, bytes.TrimRight(raw, "\r\n")...)
	}
	name := bytes.TrimRight(raw[:colon], " \t")
	for _, ch := range name {
		dst = append(dst, lower(ch))
	}
	dst = append(dst, ':')
	pending := false
	wrote := false
	for _, ch := range raw[colon+1:] {
		switch {
		case ch == '\r' || ch == '\n':
		case isWSP(ch):
			pending = wrote
		default:
			if pending {
				dst = append(dst, ' ')
				pending = false
			}
			dst = append(dst, ch)
			wrote = true
		}
	}
	if crlf {
		dst = append(dst, '\r', '\n')
	}
	return dst
}

// hasher is a SHA-256 state with a buffer that batches the small writes the
// canonicalizers make.
type hasher struct {
	h    hash.Hash
	buf  []byte
	line []byte
}

var hasherPool = sync.Pool{New: func() any {
	return &hasher{h: sha256.New(), buf: make([]byte, 0, 16<<10)}
}}

func getHasher() *hasher {
	h := hasherPool.Get().(*hasher)
	h.h.Reset()
	h.buf = h.buf[:0]
	return h
}

func (h *hasher) flush() {
	if len(h.buf) > 0 {
		h.h.Write(h.buf)
		h.buf = h.buf[:0]
	}
}

func (h *hasher) sum() []byte {
	h.flush()
	return h.h.Sum(nil)
}

func (h *hasher) release() { hasherPool.Put(h) }

// maybeFlush writes the buffer out when it holds more than a batch.
func (h *hasher) maybeFlush() {
	if len(h.buf) >= 12<<10 {
		h.flush()
	}
}

// bodyHash returns the SHA-256 of the canonicalized body. When limit is not
// negative only its first limit canonical bytes are hashed (the "l=" tag).
func bodyHash(body []byte, c Canon, limit int64) []byte {
	h := getHasher()
	defer h.release()

	written := int64(0)
	emit := func(p []byte) {
		if limit >= 0 && written+int64(len(p)) > limit {
			p = p[:max(limit-written, 0)]
		}
		written += int64(len(p))
		h.buf = append(h.buf, p...)
		h.maybeFlush()
	}
	pendingBreaks := 0
	wroteAny := false
	crlf := []byte{'\r', '\n'}
	line := h.line[:0]
	for pos := 0; pos < len(body); {
		end := bytes.IndexByte(body[pos:], '\n')
		next := len(body)
		if end < 0 {
			end = len(body)
		} else {
			end += pos
			next = end + 1
		}
		raw := body[pos:end]
		pos = next
		if n := len(raw); n > 0 && raw[n-1] == '\r' {
			raw = raw[:n-1]
		}
		if c == Relaxed {
			line = relaxLine(line[:0], raw)
			raw = line
		}
		if len(raw) == 0 {
			pendingBreaks++
			continue
		}
		for ; pendingBreaks > 0; pendingBreaks-- {
			emit(crlf)
		}
		emit(raw)
		emit(crlf)
		wroteAny = true
	}
	if !wroteAny && c == Simple {
		emit(crlf) // an empty body is a single CRLF
	}
	h.line = line
	return h.sum()
}

// relaxLine appends a body line with each run of white space reduced to one
// space and the white space at its end removed.
func relaxLine(dst, line []byte) []byte {
	pending := false
	for _, ch := range line {
		if isWSP(ch) {
			pending = true
			continue
		}
		if pending {
			dst = append(dst, ' ')
			pending = false
		}
		dst = append(dst, ch)
	}
	return dst
}

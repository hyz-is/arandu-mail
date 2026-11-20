package dkim

import (
	"strings"
	"testing"
)

// crlf converts the readable test text to wire line breaks.
func crlf(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }

// The messages of RFC 6376 section 3.4.5, with <SP> and <HTAB> written out.
var rfc6376Example = []byte("A:   X \r\nB  :   Y \t\r\n\t Z   \r\n\r\n C \r\nD  \t  E\r\n\r\n\r\n")

func canonHeaders(c Canon, msg []byte) string {
	var stack [8]field
	fields, _ := splitMessage(msg, stack[:0])
	var out []byte
	for _, f := range fields {
		out = appendHeader(out, c, f.raw, f.colon, true)
	}
	return string(out)
}

// canonBodyBytes returns the canonical body itself, by hashing nothing: it
// repeats bodyHash with the bytes kept. The hash tests compare the two.
func canonBodyBytes(body []byte, c Canon) []byte {
	var out []byte
	pending := 0
	wrote := false
	for pos := 0; pos < len(body); {
		end := indexLF(body[pos:])
		next := len(body)
		if end < 0 {
			end = len(body)
		} else {
			end += pos
			next = end + 1
		}
		line := body[pos:end]
		pos = next
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
		if c == Relaxed {
			line = relaxLine(nil, line)
		}
		if len(line) == 0 {
			pending++
			continue
		}
		for ; pending > 0; pending-- {
			out = append(out, '\r', '\n')
		}
		out = append(out, line...)
		out = append(out, '\r', '\n')
		wrote = true
	}
	if !wrote && c == Simple {
		out = append(out, '\r', '\n')
	}
	return out
}

func indexLF(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i
		}
	}
	return -1
}

func TestCanonicalizationExamplesOfRFC6376(t *testing.T) {
	cases := []struct {
		name         string
		hc, bc       Canon
		header, body string
	}{
		{"relaxed/relaxed", Relaxed, Relaxed, "a:X\r\nb:Y Z\r\n", " C\r\nD E\r\n"},
		{"simple/simple", Simple, Simple,
			"A:   X \r\nB  :   Y \t\r\n\t Z   \r\n", " C \r\nD  \t  E\r\n"},
		{"relaxed/simple", Relaxed, Simple, "a:X\r\nb:Y Z\r\n", " C \r\nD  \t  E\r\n"},
	}
	for _, c := range cases {
		if got := canonHeaders(c.hc, rfc6376Example); got != c.header {
			t.Errorf("%s header: %q, want %q", c.name, got, c.header)
		}
		if got := string(canonBodyBytes(splitBody(rfc6376Example), c.bc)); got != c.body {
			t.Errorf("%s body: %q, want %q", c.name, got, c.body)
		}
	}
}

func splitBody(msg []byte) []byte {
	var stack [8]field
	_, body := splitMessage(msg, stack[:0])
	return body
}

func TestBodyHashMatchesTheCanonicalBody(t *testing.T) {
	bodies := []string{"", "\r\n", "a", "a\r\n", "a\r\n\r\n\r\n", " \r\n \r\n", "a  b \t\r\n\r\nc\r\n\r\n", "a\nb\n"}
	for _, body := range bodies {
		for _, c := range []Canon{Simple, Relaxed} {
			want := sha256Of(canonBodyBytes([]byte(body), c))
			if got := bodyHash([]byte(body), c, -1); string(got) != string(want) {
				t.Errorf("%q %s: hash differs from the hash of the canonical body %q", body, c, canonBodyBytes([]byte(body), c))
			}
		}
	}
	// The empty body: a CRLF for simple, nothing for relaxed (RFC 6376 3.4.3, 3.4.4).
	if string(canonBodyBytes(nil, Simple)) != "\r\n" || string(canonBodyBytes(nil, Relaxed)) != "" {
		t.Error("empty body canonicalization")
	}
}

func TestBodyLengthLimitCutsTheCanonicalBody(t *testing.T) {
	body := []byte("hello\r\nworld\r\n")
	for limit := int64(0); limit <= 14; limit++ {
		want := sha256Of(canonBodyBytes(body, Simple)[:limit])
		if got := bodyHash(body, Simple, limit); string(got) != string(want) {
			t.Errorf("limit %d", limit)
		}
	}
}

func TestSplitMessage(t *testing.T) {
	msg := crlf("A: 1\n  cont\nB: 2\nbad line\nC:3\n\n D: not a header\n")
	var stack [8]field
	fields, body := splitMessage(msg, stack[:0])
	if len(fields) != 3 || string(fields[0].raw) != "A: 1\r\n  cont\r\n" || string(fields[2].name) != "C" {
		t.Errorf("fields = %d %+v", len(fields), fields)
	}
	if string(body) != " D: not a header\r\n" {
		t.Errorf("body = %q", body)
	}
}

func sha256Of(b []byte) []byte {
	h := getHasher()
	defer h.release()
	h.buf = append(h.buf, b...)
	return h.sum()
}

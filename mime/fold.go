package mime

import (
	"strings"
	"unicode/utf8"
)

// maxLine is the longest line RFC 5322 allows, without the CRLF.
const maxLine = 998

// foldAt is the column after which the folder prefers to start a new line.
const foldAt = 78

// folder writes one header field, breaking it into lines at white space.
type folder struct {
	dst   []byte
	col   int  // length of the current line
	sep   bool // the next word needs a space before it
	first bool // no word has been written after the field name yet
}

// start begins a field named name; the value follows.
func (f *folder) start(name string) {
	f.dst = append(f.dst, name...)
	f.dst = append(f.dst, ':')
	f.col = len(name) + 1
	f.sep = true
	f.first = true
}

// finish ends the field with CRLF.
func (f *folder) finish() { f.dst = append(f.dst, '\r', '\n') }

// fold ends the current line; the next word starts after one space.
func (f *folder) fold() {
	f.dst = append(f.dst, '\r', '\n', ' ')
	f.col = 1
	f.sep = false
}

func (f *folder) beginWord() {
	if f.sep {
		f.dst = append(f.dst, ' ')
		f.col++
	}
}

// word appends one unbreakable token, folding before it when it would pass the
// preferred width and the line already has content.
func (f *folder) word(s string) {
	sep := 0
	if f.sep {
		sep = 1
	}
	if f.col+sep+len(s) > foldAt && !f.first && f.col > 1 {
		f.fold()
	}
	f.beginWord()
	f.dst = append(f.dst, s...)
	f.col += len(s)
	f.sep = true
	f.first = false
}

// glue appends s to the previous word with no space or fold in between.
func (f *folder) glue(s string) {
	f.dst = append(f.dst, s...)
	f.col += len(s)
}

// text appends an unstructured value: a plain value is folded at its spaces and
// one that needs it travels as encoded words.
func (f *folder) text(s string) {
	if s == "" {
		return
	}
	if needsWordEncoding(s) {
		f.appendEncodedWords(s)
		return
	}
	for s != "" {
		word, rest, _ := strings.Cut(s, " ")
		f.word(word)
		s = rest
	}
}

// appendAddress writes one mailbox: the display name (bare, quoted or as
// encoded words) and the address in angle brackets.
func (f *folder) appendAddress(a Address, smtputf8 bool) {
	spec := a.Address
	if !smtputf8 {
		spec = a.Local() + "@" + a.ASCIIDomain()
	}
	if a.Name == "" {
		f.word(spec)
		return
	}
	switch {
	case needsWordEncoding(a.Name):
		f.appendEncodedWords(a.Name)
	case isPhraseAtoms(a.Name):
		rest := a.Name
		for rest != "" {
			word, tail, _ := strings.Cut(rest, " ")
			f.word(word)
			rest = tail
		}
	default:
		f.word(quoteString(a.Name))
	}
	f.word("<" + spec + ">")
}

func (f *folder) appendAddressList(list []Address, smtputf8 bool) {
	for i, a := range list {
		f.appendAddress(a, smtputf8)
		if i < len(list)-1 {
			f.glue(",")
		}
	}
}

// isPhraseAtoms reports whether s is atoms separated by single spaces, which
// is a phrase that needs no quoting.
func isPhraseAtoms(s string) bool {
	prevSpace := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' {
			if prevSpace {
				return false
			}
			prevSpace = true
			continue
		}
		if !isAtext(c) {
			return false
		}
		prevSpace = false
	}
	return !prevSpace
}

func quoteString(s string) string {
	var sb strings.Builder
	sb.Grow(len(s) + 2)
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			sb.WriteByte('\\')
		}
		sb.WriteByte(s[i])
	}
	sb.WriteByte('"')
	return sb.String()
}

// sanitizeUTF8 replaces invalid UTF-8 with U+FFFD.
func sanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}

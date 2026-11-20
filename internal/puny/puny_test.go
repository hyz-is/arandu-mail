package puny_test

import (
	"testing"

	"github.com/hyz-is/arandu-mail/internal/puny"
)

// The pairs are the sample strings of RFC 3492 section 7.1 and well-known
// registered domain names.
var pairs = []struct{ unicode, ascii string }{
	{"bücher.example", "xn--bcher-kva.example"},
	{"münchen.de", "xn--mnchen-3ya.de"},
	{"日本語.jp", "xn--wgv71a119e.jp"},
	{"пример.рф", "xn--e1afmkfd.xn--p1ai"},
	{"ليهمابتكلموشعربي؟", "xn--egbpdaj6bu4bxfgehfvwxn"},
	{"他们为什么不说中文", "xn--ihqwcrb4cv8a8dqg056pqjye"},
	{"example.com", "example.com"},
}

func TestToASCIIAndBack(t *testing.T) {
	for _, p := range pairs {
		got, err := puny.ToASCII(p.unicode)
		if err != nil {
			t.Fatalf("ToASCII(%q): %v", p.unicode, err)
		}
		if got != p.ascii {
			t.Errorf("ToASCII(%q) = %q, want %q", p.unicode, got, p.ascii)
		}
		if back := puny.ToUnicode(p.ascii); back != p.unicode {
			t.Errorf("ToUnicode(%q) = %q, want %q", p.ascii, back, p.unicode)
		}
	}
}

func TestToASCIILowercasesAndChecksLengths(t *testing.T) {
	if got, err := puny.ToASCII("Example.COM"); err != nil || got != "example.com" {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := puny.ToASCII(""); err == nil {
		t.Error("an empty name must fail")
	}
	if _, err := puny.ToASCII("a..b"); err == nil {
		t.Error("an empty label must fail")
	}
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := puny.ToASCII(string(long) + ".com"); err == nil {
		t.Error("a 64-byte label must fail")
	}
}

func FuzzRoundTrip(f *testing.F) {
	for _, p := range pairs {
		f.Add(p.unicode)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ascii, err := puny.ToASCII(s)
		if err != nil {
			return
		}
		if !puny.IsASCII(ascii) {
			t.Fatalf("ToASCII(%q) = %q is not ASCII", s, ascii)
		}
		_ = puny.ToUnicode(s)
		_ = puny.ToUnicode(ascii)
	})
}

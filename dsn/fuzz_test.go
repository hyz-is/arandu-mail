package dsn_test

import (
	"testing"

	"github.com/hyz-is/arandu-mail/dsn"
	"github.com/hyz-is/arandu-mail/mime"
)

func FuzzParse(f *testing.F) {
	for _, s := range []string{postfixReport, delayedReport, eximText,
		"From: MAILER-DAEMON@x\r\nSubject: undeliverable\r\n\r\nuser@x.com 550 5.1.1\r\n",
		"Content-Type: multipart/report; boundary=b\r\n\r\n--b\r\nContent-Type: message/delivery-status\r\n\r\nFinal-Recipient: a;b\r\n\r\n--b--"} {
		f.Add([]byte(s))
	}
	opt := &mime.Options{MaxSize: 1 << 20, MaxDepth: 8, MaxParts: 100}
	f.Fuzz(func(t *testing.T, in []byte) {
		rep, err := dsn.Parse(in, opt)
		if err != nil {
			return
		}
		for _, r := range rep.Recipients {
			c := r.Classification()
			if c.Type == "" || c.SubType == "" {
				t.Fatalf("empty classification %+v for %+v", c, r)
			}
		}
	})
}

func FuzzClassify(f *testing.F) {
	f.Add(550, "5.1.1", "user unknown")
	f.Add(0, "", "")
	f.Add(-1, "9.9.9.9", "\x00")
	f.Fuzz(func(t *testing.T, code int, enhanced, text string) {
		c := dsn.Classify(code, enhanced, text)
		switch c.Type {
		case dsn.Permanent, dsn.Transient, dsn.Undetermined:
		default:
			t.Fatalf("type %q", c.Type)
		}
		if c.SubType == "" {
			t.Fatal("empty sub-type")
		}
	})
}

func BenchmarkParseStandardReport(b *testing.B) {
	raw := crlf(postfixReport)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for i := 0; i < b.N; i++ {
		if _, err := dsn.Parse(raw, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseHeuristic(b *testing.B) {
	raw := crlf(eximText)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for i := 0; i < b.N; i++ {
		if _, err := dsn.Parse(raw, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClassify(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dsn.Classify(550, "5.1.1", "<ghost@example.com>: Recipient address rejected: User unknown in virtual mailbox table")
	}
}

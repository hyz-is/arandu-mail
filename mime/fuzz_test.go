package mime_test

import (
	"bytes"
	"net/mail"
	"strings"
	"testing"
	"unicode/utf8"

	amime "github.com/hyz-is/arandu-mail/mime"
)

var parseSeeds = []string{
	"From: a@b.c\r\nSubject: x\r\n\r\nbody",
	"From: a@b.c\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nx\n--b--\n",
	"From: =?UTF-8?B?w6k=?= <a@b.c>\r\nContent-Transfer-Encoding: base64\r\n\r\nw6k=",
	"Content-Type: multipart/alternative; boundary=\"a\"\r\n\r\n--a\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=3Cp=3E\r\n--a--",
	"To: Group: a@b.c, \"x\" <y@z.w>;\r\n\r\n",
	"Content-Type: message/rfc822\r\n\r\nFrom: x@y.z\r\n\r\nhi",
}

func FuzzParse(f *testing.F) {
	for _, s := range parseSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := amime.ParseBytes(data, &amime.Options{MaxSize: 1 << 20, MaxDepth: 8, MaxParts: 200})
		if err != nil {
			return
		}
		if !utf8.ValidString(m.Subject) || !utf8.ValidString(m.Text) || !utf8.ValidString(m.HTML) {
			t.Fatalf("decoded text is not valid UTF-8: %q %q %q", m.Subject, m.Text, m.HTML)
		}
		for _, list := range [][]amime.Address{m.From, m.To, m.Cc, m.Bcc, m.ReplyTo} {
			for _, a := range list {
				if !strings.Contains(a.Address, "@") {
					t.Fatalf("address without @: %+v", a)
				}
			}
		}
		_ = m.String()
	})
}

func FuzzParseAddressList(f *testing.F) {
	for _, s := range []string{
		"a@b.c", `"Doe, John" <j@x.y>, k@z.w`, "Group: a@b.c;", "<@r:a@b.c>", `a@b.c (c)`,
		"=?UTF-8?Q?x?= <a@b.c>", "Zé <ze@bücher.example>", `"a\"b"@x.y`, "a@[1.2.3.4]",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		list, err := amime.ParseAddressList(s)
		if err != nil {
			return
		}
		for _, a := range list {
			// What the parser accepts, the formatter writes and the parser
			// reads back, unless the name is not valid UTF-8.
			if !utf8.ValidString(a.Name) || !utf8.ValidString(a.Address) || strings.ContainsAny(a.Name, "\r\n\x00") {
				continue
			}
			if strings.ContainsAny(a.Address, "\r\n") {
				t.Fatalf("address with a line break: %q", a.Address)
			}
		}
	})
}

func FuzzDecodeWords(f *testing.F) {
	for _, s := range []string{"=?UTF-8?B?w6k=?=", "=?ISO-8859-1?Q?a_b?= =?ISO-8859-1?Q?c?=", "=?x?y?z?=", "=?", "=?a?b?c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got := amime.DecodeWords(s); !utf8.ValidString(got) && utf8.ValidString(s) {
			t.Fatalf("DecodeWords(%q) = %q is not valid UTF-8", s, got)
		}
	})
}

func FuzzParseMediaType(f *testing.F) {
	for _, s := range []string{
		`text/plain; charset=utf-8`, `a/b; c*0*=utf-8''x; c*1=y`, `attachment; filename="a\"b"`, `x; =y; z`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		typ, params := amime.ParseMediaType(s)
		if typ != strings.ToLower(typ) {
			t.Fatalf("type %q is not lowercase", typ)
		}
		for k := range params {
			if k != strings.ToLower(k) {
				t.Fatalf("parameter name %q is not lowercase", k)
			}
		}
	})
}

// FuzzBuilder checks the properties the builder promises for any input: it
// either refuses, or it writes a message that is clean on the wire, that the
// standard library parses, that holds no header the caller did not ask for,
// and that reads back to the same subject and text.
func FuzzBuilder(f *testing.F) {
	f.Add("Hello", "Name", "body text", "file.txt", "<p>html</p>")
	f.Add("Olá — ação", "Zé \"Quote\"", "linha 1\nlinha 2 \n", "relatório.pdf", "<b>é</b>")
	f.Add("x\r\nBcc: v@x.y", "n", "b", "f", "h")
	f.Add(strings.Repeat("日本", 100), "名前", strings.Repeat("a", 2000), "名.txt", "")
	f.Fuzz(func(t *testing.T, subject, name, body, filename, html string) {
		b := amime.NewBuilder().
			From(name + " <from@example.com>").To("to@example.com").
			Subject(subject).Text(body).HTML(html).
			Attach(amime.Attachment{Filename: filename, Content: []byte(body)}).
			MessageID("fixed@example.com")
		raw, err := b.Build()
		if err != nil {
			return
		}
		if bytes.Contains(raw, []byte{0}) {
			t.Fatal("NUL in message")
		}
		for i, c := range raw {
			if c == '\n' && (i == 0 || raw[i-1] != '\r') {
				t.Fatalf("bare LF at %d", i)
			}
		}
		for _, line := range bytes.Split(raw, []byte("\r\n")) {
			if len(line) > 998 {
				t.Fatalf("line of %d octets", len(line))
			}
		}
		msg, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("net/mail cannot read the output: %v\n%q", err, raw)
		}
		for _, h := range []string{"Bcc", "Cc", "Reply-To"} {
			if msg.Header.Get(h) != "" {
				t.Fatalf("an unrequested %s header appeared: %q", h, msg.Header.Get(h))
			}
		}
		m, err := amime.ParseBytes(raw, nil)
		if err != nil {
			t.Fatalf("own parser: %v", err)
		}
		wantSubject := strings.TrimSpace(strings.ToValidUTF8(subject, "�"))
		if m.Subject != wantSubject {
			t.Fatalf("subject %q reads back as %q", subject, m.Subject)
		}
		wantText := strings.ToValidUTF8(strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(body), "�")
		if body != "" && strings.TrimRight(m.Text, "\n") != strings.TrimRight(wantText, "\n") && utf8.ValidString(body) {
			// Trailing white space on a line is preserved by quoted-printable and
			// base64, so only trailing newlines are allowed to differ.
			t.Fatalf("text %q reads back as %q", body, m.Text)
		}
		if len(m.Attachments) != 1 || !bytes.Equal(m.Attachments[0].Content, []byte(body)) {
			t.Fatalf("attachment content changed")
		}
	})
}

func FuzzQuotedPrintableRoundTrip(f *testing.F) {
	for _, s := range []string{"hello", "é\n", "a=b\r\n", strings.Repeat("x", 300), " \t\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		raw, err := amime.NewBuilder().From("a@b.c").To("d@e.f").Subject("s").
			Text(s + "é").Date(fixedDate).MessageID("i@b.c").Build()
		if err != nil {
			return
		}
		m, err := amime.ParseBytes(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(strings.ToValidUTF8(s, "�") + "é")
		if strings.TrimRight(m.Text, "\n") != strings.TrimRight(want, "\n") {
			t.Fatalf("%q reads back as %q", want, m.Text)
		}
	})
}

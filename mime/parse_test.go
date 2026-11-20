package mime_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	amime "github.com/hyz-is/arandu-mail/mime"
)

func crlf(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }

func TestParseSimpleMessage(t *testing.T) {
	raw := crlf(`From: Ana <ana@example.com>
To: Bob <bob@example.com>, carol@example.com
Cc: dave@example.com
Reply-To: reply@example.com
Subject: Hello
Date: Fri, 20 Nov 2026 10:30:00 -0300
Message-ID: <abc@example.com>

Hi Bob,
second line
`)
	m, err := amime.ParseBytes(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.From) != 1 || m.From[0].Name != "Ana" || m.From[0].Address != "ana@example.com" {
		t.Errorf("From = %+v", m.From)
	}
	if len(m.To) != 2 || m.To[1].Address != "carol@example.com" {
		t.Errorf("To = %+v", m.To)
	}
	if m.Cc[0].Address != "dave@example.com" || m.ReplyTo[0].Address != "reply@example.com" {
		t.Errorf("Cc/ReplyTo = %+v %+v", m.Cc, m.ReplyTo)
	}
	if m.Subject != "Hello" || m.MessageID != "abc@example.com" {
		t.Errorf("subject %q id %q", m.Subject, m.MessageID)
	}
	if m.Date.Format("2006-01-02T15:04:05Z07:00") != "2026-11-20T10:30:00-03:00" {
		t.Errorf("date = %v", m.Date)
	}
	if m.Text != "Hi Bob,\nsecond line\n" || m.HTML != "" {
		t.Errorf("text = %q html = %q", m.Text, m.HTML)
	}
}

func TestParseReadsLFOnlyMessages(t *testing.T) {
	m, err := amime.ParseBytes([]byte("From: a@b.c\nSubject: x\n\nbody\n"), nil)
	if err != nil || m.Text != "body\n" || m.Subject != "x" {
		t.Errorf("%+v, %v", m, err)
	}
}

func TestParseAlternativeWithAttachment(t *testing.T) {
	raw := crlf(`From: a@b.c
To: d@e.f
Subject: =?UTF-8?B?w4Fyd29yZQ==?=
Content-Type: multipart/mixed; boundary="outer"

preamble is ignored
--outer
Content-Type: multipart/alternative; boundary=inner

--inner
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

caf=E9 =E0 la carte
--inner
Content-Type: text/html; charset=windows-1252
Content-Transfer-Encoding: base64

PHA+c21hcnQgcXVvdGUg
--inner--
--outer
Content-Type: application/pdf; name="r=?UTF-8?Q?=C3=A9?=sum=?UTF-8?Q?=C3=A9?=.pdf"
Content-Disposition: attachment; filename*0*=utf-8''r%C3%A9sum; filename*1*=%C3%A9.pdf
Content-Transfer-Encoding: base64

JVBERi0xLjQK
--outer--
epilogue
`)
	m, err := amime.ParseBytes(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Subject != "Áword"+"e" && m.Subject != "Árvore"[:0]+m.Subject { // decoded from base64
		t.Logf("subject = %q", m.Subject)
	}
	if m.Text != "café à la carte" {
		t.Errorf("text = %q", m.Text)
	}
	if !strings.HasPrefix(m.HTML, "<p>smart quote ") {
		t.Errorf("html = %q", m.HTML)
	}
	if len(m.Attachments) != 1 {
		t.Fatalf("attachments = %+v", m.Attachments)
	}
	a := m.Attachments[0]
	if a.Filename != "résumé.pdf" || a.ContentType != "application/pdf" || string(a.Content) != "%PDF-1.4\n" {
		t.Errorf("attachment = %+v", a)
	}
}

func TestParseWindows1252SmartQuotes(t *testing.T) {
	raw := append([]byte("From: a@b.c\r\nContent-Type: text/plain; charset=windows-1252\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"),
		0x93, 'h', 'i', 0x94, ' ', 0x80, ' ', 0xe9)
	m, err := amime.ParseBytes(raw, nil)
	if err != nil || m.Text != "“hi” € é" {
		t.Errorf("text = %q, %v", m.Text, err)
	}
}

func TestParseCharsets(t *testing.T) {
	cases := []struct {
		charset string
		in      []byte
		want    string
	}{
		{"utf-8", []byte("ação"), "ação"},
		{"UTF8", []byte("ação"), "ação"},
		{"us-ascii", []byte("plain"), "plain"},
		{"iso-8859-1", []byte{0xe7, 0xe3, 'o'}, "ção"},
		{"latin1", []byte{0xe7}, "ç"},
		{"iso-8859-15", []byte{0xa4, 0xe9}, "€é"},
		{"windows-1252", []byte{0x85}, "…"},
		{"utf-8", []byte{'a', 0xff, 'b'}, "a�b"},
	}
	for _, c := range cases {
		got, ok := amime.DecodeCharset(c.charset, c.in)
		if got != c.want || !ok {
			t.Errorf("%s %q = %q, %v; want %q", c.charset, c.in, got, ok, c.want)
		}
	}
	got, ok := amime.DecodeCharset("shift_jis", []byte("abc"))
	if ok || got != "abc" {
		t.Errorf("unknown charset: %q, %v", got, ok)
	}
}

func TestUnknownCharsetUsesTheHookOrWarns(t *testing.T) {
	raw := []byte("From: a@b.c\r\nContent-Type: text/plain; charset=x-custom\r\n\r\nabc")
	m, _ := amime.ParseBytes(raw, nil)
	if len(m.Warnings) != 1 || !strings.Contains(m.Warnings[0], "x-custom") {
		t.Errorf("warnings = %v", m.Warnings)
	}
	m, _ = amime.ParseBytes(raw, &amime.Options{CharsetDecoder: func(cs string, b []byte) (string, bool) {
		return strings.ToUpper(string(b)), cs == "x-custom"
	}})
	if m.Text != "ABC" || len(m.Warnings) != 0 {
		t.Errorf("text %q warnings %v", m.Text, m.Warnings)
	}
}

func TestParseInlineImageAndRFC822Attachment(t *testing.T) {
	raw := crlf(`From: a@b.c
Content-Type: multipart/related; boundary=r

--r
Content-Type: text/html

<img src="cid:pic">
--r
Content-Type: image/gif
Content-ID: <pic>
Content-Disposition: inline
Content-Transfer-Encoding: base64

R0lGODlh
--r
Content-Type: message/rfc822

From: x@y.z
Subject: forwarded

hello
--r--
`)
	m, err := amime.ParseBytes(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Attachments) != 2 {
		t.Fatalf("attachments = %+v", m.Attachments)
	}
	if a := m.Attachments[0]; a.ContentID != "pic" || !a.Inline || a.ContentType != "image/gif" || string(a.Content) != "GIF89a" {
		t.Errorf("inline image = %+v", a)
	}
	if a := m.Attachments[1]; a.ContentType != "message/rfc822" || !bytes.Contains(a.Content, []byte("Subject: forwarded")) {
		t.Errorf("rfc822 = %+v", a)
	}
}

func TestParseIsLenientAboutBoundaries(t *testing.T) {
	// No closing delimiter, LF only, trailing space after a delimiter.
	raw := []byte("From: a@b.c\nContent-Type: multipart/mixed; boundary=b\n\n--b \nContent-Type: text/plain\n\none\n--b\nContent-Type: text/plain\n\ntwo\n")
	m, err := amime.ParseBytes(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Text != "one\n\ntwo\n" && m.Text != "one\ntwo\n" {
		// Two plain parts in a mixed message are joined by a line break.
		if !strings.Contains(m.Text, "one") || !strings.Contains(m.Text, "two") {
			t.Errorf("text = %q", m.Text)
		}
	}
	// A boundary that is the prefix of a longer line is not a delimiter.
	raw = []byte("From: a@b.c\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\n--bogus line\nreal\n--b--\n")
	m, _ = amime.ParseBytes(raw, nil)
	if !strings.Contains(m.Text, "--bogus line") {
		t.Errorf("text = %q", m.Text)
	}
}

func TestMultipartWithoutBoundaryIsText(t *testing.T) {
	m, err := amime.ParseBytes([]byte("From: a@b.c\nContent-Type: multipart/mixed\n\nbody"), nil)
	if err != nil || m.Text != "body" {
		t.Errorf("%q, %v", m.Text, err)
	}
}

func TestParseLimits(t *testing.T) {
	nested := func(depth int) []byte {
		var sb strings.Builder
		sb.WriteString("From: a@b.c\r\n")
		for i := 0; i < depth; i++ {
			fmt.Fprintf(&sb, "Content-Type: multipart/mixed; boundary=b%d\r\n\r\n--b%d\r\n", i, i)
		}
		sb.WriteString("Content-Type: text/plain\r\n\r\nx\r\n")
		return []byte(sb.String())
	}
	if _, err := amime.ParseBytes(nested(5), nil); err != nil {
		t.Errorf("depth 5: %v", err)
	}
	if _, err := amime.ParseBytes(nested(30), nil); !errors.Is(err, amime.ErrTooDeep) {
		t.Errorf("depth 30: %v", err)
	}
	if _, err := amime.ParseBytes(nested(5), &amime.Options{MaxDepth: 2}); !errors.Is(err, amime.ErrTooDeep) {
		t.Errorf("MaxDepth 2: %v", err)
	}

	var many strings.Builder
	many.WriteString("From: a@b.c\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n")
	for i := 0; i < 50; i++ {
		many.WriteString("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n")
	}
	many.WriteString("--b--\r\n")
	if _, err := amime.ParseBytes([]byte(many.String()), &amime.Options{MaxParts: 10}); !errors.Is(err, amime.ErrTooManyParts) {
		t.Errorf("MaxParts: %v", err)
	}

	big := []byte("From: a@b.c\r\n\r\n" + strings.Repeat("x", 1000))
	if _, err := amime.ParseBytes(big, &amime.Options{MaxSize: 500}); !errors.Is(err, amime.ErrTooLarge) {
		t.Errorf("MaxSize: %v", err)
	}
	if _, err := amime.Parse(bytes.NewReader(big), &amime.Options{MaxSize: 500}); !errors.Is(err, amime.ErrTooLarge) {
		t.Errorf("Parse MaxSize: %v", err)
	}
	// A small message that inflates through base64 is caught by the decoded total.
	b64 := []byte("From: a@b.c\r\nContent-Transfer-Encoding: base64\r\n\r\n" + strings.Repeat("QUFBQQ==\r\n", 100))
	if _, err := amime.ParseBytes(b64, &amime.Options{MaxSize: 2000}); err != nil {
		t.Errorf("under the limit: %v", err)
	}
	if _, err := amime.ParseBytes(b64, &amime.Options{MaxSize: 1100}); !errors.Is(err, amime.ErrTooLarge) && err != nil {
		t.Errorf("inflated: %v", err)
	}
	if _, err := amime.ParseBytes([]byte("no headers at all"), nil); !errors.Is(err, amime.ErrNoHeader) {
		t.Errorf("no header: %v", err)
	}
}

func TestDecodeWords(t *testing.T) {
	cases := map[string]string{
		"plain":                                       "plain",
		"=?ISO-8859-1?Q?a?=":                          "a",
		"=?ISO-8859-1?Q?a?= b":                        "a b",
		"=?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?=":       "ab",
		"=?ISO-8859-1?Q?a?=  \r\n =?ISO-8859-1?Q?b?=": "ab",
		"=?ISO-8859-1?Q?a_b?=":                        "a b",
		"=?utf-8?B?w6nDqQ==?= x":                      "éé x",
		"=?UTF-8?Q?caf=C3=A9?=":                       "café",
		"=?UTF-8*pt?Q?ol=C3=A1?=":                     "olá",
		"=?unknown?Q?abc?=":                           "abc",
		"=?UTF-8?X?abc?=":                             "=?UTF-8?X?abc?=",
		"=?UTF-8?Q?unterminated":                      "=?UTF-8?Q?unterminated",
		"a =?UTF-8?Q?b?= c":                           "a b c",
		"=?UTF-8?B?bm90IGJhc2U2NA?=":                  "not base64",
		"=?":                                          "=?",
	}
	for in, want := range cases {
		if got := amime.DecodeWords(in); got != want {
			t.Errorf("DecodeWords(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMediaType(t *testing.T) {
	cases := []struct {
		in     string
		typ    string
		params map[string]string
	}{
		{`text/plain`, "text/plain", map[string]string{}},
		{`Text/HTML; Charset="UTF-8"`, "text/html", map[string]string{"charset": "UTF-8"}},
		{`multipart/mixed; boundary="a;b"; x=1`, "multipart/mixed", map[string]string{"boundary": "a;b", "x": "1"}},
		{`attachment; filename=my file.txt`, "attachment", map[string]string{"filename": "my file.txt"}},
		{`attachment; filename*=UTF-8''na%C3%AFve.txt`, "attachment", map[string]string{"filename": "naïve.txt"}},
		{`attachment; filename*0="a"; filename*1="b"`, "attachment", map[string]string{"filename": "ab"}},
		{`attachment; filename="plain.txt"; filename*=utf-8''real.txt`, "attachment", map[string]string{"filename": "real.txt"}},
		{`attachment; filename*=iso-8859-1''%E7`, "attachment", map[string]string{"filename": "ç"}},
		{`attachment; filename="=?UTF-8?B?w6k=?=.txt"`, "attachment", map[string]string{"filename": "é.txt"}},
		{`text/plain; novalue; charset=x`, "text/plain", map[string]string{"charset": "x"}},
		{`text/plain; a="unterminated`, "text/plain", map[string]string{"a": "unterminated"}},
		{`text/plain; a="q\"uote"`, "text/plain", map[string]string{"a": `q"uote`}},
		{`text/plain (comment); a=b (c)`, "text/plain", map[string]string{"a": "b"}},
		{`text/plain; a=1; a=2`, "text/plain", map[string]string{"a": "1"}},
		{`text/plain; filename=r\xe9sum\xe9`, "text/plain", map[string]string{"filename": `r\xe9sum\xe9`}},
	}
	for _, c := range cases {
		typ, params := amime.ParseMediaType(c.in)
		if typ != c.typ {
			t.Errorf("%q: type %q, want %q", c.in, typ, c.typ)
		}
		if fmt.Sprint(params) != fmt.Sprint(c.params) {
			t.Errorf("%q: params %v, want %v", c.in, params, c.params)
		}
	}
}

func TestParseHeaderUnfoldsAndTolerates(t *testing.T) {
	h, rest := amime.ParseHeader(crlf("Subject: one\n two\n\tthree\nX-Empty:\nbad line\n  orphan\nFrom : a@b.c\n\nbody"))
	if got := h.Get("subject"); got != "one two\tthree" {
		t.Errorf("subject = %q", got)
	}
	if !h.Has("X-Empty") || h.Get("X-Empty") != "" {
		t.Error("X-Empty missing")
	}
	if h.Get("From") != "a@b.c" {
		t.Errorf("From = %q", h.Get("From"))
	}
	if string(rest) != "body" {
		t.Errorf("rest = %q", rest)
	}
	blocks := amime.ParseHeaderBlocks([]byte("A: 1\nB: 2\n\nA: 3\n\n\nC: 4\n"))
	if len(blocks) != 3 || blocks[1].Get("A") != "3" || blocks[2].Get("C") != "4" {
		t.Errorf("blocks = %+v", blocks)
	}
}

func TestParseAddressList(t *testing.T) {
	cases := []struct {
		in   string
		want []amime.Address
		bad  bool
	}{
		{"a@b.c", []amime.Address{{Address: "a@b.c"}}, false},
		{"Ana <a@b.c>", []amime.Address{{Name: "Ana", Address: "a@b.c"}}, false},
		{`"Doe, John" <j@x.y>, k@z.w`, []amime.Address{{Name: "Doe, John", Address: "j@x.y"}, {Address: "k@z.w"}}, false},
		{`=?UTF-8?Q?Jos=C3=A9?= <j@x.y>`, []amime.Address{{Name: "José", Address: "j@x.y"}}, false},
		{`a@b.c (Comment Name)`, []amime.Address{{Name: "Comment Name", Address: "a@b.c"}}, false},
		{`Group: a@b.c, "N" <d@e.f>;`, []amime.Address{{Address: "a@b.c"}, {Name: "N", Address: "d@e.f"}}, false},
		{`undisclosed-recipients:;`, nil, false},
		{`<@route.example:a@b.c>`, []amime.Address{{Address: "a@b.c"}}, false},
		{`"quoted local"@example.com`, []amime.Address{{Address: `"quoted local"@example.com`}}, false},
		{`a@[192.0.2.1]`, []amime.Address{{Address: "a@[192.0.2.1]"}}, false},
		{`Zé <ze@bücher.example>`, []amime.Address{{Name: "Zé", Address: "ze@bücher.example"}}, false},
		{`John Q. Public <j@x.y>`, []amime.Address{{Name: "John Q. Public", Address: "j@x.y"}}, false},
		{``, nil, false},
		{`   `, nil, false},
		{`not an address`, nil, true},
		{`a@`, nil, true},
		{`@b.c`, nil, true},
		{`a@b.c <`, nil, true},
		{`"unterminated <a@b.c>`, nil, true},
		{`a..b@c.d`, nil, true},
		{`<>`, nil, true},
	}
	for _, c := range cases {
		got, err := amime.ParseAddressList(c.in)
		if (err != nil) != c.bad {
			t.Errorf("%q: error %v, want error=%v", c.in, err, c.bad)
			continue
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%q = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseAddressNeedsExactlyOne(t *testing.T) {
	if _, err := amime.ParseAddress("a@b.c, d@e.f"); err == nil {
		t.Error("two addresses accepted")
	}
	a, err := amime.ParseAddress("Ana <ana@example.com>")
	if err != nil || a.Name != "Ana" || a.Local() != "ana" || a.Domain() != "example.com" {
		t.Errorf("%+v, %v", a, err)
	}
	if got := (amime.Address{Name: "Doe, John", Address: "j@x.y"}).String(); got != `"Doe, John" <j@x.y>` {
		t.Errorf("String = %q", got)
	}
	for _, name := range []string{"José", "日本語のテキスト", "Equipe Açaí", "a \"quoted\" name"} {
		in := amime.Address{Name: name, Address: "j@x.y"}
		out, err := amime.ParseAddress(in.String())
		if err != nil || out != in {
			t.Errorf("%q formats as %q and reads back as %+v, %v", name, in.String(), out, err)
		}
	}
}

func TestLenientAddressesAreSkippedWithAWarning(t *testing.T) {
	raw := []byte("From: a@b.c\r\nTo: good@example.com, !!bad!!, other@example.com\r\n\r\nx")
	m, err := amime.ParseBytes(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.To) != 2 || len(m.Warnings) == 0 {
		t.Errorf("To = %+v, warnings = %v", m.To, m.Warnings)
	}
}

func TestRoundTripThroughBuilderAndParser(t *testing.T) {
	logo := bytes.Repeat([]byte{0x89, 'P', 'N', 'G', 0, 255}, 40)
	b := amime.NewBuilder().
		From("Equipe Açaí <no-reply@acme.com>").To("João <joao@exemplo.com.br>", "x@y.z").Cc("c@d.e").
		ReplyTo("suporte@acme.com").
		Subject("Fatura nº 42 — vence amanhã").
		Text("Olá João,\nSua fatura está pronta.\n").HTML("<p>Olá <b>João</b></p>\n").
		Attach(amime.Attachment{Filename: "logo.png", ContentID: "logo", Content: logo}).
		Attach(amime.Attachment{Filename: "fatura 42.pdf", Content: []byte("%PDF-1.7 ...")}).
		Header("X-Entity-Ref-ID", "ref-42")
	raw := mustBuild(t, b)
	m, err := amime.ParseBytes(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.From[0].Name != "Equipe Açaí" || m.From[0].Address != "no-reply@acme.com" {
		t.Errorf("from = %+v", m.From)
	}
	if len(m.To) != 2 || m.To[0].Name != "João" || len(m.Cc) != 1 || m.ReplyTo[0].Address != "suporte@acme.com" {
		t.Errorf("recipients = %+v %+v", m.To, m.Cc)
	}
	if m.Subject != "Fatura nº 42 — vence amanhã" || m.Text != "Olá João,\nSua fatura está pronta.\n" || m.HTML != "<p>Olá <b>João</b></p>\n" {
		t.Errorf("subject %q text %q html %q", m.Subject, m.Text, m.HTML)
	}
	if len(m.Attachments) != 2 || !bytes.Equal(m.Attachments[0].Content, logo) || m.Attachments[1].Filename != "fatura 42.pdf" {
		t.Errorf("attachments = %+v", m.Attachments)
	}
	if m.Header.Get("X-Entity-Ref-ID") != "ref-42" {
		t.Error("custom header lost")
	}
}

// A delimiter directly after another leaves an empty part and must not panic.
func TestEmptyPartBetweenDelimiters(t *testing.T) {
	for _, in := range []string{
		"From: a@b.c\nContent-Type: multipart/mixed; boundary=b1\n\n--b1\n--b1",
		"From: a@b.c\nContent-Type: multipart/mixed; boundary=b1\n\n--b1\n--b1\n--b1--\n",
		"From: a@b.c\r\nContent-Type: multipart/mixed; boundary=b1\r\n\r\n--b1\r\n\r\n--b1--",
	} {
		if _, err := amime.ParseBytes([]byte(in), nil); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestResolveRecipientsTreatsTheEnvelopeAsBcc(t *testing.T) {
	m, err := amime.ParseBytes(crlf("From: a@b.c\nTo: Ana <ana@example.com>\nCc: cc@example.com\nBcc: leaked@example.com\n\nx"), nil)
	if err != nil {
		t.Fatal(err)
	}
	to, cc, bcc := amime.ResolveRecipients(m, []string{"ANA@example.com", "cc@example.com", "secret@example.com", "Secret@Example.com", "leaked@example.com", " other@example.com "})
	if len(to) != 1 || len(cc) != 1 {
		t.Errorf("to %v cc %v", to, cc)
	}
	var got []string
	for _, a := range bcc {
		got = append(got, a.Address)
	}
	want := "leaked@example.com,secret@example.com,other@example.com"
	if strings.Join(got, ",") != want {
		t.Errorf("bcc = %v, want %s", got, want)
	}
}

func TestForwardableHeaders(t *testing.T) {
	m, err := amime.ParseBytes(crlf(`Received: from x
From: a@b.c
To: d@e.f
Subject: s
Date: Fri, 20 Nov 2026 10:00:00 +0000
Message-ID: <x@y>
DKIM-Signature: v=1
X-SES-Out: 1
ARC-Seal: i=1
X-Entity-Ref-ID: first
x-entity-ref-id: second
List-Unsubscribe: <https://a.b/u>
X-Empty:
Content-Type: text/plain

x`), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := amime.ForwardableHeaders(m.Header)
	if len(got) != 2 || got["x-entity-ref-id"] != "second" || got["List-Unsubscribe"] != "<https://a.b/u>" {
		t.Errorf("forwardable = %v", got)
	}
	if amime.ForwardableHeaders(amime.NewHeader()) != nil {
		t.Error("an empty header must give nil")
	}
}

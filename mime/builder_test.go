package mime_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	stdmime "mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"testing"
	"time"

	amime "github.com/hyz-is/arandu-mail/mime"
)

var fixedDate = time.Date(2026, 11, 20, 10, 30, 0, 0, time.FixedZone("BRT", -3*3600))

func baseBuilder() *amime.Builder {
	return amime.NewBuilder().
		From("Acme <hello@acme.com>").
		To("ana@example.com").
		Subject("Hello").
		Date(fixedDate).
		MessageID("fixed.id@acme.com")
}

// wireClean fails when the message has a bare LF, a bare CR, a NUL or a line
// longer than 998 octets.
func wireClean(t *testing.T, raw []byte) {
	t.Helper()
	if bytes.Contains(raw, []byte{0}) {
		t.Error("message holds a NUL")
	}
	if !bytes.HasSuffix(raw, []byte("\r\n")) {
		t.Error("message does not end in CRLF")
	}
	for i, c := range raw {
		if c == '\n' && (i == 0 || raw[i-1] != '\r') {
			t.Fatalf("bare LF at offset %d", i)
		}
		if c == '\r' && (i+1 >= len(raw) || raw[i+1] != '\n') {
			t.Fatalf("bare CR at offset %d", i)
		}
	}
	for _, line := range bytes.Split(raw, []byte("\r\n")) {
		if len(line) > 998 {
			t.Fatalf("line of %d octets", len(line))
		}
	}
}

func mustBuild(t *testing.T, b *amime.Builder) []byte {
	t.Helper()
	raw, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	wireClean(t, raw)
	return raw
}

// readBody reads a leaf part body through the standard library decoders.
func readBody(t *testing.T, header map[string][]string, r io.Reader) []byte {
	t.Helper()
	get := func(k string) string {
		for name, v := range header {
			if strings.EqualFold(name, k) && len(v) > 0 {
				return v[0]
			}
		}
		return ""
	}
	switch strings.ToLower(get("Content-Transfer-Encoding")) {
	case "base64":
		data, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, r))
		if err != nil {
			t.Fatalf("base64: %v", err)
		}
		return data
	case "quoted-printable":
		data, err := io.ReadAll(quotedprintable.NewReader(r))
		if err != nil {
			t.Fatalf("quoted-printable: %v", err)
		}
		return data
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func norm(s string) string {
	return strings.TrimRight(strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(s), "\n")
}

func TestPlainTextIsSevenBit(t *testing.T) {
	raw := mustBuild(t, baseBuilder().Text("hello\nworld"))
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.Header.Get("Content-Transfer-Encoding"); got != "7bit" {
		t.Errorf("encoding = %q, want 7bit", got)
	}
	if got := msg.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("content type = %q", got)
	}
	body, _ := io.ReadAll(msg.Body)
	if norm(string(body)) != "hello\nworld" {
		t.Errorf("body = %q", body)
	}
	for k, want := range map[string]string{"Mime-Version": "1.0", "Message-Id": "<fixed.id@acme.com>", "Subject": "Hello"} {
		if got := msg.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	d, err := msg.Header.Date()
	if err != nil || !d.Equal(fixedDate) {
		t.Errorf("date = %v, %v", d, err)
	}
}

func TestEncodingIsChosenFromTheContent(t *testing.T) {
	long := strings.Repeat("x", 1200)
	cases := []struct{ name, text, want string }{
		{"ascii", "hello", "7bit"},
		{"latin text", "Olá, tudo bem? Estamos enviando uma mensagem comprida com poucos acentos para você.", "quoted-printable"},
		{"cjk", strings.Repeat("日本語のテキスト", 10), "base64"},
		{"long line", long, "quoted-printable"},
		{"trailing space", "hello \nworld", "quoted-printable"},
		{"control byte", "plain text with one control byte \x01 in it and some more words", "quoted-printable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := mustBuild(t, baseBuilder().Text(c.text))
			msg, err := mail.ReadMessage(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if got := msg.Header.Get("Content-Transfer-Encoding"); got != c.want {
				t.Errorf("encoding = %q, want %q", got, c.want)
			}
			body := readBody(t, msg.Header, msg.Body)
			if norm(string(body)) != norm(c.text) {
				t.Errorf("body does not round trip: %q", body)
			}
		})
	}
}

func TestLineBreaksAreNormalizedToCRLF(t *testing.T) {
	for _, text := range []string{"a\nb\nc", "a\rb\rc", "a\r\nb\r\nc", "a\nb\r\nc\rd"} {
		raw := mustBuild(t, baseBuilder().Text(text))
		msg, _ := mail.ReadMessage(bytes.NewReader(raw))
		body, _ := io.ReadAll(msg.Body)
		if got := strings.Count(string(body), "\r\n"); got < 2 {
			t.Errorf("%q: only %d CRLF in body %q", text, got, body)
		}
	}
}

func TestAlternativeRelatedAndMixedStructure(t *testing.T) {
	logo := []byte("\x89PNG\r\n\x1a\n--data--")
	pdf := bytes.Repeat([]byte{0, 1, 2, 3, 250, 251, 252, 253, 254, 255}, 100)
	raw := mustBuild(t, baseBuilder().
		Text("plain ação").
		HTML("<p>html ação <img src=\"cid:logo@acme\"></p>").
		Attach(amime.Attachment{Filename: "logo.png", ContentType: "image/png", ContentID: "logo@acme", Content: logo}).
		Attach(amime.Attachment{Filename: "relatório final.pdf", Content: pdf}))

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, err := stdmime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/mixed" {
		t.Fatalf("top level = %q, %v", mt, err)
	}
	mixed := multipart.NewReader(msg.Body, params["boundary"])

	alt, err := mixed.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	amt, aparams, _ := stdmime.ParseMediaType(alt.Header.Get("Content-Type"))
	if amt != "multipart/alternative" {
		t.Fatalf("first part = %q", amt)
	}
	altr := multipart.NewReader(alt, aparams["boundary"])
	textPart, err := altr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if got := readBody(t, textPart.Header, textPart); norm(string(got)) != "plain ação" {
		t.Errorf("text = %q", got)
	}
	relPart, err := altr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	rmt, rparams, _ := stdmime.ParseMediaType(relPart.Header.Get("Content-Type"))
	if rmt != "multipart/related" {
		t.Fatalf("second alternative = %q", rmt)
	}
	rel := multipart.NewReader(relPart, rparams["boundary"])
	htmlPart, err := rel.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if got := readBody(t, htmlPart.Header, htmlPart); !strings.Contains(string(got), `cid:logo@acme`) {
		t.Errorf("html = %q", got)
	}
	inline, err := rel.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if inline.Header.Get("Content-Id") != "<logo@acme>" {
		t.Errorf("content id = %q", inline.Header.Get("Content-Id"))
	}
	if !strings.HasPrefix(inline.Header.Get("Content-Disposition"), "inline") {
		t.Errorf("disposition = %q", inline.Header.Get("Content-Disposition"))
	}
	if got := readBody(t, inline.Header, inline); !bytes.Equal(got, logo) {
		t.Errorf("inline image = %q", got)
	}

	file, err := mixed.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if file.FileName() != "relatório final.pdf" {
		t.Errorf("file name = %q", file.FileName())
	}
	if ct := file.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/pdf") {
		t.Errorf("guessed type = %q", ct)
	}
	if got := readBody(t, file.Header, file); !bytes.Equal(got, pdf) {
		t.Error("attachment bytes differ")
	}
	if _, err := mixed.NextPart(); err != io.EOF {
		t.Errorf("expected the end of the message, got %v", err)
	}
}

func TestInlineWithoutHTMLFallsBackToMixed(t *testing.T) {
	raw := mustBuild(t, baseBuilder().Text("hi").
		Attach(amime.Attachment{Filename: "a.png", ContentID: "a", Content: []byte("x")}))
	m, err := amime.ParseBytes(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Root.MediaType != "multipart/mixed" || len(m.Attachments) != 1 || m.Attachments[0].ContentID != "a" {
		t.Errorf("root %s, attachments %+v", m.Root.MediaType, m.Attachments)
	}
}

func TestOnlyAttachmentsStillHasATextPart(t *testing.T) {
	raw := mustBuild(t, baseBuilder().Attach(amime.Attachment{Filename: "a.txt", Content: []byte("hello")}))
	m, err := amime.ParseBytes(raw, nil)
	if err != nil || len(m.Attachments) != 1 || string(m.Attachments[0].Content) != "hello" {
		t.Fatalf("%+v, %v", m, err)
	}
}

func TestHeadersAreFoldedAndEncoded(t *testing.T) {
	subject := "Atualização importante: seu pedido nº 12345 foi enviado e chegará em breve — confira os detalhes da entrega aqui"
	raw := mustBuild(t, baseBuilder().
		To("José da Silva <jose@exemplo.com.br>", "\"Doe, John\" <john@example.com>", "plain@example.com").
		Subject(subject).Text("x"))

	for _, line := range bytes.Split(raw[:bytes.Index(raw, []byte("\r\n\r\n"))], []byte("\r\n")) {
		if len(line) > 78 {
			t.Errorf("header line of %d characters: %q", len(line), line)
		}
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	dec := new(stdmime.WordDecoder)
	got, err := dec.DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || got != subject {
		t.Errorf("stdlib decodes the subject as %q, %v", got, err)
	}
	if got := amime.DecodeWords(msg.Header.Get("Subject")); got != subject {
		t.Errorf("DecodeWords = %q", got)
	}
	to, err := msg.Header.AddressList("To")
	if err != nil || len(to) != 4 {
		t.Fatalf("To = %v, %v", to, err)
	}
	if to[1].Name != "José da Silva" || to[2].Name != "Doe, John" || to[3].Address != "plain@example.com" {
		t.Errorf("To = %+v", to)
	}
}

func TestVeryLongNonASCIISubjectStaysFolded(t *testing.T) {
	subject := strings.Repeat("日本語のテキスト", 40)
	raw := mustBuild(t, baseBuilder().Subject(subject).Text("x"))
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	got, err := new(stdmime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || got != subject {
		t.Errorf("subject does not round trip: %v", err)
	}
	for _, line := range bytes.Split(raw[:bytes.Index(raw, []byte("\r\n\r\n"))], []byte("\r\n")) {
		if len(line) > 78 {
			t.Errorf("line of %d characters", len(line))
		}
	}
}

func TestSubjectThatLooksLikeAnEncodedWordIsEncoded(t *testing.T) {
	for _, s := range []string{"=?UTF-8?B?aGk=?=", "two  spaces", " lead", "trail ", "tab\there"} {
		raw := mustBuild(t, baseBuilder().Subject(s).Text("x"))
		m, err := amime.ParseBytes(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := strings.TrimSpace(s)
		if m.Subject != want {
			t.Errorf("subject %q read back as %q", s, m.Subject)
		}
	}
}

func TestHeaderInjectionIsRefused(t *testing.T) {
	evil := "x\r\nBcc: victim@example.com"
	cases := map[string]*amime.Builder{
		"subject":       baseBuilder().Subject(evil),
		"subject lf":    baseBuilder().Subject("x\nBcc: a@b.c"),
		"from":          amime.NewBuilder().From("Evil <a@b.c>\r\nBcc: v@x.y"),
		"to":            baseBuilder().To("a@b.c\r\nBcc: v@x.y"),
		"custom header": baseBuilder().Header("X-Test", evil),
		"header name":   baseBuilder().Header("X-Test\r\nBcc", "v"),
		"filename":      baseBuilder().Attach(amime.Attachment{Filename: evil, Content: []byte("x")}),
		"content id":    baseBuilder().Attach(amime.Attachment{ContentID: "a>\r\nBcc: x", Content: []byte("x")}),
		"content type":  baseBuilder().Attach(amime.Attachment{ContentType: "text/plain\r\nBcc: x", Content: []byte("x")}),
		"message id":    baseBuilder().MessageID("a\r\nBcc: x"),
		"unsubscribe":   baseBuilder().ListUnsubscribe("https://a.b/\r\nBcc: x"),
		"nul":           baseBuilder().Subject("a\x00b"),
	}
	for name, b := range cases {
		if _, err := b.Text("x").Build(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := baseBuilder().Subject(evil).Build(); !errors.Is(err, amime.ErrHeaderInjection) {
		t.Errorf("subject error = %v, want ErrHeaderInjection", err)
	}
}

func TestReservedHeadersAreRefused(t *testing.T) {
	for _, name := range []string{"From", "to", "SUBJECT", "Date", "Message-ID", "MIME-Version", "Content-Type", "Content-Transfer-Encoding", "bcc"} {
		_, err := baseBuilder().Header(name, "x").Build()
		if !errors.Is(err, amime.ErrReservedHeader) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := baseBuilder().Header("bad name", "x").Build(); !errors.Is(err, amime.ErrInvalidHeaderName) {
		t.Errorf("bad name: %v", err)
	}
}

func TestCustomHeadersKeepTheirOrderAndEncode(t *testing.T) {
	raw := mustBuild(t, baseBuilder().Text("x").
		Header("X-One", "1").Header("X-Two", "dois — ação").Header("X-One", "again"))
	m, err := amime.ParseBytes(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Header.Values("X-One"); len(got) != 2 || got[1] != "again" {
		t.Errorf("X-One = %v", got)
	}
	if got := m.Header.Text("X-Two"); got != "dois — ação" {
		t.Errorf("X-Two = %q", got)
	}
}

func TestNoFromIsAnError(t *testing.T) {
	if _, err := amime.NewBuilder().To("a@b.c").Text("x").Build(); !errors.Is(err, amime.ErrNoFrom) {
		t.Errorf("error = %v", err)
	}
}

func TestBccIsNotWrittenButIsARecipient(t *testing.T) {
	b := baseBuilder().Cc("cc@example.com").Bcc("secret@example.com").Text("x")
	raw := mustBuild(t, b)
	if bytes.Contains(bytes.ToLower(raw), []byte("secret@example.com")) || bytes.Contains(bytes.ToLower(raw), []byte("bcc:")) {
		t.Error("the Bcc address reached the message")
	}
	got, err := b.Recipients()
	want := []string{"ana@example.com", "cc@example.com", "secret@example.com"}
	if err != nil || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("recipients = %v, %v", got, err)
	}
}

func TestInternationalAddresses(t *testing.T) {
	b := baseBuilder().To("Zé <ze@bücher.example>").Text("x")
	raw := mustBuild(t, b)
	if !bytes.Contains(raw, []byte("<ze@xn--bcher-kva.example>")) {
		t.Errorf("domain is not Punycode:\n%s", raw[:bytes.Index(raw, []byte("\r\n\r\n"))])
	}
	if b.NeedsSMTPUTF8() {
		t.Error("an ASCII local part does not need SMTPUTF8")
	}
	rcpt, err := b.Recipients()
	if err != nil || rcpt[1] != "ze@xn--bcher-kva.example" {
		t.Errorf("recipients = %v, %v", rcpt, err)
	}

	u := baseBuilder().To("用户@例子.广告").Text("x")
	if !u.NeedsSMTPUTF8() {
		t.Error("a Unicode local part needs SMTPUTF8")
	}
	if _, err := u.Build(); !errors.Is(err, amime.ErrNeedsSMTPUTF8) {
		t.Errorf("without SMTPUTF8: %v", err)
	}
	raw, err = u.SMTPUTF8(true).Build()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("用户@例子.广告")) {
		t.Error("with SMTPUTF8 the address is kept as UTF-8")
	}
	if _, err := baseBuilder().To("用户@例子.广告").Recipients(); err != nil {
		// Recipients refuses an address with no SMTPUTF8 session.
		if !errors.Is(err, amime.ErrNeedsSMTPUTF8) {
			t.Errorf("recipients: %v", err)
		}
	}
}

func TestListUnsubscribeHeaders(t *testing.T) {
	raw := mustBuild(t, baseBuilder().Text("x").
		ListUnsubscribe("https://acme.com/unsub/abc", "mailto:unsub@acme.com?subject=unsub").OneClickUnsubscribe())
	m, err := amime.ParseBytes(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Header.Get("List-Unsubscribe"); got != "<https://acme.com/unsub/abc>, <mailto:unsub@acme.com?subject=unsub>" {
		t.Errorf("List-Unsubscribe = %q", got)
	}
	if got := m.Header.Get("List-Unsubscribe-Post"); got != "List-Unsubscribe=One-Click" {
		t.Errorf("List-Unsubscribe-Post = %q", got)
	}

	for name, b := range map[string]*amime.Builder{
		"one-click without uri":   baseBuilder().OneClickUnsubscribe(),
		"one-click needs https":   baseBuilder().ListUnsubscribe("http://acme.com/u").OneClickUnsubscribe(),
		"mailto only one-click":   baseBuilder().ListUnsubscribe("mailto:a@b.c").OneClickUnsubscribe(),
		"scheme":                  baseBuilder().ListUnsubscribe("ftp://acme.com/u"),
		"angle bracket":           baseBuilder().ListUnsubscribe("https://a.b/<x>"),
		"duplicated custom field": baseBuilder().ListUnsubscribe("https://a.b/u").Header("List-Unsubscribe", "<x>"),
	} {
		if _, err := b.Text("x").Build(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestGeneratedIdentifiers(t *testing.T) {
	b := amime.NewBuilder().From("a@acme.com").To("b@x.com").Text("x")
	raw1 := mustBuild(t, b)
	id := b.ID()
	if !regexp.MustCompile(`^[a-z0-9]+\.[0-9a-f]{16}@acme\.com$`).MatchString(id) {
		t.Errorf("generated Message-ID %q", id)
	}
	if !bytes.Contains(raw1, []byte("Message-ID: <"+id+">")) {
		t.Error("the Message-ID header differs from ID()")
	}
	raw2 := mustBuild(t, b)
	if !bytes.Contains(raw2, []byte("<"+id+">")) {
		t.Error("a second Build changed the Message-ID")
	}
	other := amime.NewBuilder().From("a@acme.com")
	if other.ID() == id {
		t.Error("two builders produced the same Message-ID")
	}
	m, _ := amime.ParseBytes(raw1, nil)
	if time.Since(m.Date) > time.Minute || m.Date.IsZero() {
		t.Errorf("default Date = %v", m.Date)
	}
}

func TestBoundaryNeverAppearsInBodies(t *testing.T) {
	// The boundary is random, so the body cannot name it; the check is that a
	// body that holds boundary-like lines still parses to itself.
	body := "--arandu_deadbeef\n--arandu_deadbeef--\nplain"
	raw := mustBuild(t, baseBuilder().Text(body).HTML("<p>"+body+"</p>"))
	m, err := amime.ParseBytes(raw, nil)
	if err != nil || m.Text != body {
		t.Errorf("text = %q, %v", m.Text, err)
	}
}

func TestResetReusesTheBuilder(t *testing.T) {
	b := baseBuilder().Text("one").Header("X-A", "1")
	mustBuild(t, b)
	b.Reset()
	if _, err := b.Build(); !errors.Is(err, amime.ErrNoFrom) {
		t.Errorf("a reset builder kept its From: %v", err)
	}
	raw := mustBuild(t, b.From("a@b.c").To("d@e.f").Text("two").Date(fixedDate))
	if bytes.Contains(raw, []byte("X-A")) {
		t.Error("a reset builder kept a header")
	}
}

func TestWriteToMatchesBuild(t *testing.T) {
	b := baseBuilder().Text("hello").HTML("<b>hello</b>")
	want := mustBuild(t, b)
	var buf bytes.Buffer
	n, err := b.WriteTo(&buf)
	if err != nil || int(n) != len(want) || buf.Len() != len(want) {
		t.Fatalf("WriteTo wrote %d bytes, %v; Build made %d", n, err, len(want))
	}
	m, err := amime.ParseBytes(buf.Bytes(), nil)
	if err != nil || m.Text != "hello" || m.HTML != "<b>hello</b>" {
		t.Errorf("WriteTo output reads back as %q, %q, %v", m.Text, m.HTML, err)
	}
}

func TestQuotedPrintableAgreesWithTheStandardLibrary(t *testing.T) {
	inputs := []string{
		"simple", "café au lait", strings.Repeat("a", 200), strings.Repeat("é", 100),
		"trailing space \nnext", "a=b", "tab\tend\t\n", " nbsp",
		strings.Repeat("word ", 60) + "é",
	}
	for _, in := range inputs {
		raw := mustBuild(t, baseBuilder().Text(in+"é")) // force a non-7bit encoding
		msg, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		got := readBody(t, msg.Header, msg.Body)
		if norm(string(got)) != norm(in+"é") {
			t.Errorf("%q round trips as %q", in, got)
		}
	}
}

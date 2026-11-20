package mime_test

import (
	"io"
	"strings"
	"testing"

	amime "github.com/hyz-is/arandu-mail/mime"
)

func benchBuilder() *amime.Builder {
	html := strings.Repeat("<p>Olá, este é um parágrafo de exemplo com acentuação e <b>negrito</b>.</p>\n", 300)
	text := strings.Repeat("Olá, este é um parágrafo de exemplo com acentuação e negrito.\n", 300)
	return amime.NewBuilder().
		From("Acme <hello@acme.com>").To("ana@example.com", "bob@example.com").
		Subject("Sua fatura está pronta — confira os detalhes").
		Text(text).HTML(html).
		Date(fixedDate).MessageID("bench@acme.com").
		Header("X-Entity-Ref-ID", "abc-123").
		ListUnsubscribe("https://acme.com/u/1").OneClickUnsubscribe()
}

// BenchmarkBuildSmall measures a transactional message: a few hundred bytes of
// text and HTML.
func BenchmarkBuildSmall(b *testing.B) {
	bld := amime.NewBuilder().From("Acme <hello@acme.com>").To("ana@example.com").
		Subject("Welcome").Text("Hello Ana").HTML("<p>Hello Ana</p>").
		Date(fixedDate).MessageID("bench@acme.com")
	buf := make([]byte, 0, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		buf, err = bld.AppendTo(buf[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(int64(len(buf)))
}

// BenchmarkBuild50KB measures a message of about 50 KB of text, HTML and
// quoted-printable content.
func BenchmarkBuild50KB(b *testing.B) {
	bld := benchBuilder()
	buf := make([]byte, 0, 256<<10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		buf, err = bld.AppendTo(buf[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(int64(len(buf)))
}

// BenchmarkBuildWithAttachment measures a small message with a 100 KB file.
func BenchmarkBuildWithAttachment(b *testing.B) {
	bld := amime.NewBuilder().From("a@acme.com").To("b@x.com").Subject("File").Text("see attached").
		Date(fixedDate).MessageID("bench@acme.com").
		Attach(amime.Attachment{Filename: "report.pdf", Content: make([]byte, 100<<10)})
	buf := make([]byte, 0, 256<<10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		buf, err = bld.AppendTo(buf[:0])
		if err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(int64(len(buf)))
}

// BenchmarkBuildWriteTo measures the pooled streaming path.
func BenchmarkBuildWriteTo(b *testing.B) {
	bld := benchBuilder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bld.WriteTo(io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func benchRaw(b *testing.B) []byte {
	raw, err := benchBuilder().Build()
	if err != nil {
		b.Fatal(err)
	}
	return raw
}

// BenchmarkParse50KB measures reading the same 50 KB message back.
func BenchmarkParse50KB(b *testing.B) {
	raw := benchRaw(b)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := amime.ParseBytes(raw, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseEntity50KB measures the MIME tree alone, with no text decoding.
func BenchmarkParseEntity50KB(b *testing.B) {
	raw := benchRaw(b)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := amime.ParseEntity(raw, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseAddressList(b *testing.B) {
	const in = `"Doe, John" <john@example.com>, Ana Souza <ana@example.com>, =?UTF-8?Q?Jos=C3=A9?= <jose@example.com.br>, plain@example.com`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := amime.ParseAddressList(in); err != nil {
			b.Fatal(err)
		}
	}
}

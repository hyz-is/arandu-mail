package mime_test

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/hyz-is/arandu-mail/mime"
)

func ExampleBuilder() {
	b := mime.NewBuilder().
		From("Acme <hello@acme.com>").
		To("José da Silva <jose@exemplo.com.br>").
		Subject("Sua fatura está pronta").
		Text("Olá José, sua fatura está pronta.").
		HTML("<p>Olá José, sua fatura está pronta.</p>").
		Date(time.Date(2026, 11, 20, 10, 30, 0, 0, time.UTC)).
		MessageID("invoice-42@acme.com").
		ListUnsubscribe("https://acme.com/unsubscribe/42").
		OneClickUnsubscribe()

	raw, err := b.Build()
	if err != nil {
		panic(err)
	}
	// The part boundaries are random, so print the header up to the MIME
	// structure.
	head, _, _ := bytes.Cut(raw, []byte("Content-Type:"))
	fmt.Print(strings.ReplaceAll(string(head), "\r\n", "\n"))
	recipients, _ := b.Recipients()
	fmt.Println(recipients)

	// Output:
	// Date: Fri, 20 Nov 2026 10:30:00 +0000
	// From: Acme <hello@acme.com>
	// To: =?UTF-8?Q?Jos=C3=A9_da_Silva?= <jose@exemplo.com.br>
	// Subject: =?UTF-8?Q?Sua_fatura_est=C3=A1_pronta?=
	// Message-ID: <invoice-42@acme.com>
	// MIME-Version: 1.0
	// List-Unsubscribe: <https://acme.com/unsubscribe/42>
	// List-Unsubscribe-Post: List-Unsubscribe=One-Click
	// [jose@exemplo.com.br]
}

func ExampleParseBytes() {
	raw := []byte("From: Ana <ana@example.com>\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: =?UTF-8?Q?Caf=C3=A9?=\r\n" +
		"Content-Type: text/plain; charset=iso-8859-1\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
		"Ol=E1, tudo bem?\r\n")

	m, err := mime.ParseBytes(raw, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(m.From[0].Name, m.From[0].Address)
	fmt.Println(m.Subject)
	fmt.Printf("%q\n", m.Text)

	// Output:
	// Ana ana@example.com
	// Café
	// "Olá, tudo bem?\n"
}

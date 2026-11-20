package dsn_test

import (
	"fmt"

	"github.com/hyz-is/arandu-mail/dsn"
)

func ExampleClassify() {
	for _, c := range []struct {
		code     int
		enhanced string
		text     string
	}{
		{550, "5.1.1", "<ghost@example.com>: Recipient address rejected: User unknown"},
		{552, "5.2.2", "Mailbox full"},
		{451, "4.7.1", "Greylisted, try again later"},
		{554, "5.7.1", "Message rejected as spam"},
	} {
		got := dsn.Classify(c.code, c.enhanced, c.text)
		fmt.Println(c.code, got.Type, got.SubType)
	}

	// Output:
	// 550 Permanent NoEmail
	// 552 Transient MailboxFull
	// 451 Transient General
	// 554 Transient ContentRejected
}

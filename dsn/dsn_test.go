package dsn_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/hyz-is/arandu-mail/dsn"
)

func crlf(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }

// A standard RFC 3464 report, with the layout of Postfix.
const postfixReport = `Return-Path: <>
From: MAILER-DAEMON@mx.acme.com (Mail Delivery System)
To: bounces+cm3x8k2p.aaaaaaaaaaaaa@mail.acme.com
Subject: Undelivered Mail Returned to Sender
Auto-Submitted: auto-replied
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status;
	boundary="BOUNDARY/mx.acme.com"
Message-Id: <20261120120000.ABC@mx.acme.com>

--BOUNDARY/mx.acme.com
Content-Description: Notification
Content-Type: text/plain; charset=us-ascii

This is the mail system at host mx.acme.com.

I'm sorry to have to inform you that your message could not
be delivered to one or more recipients.

<ghost@example.com>: host mx.example.com[192.0.2.10] said: 550 5.1.1
    <ghost@example.com>: Recipient address rejected: User unknown in virtual
    mailbox table (in reply to RCPT TO command)

--BOUNDARY/mx.acme.com
Content-Description: Delivery report
Content-Type: message/delivery-status

Reporting-MTA: dns; mx.acme.com
X-Postfix-Queue-ID: ABC
X-Postfix-Sender: rfc822; bounces+cm3x8k2p.aaaaaaaaaaaaa@mail.acme.com
Arrival-Date: Fri, 20 Nov 2026 12:00:00 +0000 (UTC)
Original-Envelope-Id: cm3x8k2p

Final-Recipient: rfc822; ghost@example.com
Original-Recipient: rfc822;Ghost@example.com
Action: failed
Status: 5.1.1
Remote-MTA: dns; mx.example.com
Diagnostic-Code: smtp; 550 5.1.1 <ghost@example.com>: Recipient address rejected:
    User unknown in virtual mailbox table

--BOUNDARY/mx.acme.com
Content-Description: Undelivered Message Headers
Content-Type: text/rfc822-headers

Return-Path: <bounces+cm3x8k2p.aaaaaaaaaaaaa@mail.acme.com>
From: Acme <hello@acme.com>
To: ghost@example.com
Subject: Welcome
Message-ID: <cm3x8k2p.1@acme.com>
X-Meeng-Email-ID: cm3x8k2p

--BOUNDARY/mx.acme.com--
`

func TestParsesAStandardReport(t *testing.T) {
	rep, err := dsn.Parse(crlf(postfixReport), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Heuristic {
		t.Error("a standard report was read heuristically")
	}
	if rep.ReportingMTA != "mx.acme.com" || rep.OriginalEnvelopeID != "cm3x8k2p" {
		t.Errorf("MTA %q envelope id %q", rep.ReportingMTA, rep.OriginalEnvelopeID)
	}
	if rep.ArrivalDate.IsZero() || rep.ArrivalDate.Year() != 2026 {
		t.Errorf("arrival = %v", rep.ArrivalDate)
	}
	if len(rep.Recipients) != 1 {
		t.Fatalf("recipients = %+v", rep.Recipients)
	}
	r := rep.Recipients[0]
	if r.FinalRecipient != "ghost@example.com" || r.OriginalRecipient != "Ghost@example.com" ||
		r.Action != dsn.ActionFailed || r.Status != "5.1.1" || r.RemoteMTA != "mx.example.com" {
		t.Errorf("recipient = %+v", r)
	}
	if !strings.HasPrefix(r.DiagnosticCode, "550 5.1.1 <ghost@example.com>: Recipient address rejected:") ||
		!strings.Contains(r.DiagnosticCode, "User unknown in virtual mailbox table") {
		t.Errorf("diagnostic = %q", r.DiagnosticCode)
	}
	if r.SMTPCode() != 550 || r.EnhancedCode() != "5.1.1" {
		t.Errorf("codes %d %s", r.SMTPCode(), r.EnhancedCode())
	}
	if c := r.Classification(); c != (dsn.Classification{Type: dsn.Permanent, SubType: dsn.NoEmail}) {
		t.Errorf("classification = %+v", c)
	}
	if got := rep.OriginalHeader("X-Meeng-Email-ID"); got != "cm3x8k2p" {
		t.Errorf("original email id = %q", got)
	}
	if got := rep.OriginalHeader("message-id"); got != "<cm3x8k2p.1@acme.com>" {
		t.Errorf("original message id = %q", got)
	}
	if !strings.Contains(rep.Text, "could not") {
		t.Errorf("text = %q", rep.Text)
	}
}

const delayedReport = `From: Mail Delivery Subsystem <mailer-daemon@googlemail.com>
Subject: Delivery Status Notification (Delay)
Content-Type: multipart/report; report-type=delivery-status; boundary=b1

--b1
Content-Type: text/plain

Delivery to the following recipient has been delayed:
slow@example.net

--b1
Content-Type: message/delivery-status

Reporting-MTA: dns; googlemail.com

Final-Recipient: rfc822; slow@example.net
Action: delayed
Status: 4.4.1
Diagnostic-Code: smtp; The recipient server did not accept our requests to connect.
Will-Retry-Until: Mon, 23 Nov 2026 12:00:00 +0000

--b1
Content-Type: message/rfc822

From: a@acme.com
To: slow@example.net
Subject: hi

body
--b1--
`

func TestDelayedReport(t *testing.T) {
	rep, err := dsn.Parse(crlf(delayedReport), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Recipients[0]
	if r.Action != dsn.ActionDelayed || r.WillRetryUntil.IsZero() {
		t.Errorf("recipient = %+v", r)
	}
	if c := r.Classification(); c != (dsn.Classification{Type: dsn.Transient, SubType: dsn.General}) {
		t.Errorf("classification = %+v", c)
	}
	if rep.OriginalHeader("To") != "slow@example.net" {
		t.Errorf("original To = %q", rep.OriginalHeader("To"))
	}
}

func TestSeveralRecipientsInOneReport(t *testing.T) {
	in := `From: MAILER-DAEMON@x.com
Content-Type: multipart/report; report-type=delivery-status; boundary=b

--b
Content-Type: message/delivery-status

Reporting-MTA: dns; x.com

Final-Recipient: rfc822; a@example.com
Action: failed
Status: 5.2.2
Diagnostic-Code: smtp; 552 5.2.2 Mailbox full

Final-Recipient: rfc822; b@example.com
Action: failed
Status: 5.7.1
Diagnostic-Code: smtp; 554 5.7.1 Message rejected as spam

Final-Recipient: rfc822; c@example.com
Action: delivered
Status: 2.0.0
--b--
`
	rep, err := dsn.Parse(crlf(in), nil)
	if err != nil || len(rep.Recipients) != 3 {
		t.Fatalf("%+v, %v", rep, err)
	}
	want := []dsn.Classification{
		{Type: dsn.Transient, SubType: dsn.MailboxFull},
		{Type: dsn.Transient, SubType: dsn.ContentRejected},
		{Type: dsn.Undetermined, SubType: dsn.General},
	}
	for i, r := range rep.Recipients {
		if got := r.Classification(); got != want[i] {
			t.Errorf("%s: %+v, want %+v", r.FinalRecipient, got, want[i])
		}
	}
}

const eximText = `Return-path: <>
From: Mail Delivery System <Mailer-Daemon@mail.example.org>
To: bounces+id1.aaaaaaaaaaaaa@mail.acme.com
Subject: Mail delivery failed: returning message to sender
Content-Type: text/plain; charset=us-ascii

This message was created automatically by mail delivery software.

A message that you sent could not be delivered to one or more of its
recipients. This is a permanent error. The following address(es) failed:

  nobody@example.org
    SMTP error from remote mail server after RCPT TO:<nobody@example.org>:
    host mx.example.org [203.0.113.5]: 550 5.1.1 Unknown user

------ This is a copy of the message, including all the headers. ------

From: Acme <hello@acme.com>
To: nobody@example.org
Subject: Hello
X-Meeng-Email-ID: id1

hi
`

func TestHeuristicEximStyle(t *testing.T) {
	rep, err := dsn.Parse(crlf(eximText), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Heuristic || len(rep.Recipients) != 1 {
		t.Fatalf("%+v", rep)
	}
	r := rep.Recipients[0]
	if r.FinalRecipient != "nobody@example.org" || r.Status != "5.1.1" || r.SMTPCode() != 550 {
		t.Errorf("recipient = %+v", r)
	}
	if c := r.Classification(); c.SubType != dsn.NoEmail || c.Type != dsn.Permanent {
		t.Errorf("classification = %+v", c)
	}
}

func TestHeuristicWithXFailedRecipientsHeader(t *testing.T) {
	in := `From: Mail Delivery Subsystem <mailer-daemon@googlemail.com>
X-Failed-Recipients: gone@example.com, gone2@example.com
Subject: Delivery Status Notification (Failure)
Content-Type: text/plain

Your message wasn't delivered to gone@example.com because the address couldn't be found.
The response was:

550 5.1.1 The email account that you tried to reach does not exist.
`
	rep, err := dsn.Parse(crlf(in), nil)
	if err != nil || len(rep.Recipients) != 2 || rep.Recipients[1].FinalRecipient != "gone2@example.com" {
		t.Fatalf("%+v, %v", rep, err)
	}
	if rep.Recipients[0].Status != "5.1.1" {
		t.Errorf("status = %q", rep.Recipients[0].Status)
	}
}

func TestHeuristicPrefersTheAddressTheOriginalWasSentTo(t *testing.T) {
	in := `From: postmaster@relay.example.net
Subject: Undeliverable: Welcome
Content-Type: multipart/mixed; boundary=m

--m
Content-Type: text/plain

Delivery has failed to these recipients or groups:

someone@example.com
The email address you entered couldn't be found. Contact support@relay.example.net for help.
Diagnostic information for administrators:
Remote server returned '550 5.1.10 RESOLVER.ADR.RecipientNotFound; Recipient not found'

--m
Content-Type: message/rfc822

From: hello@acme.com
To: someone@example.com
Subject: Welcome

x
--m--
`
	rep, err := dsn.Parse(crlf(in), nil)
	if err != nil || len(rep.Recipients) != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
	if rep.Recipients[0].FinalRecipient != "someone@example.com" || rep.Recipients[0].Status != "5.1.10" {
		t.Errorf("recipient = %+v", rep.Recipients[0])
	}
}

func TestHeuristicTransientNotice(t *testing.T) {
	in := `From: Mail Delivery System <Mailer-Daemon@mx.example.org>
Subject: Warning: message delayed
Content-Type: text/plain

This message was created automatically by mail delivery software.

Delivery to the following address has been delayed; Exim will keep trying:

  <late@example.org>: host mx.example.org [203.0.113.5]: 451 4.7.1 Greylisted, try again later
`
	rep, err := dsn.Parse(crlf(in), nil)
	if err != nil || len(rep.Recipients) != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
	r := rep.Recipients[0]
	if r.Action != dsn.ActionDelayed || r.Classification().Type != dsn.Transient {
		t.Errorf("recipient = %+v, %+v", r, r.Classification())
	}
}

func TestOrdinaryMailIsNotADSN(t *testing.T) {
	for _, in := range []string{
		"From: ana@example.com\r\nTo: b@c.d\r\nSubject: Lunch?\r\n\r\nSee you at noon.\r\n",
		"not a message",
		"",
	} {
		if _, err := dsn.Parse([]byte(in), nil); !errors.Is(err, dsn.ErrNotDSN) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestClassify(t *testing.T) {
	type c = dsn.Classification
	cases := []struct {
		code     int
		enhanced string
		text     string
		want     c
	}{
		{550, "5.1.1", "user unknown", c{dsn.Permanent, dsn.NoEmail}},
		{550, "5.1.2", "bad destination system address", c{dsn.Permanent, dsn.NoEmail}},
		{550, "", "No such user here", c{dsn.Permanent, dsn.NoEmail}},
		{553, "", "5.1.3 mailbox syntax", c{dsn.Permanent, dsn.NoEmail}},
		{550, "5.7.1", "Sender domain does not exist", c{dsn.Permanent, dsn.General}},
		{550, "5.2.1", "mailbox disabled", c{dsn.Permanent, dsn.General}},
		{552, "5.2.2", "mailbox full", c{dsn.Transient, dsn.MailboxFull}},
		{452, "4.2.2", "", c{dsn.Transient, dsn.MailboxFull}},
		{552, "", "Over quota", c{dsn.Transient, dsn.MailboxFull}},
		{552, "5.3.4", "message too big for system", c{dsn.Transient, dsn.MessageTooLarge}},
		{552, "", "message size exceeds fixed limit", c{dsn.Transient, dsn.MessageTooLarge}},
		{554, "5.7.1", "Message rejected as spam", c{dsn.Transient, dsn.ContentRejected}},
		{554, "5.6.0", "", c{dsn.Transient, dsn.ContentRejected}},
		{554, "", "message contains a virus", c{dsn.Transient, dsn.AttachmentRejected}},
		{550, "5.7.1", "attachment type not allowed", c{dsn.Transient, dsn.AttachmentRejected}},
		{550, "", "address is on the suppression list", c{dsn.Permanent, dsn.Suppressed}},
		{421, "4.7.0", "try again later", c{dsn.Transient, dsn.General}},
		{451, "", "Greylisted", c{dsn.Transient, dsn.General}},
		{550, "5.7.1", "relay access denied", c{dsn.Permanent, dsn.General}},
		{554, "", "transaction failed", c{dsn.Permanent, dsn.General}},
		{0, "", "", c{dsn.Undetermined, dsn.General}},
		{0, "", "something odd happened", c{dsn.Undetermined, dsn.General}},
		{250, "2.0.0", "ok", c{dsn.Undetermined, dsn.General}},
		{0, "4.4.1", "connection timed out", c{dsn.Transient, dsn.General}},
		{0, "5.0.0", "", c{dsn.Permanent, dsn.General}},
	}
	for _, tc := range cases {
		if got := dsn.Classify(tc.code, tc.enhanced, tc.text); got != tc.want {
			t.Errorf("Classify(%d, %q, %q) = %+v, want %+v", tc.code, tc.enhanced, tc.text, got, tc.want)
		}
	}
}

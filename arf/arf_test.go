package arf_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/hyz-is/arandu-mail/arf"
	"github.com/hyz-is/arandu-mail/mime"
)

func crlf(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }

// The example of RFC 5965 section 7.1, with the addresses of the example
// domains.
const rfcExample = `From: <abusedesk@mail.example.net>
Date: Thu, 8 Mar 2005 17:40:36 EST
Subject: FW: Earn money
To: <abuse@example.com>
MIME-Version: 1.0
Content-Type: multipart/report; report-type=feedback-report;
	boundary="part1_13d.2e68ed54_boundary"

--part1_13d.2e68ed54_boundary
Content-Type: text/plain; charset="US-ASCII"
Content-Transfer-Encoding: 7bit

This is an email abuse report for an email message received from IP
192.0.2.1 on Thu, 8 Mar 2005 14:00:00 EDT.

--part1_13d.2e68ed54_boundary
Content-Type: message/feedback-report

Feedback-Type: abuse
User-Agent: SomeGenerator/1.0
Version: 1
Original-Mail-From: <somespammer@example.net>
Original-Rcpt-To: <user@example.com>
Arrival-Date: Thu, 8 Mar 2005 14:00:00 EDT
Reporting-MTA: dns; mail.example.com
Source-IP: 192.0.2.1
Authentication-Results: mail.example.com; spf=fail smtp.mail=somespammer@example.com
Reported-Domain: example.net
Reported-URI: http://example.net/earn_money.html
Reported-URI: mailto:user@example.com

--part1_13d.2e68ed54_boundary
Content-Type: message/rfc822
Content-Disposition: inline

Received: from mailserver.example.net (mailserver.example.net [192.0.2.1])
	by example.com with ESMTP id M63d4137594e46;
	Thu, 08 Mar 2005 14:00:00 -0400
From: <somespammer@example.net>
To: <Undisclosed Recipients>
Subject: Earn money
Message-ID: <8787KJKJ3K4J3K4J3K4J3.mail@example.net>
X-Meeng-Email-ID: cm3x8k2p
Date: Thu, 02 Sep 2004 12:31:03 -0500

Spam Spam Spam
--part1_13d.2e68ed54_boundary--
`

func TestParsesTheRFC5965Example(t *testing.T) {
	rep, err := arf.Parse(crlf(rfcExample), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FeedbackType != "abuse" || rep.Version != "1" || rep.UserAgent != "SomeGenerator/1.0" {
		t.Errorf("type %q version %q agent %q", rep.FeedbackType, rep.Version, rep.UserAgent)
	}
	if rep.OriginalMailFrom != "somespammer@example.net" {
		t.Errorf("mail from = %q", rep.OriginalMailFrom)
	}
	if len(rep.OriginalRcptTo) != 1 || rep.OriginalRcptTo[0] != "user@example.com" {
		t.Errorf("rcpt to = %v", rep.OriginalRcptTo)
	}
	if rep.OriginalMessageID != "8787KJKJ3K4J3K4J3K4J3.mail@example.net" {
		t.Errorf("message id = %q", rep.OriginalMessageID)
	}
	if rep.EmailID != "cm3x8k2p" || rep.OriginalHeader("subject") != "Earn money" {
		t.Errorf("email id %q subject %q", rep.EmailID, rep.OriginalHeader("subject"))
	}
	if rep.ReportingMTA != "mail.example.com" || rep.SourceIP != "192.0.2.1" || rep.ReportedDomain != "example.net" {
		t.Errorf("mta %q ip %q domain %q", rep.ReportingMTA, rep.SourceIP, rep.ReportedDomain)
	}
	if len(rep.ReportedURI) != 2 || len(rep.AuthenticationResults) != 1 {
		t.Errorf("uris %v auth %v", rep.ReportedURI, rep.AuthenticationResults)
	}
	if rep.ArrivalDate.IsZero() || rep.ArrivalDate.Year() != 2005 {
		t.Errorf("arrival = %v", rep.ArrivalDate)
	}
	if !rep.IsComplaint() {
		t.Error("an abuse report is a complaint")
	}
}

func TestCustomEmailIDHeader(t *testing.T) {
	rep, err := arf.Parse(crlf(strings.Replace(rfcExample, "X-Meeng-Email-ID", "X-Other-ID", 1)),
		&arf.Options{EmailIDHeader: "x-other-id"})
	if err != nil || rep.EmailID != "cm3x8k2p" {
		t.Errorf("%q, %v", rep.EmailID, err)
	}
	rep, _ = arf.Parse(crlf(strings.Replace(rfcExample, "X-Meeng-Email-ID", "X-Other-ID", 1)), nil)
	if rep.EmailID != "" {
		t.Errorf("email id %q found under the default header", rep.EmailID)
	}
}

// Yahoo and Outlook style: headers only, no Original-Rcpt-To.
const headersOnly = `From: complaints@fbl.example.org
Subject: complaint about message from 192.0.2.1
Content-Type: multipart/report; report-type=feedback-report; boundary="x"

--x
Content-Type: text/plain

complaint

--x
Content-Type: message/feedback-report

Feedback-Type: abuse
User-Agent: Example-FBL/1.0
Version: 0.1

--x
Content-Type: text/rfc822-headers

From: Acme <hello@acme.com>
To: Reader <reader@example.org>
Message-ID: <abc.1@acme.com>
X-Meeng-Email-ID: id-7

--x--
`

func TestHeadersOnlyReportFallsBackToTheOriginalTo(t *testing.T) {
	rep, err := arf.Parse(crlf(headersOnly), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.OriginalRcptTo) != 1 || rep.OriginalRcptTo[0] != "reader@example.org" {
		t.Errorf("rcpt = %v", rep.OriginalRcptTo)
	}
	if rep.EmailID != "id-7" || rep.OriginalMessageID != "abc.1@acme.com" {
		t.Errorf("email id %q message id %q", rep.EmailID, rep.OriginalMessageID)
	}
}

func TestReportWithoutTheOriginal(t *testing.T) {
	in := `From: x@y.z
Content-Type: multipart/report; report-type=feedback-report; boundary=b

--b
Content-Type: message/feedback-report

Feedback-Type: Not-Spam
User-Agent: A/1
Original-Rcpt-To: rfc822; Someone <p@q.r>
Original-Message-ID: <orig@acme.com>
--b--
`
	rep, err := arf.Parse(crlf(in), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FeedbackType != "not-spam" || rep.IsComplaint() {
		t.Errorf("type %q complaint %v", rep.FeedbackType, rep.IsComplaint())
	}
	if len(rep.OriginalRcptTo) != 1 || rep.OriginalRcptTo[0] != "p@q.r" {
		t.Errorf("rcpt = %v", rep.OriginalRcptTo)
	}
	if rep.OriginalMessageID != "orig@acme.com" || rep.EmailID != "" || rep.OriginalMessage != nil {
		t.Errorf("%+v", rep)
	}
}

func TestNotAReport(t *testing.T) {
	for _, in := range []string{
		"From: a@b.c\r\n\r\nhello",
		"Content-Type: multipart/report; boundary=b\r\n\r\n--b\r\nContent-Type: message/feedback-report\r\n\r\nrandom: text\r\n--b--",
		"",
	} {
		if _, err := arf.Parse([]byte(in), nil); !errors.Is(err, arf.ErrNotARF) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{rfcExample, headersOnly} {
		f.Add([]byte(s))
	}
	f.Add([]byte("Content-Type: multipart/report; boundary=b\r\n\r\n--b\r\nContent-Type: message/feedback-report\r\n\r\nFeedback-Type: abuse\r\n--b--"))
	opt := &arf.Options{Mime: &mime.Options{MaxSize: 1 << 20, MaxDepth: 8, MaxParts: 100}}
	f.Fuzz(func(t *testing.T, in []byte) {
		rep, err := arf.Parse(in, opt)
		if err != nil {
			return
		}
		if rep.FeedbackType != strings.ToLower(rep.FeedbackType) {
			t.Fatalf("feedback type %q is not lowercase", rep.FeedbackType)
		}
	})
}

func BenchmarkParse(b *testing.B) {
	raw := crlf(rfcExample)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for i := 0; i < b.N; i++ {
		if _, err := arf.Parse(raw, nil); err != nil {
			b.Fatal(err)
		}
	}
}

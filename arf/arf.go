package arf

import (
	"errors"
	netmail "net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/hyz-is/arandu-mail/mime"
)

// ErrNotARF reports a message that holds no feedback report.
var ErrNotARF = errors.New("arf: the message is not a feedback report")

// DefaultEmailIDHeader is the header the sender puts on every message to find
// it again when a report comes back.
const DefaultEmailIDHeader = "X-Meeng-Email-ID"

// Options tunes Parse.
type Options struct {
	// Mime bounds the MIME parser. Nil uses its defaults.
	Mime *mime.Options
	// EmailIDHeader is the header of the returned original that carries the
	// sender's own message id. Default DefaultEmailIDHeader.
	EmailIDHeader string
}

// Report is a feedback report.
type Report struct {
	// Version is the report format version, "1" for RFC 5965.
	Version string
	// FeedbackType is "abuse", "fraud", "virus", "not-spam", "other" or an
	// extension, lowercased.
	FeedbackType string
	// UserAgent is the software that made the report.
	UserAgent string
	// OriginalMailFrom is the envelope sender of the reported message, without
	// angle brackets.
	OriginalMailFrom string
	// OriginalRcptTo are the envelope recipients of the reported message. When
	// the report does not name one, it falls back to the To header of the
	// original.
	OriginalRcptTo []string
	// ArrivalDate is when the reported message arrived at the provider.
	ArrivalDate time.Time
	// ReportingMTA, SourceIP and ReportedDomain are the optional fields of the
	// same names, without their "dns;" type where there is one.
	ReportingMTA, SourceIP, ReportedDomain string
	// ReportedURI are the Reported-URI fields.
	ReportedURI []string
	// AuthenticationResults are the Authentication-Results fields.
	AuthenticationResults []string
	// OriginalMessageID is the Message-ID of the reported message, without
	// angle brackets. Providers that return the original put it here; some put
	// it in the report itself, which wins when the original has none.
	OriginalMessageID string
	// EmailID is the value of Options.EmailIDHeader in the original, "" when
	// the original was not returned or does not carry it.
	EmailID string
	// OriginalHeaders are the header fields of the returned original.
	OriginalHeaders mime.Header
	// OriginalMessage is the returned original, headers and any body.
	OriginalMessage []byte
	// Fields holds every field of the feedback-report part.
	Fields mime.Header
	// Header is the header of the notice itself.
	Header mime.Header
}

// OriginalHeader returns the first value of a header field of the returned
// original message.
func (r *Report) OriginalHeader(name string) string { return r.OriginalHeaders.Get(name) }

// Parse reads a feedback report.
func Parse(raw []byte, opt *Options) (*Report, error) {
	var o Options
	if opt != nil {
		o = *opt
	}
	if o.EmailIDHeader == "" {
		o.EmailIDHeader = DefaultEmailIDHeader
	}
	root, err := mime.ParseEntity(raw, o.Mime)
	if err != nil {
		return nil, err
	}
	fb := root.Find("message/feedback-report")
	if fb == nil {
		return nil, ErrNotARF
	}
	blocks := mime.ParseHeaderBlocks(fb.Body)
	if len(blocks) == 0 {
		return nil, ErrNotARF
	}
	f := blocks[0]
	if !f.Has("Feedback-Type") && !f.Has("User-Agent") && !f.Has("Original-Rcpt-To") {
		return nil, ErrNotARF
	}
	// Extra blocks after the first (some providers repeat per-recipient fields)
	// are merged for the recipient list.
	rep := &Report{
		Header:                root.Header,
		Fields:                f,
		Version:               strings.TrimSpace(f.Get("Version")),
		FeedbackType:          strings.ToLower(strings.TrimSpace(f.Get("Feedback-Type"))),
		UserAgent:             f.Get("User-Agent"),
		OriginalMailFrom:      cleanAddr(f.Get("Original-Mail-From")),
		ReportingMTA:          stripType(f.Get("Reporting-MTA")),
		SourceIP:              strings.TrimSpace(f.Get("Source-IP")),
		ReportedDomain:        strings.TrimSpace(f.Get("Reported-Domain")),
		ReportedURI:           f.Values("Reported-URI"),
		AuthenticationResults: f.Values("Authentication-Results"),
		ArrivalDate:           parseDate(f.Get("Arrival-Date")),
	}
	if rep.ArrivalDate.IsZero() {
		rep.ArrivalDate = parseDate(f.Get("Received-Date"))
	}
	for _, b := range blocks {
		for _, v := range b.Values("Original-Rcpt-To") {
			if a := cleanAddr(v); a != "" && !has(rep.OriginalRcptTo, a) {
				rep.OriginalRcptTo = append(rep.OriginalRcptTo, a)
			}
		}
	}

	root.Walk(func(e *mime.Entity) bool {
		switch e.MediaType {
		case "message/rfc822", "message/global", "text/rfc822-headers", "message/global-headers":
			if rep.OriginalMessage == nil {
				rep.OriginalMessage = e.Body
				rep.OriginalHeaders, _ = mime.ParseHeader(e.Body)
			}
		}
		return true
	})

	if id := strings.TrimSpace(rep.OriginalHeaders.Get("Message-ID")); id != "" {
		rep.OriginalMessageID = strings.TrimSuffix(strings.TrimPrefix(id, "<"), ">")
	} else if id := strings.TrimSpace(f.Get("Original-Message-ID")); id != "" {
		rep.OriginalMessageID = strings.TrimSuffix(strings.TrimPrefix(id, "<"), ">")
	}
	rep.EmailID = strings.TrimSpace(rep.OriginalHeaders.Get(o.EmailIDHeader))
	if len(rep.OriginalRcptTo) == 0 {
		if list, err := mime.ParseAddressList(rep.OriginalHeaders.Get("To")); err == nil {
			for _, a := range list {
				rep.OriginalRcptTo = append(rep.OriginalRcptTo, a.Address)
			}
		}
	}
	return rep, nil
}

// IsComplaint reports whether the report is a complaint about the message: an
// abuse, fraud or virus report. A "not-spam" report takes a complaint back and
// "other" says nothing definite.
func (r *Report) IsComplaint() bool {
	switch r.FeedbackType {
	case "abuse", "fraud", "virus":
		return true
	}
	return false
}

func cleanAddr(v string) string {
	v = strings.TrimSpace(v)
	if stripped, ok := strings.CutPrefix(strings.ToLower(v), "rfc822;"); ok {
		v = strings.TrimSpace(v[len(v)-len(stripped):])
	}
	if a, err := mime.ParseAddress(v); err == nil {
		return a.Address
	}
	return strings.Trim(v, "<> ")
}

func stripType(v string) string {
	if _, rest, ok := strings.Cut(v, ";"); ok {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(v)
}

func parseDate(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	if i := strings.IndexByte(v, '('); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if t, err := netmail.ParseDate(v); err == nil {
		return t
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(n, 0).UTC()
	}
	return time.Time{}
}

func has(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

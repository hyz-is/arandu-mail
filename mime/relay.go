package mime

import (
	"strings"
)

// ResolveRecipients splits the recipients of a submitted message into the
// visible ones and the blind ones, from the parsed message and the SMTP
// envelope.
//
// A client strips the Bcc header before it sends (RFC 5322 section 3.6.3), so
// the blind recipients survive only in the envelope: every envelope address
// that is in neither To nor Cc is a Bcc. A Bcc header that was left in the
// message is honoured too, so a client that does not strip it still works.
// Addresses are compared without regard to case and each blind address is
// returned once.
func ResolveRecipients(m *Message, envelope []string) (to, cc, bcc []Address) {
	visible := map[string]bool{}
	for _, a := range m.To {
		visible[strings.ToLower(a.Address)] = true
	}
	for _, a := range m.Cc {
		visible[strings.ToLower(a.Address)] = true
	}
	seen := map[string]bool{}
	add := func(a Address) {
		key := strings.ToLower(a.Address)
		if key == "" || visible[key] || seen[key] {
			return
		}
		seen[key] = true
		bcc = append(bcc, a)
	}
	for _, a := range m.Bcc {
		add(a)
	}
	for _, e := range envelope {
		add(Address{Address: strings.TrimSpace(e)})
	}
	return m.To, m.Cc, bcc
}

// nonForwardable are the fields that are rebuilt by the builder, added by the
// receiving MTA, or carried by a field of the message structure, so a relay
// that rebuilds the message does not copy them.
var nonForwardable = map[string]bool{
	"authentication-results": true, "bcc": true, "cc": true, "content-disposition": true, "content-id": true,
	"content-length": true, "content-md5": true, "content-transfer-encoding": true, "content-type": true,
	"date": true, "delivered-to": true, "dkim-signature": true, "domainkey-signature": true, "envelope-to": true,
	"errors-to": true, "from": true, "message-id": true, "mime-version": true, "received": true,
	"received-spf": true, "reply-to": true, "return-path": true, "sender": true, "subject": true, "to": true,
	"x-envelope-to": true, "x-original-to": true, "x-received": true, "x-google-dkim-signature": true,
}

var nonForwardablePrefixes = []string{"arc-", "resent-", "x-ses-", "x-unsend-", "x-usesend-"}

// ForwardableHeaders returns the end-to-end header fields of a message that
// still mean something after it is rebuilt: everything except the fields the
// builder writes itself, the trace fields and the signatures. When a field
// repeats, the last value wins, because the public API takes a name and one
// value. A field with an empty value, or whose unfolded value holds a line
// break, is skipped.
func ForwardableHeaders(h Header) map[string]string {
	var out map[string]string
	for _, f := range h.Fields() {
		lower := strings.ToLower(f.Name)
		if nonForwardable[lower] {
			continue
		}
		skip := false
		for _, p := range nonForwardablePrefixes {
			if strings.HasPrefix(lower, p) {
				skip = true
				break
			}
		}
		if skip || f.Value == "" || strings.ContainsAny(f.Value, "\r\n") {
			continue
		}
		if !validHeaderName(f.Name) || strings.ContainsRune(f.Name, ':') {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		// Keep one entry per name, written as the last occurrence wrote it.
		for k := range out {
			if strings.EqualFold(k, f.Name) {
				delete(out, k)
			}
		}
		out[f.Name] = f.Value
	}
	return out
}

package dsn

import (
	"errors"
	netmail "net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/hyz-is/arandu-mail/mime"
)

// ErrNotDSN reports a message that is neither a standard delivery status
// notification nor something that looks like a bounce.
var ErrNotDSN = errors.New("dsn: the message is not a delivery status notification")

// Action is the "Action" field of a per-recipient block (RFC 3464 section 2.3.3).
type Action string

// The actions of RFC 3464.
const (
	ActionFailed    Action = "failed"
	ActionDelayed   Action = "delayed"
	ActionDelivered Action = "delivered"
	ActionRelayed   Action = "relayed"
	ActionExpanded  Action = "expanded"
)

// Recipient is the status of one recipient of the original message.
type Recipient struct {
	// FinalRecipient is the address the message was last sent to (the address
	// part of Final-Recipient, without its "rfc822;" type).
	FinalRecipient string
	// OriginalRecipient is the address given in the original request, when the
	// report names it.
	OriginalRecipient string
	// Action is what the reporting MTA did.
	Action Action
	// Status is the enhanced status code, such as "5.1.1".
	Status string
	// DiagnosticCode is the reply of the remote server as the report quotes it,
	// without its "smtp;" type.
	DiagnosticCode string
	// RemoteMTA is the host that answered, without its "dns;" type.
	RemoteMTA string
	// LastAttemptDate and WillRetryUntil are the dates of the report, zero when
	// absent.
	LastAttemptDate, WillRetryUntil time.Time
	// Fields holds every field of the block.
	Fields mime.Header
}

// SMTPCode returns the three-digit reply code found in the diagnostic code, or
// 0.
func (r Recipient) SMTPCode() int { return findReplyCode(r.DiagnosticCode) }

// EnhancedCode returns Status when it is an enhanced code, or else the first
// one found in the diagnostic code.
func (r Recipient) EnhancedCode() string {
	var x, y, z int
	if s := strings.TrimSpace(r.Status); parseEnhanced(s, &x, &y, &z) {
		return s
	}
	return findEnhancedCode(r.DiagnosticCode)
}

// Classification classifies the failure with Classify. A delivery that is only
// delayed is Transient whatever the text says.
func (r Recipient) Classification() Classification {
	c := Classify(r.SMTPCode(), r.EnhancedCode(), r.DiagnosticCode)
	if r.Action == ActionDelayed && c.Type != Transient {
		return Classification{Transient, General}
	}
	return c
}

// Report is a delivery status notification.
type Report struct {
	// ReportingMTA is the host that wrote the report, without its "dns;" type.
	ReportingMTA string
	// OriginalEnvelopeID is the Original-Envelope-Id of the per-message block.
	OriginalEnvelopeID string
	// ArrivalDate is when the original message reached the reporting MTA.
	ArrivalDate time.Time
	// Recipients are the per-recipient blocks, in order.
	Recipients []Recipient
	// Text is the human-readable part of the notice.
	Text string
	// OriginalHeaders are the header fields of the returned original message,
	// when the report carries it (a message/rfc822 or text/rfc822-headers part).
	OriginalHeaders mime.Header
	// OriginalMessage is the returned original, headers and any body.
	OriginalMessage []byte
	// Heuristic is true when the message was not a standard report and the
	// fields come from reading its text.
	Heuristic bool
	// Header is the header of the notice itself.
	Header mime.Header
}

// OriginalHeader returns the first value of a header field of the returned
// original message, such as "Message-ID" or an "X-...-Email-ID" the sender put
// there.
func (r *Report) OriginalHeader(name string) string { return r.OriginalHeaders.Get(name) }

// Parse reads a delivery status notification. opt bounds the MIME parser; nil
// uses its defaults.
func Parse(raw []byte, opt *mime.Options) (*Report, error) {
	root, err := mime.ParseEntity(raw, opt)
	if err != nil {
		return nil, err
	}
	if root.Header.Len() == 0 {
		return nil, ErrNotDSN
	}
	rep := &Report{Header: root.Header}
	if status := findStatusPart(root); status != nil {
		rep.parseStandard(root, status)
		if len(rep.Recipients) > 0 {
			return rep, nil
		}
		*rep = Report{Header: root.Header}
	}
	if !looksLikeBounce(root) {
		return nil, ErrNotDSN
	}
	rep.parseHeuristic(root, opt)
	return rep, nil
}

func findStatusPart(root *mime.Entity) *mime.Entity {
	return root.Find("message/delivery-status")
}

func (r *Report) parseStandard(root, status *mime.Entity) {
	blocks := mime.ParseHeaderBlocks(status.Body)
	if len(blocks) == 0 {
		return
	}
	msg := blocks[0]
	r.ReportingMTA = stripType(msg.Get("Reporting-MTA"))
	r.OriginalEnvelopeID = msg.Get("Original-Envelope-Id")
	r.ArrivalDate = parseDate(msg.Get("Arrival-Date"))
	for _, b := range blocks[1:] {
		if !b.Has("Final-Recipient") && !b.Has("Original-Recipient") && !b.Has("Action") && !b.Has("Status") {
			continue
		}
		rec := Recipient{
			FinalRecipient:    cleanAddress(stripType(b.Get("Final-Recipient"))),
			OriginalRecipient: cleanAddress(stripType(b.Get("Original-Recipient"))),
			Action:            Action(strings.ToLower(strings.TrimSpace(stripComment(b.Get("Action"))))),
			Status:            strings.TrimSpace(stripComment(b.Get("Status"))),
			DiagnosticCode:    stripType(b.Get("Diagnostic-Code")),
			RemoteMTA:         stripType(b.Get("Remote-MTA")),
			LastAttemptDate:   parseDate(b.Get("Last-Attempt-Date")),
			WillRetryUntil:    parseDate(b.Get("Will-Retry-Until")),
			Fields:            b,
		}
		if rec.FinalRecipient == "" {
			rec.FinalRecipient = rec.OriginalRecipient
		}
		r.Recipients = append(r.Recipients, rec)
	}
	r.collectParts(root)
}

// collectParts fills the human text and the returned original from the tree.
func (r *Report) collectParts(root *mime.Entity) {
	root.Walk(func(e *mime.Entity) bool {
		switch e.MediaType {
		case "text/plain":
			if r.Text == "" && e.Disposition != "attachment" {
				r.Text, _ = e.Text(nil)
			}
		case "message/rfc822", "message/global", "text/rfc822-headers", "message/global-headers", "message/partial":
			if r.OriginalMessage == nil {
				r.OriginalMessage = e.Body
				r.OriginalHeaders, _ = mime.ParseHeader(e.Body)
			}
		}
		return true
	})
}

func stripType(v string) string {
	if _, rest, ok := strings.Cut(v, ";"); ok {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(v)
}

func stripComment(v string) string {
	if i := strings.IndexByte(v, '('); i >= 0 {
		return v[:i]
	}
	return v
}

func cleanAddress(v string) string {
	v = strings.TrimSpace(v)
	if a, err := mime.ParseAddress(v); err == nil {
		return a.Address
	}
	return strings.Trim(v, "<> ")
}

func parseDate(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	t, err := netmail.ParseDate(strings.TrimSpace(stripComment(v)))
	if err != nil {
		return time.Time{}
	}
	return t
}

// ---- heuristics ----

var bounceSubjects = []string{
	"delivery status notification", "undeliverable", "undelivered mail", "mail delivery failed",
	"mail delivery failure", "returned mail", "failure notice", "delivery failure", "delivery has failed",
	"non-delivery", "non delivery", "message not delivered", "could not be delivered", "couldn't be delivered",
	"wasn't delivered", "was not delivered", "delivery problem", "mail system error", "failed delivery",
	"returned to sender", "undelivered message", "mensagem não entregue", "falha na entrega",
}

func looksLikeBounce(root *mime.Entity) bool {
	h := root.Header
	from := strings.ToLower(h.Get("From"))
	if strings.Contains(from, "mailer-daemon") || strings.Contains(from, "postmaster@") ||
		strings.Contains(from, "mail delivery") || strings.Contains(from, "mail-daemon") {
		return true
	}
	subject := strings.ToLower(h.Text("Subject"))
	for _, s := range bounceSubjects {
		if strings.Contains(subject, s) {
			return true
		}
	}
	if h.Has("X-Failed-Recipients") {
		return true
	}
	if strings.TrimSpace(h.Get("Return-Path")) == "<>" {
		auto := strings.ToLower(h.Get("Auto-Submitted"))
		return auto != "" && auto != "no"
	}
	if strings.HasPrefix(strings.ToLower(h.Get("Content-Type")), "multipart/report") {
		return true
	}
	return false
}

func (r *Report) parseHeuristic(root *mime.Entity, opt *mime.Options) {
	r.Heuristic = true
	var texts []string
	root.Walk(func(e *mime.Entity) bool {
		switch e.MediaType {
		case "text/plain", "text/html":
			if e.Disposition == "attachment" {
				return true
			}
			t, _ := e.Text(opt)
			if e.MediaType == "text/html" {
				t = stripTags(t)
			}
			texts = append(texts, t)
		case "message/rfc822", "message/global", "text/rfc822-headers", "message/global-headers":
			if r.OriginalMessage == nil {
				r.OriginalMessage = e.Body
				r.OriginalHeaders, _ = mime.ParseHeader(e.Body)
			}
		}
		return true
	})
	if len(texts) > 0 {
		r.Text = texts[0]
	}
	body := strings.Join(texts, "\n")
	if len(body) > 64<<10 {
		body = body[:64<<10]
	}
	// A bounce that quotes the original inline puts it after a marker.
	if r.OriginalMessage == nil {
		if i := indexAny(body, "----- original message", "-----original message", "--- original message",
			"----- message header follows", "content-type: message/rfc822", "reporting-mta:"); i >= 0 {
			quoted := body[i:]
			if j := strings.Index(quoted, "\n\n"); j >= 0 {
				r.OriginalHeaders, _ = mime.ParseHeader([]byte(quoted[j+2:]))
			}
			body = body[:i]
		}
	}

	candidates := r.candidateRecipients(root.Header, body)
	status := findEnhancedCode(body)
	diag := diagnosticLine(body)
	code := findReplyCode(diag)
	if status == "" {
		status = findEnhancedCode(diag)
	}
	for _, addr := range candidates {
		rec := Recipient{FinalRecipient: addr, Action: ActionFailed, Status: status, DiagnosticCode: diag}
		if code >= 400 && code < 500 || strings.HasPrefix(status, "4.") {
			rec.Action = ActionDelayed
		}
		if strings.Contains(strings.ToLower(body), "will keep trying") || strings.Contains(strings.ToLower(body), "will be retried") {
			rec.Action = ActionDelayed
		}
		r.Recipients = append(r.Recipients, rec)
	}
}

func indexAny(s string, subs ...string) int {
	ls := strings.ToLower(s)
	best := -1
	for _, sub := range subs {
		if i := strings.Index(ls, sub); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	return best
}

// candidateRecipients picks the addresses that failed, from the strongest hint
// to the weakest.
func (r *Report) candidateRecipients(h mime.Header, body string) []string {
	var out []string
	add := func(a string) {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" || contains(out, a) {
			return
		}
		out = append(out, a)
	}
	for _, v := range h.Values("X-Failed-Recipients") {
		for _, part := range strings.Split(v, ",") {
			add(cleanAddress(part))
		}
	}
	if len(out) > 0 {
		return out
	}

	sender := ""
	if a, err := mime.ParseAddress(r.OriginalHeaders.Get("From")); err == nil {
		sender = strings.ToLower(a.Address)
	}
	reporting := ""
	if a, err := mime.ParseAddress(h.Get("From")); err == nil {
		reporting = strings.ToLower(a.Address)
	}
	originalTo := map[string]bool{}
	for _, name := range []string{"To", "Cc", "Bcc"} {
		list, _ := mime.ParseAddressList(r.OriginalHeaders.Get(name))
		for _, a := range list {
			originalTo[strings.ToLower(a.Address)] = true
		}
	}

	found := scanAddresses(body)
	usable := found[:0:0]
	for _, f := range found {
		a := strings.ToLower(f.addr)
		local, _, _ := strings.Cut(a, "@")
		if a == sender || a == reporting || local == "postmaster" || local == "mailer-daemon" ||
			strings.HasPrefix(local, "mailer-daemon") || local == "abuse" || local == "noreply" || local == "no-reply" {
			continue
		}
		usable = append(usable, f)
	}
	// The strongest signal is an address the original message was sent to.
	for _, f := range usable {
		if originalTo[strings.ToLower(f.addr)] {
			add(f.addr)
		}
	}
	if len(out) > 0 {
		return out
	}
	// Next an address introduced the way MTAs introduce a failed one.
	for _, f := range usable {
		if f.angle && f.colonAfter {
			add(f.addr)
		}
	}
	if len(out) == 0 && len(usable) > 0 {
		add(usable[0].addr)
	}
	if len(out) == 0 && len(originalTo) == 1 {
		for a := range originalTo {
			add(a)
		}
	}
	return out
}

type foundAddr struct {
	addr       string
	angle      bool // inside < >
	colonAfter bool // followed by ":"
}

// scanAddresses finds the e-mail addresses in free text.
func scanAddresses(s string) []foundAddr {
	var out []foundAddr
	for i := 0; i < len(s); i++ {
		if s[i] != '@' {
			continue
		}
		l := i
		for l > 0 && isLocalByte(s[l-1]) {
			l--
		}
		r := i + 1
		for r < len(s) && isDomainByte(s[r]) {
			r++
		}
		local, domain := s[l:i], strings.TrimRight(s[i+1:r], ".-")
		if local == "" || !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.Contains(domain, "..") {
			continue
		}
		local = strings.TrimLeft(local, ".")
		if local == "" {
			continue
		}
		end := i + 1 + len(domain)
		fa := foundAddr{addr: local + "@" + domain}
		if l > 0 && s[l-1] == '<' && end < len(s) && s[end] == '>' {
			fa.angle = true
			if end+1 < len(s) && s[end+1] == ':' {
				fa.colonAfter = true
			}
		}
		out = append(out, fa)
		i = r
	}
	return out
}

func isLocalByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._%+-=!#$&'*/?^`{|}~", c) >= 0
}

func isDomainByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-'
}

// diagnosticLine returns the line of the notice that carries the reply of the
// remote server: the one with a reply code, preferably next to "said:" or an
// enhanced code.
func diagnosticLine(body string) string {
	best, bestScore := "", 0
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || len(line) > 1000 {
			continue
		}
		score := 0
		if findReplyCode(line) != 0 {
			score++
		}
		if findEnhancedCode(line) != "" {
			score += 2
		}
		ll := strings.ToLower(line)
		if strings.Contains(ll, " said:") || strings.Contains(ll, "smtp error") || strings.Contains(ll, "remote server") ||
			strings.Contains(ll, "diagnostic") || strings.Contains(ll, "returned") {
			score++
		}
		if score > bestScore {
			best, bestScore = line, score
		}
	}
	if bestScore < 2 {
		return ""
	}
	return best
}

func stripTags(s string) string {
	var sb strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '<':
			in = true
		case c == '>':
			in = false
			sb.WriteByte(' ')
		case !in:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// findEnhancedCode returns the first RFC 3463 status code ("5.1.1") in s: a
// class of 2, 4 or 5, a subject of one to three digits and a detail of one to
// three, not part of a longer number or an IP address.
func findEnhancedCode(s string) string {
	for i := 0; i+5 <= len(s); i++ {
		c := s[i]
		if c != '2' && c != '4' && c != '5' {
			continue
		}
		if i > 0 && (isDigit(s[i-1]) || s[i-1] == '.') {
			continue
		}
		j := i + 1
		ok := true
		for part := 0; part < 2; part++ {
			if j >= len(s) || s[j] != '.' {
				ok = false
				break
			}
			j++
			start := j
			for j < len(s) && isDigit(s[j]) && j-start < 3 {
				j++
			}
			if j == start {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if j < len(s) && (isDigit(s[j]) || (s[j] == '.' && j+1 < len(s) && isDigit(s[j+1]))) {
			continue
		}
		return s[i:j]
	}
	return ""
}

// findReplyCode returns the first three-digit SMTP reply code (2xx, 4xx or
// 5xx) that stands alone in s.
func findReplyCode(s string) int {
	for i := 0; i+3 <= len(s); i++ {
		c := s[i]
		if c != '2' && c != '4' && c != '5' {
			continue
		}
		if !isDigit(s[i+1]) || !isDigit(s[i+2]) {
			continue
		}
		if i > 0 && (isDigit(s[i-1]) || s[i-1] == '.') {
			continue
		}
		if i+3 < len(s) && s[i+3] != ' ' && s[i+3] != '-' && s[i+3] != ':' && s[i+3] != ',' && s[i+3] != ')' && s[i+3] != '.' && s[i+3] != '\'' && s[i+3] != '"' && s[i+3] != '\r' {
			continue
		}
		if i+4 < len(s) && s[i+3] == '.' && isDigit(s[i+4]) {
			continue
		}
		n, err := strconv.Atoi(s[i : i+3])
		if err == nil {
			return n
		}
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

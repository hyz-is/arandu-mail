package dsn

import "strings"

// BounceType is the first level of the SES bounce vocabulary.
type BounceType string

// The bounce types. Permanent means the address will not accept mail and the
// sender should stop (and suppress it); Transient means a later attempt may
// work; Undetermined means the notice did not say.
const (
	Permanent    BounceType = "Permanent"
	Transient    BounceType = "Transient"
	Undetermined BounceType = "Undetermined"
)

// BounceSubType is the second level of the SES bounce vocabulary.
type BounceSubType string

// The bounce sub-types. SES reports Undetermined bounces with no further
// detail; this package gives them General, which is what the useSend API shows
// for a sub-type it does not know.
const (
	General            BounceSubType = "General"
	NoEmail            BounceSubType = "NoEmail"
	Suppressed         BounceSubType = "Suppressed"
	MailboxFull        BounceSubType = "MailboxFull"
	MessageTooLarge    BounceSubType = "MessageTooLarge"
	ContentRejected    BounceSubType = "ContentRejected"
	AttachmentRejected BounceSubType = "AttachmentRejected"
)

// Classification is a bounce type and sub-type.
type Classification struct {
	Type    BounceType
	SubType BounceSubType
}

// Classify decides the type and sub-type of a failed delivery from the reply
// code of the remote server (0 when unknown), the enhanced status code such as
// "5.1.1" ("" when unknown) and the text of the reply or of the notice.
//
// The rules are, in order: a suppression notice is Permanent/Suppressed; a
// full mailbox is Transient/MailboxFull and an oversize message is
// Transient/MessageTooLarge, as SES reports them; an address that does not
// exist (5.1.x, or 550, 551 and 553 with the usual wording) is
// Permanent/NoEmail (a code or reply not given is looked for in the text); a refused attachment or virus is
// Transient/AttachmentRejected and a refused content or spam judgement is
// Transient/ContentRejected; anything else is General under the class of the
// code (5 is Permanent, 4 is Transient), and Undetermined when no code says.
func Classify(code int, enhanced, text string) Classification {
	enhanced = strings.TrimSpace(enhanced)
	if enhanced == "" {
		enhanced = findEnhancedCode(text)
	}
	if code == 0 {
		code = findReplyCode(text)
	}
	lower := strings.ToLower(text)
	class := statusClass(code, enhanced)
	var x, y, z int
	hasEnhanced := parseEnhanced(enhanced, &x, &y, &z)

	switch {
	case containsAny(lower, "suppression list", "on the suppression", "previously bounced", "account-level suppression"):
		return Classification{Permanent, Suppressed}
	case (hasEnhanced && y == 2 && z == 2) || containsAny(lower,
		"mailbox full", "mailbox is full", "over quota", "over the quota", "quota exceeded", "exceeded quota",
		"exceeded storage", "insufficient storage", "disk quota", "mailbox size limit", "inbox is full", "storage limit"):
		return Classification{Transient, MailboxFull}
	case (hasEnhanced && ((y == 3 && z == 4) || (y == 2 && z == 3))) || code == 552 && containsAny(lower, "size", "large") ||
		containsAny(lower, "message too large", "message is too large", "message size exceeds", "exceeds size limit",
			"exceeds the size", "too big", "message length exceeds", "maximum message size", "size limit"):
		return Classification{Transient, MessageTooLarge}
	case class == 5 && hasEnhanced && y == 1 && z != 0 && z != 4 && z != 5 && z != 7 && z != 8 && z != 9:
		// 5.1.1 to 5.1.3, 5.1.6, 5.1.10 and the rest of the address family.
		return Classification{Permanent, NoEmail}
	case class != 4 && !(hasEnhanced && y == 7) && containsAny(lower, "user unknown", "unknown user", "no such user", "user doesn't exist",
		"user does not exist", "does not exist", "doesn't exist", "recipient not found", "recipient address rejected: user",
		"invalid recipient", "unknown recipient", "no mailbox", "mailbox not found", "mailbox unavailable",
		"address not found", "address rejected", "couldn't be found", "could not be found", "unrouteable address",
		"account has been disabled", "account is disabled", "no such recipient", "bad destination mailbox"):
		return Classification{Permanent, NoEmail}
	case containsAny(lower, "attachment", "virus", "malware", "infected", "executable content"):
		return Classification{Transient, AttachmentRejected}
	case (hasEnhanced && x != 2 && y == 6) || (class != 0 && containsAny(lower, "spam", "junk", "phishing",
		"content rejected", "message content", "rejected due to content", "unsolicited", "bulk mail", "suspicious")):
		return Classification{Transient, ContentRejected}
	}
	switch class {
	case 5:
		return Classification{Permanent, General}
	case 4:
		return Classification{Transient, General}
	}
	return Classification{Undetermined, General}
}

// statusClass is the first digit that says whether a failure is permanent (5)
// or temporary (4), taken from the enhanced code and then the reply code.
func statusClass(code int, enhanced string) int {
	if enhanced != "" && (enhanced[0] == '4' || enhanced[0] == '5') {
		return int(enhanced[0] - '0')
	}
	switch {
	case code >= 500 && code < 600:
		return 5
	case code >= 400 && code < 500:
		return 4
	}
	return 0
}

// parseEnhanced reads "x.y.z" into its numbers.
func parseEnhanced(s string, x, y, z *int) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	vals := [3]int{}
	for i, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		vals[i] = n
	}
	*x, *y, *z = vals[0], vals[1], vals[2]
	return *x >= 2 && *x <= 5
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

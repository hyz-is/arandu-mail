package dkim

import (
	"errors"
	"strings"
)

// tag is a name and value of a tag-list (RFC 6376 section 3.2).
type tag struct{ name, value string }

var errTagList = errors.New("dkim: malformed tag-list")

// parseTagList reads "a=1; b=2" into its tags. White space around names and
// values is dropped, a repeated name is an error, and an empty trailing tag
// after the last ";" is allowed.
func parseTagList(s string) ([]tag, error) {
	var out []tag
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || !validTagName(name) {
			return nil, errTagList
		}
		for _, t := range out {
			if t.name == name {
				return nil, errTagList
			}
		}
		out = append(out, tag{name, strings.TrimSpace(value)})
	}
	return out, nil
}

func validTagName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func tagValue(tags []tag, name string) (string, bool) {
	for _, t := range tags {
		if t.name == name {
			return t.value, true
		}
	}
	return "", false
}

// stripWSP removes every white space and line break from s; the base64 values
// of a signature are folded anywhere.
func stripWSP(s string) string {
	if !strings.ContainsAny(s, " \t\r\n") {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

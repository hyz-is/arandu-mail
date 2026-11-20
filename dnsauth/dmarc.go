package dnsauth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Disposition is the action a DMARC policy asks a receiver to take.
type Disposition string

// The policies of RFC 7489.
const (
	DispositionNone       Disposition = "none"
	DispositionQuarantine Disposition = "quarantine"
	DispositionReject     Disposition = "reject"
)

// DMARCRecord is a parsed DMARC policy record.
type DMARCRecord struct {
	// Policy is the "p=" tag, and SubdomainPolicy the "sp=" tag ("" when absent).
	Policy, SubdomainPolicy Disposition
	// ADKIM and ASPF are the alignment modes, 'r' (relaxed, the default) or 's'.
	ADKIM, ASPF byte
	// Percent is the "pct=" tag, 100 by default.
	Percent int
	// RUA and RUF are the aggregate and failure report URIs, as written.
	RUA, RUF []string
	// FailureOptions is the "fo=" tag, "0" by default.
	FailureOptions string
	// ReportInterval is the "ri=" tag in seconds, 86400 by default.
	ReportInterval int
	// Raw is the record text.
	Raw string
}

// ErrDMARCSyntax reports a record that is not a valid DMARC policy.
var ErrDMARCSyntax = errors.New("dnsauth: invalid DMARC record")

// ParseDMARC parses the text of a "v=DMARC1" record. A record with no "p=" but
// with a valid "rua=" is read as p=none, as RFC 7489 section 6.6.3 asks.
func ParseDMARC(txt string) (*DMARCRecord, error) {
	rec := &DMARCRecord{ADKIM: 'r', ASPF: 'r', Percent: 100, FailureOptions: "0", ReportInterval: 86400, Raw: txt}
	parts := strings.Split(txt, ";")
	first := true
	seen := map[string]bool{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrDMARCSyntax, part)
		}
		if first {
			if name != "v" || value != "DMARC1" {
				return nil, fmt.Errorf("%w: the record must start with v=DMARC1", ErrDMARCSyntax)
			}
			first = false
			continue
		}
		if seen[name] {
			continue // a repeated tag: the first one counts
		}
		seen[name] = true
		switch name {
		case "p":
			d, ok := disposition(value)
			if !ok {
				return nil, fmt.Errorf("%w: p=%q", ErrDMARCSyntax, value)
			}
			rec.Policy = d
		case "sp":
			d, ok := disposition(value)
			if !ok {
				return nil, fmt.Errorf("%w: sp=%q", ErrDMARCSyntax, value)
			}
			rec.SubdomainPolicy = d
		case "adkim", "aspf":
			var mode byte
			switch strings.ToLower(value) {
			case "r":
				mode = 'r'
			case "s":
				mode = 's'
			default:
				return nil, fmt.Errorf("%w: %s=%q", ErrDMARCSyntax, name, value)
			}
			if name == "adkim" {
				rec.ADKIM = mode
			} else {
				rec.ASPF = mode
			}
		case "pct":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 100 {
				return nil, fmt.Errorf("%w: pct=%q", ErrDMARCSyntax, value)
			}
			rec.Percent = n
		case "ri":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("%w: ri=%q", ErrDMARCSyntax, value)
			}
			rec.ReportInterval = n
		case "rua":
			rec.RUA = splitURIs(value)
		case "ruf":
			rec.RUF = splitURIs(value)
		case "fo":
			rec.FailureOptions = value
		}
	}
	if first {
		return nil, fmt.Errorf("%w: empty record", ErrDMARCSyntax)
	}
	if rec.Policy == "" {
		if len(rec.RUA) == 0 {
			return nil, fmt.Errorf("%w: no p= tag", ErrDMARCSyntax)
		}
		rec.Policy = DispositionNone
	}
	return rec, nil
}

func disposition(s string) (Disposition, bool) {
	switch d := Disposition(strings.ToLower(s)); d {
	case DispositionNone, DispositionQuarantine, DispositionReject:
		return d, true
	}
	return "", false
}

func splitURIs(v string) []string {
	var out []string
	for _, u := range strings.Split(v, ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// OrganizationalDomain returns the registrable domain of name by the public
// suffix list: "mail.example.co.uk" gives "example.co.uk". A name that has none
// (a public suffix itself, or not a domain) is returned as it is.
func OrganizationalDomain(name string) string {
	name = normalize(name)
	if org, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return org
	}
	return name
}

// Aligned reports whether the domain a mechanism authenticated (the DKIM d=,
// the SPF MAIL FROM domain) is aligned with the From domain: equal in strict
// mode, and sharing the organizational domain in relaxed mode.
func Aligned(fromDomain, authDomain string, strict bool) bool {
	f, a := normalize(fromDomain), normalize(authDomain)
	if f == "" || a == "" {
		return false
	}
	if strict {
		return f == a
	}
	return OrganizationalDomain(f) == OrganizationalDomain(a)
}

// LookupDMARC finds the policy record of a From domain: the "_dmarc" TXT record
// of the domain itself, else of its organizational domain. It returns the
// record and the domain it was published at, or a nil record when there is
// none. Several DMARC records at one name mean there is none (RFC 7489
// section 6.6.3).
func LookupDMARC(ctx context.Context, r Resolver, fromDomain string) (*DMARCRecord, string, error) {
	domain := normalize(fromDomain)
	names := []string{domain}
	if org := OrganizationalDomain(domain); org != domain {
		names = append(names, org)
	}
	for _, d := range names {
		txts, err := r.LookupTXT(ctx, "_dmarc."+d)
		if err != nil {
			if IsNotFound(err) {
				continue
			}
			return nil, "", err
		}
		var found []string
		for _, t := range txts {
			if t = strings.TrimSpace(t); len(t) >= 8 && strings.EqualFold(t[:8], "v=DMARC1") {
				found = append(found, t)
			}
		}
		if len(found) != 1 {
			continue
		}
		rec, err := ParseDMARC(found[0])
		if err != nil {
			continue // an unusable record is the same as none
		}
		return rec, d, nil
	}
	return nil, "", nil
}

// SPFOutcome is what SPF decided about the message.
type SPFOutcome struct {
	// Result is the SPF result and Domain the MAIL FROM (or HELO) domain it was
	// checked for.
	Result SPFResult
	Domain string
}

// DKIMOutcome is one DKIM signature that verified or not.
type DKIMOutcome struct {
	// Pass is true when the signature verified; Domain is its d= tag.
	Pass   bool
	Domain string
}

// DMARCInput is what DMARC needs to evaluate a message.
type DMARCInput struct {
	// FromDomain is the domain of the From header.
	FromDomain string
	SPF        SPFOutcome
	DKIM       []DKIMOutcome
}

// DMARCResult is the outcome of EvaluateDMARC.
type DMARCResult struct {
	// HasPolicy is false when the domain publishes no DMARC record, in which
	// case nothing else is set and Pass is false.
	HasPolicy bool
	// Pass is true when SPF or DKIM passed with an aligned domain.
	Pass bool
	// SPFAligned and DKIMAligned say which mechanism produced the pass.
	SPFAligned, DKIMAligned bool
	// Policy is the disposition that applies to the From domain: the "sp" of
	// the record when it was found at the organizational domain and the From
	// domain is a subdomain, and "p" otherwise.
	Policy Disposition
	// Record is the policy and RecordDomain where it was published.
	Record       *DMARCRecord
	RecordDomain string
}

// EvaluateDMARC finds the policy of the From domain and decides whether the
// message passes: SPF passed and its domain is aligned with From, or a DKIM
// signature verified with an aligned domain (RFC 7489 section 3.1). A DNS
// failure while looking for the record is returned as an error.
func EvaluateDMARC(ctx context.Context, r Resolver, in DMARCInput) (DMARCResult, error) {
	rec, at, err := LookupDMARC(ctx, r, in.FromDomain)
	if err != nil {
		return DMARCResult{}, err
	}
	if rec == nil {
		return DMARCResult{}, nil
	}
	res := DMARCResult{HasPolicy: true, Record: rec, RecordDomain: at, Policy: rec.Policy}
	if normalize(in.FromDomain) != at && rec.SubdomainPolicy != "" {
		res.Policy = rec.SubdomainPolicy
	}
	if in.SPF.Result == SPFPass && Aligned(in.FromDomain, in.SPF.Domain, rec.ASPF == 's') {
		res.SPFAligned = true
	}
	for _, d := range in.DKIM {
		if d.Pass && Aligned(in.FromDomain, d.Domain, rec.ADKIM == 's') {
			res.DKIMAligned = true
			break
		}
	}
	res.Pass = res.SPFAligned || res.DKIMAligned
	return res, nil
}

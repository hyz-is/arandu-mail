package dnsauth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"

	"github.com/hyz-is/arandu-mail/internal/puny"
)

// Status is the verification state of a record or of a domain, with the names
// of the DomainStatus enum of useSend.
type Status string

// The statuses.
const (
	// NotStarted: nothing was looked for yet, or an optional record is absent.
	NotStarted Status = "NOT_STARTED"
	// Pending: the record is not published yet, or not visible yet.
	Pending Status = "PENDING"
	// Success: the record is published and right.
	Success Status = "SUCCESS"
	// Failed: the record is published and wrong, or still missing after the
	// time allowed.
	Failed Status = "FAILED"
	// TemporaryFailure: the DNS did not answer; look again later.
	TemporaryFailure Status = "TEMPORARY_FAILURE"
)

// Purpose says what a record is for.
type Purpose string

// The purposes.
const (
	PurposeDKIM  Purpose = "dkim"
	PurposeSPF   Purpose = "spf"
	PurposeMX    Purpose = "mx"
	PurposeDMARC Purpose = "dmarc"
)

// Record is a DNS record the customer has to publish, with the columns of the
// useSend dashboard.
type Record struct {
	Purpose Purpose
	// Type is "TXT" or "MX".
	Type string
	// Name is the host as the dashboard shows it, relative to the zone: "mail",
	// "meeng._domainkey", "_dmarc". FQDN is the full name that is looked up.
	Name, FQDN string
	// Value is the content: the TXT text, or the host of an MX.
	Value string
	// TTL is "Auto" unless Config.TTL says otherwise.
	TTL string
	// Priority is the MX preference as text ("10"), empty for TXT.
	Priority string
	// Status is set by Verify.
	Status Status
	// Recommended marks the record the domain works without (DMARC).
	Recommended bool
}

// Config describes the records of one sending domain.
type Config struct {
	// Domain is the domain the customer sends from, such as "acme.com" or the
	// subdomain "send.acme.com". The zone is its registrable domain.
	Domain string
	// DKIMSelector is the key selector. Default "meeng".
	DKIMSelector string
	// DKIMPublicKey is the base64 text of the "p=" tag (dkim.KeyPair.PublicKey).
	DKIMPublicKey string
	// DKIMKeyType is "rsa" (the default) or "ed25519". An RSA key is published
	// as "p=KEY" as the useSend dashboard shows it, and an Ed25519 key as
	// "v=DKIM1; k=ed25519; p=KEY", because the default key type is RSA.
	DKIMKeyType string
	// MailFromSubdomain is the label of the bounce domain under Domain.
	// Default "mail".
	MailFromSubdomain string
	// InboundHost is the host the MX points at: the server that receives the
	// bounces. Required.
	InboundHost string
	// MXPriority is the MX preference. Default 10.
	MXPriority int
	// SPFMechanisms are the terms of the SPF record, such as
	// "include:spf.meeng.dev" or "ip4:192.0.2.0/24". Required.
	SPFMechanisms []string
	// SPFAll is the closing term. Default "~all".
	SPFAll string
	// DMARC is the value of the recommended record. Default "v=DMARC1; p=none;".
	DMARC string
	// TTL is shown in the TTL column. Default "Auto".
	TTL string
}

// ErrConfig reports a Config that cannot give records.
var ErrConfig = errors.New("dnsauth: invalid configuration")

// zone splits a domain into the zone and the subdomain under it.
func zone(domain string) (zone, sub string, err error) {
	z, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", "", fmt.Errorf("%w: %q has no registrable domain", ErrConfig, domain)
	}
	return z, strings.TrimSuffix(strings.TrimSuffix(domain, z), "."), nil
}

// Records returns the records Config asks for, in the order of the dashboard:
// the MX and the SPF of the mail-from subdomain, the DKIM key, and the
// recommended DMARC record. Every Status is NotStarted.
func Records(cfg Config) ([]Record, error) {
	domain, err := puny.ToASCII(strings.TrimSuffix(cfg.Domain, "."))
	if err != nil {
		return nil, fmt.Errorf("%w: domain %q", ErrConfig, cfg.Domain)
	}
	domain = strings.ToLower(domain)
	z, sub, err := zone(domain)
	if err != nil {
		return nil, err
	}
	if cfg.DKIMPublicKey == "" || cfg.InboundHost == "" || len(cfg.SPFMechanisms) == 0 {
		return nil, fmt.Errorf("%w: DKIMPublicKey, InboundHost and SPFMechanisms are required", ErrConfig)
	}
	for _, m := range cfg.SPFMechanisms {
		if _, err := parseTerm(m); err != nil {
			return nil, fmt.Errorf("%w: SPF term %q: %v", ErrConfig, m, err)
		}
	}
	selector := orDefault(cfg.DKIMSelector, "meeng")
	mailLabel := orDefault(cfg.MailFromSubdomain, "mail")
	ttl := orDefault(cfg.TTL, "Auto")
	prio := cfg.MXPriority
	if prio == 0 {
		prio = 10
	}
	all := orDefault(cfg.SPFAll, "~all")

	suffix := ""
	if sub != "" {
		suffix = "." + sub
	}
	rel := func(label string) (name, fqdn string) {
		name = label + suffix
		return name, name + "." + z
	}

	dkimValue := "p=" + cfg.DKIMPublicKey
	if strings.EqualFold(cfg.DKIMKeyType, "ed25519") {
		dkimValue = "v=DKIM1; k=ed25519; p=" + cfg.DKIMPublicKey
	}
	spfValue := "v=spf1 " + strings.Join(cfg.SPFMechanisms, " ") + " " + all

	mxName, mxFQDN := rel(mailLabel)
	dkimName, dkimFQDN := rel(selector + "._domainkey")
	return []Record{
		{Purpose: PurposeMX, Type: "MX", Name: mxName, FQDN: mxFQDN, Value: normalize(cfg.InboundHost),
			TTL: ttl, Priority: strconv.Itoa(prio), Status: NotStarted},
		{Purpose: PurposeDKIM, Type: "TXT", Name: dkimName, FQDN: dkimFQDN, Value: dkimValue, TTL: ttl, Status: NotStarted},
		{Purpose: PurposeSPF, Type: "TXT", Name: mxName, FQDN: mxFQDN, Value: spfValue, TTL: ttl, Status: NotStarted},
		{Purpose: PurposeDMARC, Type: "TXT", Name: "_dmarc", FQDN: "_dmarc." + z,
			Value: orDefault(cfg.DMARC, "v=DMARC1; p=none;"), TTL: ttl, Status: NotStarted, Recommended: true},
	}, nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// VerifyOptions tunes Verify.
type VerifyOptions struct {
	// FailMissing makes a record that is not published Failed instead of
	// Pending. Set it once the time allowed for the DNS to propagate has run
	// out.
	FailMissing bool
}

// Verify looks every record up and returns them with their Status set. The
// lookups run together.
func Verify(ctx context.Context, r Resolver, records []Record, opt VerifyOptions) []Record {
	out := make([]Record, len(records))
	copy(out, records)
	var wg sync.WaitGroup
	for i := range out {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i].Status = VerifyRecord(ctx, r, out[i], opt)
		}()
	}
	wg.Wait()
	return out
}

// VerifyRecord checks one record against the DNS.
//
// A DKIM record is Success when a TXT record at its name carries the same
// "p=" key. An SPF record is Success when exactly one SPF record is published
// there and it holds every term asked for (it may hold more). An MX record is
// Success when the host is among the answers with the lowest preference. A
// DMARC record is Success when a valid policy is published; it is
// NotStarted, not Pending, while absent, because the domain works without it.
// A record that is published with another value is Failed.
func VerifyRecord(ctx context.Context, r Resolver, rec Record, opt VerifyOptions) Status {
	missing := Pending
	if opt.FailMissing {
		missing = Failed
	}
	if rec.Recommended && !opt.FailMissing {
		missing = NotStarted
	}
	switch rec.Purpose {
	case PurposeMX:
		mxs, err := r.LookupMX(ctx, rec.FQDN)
		if err != nil {
			if IsNotFound(err) {
				return missing
			}
			return TemporaryFailure
		}
		want := normalize(rec.Value)
		low, found := uint16(65535), false
		for _, mx := range mxs {
			low = min(low, mx.Pref)
		}
		for _, mx := range mxs {
			if normalize(mx.Host) == want && mx.Pref == low {
				found = true
			}
		}
		if found {
			return Success
		}
		return Failed
	case PurposeDKIM:
		txts, err := r.LookupTXT(ctx, rec.FQDN)
		if err != nil {
			if IsNotFound(err) {
				return missing
			}
			return TemporaryFailure
		}
		want := txtTag(rec.Value, "p")
		for _, t := range txts {
			if got := txtTag(t, "p"); got != "" && got == want {
				return Success
			}
		}
		return Failed
	case PurposeSPF:
		txts, err := r.LookupTXT(ctx, rec.FQDN)
		if err != nil {
			if IsNotFound(err) {
				return missing
			}
			return TemporaryFailure
		}
		var published []string
		for _, t := range txts {
			if isSPFRecord(t) {
				published = append(published, t)
			}
		}
		switch len(published) {
		case 0:
			return missing
		case 1:
		default:
			return Failed
		}
		got, err := ParseSPF(published[0])
		if err != nil {
			return Failed
		}
		want, err := ParseSPF(rec.Value)
		if err != nil {
			return Failed
		}
		for _, w := range want.Terms {
			if w.Mechanism == "all" {
				continue
			}
			if !hasTerm(got.Terms, w) {
				return Failed
			}
		}
		return Success
	case PurposeDMARC:
		txts, err := r.LookupTXT(ctx, rec.FQDN)
		if err != nil {
			if IsNotFound(err) {
				return missing
			}
			return TemporaryFailure
		}
		var found []string
		for _, t := range txts {
			if t = strings.TrimSpace(t); len(t) >= 8 && strings.EqualFold(t[:8], "v=DMARC1") {
				found = append(found, t)
			}
		}
		if len(found) == 0 {
			return missing
		}
		if len(found) > 1 {
			return Failed
		}
		if _, err := ParseDMARC(found[0]); err != nil {
			return Failed
		}
		return Success
	}
	return Failed
}

func hasTerm(list []SPFTerm, want SPFTerm) bool {
	for _, t := range list {
		if t.Mechanism != want.Mechanism || t.Qualifier != want.Qualifier {
			continue
		}
		if termString(t) == termString(want) || strings.EqualFold(termString(t), termString(want)) {
			return true
		}
	}
	return false
}

// txtTag returns the value of a tag of a "name=value; name=value" record with
// the white space removed from it.
func txtTag(txt, name string) string {
	for _, part := range strings.Split(txt, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.TrimSpace(k) == name {
			return strings.Join(strings.Fields(v), "")
		}
	}
	return ""
}

// Overall is the status of the domain: Success when the required records (MX,
// SPF and DKIM) all are; Failed when one is; TemporaryFailure when one could
// not be read and none failed; NotStarted when none was looked at; Pending
// otherwise. The recommended DMARC record does not count.
func Overall(records []Record) Status {
	required, success, notStarted := 0, 0, 0
	failed, temp := false, false
	for _, r := range records {
		if r.Recommended {
			continue
		}
		required++
		switch r.Status {
		case Success:
			success++
		case Failed:
			failed = true
		case TemporaryFailure:
			temp = true
		case NotStarted:
			notStarted++
		}
	}
	switch {
	case required == 0:
		return NotStarted
	case failed:
		return Failed
	case temp:
		return TemporaryFailure
	case success == required:
		return Success
	case notStarted == required:
		return NotStarted
	}
	return Pending
}

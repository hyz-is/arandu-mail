package dnsauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MTA-STS (RFC 8461) and TLS-RPT (RFC 8460).

// Errors of the MTA-STS and TLS-RPT readers.
var (
	// ErrNoMTASTS reports a domain with no MTA-STS TXT record.
	ErrNoMTASTS = errors.New("dnsauth: no MTA-STS record")
	// ErrMTASTSSyntax reports a TXT record or a policy that is not valid.
	ErrMTASTSSyntax = errors.New("dnsauth: invalid MTA-STS data")
	// ErrNoTLSRPT reports a domain with no TLS-RPT record.
	ErrNoTLSRPT = errors.New("dnsauth: no TLS-RPT record")
	// ErrTLSRPTSyntax reports a TLS-RPT record that is not valid.
	ErrTLSRPTSyntax = errors.New("dnsauth: invalid TLS-RPT record")
)

// MaxPolicySize is the largest MTA-STS policy accepted (RFC 8461 section 3.3).
const MaxPolicySize = 64 << 10

// MTASTSMode is the "mode" of a policy.
type MTASTSMode string

// The modes. Enforce makes a sender refuse delivery when the MX or its TLS
// does not match; Testing reports and delivers; None says the domain has
// stopped using the policy.
const (
	MTASTSEnforce MTASTSMode = "enforce"
	MTASTSTesting MTASTSMode = "testing"
	MTASTSNone    MTASTSMode = "none"
)

// MTASTSPolicy is a policy file.
type MTASTSPolicy struct {
	// Version is "STSv1".
	Version string
	Mode    MTASTSMode
	// MX are the allowed mail host patterns, such as "mx.example.com" or
	// "*.example.com".
	MX []string
	// MaxAge is how long the policy may be cached, in seconds.
	MaxAge int
}

// ParseMTASTSPolicy reads a policy file: "key: value" lines ended by CRLF or
// LF. "version", "mode" and "max_age" are required, and "mx" is required unless
// the mode is "none". Unknown keys are ignored.
func ParseMTASTSPolicy(body []byte) (*MTASTSPolicy, error) {
	p := &MTASTSPolicy{MaxAge: -1}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("%w: line %q", ErrMTASTSSyntax, line)
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		switch key {
		case "version":
			p.Version = value
		case "mode":
			p.Mode = MTASTSMode(strings.ToLower(value))
		case "mx":
			if value != "" {
				p.MX = append(p.MX, strings.ToLower(strings.TrimSuffix(value, ".")))
			}
		case "max_age":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 31557600 {
				return nil, fmt.Errorf("%w: max_age %q", ErrMTASTSSyntax, value)
			}
			p.MaxAge = n
		}
	}
	if p.Version != "STSv1" {
		return nil, fmt.Errorf("%w: version %q", ErrMTASTSSyntax, p.Version)
	}
	switch p.Mode {
	case MTASTSEnforce, MTASTSTesting, MTASTSNone:
	default:
		return nil, fmt.Errorf("%w: mode %q", ErrMTASTSSyntax, p.Mode)
	}
	if p.MaxAge < 0 {
		return nil, fmt.Errorf("%w: max_age is missing", ErrMTASTSSyntax)
	}
	if p.Mode != MTASTSNone && len(p.MX) == 0 {
		return nil, fmt.Errorf("%w: no mx", ErrMTASTSSyntax)
	}
	return p, nil
}

// String writes the policy as the file to serve, with CRLF line ends.
func (p *MTASTSPolicy) String() string {
	var sb strings.Builder
	sb.WriteString("version: STSv1\r\nmode: " + string(p.Mode) + "\r\n")
	for _, mx := range p.MX {
		sb.WriteString("mx: " + mx + "\r\n")
	}
	sb.WriteString("max_age: " + strconv.Itoa(p.MaxAge) + "\r\n")
	return sb.String()
}

// MatchMX reports whether a mail host name is allowed by the policy: it equals
// a pattern, or a pattern "*.example.com" stands for exactly one label before
// "example.com" (RFC 8461 section 4.1).
func (p *MTASTSPolicy) MatchMX(host string) bool {
	host = normalize(host)
	for _, pat := range p.MX {
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) {
				label := strings.TrimSuffix(host, suffix)
				if label != "" && !strings.Contains(label, ".") {
					return true
				}
			}
			continue
		}
		if host == pat {
			return true
		}
	}
	return false
}

// ParseMTASTSRecord reads the TXT record "v=STSv1; id=20261120T000000" and
// returns its id.
func ParseMTASTSRecord(txt string) (id string, err error) {
	var version string
	for _, part := range strings.Split(txt, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "v":
			version = strings.TrimSpace(value)
		case "id":
			id = strings.TrimSpace(value)
		}
	}
	if version != "STSv1" || id == "" || len(id) > 32 {
		return "", fmt.Errorf("%w: %q", ErrMTASTSSyntax, txt)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return "", fmt.Errorf("%w: id %q", ErrMTASTSSyntax, id)
		}
	}
	return id, nil
}

// MTASTSRecord returns the TXT value to publish at _mta-sts.<domain> for a
// policy version id.
func MTASTSRecord(id string) string { return "v=STSv1; id=" + id }

// HTTPClient is what FetchMTASTSPolicy needs to get the policy. A *http.Client
// satisfies it, provided it does not follow redirects: see NewHTTPClient.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// NewHTTPClient returns a client fit for fetching a policy: HTTPS with the
// system roots, no redirects, and a timeout.
func NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// MTASTSResult is what LookupMTASTS found.
type MTASTSResult struct {
	// ID is the policy id of the TXT record.
	ID string
	// Policy is the policy fetched over HTTPS.
	Policy *MTASTSPolicy
}

// PolicyURL returns where the policy of a domain is published.
func PolicyURL(domain string) string {
	return "https://mta-sts." + normalize(domain) + "/.well-known/mta-sts.txt"
}

// LookupMTASTS reads the TXT record of the domain and fetches its policy. With
// no record it returns ErrNoMTASTS. The policy is fetched only when the record
// exists, over HTTPS at PolicyURL, and must answer 200 with text/plain, no
// more than MaxPolicySize bytes and no redirect.
func LookupMTASTS(ctx context.Context, r Resolver, c HTTPClient, domain string) (*MTASTSResult, error) {
	txts, err := r.LookupTXT(ctx, "_mta-sts."+normalize(domain))
	if err != nil {
		if IsNotFound(err) {
			return nil, ErrNoMTASTS
		}
		return nil, err
	}
	var id string
	count := 0
	for _, t := range txts {
		if strings.HasPrefix(strings.TrimSpace(t), "v=STSv1") {
			count++
			if id, err = ParseMTASTSRecord(t); err != nil {
				return nil, err
			}
		}
	}
	if count == 0 {
		return nil, ErrNoMTASTS
	}
	if count > 1 {
		return nil, fmt.Errorf("%w: more than one record", ErrMTASTSSyntax)
	}
	policy, err := FetchMTASTSPolicy(ctx, c, domain)
	if err != nil {
		return nil, err
	}
	return &MTASTSResult{ID: id, Policy: policy}, nil
}

// FetchMTASTSPolicy gets and parses the policy of a domain.
func FetchMTASTSPolicy(ctx context.Context, c HTTPClient, domain string) (*MTASTSPolicy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, PolicyURL(domain), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dnsauth: fetching the MTA-STS policy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dnsauth: the MTA-STS policy answered %d", resp.StatusCode)
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if mt, _, _ := strings.Cut(ct, ";"); strings.TrimSpace(mt) != "text/plain" {
		return nil, fmt.Errorf("dnsauth: the MTA-STS policy has content type %q, not text/plain", ct)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxPolicySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxPolicySize {
		return nil, fmt.Errorf("dnsauth: the MTA-STS policy is over %d bytes", MaxPolicySize)
	}
	return ParseMTASTSPolicy(body)
}

// TLSRPTRecord is a TLS-RPT record.
type TLSRPTRecord struct {
	// RUA are the report destinations, "mailto:" or "https:" URIs.
	RUA []string
}

// ParseTLSRPT reads the TXT record "v=TLSRPTv1; rua=mailto:tls@example.com".
// Each destination must be a mailto: or https: URI.
func ParseTLSRPT(txt string) (*TLSRPTRecord, error) {
	rec := &TLSRPTRecord{}
	var version string
	for _, part := range strings.Split(txt, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "v":
			version = strings.TrimSpace(value)
		case "rua":
			for _, u := range strings.Split(value, ",") {
				u = strings.TrimSpace(u)
				l := strings.ToLower(u)
				if !strings.HasPrefix(l, "mailto:") && !strings.HasPrefix(l, "https://") || len(u) < 9 {
					return nil, fmt.Errorf("%w: destination %q", ErrTLSRPTSyntax, u)
				}
				rec.RUA = append(rec.RUA, u)
			}
		}
	}
	if version != "TLSRPTv1" || len(rec.RUA) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrTLSRPTSyntax, txt)
	}
	return rec, nil
}

// LookupTLSRPT reads the record at _smtp._tls.<domain>. With none it returns
// ErrNoTLSRPT.
func LookupTLSRPT(ctx context.Context, r Resolver, domain string) (*TLSRPTRecord, error) {
	txts, err := r.LookupTXT(ctx, "_smtp._tls."+normalize(domain))
	if err != nil {
		if IsNotFound(err) {
			return nil, ErrNoTLSRPT
		}
		return nil, err
	}
	var found []string
	for _, t := range txts {
		if strings.HasPrefix(strings.TrimSpace(t), "v=TLSRPTv1") {
			found = append(found, t)
		}
	}
	switch len(found) {
	case 0:
		return nil, ErrNoTLSRPT
	case 1:
		return ParseTLSRPT(found[0])
	}
	return nil, fmt.Errorf("%w: more than one record", ErrTLSRPTSyntax)
}

package dnsauth

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
)

// Resolver is the DNS lookups the package needs. A *net.Resolver satisfies it.
//
// A name that does not exist, or has no record of the type, is reported with a
// *net.DNSError whose IsNotFound is true (net.Resolver does that). Any other
// error is a failure to get an answer.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// DefaultResolver returns the system resolver.
func DefaultResolver() Resolver { return net.DefaultResolver }

// IsNotFound reports whether err says the name or the record does not exist.
func IsNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// IsTemporary reports whether err is a failure to get an answer, as opposed to
// an answer that the record does not exist.
func IsTemporary(err error) bool { return err != nil && !IsNotFound(err) }

func normalize(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

// Fake is an in-memory Resolver for tests. A name it does not know is not
// found; SetError makes a lookup fail instead. It is safe for concurrent use.
type Fake struct {
	mu      sync.Mutex
	txt     map[string][]string
	mx      map[string][]*net.MX
	ip      map[string][]net.IP
	ptr     map[string][]string
	errs    map[string]error
	lookups int
	log     []string
}

// NewFake returns an empty Fake.
func NewFake() *Fake {
	return &Fake{txt: map[string][]string{}, mx: map[string][]*net.MX{}, ip: map[string][]net.IP{},
		ptr: map[string][]string{}, errs: map[string]error{}}
}

// SetTXT sets the TXT records of a name. Each value is one record; a record
// longer than 255 bytes is returned as it is, already joined.
func (f *Fake) SetTXT(name string, values ...string) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txt[normalize(name)] = values
	return f
}

// SetMX sets the MX records of a name.
func (f *Fake) SetMX(name string, records ...MX) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	var list []*net.MX
	for _, r := range records {
		list = append(list, &net.MX{Host: strings.TrimSuffix(r.Host, ".") + ".", Pref: r.Pref})
	}
	f.mx[normalize(name)] = list
	return f
}

// MX is a mail exchanger for Fake.SetMX.
type MX struct {
	Host string
	Pref uint16
}

// SetIP sets the A and AAAA addresses of a name.
func (f *Fake) SetIP(name string, addrs ...string) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	var list []net.IP
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			panic("dnsauth: Fake.SetIP: invalid address " + a)
		}
		list = append(list, ip)
	}
	f.ip[normalize(name)] = list
	return f
}

// SetPTR sets the names an address resolves back to.
func (f *Fake) SetPTR(addr string, names ...string) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ptr[addr] = names
	return f
}

// SetError makes lookups of one kind ("txt", "mx", "ip" or "ptr") for a name
// fail with err.
func (f *Fake) SetError(kind, name string, err error) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[kind+":"+normalize(name)] = err
	return f
}

// Lookups returns how many lookups have been made.
func (f *Fake) Lookups() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookups
}

// Log returns the lookups made, as "kind:name", in order.
func (f *Fake) Log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *Fake) begin(kind, name string) (string, error) {
	f.lookups++
	n := normalize(name)
	f.log = append(f.log, kind+":"+n)
	if err := f.errs[kind+":"+n]; err != nil {
		return n, err
	}
	return n, nil
}

// LookupTXT implements Resolver.
func (f *Fake) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.begin("txt", name)
	if err != nil {
		return nil, err
	}
	if v, ok := f.txt[n]; ok && len(v) > 0 {
		return append([]string(nil), v...), nil
	}
	return nil, notFound(name)
}

// LookupMX implements Resolver.
func (f *Fake) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.begin("mx", name)
	if err != nil {
		return nil, err
	}
	if v, ok := f.mx[n]; ok && len(v) > 0 {
		out := make([]*net.MX, len(v))
		for i, r := range v {
			c := *r
			out[i] = &c
		}
		return out, nil
	}
	return nil, notFound(name)
}

// LookupIP implements Resolver. network is "ip", "ip4" or "ip6".
func (f *Fake) LookupIP(_ context.Context, network, host string) ([]net.IP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.begin("ip", host)
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, ip := range f.ip[n] {
		is4 := ip.To4() != nil
		if network == "ip4" && !is4 || network == "ip6" && is4 {
			continue
		}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, notFound(host)
	}
	return out, nil
}

// LookupAddr implements Resolver.
func (f *Fake) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.begin("ptr", addr); err != nil {
		return nil, err
	}
	if v, ok := f.ptr[addr]; ok && len(v) > 0 {
		out := make([]string, len(v))
		for i, n := range v {
			out[i] = strings.TrimSuffix(n, ".") + "."
		}
		return out, nil
	}
	return nil, notFound(addr)
}

var _ Resolver = (*Fake)(nil)
var _ Resolver = (*net.Resolver)(nil)

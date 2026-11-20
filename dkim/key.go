package dkim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Algorithm names a DKIM signing algorithm, as written in the "a=" tag.
type Algorithm string

// The algorithms the package signs and verifies.
const (
	RSASHA256     Algorithm = "rsa-sha256"
	Ed25519SHA256 Algorithm = "ed25519-sha256"
)

// KeyType is the "k=" value of a key record for the algorithm.
func (a Algorithm) KeyType() string {
	if a == Ed25519SHA256 {
		return "ed25519"
	}
	return "rsa"
}

// ErrUnsupportedKey reports a private key that is neither RSA nor Ed25519.
var ErrUnsupportedKey = errors.New("dkim: the key is neither RSA nor Ed25519")

// KeyPair is a DKIM private key and what is known about it.
type KeyPair struct {
	// Algorithm is the algorithm the key signs with.
	Algorithm Algorithm
	// Signer holds the private key.
	Signer crypto.Signer
}

// GenerateKey creates a key for the algorithm: RSA with a 2048-bit modulus, or
// Ed25519.
func GenerateKey(alg Algorithm) (*KeyPair, error) {
	switch alg {
	case RSASHA256:
		return GenerateRSAKey(2048)
	case Ed25519SHA256:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &KeyPair{Algorithm: alg, Signer: priv}, nil
	}
	return nil, fmt.Errorf("dkim: unknown algorithm %q", alg)
}

// GenerateRSAKey creates an RSA key of the given size. Sizes under 1024 bits
// are refused, as no verifier accepts them (RFC 8301), and 2048 is the size to
// publish.
func GenerateRSAKey(bits int) (*KeyPair, error) {
	if bits < 1024 {
		return nil, fmt.Errorf("dkim: RSA keys under 1024 bits are not accepted by verifiers (%d)", bits)
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &KeyPair{Algorithm: RSASHA256, Signer: priv}, nil
}

// ParsePrivateKey reads a PEM private key: PKCS#8 (RSA or Ed25519) or PKCS#1
// (RSA). Anything else is ErrUnsupportedKey.
func ParsePrivateKey(pemBytes []byte) (*KeyPair, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("dkim: no PEM block in the private key")
	}
	var key any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: PEM type %q", ErrUnsupportedKey, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("dkim: reading the private key: %w", err)
	}
	return newKeyPair(key)
}

func newKeyPair(key any) (*KeyPair, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &KeyPair{Algorithm: RSASHA256, Signer: k}, nil
	case ed25519.PrivateKey:
		return &KeyPair{Algorithm: Ed25519SHA256, Signer: k}, nil
	}
	return nil, ErrUnsupportedKey
}

// KeyPairFrom wraps an RSA or Ed25519 private key.
func KeyPairFrom(key crypto.Signer) (*KeyPair, error) { return newKeyPair(key) }

// PrivateKeyPEM returns the private key as PKCS#8 PEM, the form ParsePrivateKey
// reads back.
func (k *KeyPair) PrivateKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.Signer)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// PublicKey returns the base64 text of the "p=" tag: the DER SubjectPublicKeyInfo
// of an RSA key, or the 32 raw bytes of an Ed25519 key (RFC 8463).
func (k *KeyPair) PublicKey() (string, error) { return PublicKeyText(k.Signer.Public()) }

// PublicKeyText formats a public key as the "p=" value.
func PublicKeyText(pub crypto.PublicKey) (string, error) {
	switch p := pub.(type) {
	case ed25519.PublicKey:
		return base64.StdEncoding.EncodeToString(p), nil
	case *rsa.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(p)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(der), nil
	}
	return "", ErrUnsupportedKey
}

// TXT returns the value of the DNS TXT record that publishes the public key,
// for example "v=DKIM1; k=rsa; p=MIIBIj...". It can exceed 255 characters:
// SplitTXT cuts it for a DNS provider that wants character-strings.
func (k *KeyPair) TXT() (string, error) {
	p, err := k.PublicKey()
	if err != nil {
		return "", err
	}
	return "v=DKIM1; k=" + k.Algorithm.KeyType() + "; p=" + p, nil
}

// RecordName returns the DNS name of the key record: selector._domainkey.domain.
func RecordName(selector, domain string) string {
	return selector + "._domainkey." + strings.TrimSuffix(domain, ".")
}

// SplitTXT cuts a TXT value into the character-strings of at most 255 bytes a
// DNS record carries. Resolvers join them again before the value is read.
func SplitTXT(value string) []string {
	if len(value) <= 255 {
		return []string{value}
	}
	var out []string
	for len(value) > 255 {
		out = append(out, value[:255])
		value = value[255:]
	}
	return append(out, value)
}

package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadPrivateKey reads a PEM-encoded RSA private key (PKCS#1 or PKCS#8) from
// disk. The access token is signed with this key (RS256); only the
// corresponding public key needs to be shared with other systems that want
// to verify tokens independently — see the JWKS endpoint.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key file %s: %w", path, err)
	}
	key, err := ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// ParsePrivateKeyPEM parses PEM-encoded RSA private key bytes (PKCS#1 or
// PKCS#8) directly — the same format LoadPrivateKey reads from disk, usable
// when the key instead comes from an env var (e.g. a platform with no
// persistent/writable filesystem to put a keys/private.pem on).
func ParsePrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an RSA key")
	}
	return key, nil
}

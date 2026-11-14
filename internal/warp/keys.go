package warp

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

type KeyMaterial struct {
	PrivateDER string `json:"private_key_der"`
	PublicDER  string `json:"public_key_der"`
	RawD       []byte `json:"-"`
	RawX       []byte `json:"-"`
	RawY       []byte `json:"-"`
}

func GenerateWireGuardKeypair() (private, public string, err error) {
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return "", "", e
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
func GenerateMasqueKeys() (KeyMaterial, error) {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return KeyMaterial{}, e
	}
	priv, e := x509.MarshalECPrivateKey(k)
	if e != nil {
		return KeyMaterial{}, e
	}
	pub, e := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if e != nil {
		return KeyMaterial{}, e
	}
	return KeyMaterial{PrivateDER: base64.StdEncoding.EncodeToString(priv), PublicDER: base64.StdEncoding.EncodeToString(pub), RawD: fixed(k.D.Bytes(), 32), RawX: fixed(k.X.Bytes(), 32), RawY: fixed(k.Y.Bytes(), 32)}, nil
}
func NormalizeServerPublicKey(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "-----BEGIN") {
		b, _ := pem.Decode([]byte(raw))
		if b == nil {
			return "", fmt.Errorf("invalid public key PEM")
		}
		raw = base64.StdEncoding.EncodeToString(b.Bytes)
	} else {
		raw = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, raw)
		if _, e := base64.StdEncoding.DecodeString(raw); e != nil {
			return "", fmt.Errorf("invalid public key base64: %w", e)
		}
	}
	return raw, nil
}
func fixed(in []byte, n int) []byte {
	o := make([]byte, n)
	if len(in) > n {
		in = in[len(in)-n:]
	}
	copy(o[n-len(in):], in)
	return o
}

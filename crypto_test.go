package hpke

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/dh/sidh"
)

func randomBytes(size int) []byte {
	out := make([]byte, size)
	rand.Read(out)
	return out
}

func TestKEMSchemes(t *testing.T) {
	schemes := []KEMScheme{
		dhkemScheme{ecdhScheme{curve: elliptic.P256()}},
		dhkemScheme{ecdhScheme{curve: elliptic.P521()}},
		dhkemScheme{x25519Scheme{}},
		dhkemScheme{x448Scheme{}},
		sikeScheme{sidh.Fp503},
	}

	for i, s := range schemes {
		skR, pkR, err := s.GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Fatalf("[%d] Error generating KEM key pair: %v", i, err)
		}

		zzI, enc, err := s.Encap(rand.Reader, pkR)
		if err != nil {
			t.Fatalf("[%d] Error in KEM encapsulation: %v", i, err)
		}

		zzR, err := s.Decap(enc, skR)
		if err != nil {
			t.Fatalf("[%d] Error in KEM decapsulation: %v", i, err)
		}

		if !bytes.Equal(zzI, zzR) {
			t.Fatalf("[%d] Asymmetric KEM results [%x] != [%x]", i, zzI, zzR)
		}
	}
}

func TestDHSchemes(t *testing.T) {
	schemes := []dhScheme{
		ecdhScheme{curve: elliptic.P256()},
		ecdhScheme{curve: elliptic.P521()},
		x25519Scheme{},
		x448Scheme{},
	}

	for i, s := range schemes {
		skA, pkA, err := s.GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Fatalf("[%d] Error generating DH key pair: %v", i, err)
		}

		skB, pkB, err := s.GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Fatalf("[%d] Error generating DH key pair: %v", i, err)
		}

		enc := s.Marshal(pkA)
		_, err = s.Unmarshal(enc)
		if err != nil {
			t.Fatalf("[%d] Error parsing DH public key: %v", i, err)
		}

		zzAB, err := s.DH(skA, pkB)
		if err != nil {
			t.Fatalf("[%d] Error performing DH operation: %v", i, err)
		}

		zzBA, err := s.DH(skB, pkA)
		if err != nil {
			t.Fatalf("[%d] Error performing DH operation: %v", i, err)
		}

		if !bytes.Equal(zzAB, zzBA) {
			t.Fatalf("[%d] Asymmetric DH results [%x] != [%x]", i, zzAB, zzBA)
		}

		if len(s.Marshal(pkA)) != len(s.Marshal(pkB)) {
			t.Fatalf("[%d] Non-constant public key size [%x] != [%x]", i, len(s.Marshal(pkA)), len(s.Marshal(pkB)))
		}
	}
}

func TestAEADSchemes(t *testing.T) {
	schemes := []AEADScheme{
		aesgcmScheme{keySize: 16},
		aesgcmScheme{keySize: 32},
		chachaPolyScheme{},
	}

	for i, s := range schemes {
		key := randomBytes(s.KeySize())
		nonce := randomBytes(s.NonceSize())
		pt := randomBytes(1024)
		aad := randomBytes(1024)

		aead, err := s.New(key)
		if err != nil {
			t.Fatalf("[%d] Error instantiating AEAD: %v", i, err)
		}

		ctWithAAD := aead.Seal(nil, nonce, pt, aad)
		ptWithAAD, err := aead.Open(nil, nonce, ctWithAAD, aad)
		if err != nil {
			t.Fatalf("[%d] Error decrypting with AAD: %v", i, err)
		}

		if !bytes.Equal(ptWithAAD, pt) {
			t.Fatalf("[%d] Incorrect decryption [%x] != [%x]", i, ptWithAAD, pt)
		}

		ctWithoutAAD := aead.Seal(nil, nonce, pt, nil)
		ptWithoutAAD, err := aead.Open(nil, nonce, ctWithoutAAD, nil)
		if err != nil {
			t.Fatalf("[%d] Error decrypting without AAD: %v", i, err)
		}

		if !bytes.Equal(ptWithoutAAD, pt) {
			t.Fatalf("[%d] Incorrect decryption [%x] != [%x]", i, ptWithoutAAD, pt)
		}

		if bytes.Equal(ctWithAAD, ctWithoutAAD) {
			t.Fatalf("[%d] AAD not included in ciphertext", i)
		}
	}
}

package ecies

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestECIES(t *testing.T) {
	suites := []byte{
		X25519_HKDF_SHA256_AESGCM128,
		X25519_HKDF_SHA256_CHACHA20POLY1305,
		X448_HKDF_SHA512_AESGCM256,
		X448_HKDF_SHA512_CHACHA20POLY1305,
		P256_HKDF_SHA256_AESGCM128,
		P256_HKDF_SHA256_CHACHA20POLY1305,
		P521_HKDF_SHA512_AESGCM256,
		P521_HKDF_SHA512_CHACHA20POLY1305,
	}

	for i, id := range suites {
		logString(fmt.Sprintf("~~~ Suite %d %d ~~~", i, id))

		suite, err := GetRegisteredCipherSuite(id)
		if err != nil {
			t.Fatalf("[%d] Error retreiving ciphersuite: %s", i, err)
		}

		privR, pubR, err := suite.KEM.Generate(rand.Reader)
		if err != nil {
			t.Fatalf("[%d] Error generating DH key pair: %s", i, err)
		}

		original := []byte("Beauty is truth, truth beauty")
		aad := []byte("that is all // Ye know on earth, and all ye need to know")
		info := []byte("Ode on a Grecian Urn")
		enc, encrypted, err := Seal(suite, rand.Reader, pubR, info, aad, original)
		if err != nil {
			t.Fatalf("[%d] Error in Seal: %s", i, err)
		}

		decrypted, err := Open(suite, privR, enc, info, aad, encrypted)
		if err != nil {
			t.Fatalf("[%d] Error in Open: %s", i, err)
		}

		if !bytes.Equal(decrypted, original) {
			t.Fatalf("[%d] Incorrect decryption: [%x] != [%x]", i, decrypted, original)
		}
	}
}

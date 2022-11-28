package hpke

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/dh/sidh"
	"github.com/stretchr/testify/require"
)

func randomBytes(size int) []byte {
	out := make([]byte, size)
	rand.Read(out)
	return out
}

func TestKEMSchemes(t *testing.T) {
	schemes := []KEMScheme{
		&dhkemScheme{group: x25519Scheme{}},
		&dhkemScheme{group: x448Scheme{}},
		&dhkemScheme{group: ecdhScheme{curve: elliptic.P256(), KDF: hkdfScheme{hash: crypto.SHA256}}},
		&dhkemScheme{group: ecdhScheme{curve: elliptic.P521(), KDF: hkdfScheme{hash: crypto.SHA256}}},
		&kyber512Scheme{},
		&kyber768Scheme{},
		&sikeScheme{field: sidh.Fp503, KDF: hkdfScheme{hash: crypto.SHA512}},
		&sikeScheme{field: sidh.Fp751, KDF: hkdfScheme{hash: crypto.SHA512}},
	}

	for i, s := range schemes {
		ikm := make([]byte, s.PrivateKeySize())
		rand.Reader.Read(ikm)

		skR, pkR, err := s.DeriveKeyPair(ikm)
		require.Nil(t, err, "[%d] Error generating KEM key pair: %v", i, err)

		sharedSecretI, enc, err := s.Encap(rand.Reader, pkR)
		require.Nil(t, err, "[%d] Error in KEM encapsulation: %v", i, err)

		sharedSecretR, err := s.Decap(enc, skR)
		require.Nil(t, err, "[%d] Error in KEM decapsulation: %v", i, err)

		require.Equal(t, sharedSecretI, sharedSecretR, "[%d] Asymmetric KEM results [%x] != [%x]", i, sharedSecretI, sharedSecretR)
	}
}

func TestDHSchemes(t *testing.T) {
	schemes := []dhScheme{
		ecdhScheme{curve: elliptic.P256(), KDF: hkdfScheme{hash: crypto.SHA256}},
		ecdhScheme{curve: elliptic.P521(), KDF: hkdfScheme{hash: crypto.SHA512}},
		x25519Scheme{},
		x448Scheme{},
	}

	for i, s := range schemes {
		ikm := make([]byte, s.PrivateKeySize())
		rand.Reader.Read(ikm)
		skA, pkA, err := s.DeriveKeyPair(ikm)
		require.Nil(t, err, "[%d] Error generating DH key pair: %v", i, err)

		rand.Reader.Read(ikm)
		skB, pkB, err := s.DeriveKeyPair(ikm)
		require.Nil(t, err, "[%d] Error generating DH key pair: %v", i, err)

		enc := s.SerializePublicKey(pkA)
		_, err = s.DeserializePublicKey(enc)
		require.Nil(t, err, "[%d] Error parsing DH public key: %v", i, err)

		sharedSecretAB, err := s.DH(skA, pkB)
		require.Nil(t, err, "[%d] Error performing DH operation: %v", i, err)

		sharedSecretBA, err := s.DH(skB, pkA)
		require.Nil(t, err, "[%d] Error performing DH operation: %v", i, err)
		require.Equal(t, sharedSecretAB, sharedSecretBA, "[%d] Asymmetric DH results [%x] != [%x]", i, sharedSecretAB, sharedSecretBA)

		pkAn := len(s.SerializePublicKey(pkA))
		pkBn := len(s.SerializePublicKey(pkB))
		require.Equal(t, pkAn, pkBn, "[%d] Non-constant public key size [%x] != [%x]", i, pkAn, pkBn)
	}
}

func TestAEADSchemes(t *testing.T) {
	schemes := []AEADScheme{
		aesgcmScheme{keySize: 16},
		aesgcmScheme{keySize: 32},
		chachaPolyScheme{},
	}

	for i, s := range schemes {
		key := randomBytes(int(s.KeySize()))
		nonce := randomBytes(int(s.NonceSize()))
		pt := randomBytes(1024)
		aad := randomBytes(1024)

		aead, err := s.New(key)
		require.Nil(t, err, "[%d] Error instantiating AEAD: %v", i, err)

		ctWithAAD := aead.Seal(nil, nonce, pt, aad)
		ptWithAAD, err := aead.Open(nil, nonce, ctWithAAD, aad)
		require.Nil(t, err, "[%d] Error decrypting with AAD: %v", i, err)
		require.Equal(t, ptWithAAD, pt, "[%d] Incorrect decryption [%x] != [%x]", i, ptWithAAD, pt)

		ctWithoutAAD := aead.Seal(nil, nonce, pt, nil)
		ptWithoutAAD, err := aead.Open(nil, nonce, ctWithoutAAD, nil)
		require.Nil(t, err, "[%d] Error decrypting without AAD: %v", i, err)
		require.Equal(t, ptWithoutAAD, pt, "[%d] Incorrect decryption [%x] != [%x]", i, ptWithoutAAD, pt)

		require.NotEqual(t, ctWithAAD, ctWithoutAAD, "[%d] AAD not included in ciphertext", i)
	}
}

func TestExportOnlyAEADScheme(t *testing.T) {
	scheme, ok := aeads[AEAD_EXPORT_ONLY]

	require.True(t, ok, "Export-only AEAD lookup failed")
	require.Equal(t, scheme.ID(), AEAD_EXPORT_ONLY, "Export-only AEAD ID mismatch")
	require.Panics(t, func() {
		_, _ = scheme.New([]byte{0x00})
	}, "New() did not panic")
	require.Panics(t, func() {
		_ = scheme.KeySize()
	}, "KeySize() did not panic")
	require.Panics(t, func() {
		_ = scheme.NonceSize()
	}, "NonceSize() did not panic")
}

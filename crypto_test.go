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
		&sikeScheme{field: sidh.Fp503, KDF: hkdfScheme{hash: crypto.SHA512}},
		&sikeScheme{field: sidh.Fp751, KDF: hkdfScheme{hash: crypto.SHA512}},
	}

	for _, s := range schemes {
		ikm := make([]byte, s.PrivateKeySize())
		rand.Reader.Read(ikm)

		skR, pkR, err := s.DeriveKeyPair(ikm)
		require.Nil(t, err)

		sharedSecretI, enc, err := s.Encap(rand.Reader, pkR)
		require.Nil(t, err)

		sharedSecretR, err := s.Decap(enc, skR)
		require.Nil(t, err)

		require.Equal(t, sharedSecretI, sharedSecretR)
	}
}

func TestDHSchemes(t *testing.T) {
	schemes := []dhScheme{
		ecdhScheme{curve: elliptic.P256(), KDF: hkdfScheme{hash: crypto.SHA256}},
		ecdhScheme{curve: elliptic.P521(), KDF: hkdfScheme{hash: crypto.SHA512}},
		x25519Scheme{},
		x448Scheme{},
	}

	for _, s := range schemes {
		ikm := make([]byte, s.PrivateKeySize())
		rand.Reader.Read(ikm)
		skA, pkA, err := s.DeriveKeyPair(ikm)
		require.Nil(t, err)

		rand.Reader.Read(ikm)
		skB, pkB, err := s.DeriveKeyPair(ikm)
		require.Nil(t, err)

		enc := s.SerializePublicKey(pkA)
		_, err = s.DeserializePublicKey(enc)
		require.Nil(t, err)

		sharedSecretAB, err := s.DH(skA, pkB)
		require.Nil(t, err)

		sharedSecretBA, err := s.DH(skB, pkA)
		require.Nil(t, err)

		require.Equal(t, sharedSecretAB, sharedSecretBA)

		pkAm := s.SerializePublicKey(pkA)
		pkBm := s.SerializePublicKey(pkB)
		require.Equal(t, len(pkAm), len(pkBm))
	}
}

func TestAEADSchemes(t *testing.T) {
	schemes := []AEADScheme{
		aesgcmScheme{keySize: 16},
		aesgcmScheme{keySize: 32},
		chachaPolyScheme{},
	}

	for _, s := range schemes {
		key := randomBytes(int(s.KeySize()))
		nonce := randomBytes(int(s.NonceSize()))
		pt := randomBytes(1024)
		aad := randomBytes(1024)

		aead, err := s.New(key)
		require.Nil(t, err)

		ctWithAAD := aead.Seal(nil, nonce, pt, aad)
		ptWithAAD, err := aead.Open(nil, nonce, ctWithAAD, aad)
		require.Nil(t, err)
		require.Equal(t, ptWithAAD, pt)

		ctWithoutAAD := aead.Seal(nil, nonce, pt, nil)
		ptWithoutAAD, err := aead.Open(nil, nonce, ctWithoutAAD, nil)
		require.Nil(t, err)
		require.Equal(t, ptWithoutAAD, pt)
		require.NotEqual(t, ctWithAAD, ctWithoutAAD)
	}
}

func TestExportOnlyAEADScheme(t *testing.T) {
	scheme, ok := aeads[AEAD_EXPORT_ONLY]

	require.True(t, ok, "Export-only AEAD lookup failed")
	require.Equal(t, scheme.ID(), AEAD_EXPORT_ONLY, "Export-only AEAD ID mismatch")
	require.Panics(t, func() { scheme.New([]byte{0x00}) })
	require.Panics(t, func() { scheme.KeySize() })
	require.Panics(t, func() { scheme.NonceSize() })
}

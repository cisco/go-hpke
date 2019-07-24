package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"fmt"
	"io"
	"math/big"

	_ "crypto/sha256"
	_ "crypto/sha512"

	"git.schwanenlied.me/yawning/x448.git"
	"github.com/cloudflare/circl/dh/sidh"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

////////
// DHKEM

type dhScheme interface {
	GenerateKeyPair(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error)
	Marshal(pk KEMPublicKey) []byte
	Unmarshal(enc []byte) (KEMPublicKey, error)
	DH(priv KEMPrivateKey, pub KEMPublicKey) ([]byte, error)
	PublicKeySize() int
}

type dhkemScheme struct {
	group dhScheme
}

func (s dhkemScheme) GenerateKeyPair(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error) {
	return s.group.GenerateKeyPair(rand)
}

func (s dhkemScheme) Marshal(pk KEMPublicKey) []byte {
	return s.group.Marshal(pk)
}

func (s dhkemScheme) Unmarshal(enc []byte) (KEMPublicKey, error) {
	return s.group.Unmarshal(enc)
}

func (s dhkemScheme) Encap(rand io.Reader, pkR KEMPublicKey) ([]byte, []byte, error) {
	skE, pkE, err := s.group.GenerateKeyPair(rand)
	if err != nil {
		return nil, nil, err
	}

	zz, err := s.group.DH(skE, pkR)
	if err != nil {
		return nil, nil, err
	}

	return zz, s.group.Marshal(pkE), nil
}

func (s dhkemScheme) Decap(enc []byte, skR KEMPrivateKey) ([]byte, error) {
	pkE, err := s.group.Unmarshal(enc)
	if err != nil {
		return nil, err
	}

	zz, err := s.group.DH(skR, pkE)
	if err != nil {
		return nil, err
	}

	return zz, nil
}

func (s dhkemScheme) AuthEncap(rand io.Reader, pkR KEMPublicKey, skI KEMPrivateKey) ([]byte, []byte, error) {

	skE, pkE, err := s.group.GenerateKeyPair(rand)
	if err != nil {
		return nil, nil, err
	}

	zzER, err := s.group.DH(skE, pkR)
	if err != nil {
		return nil, nil, err
	}

	zzIR, err := s.group.DH(skI, pkR)
	if err != nil {
		return nil, nil, err
	}

	zz := append(zzER, zzIR...)
	return zz, s.group.Marshal(pkE), nil
}

func (s dhkemScheme) AuthDecap(enc []byte, skR KEMPrivateKey, pkI KEMPublicKey) ([]byte, error) {
	pkE, err := s.group.Unmarshal(enc)
	if err != nil {
		return nil, err
	}

	zzER, err := s.group.DH(skR, pkE)
	if err != nil {
		return nil, err
	}

	zzIR, err := s.group.DH(skR, pkI)
	if err != nil {
		return nil, err
	}

	zz := append(zzER, zzIR...)
	return zz, nil
}

func (s dhkemScheme) PublicKeySize() int {
	return s.group.PublicKeySize()
}

////////////////////////
// ECDH with NIST curves

type ecdhPrivateKey struct {
	curve elliptic.Curve
	d     []byte
	x, y  *big.Int
}

func (priv ecdhPrivateKey) PublicKey() KEMPublicKey {
	return &ecdhPublicKey{priv.curve, priv.x, priv.y}
}

type ecdhPublicKey struct {
	curve elliptic.Curve
	x, y  *big.Int
}

type ecdhScheme struct {
	curve elliptic.Curve
}

func (s ecdhScheme) GenerateKeyPair(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error) {
	d, x, y, err := elliptic.GenerateKey(s.curve, rand)
	if err != nil {
		return nil, nil, err
	}

	priv := &ecdhPrivateKey{s.curve, d, x, y}
	return priv, priv.PublicKey(), nil
}

func (s ecdhScheme) Marshal(pk KEMPublicKey) []byte {
	raw := pk.(*ecdhPublicKey)
	return elliptic.Marshal(raw.curve, raw.x, raw.y)
}

func (s ecdhScheme) Unmarshal(enc []byte) (KEMPublicKey, error) {
	x, y := elliptic.Unmarshal(s.curve, enc)
	if x == nil {
		return nil, fmt.Errorf("Error unmarshaling public key")
	}

	return &ecdhPublicKey{s.curve, x, y}, nil
}

func (s ecdhScheme) DH(priv KEMPrivateKey, pub KEMPublicKey) ([]byte, error) {
	ecdhPriv, ok := priv.(*ecdhPrivateKey)
	if !ok {
		return nil, fmt.Errorf("Private key not suitable for ECDH")
	}

	ecdhPub, ok := pub.(*ecdhPublicKey)
	if !ok {
		return nil, fmt.Errorf("Public key not suitable for ECDH")
	}

	zzInt, _ := s.curve.Params().ScalarMult(ecdhPub.x, ecdhPub.y, ecdhPriv.d)
	zz := zzInt.Bytes()

	size := (s.curve.Params().BitSize + 7) >> 3
	pad := make([]byte, size-len(zz))
	zz = append(pad, zz...)

	return zz, nil
}

func (s ecdhScheme) PublicKeySize() int {
	feSize := (s.curve.Params().BitSize + 7) >> 3
	return 1 + 2*feSize
}

///////////////////
// ECDH with X25519

type x25519PrivateKey struct {
	val [32]byte
}

func (priv x25519PrivateKey) PublicKey() KEMPublicKey {
	pub := &x25519PublicKey{}
	curve25519.ScalarBaseMult(&pub.val, &priv.val)
	return pub
}

type x25519PublicKey struct {
	val [32]byte
}

type x25519Scheme struct{}

func (s x25519Scheme) GenerateKeyPair(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error) {
	priv := &x25519PrivateKey{}
	_, err := rand.Read(priv.val[:])
	if err != nil {
		return nil, nil, err
	}

	return priv, priv.PublicKey(), nil
}

func (s x25519Scheme) Marshal(pk KEMPublicKey) []byte {
	raw := pk.(*x25519PublicKey)
	return raw.val[:]
}

func (s x25519Scheme) Unmarshal(enc []byte) (KEMPublicKey, error) {
	if len(enc) != 32 {
		return nil, fmt.Errorf("Error unmarshaling X25519 public key")
	}

	pub := &x25519PublicKey{}
	copy(pub.val[:], enc)
	return pub, nil
}

func (s x25519Scheme) DH(priv KEMPrivateKey, pub KEMPublicKey) ([]byte, error) {
	xPriv, ok := priv.(*x25519PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Private key not suitable for X25519: %+v", priv)
	}

	xPub, ok := pub.(*x25519PublicKey)
	if !ok {
		return nil, fmt.Errorf("Private key not suitable for X25519")
	}

	// TODO ScalarMult
	var zz [32]byte
	curve25519.ScalarMult(&zz, &xPriv.val, &xPub.val)
	return zz[:], nil
}

func (s x25519Scheme) PublicKeySize() int {
	return 32
}

///////////////////
// ECDH with X448

type x448PrivateKey struct {
	val [56]byte
}

func (priv x448PrivateKey) PublicKey() KEMPublicKey {
	pub := &x448PublicKey{}
	x448.ScalarBaseMult(&pub.val, &priv.val)
	return pub
}

type x448PublicKey struct {
	val [56]byte
}

type x448Scheme struct{}

func (s x448Scheme) GenerateKeyPair(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error) {
	priv := &x448PrivateKey{}
	_, err := rand.Read(priv.val[:])
	if err != nil {
		return nil, nil, err
	}

	return priv, priv.PublicKey(), nil
}

func (s x448Scheme) Marshal(pk KEMPublicKey) []byte {
	raw := pk.(*x448PublicKey)
	return raw.val[:]
}

func (s x448Scheme) Unmarshal(enc []byte) (KEMPublicKey, error) {
	if len(enc) != 56 {
		return nil, fmt.Errorf("Error unmarshaling X448 public key")
	}

	pub := &x448PublicKey{}
	copy(pub.val[:], enc)
	return pub, nil
}

func (s x448Scheme) DH(priv KEMPrivateKey, pub KEMPublicKey) ([]byte, error) {
	xPriv, ok := priv.(*x448PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Private key not suitable for X448: %+v", priv)
	}

	xPub, ok := pub.(*x448PublicKey)
	if !ok {
		return nil, fmt.Errorf("Public key not suitable for X448: %+v", pub)
	}

	var zz [56]byte
	x448.ScalarMult(&zz, &xPriv.val, &xPub.val)
	return zz[:], nil
}

func (s x448Scheme) PublicKeySize() int {
	return 56
}

///////
// SIKE

type sikePublicKey struct {
	field uint8
	pub   *sidh.PublicKey
}

type sikePrivateKey struct {
	field uint8
	priv  *sidh.PrivateKey
	pub   *sidh.PublicKey
}

func (priv sikePrivateKey) PublicKey() KEMPublicKey {
	return &sikePublicKey{priv.field, priv.pub}
}

type sikeScheme struct {
	field uint8
}

func (s sikeScheme) GenerateKeyPair(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error) {
	rawPriv := sidh.NewPrivateKey(s.field, sidh.KeyVariantSike)
	err := rawPriv.Generate(rand)
	if err != nil {
		return nil, nil, err
	}

	rawPub := sidh.NewPublicKey(s.field, sidh.KeyVariantSike)
	rawPriv.GeneratePublicKey(rawPub)

	priv := &sikePrivateKey{s.field, rawPriv, rawPub}
	return priv, priv.PublicKey(), nil
}

func (s sikeScheme) Marshal(pk KEMPublicKey) []byte {
	raw := pk.(*sikePublicKey)
	out := make([]byte, raw.pub.Size())
	raw.pub.Export(out)
	return out
}

func (s sikeScheme) Unmarshal(enc []byte) (KEMPublicKey, error) {
	rawPub := sidh.NewPublicKey(s.field, sidh.KeyVariantSike)
	if len(enc) != rawPub.Size() {
		return nil, fmt.Errorf("Invalid public key size")
	}

	err := rawPub.Import(enc)
	if err != nil {
		return nil, err
	}

	return &sikePublicKey{s.field, rawPub}, nil
}

func (s sikeScheme) newKEM(rand io.Reader) (*sidh.KEM, error) {
	switch s.field {
	case sidh.Fp503:
		return sidh.NewSike503(rand), nil
	case sidh.Fp751:
		return sidh.NewSike751(rand), nil
	}
	return nil, fmt.Errorf("Invalid field")
}

func (s sikeScheme) Encap(rand io.Reader, pkR KEMPublicKey) ([]byte, []byte, error) {
	raw := pkR.(*sikePublicKey)

	kem, err := s.newKEM(rand)
	if err != nil {
		return nil, nil, err
	}

	enc := make([]byte, kem.CiphertextSize())
	zz := make([]byte, kem.SharedSecretSize())
	err = kem.Encapsulate(enc, zz, raw.pub)
	if err != nil {
		return nil, nil, err
	}

	return zz, enc, nil
}

type panicReader struct{}

func (p panicReader) Read(unused []byte) (int, error) {
	panic("Should not read")
}

func (s sikeScheme) Decap(enc []byte, skR KEMPrivateKey) ([]byte, error) {
	raw := skR.(*sikePrivateKey)

	kem, err := s.newKEM(panicReader{})
	if err != nil {
		return nil, err
	}

	zz := make([]byte, kem.SharedSecretSize())
	err = kem.Decapsulate(zz, raw.priv, raw.pub, enc)
	if err != nil {
		return nil, err
	}

	return zz, nil
}

func (s sikeScheme) PublicKeySize() int {
	rawPub := sidh.NewPublicKey(s.field, sidh.KeyVariantSike)
	return rawPub.Size()
}

//////////
// AES-GCM

type aesgcmScheme struct {
	keySize int
}

func (s aesgcmScheme) New(key []byte) (cipher.AEAD, error) {
	if len(key) != s.keySize {
		return nil, fmt.Errorf("Incorrect key size %d != %d", len(key), s.keySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func (s aesgcmScheme) KeySize() int {
	return s.keySize
}

func (s aesgcmScheme) NonceSize() int {
	return 12
}

//////////
// ChaCha20-Poly1305

type chachaPolyScheme struct{}

func (s chachaPolyScheme) New(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

func (s chachaPolyScheme) KeySize() int {
	return chacha20poly1305.KeySize
}

func (s chachaPolyScheme) NonceSize() int {
	return chacha20poly1305.NonceSize
}

///////
// HKDF

type hkdfScheme struct {
	hash crypto.Hash
}

func (s hkdfScheme) Extract(salt, ikm []byte) []byte {
	saltOrZero := salt

	// if [salt is] not provided, it is set to a string of HashLen zeros
	if salt == nil {
		saltOrZero = make([]byte, s.hash.Size())
	}

	h := hmac.New(s.hash.New, saltOrZero)
	h.Write(ikm)
	return h.Sum(nil)
}

func (s hkdfScheme) Expand(prk, info []byte, outLen int) []byte {
	out := []byte{}
	T := []byte{}
	i := byte(1)
	for len(out) < outLen {
		block := append(T, info...)
		block = append(block, i)

		h := hmac.New(s.hash.New, prk)
		h.Write(block)

		T = h.Sum(nil)
		out = append(out, T...)
		i++
	}
	return out[:outLen]
}

func (s hkdfScheme) OutputSize() int {
	return s.hash.Size()
}

///////////////////////////
// Pre-defined ciphersuites

const (
	X25519_HKDF_SHA256_AESGCM128        uint16 = 0x01
	X25519_HKDF_SHA256_CHACHA20POLY1305 uint16 = 0x02
	X448_HKDF_SHA512_AESGCM256          uint16 = 0x03
	X448_HKDF_SHA512_CHACHA20POLY1305   uint16 = 0x04
	P256_HKDF_SHA256_AESGCM128          uint16 = 0x05
	P256_HKDF_SHA256_CHACHA20POLY1305   uint16 = 0x06
	P521_HKDF_SHA512_AESGCM256          uint16 = 0x07
	P521_HKDF_SHA512_CHACHA20POLY1305   uint16 = 0x08
	SIKE503_HKDF_SHA256_AESGCM128       uint16 = 0xff
	SIKE751_HKDF_SHA512_AESGCM256       uint16 = 0xfe
)

var ciphersuites = map[uint16]CipherSuite{
	X25519_HKDF_SHA256_AESGCM128: {
		ID:   X25519_HKDF_SHA256_AESGCM128,
		KEM:  dhkemScheme{x25519Scheme{}},
		KDF:  hkdfScheme{hash: crypto.SHA256},
		AEAD: aesgcmScheme{keySize: 16},
	},

	X25519_HKDF_SHA256_CHACHA20POLY1305: {
		ID:   X25519_HKDF_SHA256_CHACHA20POLY1305,
		KEM:  dhkemScheme{x25519Scheme{}},
		KDF:  hkdfScheme{hash: crypto.SHA256},
		AEAD: chachaPolyScheme{},
	},

	X448_HKDF_SHA512_AESGCM256: {
		ID:   X448_HKDF_SHA512_AESGCM256,
		KEM:  dhkemScheme{x448Scheme{}},
		KDF:  hkdfScheme{hash: crypto.SHA512},
		AEAD: aesgcmScheme{keySize: 32},
	},

	X448_HKDF_SHA512_CHACHA20POLY1305: {
		ID:   X448_HKDF_SHA512_CHACHA20POLY1305,
		KEM:  dhkemScheme{x448Scheme{}},
		KDF:  hkdfScheme{hash: crypto.SHA512},
		AEAD: chachaPolyScheme{},
	},

	P256_HKDF_SHA256_AESGCM128: {
		ID:   P256_HKDF_SHA256_AESGCM128,
		KEM:  dhkemScheme{ecdhScheme{curve: elliptic.P256()}},
		KDF:  hkdfScheme{hash: crypto.SHA256},
		AEAD: aesgcmScheme{keySize: 16},
	},

	P256_HKDF_SHA256_CHACHA20POLY1305: {
		ID:   P256_HKDF_SHA256_CHACHA20POLY1305,
		KEM:  dhkemScheme{ecdhScheme{curve: elliptic.P256()}},
		KDF:  hkdfScheme{hash: crypto.SHA256},
		AEAD: chachaPolyScheme{},
	},

	P521_HKDF_SHA512_AESGCM256: {
		ID:   P521_HKDF_SHA512_AESGCM256,
		KEM:  dhkemScheme{ecdhScheme{curve: elliptic.P521()}},
		KDF:  hkdfScheme{hash: crypto.SHA512},
		AEAD: aesgcmScheme{keySize: 32},
	},

	P521_HKDF_SHA512_CHACHA20POLY1305: {
		ID:   P521_HKDF_SHA512_CHACHA20POLY1305,
		KEM:  dhkemScheme{ecdhScheme{curve: elliptic.P521()}},
		KDF:  hkdfScheme{hash: crypto.SHA512},
		AEAD: chachaPolyScheme{},
	},

	SIKE503_HKDF_SHA256_AESGCM128: {
		ID:   SIKE503_HKDF_SHA256_AESGCM128,
		KEM:  sikeScheme{sidh.Fp503},
		KDF:  hkdfScheme{hash: crypto.SHA256},
		AEAD: aesgcmScheme{keySize: 16},
	},

	SIKE751_HKDF_SHA512_AESGCM256: {
		ID:   SIKE751_HKDF_SHA512_AESGCM256,
		KEM:  sikeScheme{sidh.Fp751},
		KDF:  hkdfScheme{hash: crypto.SHA512},
		AEAD: aesgcmScheme{keySize: 32},
	},
}

func GetRegisteredCipherSuite(id uint16) (CipherSuite, error) {
	suite, ok := ciphersuites[id]
	if !ok {
		return CipherSuite{}, fmt.Errorf("Unknown ciphersuite id")
	}

	return suite, nil
}

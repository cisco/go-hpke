package ecies

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
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

////////
// DHKEM

type dhkemScheme struct {
	group DHScheme
}

func (s dhkemScheme) Generate(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error) {
	return s.group.Generate(rand)
}

func (s dhkemScheme) Encap(rand io.Reader, pubR KEMPublicKey) ([]byte, []byte, error) {
	privE, pubE, err := s.group.Generate(rand)
	if err != nil {
		return nil, nil, err
	}

	zz, err := s.group.Derive(privE, pubR)
	if err != nil {
		return nil, nil, err
	}

	return zz, pubE.Bytes(), nil
}

func (s dhkemScheme) Decap(enc []byte, privR KEMPrivateKey) ([]byte, error) {
	pubE, err := s.group.ParsePublicKey(enc)
	if err != nil {
		return nil, err
	}

	zz, err := s.group.Derive(privR, pubE)
	if err != nil {
		return nil, err
	}

	return zz, nil
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

func (pub ecdhPublicKey) Bytes() []byte {
	return elliptic.Marshal(pub.curve, pub.x, pub.y)
}

type ecdhScheme struct {
	curve elliptic.Curve
}

func (s ecdhScheme) ParsePublicKey(enc []byte) (KEMPublicKey, error) {
	x, y := elliptic.Unmarshal(s.curve, enc)
	if x == nil {
		return nil, fmt.Errorf("Error unmarshaling public key")
	}

	return &ecdhPublicKey{s.curve, x, y}, nil
}

func (s ecdhScheme) Generate(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error) {
	d, x, y, err := elliptic.GenerateKey(s.curve, rand)
	if err != nil {
		return nil, nil, err
	}

	priv := &ecdhPrivateKey{s.curve, d, x, y}
	return priv, priv.PublicKey(), nil
}

func (s ecdhScheme) Derive(priv KEMPrivateKey, pub KEMPublicKey) ([]byte, error) {
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

func (pub x25519PublicKey) Bytes() []byte {
	return pub.val[:]
}

type x25519Scheme struct{}

func (s x25519Scheme) ParsePublicKey(enc []byte) (KEMPublicKey, error) {
	if len(enc) != 32 {
		return nil, fmt.Errorf("Error unmarshaling X25519 public key")
	}

	pub := &x25519PublicKey{}
	copy(pub.val[:], enc)
	return pub, nil
}

func (s x25519Scheme) Generate(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error) {
	priv := &x25519PrivateKey{}
	_, err := rand.Read(priv.val[:])
	if err != nil {
		return nil, nil, err
	}

	return priv, priv.PublicKey(), nil
}

func (s x25519Scheme) Derive(priv KEMPrivateKey, pub KEMPublicKey) ([]byte, error) {
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

func (pub x448PublicKey) Bytes() []byte {
	return pub.val[:]
}

type x448Scheme struct{}

func (s x448Scheme) ParsePublicKey(enc []byte) (KEMPublicKey, error) {
	if len(enc) != 56 {
		return nil, fmt.Errorf("Error unmarshaling X448 public key")
	}

	pub := &x448PublicKey{}
	copy(pub.val[:], enc)
	return pub, nil
}

func (s x448Scheme) Generate(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error) {
	priv := &x448PrivateKey{}
	_, err := rand.Read(priv.val[:])
	if err != nil {
		return nil, nil, err
	}

	return priv, priv.PublicKey(), nil
}

func (s x448Scheme) Derive(priv KEMPrivateKey, pub KEMPublicKey) ([]byte, error) {
	xPriv, ok := priv.(*x448PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Private key not suitable for X448: %+v", priv)
	}

	xPub, ok := pub.(*x448PublicKey)
	if !ok {
		return nil, fmt.Errorf("Public key not suitable for X448: %+v", pub)
	}

	// TODO ScalarMult
	var zz [56]byte
	x448.ScalarMult(&zz, &xPriv.val, &xPub.val)
	return zz[:], nil
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
	X25519_HKDF_SHA256_AESGCM128        byte = 0x01
	X25519_HKDF_SHA256_CHACHA20POLY1305 byte = 0x02
	X448_HKDF_SHA512_AESGCM256          byte = 0x03
	X448_HKDF_SHA512_CHACHA20POLY1305   byte = 0x04
	P256_HKDF_SHA256_AESGCM128          byte = 0x05
	P256_HKDF_SHA256_CHACHA20POLY1305   byte = 0x06
	P521_HKDF_SHA512_AESGCM256          byte = 0x07
	P521_HKDF_SHA512_CHACHA20POLY1305   byte = 0x08
)

var ciphersuites = map[byte]CipherSuite{
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
}

func GetRegisteredCipherSuite(id byte) (CipherSuite, error) {
	suite, ok := ciphersuites[id]
	if !ok {
		return CipherSuite{}, fmt.Errorf("Unknown ciphersuite id")
	}

	return suite, nil
}

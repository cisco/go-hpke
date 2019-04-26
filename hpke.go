package hpke

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"log"
)

const (
	debug = true
)

type KEMPrivateKey interface {
	PublicKey() KEMPublicKey
}

type KEMPublicKey interface{}

type KEMScheme interface {
	GenerateKeyPair(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error)
	Marshal(pk KEMPublicKey) []byte
	Unmarshal(enc []byte) (KEMPublicKey, error)
	Encap(rand io.Reader, pkR KEMPublicKey) ([]byte, []byte, error)
	Decap(enc []byte, skR KEMPrivateKey) ([]byte, error)
	AuthEncap(rand io.Reader, pkR KEMPublicKey, skI KEMPrivateKey) ([]byte, []byte, error)
	AuthDecap(enc []byte, skR KEMPrivateKey, pkI KEMPublicKey) ([]byte, error)
}

type KDFScheme interface {
	Extract(salt, ikm []byte) []byte
	Expand(prk, info []byte, L int) []byte
	OutputSize() int
}

type AEADScheme interface {
	New(key []byte) (cipher.AEAD, error)
	KeySize() int
	NonceSize() int
}

type CipherSuite struct {
	ID   uint16
	KEM  KEMScheme
	KDF  KDFScheme
	AEAD AEADScheme
}

type HPKEMode byte

const (
	modeBase HPKEMode = 0x00
	modePSK  HPKEMode = 0x01
	modeAuth HPKEMode = 0x02
)

func logString(val string) {
	if debug {
		log.Printf("%s", val)
	}
}

func logVal(name string, value []byte) {
	if debug {
		log.Printf("  %6s %x", name, value)
	}
}

///////
// Core

func setupCore(suite CipherSuite, mode HPKEMode, secret, kemContext, info []byte) (key, nonce []byte) {
	// context = ciphersuite + mode +
	//					 len(kemContext) + kemContext +
	//					 len(info) + info
	context := []byte{byte(suite.ID) >> 8, byte(suite.ID), byte(mode)}
	context = append(context, byte(len(kemContext)))
	context = append(context, kemContext...)
	context = append(context, byte(len(info)))
	context = append(context, info...)

	// key = Expand(secret, "hpke key" || context, Nk)
	keyContext := append([]byte("hpke key"), context...)
	key = suite.KDF.Expand(secret, keyContext, suite.AEAD.KeySize())

	// nonce = Expand(secret, "hpke nonce" || context, Nn)
	nonceContext := append([]byte("hpke nonce"), context...)
	nonce = suite.KDF.Expand(secret, nonceContext, suite.AEAD.NonceSize())
	return
}

type context struct {
	aead  cipher.AEAD
	seq   uint64
	nonce []byte
}

func (ctx *context) updateNonce() {
	ctx.seq += 1
	if ctx.seq == 0 {
		panic("sequence number wrapped")
	}

	buf := make([]byte, 8)
	delta := ctx.seq ^ (ctx.seq - 1)
	binary.BigEndian.PutUint64(buf, delta)

	Nn := len(ctx.nonce)
	for i := range buf {
		ctx.nonce[Nn-8+i] ^= buf[i]
	}
}

type EncryptContext struct {
	context
}

func newEncContext(suite CipherSuite, key, nonce []byte) (*EncryptContext, error) {
	aead, err := suite.AEAD.New(key)
	if err != nil {
		return nil, err
	}

	ctx := context{aead, 0, nonce}
	return &EncryptContext{ctx}, nil
}

func (ctx *EncryptContext) Seal(aad, pt []byte) []byte {
	ct := ctx.aead.Seal(nil, ctx.nonce, pt, aad)
	ctx.updateNonce()
	return ct
}

type DecryptContext struct {
	context
}

func newDecContext(suite CipherSuite, key, nonce []byte) (*DecryptContext, error) {
	aead, err := suite.AEAD.New(key)
	if err != nil {
		return nil, err
	}

	ctx := context{aead, 0, nonce}
	return &DecryptContext{ctx}, nil
}

func (ctx *DecryptContext) Open(aad, ct []byte) ([]byte, error) {
	pt, err := ctx.aead.Open(nil, ctx.nonce, ct, aad)
	if err != nil {
		return nil, err
	}

	ctx.updateNonce()
	return pt, nil
}

///////
// Base

func setupBase(suite CipherSuite, pkR KEMPublicKey, zz, enc, info []byte) (key, nonce []byte) {
	// kemContext = enc + pkR
	kemContext := append(enc, suite.KEM.Marshal(pkR)...)

	// secret = Extract(0*Nh, zz)
	zero := bytes.Repeat([]byte{0}, suite.KDF.OutputSize())
	secret := suite.KDF.Extract(zero, zz)

	key, nonce = setupCore(suite, modeBase, secret, kemContext, info)
	return
}

func SetupBaseI(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, info []byte) ([]byte, *EncryptContext, error) {
	// zz, enc = Encap(pkR)
	zz, enc, err := suite.KEM.Encap(rand, pkR)
	if err != nil {
		return nil, nil, err
	}

	key, nonce := setupBase(suite, pkR, zz, enc, info)
	ctx, err := newEncContext(suite, key, nonce)
	return enc, ctx, err
}

func SetupBaseR(suite CipherSuite, skR KEMPrivateKey, enc, info []byte) (*DecryptContext, error) {
	// zz = Decap(enc, skR)
	zz, err := suite.KEM.Decap(enc, skR)
	if err != nil {
		return nil, err
	}

	key, nonce := setupBase(suite, skR.PublicKey(), zz, enc, info)
	return newDecContext(suite, key, nonce)
}

//////
// PSK

func setupPSK(suite CipherSuite, pkR KEMPublicKey, zz, enc, psk, pskID, info []byte) (key, nonce []byte) {
	// kemContext = enc + pkR + pskID
	kemContext := append(enc, suite.KEM.Marshal(pkR)...)
	kemContext = append(kemContext, pskID...)

	// secret = Extract(psk, zz)
	secret := suite.KDF.Extract(psk, zz)

	key, nonce = setupCore(suite, modePSK, secret, kemContext, info)
	return
}

func SetupPSKI(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, psk, pskID, info []byte) ([]byte, *EncryptContext, error) {
	// zz, enc = Encap(pkR)
	zz, enc, err := suite.KEM.Encap(rand, pkR)
	if err != nil {
		return nil, nil, err
	}

	key, nonce := setupPSK(suite, pkR, zz, enc, psk, pskID, info)
	ctx, err := newEncContext(suite, key, nonce)
	return enc, ctx, err
}

func SetupPSKR(suite CipherSuite, skR KEMPrivateKey, enc, psk, pskID, info []byte) (*DecryptContext, error) {
	// zz = Decap(enc, skR)
	zz, err := suite.KEM.Decap(enc, skR)
	if err != nil {
		return nil, err
	}

	key, nonce := setupPSK(suite, skR.PublicKey(), zz, enc, psk, pskID, info)
	return newDecContext(suite, key, nonce)
}

///////
// Auth

func setupAuth(suite CipherSuite, pkR, pkI KEMPublicKey, zz, enc, info []byte) (key, nonce []byte) {
	// kemContext = enc + pkR + pkI
	kemContext := append(enc, suite.KEM.Marshal(pkR)...)
	kemContext = append(kemContext, suite.KEM.Marshal(pkI)...)

	// secret = Extract(0*Nh, zz)
	zero := bytes.Repeat([]byte{0}, suite.KDF.OutputSize())
	secret := suite.KDF.Extract(zero, zz)

	key, nonce = setupCore(suite, modeAuth, secret, kemContext, info)
	return
}

func SetupAuthI(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, skI KEMPrivateKey, info []byte) ([]byte, *EncryptContext, error) {
	// zz, enc = AuthEncap(pkR, skI)
	zz, enc, err := suite.KEM.AuthEncap(rand, pkR, skI)
	if err != nil {
		return nil, nil, err
	}

	key, nonce := setupAuth(suite, pkR, skI.PublicKey(), zz, enc, info)
	ctx, err := newEncContext(suite, key, nonce)
	return enc, ctx, err
}

func SetupAuthR(suite CipherSuite, skR KEMPrivateKey, pkI KEMPublicKey, enc, info []byte) (*DecryptContext, error) {
	// zz = AuthDecap(enc, skR, pkI)
	zz, err := suite.KEM.AuthDecap(enc, skR, pkI)
	if err != nil {
		return nil, err
	}

	key, nonce := setupAuth(suite, skR.PublicKey(), pkI, zz, enc, info)
	return newDecContext(suite, key, nonce)
}

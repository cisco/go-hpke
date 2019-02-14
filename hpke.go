package hpke

import (
	"bytes"
	"crypto/cipher"
	"io"
	"log"
)

const (
	debug = true
)

type KEMPrivateKey interface {
	PublicKey() KEMPublicKey
}

type KEMPublicKey interface {
	Bytes() []byte
}

type KEMScheme interface {
	Generate(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error)
	Encap(rand io.Reader, pkR KEMPublicKey) ([]byte, []byte, error)
	Decap(enc []byte, skR KEMPrivateKey) ([]byte, error)
	AuthEncap(rand io.Reader, pkR KEMPublicKey, skI KEMPrivateKey) ([]byte, []byte, error)
	AuthDecap(enc []byte, skR KEMPrivateKey, pkI KEMPublicKey) ([]byte, error)
}

type DHScheme interface {
	ParsePublicKey(enc []byte) (KEMPublicKey, error)
	Generate(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error)
	Derive(priv KEMPrivateKey, pub KEMPublicKey) ([]byte, error)
}

type AEADScheme interface {
	New(key []byte) (cipher.AEAD, error)
	KeySize() int
	NonceSize() int
}

type KDFScheme interface {
	Extract(salt, ikm []byte) []byte
	Expand(prk, info []byte, outLen int) []byte
	OutputSize() int
}

type CipherSuite struct {
	ID   uint16
	KEM  KEMScheme
	KDF  KDFScheme
	AEAD AEADScheme
}

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

func setupCore(suite CipherSuite, secret, kemContext, info []byte) (keyIR, nonceIR []byte) {
	// context = ciphersuite || kemContext || info
	context := []byte{byte(suite.ID) >> 8, byte(suite.ID)}
	context = append(context, kemContext...)
	context = append(context, info...)

	// keyIR = Expand(secret, "hpke key" || context, Nk)
	keyContext := append([]byte("hpke key"), context...)
	keyIR = suite.KDF.Expand(secret, keyContext, suite.AEAD.KeySize())

	// nonceIR = Expand(secret, "hpke nonce" || context, Nn)
	nonceContext := append([]byte("hpke nonce"), context...)
	nonceIR = suite.KDF.Expand(secret, nonceContext, suite.AEAD.NonceSize())
	return
}

// TODO split encrypt and decrypt context
type Context struct {
	aead  cipher.AEAD
	nonce []byte
}

func newContext(suite CipherSuite, key, nonce []byte) (*Context, error) {
	aead, err := suite.AEAD.New(key)
	if err != nil {
		return nil, err
	}

	return &Context{aead, nonce}, nil
}

func (ctx *Context) Seal(aad, pt []byte) []byte {
	ct := ctx.aead.Seal(nil, ctx.nonce, pt, aad)
	// TODO update nonce
	return ct
}

func (ctx *Context) Open(aad, ct []byte) ([]byte, error) {
	pt, err := ctx.aead.Open(nil, ctx.nonce, ct, aad)
	if err != nil {
		return nil, err
	}

	// TODO update nonce
	return pt, nil
}

///////
// Base

func setupBaseCore(suite CipherSuite, pkR KEMPublicKey, zz, enc, info []byte) (keyIR, nonceIR []byte) {
	// kemContext = enc || pkR
	kemContext := append(enc, pkR.Bytes()...)

	// secret = Extract(0^Nh, zz)
	zero := bytes.Repeat([]byte{0}, suite.KDF.OutputSize())
	secret := suite.KDF.Extract(zero, zz)

	keyIR, nonceIR = setupCore(suite, secret, kemContext, info)
	return
}

func SetupIBase(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, info []byte) ([]byte, *Context, error) {
	// zz, enc = Encap(pkR)
	zz, enc, err := suite.KEM.Encap(rand, pkR)
	if err != nil {
		return nil, nil, err
	}

	keyIR, nonceIR := setupBaseCore(suite, pkR, zz, enc, info)
	ctx, err := newContext(suite, keyIR, nonceIR)
	return enc, ctx, err
}

func SetupRBase(suite CipherSuite, skR KEMPrivateKey, enc, info []byte) (*Context, error) {
	// zz = Decap(enc, skR)
	zz, err := suite.KEM.Decap(enc, skR)
	if err != nil {
		return nil, err
	}

	keyIR, nonceIR := setupBaseCore(suite, skR.PublicKey(), zz, enc, info)
	return newContext(suite, keyIR, nonceIR)
}

//////
// PSK

func setupPSKCore(suite CipherSuite, pkR KEMPublicKey, zz, enc, psk, pskID, info []byte) (keyIR, nonceIR []byte) {
	// kemContext = enc || pkR || pskID
	kemContext := append(enc, pkR.Bytes()...)
	kemContext = append(kemContext, pskID...)

	// secret = Extract(psk, zz)
	secret := suite.KDF.Extract(psk, zz)

	keyIR, nonceIR = setupCore(suite, secret, kemContext, info)
	return
}

func SetupIPSK(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, psk, pskID, info []byte) ([]byte, *Context, error) {
	// zz, enc = Encap(pkR)
	zz, enc, err := suite.KEM.Encap(rand, pkR)
	if err != nil {
		return nil, nil, err
	}

	keyIR, nonceIR := setupPSKCore(suite, pkR, zz, enc, psk, pskID, info)
	ctx, err := newContext(suite, keyIR, nonceIR)
	return enc, ctx, err
}

func SetupRPSK(suite CipherSuite, skR KEMPrivateKey, enc, psk, pskID, info []byte) (*Context, error) {
	// zz = Decap(enc, skR)
	zz, err := suite.KEM.Decap(enc, skR)
	if err != nil {
		return nil, err
	}

	keyIR, nonceIR := setupPSKCore(suite, skR.PublicKey(), zz, enc, psk, pskID, info)
	return newContext(suite, keyIR, nonceIR)
}

///////
// Auth

func setupAuthCore(suite CipherSuite, pkR, pkI KEMPublicKey, zz, enc, info []byte) (keyIR, nonceIR []byte) {
	// kemContext = enc || pkR || pkI
	kemContext := append(enc, pkR.Bytes()...)
	kemContext = append(kemContext, pkI.Bytes()...)

	// secret = Extract(psk, zz)
	zero := bytes.Repeat([]byte{0}, suite.KDF.OutputSize())
	secret := suite.KDF.Extract(zero, zz)

	keyIR, nonceIR = setupCore(suite, secret, kemContext, info)
	return
}

func SetupIAuth(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, skI KEMPrivateKey, info []byte) ([]byte, *Context, error) {
	// zz, enc = AuthEncap(pkR, skI)
	zz, enc, err := suite.KEM.AuthEncap(rand, pkR, skI)
	if err != nil {
		return nil, nil, err
	}

	keyIR, nonceIR := setupAuthCore(suite, pkR, skI.PublicKey(), zz, enc, info)
	ctx, err := newContext(suite, keyIR, nonceIR)
	return enc, ctx, err
}

func SetupRAuth(suite CipherSuite, skR KEMPrivateKey, pkI KEMPublicKey, enc, info []byte) (*Context, error) {
	// zz = AuthDecap(enc, skR, pkI)
	zz, err := suite.KEM.AuthDecap(enc, skR, pkI)
	if err != nil {
		return nil, err
	}

	keyIR, nonceIR := setupAuthCore(suite, skR.PublicKey(), pkI, zz, enc, info)
	return newContext(suite, keyIR, nonceIR)
}

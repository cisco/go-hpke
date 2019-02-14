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
	ID   byte
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
	context := []byte{suite.ID}
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

func sealCore(suite CipherSuite, key, nonce, aad, pt []byte) ([]byte, error) {
	// ct = Seal(keyIR, nonceIR, aad, pt)
	aead, err := suite.AEAD.New(key)
	if err != nil {
		return nil, err
	}

	ct := aead.Seal(nil, nonce, pt, aad)
	return ct, err
}

func openCore(suite CipherSuite, key, nonce, aad, ct []byte) ([]byte, error) {
	// pt := Open(keyIR, nonceIR, aad, ct)
	aead, err := suite.AEAD.New(key)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ct, aad)
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

func setupIBase(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, info []byte) (enc, key, nonce []byte, err error) {
	// zz, enc = Encap(pkR)
	zz, enc, err := suite.KEM.Encap(rand, pkR)
	if err != nil {
		return nil, nil, nil, err
	}

	keyIR, nonceIR := setupBaseCore(suite, pkR, zz, enc, info)
	return enc, keyIR, nonceIR, nil
}

func setupRBase(suite CipherSuite, enc []byte, skR KEMPrivateKey, info []byte) (key, nonce []byte, err error) {
	// zz = Decap(enc, skR)
	zz, err := suite.KEM.Decap(enc, skR)
	if err != nil {
		return nil, nil, err
	}

	key, nonce = setupBaseCore(suite, skR.PublicKey(), zz, enc, info)
	return
}

func Seal(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, info, aad, pt []byte) ([]byte, []byte, error) {
	// enc, keyIR, nonceIR = SetupI(ciphersuite, pkR, info)
	enc, keyIR, nonceIR, err := setupIBase(suite, rand, pkR, info)
	if err != nil {
		return nil, nil, err
	}

	ct, err := sealCore(suite, keyIR, nonceIR, aad, pt)
	return enc, ct, nil
}

func Open(suite CipherSuite, skR KEMPrivateKey, enc, info, aad, ct []byte) ([]byte, error) {
	// keyIR, nonceIR = SetupR(ciphersuite, enc, pkR, info)
	keyIR, nonceIR, err := setupRBase(suite, enc, skR, info)
	if err != nil {
		return nil, err
	}

	return openCore(suite, keyIR, nonceIR, aad, ct)
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

func setupIPSK(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, psk, pskID, info []byte) (enc, keyIR, nonceIR []byte, err error) {
	// zz, enc = Encap(pkR)
	zz, enc, err := suite.KEM.Encap(rand, pkR)
	if err != nil {
		return nil, nil, nil, err
	}

	keyIR, nonceIR = setupPSKCore(suite, pkR, zz, enc, psk, pskID, info)
	return
}

func setupRPSK(suite CipherSuite, enc []byte, skR KEMPrivateKey, psk, pskID, info []byte) (keyIR, nonceIR []byte, err error) {
	// zz = Decap(enc, skR)
	zz, err := suite.KEM.Decap(enc, skR)
	if err != nil {
		return nil, nil, err
	}

	keyIR, nonceIR = setupPSKCore(suite, skR.PublicKey(), zz, enc, psk, pskID, info)
	return
}

func SealPSK(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, psk, pskID, info, aad, pt []byte) ([]byte, []byte, error) {
	// enc, keyIR, nonceIR = SetupI(ciphersuite, pkR, info)
	enc, keyIR, nonceIR, err := setupIPSK(suite, rand, pkR, psk, pskID, info)
	if err != nil {
		return nil, nil, err
	}

	ct, err := sealCore(suite, keyIR, nonceIR, aad, pt)
	return enc, ct, err
}

func OpenPSK(suite CipherSuite, skR KEMPrivateKey, enc, psk, pskID, info, aad, ct []byte) ([]byte, error) {
	// keyIR, nonceIR = SetupR(ciphersuite, enc, pkR, info)
	keyIR, nonceIR, err := setupRPSK(suite, enc, skR, psk, pskID, info)
	if err != nil {
		return nil, err
	}

	return openCore(suite, keyIR, nonceIR, aad, ct)
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

func setupIAuth(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, skI KEMPrivateKey, info []byte) (enc, keyIR, nonceIR []byte, err error) {
	// zz, enc = AuthEncap(pkR, skI)
	zz, enc, err := suite.KEM.AuthEncap(rand, pkR, skI)
	if err != nil {
		return nil, nil, nil, err
	}

	keyIR, nonceIR = setupAuthCore(suite, pkR, skI.PublicKey(), zz, enc, info)
	return
}

func setupRAuth(suite CipherSuite, enc []byte, skR KEMPrivateKey, pkI KEMPublicKey, info []byte) (keyIR, nonceIR []byte, err error) {
	// zz = AuthDecap(enc, skR, pkI)
	zz, err := suite.KEM.AuthDecap(enc, skR, pkI)
	if err != nil {
		return nil, nil, err
	}

	keyIR, nonceIR = setupAuthCore(suite, skR.PublicKey(), pkI, zz, enc, info)
	return
}

func SealAuth(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, skI KEMPrivateKey, info, aad, pt []byte) ([]byte, []byte, error) {
	// enc, keyIR, nonceIR = SetupI(ciphersuite, pkR, info)
	enc, keyIR, nonceIR, err := setupIAuth(suite, rand, pkR, skI, info)
	if err != nil {
		return nil, nil, err
	}

	ct, err := sealCore(suite, keyIR, nonceIR, aad, pt)
	return enc, ct, err
}

func OpenAuth(suite CipherSuite, skR KEMPrivateKey, pkI KEMPublicKey, enc, info, aad, ct []byte) ([]byte, error) {
	// keyIR, nonceIR = SetupR(ciphersuite, enc, pkR, info)
	keyIR, nonceIR, err := setupRAuth(suite, enc, skR, pkI, info)
	if err != nil {
		return nil, err
	}

	return openCore(suite, keyIR, nonceIR, aad, ct)
}

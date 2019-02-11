package hpke

import (
	"bytes"
	"crypto/cipher"
	"io"
	"log"
)

const (
	debug = false
)

type KEMPrivateKey interface {
	PublicKey() KEMPublicKey
}

type KEMPublicKey interface {
	Bytes() []byte
}

type KEMScheme interface {
	Generate(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error)
	Encap(rand io.Reader, pub KEMPublicKey) ([]byte, []byte, error)
	Decap(enc []byte, priv KEMPrivateKey) ([]byte, error)
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

func setupCore(suite CipherSuite, zz []byte, enc []byte, pkR KEMPublicKey, info []byte) (keyIR, nonceIR []byte) {
	// secret = Extract(0, zz)
	zero := bytes.Repeat([]byte{0}, suite.KDF.OutputSize())
	secret := suite.KDF.Extract(zero, zz)

	logVal("secret", secret)

	// context = ciphersuite || Marshal(pkE) || Marshal(pkR) || info
	context := []byte{suite.ID}
	context = append(context, enc...)
	context = append(context, pkR.Bytes()...)
	context = append(context, info...)

	logVal("context", context)

	// keyIR = Expand(secret, "hpke key" || context, Nk)
	keyContext := append([]byte("hpke key"), context...)
	keyIR = suite.KDF.Expand(secret, keyContext, suite.AEAD.KeySize())

	// nonceIR = Expand(secret, "hpke nonce" || context, Nn)
	nonceContext := append([]byte("hpke nonce"), context...)
	nonceIR = suite.KDF.Expand(secret, nonceContext, suite.AEAD.NonceSize())
	return
}

func setupI(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, info []byte) (enc, key, nonce []byte, err error) {
	// zz, enc = Encap(pkR)
	zz, enc, err := suite.KEM.Encap(rand, pkR)
	if err != nil {
		return nil, nil, nil, err
	}

	keyIR, nonceIR := setupCore(suite, zz, enc, pkR, info)
	return enc, keyIR, nonceIR, nil
}

func setupR(suite CipherSuite, enc []byte, skR KEMPrivateKey, info []byte) (key, nonce []byte, err error) {
	// zz = Decap(enc, skR)
	zz, err := suite.KEM.Decap(enc, skR)
	if err != nil {
		return nil, nil, err
	}

	key, nonce = setupCore(suite, zz, enc, skR.PublicKey(), info)
	return
}

func Seal(suite CipherSuite, rand io.Reader, pubR KEMPublicKey, info, aad, pt []byte) ([]byte, []byte, error) {
	logString("=== Seal ===")

	// enc, keyIR, nonceIR = SetupI(ciphersuite, pkR, info)
	enc, keyIR, nonceIR, err := setupI(suite, rand, pubR, info)
	if err != nil {
		return nil, nil, err
	}

	logVal("enc", enc)
	logVal("keyIR", keyIR)
	logVal("nonceIR", keyIR)

	// ct = Seal(keyIR, nonceIR, aad, pt)
	aead, err := suite.AEAD.New(keyIR)
	if err != nil {
		return nil, nil, err
	}

	ct := aead.Seal(nil, nonceIR, pt, aad)
	return enc, ct, nil
}

func Open(suite CipherSuite, privR KEMPrivateKey, enc, info, aad, ct []byte) ([]byte, error) {
	logString("=== Open ===")

	// keyIR, nonceIR = SetupR(ciphersuite, enc, pkR, info)
	keyIR, nonceIR, err := setupR(suite, enc, privR, info)
	if err != nil {
		return nil, err
	}

	logVal("enc", enc)
	logVal("keyIR", keyIR)
	logVal("nonceIR", keyIR)

	// 2. ct := Open(keyIR, nonceIR, aad, ct)
	aead, err := suite.AEAD.New(keyIR)
	if err != nil {
		return nil, err
	}

	pt, err := aead.Open(nil, nonceIR, ct, aad)

	return pt, err
}

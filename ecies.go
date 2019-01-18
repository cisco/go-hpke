package ecies

import (
	"bytes"
	"crypto/cipher"
	"io"
	"log"
)

const (
	debug = false
)

type DHPrivateKey interface {
	PublicKey() DHPublicKey
}

type DHPublicKey interface {
	Bytes() []byte
}

type DHScheme interface {
	Generate(rand io.Reader) (DHPrivateKey, DHPublicKey, error)
	Derive(priv DHPrivateKey, pub DHPublicKey) ([]byte, error)
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

type Ciphersuite struct {
	ID   byte
	DH   DHScheme
	AEAD AEADScheme
	KDF  KDFScheme
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

func setup(initiator bool, suite Ciphersuite, priv DHPrivateKey, pub DHPublicKey, info []byte) (key, nonce []byte, err error) {
	// zz = DH(skE, pkR)
	zz, err := suite.DH.Derive(priv, pub)
	if err != nil {
		return nil, nil, err
	}

	// secret = Extract(0, zz)
	zero := bytes.Repeat([]byte{0}, suite.KDF.OutputSize())
	secret := suite.KDF.Extract(zero, zz)

	// context = ciphersuite || Marshal(pkE) || Marshal(pkR) || info
	context := []byte{suite.ID}
	if initiator {
		context = append(context, priv.PublicKey().Bytes()...)
		context = append(context, pub.Bytes()...)
	} else {
		context = append(context, pub.Bytes()...)
		context = append(context, priv.PublicKey().Bytes()...)
	}
	context = append(context, info...)

	// keyIR = Expand(secret, "ecies key" || context, Nk)
	keyContext := append([]byte("ecies key"), context...)
	keyIR := suite.KDF.Expand(secret, keyContext, suite.AEAD.KeySize())

	// nonceIR = Expand(secret, "ecies nonce" || context, Nk)
	nonceContext := append([]byte("ecies nonce"), context...)
	nonceIR := suite.KDF.Expand(secret, nonceContext, suite.AEAD.NonceSize())

	return keyIR, nonceIR, nil
}

func Seal(suite Ciphersuite, rand io.Reader, pubR DHPublicKey, pt, info, aad []byte) (DHPublicKey, []byte, error) {
	logString("=== ECIES Seal ===")

	// (skE, pkE) = GenerateKeyPair()
	privE, pubE, err := suite.DH.Generate(rand)
	if err != nil {
		return nil, nil, err
	}

	logVal("pubR", pubR.Bytes())
	logVal("pubE", pubE.Bytes())

	// ... (remainder of SetupI)
	keyIR, nonceIR, err := setup(true, suite, privE, pubR, info)
	if err != nil {
		return nil, nil, err
	}
	logVal("key", keyIR)
	logVal("nonce", nonceIR)
	logVal("aad", aad)

	// 3. ct := Seal(keyIR, nonceIR, aad, pt)
	aead, err := suite.AEAD.New(keyIR)
	if err != nil {
		return nil, nil, err
	}

	ct := aead.Seal(nil, nonceIR, pt, aad)

	logVal("pt", pt)
	logVal("ct", ct)

	return pubE, ct, nil
}

func Open(suite Ciphersuite, privR DHPrivateKey, pubE DHPublicKey, ct, info, aad []byte) ([]byte, error) {
	logString("=== ECIES Open ===")

	logVal("pubR", privR.PublicKey().Bytes())
	logVal("pubE", pubE.Bytes())

	// ... (SetupR)
	keyIR, nonceIR, err := setup(false, suite, privR, pubE, info)
	if err != nil {
		return nil, err
	}

	logVal("key", keyIR)
	logVal("nonce", nonceIR)
	logVal("aad", aad)

	// 2. ct := Open(keyIR, nonceIR, aad, ct)
	aead, err := suite.AEAD.New(keyIR)
	if err != nil {
		return nil, err
	}

	pt, err := aead.Open(nil, nonceIR, ct, aad)

	logVal("ct", ct)
	logVal("pt", pt)

	return pt, err
}

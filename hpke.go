package hpke

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/bifurcation/mint/syntax"
)

const (
	debug = true
)

type KEMPrivateKey interface {
	PublicKey() KEMPublicKey
}

type KEMPublicKey interface{}

type KEMScheme interface {
	ID() KEMID
	GenerateKeyPair(rand io.Reader) (KEMPrivateKey, KEMPublicKey, error)
	Marshal(pk KEMPublicKey) []byte
	Unmarshal(enc []byte) (KEMPublicKey, error)
	Encap(rand io.Reader, pkR KEMPublicKey) ([]byte, []byte, error)
	Decap(enc []byte, skR KEMPrivateKey) ([]byte, error)
	PublicKeySize() int
}

type AuthKEMScheme interface {
	KEMScheme
	AuthEncap(rand io.Reader, pkR KEMPublicKey, skI KEMPrivateKey) ([]byte, []byte, error)
	AuthDecap(enc []byte, skR KEMPrivateKey, pkI KEMPublicKey) ([]byte, error)
}

type KDFScheme interface {
	ID() KDFID
	Hash(message []byte) []byte
	Extract(salt, ikm []byte) []byte
	Expand(prk, info []byte, L int) []byte
	OutputSize() int
}

type AEADScheme interface {
	ID() AEADID
	New(key []byte) (cipher.AEAD, error)
	KeySize() int
	NonceSize() int
}

type CipherSuite struct {
	KEM  KEMScheme
	KDF  KDFScheme
	AEAD AEADScheme
}

type HPKEMode uint8

const (
	modeBase    HPKEMode = 0x00
	modePSK     HPKEMode = 0x01
	modeAuth    HPKEMode = 0x02
	modePSKAuth HPKEMode = 0x03
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

func defaultPKIm(suite CipherSuite) []byte {
	return bytes.Repeat([]byte{0x00}, suite.KEM.PublicKeySize())
}

func defaultPSK(suite CipherSuite) []byte {
	return bytes.Repeat([]byte{0x00}, suite.KDF.OutputSize())
}

func defaultPSKID(suite CipherSuite) []byte {
	return []byte{}
}

func verifyMode(suite CipherSuite, mode HPKEMode, psk, pskID, pkIm []byte) error {
	defaultPKIm := defaultPKIm(suite)
	defaultPSK := defaultPSK(suite)
	defaultPSKID := defaultPSKID(suite)

	gotPKIm := !bytes.Equal(pkIm, defaultPKIm)
	noPKIm := bytes.Equal(pkIm, defaultPKIm)
	gotPSK := !bytes.Equal(psk, defaultPSK) && !bytes.Equal(pskID, defaultPSKID)
	noPSK := bytes.Equal(psk, defaultPSK) && bytes.Equal(pskID, defaultPSKID)

	ok := false
	switch mode {
	case modeBase:
		ok = noPKIm && noPSK
	case modePSK:
		ok = noPKIm && gotPSK
	case modeAuth:
		ok = gotPKIm && noPSK
	case modePSKAuth:
		ok = gotPKIm && gotPSK
	}

	if !ok {
		return fmt.Errorf("Invalid configuration [%d] [%v] [%v]", mode, gotPKIm, gotPSK)
	}

	return nil
}

type hpkeContext struct {
	mode      HPKEMode
	kemID     KEMID
	kdfID     KDFID
	aeadID    AEADID
	enc       []byte `tls:"head=none"`
	pkRm      []byte `tls:"head=none"`
	pkIm      []byte `tls:"head=none"`
	pskIDHash []byte `tls:"head=none"`
	infoHash  []byte `tls:"head=none"`
}

func keySchedule(suite CipherSuite, mode HPKEMode, pkR KEMPublicKey, zz, enc, info, psk, pskID, pkIm []byte) (key, nonce []byte, err error) {
	err = verifyMode(suite, mode, psk, pskID, pkIm)
	if err != nil {
		return
	}

	pkRm := suite.KEM.Marshal(pkR)
	pskIDHash := suite.KDF.Hash(pskID)
	infoHash := suite.KDF.Hash(info)

	contextStruct := hpkeContext{mode, suite.KEM.ID(), suite.KDF.ID(), suite.AEAD.ID(), enc, pkRm, pkIm, pskIDHash, infoHash}
	context, err := syntax.Marshal(contextStruct)
	if err != nil {
		return
	}

	// secret = Extract(psk, zz)
	secret := suite.KDF.Extract(psk, zz)

	// key = Expand(secret, concat("hpke key", context), Nk)
	keyContext := append([]byte("hpke key"), context...)
	key = suite.KDF.Expand(secret, keyContext, suite.AEAD.KeySize())

	// nonce = Expand(secret, concat("hpke nonce", context), Nn)
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

func SetupBaseI(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, info []byte) ([]byte, *EncryptContext, error) {
	// zz, enc = Encap(pkR)
	zz, enc, err := suite.KEM.Encap(rand, pkR)
	if err != nil {
		return nil, nil, err
	}

	// return enc, KeySchedule(mode_base, pkR, zz, enc, info,
	//                        default_psk, default_pskID, default_pkIm)
	key, nonce, err := keySchedule(suite, modeBase, pkR, zz, enc, info, defaultPSK(suite), defaultPSKID(suite), defaultPKIm(suite))
	if err != nil {
		return nil, nil, err
	}

	ctx, err := newEncContext(suite, key, nonce)
	return enc, ctx, err
}

func SetupBaseR(suite CipherSuite, skR KEMPrivateKey, enc, info []byte) (*DecryptContext, error) {
	// zz = Decap(enc, skR)
	zz, err := suite.KEM.Decap(enc, skR)
	if err != nil {
		return nil, err
	}

	pkR := skR.PublicKey()
	key, nonce, err := keySchedule(suite, modeBase, pkR, zz, enc, info, defaultPSK(suite), defaultPSKID(suite), defaultPKIm(suite))
	if err != nil {
		return nil, err
	}

	return newDecContext(suite, key, nonce)
}

//////
// PSK

func SetupPSKI(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, psk, pskID, info []byte) ([]byte, *EncryptContext, error) {
	// zz, enc = Encap(pkR)
	zz, enc, err := suite.KEM.Encap(rand, pkR)
	if err != nil {
		return nil, nil, err
	}

	key, nonce, err := keySchedule(suite, modePSK, pkR, zz, enc, info, psk, pskID, defaultPKIm(suite))
	if err != nil {
		return nil, nil, err
	}

	ctx, err := newEncContext(suite, key, nonce)
	return enc, ctx, err
}

func SetupPSKR(suite CipherSuite, skR KEMPrivateKey, enc, psk, pskID, info []byte) (*DecryptContext, error) {
	// zz = Decap(enc, skR)
	zz, err := suite.KEM.Decap(enc, skR)
	if err != nil {
		return nil, err
	}

	pkR := skR.PublicKey()
	key, nonce, err := keySchedule(suite, modePSK, pkR, zz, enc, info, psk, pskID, defaultPKIm(suite))
	if err != nil {
		return nil, err
	}

	return newDecContext(suite, key, nonce)
}

///////
// Auth

func SetupAuthI(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, skI KEMPrivateKey, info []byte) ([]byte, *EncryptContext, error) {
	// zz, enc = AuthEncap(pkR, skI)
	auth := suite.KEM.(AuthKEMScheme)
	zz, enc, err := auth.AuthEncap(rand, pkR, skI)
	if err != nil {
		return nil, nil, err
	}

	pkIm := suite.KEM.Marshal(skI.PublicKey())
	key, nonce, err := keySchedule(suite, modeAuth, pkR, zz, enc, info, defaultPSK(suite), defaultPSKID(suite), pkIm)
	if err != nil {
		return nil, nil, err
	}

	ctx, err := newEncContext(suite, key, nonce)
	return enc, ctx, err
}

func SetupAuthR(suite CipherSuite, skR KEMPrivateKey, pkI KEMPublicKey, enc, info []byte) (*DecryptContext, error) {
	// zz = AuthDecap(enc, skR, pkI)
	auth := suite.KEM.(AuthKEMScheme)
	zz, err := auth.AuthDecap(enc, skR, pkI)
	if err != nil {
		return nil, err
	}

	pkIm := suite.KEM.Marshal(pkI)
	pkR := skR.PublicKey()
	key, nonce, err := keySchedule(suite, modeAuth, pkR, zz, enc, info, defaultPSK(suite), defaultPSKID(suite), pkIm)
	if err != nil {
		return nil, err
	}

	return newDecContext(suite, key, nonce)
}

/////////////
// PSK + Auth

func SetupPSKAuthI(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, skI KEMPrivateKey, psk, pskID, info []byte) ([]byte, *EncryptContext, error) {
	// zz, enc = AuthEncap(pkR, skI)
	auth := suite.KEM.(AuthKEMScheme)
	zz, enc, err := auth.AuthEncap(rand, pkR, skI)
	if err != nil {
		return nil, nil, err
	}

	pkIm := suite.KEM.Marshal(skI.PublicKey())
	key, nonce, err := keySchedule(suite, modePSKAuth, pkR, zz, enc, info, psk, pskID, pkIm)
	if err != nil {
		return nil, nil, err
	}

	ctx, err := newEncContext(suite, key, nonce)
	return enc, ctx, err
}

func SetupPSKAuthR(suite CipherSuite, skR KEMPrivateKey, pkI KEMPublicKey, enc, psk, pskID, info []byte) (*DecryptContext, error) {
	// zz = AuthDecap(enc, skR, pkI)
	auth := suite.KEM.(AuthKEMScheme)
	zz, err := auth.AuthDecap(enc, skR, pkI)
	if err != nil {
		return nil, err
	}

	pkIm := suite.KEM.Marshal(pkI)
	pkR := skR.PublicKey()
	key, nonce, err := keySchedule(suite, modePSKAuth, pkR, zz, enc, info, psk, pskID, pkIm)
	if err != nil {
		return nil, err
	}

	return newDecContext(suite, key, nonce)
}

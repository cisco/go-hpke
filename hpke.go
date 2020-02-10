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

	MarshalPrivate(sk KEMPrivateKey) []byte
	UnmarshalPrivate(enc []byte) (KEMPrivateKey, error)

	setEphemeralKeyPair(sk KEMPrivateKey)
}

type AuthKEMScheme interface {
	KEMScheme
	AuthEncap(rand io.Reader, pkR KEMPublicKey, skS KEMPrivateKey) ([]byte, []byte, error)
	AuthDecap(enc []byte, skR KEMPrivateKey, pkS KEMPublicKey) ([]byte, error)
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

func verifyMode(suite CipherSuite, mode HPKEMode, psk, pskID, pkSm []byte) error {
	defaultPKIm := defaultPKIm(suite)
	defaultPSK := defaultPSK(suite)
	defaultPSKID := defaultPSKID(suite)

	gotPKIm := !bytes.Equal(pkSm, defaultPKIm)
	noPKIm := bytes.Equal(pkSm, defaultPKIm)
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
	pkSm      []byte `tls:"head=none"`
	pskIDHash []byte `tls:"head=none"`
	infoHash  []byte `tls:"head=none"`
}

type contextParameters struct {
	suite   CipherSuite
	context []byte
	secret  []byte
}

func (cp contextParameters) aeadKey() []byte {
	context := append([]byte("hpke key"), cp.context...)
	return cp.suite.KDF.Expand(cp.secret, context, cp.suite.AEAD.KeySize())
}

func (cp contextParameters) exporterSecret() []byte {
	context := append([]byte("hpke exp"), cp.context...)
	return cp.suite.KDF.Expand(cp.secret, context, cp.suite.KDF.OutputSize())
}

func (cp contextParameters) aeadNonce() []byte {
	context := append([]byte("hpke nonce"), cp.context...)
	return cp.suite.KDF.Expand(cp.secret, context, cp.suite.AEAD.NonceSize())
}

type setupParameters struct {
	zz  []byte
	enc []byte
}

func keySchedule(suite CipherSuite, mode HPKEMode, pkR KEMPublicKey, zz, enc, info, psk, pskID, pkSm []byte) (contextParameters, error) {
	err := verifyMode(suite, mode, psk, pskID, pkSm)
	if err != nil {
		return contextParameters{}, err
	}

	pkRm := suite.KEM.Marshal(pkR)
	pskIDHash := suite.KDF.Hash(pskID)
	infoHash := suite.KDF.Hash(info)

	contextStruct := hpkeContext{mode, suite.KEM.ID(), suite.KDF.ID(), suite.AEAD.ID(), enc, pkRm, pkSm, pskIDHash, infoHash}
	context, err := syntax.Marshal(contextStruct)
	if err != nil {
		return contextParameters{}, err
	}

	// secret = Extract(psk, zz)
	secret := suite.KDF.Extract(psk, zz)

	params := contextParameters{
		suite:   suite,
		context: context,
		secret:  secret,
	}

	return params, nil
}

type cipherContext struct {
	key            []byte
	nonce          []byte
	exporterSecret []byte
	aead           cipher.AEAD
	seq            uint64
	kdf            KDFScheme

	// Historical record
	nonces        [][]byte
	setupParams   setupParameters
	contextParams contextParameters
}

func newCipherContext(suite CipherSuite, setupParams setupParameters, contextParams contextParameters) (cipherContext, error) {
	key := contextParams.aeadKey()
	nonce := contextParams.aeadNonce()
	exporterSecrert := contextParams.exporterSecret()

	aead, err := suite.AEAD.New(key)
	if err != nil {
		return cipherContext{}, err
	}

	return cipherContext{key, nonce, exporterSecrert, aead, 0, suite.KDF, nil, setupParams, contextParams}, nil
}

func (ctx *cipherContext) currNonce() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, ctx.seq)

	Nn := len(ctx.nonce)
	nonce := make([]byte, Nn)
	copy(nonce, ctx.nonce)
	for i := range buf {
		nonce[Nn-8+i] ^= buf[i]
	}

	ctx.nonces = append(ctx.nonces, nonce)
	return nonce
}

func (ctx *cipherContext) incrementSeq() {
	ctx.seq += 1
	if ctx.seq == 0 {
		panic("sequence number wrapped")
	}
}

func (ctx *cipherContext) Export(context []byte, L int) []byte {
	return ctx.kdf.Expand(ctx.exporterSecret, context, L)
}

type EncryptContext struct {
	cipherContext
}

func newEncryptContext(suite CipherSuite, setupParams setupParameters, contextParams contextParameters) (*EncryptContext, error) {
	ctx, err := newCipherContext(suite, setupParams, contextParams)
	if err != nil {
		return nil, err
	}

	return &EncryptContext{ctx}, nil
}

func (ctx *EncryptContext) Seal(aad, pt []byte) []byte {
	ct := ctx.aead.Seal(nil, ctx.currNonce(), pt, aad)
	ctx.incrementSeq()
	return ct
}

type DecryptContext struct {
	cipherContext
}

func newDecryptContext(suite CipherSuite, setupParams setupParameters, contextParams contextParameters) (*DecryptContext, error) {
	ctx, err := newCipherContext(suite, setupParams, contextParams)
	if err != nil {
		return nil, err
	}

	return &DecryptContext{ctx}, nil
}

func (ctx *DecryptContext) Open(aad, ct []byte) ([]byte, error) {
	pt, err := ctx.aead.Open(nil, ctx.currNonce(), ct, aad)
	if err != nil {
		return nil, err
	}

	ctx.incrementSeq()
	return pt, nil
}

func (ctx *DecryptContext) Export(context []byte, L int) []byte {
	return ctx.kdf.Expand(ctx.exporterSecret, context, L)
}

///////
// Base

func SetupBaseS(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, info []byte) ([]byte, *EncryptContext, error) {
	// zz, enc = Encap(pkR)
	zz, enc, err := suite.KEM.Encap(rand, pkR)
	if err != nil {
		return nil, nil, err
	}

	setupParams := setupParameters{
		zz:  zz,
		enc: enc,
	}

	// return enc, KeySchedule(mode_base, pkR, zz, enc, info,
	//                        default_psk, default_pskID, default_pkSm)
	params, err := keySchedule(suite, modeBase, pkR, zz, enc, info, defaultPSK(suite), defaultPSKID(suite), defaultPKIm(suite))
	if err != nil {
		return nil, nil, err
	}

	ctx, err := newEncryptContext(suite, setupParams, params)
	return enc, ctx, err
}

func SetupBaseR(suite CipherSuite, skR KEMPrivateKey, enc, info []byte) (*DecryptContext, error) {
	// zz = Decap(enc, skR)
	zz, err := suite.KEM.Decap(enc, skR)
	if err != nil {
		return nil, err
	}

	setupParams := setupParameters{
		zz:  zz,
		enc: enc,
	}

	pkR := skR.PublicKey()
	params, err := keySchedule(suite, modeBase, pkR, zz, enc, info, defaultPSK(suite), defaultPSKID(suite), defaultPKIm(suite))
	if err != nil {
		return nil, err
	}

	return newDecryptContext(suite, setupParams, params)
}

//////
// PSK

func SetupPSKS(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, psk, pskID, info []byte) ([]byte, *EncryptContext, error) {
	// zz, enc = Encap(pkR)
	zz, enc, err := suite.KEM.Encap(rand, pkR)
	if err != nil {
		return nil, nil, err
	}

	setupParams := setupParameters{
		zz:  zz,
		enc: enc,
	}

	params, err := keySchedule(suite, modePSK, pkR, zz, enc, info, psk, pskID, defaultPKIm(suite))
	if err != nil {
		return nil, nil, err
	}

	ctx, err := newEncryptContext(suite, setupParams, params)
	return enc, ctx, err
}

func SetupPSKR(suite CipherSuite, skR KEMPrivateKey, enc, psk, pskID, info []byte) (*DecryptContext, error) {
	// zz = Decap(enc, skR)
	zz, err := suite.KEM.Decap(enc, skR)
	if err != nil {
		return nil, err
	}

	setupParams := setupParameters{
		zz:  zz,
		enc: enc,
	}

	pkR := skR.PublicKey()
	params, err := keySchedule(suite, modePSK, pkR, zz, enc, info, psk, pskID, defaultPKIm(suite))
	if err != nil {
		return nil, err
	}

	return newDecryptContext(suite, setupParams, params)
}

///////
// Auth

func SetupAuthS(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, skS KEMPrivateKey, info []byte) ([]byte, *EncryptContext, error) {
	// zz, enc = AuthEncap(pkR, skS)
	auth := suite.KEM.(AuthKEMScheme)
	zz, enc, err := auth.AuthEncap(rand, pkR, skS)
	if err != nil {
		return nil, nil, err
	}

	setupParams := setupParameters{
		zz:  zz,
		enc: enc,
	}

	pkSm := suite.KEM.Marshal(skS.PublicKey())
	params, err := keySchedule(suite, modeAuth, pkR, zz, enc, info, defaultPSK(suite), defaultPSKID(suite), pkSm)
	if err != nil {
		return nil, nil, err
	}

	ctx, err := newEncryptContext(suite, setupParams, params)
	return enc, ctx, err
}

func SetupAuthR(suite CipherSuite, skR KEMPrivateKey, pkS KEMPublicKey, enc, info []byte) (*DecryptContext, error) {
	// zz = AuthDecap(enc, skR, pkS)
	auth := suite.KEM.(AuthKEMScheme)
	zz, err := auth.AuthDecap(enc, skR, pkS)
	if err != nil {
		return nil, err
	}

	setupParams := setupParameters{
		zz:  zz,
		enc: enc,
	}

	pkSm := suite.KEM.Marshal(pkS)
	pkR := skR.PublicKey()
	params, err := keySchedule(suite, modeAuth, pkR, zz, enc, info, defaultPSK(suite), defaultPSKID(suite), pkSm)
	if err != nil {
		return nil, err
	}

	return newDecryptContext(suite, setupParams, params)
}

/////////////
// PSK + Auth

func SetupPSKAuthS(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, skS KEMPrivateKey, psk, pskID, info []byte) ([]byte, *EncryptContext, error) {
	// zz, enc = AuthEncap(pkR, skS)
	auth := suite.KEM.(AuthKEMScheme)
	zz, enc, err := auth.AuthEncap(rand, pkR, skS)
	if err != nil {
		return nil, nil, err
	}

	setupParams := setupParameters{
		zz:  zz,
		enc: enc,
	}

	pkSm := suite.KEM.Marshal(skS.PublicKey())
	params, err := keySchedule(suite, modePSKAuth, pkR, zz, enc, info, psk, pskID, pkSm)
	if err != nil {
		return nil, nil, err
	}

	ctx, err := newEncryptContext(suite, setupParams, params)
	return enc, ctx, err
}

func SetupPSKAuthR(suite CipherSuite, skR KEMPrivateKey, pkS KEMPublicKey, enc, psk, pskID, info []byte) (*DecryptContext, error) {
	// zz = AuthDecap(enc, skR, pkS)
	auth := suite.KEM.(AuthKEMScheme)
	zz, err := auth.AuthDecap(enc, skR, pkS)
	if err != nil {
		return nil, err
	}

	setupParams := setupParameters{
		zz:  zz,
		enc: enc,
	}

	pkSm := suite.KEM.Marshal(pkS)
	pkR := skR.PublicKey()
	params, err := keySchedule(suite, modePSKAuth, pkR, zz, enc, info, psk, pskID, pkSm)
	if err != nil {
		return nil, err
	}

	return newDecryptContext(suite, setupParams, params)
}

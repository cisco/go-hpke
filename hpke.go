package hpke

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/cisco/go-tls-syntax"
)

const (
	debug    = true
	rfcLabel = "RFCXXXX"
)

type KEMPrivateKey interface {
	PublicKey() KEMPublicKey
}

type KEMPublicKey interface{}

type KEMScheme interface {
	ID() KEMID
	DeriveKeyPair(ikm []byte) (KEMPrivateKey, KEMPublicKey, error)
	Serialize(pk KEMPublicKey) []byte
	Deserialize(enc []byte) (KEMPublicKey, error)
	Encap(rand io.Reader, pkR KEMPublicKey) ([]byte, []byte, error)
	Decap(enc []byte, skR KEMPrivateKey) ([]byte, error)
	PublicKeySize() int
	PrivateKeySize() int

	SerializePrivate(sk KEMPrivateKey) []byte
	DeserializePrivate(enc []byte) (KEMPrivateKey, error)

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
	LabeledExtract(salt []byte, suiteID []byte, label string, ikm []byte) []byte
	LabeledExpand(prk []byte, suiteID []byte, label string, info []byte, L int) []byte
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

func (suite CipherSuite) ID() []byte {
	suiteID := make([]byte, 6)
	binary.BigEndian.PutUint16(suiteID, uint16(suite.KEM.ID()))
	binary.BigEndian.PutUint16(suiteID[2:], uint16(suite.KDF.ID()))
	binary.BigEndian.PutUint16(suiteID[4:], uint16(suite.AEAD.ID()))
	return append([]byte("HPKE"), suiteID...)
}

type Mode uint8

const (
	modeBase    Mode = 0x00
	modePSK     Mode = 0x01
	modeAuth    Mode = 0x02
	modeAuthPSK Mode = 0x03
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

func defaultPSK(suite CipherSuite) []byte {
	return []byte{}
}

func defaultPSKID(suite CipherSuite) []byte {
	return []byte{}
}

func verifyPSKInputs(suite CipherSuite, mode Mode, psk, pskID []byte) error {
	defaultPSK := defaultPSK(suite)
	defaultPSKID := defaultPSKID(suite)
	pskMode := map[Mode]bool{modePSK: true, modeAuthPSK: true}

	gotPSK := !bytes.Equal(psk, defaultPSK)
	gotPSKID := !bytes.Equal(pskID, defaultPSKID)

	switch {
	case gotPSK != gotPSKID:
		return fmt.Errorf("Inconsistent PSK inputs [%d] [%v] [%v]", mode, gotPSK, gotPSKID)
	case gotPSK && !pskMode[mode]:
		return fmt.Errorf("PSK input provided when not needed [%d]", mode)
	case !gotPSK && pskMode[mode]:
		return fmt.Errorf("Missing required PSK input [%d]", mode)
	}

	return nil
}

type hpkeContext struct {
	mode      Mode
	pskIDHash []byte `tls:"head=none"`
	infoHash  []byte `tls:"head=none"`
}

type contextParameters struct {
	suite              CipherSuite
	keyScheduleContext []byte
	secret             []byte
}

func (cp contextParameters) aeadKey() []byte {
	return cp.suite.KDF.LabeledExpand(cp.secret, cp.suite.ID(), "key", cp.keyScheduleContext, cp.suite.AEAD.KeySize())
}

func (cp contextParameters) exporterSecret() []byte {
	return cp.suite.KDF.LabeledExpand(cp.secret, cp.suite.ID(), "exp", cp.keyScheduleContext, cp.suite.KDF.OutputSize())
}

func (cp contextParameters) aeadNonce() []byte {
	return cp.suite.KDF.LabeledExpand(cp.secret, cp.suite.ID(), "nonce", cp.keyScheduleContext, cp.suite.AEAD.NonceSize())
}

type setupParameters struct {
	zz  []byte
	enc []byte
}

func keySchedule(suite CipherSuite, mode Mode, zz, info, psk, pskID []byte) (contextParameters, error) {
	err := verifyPSKInputs(suite, mode, psk, pskID)
	if err != nil {
		return contextParameters{}, err
	}

	suiteID := suite.ID()
	pskIDHash := suite.KDF.LabeledExtract(nil, suiteID, "pskID_hash", pskID)
	infoHash := suite.KDF.LabeledExtract(nil, suiteID, "info_hash", info)

	contextStruct := hpkeContext{mode, pskIDHash, infoHash}
	keyScheduleContext, err := syntax.Marshal(contextStruct)
	if err != nil {
		return contextParameters{}, err
	}

	pskHash := suite.KDF.LabeledExtract(nil, suiteID, "psk_hash", psk)
	secret := suite.KDF.LabeledExtract(pskHash, suiteID, "secret", zz)

	params := contextParameters{
		suite:              suite,
		keyScheduleContext: keyScheduleContext,
		secret:             secret,
	}

	return params, nil
}

type cipherContext struct {
	key            []byte
	nonce          []byte
	exporterSecret []byte
	aead           cipher.AEAD
	seq            uint64
	suite          CipherSuite

	// Historical record
	nonces        [][]byte
	setupParams   setupParameters
	contextParams contextParameters
}

func newCipherContext(suite CipherSuite, setupParams setupParameters, contextParams contextParameters) (cipherContext, error) {
	key := contextParams.aeadKey()
	nonce := contextParams.aeadNonce()
	exporterSecret := contextParams.exporterSecret()

	aead, err := suite.AEAD.New(key)
	if err != nil {
		return cipherContext{}, err
	}

	return cipherContext{key, nonce, exporterSecret, aead, 0, suite, nil, setupParams, contextParams}, nil
}

func (ctx *cipherContext) computeNonce() []byte {
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
	return ctx.suite.KDF.LabeledExpand(ctx.exporterSecret, ctx.suite.ID(), "sec", context, L)
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
	ct := ctx.aead.Seal(nil, ctx.computeNonce(), pt, aad)
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
	pt, err := ctx.aead.Open(nil, ctx.computeNonce(), ct, aad)
	if err != nil {
		return nil, err
	}

	ctx.incrementSeq()
	return pt, nil
}

func (ctx *DecryptContext) Export(context []byte, L int) []byte {
	return ctx.suite.KDF.LabeledExpand(ctx.exporterSecret, ctx.suite.ID(), "sec", context, L)
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

	params, err := keySchedule(suite, modeBase, zz, info, defaultPSK(suite), defaultPSKID(suite))
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

	params, err := keySchedule(suite, modeBase, zz, info, defaultPSK(suite), defaultPSKID(suite))
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

	params, err := keySchedule(suite, modePSK, zz, info, psk, pskID)
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

	params, err := keySchedule(suite, modePSK, zz, info, psk, pskID)
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

	params, err := keySchedule(suite, modeAuth, zz, info, defaultPSK(suite), defaultPSKID(suite))
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

	params, err := keySchedule(suite, modeAuth, zz, info, defaultPSK(suite), defaultPSKID(suite))
	if err != nil {
		return nil, err
	}

	return newDecryptContext(suite, setupParams, params)
}

/////////////
// PSK + Auth

func SetupAuthPSKS(suite CipherSuite, rand io.Reader, pkR KEMPublicKey, skS KEMPrivateKey, psk, pskID, info []byte) ([]byte, *EncryptContext, error) {
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

	params, err := keySchedule(suite, modeAuthPSK, zz, info, psk, pskID)
	if err != nil {
		return nil, nil, err
	}

	ctx, err := newEncryptContext(suite, setupParams, params)
	return enc, ctx, err
}

func SetupAuthPSKR(suite CipherSuite, skR KEMPrivateKey, pkS KEMPublicKey, enc, psk, pskID, info []byte) (*DecryptContext, error) {
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

	params, err := keySchedule(suite, modeAuthPSK, zz, info, psk, pskID)
	if err != nil {
		return nil, err
	}

	return newDecryptContext(suite, setupParams, params)
}

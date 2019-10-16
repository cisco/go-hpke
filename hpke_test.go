package hpke

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

var (
	psk      = []byte("mellon")
	pskID    = []byte("Ennyn Durin aran Moria")
	original = []byte("Beauty is truth, truth beauty")
	aad      = []byte("that is all // Ye know on earth, and all ye need to know")
	info     = []byte("Ode on a Grecian Urn")
	rtts     = 10
)

const (
	outputTestVectorEnvironmentKey = "HPKE_TEST_VECTORS_OUT"
	inputTestVectorEnvironmentKey  = "HPKE_TEST_VECTORS_IN"
	testVectorEncryptionCount      = 10
)

///////
// Infallible marshal / unmarshal
func fatalOnError(t *testing.T, err error, msg string) {
	realMsg := fmt.Sprintf("%s: %v", msg, err)
	if err != nil {
		if t != nil {
			t.Fatalf(realMsg)
		} else {
			panic(realMsg)
		}
	}
}

func mustUnhex(t *testing.T, h string) []byte {
	out, err := hex.DecodeString(h)
	fatalOnError(t, err, "Unhex failed")
	return out
}

func mustHex(d []byte) string {
	return hex.EncodeToString(d)
}

func mustUnmarshalPriv(t *testing.T, suite CipherSuite, h string) KEMPrivateKey {
	skm := mustUnhex(t, h)
	sk, err := suite.KEM.unmarshalPrivate(skm)
	fatalOnError(t, err, "unmarshalPrivate failed")
	return sk
}

func mustMarshalPriv(suite CipherSuite, priv KEMPrivateKey) string {
	return mustHex(suite.KEM.marshalPrivate(priv))
}

func mustUnmarshalPub(t *testing.T, suite CipherSuite, h string) KEMPublicKey {
	pkm := mustUnhex(t, h)
	pk, err := suite.KEM.Unmarshal(pkm)
	fatalOnError(t, err, "Unmarshal failed")
	return pk
}

func mustMarshalPub(suite CipherSuite, pub KEMPublicKey) string {
	return mustHex(suite.KEM.Marshal(pub))
}

///////
// Symmetric encryption test vector structures
type encryptionTestVector struct {
	plaintext  []byte
	aad        []byte
	ciphertext []byte
}

func (etv encryptionTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"plaintext":  mustHex(etv.plaintext),
		"aad":        mustHex(etv.aad),
		"ciphertext": mustHex(etv.ciphertext),
	})
}

func (etv *encryptionTestVector) UnmarshalJSON(data []byte) error {
	raw := map[string]string{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.plaintext = mustUnhex(nil, raw["plaintext"])
	etv.aad = mustUnhex(nil, raw["aad"])
	etv.ciphertext = mustUnhex(nil, raw["ciphertext"])
	return nil
}

///////
// HPKE test vector structures
type rawTestVector struct {
	// Parameters
	Mode   HPKEMode `json:"mode"`
	KEMID  KEMID    `json:"kemID"`
	KDFID  KDFID    `json:"kdfID"`
	AEADID AEADID   `json:"aeadID"`
	Info   string   `json:"info"`

	// Private keys
	SKR   string `json:"skR"`
	SKI   string `json:"skI,omitempty"`
	PSK   string `json:"psk,omitempty"`
	PSKID string `json:"pskID,omitempty"`

	// Public keys
	PKR string `json:"pkR"`
	PKI string `json:"pkI,omitempty"`

	// Ephemeral key
	SKE string `json:"skE"`
	PKE string `json:"pkE"`

	// Key schedule inputs and computations
	Enc     string `json:"enc"`
	Zz      string `json:"zz"`
	Context string `json:"context"`
	Secret  string `json:"secret"`
	Key     string `json:"key"`
	Nonce   string `json:"nonce"`

	Encryptions []encryptionTestVector `json:"encryptions"`
}

type testVector struct {
	t     *testing.T
	suite CipherSuite

	// Parameters
	mode   HPKEMode
	kemID  KEMID
	kdfID  KDFID
	aeadID AEADID
	info   []byte

	// Private keys
	skR   KEMPrivateKey
	skI   KEMPrivateKey
	skE   KEMPrivateKey
	psk   []byte
	pskID []byte

	// Public keys
	pkR KEMPublicKey
	pkI KEMPublicKey
	pkE KEMPublicKey

	// Key schedule inputs and computations
	enc     []byte
	zz      []byte
	context []byte
	secret  []byte
	key     []byte
	nonce   []byte

	encryptions []encryptionTestVector
}

func (tv testVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawTestVector{
		Mode:   tv.mode,
		KEMID:  tv.kemID,
		KDFID:  tv.kdfID,
		AEADID: tv.aeadID,
		Info:   mustHex(tv.info),

		SKR:   mustMarshalPriv(tv.suite, tv.skR),
		SKI:   mustMarshalPriv(tv.suite, tv.skI),
		SKE:   mustMarshalPriv(tv.suite, tv.skE),
		PSK:   mustHex(tv.psk),
		PSKID: mustHex(tv.pskID),

		PKR: mustMarshalPub(tv.suite, tv.pkR),
		PKI: mustMarshalPub(tv.suite, tv.pkI),
		PKE: mustMarshalPub(tv.suite, tv.pkE),

		Enc:     mustHex(tv.enc),
		Zz:      mustHex(tv.zz),
		Context: mustHex(tv.context),
		Secret:  mustHex(tv.secret),
		Key:     mustHex(tv.key),
		Nonce:   mustHex(tv.nonce),

		Encryptions: tv.encryptions,
	})
}

func (tv *testVector) UnmarshalJSON(data []byte) error {
	raw := rawTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	tv.mode = raw.Mode
	tv.kemID = raw.KEMID
	tv.kdfID = raw.KDFID
	tv.aeadID = raw.AEADID
	tv.info = mustUnhex(tv.t, raw.Info)

	tv.skR = mustUnmarshalPriv(tv.t, tv.suite, raw.SKR)
	tv.skI = mustUnmarshalPriv(tv.t, tv.suite, raw.SKI)
	tv.skE = mustUnmarshalPriv(tv.t, tv.suite, raw.SKE)
	tv.psk = mustUnhex(tv.t, raw.PSK)
	tv.pskID = mustUnhex(tv.t, raw.PSKID)

	tv.pkR = mustUnmarshalPub(tv.t, tv.suite, raw.PKR)
	tv.pkI = mustUnmarshalPub(tv.t, tv.suite, raw.PKI)
	tv.pkE = mustUnmarshalPub(tv.t, tv.suite, raw.PKE)

	tv.enc = mustUnhex(tv.t, raw.Enc)
	tv.zz = mustUnhex(tv.t, raw.Zz)
	tv.context = mustUnhex(tv.t, raw.Context)
	tv.secret = mustUnhex(tv.t, raw.Secret)
	tv.key = mustUnhex(tv.t, raw.Key)
	tv.nonce = mustUnhex(tv.t, raw.Nonce)

	tv.encryptions = raw.Encryptions
	return nil
}

///////
// Direct tests

func roundTrip(t *testing.T, kemID KEMID, kdfID KDFID, aeadID AEADID, enc *EncryptContext, dec *DecryptContext) {
	for range make([]struct{}, rtts) {
		encrypted := enc.Seal(aad, original)
		decrypted, err := dec.Open(aad, encrypted)
		if err != nil {
			t.Fatalf("[%x, %x, %x] Error in Open: %s", kemID, kdfID, aeadID, err)
		}

		if !bytes.Equal(decrypted, original) {
			t.Fatalf("[%x, %x, %x] Incorrect decryption: [%x] != [%x]", kemID, kdfID, aeadID, decrypted, original)
		}
	}
}

func roundTripBase(t *testing.T, kemID KEMID, kdfID KDFID, aeadID AEADID) {
	suite, err := AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	skR, pkR, err := suite.KEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error generating DH key pair: %s", kemID, kdfID, aeadID, err)
	}

	enc, ctxI, err := SetupBaseI(suite, rand.Reader, pkR, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", kemID, kdfID, aeadID, err)
	}

	ctxR, err := SetupBaseR(suite, skR, enc, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", kemID, kdfID, aeadID, err)
	}

	roundTrip(t, kemID, kdfID, aeadID, ctxI, ctxR)
}

func roundTripPSK(t *testing.T, kemID KEMID, kdfID KDFID, aeadID AEADID) {
	suite, err := AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	skR, pkR, err := suite.KEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error generating DH key pair: %s", kemID, kdfID, aeadID, err)
	}

	enc, ctxI, err := SetupPSKI(suite, rand.Reader, pkR, psk, pskID, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupPSKI: %s", kemID, kdfID, aeadID, err)
	}

	ctxR, err := SetupPSKR(suite, skR, enc, psk, pskID, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", kemID, kdfID, aeadID, err)
	}

	roundTrip(t, kemID, kdfID, aeadID, ctxI, ctxR)
}

func roundTripAuth(t *testing.T, kemID KEMID, kdfID KDFID, aeadID AEADID) {
	suite, err := AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	if _, ok := suite.KEM.(AuthKEMScheme); !ok {
		return
	}

	skI, pkI, err := suite.KEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error generating initiator DH key pair: %s", kemID, kdfID, aeadID, err)
	}

	skR, pkR, err := suite.KEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error generating responder DH key pair: %s", kemID, kdfID, aeadID, err)
	}

	enc, ctxI, err := SetupAuthI(suite, rand.Reader, pkR, skI, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupAuthI: %s", kemID, kdfID, aeadID, err)
	}

	ctxR, err := SetupAuthR(suite, skR, pkI, enc, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", kemID, kdfID, aeadID, err)
	}

	roundTrip(t, kemID, kdfID, aeadID, ctxI, ctxR)
}

func roundTripPSKAuth(t *testing.T, kemID KEMID, kdfID KDFID, aeadID AEADID) {
	suite, err := AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	if _, ok := suite.KEM.(AuthKEMScheme); !ok {
		return
	}

	skI, pkI, err := suite.KEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error generating initiator DH key pair: %s", kemID, kdfID, aeadID, err)
	}

	skR, pkR, err := suite.KEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error generating responder DH key pair: %s", kemID, kdfID, aeadID, err)
	}

	enc, ctxI, err := SetupPSKAuthI(suite, rand.Reader, pkR, skI, psk, pskID, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupPSKAuthI: %s", kemID, kdfID, aeadID, err)
	}

	ctxR, err := SetupPSKAuthR(suite, skR, pkI, enc, psk, pskID, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", kemID, kdfID, aeadID, err)
	}

	roundTrip(t, kemID, kdfID, aeadID, ctxI, ctxR)
}

func TestModes(t *testing.T) {
	for kemID, _ := range kems {
		for kdfID, _ := range kdfs {
			for aeadID, _ := range aeads {
				roundTripBase(t, kemID, kdfID, aeadID)
				roundTripAuth(t, kemID, kdfID, aeadID)
				roundTripPSK(t, kemID, kdfID, aeadID)
				roundTripPSKAuth(t, kemID, kdfID, aeadID)
			}
		}
	}
}

func processTestVectorEncryptions(t *testing.T, vector testVector, enc *EncryptContext, dec *DecryptContext) {
	for _, data := range vector.encryptions {
		encrypted := enc.Seal(data.aad, data.plaintext)
		decrypted, err := dec.Open(data.aad, encrypted)
		if err != nil {
			t.Fatalf("[%x, %x, %x] Error in Open: %s", vector.kemID, vector.kdfID, vector.aeadID, err)
		}

		if data.ciphertext != nil && !bytes.Equal(encrypted, data.ciphertext) {
			t.Fatalf("[%x, %x, %x] Incorrect encryption: [%x] != [%x]", vector.kemID, vector.kdfID, vector.aeadID, data.ciphertext, encrypted)
		}

		if !bytes.Equal(decrypted, data.plaintext) {
			t.Fatalf("[%x, %x, %x] Incorrect decryption: [%x] != [%x]", vector.kemID, vector.kdfID, vector.aeadID, decrypted, data.plaintext)
		}
	}
}

func (vector testVector) matchesParameters(t *testing.T, setupParams SetupParameters, contextParams ContextParameters) {
	if !bytes.Equal(setupParams.zz, vector.zz) {
		t.Fatalf("[%x, %x, %x] Mismatched zz. Expected %s, got %s", vector.kemID, vector.kdfID, vector.aeadID, mustHex(vector.zz), mustHex(setupParams.zz))
	}
	if !bytes.Equal(setupParams.enc, vector.enc) {
		t.Fatalf("[%x, %x, %x] Mismatched enc. Expected %s, got %s", vector.kemID, vector.kdfID, vector.aeadID, mustHex(vector.enc), mustHex(setupParams.enc))
	}
	if !bytes.Equal(contextParams.context, vector.context) {
		t.Fatalf("[%x, %x, %x] Mismatched hpkeContext. Expected %s, got %s", vector.kemID, vector.kdfID, vector.aeadID, mustHex(vector.context), mustHex(contextParams.context))
	}
	if !bytes.Equal(contextParams.secret, vector.secret) {
		t.Fatalf("[%x, %x, %x] Mismatched secret. Expected %s, got %s", vector.kemID, vector.kdfID, vector.aeadID, mustHex(vector.secret), mustHex(contextParams.secret))
	}
	if !bytes.Equal(contextParams.key, vector.key) {
		t.Fatalf("[%x, %x, %x] Mismatched key. Expected %s, got %s", vector.kemID, vector.kdfID, vector.aeadID, mustHex(vector.key), mustHex(contextParams.key))
	}
	if !bytes.Equal(contextParams.nonce, vector.nonce) {
		t.Fatalf("[%x, %x, %x] Mismatched nonce. Expected %s, got %s", vector.kemID, vector.kdfID, vector.aeadID, mustHex(vector.nonce), mustHex(contextParams.nonce))
	}
}

func processTestVector(t *testing.T, vector testVector) {
	suite, err := assembleCipherSuiteWithEphemeralKeys(vector.kemID, vector.kdfID, vector.aeadID, vector.skE)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", vector.kemID, vector.kdfID, vector.aeadID, err)
	}

	var enc []byte
	var ctxI *EncryptContext
	var ctxR *DecryptContext

	switch vector.mode {
	case modeBase:
		enc, ctxI, err = SetupBaseI(suite, rand.Reader, vector.pkR, vector.info)
		if err != nil {
			t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", vector.kemID, vector.kdfID, vector.aeadID, err)
		}

		ctxR, err = SetupBaseR(suite, vector.skR, enc, vector.info)
		if err != nil {
			t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", vector.kemID, vector.kdfID, vector.aeadID, err)
		}
	case modePSK:
		enc, ctxI, err = SetupPSKI(suite, rand.Reader, vector.pkR, vector.psk, vector.pskID, vector.info)
		if err != nil {
			t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", vector.kemID, vector.kdfID, vector.aeadID, err)
		}

		ctxR, err = SetupPSKR(suite, vector.skR, enc, vector.psk, vector.pskID, vector.info)
		if err != nil {
			t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", vector.kemID, vector.kdfID, vector.aeadID, err)
		}
	case modeAuth:
		enc, ctxI, err = SetupAuthI(suite, rand.Reader, vector.pkR, vector.skI, vector.info)
		if err != nil {
			t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", vector.kemID, vector.kdfID, vector.aeadID, err)
		}

		ctxR, err = SetupAuthR(suite, vector.skR, vector.pkI, enc, vector.info)
		if err != nil {
			t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", vector.kemID, vector.kdfID, vector.aeadID, err)
		}
	case modePSKAuth:
		enc, ctxI, err = SetupPSKAuthI(suite, rand.Reader, vector.pkR, vector.skI, vector.psk, vector.pskID, vector.info)
		if err != nil {
			t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", vector.kemID, vector.kdfID, vector.aeadID, err)
		}

		ctxR, err = SetupPSKAuthR(suite, vector.skR, vector.pkI, enc, vector.psk, vector.pskID, vector.info)
		if err != nil {
			t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", vector.kemID, vector.kdfID, vector.aeadID, err)
		}
	}

	setupParamsI, contextParamsI := ctxI.parameters()
	vector.matchesParameters(t, setupParamsI, contextParamsI)
	setupParamsR, contextParamsR := ctxR.parameters()
	vector.matchesParameters(t, setupParamsR, contextParamsR)

	processTestVectorEncryptions(t, vector, ctxI, ctxR)
}

/*
func unmarshalPrivate(t *testing.T, suite CipherSuite, encodedKey string) KEMPrivateKey {
	skM := mustUnhex(encodedKey)
	sk, err := suite.KEM.unmarshalPrivate(skM)
	if err != nil {
		t.Fatalf("Error in unmarshalPrivate: %s", err)
	}
	return sk
}

func unmarshalPublic(t *testing.T, suite CipherSuite, encodedKey string) KEMPublicKey {
	pkM := mustUnhex(encodedKey)
	pk, err := suite.KEM.Unmarshal(pkM)
	if err != nil {
		t.Fatalf("Error in unmarshalPublic: %s", err)
	}
	return pk
}

func (vector rawTestVector) Unmarshal(t *testing.T) testVector {
	suite, err := assembleCipherSuiteWithEphemeralKeys(vector.KEMID, vector.KDFID, vector.AEADID, nil)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", vector.KEMID, vector.KDFID, vector.AEADID, err)
	}

	skR := unmarshalPrivate(t, suite, vector.SKR)
	pkR := unmarshalPublic(t, suite, vector.PKR)

	skE := unmarshalPrivate(t, suite, vector.SKE)
	pkE := unmarshalPublic(t, suite, vector.PKE)

	var skI KEMPrivateKey
	var pkI KEMPublicKey
	if vector.SKI != "" && vector.PKI != "" {
		skI = unmarshalPrivate(t, suite, vector.SKI)
		pkI = unmarshalPublic(t, suite, vector.PKI)
	}

	rawVector := testVector{
		mode:        vector.Mode,
		kemID:       vector.KEMID,
		kdfID:       vector.KDFID,
		aeadID:      vector.AEADID,
		info:        mustUnhex(vector.Info),
		skR:         skR,
		pkR:         pkR,
		skI:         skI,
		psk:         mustUnhex(vector.PSK),
		pskID:       mustUnhex(vector.PSKID),
		pkI:         pkI,
		skE:         skE,
		pkE:         pkE,
		enc:         mustUnhex(vector.Enc),
		zz:          mustUnhex(vector.Zz),
		context:     mustUnhex(vector.Context),
		secret:      mustUnhex(vector.Secret),
		key:         mustUnhex(vector.Key),
		nonce:       mustUnhex(vector.Nonce),
		encryptions: vector.Encryptions,
	}

	return rawVector
}

func createTestVectors(t *testing.T, vectors []rawTestVector) []testVector {
	rawVectors := make([]testVector, len(vectors))
	for i, vector := range vectors {
		rawVectors[i] = vector.Unmarshal(t)
	}
	return rawVectors
}
*/

func verifyTestVectors(t *testing.T, vectorString []byte) {
	var vectors []testVector
	err := json.Unmarshal(vectorString, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %s", err)
	}

	for _, vector := range vectors {
		processTestVector(t, vector)
	}
}

func generateEncryptionTestVectors(ctxI *EncryptContext, ctxR *DecryptContext) ([]encryptionTestVector, error) {
	vectors := make([]encryptionTestVector, testVectorEncryptionCount)
	for i := 0; i < len(vectors); i++ {
		aad := []byte(fmt.Sprintf("Count-%d", i))
		encrypted := ctxI.Seal(aad, original)
		decrypted, err := ctxR.Open(aad, encrypted)
		if err != nil {
			return nil, fmt.Errorf("Decryption failure: %s", err)
		}

		if !bytes.Equal(original, decrypted) {
			return nil, fmt.Errorf("Decryption mismatch: %s", err)
		}

		vectors[i] = encryptionTestVector{
			plaintext:  original,
			aad:        aad,
			ciphertext: encrypted,
		}
	}

	return vectors, nil
}

func generateKeyPair(t *testing.T, suite CipherSuite) (KEMPrivateKey, KEMPublicKey) {
	sk, pk, err := suite.KEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error generating DH key pair: %s", suite.KEM.ID(), suite.KDF.ID(), suite.AEAD.ID(), err)
	}
	return sk, pk
}

func generateBaseTestVector(t *testing.T, kemID KEMID, kdfID KDFID, aeadID AEADID) testVector {
	suite, err := assembleCipherSuiteWithEphemeralKeys(kemID, kdfID, aeadID, nil)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	skE, pkE := generateKeyPair(t, suite)
	skR, pkR := generateKeyPair(t, suite)

	suite, err = assembleCipherSuiteWithEphemeralKeys(kemID, kdfID, aeadID, skE)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	enc, ctxI, err := SetupBaseI(suite, rand.Reader, pkR, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", kemID, kdfID, aeadID, err)
	}

	ctxR, err := SetupBaseR(suite, skR, enc, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupBaseI: %s", kemID, kdfID, aeadID, err)
	}

	setupParams, contextParams := ctxI.parameters()
	key := make([]byte, len(contextParams.key))
	copy(key, contextParams.key)
	nonce := make([]byte, len(contextParams.nonce))
	copy(nonce, contextParams.nonce)

	encryptionVectors, err := generateEncryptionTestVectors(ctxI, ctxR)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in generateEncryptionTestVectors: %s", kemID, kdfID, aeadID, err)
	}

	vector := testVector{
		mode:        modeBase,
		kemID:       kemID,
		kdfID:       kdfID,
		aeadID:      aeadID,
		info:        info,
		skR:         skR,
		pkR:         pkR,
		skI:         nil,
		psk:         nil,
		pskID:       nil,
		pkI:         nil,
		skE:         skE,
		pkE:         pkE,
		enc:         setupParams.enc,
		zz:          setupParams.zz,
		context:     contextParams.context,
		secret:      contextParams.secret,
		key:         key,
		nonce:       nonce,
		encryptions: encryptionVectors,
	}

	return vector
}

func generatePSKTestVector(t *testing.T, kemID KEMID, kdfID KDFID, aeadID AEADID) testVector {
	suite, err := assembleCipherSuiteWithEphemeralKeys(kemID, kdfID, aeadID, nil)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	skE, pkE := generateKeyPair(t, suite)
	skR, pkR := generateKeyPair(t, suite)

	suite, err = assembleCipherSuiteWithEphemeralKeys(kemID, kdfID, aeadID, skE)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	enc, ctxI, err := SetupPSKI(suite, rand.Reader, pkR, psk, pskID, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupPSKI: %s", kemID, kdfID, aeadID, err)
	}

	ctxR, err := SetupPSKR(suite, skR, enc, psk, pskID, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupPSKR: %s", kemID, kdfID, aeadID, err)
	}

	setupParams, contextParams := ctxI.parameters()
	key := make([]byte, len(contextParams.key))
	copy(key, contextParams.key)
	nonce := make([]byte, len(contextParams.nonce))
	copy(nonce, contextParams.nonce)

	encryptionVectors, err := generateEncryptionTestVectors(ctxI, ctxR)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in generateEncryptionTestVectors: %s", kemID, kdfID, aeadID, err)
	}

	vector := testVector{
		mode:        modePSK,
		kemID:       kemID,
		kdfID:       kdfID,
		aeadID:      aeadID,
		info:        info,
		skR:         skR,
		pkR:         pkR,
		skI:         nil,
		psk:         psk,
		pskID:       pskID,
		pkI:         nil,
		skE:         skE,
		pkE:         pkE,
		enc:         setupParams.enc,
		zz:          setupParams.zz,
		context:     contextParams.context,
		secret:      contextParams.secret,
		key:         key,
		nonce:       nonce,
		encryptions: encryptionVectors,
	}

	return vector
}

func generateAuthTestVector(t *testing.T, kemID KEMID, kdfID KDFID, aeadID AEADID) testVector {
	suite, err := assembleCipherSuiteWithEphemeralKeys(kemID, kdfID, aeadID, nil)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	skE, pkE := generateKeyPair(t, suite)
	skR, pkR := generateKeyPair(t, suite)
	skI, pkI := generateKeyPair(t, suite)

	suite, err = assembleCipherSuiteWithEphemeralKeys(kemID, kdfID, aeadID, skE)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	enc, ctxI, err := SetupAuthI(suite, rand.Reader, pkR, skI, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupPSKI: %s", kemID, kdfID, aeadID, err)
	}

	ctxR, err := SetupAuthR(suite, skR, pkI, enc, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupPSKR: %s", kemID, kdfID, aeadID, err)
	}

	setupParams, contextParams := ctxI.parameters()
	key := make([]byte, len(contextParams.key))
	copy(key, contextParams.key)
	nonce := make([]byte, len(contextParams.nonce))
	copy(nonce, contextParams.nonce)

	encryptionVectors, err := generateEncryptionTestVectors(ctxI, ctxR)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in generateEncryptionTestVectors: %s", kemID, kdfID, aeadID, err)
	}

	vector := testVector{
		mode:        modeAuth,
		kemID:       kemID,
		kdfID:       kdfID,
		aeadID:      aeadID,
		info:        info,
		skR:         skR,
		pkR:         pkR,
		skI:         skI,
		psk:         nil,
		pskID:       nil,
		pkI:         pkI,
		skE:         skE,
		pkE:         pkE,
		enc:         setupParams.enc,
		zz:          setupParams.zz,
		context:     contextParams.context,
		secret:      contextParams.secret,
		key:         key,
		nonce:       nonce,
		encryptions: encryptionVectors,
	}

	return vector
}

func generatePSKAuthTestVector(t *testing.T, kemID KEMID, kdfID KDFID, aeadID AEADID) testVector {
	suite, err := assembleCipherSuiteWithEphemeralKeys(kemID, kdfID, aeadID, nil)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	skE, pkE := generateKeyPair(t, suite)
	skR, pkR := generateKeyPair(t, suite)
	skI, pkI := generateKeyPair(t, suite)

	suite, err = assembleCipherSuiteWithEphemeralKeys(kemID, kdfID, aeadID, skE)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	enc, ctxI, err := SetupPSKAuthI(suite, rand.Reader, pkR, skI, psk, pskID, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupPSKI: %s", kemID, kdfID, aeadID, err)
	}

	ctxR, err := SetupPSKAuthR(suite, skR, pkI, enc, psk, pskID, info)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in SetupPSKR: %s", kemID, kdfID, aeadID, err)
	}

	setupParams, contextParams := ctxI.parameters()
	key := make([]byte, len(contextParams.key))
	copy(key, contextParams.key)
	nonce := make([]byte, len(contextParams.nonce))
	copy(nonce, contextParams.nonce)

	encryptionVectors, err := generateEncryptionTestVectors(ctxI, ctxR)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error in generateEncryptionTestVectors: %s", kemID, kdfID, aeadID, err)
	}

	vector := testVector{
		mode:        modePSKAuth,
		kemID:       kemID,
		kdfID:       kdfID,
		aeadID:      aeadID,
		info:        info,
		skR:         skR,
		pkR:         pkR,
		skI:         skI,
		psk:         psk,
		pskID:       pskID,
		pkI:         pkI,
		skE:         skE,
		pkE:         pkE,
		enc:         setupParams.enc,
		zz:          setupParams.zz,
		context:     contextParams.context,
		secret:      contextParams.secret,
		key:         key,
		nonce:       nonce,
		encryptions: encryptionVectors,
	}

	return vector
}

/*
func createRawTestVectors(t *testing.T, vectors []testVector) []rawTestVector {
	rawVectors := make([]rawTestVector, len(vectors))
	for i, vector := range vectors {
		suite, err := assembleCipherSuiteWithEphemeralKeys(vector.kemID, vector.kdfID, vector.aeadID, nil)
		if err != nil {
			t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", vector.kemID, vector.kdfID, vector.aeadID, err)
		}

		rawVectors[i] = rawTestVector{
			Mode:        vector.mode,
			KEMID:       vector.kemID,
			KDFID:       vector.kdfID,
			AEADID:      vector.aeadID,
			Info:        mustHex(vector.info),
			SKR:         mustHex(suite.KEM.marshalPrivate(vector.skR)),
			PKR:         mustHex(suite.KEM.Marshal(vector.pkR)),
			SKI:         mustHex(suite.KEM.marshalPrivate(vector.skI)),
			PSK:         mustHex(vector.psk),
			PSKID:       mustHex(vector.pskID),
			PKI:         mustHex(suite.KEM.Marshal(vector.pkI)),
			SKE:         mustHex(suite.KEM.marshalPrivate(vector.skE)),
			PKE:         mustHex(suite.KEM.Marshal(vector.pkE)),
			Enc:         mustHex(vector.enc),
			Zz:          mustHex(vector.zz),
			Context:     mustHex(vector.context),
			Secret:      mustHex(vector.secret),
			Key:         mustHex(vector.key),
			Nonce:       mustHex(vector.nonce),
			Encryptions: vector.encryptions,
		}
	}
	return rawVectors
}
*/

func TestVectorGenerate(t *testing.T) {
	var outputFile string
	if outputFile = os.Getenv(outputTestVectorEnvironmentKey); len(outputFile) == 0 {
		t.Skip("Test vectors were not requested")
	}

	// We only generate test vectors for select ciphersuites
	supportedKEMs := []KEMID{DHKEM_X25519, DHKEM_X448, DHKEM_P256, DHKEM_P521}
	supportedKDFs := []KDFID{KDF_HKDF_SHA256, KDF_HKDF_SHA512}
	supportedAEADs := []AEADID{AEAD_AESGCM128, AEAD_AESGCM256, AEAD_CHACHA20POLY1305}

	vectors := make([]testVector, 0)
	for _, kemID := range supportedKEMs {
		for _, kdfID := range supportedKDFs {
			for _, aeadID := range supportedAEADs {
				vectors = append(vectors, generateBaseTestVector(t, kemID, kdfID, aeadID))
				vectors = append(vectors, generatePSKTestVector(t, kemID, kdfID, aeadID))
				vectors = append(vectors, generateAuthTestVector(t, kemID, kdfID, aeadID))
				vectors = append(vectors, generatePSKAuthTestVector(t, kemID, kdfID, aeadID))
			}
		}
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %s", err)
	}

	// Verify that we process them correctly
	verifyTestVectors(t, encoded)

	// Write them to the indicated file
	ioutil.WriteFile(outputFile, encoded, 0644)
}

func TestVectorInterop(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %s", err)
	}

	verifyTestVectors(t, encoded)
}

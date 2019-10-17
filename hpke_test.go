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

func mustGenerateKeyPair(t *testing.T, suite CipherSuite) (KEMPrivateKey, KEMPublicKey) {
	sk, pk, err := suite.KEM.GenerateKeyPair(rand.Reader)
	fatalOnError(t, err, "Error generating DH key pair")
	return sk, pk
}

///////
// Assertions
func assert(t *testing.T, suite CipherSuite, msg string, test bool) {
	if !test {
		t.Fatalf("[%04x, %04x, %04x] %s", suite.KEM.ID(), suite.KDF.ID(), suite.AEAD.ID(), msg)
	}
}

func assertNotError(t *testing.T, suite CipherSuite, msg string, err error) {
	realMsg := fmt.Sprintf("%s: %v", msg, err)
	assert(t, suite, realMsg, err == nil)
}

func assertBytesEqual(t *testing.T, suite CipherSuite, msg string, lhs, rhs []byte) {
	realMsg := fmt.Sprintf("%s: [%x] != [%x]", msg, lhs, rhs)
	assert(t, suite, realMsg, bytes.Equal(lhs, rhs))
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
	SKE   string `json:"skE"`
	PSK   string `json:"psk,omitempty"`
	PSKID string `json:"pskID,omitempty"`

	// Public keys
	PKR string `json:"pkR"`
	PKI string `json:"pkI,omitempty"`
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

	tv.suite, err = AssembleCipherSuite(raw.KEMID, raw.KDFID, raw.AEADID)
	if err != nil {
		return err
	}

	tv.skR = mustUnmarshalPriv(tv.t, tv.suite, raw.SKR)
	tv.skI = mustUnmarshalPriv(tv.t, tv.suite, raw.SKI)
	tv.skE = mustUnmarshalPriv(tv.t, tv.suite, raw.SKE)
	tv.psk = mustUnhex(tv.t, raw.PSK)
	tv.pskID = mustUnhex(tv.t, raw.PSKID)

	tv.suite.KEM.setEphemeralKeyPair(tv.skE)

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

type testVectorArray struct {
	t       *testing.T
	vectors []testVector
}

func (tva testVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *testVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

///////
// Generalize setup functions so that we can iterate over them easily
type setupMode struct {
	Mode HPKEMode
	OK   func(suite CipherSuite) bool
	I    func(suite CipherSuite, pkR KEMPublicKey, info []byte, skI KEMPrivateKey, psk, pskID []byte) ([]byte, *EncryptContext, error)
	R    func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkI KEMPublicKey, psk, pskID []byte) (*DecryptContext, error)
}

var setupModes = map[HPKEMode]setupMode{
	modeBase: {
		Mode: modeBase,
		OK:   func(suite CipherSuite) bool { return true },
		I: func(suite CipherSuite, pkR KEMPublicKey, info []byte, skI KEMPrivateKey, psk, pskID []byte) ([]byte, *EncryptContext, error) {
			return SetupBaseI(suite, rand.Reader, pkR, info)
		},
		R: func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkI KEMPublicKey, psk, pskID []byte) (*DecryptContext, error) {
			return SetupBaseR(suite, skR, enc, info)
		},
	},
	modePSK: {
		Mode: modePSK,
		OK:   func(suite CipherSuite) bool { return true },
		I: func(suite CipherSuite, pkR KEMPublicKey, info []byte, skI KEMPrivateKey, psk, pskID []byte) ([]byte, *EncryptContext, error) {
			return SetupPSKI(suite, rand.Reader, pkR, psk, pskID, info)
		},
		R: func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkI KEMPublicKey, psk, pskID []byte) (*DecryptContext, error) {
			return SetupPSKR(suite, skR, enc, psk, pskID, info)
		},
	},
	modeAuth: {
		Mode: modeAuth,
		OK: func(suite CipherSuite) bool {
			_, ok := suite.KEM.(AuthKEMScheme)
			return ok
		},
		I: func(suite CipherSuite, pkR KEMPublicKey, info []byte, skI KEMPrivateKey, psk, pskID []byte) ([]byte, *EncryptContext, error) {
			return SetupAuthI(suite, rand.Reader, pkR, skI, info)
		},
		R: func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkI KEMPublicKey, psk, pskID []byte) (*DecryptContext, error) {
			return SetupAuthR(suite, skR, pkI, enc, info)
		},
	},
	modePSKAuth: {
		Mode: modePSKAuth,
		OK: func(suite CipherSuite) bool {
			_, ok := suite.KEM.(AuthKEMScheme)
			return ok
		},
		I: func(suite CipherSuite, pkR KEMPublicKey, info []byte, skI KEMPrivateKey, psk, pskID []byte) ([]byte, *EncryptContext, error) {
			return SetupPSKAuthI(suite, rand.Reader, pkR, skI, psk, pskID, info)
		},
		R: func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkI KEMPublicKey, psk, pskID []byte) (*DecryptContext, error) {
			return SetupPSKAuthR(suite, skR, pkI, enc, psk, pskID, info)
		},
	},
}

///////
// Direct tests

type roundTripTest struct {
	kemID  KEMID
	kdfID  KDFID
	aeadID AEADID
	setup  setupMode
}

func (rtt roundTripTest) Test(t *testing.T) {
	suite, err := AssembleCipherSuite(rtt.kemID, rtt.kdfID, rtt.aeadID)
	if err != nil {
		t.Fatalf("[%04x, %04x, %04x] Error looking up ciphersuite: %v", rtt.kemID, rtt.kdfID, rtt.aeadID, err)
	}

	if !rtt.setup.OK(suite) {
		return
	}

	skI, pkI := mustGenerateKeyPair(t, suite)
	skR, pkR := mustGenerateKeyPair(t, suite)

	enc, ctxI, err := rtt.setup.I(suite, pkR, info, skI, psk, pskID)
	assertNotError(t, suite, "Error in SetupI", err)

	ctxR, err := rtt.setup.R(suite, skR, enc, info, pkI, psk, pskID)
	assertNotError(t, suite, "Error in SetupR", err)

	for range make([]struct{}, rtts) {
		encrypted := ctxI.Seal(aad, original)
		decrypted, err := ctxR.Open(aad, encrypted)
		assertNotError(t, suite, "Error in Open", err)
		assertBytesEqual(t, suite, "Incorrect decryption", decrypted, original)
	}
}

func TestModes(t *testing.T) {
	for kemID, _ := range kems {
		for kdfID, _ := range kdfs {
			for aeadID, _ := range aeads {
				for mode, setup := range setupModes {
					label := fmt.Sprintf("kem=%04x/kdf=%04x/aead=%04x/mode=%02x", kemID, kdfID, aeadID, mode)
					rtt := roundTripTest{kemID, kdfID, aeadID, setup}
					t.Run(label, rtt.Test)
				}
			}
		}
	}
}

///////
// Generation and processing of test vectors

func verifyEncryptions(tv testVector, enc *EncryptContext, dec *DecryptContext) {
	for _, data := range tv.encryptions {
		encrypted := enc.Seal(data.aad, data.plaintext)
		decrypted, err := dec.Open(data.aad, encrypted)

		assertNotError(tv.t, tv.suite, "Error in Open", err)
		assertBytesEqual(tv.t, tv.suite, "Incorrect encryption", encrypted, data.ciphertext)
		assertBytesEqual(tv.t, tv.suite, "Incorrect decryption", decrypted, data.plaintext)
	}
}

func verifyParameters(tv testVector, setupParams SetupParameters, contextParams ContextParameters) {
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'zz'", tv.zz, setupParams.zz)
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'enc'", tv.enc, setupParams.enc)
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'context'", tv.context, contextParams.context)
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'secret'", tv.secret, contextParams.secret)
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'key'", tv.key, contextParams.key)
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'nonce'", tv.nonce, contextParams.nonce)
}

func verifyTestVector(tv testVector) {
	setup := setupModes[tv.mode]

	enc, ctxI, err := setup.I(tv.suite, tv.pkR, tv.info, tv.skI, tv.psk, tv.pskID)
	assertNotError(tv.t, tv.suite, "Error in SetupI", err)
	assertBytesEqual(tv.t, tv.suite, "Encapsulated key mismatch", enc, tv.enc)

	ctxR, err := setup.R(tv.suite, tv.skR, tv.enc, tv.info, tv.pkI, tv.psk, tv.pskID)
	assertNotError(tv.t, tv.suite, "Error in SetupR", err)

	setupParamsI, contextParamsI := ctxI.parameters()
	verifyParameters(tv, setupParamsI, contextParamsI)

	setupParamsR, contextParamsR := ctxR.parameters()
	verifyParameters(tv, setupParamsR, contextParamsR)

	verifyEncryptions(tv, ctxI, ctxR)
}

func vectorTest(vector testVector) func(t *testing.T) {
	return func(t *testing.T) {
		verifyTestVector(vector)
	}
}

func verifyTestVectors(t *testing.T, vectorString []byte, subtest bool) {
	vectors := testVectorArray{t: t}
	err := json.Unmarshal(vectorString, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, tv := range vectors.vectors {
		test := vectorTest(tv)
		if !subtest {
			test(t)
		} else {
			label := fmt.Sprintf("kem=%04x/kdf=%04x/aead=%04x/mode=%02x", tv.kemID, tv.kdfID, tv.aeadID, tv.mode)
			t.Run(label, test)
		}
	}
}

func generateEncryptions(t *testing.T, suite CipherSuite, ctxI *EncryptContext, ctxR *DecryptContext) ([]encryptionTestVector, error) {
	vectors := make([]encryptionTestVector, testVectorEncryptionCount)
	for i := 0; i < len(vectors); i++ {
		aad := []byte(fmt.Sprintf("Count-%d", i))
		encrypted := ctxI.Seal(aad, original)
		decrypted, err := ctxR.Open(aad, encrypted)
		assertNotError(t, suite, "Decryption failure", err)
		assertBytesEqual(t, suite, "Incorrect decryption", original, decrypted)

		vectors[i] = encryptionTestVector{
			plaintext:  original,
			aad:        aad,
			ciphertext: encrypted,
		}
	}

	return vectors, nil
}

func generateTestVector(t *testing.T, setup setupMode, kemID KEMID, kdfID KDFID, aeadID AEADID) testVector {
	suite, err := AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kemID, kdfID, aeadID, err)
	}

	skR, pkR := mustGenerateKeyPair(t, suite)
	skI, pkI := mustGenerateKeyPair(t, suite)
	skE, pkE := mustGenerateKeyPair(t, suite)

	suite.KEM.setEphemeralKeyPair(skE)

	enc, ctxI, err := setup.I(suite, pkR, info, skI, psk, pskID)
	assertNotError(t, suite, "Error in SetupPSKI", err)

	ctxR, err := setup.R(suite, skR, enc, info, pkI, psk, pskID)
	assertNotError(t, suite, "Error in SetupPSKR", err)

	setupParams, contextParams := ctxI.parameters()
	key := make([]byte, len(contextParams.key))
	copy(key, contextParams.key)
	nonce := make([]byte, len(contextParams.nonce))
	copy(nonce, contextParams.nonce)

	encryptionVectors, err := generateEncryptions(t, suite, ctxI, ctxR)
	assertNotError(t, suite, "Error in generateEncryptions", err)

	vector := testVector{
		t:           t,
		suite:       suite,
		mode:        setup.Mode,
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

func TestVectorGenerate(t *testing.T) {
	// We only generate test vectors for select ciphersuites
	supportedKEMs := []KEMID{DHKEM_X25519, DHKEM_X448, DHKEM_P256, DHKEM_P521}
	supportedKDFs := []KDFID{KDF_HKDF_SHA256, KDF_HKDF_SHA512}
	supportedAEADs := []AEADID{AEAD_AESGCM128, AEAD_AESGCM256, AEAD_CHACHA20POLY1305}

	vectors := make([]testVector, 0)
	for _, kemID := range supportedKEMs {
		for _, kdfID := range supportedKDFs {
			for _, aeadID := range supportedAEADs {
				for _, setup := range setupModes {
					vectors = append(vectors, generateTestVector(t, setup, kemID, kdfID, aeadID))
				}
			}
		}
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyTestVectors(t, encoded, false)

	// Write them to a file if requested
	var outputFile string
	if outputFile = os.Getenv(outputTestVectorEnvironmentKey); len(outputFile) > 0 {
		err = ioutil.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerify(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyTestVectors(t, encoded, true)
}

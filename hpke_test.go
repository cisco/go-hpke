package hpke

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	fixedPSK = []byte{0x02, 0x47, 0xFD, 0x33, 0xB9, 0x13, 0x76, 0x0F,
		0xA1, 0xFA, 0x51, 0xE1, 0x89, 0x2D, 0x9F, 0x30,
		0x7F, 0xBE, 0x65, 0xEB, 0x17, 0x1E, 0x81, 0x32,
		0xC2, 0xAF, 0x18, 0x55, 0x5A, 0x73, 0x8B, 0x82} // 32 bytes
	fixedPSKID    = []byte("Ennyn Durin aran Moria")
	original      = []byte("Beauty is truth, truth beauty")
	aad           = []byte("that is all // Ye know on earth, and all ye need to know")
	info          = []byte("Ode on a Grecian Urn")
	rtts          = 10
	exportContext = []byte("test export")
	exportLength  = 32
)

const (
	outputTestVectorEnvironmentKey = "HPKE_TEST_VECTORS_OUT"
	inputTestVectorEnvironmentKey  = "HPKE_TEST_VECTORS_IN"
	testVectorEncryptionCount      = 257
	testVectorExportLength         = 32
)

///////
// Infallible Serialize / Deserialize
func mustUnhex(h string) []byte {
	out, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}

	return out
}

func mustHex(d []byte) string {
	return hex.EncodeToString(d)
}

func mustDeserializePriv(suite CipherSuite, h string, required bool) KEMPrivateKey {
	skm := mustUnhex(h)
	sk, err := suite.KEM.DeserializePrivateKey(skm)
	if required && err != nil {
		panic(err)
	}
	return sk
}

func mustSerializePriv(suite CipherSuite, priv KEMPrivateKey) string {
	return mustHex(suite.KEM.SerializePrivateKey(priv))
}

func mustDeserializePub(suite CipherSuite, h string, required bool) KEMPublicKey {
	pkm := mustUnhex(h)
	pk, err := suite.KEM.DeserializePublicKey(pkm)
	if required && err != nil {
		panic(err)
	}
	return pk
}

func mustSerializePub(suite CipherSuite, pub KEMPublicKey) string {
	return mustHex(suite.KEM.SerializePublicKey(pub))
}

func mustGenerateKeyPair(suite CipherSuite) (KEMPrivateKey, KEMPublicKey, []byte) {
	ikm := make([]byte, suite.KEM.PrivateKeySize())
	rand.Reader.Read(ikm)
	sk, pk, err := suite.KEM.DeriveKeyPair(ikm)
	if err != nil {
		panic(err)
	}
	return sk, pk, ikm
}

func verifyCipherContextEqual(t *testing.T, lhs, rhs context) {
	// Verify the serialized fields match.
	require.Equal(t, lhs.Role, rhs.Role)
	require.Equal(t, lhs.KEMID, rhs.KEMID)
	require.Equal(t, lhs.KDFID, rhs.KDFID)
	require.Equal(t, lhs.AEADID, rhs.AEADID)
	require.Equal(t, lhs.ExporterSecret, rhs.ExporterSecret)
	require.Equal(t, lhs.Key, rhs.Key)
	require.Equal(t, lhs.BaseNonce, rhs.BaseNonce)
	require.Equal(t, lhs.Seq, rhs.Seq)

	// Verify that the internal representation of the cipher suite matches.
	require.Equal(t, lhs.suite.KEM.ID(), rhs.suite.KEM.ID())
	require.Equal(t, lhs.suite.KDF.ID(), rhs.suite.KDF.ID())
	require.Equal(t, lhs.suite.AEAD.ID(), rhs.suite.AEAD.ID())

	if lhs.AEADID == AEAD_EXPORT_ONLY {
		return
	}

	// Verify that the internal AEAD object uses the same algorithm and is keyed
	// with the same key.
	got := lhs.aead.Seal(nil, lhs.BaseNonce, nil, nil)
	want := rhs.aead.Seal(nil, rhs.BaseNonce, nil, nil)
	require.Equal(t, got, want)
}

///////
// Symmetric encryption test vector structure
type encryptionTestVector struct {
	plaintext  []byte
	aad        []byte
	nonce      []byte
	ciphertext []byte
}

func (etv encryptionTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"plaintext":  mustHex(etv.plaintext),
		"aad":        mustHex(etv.aad),
		"nonce":      mustHex(etv.nonce),
		"ciphertext": mustHex(etv.ciphertext),
	})
}

func (etv *encryptionTestVector) UnmarshalJSON(data []byte) error {
	raw := map[string]string{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.plaintext = mustUnhex(raw["plaintext"])
	etv.aad = mustUnhex(raw["aad"])
	etv.nonce = mustUnhex(raw["nonce"])
	etv.ciphertext = mustUnhex(raw["ciphertext"])
	return nil
}

///////
// Exporter test vector structures
type rawExporterTestVector struct {
	ExportContext string `json:"exporter_context"`
	ExportLength  int    `json:"L"`
	ExportValue   string `json:"exported_value"`
}

type exporterTestVector struct {
	exportContext []byte
	exportLength  int
	exportValue   []byte
}

func (etv exporterTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawExporterTestVector{
		ExportContext: mustHex(etv.exportContext),
		ExportLength:  etv.exportLength,
		ExportValue:   mustHex(etv.exportValue),
	})
}

func (etv *exporterTestVector) UnmarshalJSON(data []byte) error {
	raw := rawExporterTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.exportContext = mustUnhex(raw.ExportContext)
	etv.exportLength = raw.ExportLength
	etv.exportValue = mustUnhex(raw.ExportValue)
	return nil
}

///////
// HPKE test vector structures
type rawTestVector struct {
	// Parameters
	Mode   Mode   `json:"mode"`
	KEMID  KEMID  `json:"kem_id"`
	KDFID  KDFID  `json:"kdf_id"`
	AEADID AEADID `json:"aead_id"`
	Info   string `json:"info"`

	// Private keys
	IKMR  string `json:"ikmR"`
	IKMS  string `json:"ikmS,omitempty"`
	IKME  string `json:"ikmE"`
	SKR   string `json:"skRm"`
	SKS   string `json:"skSm,omitempty"`
	SKE   string `json:"skEm"`
	PSK   string `json:"psk,omitempty"`
	PSKID string `json:"psk_id,omitempty"`

	// Public keys
	PKR string `json:"pkRm"`
	PKS string `json:"pkSm,omitempty"`
	PKE string `json:"pkEm"`

	// Key schedule inputs and computations
	Enc                string `json:"enc"`
	SharedSecret       string `json:"shared_secret"`
	KeyScheduleContext string `json:"key_schedule_context"`
	Secret             string `json:"secret"`
	Key                string `json:"key"`
	BaseNonce          string `json:"base_nonce"`
	ExporterSecret     string `json:"exporter_secret"`

	Encryptions []encryptionTestVector `json:"encryptions"`
	Exports     []exporterTestVector   `json:"exports"`
}

type testVector struct {
	t     *testing.T
	suite CipherSuite

	// Parameters
	mode    Mode
	kem_id  KEMID
	kdf_id  KDFID
	aead_id AEADID
	info    []byte

	// Private keys
	skR    KEMPrivateKey
	skS    KEMPrivateKey
	skE    KEMPrivateKey
	ikmR   []byte
	ikmS   []byte
	ikmE   []byte
	psk    []byte
	psk_id []byte

	// Public keys
	pkR KEMPublicKey
	pkS KEMPublicKey
	pkE KEMPublicKey

	// Key schedule inputs and computations
	enc                []byte
	sharedSecret       []byte
	keyScheduleContext []byte
	secret             []byte
	key                []byte
	baseNonce          []byte
	exporterSecret     []byte

	encryptions []encryptionTestVector
	exports     []exporterTestVector
}

func (tv testVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawTestVector{
		Mode:   tv.mode,
		KEMID:  tv.kem_id,
		KDFID:  tv.kdf_id,
		AEADID: tv.aead_id,
		Info:   mustHex(tv.info),

		IKMR:  mustHex(tv.ikmR),
		IKMS:  mustHex(tv.ikmS),
		IKME:  mustHex(tv.ikmE),
		SKR:   mustSerializePriv(tv.suite, tv.skR),
		SKS:   mustSerializePriv(tv.suite, tv.skS),
		SKE:   mustSerializePriv(tv.suite, tv.skE),
		PSK:   mustHex(tv.psk),
		PSKID: mustHex(tv.psk_id),

		PKR: mustSerializePub(tv.suite, tv.pkR),
		PKS: mustSerializePub(tv.suite, tv.pkS),
		PKE: mustSerializePub(tv.suite, tv.pkE),

		Enc:                mustHex(tv.enc),
		SharedSecret:       mustHex(tv.sharedSecret),
		KeyScheduleContext: mustHex(tv.keyScheduleContext),
		Secret:             mustHex(tv.secret),
		Key:                mustHex(tv.key),
		BaseNonce:          mustHex(tv.baseNonce),
		ExporterSecret:     mustHex(tv.exporterSecret),

		Encryptions: tv.encryptions,
		Exports:     tv.exports,
	})
}

func (tv *testVector) UnmarshalJSON(data []byte) error {
	raw := rawTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	tv.mode = raw.Mode
	tv.kem_id = raw.KEMID
	tv.kdf_id = raw.KDFID
	tv.aead_id = raw.AEADID
	tv.info = mustUnhex(raw.Info)

	tv.suite, err = AssembleCipherSuite(raw.KEMID, raw.KDFID, raw.AEADID)
	if err != nil {
		return err
	}

	modeRequiresSenderKey := (tv.mode == modeAuth || tv.mode == modeAuthPSK)
	tv.skR = mustDeserializePriv(tv.suite, raw.SKR, true)
	tv.skS = mustDeserializePriv(tv.suite, raw.SKS, modeRequiresSenderKey)
	tv.skE = mustDeserializePriv(tv.suite, raw.SKE, true)

	tv.pkR = mustDeserializePub(tv.suite, raw.PKR, true)
	tv.pkS = mustDeserializePub(tv.suite, raw.PKS, modeRequiresSenderKey)
	tv.pkE = mustDeserializePub(tv.suite, raw.PKE, true)

	tv.psk = mustUnhex(raw.PSK)
	tv.psk_id = mustUnhex(raw.PSKID)

	tv.ikmR = mustUnhex(raw.IKMR)
	tv.ikmS = mustUnhex(raw.IKMS)
	tv.ikmE = mustUnhex(raw.IKME)

	tv.enc = mustUnhex(raw.Enc)
	tv.sharedSecret = mustUnhex(raw.SharedSecret)
	tv.keyScheduleContext = mustUnhex(raw.KeyScheduleContext)
	tv.secret = mustUnhex(raw.Secret)
	tv.key = mustUnhex(raw.Key)
	tv.baseNonce = mustUnhex(raw.BaseNonce)
	tv.exporterSecret = mustUnhex(raw.ExporterSecret)

	tv.encryptions = raw.Encryptions
	tv.exports = raw.Exports
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
	Mode Mode
	OK   func(suite CipherSuite) bool
	I    func(suite CipherSuite, pkR KEMPublicKey, info []byte, skS KEMPrivateKey, psk, psk_id []byte) ([]byte, *SenderContext, error)
	R    func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkS KEMPublicKey, psk, psk_id []byte) (*ReceiverContext, error)
}

var setupModes = map[Mode]setupMode{
	modeBase: {
		Mode: modeBase,
		OK:   func(suite CipherSuite) bool { return true },
		I: func(suite CipherSuite, pkR KEMPublicKey, info []byte, skS KEMPrivateKey, psk, psk_id []byte) ([]byte, *SenderContext, error) {
			return SetupBaseS(suite, rand.Reader, pkR, info)
		},
		R: func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkS KEMPublicKey, psk, psk_id []byte) (*ReceiverContext, error) {
			return SetupBaseR(suite, skR, enc, info)
		},
	},
	modePSK: {
		Mode: modePSK,
		OK:   func(suite CipherSuite) bool { return true },
		I: func(suite CipherSuite, pkR KEMPublicKey, info []byte, skS KEMPrivateKey, psk, psk_id []byte) ([]byte, *SenderContext, error) {
			return SetupPSKS(suite, rand.Reader, pkR, psk, psk_id, info)
		},
		R: func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkS KEMPublicKey, psk, psk_id []byte) (*ReceiverContext, error) {
			return SetupPSKR(suite, skR, enc, psk, psk_id, info)
		},
	},
	modeAuth: {
		Mode: modeAuth,
		OK: func(suite CipherSuite) bool {
			_, ok := suite.KEM.(AuthKEMScheme)
			return ok
		},
		I: func(suite CipherSuite, pkR KEMPublicKey, info []byte, skS KEMPrivateKey, psk, psk_id []byte) ([]byte, *SenderContext, error) {
			return SetupAuthS(suite, rand.Reader, pkR, skS, info)
		},
		R: func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkS KEMPublicKey, psk, psk_id []byte) (*ReceiverContext, error) {
			return SetupAuthR(suite, skR, pkS, enc, info)
		},
	},
	modeAuthPSK: {
		Mode: modeAuthPSK,
		OK: func(suite CipherSuite) bool {
			_, ok := suite.KEM.(AuthKEMScheme)
			return ok
		},
		I: func(suite CipherSuite, pkR KEMPublicKey, info []byte, skS KEMPrivateKey, psk, psk_id []byte) ([]byte, *SenderContext, error) {
			return SetupAuthPSKS(suite, rand.Reader, pkR, skS, psk, psk_id, info)
		},
		R: func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkS KEMPublicKey, psk, psk_id []byte) (*ReceiverContext, error) {
			return SetupAuthPSKR(suite, skR, pkS, enc, psk, psk_id, info)
		},
	},
}

///////
// Direct tests

type roundTripTest struct {
	kem_id  KEMID
	kdf_id  KDFID
	aead_id AEADID
	setup   setupMode
}

func (rtt roundTripTest) Test(t *testing.T) {
	suite, err := AssembleCipherSuite(rtt.kem_id, rtt.kdf_id, rtt.aead_id)
	require.Nil(t, err)

	if !rtt.setup.OK(suite) {
		return
	}

	skS, pkS, _ := mustGenerateKeyPair(suite)
	skR, pkR, _ := mustGenerateKeyPair(suite)

	enc, ctxS, err := rtt.setup.I(suite, pkR, info, skS, fixedPSK, fixedPSKID)
	require.Nil(t, err)

	ctxR, err := rtt.setup.R(suite, skR, enc, info, pkS, fixedPSK, fixedPSKID)
	require.Nil(t, err)

	// Verify encryption functionality, if applicable
	if rtt.aead_id != AEAD_EXPORT_ONLY {
		for range make([]struct{}, rtts) {
			encrypted := ctxS.Seal(aad, original)
			decrypted, err := ctxR.Open(aad, encrypted)
			require.Nil(t, err)
			require.Equal(t, decrypted, original)
		}
	}

	// Verify exporter functionality
	exportedS := ctxS.Export(exportContext, exportLength)
	exportedR := ctxR.Export(exportContext, exportLength)
	require.Equal(t, exportedS, exportedR)

	// Verify encryption context serialization functionality
	opaqueS, err := ctxS.Marshal()
	require.Nil(t, err)

	unmarshaledS, err := UnmarshalSenderContext(opaqueS)
	require.Nil(t, err)

	verifyCipherContextEqual(t, ctxS.context, unmarshaledS.context)

	// Verify decryption context serialization functionality
	opaqueR, err := ctxR.Marshal()
	require.Nil(t, err)

	unmarshaledR, err := UnmarshalReceiverContext(opaqueR)
	require.Nil(t, err)

	verifyCipherContextEqual(t, ctxR.context, unmarshaledR.context)

	// Verify exporter functionality for a deserialized context
	require.Equal(t, exportedS, unmarshaledS.Export(exportContext, exportLength))
	require.Equal(t, exportedR, unmarshaledR.Export(exportContext, exportLength))
}

func TestModes(t *testing.T) {
	for kem_id, _ := range kems {
		for kdf_id, _ := range kdfs {
			for aead_id, _ := range aeads {
				for mode, setup := range setupModes {
					label := fmt.Sprintf("kem=%04x/kdf=%04x/aead=%04x/mode=%02x", kem_id, kdf_id, aead_id, mode)
					rtt := roundTripTest{kem_id, kdf_id, aead_id, setup}
					t.Run(label, rtt.Test)
				}
			}
		}
	}
}

///////
// Generation and processing of test vectors

func verifyEncryptions(tv testVector, enc *SenderContext, dec *ReceiverContext) {
	for _, data := range tv.encryptions {
		encrypted := enc.Seal(data.aad, data.plaintext)
		decrypted, err := dec.Open(data.aad, encrypted)
		require.Nil(tv.t, err)

		require.Equal(tv.t, encrypted, data.ciphertext)
		require.Equal(tv.t, decrypted, data.plaintext)
	}
}

func verifyParameters(tv testVector, ctx context) {
	require.Equal(tv.t, tv.sharedSecret, ctx.setupParams.sharedSecret)
	require.Equal(tv.t, tv.enc, ctx.setupParams.enc)
	require.Equal(tv.t, tv.keyScheduleContext, ctx.contextParams.keyScheduleContext)
	require.Equal(tv.t, tv.secret, ctx.contextParams.secret)
	require.Equal(tv.t, tv.key, ctx.Key)
	require.Equal(tv.t, tv.baseNonce, ctx.BaseNonce)
	require.Equal(tv.t, tv.exporterSecret, ctx.ExporterSecret)
}

func verifyPublicKeysEqual(tv testVector, pkX, pkY KEMPublicKey) {
	pkXm := mustSerializePub(tv.suite, pkX)
	pkYm := mustSerializePub(tv.suite, pkY)
	require.Equal(tv.t, []byte(pkXm), []byte(pkYm))
}

func verifyPrivateKeysEqual(tv testVector, skX, skY KEMPrivateKey) {
	skXm := mustSerializePriv(tv.suite, skX)
	skYm := mustSerializePriv(tv.suite, skY)
	require.Equal(tv.t, []byte(skXm), []byte(skYm))
}

func verifyTestVector(tv testVector) {
	setup := setupModes[tv.mode]

	skR, pkR, err := tv.suite.KEM.DeriveKeyPair(tv.ikmR)
	require.Nil(tv.t, err)
	verifyPublicKeysEqual(tv, tv.pkR, pkR)
	verifyPrivateKeysEqual(tv, tv.skR, skR)

	skE, pkE, err := tv.suite.KEM.DeriveKeyPair(tv.ikmE)
	require.Nil(tv.t, err)
	verifyPublicKeysEqual(tv, tv.pkE, pkE)
	verifyPrivateKeysEqual(tv, tv.skE, skE)

	tv.suite.KEM.setEphemeralKeyPair(skE)

	var pkS KEMPublicKey
	var skS KEMPrivateKey
	if setup.Mode == modeAuth || setup.Mode == modeAuthPSK {
		skS, pkS, err = tv.suite.KEM.DeriveKeyPair(tv.ikmS)
		require.Nil(tv.t, err)
		verifyPublicKeysEqual(tv, tv.pkS, pkS)
		verifyPrivateKeysEqual(tv, tv.skS, skS)
	}

	enc, ctxS, err := setup.I(tv.suite, pkR, tv.info, skS, tv.psk, tv.psk_id)
	require.Nil(tv.t, err)
	require.Equal(tv.t, enc, tv.enc)

	ctxR, err := setup.R(tv.suite, skR, tv.enc, tv.info, pkS, tv.psk, tv.psk_id)
	require.Nil(tv.t, err)

	verifyParameters(tv, ctxS.context)
	verifyParameters(tv, ctxR.context)

	verifyEncryptions(tv, ctxS, ctxR)
}

func vectorTest(vector testVector) func(t *testing.T) {
	return func(t *testing.T) {
		verifyTestVector(vector)
	}
}

func verifyTestVectors(t *testing.T, vectorString []byte, subtest bool) {
	vectors := testVectorArray{t: t}
	err := json.Unmarshal(vectorString, &vectors)
	require.Nil(t, err)

	for _, tv := range vectors.vectors {
		test := vectorTest(tv)
		if !subtest {
			test(t)
		} else {
			label := fmt.Sprintf("kem=%04x/kdf=%04x/aead=%04x/mode=%02x", tv.kem_id, tv.kdf_id, tv.aead_id, tv.mode)
			t.Run(label, test)
		}
	}
}

func generateEncryptions(t *testing.T, suite CipherSuite, ctxS *SenderContext, ctxR *ReceiverContext) ([]encryptionTestVector, error) {
	vectors := make([]encryptionTestVector, testVectorEncryptionCount)
	for i := 0; i < len(vectors); i++ {
		aad := []byte(fmt.Sprintf("Count-%d", i))
		encrypted := ctxS.Seal(aad, original)
		decrypted, err := ctxR.Open(aad, encrypted)
		require.Nil(t, err)
		require.Equal(t, original, decrypted)

		vectors[i] = encryptionTestVector{
			plaintext:  original,
			aad:        aad,
			nonce:      ctxS.nonces[i],
			ciphertext: encrypted,
		}
	}

	return vectors, nil
}

func generateExports(t *testing.T, suite CipherSuite, ctxS *SenderContext, ctxR *ReceiverContext) ([]exporterTestVector, error) {
	exportContexts := [][]byte{
		[]byte(""),
		[]byte{0x00},
		[]byte("TestContext"),
	}
	vectors := make([]exporterTestVector, len(exportContexts))
	for i := 0; i < len(vectors); i++ {
		exportS := ctxS.Export(exportContexts[i], testVectorExportLength)
		exportR := ctxR.Export(exportContexts[i], testVectorExportLength)
		require.Equal(t, exportS, exportR)

		vectors[i] = exporterTestVector{
			exportContext: exportContexts[i],
			exportLength:  testVectorExportLength,
			exportValue:   exportS,
		}
	}

	return vectors, nil
}

func generateTestVector(t *testing.T, setup setupMode, kem_id KEMID, kdf_id KDFID, aead_id AEADID) testVector {
	suite, err := AssembleCipherSuite(kem_id, kdf_id, aead_id)
	require.Nil(t, err)

	skR, pkR, ikmR := mustGenerateKeyPair(suite)
	skE, pkE, ikmE := mustGenerateKeyPair(suite)

	// The sender key share is only required for Auth mode variants.
	var pkS KEMPublicKey
	var skS KEMPrivateKey
	var ikmS []byte
	if setup.Mode == modeAuth || setup.Mode == modeAuthPSK {
		skS, pkS, ikmS = mustGenerateKeyPair(suite)
	}

	// A PSK is only required for PSK mode variants.
	var psk []byte
	var psk_id []byte
	if setup.Mode == modePSK || setup.Mode == modeAuthPSK {
		psk = fixedPSK
		psk_id = fixedPSKID
	}

	suite.KEM.setEphemeralKeyPair(skE)

	enc, ctxS, err := setup.I(suite, pkR, info, skS, psk, psk_id)
	require.Nil(t, err)

	ctxR, err := setup.R(suite, skR, enc, info, pkS, psk, psk_id)
	require.Nil(t, err)

	encryptionVectors := []encryptionTestVector{}
	if aead_id != AEAD_EXPORT_ONLY {
		encryptionVectors, err = generateEncryptions(t, suite, ctxS, ctxR)
		require.Nil(t, err)
	}

	exportVectors, err := generateExports(t, suite, ctxS, ctxR)
	require.Nil(t, err)

	vector := testVector{
		t:                  t,
		suite:              suite,
		mode:               setup.Mode,
		kem_id:             kem_id,
		kdf_id:             kdf_id,
		aead_id:            aead_id,
		info:               info,
		skR:                skR,
		pkR:                pkR,
		skS:                skS,
		pkS:                pkS,
		skE:                skE,
		pkE:                pkE,
		ikmR:               ikmR,
		ikmS:               ikmS,
		ikmE:               ikmE,
		psk:                psk,
		psk_id:             psk_id,
		enc:                ctxS.setupParams.enc,
		sharedSecret:       ctxS.setupParams.sharedSecret,
		keyScheduleContext: ctxS.contextParams.keyScheduleContext,
		secret:             ctxS.contextParams.secret,
		key:                ctxS.Key,
		baseNonce:          ctxS.BaseNonce,
		exporterSecret:     ctxS.ExporterSecret,
		encryptions:        encryptionVectors,
		exports:            exportVectors,
	}

	return vector
}

func TestVectorGenerate(t *testing.T) {
	// We only generate test vectors for select ciphersuites
	supportedKEMs := []KEMID{DHKEM_X25519, DHKEM_X448, DHKEM_P256, DHKEM_P521}
	supportedKDFs := []KDFID{KDF_HKDF_SHA256, KDF_HKDF_SHA512}
	supportedAEADs := []AEADID{AEAD_AESGCM128, AEAD_AESGCM256, AEAD_CHACHA20POLY1305, AEAD_EXPORT_ONLY}

	vectors := make([]testVector, 0)
	for _, kem_id := range supportedKEMs {
		for _, kdf_id := range supportedKDFs {
			for _, aead_id := range supportedAEADs {
				for _, setup := range setupModes {
					vectors = append(vectors, generateTestVector(t, setup, kem_id, kdf_id, aead_id))
				}
			}
		}
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	require.Nil(t, err)

	// Verify that we process them correctly
	verifyTestVectors(t, encoded, false)

	// Write them to a file if requested
	var outputFile string
	if outputFile = os.Getenv(outputTestVectorEnvironmentKey); len(outputFile) > 0 {
		err = ioutil.WriteFile(outputFile, encoded, 0644)
		require.Nil(t, err)
	}
}

func TestVectorVerify(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	require.Nil(t, err)

	verifyTestVectors(t, encoded, true)
}

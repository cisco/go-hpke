package hpke

import (
	"bytes"
	"crypto/rand"
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

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
)

func roundTrip(t *testing.T, id uint16, enc *Context, dec *Context) {
	encrypted := enc.Seal(aad, original)
	decrypted, err := dec.Open(aad, encrypted)
	if err != nil {
		t.Fatalf("[%d] Error in Open: %s", id, err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Fatalf("[%d] Incorrect decryption: [%x] != [%x]", id, decrypted, original)
	}
}

func TestBase(t *testing.T) {
	for id, suite := range ciphersuites {
		skR, pkR, err := suite.KEM.Generate(rand.Reader)
		if err != nil {
			t.Fatalf("[%d] Error generating DH key pair: %s", id, err)
		}

		enc, ctxI, err := SetupIBase(suite, rand.Reader, pkR, info)
		if err != nil {
			t.Fatalf("[%d] Error in SetupIBase: %s", id, err)
		}

		ctxR, err := SetupRBase(suite, skR, enc, info)
		if err != nil {
			t.Fatalf("[%d] Error in SetupIBase: %s", id, err)
		}

		roundTrip(t, id, ctxI, ctxR)
	}
}

func TestPSK(t *testing.T) {
	for id, suite := range ciphersuites {
		skR, pkR, err := suite.KEM.Generate(rand.Reader)
		if err != nil {
			t.Fatalf("[%d] Error generating DH key pair: %s", id, err)
		}

		enc, ctxI, err := SetupIPSK(suite, rand.Reader, pkR, psk, pskID, info)
		if err != nil {
			t.Fatalf("[%d] Error in SetupIPSK: %s", id, err)
		}

		ctxR, err := SetupRPSK(suite, skR, enc, psk, pskID, info)
		if err != nil {
			t.Fatalf("[%d] Error in SetupIBase: %s", id, err)
		}

		roundTrip(t, id, ctxI, ctxR)
	}
}

func TestAuth(t *testing.T) {
	for id, suite := range ciphersuites {
		skI, pkI, err := suite.KEM.Generate(rand.Reader)
		if err != nil {
			t.Fatalf("[%d] Error generating initiator DH key pair: %s", id, err)
		}

		skR, pkR, err := suite.KEM.Generate(rand.Reader)
		if err != nil {
			t.Fatalf("[%d] Error generating responder DH key pair: %s", id, err)
		}

		enc, ctxI, err := SetupIAuth(suite, rand.Reader, pkR, skI, info)
		if err != nil {
			t.Fatalf("[%d] Error in SetupIAuth: %s", id, err)
		}

		ctxR, err := SetupRAuth(suite, skR, pkI, enc, info)
		if err != nil {
			t.Fatalf("[%d] Error in SetupIBase: %s", id, err)
		}

		roundTrip(t, id, ctxI, ctxR)
	}
}

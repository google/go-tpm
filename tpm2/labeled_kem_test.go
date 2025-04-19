package tpm2

// Note: this unit test is in the tpm2 package instead of in the tpm2test package.
// This is to allow calling encapsulateDerandomized from the test without exporting it.

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2/test/testvectors"
)

func TestECCLabeledEncapsulation(t *testing.T) {
	for _, testcase := range testvectors.ECCLabeledEncapsulation(t) {
		t.Run(testcase.Name, func(t *testing.T) {
			pub, err := Unmarshal[TPMTPublic](testcase.PublicKey)
			if err != nil {
				t.Fatalf("Unmarshal() = %v", err)
			}
			encapsPub, err := importECCEncapsulationKey(pub)
			if err != nil {
				t.Fatalf("importECCEncapsulationKey() = %v", err)
			}
			ephPriv, err := encapsPub.eccPub.Curve().NewPrivateKey(testcase.EphemeralPrivate)
			if err != nil {
				t.Fatalf("NewPrivateKey() = %v", err)
			}
			secret, ciphertext, err := encapsPub.encapsulateDerandomized(ephPriv, testcase.Label)
			if err != nil {
				t.Fatalf("encapsulateDerandomized() = %v", err)
			}

			if !bytes.Equal(testcase.Secret, secret) {
				t.Errorf("want %x got %x", testcase.Secret, secret)
			}
			if !bytes.Equal(testcase.Ciphertext, ciphertext) {
				t.Errorf("want %x got %x", testcase.Ciphertext, ciphertext)
			}
		})
	}
}

func TestRSALabeledEncapsulation(t *testing.T) {
	for _, testcase := range testvectors.RSALabeledEncapsulation(t) {
		t.Run(testcase.Name, func(t *testing.T) {
			pub, err := Unmarshal[TPMTPublic](testcase.PublicKey)
			if err != nil {
				t.Fatalf("Unmarshal() = %v", err)
			}
			encapsPub, err := importRSAEncapsulationKey(pub)
			if err != nil {
				t.Fatalf("importRSAEncapsulationKey() = %v", err)
			}

			ciphertext, err := encapsPub.encapsulateDerandomized(bytes.NewReader(testcase.OAEPSalt), testcase.Secret, testcase.Label)
			if err != nil {
				t.Fatalf("Encapsulate() = %v", err)
			}

			if !bytes.Equal(testcase.Ciphertext, ciphertext) {
				t.Errorf("want %x got %x", testcase.Ciphertext, ciphertext)
			}
		})
	}
}

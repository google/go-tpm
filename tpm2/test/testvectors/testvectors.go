// Package testvectors contains test vectors for TPM crypto.
package testvectors

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// This package contains test vectors from https://github.com/chrisfenner/tpm-test-vectors.
// These test vectors were validated against the TCG Reference Implementation.

type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(data []byte) error {
	var err error
	*h, err = hex.DecodeString(strings.Trim(string(data), "\""))
	return err
}

//go:embed ecc_labeled_encaps.json
var eccLabeledEncapsJSON []byte

// ECCLabeledEncapsTestCase is a test case for ECC Labeled Encapsulation (Secret Sharing).
type ECCLabeledEncapsTestCase struct {
	Name             string
	Description      string
	Label            string
	EphemeralPrivate hexBytes
	PublicKey        hexBytes
	Secret           hexBytes
	Ciphertext       hexBytes
}

// ECCLabeledEncapsulation iterates the ECC Labeled Encapsulation test cases.
func ECCLabeledEncapsulation(t *testing.T) []ECCLabeledEncapsTestCase {
	t.Helper()

	var testCases []ECCLabeledEncapsTestCase
	if err := json.Unmarshal(eccLabeledEncapsJSON, &testCases); err != nil {
		t.Fatalf("could not unmarshal JSON: %v", err)
	}

	return testCases
}

//go:embed rsa_labeled_encaps.json
var rsaLabeledEncapsJSON []byte

// RSALabeledEncapsTestCase is a test case for ECC Labeled Encapsulation (Secret Sharing).
type RSALabeledEncapsTestCase struct {
	Name        string
	Description string
	Label       string
	OAEPSalt    hexBytes
	PublicKey   hexBytes
	Secret      hexBytes
	Ciphertext  hexBytes
}

// RSALabeledEncapsulation iterates the ECC Labeled Encapsulation test cases.
func RSALabeledEncapsulation(t *testing.T) []RSALabeledEncapsTestCase {
	t.Helper()

	var testCases []RSALabeledEncapsTestCase
	if err := json.Unmarshal(rsaLabeledEncapsJSON, &testCases); err != nil {
		t.Fatalf("could not unmarshal JSON: %v", err)
	}

	return testCases
}

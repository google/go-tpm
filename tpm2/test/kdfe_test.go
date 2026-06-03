package tpm2test

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/test/testvectors"
)

func TestKDFe(t *testing.T) {
	for _, testcase := range testvectors.KDFe(t) {
		h, err := tpm2.TPMIAlgHash(testcase.HashAlg).Hash()
		if err != nil {
			t.Fatalf("%v", err)
		}
		t.Run(testcase.Name, func(t *testing.T) {
			result := tpm2.KDFe(h, testcase.Z, testcase.Label, testcase.ContextU, testcase.ContextV, testcase.Bits)
			if !bytes.Equal(result, testcase.Result) {
				t.Errorf("KDFe() = %x\nwant %x", result, testcase.Result)
			}
		})
	}
}

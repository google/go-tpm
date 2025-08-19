package tpm2test

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/test/testvectors"
)

func TestKDFa(t *testing.T) {
	for _, testcase := range testvectors.KDFa(t) {
		h, err := tpm2.TPMIAlgHash(testcase.HashAlg).Hash()
		if err != nil {
			t.Fatalf("%v", err)
		}
		t.Run(testcase.Name, func(t *testing.T) {
			result := tpm2.KDFa(h, testcase.Key, testcase.Label, testcase.ContextU, testcase.ContextV, testcase.Bits)
			if !bytes.Equal(result, testcase.Result) {
				t.Errorf("KDFa() = %x\nwant %x", result, testcase.Result)
			}
		})
	}
}

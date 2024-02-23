package tpm2_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestTPMTPublicCopy(t *testing.T) {
	testCases := []struct {
		name           string
		src            tpm2.TPMTPublic
		expErr         error
		expPanicOnCopy bool
	}{
		{
			name:           "Panic on empty TPMTPublic object",
			expPanicOnCopy: true,
			expErr:         fmt.Errorf("unexpected error marshalling TPMTPublic: no union member for tag 0"),
		},
		{
			name: "RSA EK template",
			src:  tpm2.RSAEKTemplate,
		},
		{
			name: "ECC EK template",
			src:  tpm2.ECCEKTemplate,
		},
		{
			name: "RSA EK",
			src:  rsaEKWithPubKey(ekRSAPubKey),
		},
		{
			name: "ECC EK",
			src:  eccEKWithPoint(ekECCPointX, ekECCPointY),
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(t *testing.T) {
			if tc.expPanicOnCopy {
				defer func() {
					if r := recover(); r != nil {
						actErr := fmt.Errorf(r.(string))
						assertExpectedError(t, true, actErr, tc.expErr)
					}
				}()
			}
			dst, err := tpm2.Copy(tc.src)
			if !tc.expPanicOnCopy {
				if !assertExpectedError(t, true, err, tc.expErr) {
					return
				}
			}

			srcData := tpm2.Marshal(tc.src)
			dstData := tpm2.Marshal(dst)

			if !bytes.Equal(srcData, dstData) {
				t.Fatal("src and dst are not equal")
			}
		})
	}
}

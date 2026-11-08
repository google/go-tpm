package tpm2

import (
	"strings"
	"testing"
)

func attestWithMagic(magic TPMGenerated) []byte {
	return Marshal(TPMSAttest{
		Magic: magic,
		Type:  TPMSTAttestQuote,
		Attested: NewTPMUAttest(TPMSTAttestQuote, &TPMSQuoteInfo{
			PCRDigest: TPM2BDigest{Buffer: make([]byte, 32)},
		}),
	})
}

// TestUnmarshalAttestChecksMagic checks that the `gotpm:"check"` tag on
// TPMSAttest.Magic is enforced, so an attestation that was not produced by a
// TPM (Magic != TPM_GENERATED_VALUE) is rejected when parsed.
func TestUnmarshalAttestChecksMagic(t *testing.T) {
	for _, magic := range []TPMGenerated{0, 0xdeadbeef, 0x47ff5443} {
		blob := attestWithMagic(magic)
		if _, err := Unmarshal[TPMSAttest](blob); err == nil || !strings.Contains(err.Error(), "TPM_GENERATED") {
			t.Errorf("Unmarshal(Magic=0x%08x) error = %v, want TPM_GENERATED check failure", uint32(magic), err)
		}
		attest := BytesAs2B[TPMSAttest](blob)
		if _, err := attest.Contents(); err == nil {
			t.Errorf("TPM2BAttest.Contents() accepted Magic=0x%08x", uint32(magic))
		}
	}

	got, err := Unmarshal[TPMSAttest](attestWithMagic(TPMGeneratedValue))
	if err != nil {
		t.Fatalf("Unmarshal(Magic=TPM_GENERATED_VALUE) = %v", err)
	}
	if got.Magic != TPMGeneratedValue {
		t.Errorf("Magic = 0x%08x, want 0x%08x", uint32(got.Magic), uint32(TPMGeneratedValue))
	}
}

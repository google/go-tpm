package tpm2

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpml"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	"github.com/google/go-tpm/direct/transport/simulator"
)

var extendsDirect = map[tpm.AlgID][]struct {
	digest []byte
}{
	tpm.AlgSHA1: {
		{bytes.Repeat([]byte{0x00}, sha1.Size)},
		{bytes.Repeat([]byte{0x01}, sha1.Size)},
		{bytes.Repeat([]byte{0x02}, sha1.Size)}},
	tpm.AlgSHA256: {
		{bytes.Repeat([]byte{0x00}, sha256.Size)},
		{bytes.Repeat([]byte{0x01}, sha256.Size)},
		{bytes.Repeat([]byte{0x02}, sha256.Size)}},
	tpm.AlgSHA384: {
		{bytes.Repeat([]byte{0x00}, sha512.Size384)},
		{bytes.Repeat([]byte{0x01}, sha512.Size384)},
		{bytes.Repeat([]byte{0x02}, sha512.Size384)}},
}

func allZero(s []byte) bool {
    for _, v := range s {
        if v != 0 {
            return false
        }
    }
    return true
}

func TestPCRReset(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	DebugPCR := 16

	cases := []struct {
		name    string
		hashalg tpm.AlgID
	}{
		{"SHA1", tpm.AlgSHA1},
		{"SHA256", tpm.AlgSHA256},
		{"SHA384", tpm.AlgSHA384},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			PCRs, err := CreatePCRSelection([]int{DebugPCR})
			if err != nil {
				t.Fatalf("Failed to create PCRSelection")
			}

			authHandle := AuthHandle{
				Handle: tpm.Handle(DebugPCR),
				Auth:   PasswordAuth(nil),
			}

			pcrRead := PCRRead{
				PCRSelectionIn: tpml.PCRSelection{
					PCRSelections: []tpms.PCRSelection{
						{
							Hash:      c.hashalg,
							PCRSelect: PCRs,
						},
					},
				},
			}

			// Extending PCR 16
			for _, d := range extendsDirect[c.hashalg] {
				pcrExtend := PCRExtend{
					PCRHandle: authHandle,
					Digests: tpml.DigestValues{
						Digests: []tpmt.HA{
							{
								HashAlg: c.hashalg,
								Digest:  d.digest,
							},
						},
					},
				}
				if err := pcrExtend.Execute(thetpm); err != nil {
					t.Fatalf("failed to extend pcr for test %v", err)
				}
			}

			pcrReadRsp, err := pcrRead.Execute(thetpm)
			if err != nil {
				t.Fatalf("failed to read PCRs")
			}
			postExtendPCR16 := pcrReadRsp.PCRValues.Digests[0].Buffer
			if allZero(postExtendPCR16) {
				t.Errorf("postExtendPCR16 not expected to be all Zero: %v", postExtendPCR16)
			}

			// Resetting PCR 16
			pcrReset := PCRReset{
				PCRHandle: authHandle,
			}
			if _, err := pcrReset.Execute(thetpm); err != nil {
				t.Fatalf("pcrReset failed: %v", err)
			}
			if pcrReadRsp, err = pcrRead.Execute(thetpm); err != nil {
				t.Fatalf("failed to read PCRs")
			}
			postResetPCR16 := pcrReadRsp.PCRValues.Digests[0].Buffer

			if !allZero(postResetPCR16) {
				t.Errorf("postResetPCR16 expected to be all Zero: %v", postExtendPCR16)
			}
		})
	}
}

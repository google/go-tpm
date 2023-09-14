package tpm2test

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestPCRs(t *testing.T) {
	for i, tc := range []struct {
		pcrs       []uint
		wantSelect []byte
	}{
		{
			pcrs:       nil,
			wantSelect: []byte{0x00, 0x00, 0x00},
		},
		{
			pcrs:       []uint{0},
			wantSelect: []byte{0x01, 0x00, 0x00},
		},
		{
			pcrs:       []uint{0, 1, 2},
			wantSelect: []byte{0x07, 0x00, 0x00},
		},
		{
			pcrs:       []uint{0, 7},
			wantSelect: []byte{0x81, 0x00, 0x00},
		},
		{
			pcrs:       []uint{8},
			wantSelect: []byte{0x00, 0x01, 0x00},
		},
		{
			pcrs:       []uint{1, 8, 9},
			wantSelect: []byte{0x02, 0x03, 0x00},
		},
		{
			pcrs:       []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
			wantSelect: []byte{0xff, 0xff, 0xff},
		},
		{
			pcrs: []uint{255},
			wantSelect: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80},
		},
	} {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			selection := PCClientCompatible.PCRs(tc.pcrs...)
			if !bytes.Equal(selection, tc.wantSelect) {
				t.Errorf("PCRs() = 0x%x, want 0x%x", selection, tc.wantSelect)
			}
		})
	}
}

var extendstpm2 = map[TPMAlgID][]struct {
	digest []byte
}{
	TPMAlgSHA1: {
		{bytes.Repeat([]byte{0x00}, sha1.Size)},
		{bytes.Repeat([]byte{0x01}, sha1.Size)},
		{bytes.Repeat([]byte{0x02}, sha1.Size)}},
	TPMAlgSHA256: {
		{bytes.Repeat([]byte{0x00}, sha256.Size)},
		{bytes.Repeat([]byte{0x01}, sha256.Size)},
		{bytes.Repeat([]byte{0x02}, sha256.Size)}},
	TPMAlgSHA384: {
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

	DebugPCR := uint(16)

	cases := []struct {
		name    string
		hashalg TPMAlgID
	}{
		{"SHA1", TPMAlgSHA1},
		{"SHA256", TPMAlgSHA256},
		{"SHA384", TPMAlgSHA384},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			authHandle := AuthHandle{
				Handle: TPMHandle(DebugPCR),
				Auth:   PasswordAuth(nil),
			}

			pcrRead := PCRRead{
				PCRSelectionIn: TPMLPCRSelection{
					PCRSelections: []TPMSPCRSelection{
						{
							Hash:      c.hashalg,
							PCRSelect: PCClientCompatible.PCRs(DebugPCR),
						},
					},
				},
			}

			// Extending PCR 16
			for _, d := range extendstpm2[c.hashalg] {
				pcrExtend := PCRExtend{
					PCRHandle: authHandle,
					Digests: TPMLDigestValues{
						Digests: []TPMTHA{
							{
								HashAlg: c.hashalg,
								Digest:  d.digest,
							},
						},
					},
				}
				if _, err := pcrExtend.Execute(thetpm); err != nil {
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

func TestPCREvent(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	cases := []struct {
		name    string
		hashalg TPMAlgID
	}{
		{"SHA1", TPMAlgSHA1},
		{"SHA256", TPMAlgSHA256},
		{"SHA384", TPMAlgSHA384},
	}

	// Extend every SRTM PCR with TPM2_PCR_Event
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for i := 0; i < 17; i++ {
				t.Run(fmt.Sprintf("PCR%02d", i), func(t *testing.T) {
					pcrRead := PCRRead{
						PCRSelectionIn: TPMLPCRSelection{
							PCRSelections: []TPMSPCRSelection{
								{
									Hash:      c.hashalg,
									PCRSelect: PCClientCompatible.PCRs(20),
								},
							},
						},
					}

					pcrEvent := PCREvent{
						PCRHandle: TPMHandle(i),
						EventData: TPM2BEvent{Buffer: []byte("hello")},
					}
					if _, err := pcrEvent.Execute(thetpm); err != nil {
						t.Fatalf("failed to extend pcr for test %v", err)
					}

					pcrReadRsp, err := pcrRead.Execute(thetpm)
					if err != nil {
						t.Fatalf("failed to read PCRs")
					}
					postExtendPCR16 := pcrReadRsp.PCRValues.Digests[0].Buffer
					if allZero(postExtendPCR16) {
						t.Errorf("postExtendPCR16 not expected to be all Zero: %v", postExtendPCR16)
					}
				})
			}
		})
	}
}

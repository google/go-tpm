package tpm2

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/google/go-tpm/tpm2/helpers"
	"github.com/google/go-tpm/tpm2/structures/tpm"
	"github.com/google/go-tpm/tpm2/structures/tpm2b"
	"github.com/google/go-tpm/tpm2/structures/tpma"
	"github.com/google/go-tpm/tpm2/structures/tpml"
	"github.com/google/go-tpm/tpm2/structures/tpms"
	"github.com/google/go-tpm/tpm2/structures/tpmt"
	"github.com/google/go-tpm/tpm2/structures/tpmu"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpmutil"
)

func CreatePCRSelection(s []int) ([]byte, error) {

	const sizeOfPCRSelect = 3

	PCRs := make(tpmutil.RawBytes, sizeOfPCRSelect)

	for _, n := range s {
		if n >= 8*sizeOfPCRSelect {
			return nil, fmt.Errorf("PCR index %d is out of range (exceeds maximum value %d)", n, 8*sizeOfPCRSelect-1)
		}
		byteNum := n / 8
		bytePos := byte(1 << (n % 8))
		PCRs[byteNum] |= bytePos
	}

	return PCRs, nil
}

func TestCreatePCRSelection(t *testing.T) {

	emptyTest, err := CreatePCRSelection([]int{})
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}

	if !cmp.Equal(emptyTest, []byte{0, 0, 0}) {
		t.Fatalf("emptyTest does not return valid PCRs")
	}

	filledTest, err := CreatePCRSelection([]int{0, 1, 2})
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}

	if !cmp.Equal(filledTest, []byte{7, 0, 0}) {
		t.Fatalf("filledTest does not return valid PCRs")
	}
}

func TestSign(t *testing.T) {

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	PCR7, err := CreatePCRSelection([]int{7})
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}

	createPrimary := CreatePrimary{
		PrimaryHandle: tpm.RHOwner,

		InPublic: tpm2b.Public{
			PublicArea: tpmt.Public{
				Type:    tpm.AlgRSA,
				NameAlg: tpm.AlgSHA256,
				ObjectAttributes: tpma.Object{
					SignEncrypt:         true,
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
				},
				Parameters: tpmu.PublicParms{
					RSADetail: &tpms.RSAParms{
						Scheme: tpmt.RSAScheme{
							Scheme: tpm.AlgRSASSA,
							Details: tpmu.AsymScheme{
								RSASSA: &tpms.SigSchemeRSASSA{
									HashAlg: tpm.AlgSHA256,
								},
							},
						},
						KeyBits: 2048,
					},
				},
			},
		},
		CreationPCR: tpml.PCRSelection{
			PCRSelections: []tpms.PCRSelection{
				{
					Hash:      tpm.AlgSHA1,
					PCRSelect: PCR7,
				},
			},
		},
	}

	rspCP, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not create key: %v", err)
	}

	flushContext := FlushContext{FlushHandle: rspCP.ObjectHandle}
	defer flushContext.Execute(thetpm)

	digest := sha256.Sum256([]byte("migrationpains"))

	sign := Sign{
		KeyHandle: NamedHandle{
			Handle: rspCP.ObjectHandle,
			Name:   rspCP.Name,
		},
		Digest: tpm2b.Digest{
			Buffer: digest[:],
		},
		InScheme: tpmt.SigScheme{
			Scheme: tpm.AlgRSASSA,
			Details: tpmu.SigScheme{
				RSASSA: &tpms.SchemeHash{
					HashAlg: tpm.AlgSHA256,
				},
			},
		},
		Validation: tpmt.TKHashCheck{
			Tag: tpm.STHashCheck,
		},
	}

	rspSign, err := sign.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to Sign Digest: %v", err)
	}

	pub := rspCP.OutPublic.PublicArea
	rsaPub, err := helpers.RSAPub(pub.Parameters.RSADetail, pub.Unique.RSA)
	if err != nil {
		t.Fatalf("Failed to retrive Public Key: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], rspSign.Signature.Signature.RSASSA.Sig.Buffer); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}

}

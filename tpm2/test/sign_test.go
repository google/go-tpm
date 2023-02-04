package tpm2test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	. "github.com/google/go-tpm/tpm2"
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
		PrimaryHandle: TPMRHOwner,

		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgRSA,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				SignEncrypt:         true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgRSA,
				&TPMSRSAParms{
					Scheme: TPMTRSAScheme{
						Scheme: TPMAlgRSASSA,
						Details: NewTPMUAsymScheme(
							TPMAlgRSASSA,
							&TPMSSigSchemeRSASSA{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
					KeyBits: 2048,
				},
			),
		}),
		CreationPCR: TPMLPCRSelection{
			PCRSelections: []TPMSPCRSelection{
				{
					Hash:      TPMAlgSHA1,
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
		Digest: TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: TPMTSigScheme{
			Scheme: TPMAlgRSASSA,
			Details: NewTPMUSigScheme(
				TPMAlgRSASSA,
				&TPMSSchemeHash{
					HashAlg: TPMAlgSHA256,
				},
			),
		},
		Validation: TPMTTKHashCheck{
			Tag: TPMSTHashCheck,
		},
	}

	rspSign, err := sign.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to Sign Digest: %v", err)
	}

	pub, err := rspCP.OutPublic.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		t.Fatalf("%v", err)
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		t.Fatalf("%v", err)
	}

	rsaPub, err := RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		t.Fatalf("Failed to retrieve Public Key: %v", err)
	}

	rsassa, err := rspSign.Signature.Signature.RSASSA()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], rsassa.Sig.Buffer); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}

}

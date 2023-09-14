package tpm2test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestSign(t *testing.T) {

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

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
					PCRSelect: PCClientCompatible.PCRs(7),
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

package tpm2test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestImport(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	srkCreate := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(ECCSRKTemplate),
	}

	srkCreateRsp, err := srkCreate.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not generate SRK: %v", err)
	}
	defer func() {
		flush := FlushContext{
			FlushHandle: srkCreateRsp.ObjectHandle,
		}
		_, err := flush.Execute(thetpm)
		if err != nil {
			t.Fatalf("could not flush SRK: %v", err)
		}
	}()

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	sens2B := Marshal(TPMTSensitive{
		SensitiveType: TPMAlgECC,
		Sensitive: NewTPMUSensitiveComposite(
			TPMAlgECC,
			&TPM2BECCParameter{Buffer: pk.D.FillBytes(make([]byte, 32))},
		),
	})

	l := Marshal(TPM2BPrivate{Buffer: sens2B})

	_, err = Import{
		ParentHandle: &AuthHandle{
			Handle: srkCreateRsp.ObjectHandle,
			Name:   srkCreateRsp.Name,
			Auth:   PasswordAuth(nil),
		},
		Duplicate: TPM2BPrivate{Buffer: l},
		ObjectPublic: New2B(TPMTPublic{
			Type:    TPMAlgECC,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				SignEncrypt:          true,
				SensitiveDataOrigin:  false,
				EncryptedDuplication: false,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgECC,
				&TPMSECCParms{
					CurveID: TPMECCNistP256,
					Scheme: TPMTECCScheme{
						Scheme: TPMAlgECDSA,
						Details: NewTPMUAsymScheme(
							TPMAlgECDSA,
							&TPMSSigSchemeECDSA{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
				},
			),
			Unique: NewTPMUPublicID(
				TPMAlgECC,
				&TPMSECCPoint{
					X: TPM2BECCParameter{
						Buffer: pk.X.FillBytes(make([]byte, 32)),
					},
					Y: TPM2BECCParameter{
						Buffer: pk.Y.FillBytes(make([]byte, 32)),
					},
				},
			),
		}),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not import: %v", err)
	}
}

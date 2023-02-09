package tpm2test

import (
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestCommit(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	defer thetpm.Close()

	password := []byte("hello")

	create := CreateLoaded{
		ParentHandle: TPMRHOwner,
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: &TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
					Buffer: password,
				},
			},
		},
		InPublic: New2BTemplate(
			&TPMTPublic{
				Type:    TPMAlgECC,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					FixedTPM:            true,
					FixedParent:         true,
					UserWithAuth:        true,
					SensitiveDataOrigin: true,
					SignEncrypt:         true,
				},
				Parameters: NewTPMUPublicParms(
					TPMAlgECC,
					&TPMSECCParms{
						Symmetric: TPMTSymDefObject{
							Algorithm: TPMAlgNull,
						},
						Scheme: TPMTECCScheme{
							Scheme: TPMAlgECDAA,
							Details: NewTPMUAsymScheme(
								TPMAlgECDAA,
								&TPMSSchemeECDAA{
									HashAlg: TPMAlgSHA256,
								},
							),
						},
						CurveID: TPMECCBNP256,
						KDF: TPMTKDFScheme{
							Scheme: TPMAlgNull,
						},
					},
				),
			}),
	}

	rspCP, err := create.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not create key: %v", err)
	}

	flushContextCP := FlushContext{FlushHandle: rspCP.ObjectHandle}
	defer flushContextCP.Execute(thetpm)

	commit := Commit{
		SignHandle: AuthHandle{
			Handle: rspCP.ObjectHandle,
			Name:   rspCP.Name,
			Auth:   PasswordAuth(password),
		},
		P1: New2B(
			TPMSECCPoint{
				X: TPM2BECCParameter{
					Buffer: []byte{1},
				},
				Y: TPM2BECCParameter{
					Buffer: []byte{2},
				},
			}),
		S2: TPM2BSensitiveData{
			Buffer: []byte{},
		},
		Y2: TPM2BECCParameter{
			Buffer: []byte{},
		},
	}

	resp, err := commit.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not commit: %v", err)
	}

	firstCounter := resp.Counter

	resp, err = commit.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not commit: %v", err)
	}

	secondCounter := resp.Counter

	if firstCounter+1 != secondCounter {
		t.Fatalf("counter did not increment")
	}
}

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	"github.com/google/go-tpm/direct/structures/tpmu"
	"github.com/google/go-tpm/direct/transport/simulator"
)

func TestCommit(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	password := []byte{1, 2, 3}

	create := CreateLoaded{
		ParentHandle: tpm.RHEndorsement,
		InSensitive: tpm2b.SensitiveCreate{
			Sensitive: tpms.SensitiveCreate{
				UserAuth: tpm2b.Auth{
					Buffer: password,
				},
			},
		},
		InPublic: tpm2b.Template{
			Template: tpmt.Public{
				Type:    tpm.AlgECC,
				NameAlg: tpm.AlgSHA1,
				ObjectAttributes: tpma.Object{
					FixedTPM:            true,
					FixedParent:         true,
					UserWithAuth:        true,
					SensitiveDataOrigin: true,
					SignEncrypt:         true,
				},
				Parameters: tpmu.PublicParms{
					ECCDetail: &tpms.ECCParms{
						Symmetric: tpmt.SymDefObject{
							Algorithm: tpm.AlgNull,
						},
						Scheme: tpmt.ECCScheme{
							Scheme: tpm.AlgECDAA,
							Details: tpmu.AsymScheme{
								ECDAA: &tpms.SigSchemeECDAA{
									HashAlg: tpm.AlgSHA1,
									Count:   0,
								},
							},
						},
						CurveID: tpm.ECCBNP256,
						KDF: tpmt.KDFScheme{
							Scheme: tpm.AlgNull,
						},
					},
				},
			},
		},
	}

	rspC, err := create.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not create key: %v", err)
	}

	commit := Commit{
		SignHandle: AuthHandle{
			Handle: rspC.ObjectHandle,
			Name:   rspC.Name,
			Auth:   PasswordAuth(password),
		},
		P1: tpm2b.ECCPoint{
			Point: tpms.ECCPoint{
				X: tpm2b.ECCParameter{
					Buffer: []byte{
						0x1, 0x1,
					},
				},
				Y: tpm2b.ECCParameter{
					Buffer: []byte{0x1, 0x1},
				},
			},
			Size: 8,
		},
		S2: tpm2b.SensitiveData{
			Buffer: []byte{},
		},
		Y2: tpm2b.ECCParameter{
			Buffer: []byte{},
		},
		Count: 0,
	}

	_, err = commit.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not commit: %v", err)
	}

	flushContext := FlushContext{FlushHandle: rspC.ObjectHandle}
	defer flushContext.Execute(thetpm)
}

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2/structures/tpm"
	"github.com/google/go-tpm/tpm2/structures/tpm2b"
	"github.com/google/go-tpm/tpm2/structures/tpma"
	"github.com/google/go-tpm/tpm2/structures/tpms"
	"github.com/google/go-tpm/tpm2/structures/tpmt"
	"github.com/google/go-tpm/tpm2/structures/tpmu"
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
		ParentHandle: tpm.RHOwner,
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
				NameAlg: tpm.AlgSHA256,
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
									HashAlg: tpm.AlgSHA256,
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
		P1: tpm2b.ECCPoint{
			Point: tpms.ECCPoint{
				X: tpm2b.ECCParameter{
					Buffer: []byte{1},
				},
				Y: tpm2b.ECCParameter{
					Buffer: []byte{2},
				},
			},
		},
		S2: tpm2b.SensitiveData{
			Buffer: []byte{},
		},
		Y2: tpm2b.ECCParameter{
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

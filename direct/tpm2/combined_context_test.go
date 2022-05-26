package tpm2

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	"github.com/google/go-tpm/direct/structures/tpmu"
	"github.com/google/go-tpm/direct/transport/simulator"
)

func CombinedContextTest(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	createPrimary := CreatePrimary{
		PrimaryHandle: tpm.RHOwner,
		InPublic: tpm2b.Public{
			PublicArea: tpmt.Public{
				Type:    tpm.AlgECC,
				NameAlg: tpm.AlgSHA256,
				ObjectAttributes: tpma.Object{
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
					SignEncrypt:         true,
				},
				Parameters: tpmu.PublicParms{
					ECCDetail: &tpms.ECCParms{
						Scheme: tpmt.ECCScheme{
							Scheme: tpm.AlgECDSA,
							Details: tpmu.AsymScheme{
								ECDSA: &tpms.SigSchemeECDSA{
									HashAlg: tpm.AlgSHA256,
								},
							},
						},
						CurveID: tpm.ECCNistP256,
					},
				},
			},
		},
	}

	rspCP, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}

	flushContextCP := FlushContext{FlushHandle: rspCP.ObjectHandle}
	defer flushContextCP.Execute(thetpm)

	cl := CreateLoaded{
		ParentHandle: rspCP.ObjectHandle,
		InPublic: tpm2b.Template{
			Template: tpmt.Public{
				Type:    tpm.AlgKeyedHash,
				NameAlg: tpm.AlgSHA256,
				ObjectAttributes: tpma.Object{
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
					Decrypt:             true,
					Restricted:          true,
				},
				Parameters: tpmu.PublicParms{
					KeyedHashDetail: &tpms.KeyedHashParms{
						Scheme: tpmt.KeyedHashScheme{
							Scheme: tpm.AlgXOR,
							Details: tpmu.SchemeKeyedHash{
								XOR: &tpms.SchemeXOR{
									HashAlg: tpm.AlgSHA256,
									KDF:     tpm.AlgKDF1SP800108,
								},
							},
						},
					},
				},
			},
		},
	}

	rspCrL, err := cl.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not create derivation parent: %v:", err)
	}

	contextSave := ContextSave{
		SaveHandle: rspCrL.ObjectHandle,
	}
	rspCS, err := contextSave.Execute(thetpm)
	if err != nil {
		t.Fatalf("ContextSave failed: %v", err)
	}

	flushContextCL := FlushContext{FlushHandle: rspCrL.ObjectHandle}
	flushContextCL.Execute(thetpm)

	contextLoad := ContextLoad{
		Context: rspCS.Context,
	}

	rspCoL, err := contextLoad.Execute(thetpm)
	if err != nil {
		t.Fatalf("ContextLoad failed: %v", err)
	}

	if !cmp.Equal(rspCoL.LoadedHandle, rspCrL.ObjectHandle) {
		t.Error("Mismatch between public returned from ContextLoad & CreateLoaded")
	}
}

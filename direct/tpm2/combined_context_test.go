package tpm2

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpml"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	"github.com/google/go-tpm/direct/structures/tpmu"
	"github.com/google/go-tpm/direct/transport"
	"github.com/google/go-tpm/direct/transport/simulator"
)

func ReadPublicName(t *testing.T, handle tpm.Handle, thetpm transport.TPM) tpm2b.Name {
	readPublic := ReadPublic{
		ObjectHandle: handle,
	}

	rspRP, err := readPublic.Execute(thetpm)
	if err != nil {
		t.Fatalf("Failed to read public: %v", err)
	}

	return rspRP.Name
}

func TestCombinedContext(t *testing.T) {
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

	flushContextObject := FlushContext{FlushHandle: rspCP.ObjectHandle}
	defer flushContextObject.Execute(thetpm)

	contextSave := ContextSave{
		SaveHandle: rspCP.ObjectHandle,
	}

	rspCS, err := contextSave.Execute(thetpm)
	if err != nil {
		t.Fatalf("ContextSave failed: %v", err)
	}

	contextLoad := ContextLoad{
		Context: rspCS.Context,
	}

	rspCL, err := contextLoad.Execute(thetpm)
	if err != nil {
		t.Fatalf("ContextLoad failed: %v", err)
	}

	flushContextLoaded := FlushContext{FlushHandle: rspCL.LoadedHandle}
	defer flushContextLoaded.Execute(thetpm)

	rspCLName := ReadPublicName(t, rspCL.LoadedHandle, thetpm)
	rspCPName := ReadPublicName(t, rspCP.ObjectHandle, thetpm)

	if !cmp.Equal(rspCLName, rspCPName) {
		t.Error("Mismatch between public returned from ContextLoad & CreateLoaded")
	}
}

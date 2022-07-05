package tpm2

import (
	"testing"

	"github.com/google/go-tpm/direct/helpers"
	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpml"
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
	defer thetpm.Close()

	PCR7, err := CreatePCRSelection([]int{7})
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}

	createPrimary := CreatePrimary{
		PrimaryHandle: tpm.RHOwner,

		InPublic: tpm2b.Public{
			PublicArea: tpmt.Public{
				Type:    tpm.AlgECC,
				NameAlg: tpm.AlgSHA1,
				ObjectAttributes: tpma.Object{
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
					Decrypt:             true,
					Restricted:          true,
				},
				Parameters: tpmu.PublicParms{
					ECCDetail: &tpms.ECCParms{
						Symmetric: tpmt.SymDefObject{
							Algorithm: tpm.AlgAES,
							KeyBits: tpmu.SymKeyBits{
								AES: helpers.NewKeyBits(128),
							},
							Mode: tpmu.SymMode{
								AES: helpers.NewAlgID(tpm.AlgCFB),
							},
						},
						CurveID: tpm.ECCNistP256,
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

}

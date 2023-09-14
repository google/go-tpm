package tpm2test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func ReadPublicName(t *testing.T, handle TPMHandle, thetpm transport.TPM) TPM2BName {
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
							TPMAlgRSASSA, &TPMSSigSchemeRSASSA{
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

	if !cmp.Equal(rspCLName, rspCPName, cmpopts.IgnoreUnexported(rspCLName)) {
		t.Error("Mismatch between public returned from ContextLoad & CreateLoaded")
	}
}

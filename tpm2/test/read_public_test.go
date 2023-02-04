package tpm2test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// TestReadPublicKey compares the CreatePrimary response parameter outPublic with the output of ReadPublic outPublic.
func TestReadPublicKey(t *testing.T) {
	// Open simulated TPM for testing.
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	// Defer the close of the simulated TPM to after use.
	// Without this, other programs/tests may not be able to get a handle to the TPM.
	defer thetpm.Close()

	// Fill in the CreatePrimary struct.
	// See definition in Part 3, Commands, section 24.1.
	// See tpm2/templates/go for more TPMTPublic examples.
	createPrimary := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgECC,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgECC,
				&TPMSECCParms{
					Scheme: TPMTECCScheme{
						Scheme: TPMAlgECDSA,
						Details: NewTPMUAsymScheme(
							TPMAlgECDSA,
							&TPMSSigSchemeECDSA{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
					CurveID: TPMECCNistP256,
				},
			),
		}),
	}

	// Executing the command uses reflection to pack the bytes into a
	// TPM2_CreatePrimary command, returns a TPM2_CreatePrimary Response.
	// This response is also decoded so you are again working with structs
	// that can be found in Part 3, Commands, section 24.1.
	rspCP, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}

	// The TPM can only hold so much in nonvolatile memory, thus we must
	// flush the handle after we are done using it to prevent overloading.
	// Again we defer the flush to after we are done using the object.
	// It is generally good practice to defer the cleanup immediately
	// after loading an object or creating an Authorization Session.
	// See Part 1, Architecture, section 30.4
	flushContext := FlushContext{FlushHandle: rspCP.ObjectHandle}
	defer flushContext.Execute(thetpm)

	// Fill in the ReadPublic struct.
	// See definition in Part 3, Commands, section 12.4.
	readPublic := ReadPublic{
		ObjectHandle: rspCP.ObjectHandle,
	}

	// Executing the command uses reflection to pack the bytes into a
	// TPM2_ReadPublic command, returns a TPM2_ReadPublic Response.
	// This response is also decoded so you are again working with structs
	// that can be found in Part 3, Commands, section 12.4.
	rspRP, err := readPublic.Execute(thetpm)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	// PublicArea.Unique represents the unique identifier of the TPMTPublic.
	// Notice how this test uses verification of another TPM command that is
	// able to produce similar results to validate the response.
	pubCreate, err := rspCP.OutPublic.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	pubRead, err := rspRP.OutPublic.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	eccCreate, err := pubCreate.Unique.ECC()
	if err != nil {
		t.Fatalf("%v", err)
	}
	eccRead, err := pubRead.Unique.ECC()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !cmp.Equal(eccCreate.X, eccRead.X, cmpopts.IgnoreUnexported(eccCreate.X)) {
		t.Error("Mismatch between public returned from CreatePrimary & ReadPublic")
	}
}

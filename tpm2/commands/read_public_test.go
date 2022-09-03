package tpm2

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm/tpm2/structures/tpm"
	"github.com/google/go-tpm/tpm2/structures/tpm2b"
	"github.com/google/go-tpm/tpm2/structures/tpma"
	"github.com/google/go-tpm/tpm2/structures/tpms"
	"github.com/google/go-tpm/tpm2/structures/tpmt"
	"github.com/google/go-tpm/tpm2/structures/tpmu"
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
	// See tpm2/templates/templates.go for more tpmt.Public examples.
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

	// PublicArea.Unique represents the unique identifier of the TPMT.Public.
	// Notice how this test uses verification of another TPM command that is
	// able to produce similar results to validate the response.
	rspCPUnique := rspCP.OutPublic.PublicArea.Unique
	rspRPUnique := rspRP.OutPublic.PublicArea.Unique
	if !cmp.Equal(rspCPUnique, rspRPUnique) {
		t.Error("Mismatch between public returned from CreatePrimary & ReadPublic")
	}
}

package tpm2

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpml"
	"github.com/google/go-tpm/direct/transport/simulator"

	"github.com/google/go-tpm/direct/structures/tpms"
)

func TestPCRReset(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	PCRs, err := CreatePCRSelection([]int{16})
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}

	selection := tpml.PCRSelection{
		PCRSelections: []tpms.PCRSelection{
			{
				Hash:      tpm.AlgSHA1,
				PCRSelect: PCRs,
			},
		},
	}

	pcrRead := PCRRead{
		PCRSelectionIn: selection,
	}

	pcrReadRsp, err := pcrRead.Execute(thetpm)
	if err != nil {
		t.Fatalf("failed to read PCRs")
	}
	preResetBuffer := pcrReadRsp.PCRValues.Digests[0].Buffer[:]

	authHandle := AuthHandle{
		Handle: 16,
		Auth:   PasswordAuth(nil),
	}

	pcrReset := PCRReset{
		PCRHandle: authHandle,
	}

	if _, err := pcrReset.Execute(thetpm); err != nil {
		t.Fatalf("pcrReset failed: %v", err)
	}

	pcrRead = PCRRead{
		PCRSelectionIn: selection,
	}

	pcrReadRsp, err = pcrRead.Execute(thetpm)
	if err != nil {
		t.Fatalf("failed to read PCRs")
	}

	postResetBuffer := pcrReadRsp.PCRValues.Digests[0].Buffer[:]

	if !cmp.Equal(preResetBuffer, postResetBuffer) {
		t.Errorf("pcr after reset changed.")
	}
}

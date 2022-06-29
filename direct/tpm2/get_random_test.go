package tpm2

import (
	"testing"

	"github.com/google/go-tpm/direct/transport/simulator"
)

func TestGetRandom(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	grc := GetRandom{
		BytesRequested: 16,
	}

	if _, err := grc.Execute(thetpm); err != nil {
		t.Fatalf("GetRandom failed: %v", err)
	}
}

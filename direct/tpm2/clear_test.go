package tpm2

import (
	"testing"

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/transport/simulator"
)

func TestClear(t *testing.T) {

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	clear := Clear{
		AuthHandle: tpm.RHLockout,
	}

	if _, err := clear.Execute(thetpm); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}
}

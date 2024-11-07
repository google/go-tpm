package tpm2_test

import (
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func FuzzGetRandom(f *testing.F) {
	// Set up a simulated TPM transport
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		f.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close() // Close the simulator after the test

	// Seed corpus with initial values for fuzzing.
	f.Add(uint16(16)) // Example of a starting point with 16 bytes requested.

	f.Fuzz(func(t *testing.T, bytesRequested uint16) {
		cmd := GetRandom{BytesRequested: bytesRequested}

		// Use the simulator transport
		_, err := cmd.Execute(thetpm)
		if err != nil {
			t.Skip("Execution resulted in error:", err)
		}
	})
}

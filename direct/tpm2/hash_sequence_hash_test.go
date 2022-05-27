package tpm2

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/transport/simulator"
)

func TestHash(t *testing.T) {

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	hashF := Hash{
		Data:      tpm2b.MaxBuffer{Buffer: []byte("fiona")},
		HashAlg:   tpm.AlgSHA256,
		Hierarchy: tpm.RHOwner,
	}
	rspF, err := hashF.Execute(thetpm)

	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	hashC := Hash{
		Data:      tpm2b.MaxBuffer{Buffer: []byte("charlie")},
		HashAlg:   tpm.AlgSHA256,
		Hierarchy: tpm.RHOwner,
	}
	rspC, err := hashC.Execute(thetpm)

	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if cmp.Equal(rspC, rspF) {
		t.Fatalf("Hash not collision resistant")
	}

	if !cmp.Equal(rspF.Validation.Hierarchy, tpm.RHOwner) {
		t.Fatalf("Reponse Handle doesn't match Input Handle")
	}
}

func TestHashSequence(t *testing.T) {

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	hashSequenceStart := HashSequenceStart{
		Auth: tpm2b.Auth{
			Buffer: []byte("InitialBuffer"),
		},
		HashAlg: tpm.AlgSHA256,
	}

	rspHSS, err := hashSequenceStart.Execute(thetpm)
	if err != nil {
		t.Fatalf("HashSequenceStart failed: %v", err)
	}

	sequenceUpdate := SequenceUpdate{
		SequenceHandle: rspHSS.SequenceHandle,
		Buffer: tpm2b.MaxBuffer{
			Buffer: []byte("UpdateBuffer"),
		},
	}

	_, err = sequenceUpdate.Execute(thetpm)
	if err != nil {
		t.Fatalf("SequenceUpdate failed: %v", err)
	}

	sequenceComplete := SequenceComplete{
		Buffer: tpm2b.MaxBuffer{
			Buffer: []byte("CompleteBuffer"),
		},
		Hierarchy: tpm.RHOwner,
	}

	rspSC, err := sequenceComplete.Execute(thetpm)
	if err != nil {
		t.Fatalf("SequenceComplete failed: %v", err)
	}

	print(rspSC.Result.Buffer)

}

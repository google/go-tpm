package tpm2test

import (
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestEvictControl(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	srkCreate := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(ECCSRKTemplate),
	}

	srkCreateRsp, err := srkCreate.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not generate SRK: %v", err)
	}

	_, err = EvictControl{
		Auth: TPMRHOwner,
		ObjectHandle: &NamedHandle{
			Handle: srkCreateRsp.ObjectHandle,
			Name:   srkCreateRsp.Name,
		},
		PersistentHandle: 0x81000000,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not persist: %v", err)
	}
}

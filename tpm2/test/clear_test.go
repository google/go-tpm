package tpm2test

import (
	"bytes"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestClear(t *testing.T) {
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

	srkName1 := srkCreateRsp.Name

	clear := Clear{
		AuthHandle: AuthHandle{
			Handle: TPMRHLockout,
			Auth:   PasswordAuth(nil),
		},
	}
	_, err = clear.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not clear TPM: %v", err)
	}

	srkCreateRsp, err = srkCreate.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not generate SRK: %v", err)
	}
	defer func() {
		flush := FlushContext{
			FlushHandle: srkCreateRsp.ObjectHandle,
		}
		_, err := flush.Execute(thetpm)
		if err != nil {
			t.Fatalf("could not flush SRK: %v", err)
		}
	}()

	srkName2 := srkCreateRsp.Name

	if bytes.Equal(srkName1.Buffer, srkName2.Buffer) {
		t.Errorf("SRK Name did not change across clear, was %x both times", srkName1.Buffer)
	}
}

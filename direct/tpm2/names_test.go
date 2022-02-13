package tpm2

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/templates"
)

func TestHandleName(t *testing.T) {
	want := []byte{0x40, 0x00, 0x00, 0x0B}
	name := HandleName(tpm.RHEndorsement)
	if !bytes.Equal(want, name.Buffer) {
		t.Errorf("Incorrect name for RH_ENDORSEMENT (want %x got %x)", want, name.Buffer)
	}
}

func TestObjectName(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	thetpm := NewTPM(sim)
	defer thetpm.Close()

	createPrimary := CreatePrimary{
		PrimaryHandle: AuthHandle{
			Handle: tpm.RHEndorsement,
		},
		InPublic: templates.ECCEKTemplate,
	}
	rsp, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not call TPM2_CreatePrimary: %v", err)
	}
	flush := FlushContext{FlushHandle: rsp.ObjectHandle}
	defer flush.Execute(thetpm)
	public := rsp.OutPublic

	want := rsp.Name
	name, err := ObjectName(&public.PublicArea)
	if err != nil {
		t.Fatalf("error from ObjectName: %v", err)
	}
	if !bytes.Equal(want.Buffer, name.Buffer) {
		t.Errorf("Incorrect name for ECC EK (want %x got %x)", want.Buffer, name.Buffer)
	}
}

func TestNVName(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	thetpm := NewTPM(sim)
	defer thetpm.Close()

	public := tpm2b.NVPublic{
		NVPublic: tpms.NVPublic{
			NVIndex: tpm.Handle(0x0180000F),
			NameAlg: tpm.AlgSHA256,
			Attributes: tpma.NV{
				OwnerWrite: true,
				OwnerRead:  true,
				NT:         tpm.NTOrdinary,
			},
			DataSize: 4,
		},
	}

	defineSpace := NVDefineSpace{
		AuthHandle: AuthHandle{
			Handle: tpm.RHOwner,
		},
		PublicInfo: public,
	}
	if _, err := defineSpace.Execute(thetpm); err != nil {
		t.Fatalf("could not call TPM2_DefineSpace: %v", err)
	}

	readPublic := NVReadPublic{
		NVIndex: Handle{Handle: public.NVPublic.NVIndex},
	}
	rsp, err := readPublic.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not call TPM2_ReadPublic: %v", err)
	}

	want := rsp.NVName
	name, err := NVName(&public.NVPublic)
	if err != nil {
		t.Fatalf("error from NVIndexName: %v", err)
	}
	if !bytes.Equal(want.Buffer, name.Buffer) {
		t.Errorf("Incorrect name for NV index (want %x got %x)", want.Buffer, name.Buffer)
	}
}

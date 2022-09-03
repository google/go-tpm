package tpm2test

import (
	"bytes"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestHandleName(t *testing.T) {
	want := []byte{0x40, 0x00, 0x00, 0x0B}
	name := HandleName(TPMRHEndorsement)
	if !bytes.Equal(want, name.Buffer) {
		t.Errorf("Incorrect name for RH_ENDORSEMENT (want %x got %x)", want, name.Buffer)
	}
}

func TestObjectName(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	createPrimary := CreatePrimary{
		PrimaryHandle: TPMRHEndorsement,
		InPublic: TPM2BPublic{
			PublicArea: ECCEKTemplate,
		},
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
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	public := TPM2BNVPublic{
		NVPublic: TPMSNVPublic{
			NVIndex: TPMHandle(0x0180000F),
			NameAlg: TPMAlgSHA256,
			Attributes: TPMANV{
				OwnerWrite: true,
				OwnerRead:  true,
				NT:         TPMNTOrdinary,
			},
			DataSize: 4,
		},
	}

	defineSpace := NVDefineSpace{
		AuthHandle: TPMRHOwner,
		PublicInfo: public,
	}
	if err := defineSpace.Execute(thetpm); err != nil {
		t.Fatalf("could not call TPM2_DefineSpace: %v", err)
	}

	readPublic := NVReadPublic{
		NVIndex: public.NVPublic.NVIndex,
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

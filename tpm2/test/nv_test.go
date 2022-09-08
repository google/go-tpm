package tpm2test

import (
	"bytes"
	"encoding/binary"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestNVAuthWrite(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	def := NVDefineSpace{
		AuthHandle: TPMRHOwner,
		Auth: TPM2BAuth{
			Buffer: []byte("p@ssw0rd"),
		},
		PublicInfo: TPM2BNVPublic(
			&TPMSNVPublic{
				NVIndex: TPMHandle(0x0180000F),
				NameAlg: TPMAlgSHA256,
				Attributes: TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					AuthWrite:  true,
					AuthRead:   true,
					NT:         TPMNTOrdinary,
					NoDA:       true,
				},
				DataSize: 4,
			}),
	}
	if err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	nvName, err := NVName(def.PublicInfo.Contents().Unwrap())
	if err != nil {
		t.Fatalf("Calculating name of NV index: %v", err)
	}

	prewrite := NVWrite{
		AuthHandle: AuthHandle{
			Handle: def.PublicInfo.Contents().Unwrap().NVIndex,
			Name:   *nvName,
			Auth:   PasswordAuth([]byte("p@ssw0rd")),
		},
		NVIndex: NamedHandle{
			Handle: def.PublicInfo.Contents().Unwrap().NVIndex,
			Name:   *nvName,
		},
		Data: TPM2BMaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if err := prewrite.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Write: %v", err)
	}

	read := NVReadPublic{
		NVIndex: def.PublicInfo.Contents().Unwrap().NVIndex,
	}
	readRsp, err := read.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_ReadPublic: %v", err)
	}
	t.Logf("Name: %x", readRsp.NVName.Buffer)

	write := NVWrite{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   HMAC(TPMAlgSHA256, 16, Auth([]byte{})),
		},
		NVIndex: NamedHandle{
			Handle: def.PublicInfo.Contents().Unwrap().NVIndex,
			Name:   readRsp.NVName,
		},
		Data: TPM2BMaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if err := write.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Write: %v", err)
	}
}

func TestNVAuthIncrement(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// Define the counter space
	def := NVDefineSpace{
		AuthHandle: TPMRHOwner,
		Auth: TPM2BAuth{
			Buffer: []byte("p@ssw0rd"),
		},
		PublicInfo: TPM2BNVPublic(
			&TPMSNVPublic{
				NVIndex: TPMHandle(0x0180000F),
				NameAlg: TPMAlgSHA256,
				Attributes: TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					AuthWrite:  true,
					AuthRead:   true,
					NT:         TPMNTCounter,
					NoDA:       true,
				},
				DataSize: 8,
			}),
	}
	if err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	// Calculate the Name of the index as of its creation
	// (i.e., without NV_WRITTEN set).
	nvName, err := NVName(def.PublicInfo.Contents().Unwrap())
	if err != nil {
		t.Fatalf("Calculating name of NV index: %v", err)
	}

	incr := NVIncrement{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   HMAC(TPMAlgSHA256, 16, Auth([]byte{})),
		},
		NVIndex: NamedHandle{
			Handle: def.PublicInfo.Contents().Unwrap().NVIndex,
			Name:   *nvName,
		},
	}
	if err := incr.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Increment: %v", err)
	}

	// The NV index's Name has changed. Ask the TPM for it.
	readPub := NVReadPublic{
		NVIndex: def.PublicInfo.Contents().Unwrap().NVIndex,
	}
	readPubRsp, err := readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_ReadPublic: %v", err)
	}
	incr.NVIndex = NamedHandle{
		Handle: def.PublicInfo.Contents().Unwrap().NVIndex,
		Name:   readPubRsp.NVName,
	}

	read := NVRead{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   HMAC(TPMAlgSHA256, 16, Auth([]byte{})),
		},
		NVIndex: NamedHandle{
			Handle: def.PublicInfo.Contents().Unwrap().NVIndex,
			Name:   readPubRsp.NVName,
		},
		Size: 8,
	}
	readRsp, err := read.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_Read: %v", err)
	}

	if err := incr.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Increment: %v", err)
	}

	var val1 uint64
	err = binary.Read(bytes.NewReader(readRsp.Data.Buffer), binary.BigEndian, &val1)
	if err != nil {
		t.Fatalf("Parsing counter: %v", err)
	}

	readRsp, err = read.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_Read: %v", err)
	}

	var val2 uint64
	err = binary.Read(bytes.NewReader(readRsp.Data.Buffer), binary.BigEndian, &val2)
	if err != nil {
		t.Fatalf("Parsing counter: %v", err)
	}

	if val2 != (val1 + 1) {
		t.Errorf("want %v got %v", val1+1, val2)
	}
}

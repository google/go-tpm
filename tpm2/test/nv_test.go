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
		PublicInfo: New2B(
			TPMSNVPublic{
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
	if _, err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	pub, err := def.PublicInfo.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	nvName, err := NVName(pub)
	if err != nil {
		t.Fatalf("Calculating name of NV index: %v", err)
	}

	prewrite := NVWrite{
		AuthHandle: AuthHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
			Auth:   PasswordAuth([]byte("p@ssw0rd")),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: TPM2BMaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if _, err := prewrite.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Write: %v", err)
	}

	read := NVReadPublic{
		NVIndex: pub.NVIndex,
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
			Handle: pub.NVIndex,
			Name:   readRsp.NVName,
		},
		Data: TPM2BMaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if _, err := write.Execute(thetpm); err != nil {
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
		PublicInfo: New2B(
			TPMSNVPublic{
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
	if _, err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	pub, err := def.PublicInfo.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	// Calculate the Name of the index as of its creation
	// (i.e., without NV_WRITTEN set).
	nvName, err := NVName(pub)
	if err != nil {
		t.Fatalf("Calculating name of NV index: %v", err)
	}

	incr := NVIncrement{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   HMAC(TPMAlgSHA256, 16, Auth([]byte{})),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
	}
	if _, err := incr.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Increment: %v", err)
	}

	// The NV index's Name has changed. Ask the TPM for it.
	readPub := NVReadPublic{
		NVIndex: pub.NVIndex,
	}
	readPubRsp, err := readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_ReadPublic: %v", err)
	}
	incr.NVIndex = NamedHandle{
		Handle: pub.NVIndex,
		Name:   readPubRsp.NVName,
	}

	read := NVRead{
		AuthHandle: AuthHandle{
			Handle: TPMRHOwner,
			Auth:   HMAC(TPMAlgSHA256, 16, Auth([]byte{})),
		},
		NVIndex: NamedHandle{
			Handle: pub.NVIndex,
			Name:   readPubRsp.NVName,
		},
		Size: 8,
	}
	readRsp, err := read.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_Read: %v", err)
	}

	if _, err := incr.Execute(thetpm); err != nil {
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

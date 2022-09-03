package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2/structures/tpm"
	"github.com/google/go-tpm/tpm2/structures/tpm2b"
	"github.com/google/go-tpm/tpm2/structures/tpma"
	"github.com/google/go-tpm/tpm2/structures/tpms"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestNVAuthWrite(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	def := NVDefineSpace{
		AuthHandle: tpm.RHOwner,
		Auth: tpm2b.Auth{
			Buffer: []byte("p@ssw0rd"),
		},
		PublicInfo: tpm2b.NVPublic{
			NVPublic: tpms.NVPublic{
				NVIndex: tpm.Handle(0x0180000F),
				NameAlg: tpm.AlgSHA256,
				Attributes: tpma.NV{
					OwnerWrite: true,
					OwnerRead:  true,
					AuthWrite:  true,
					AuthRead:   true,
					NT:         tpm.NTOrdinary,
					NoDA:       true,
				},
				DataSize: 4,
			},
		},
	}
	if err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	nvName, err := NVName(&def.PublicInfo.NVPublic)
	if err != nil {
		t.Fatalf("Calculating name of NV index: %v", err)
	}

	prewrite := NVWrite{
		AuthHandle: AuthHandle{
			Handle: def.PublicInfo.NVPublic.NVIndex,
			Name:   *nvName,
			Auth:   PasswordAuth([]byte("p@ssw0rd")),
		},
		NVIndex: NamedHandle{
			Handle: def.PublicInfo.NVPublic.NVIndex,
			Name:   *nvName,
		},
		Data: tpm2b.MaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if err := prewrite.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Write: %v", err)
	}

	read := NVReadPublic{
		NVIndex: def.PublicInfo.NVPublic.NVIndex,
	}
	readRsp, err := read.Execute(thetpm)
	if err != nil {
		t.Fatalf("Calling TPM2_NV_ReadPublic: %v", err)
	}
	t.Logf("Name: %x", readRsp.NVName.Buffer)

	write := NVWrite{
		AuthHandle: AuthHandle{
			Handle: tpm.RHOwner,
			Auth:   HMAC(tpm.AlgSHA256, 16, Auth([]byte{})),
		},
		NVIndex: NamedHandle{
			Handle: def.PublicInfo.NVPublic.NVIndex,
			Name:   readRsp.NVName,
		},
		Data: tpm2b.MaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if err := write.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Write: %v", err)
	}
}

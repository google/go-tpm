package tpm2

import (
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpms"
)

func TestNVAuthWrite(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	thetpm := NewTPM(sim)
	defer thetpm.Close()

	def := NVDefineSpace{
		AuthHandle: AuthHandle{
			Handle: tpm.RHOwner,
		},
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
	if _, err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	prewrite := NVWrite{
		AuthHandle: AuthHandle{
			Handle: def.PublicInfo.NVPublic.NVIndex,
			Auth:   PasswordAuth([]byte("p@ssw0rd")),
		},
		// Don't have to provide the name when authorizing by password.
		NVIndex: Handle{Handle: def.PublicInfo.NVPublic.NVIndex},
		Data: tpm2b.MaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if _, err := prewrite.Execute(thetpm); err != nil {
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
		NVIndex: Handle{
			Handle: def.PublicInfo.NVPublic.NVIndex,
			// When authorizing by HMAC or Policy, have to provide the Name.
			Name: readRsp.NVName,
		},
		Data: tpm2b.MaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	if _, err := write.Execute(thetpm); err != nil {
		t.Errorf("Calling TPM2_NV_Write: %v", err)
	}
}

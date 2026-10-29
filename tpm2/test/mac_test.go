package tpm2test

import (
	"bytes"
	"encoding/hex"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

// AES-128 CMAC test vectors from RFC 4493, section 4.
var cmacKey = mustHex("2b7e151628aed2a6abf7158809cf4f3c")

var cmacVectors = []struct {
	name string
	msg  string
	mac  string
}{
	{"empty", "", "bb1d6929e95937287fa37d129b756746"},
	{"16 bytes", "6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
	{"40 bytes", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
	{"64 bytes", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe"},
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// loadCMACKey creates an AES-128 signing key with the RFC 4493 key value under
// a fresh SRK and loads it. The returned cleanup flushes both objects.
func loadCMACKey(t *testing.T, thetpm transport.TPM) (NamedHandle, func()) {
	t.Helper()

	srk, err := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(RSASRKTemplate),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary SRK failed: %v", err)
	}
	srkAuth := AuthHandle{
		Handle: srk.ObjectHandle,
		Name:   srk.Name,
		Auth:   PasswordAuth(nil),
	}

	created, err := Create{
		ParentHandle: srkAuth,
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: &TPMSSensitiveCreate{
				Data: NewTPMUSensitiveCreate(&TPM2BSensitiveData{Buffer: cmacKey}),
			},
		},
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgSymCipher,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				SignEncrypt:  true,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgSymCipher,
				&TPMSSymCipherParms{
					Sym: TPMTSymDefObject{
						Algorithm: TPMAlgAES,
						Mode:      NewTPMUSymMode(TPMAlgAES, TPMAlgCMAC),
						KeyBits:   NewTPMUSymKeyBits(TPMAlgAES, TPMKeyBits(128)),
					},
				},
			),
		}),
	}.Execute(thetpm)
	if err != nil {
		FlushContext{FlushHandle: srk.ObjectHandle}.Execute(thetpm)
		t.Fatalf("Create CMAC key failed: %v", err)
	}

	loaded, err := Load{
		ParentHandle: srkAuth,
		InPrivate:    created.OutPrivate,
		InPublic:     created.OutPublic,
	}.Execute(thetpm)
	if err != nil {
		FlushContext{FlushHandle: srk.ObjectHandle}.Execute(thetpm)
		t.Fatalf("Load CMAC key failed: %v", err)
	}

	cleanup := func() {
		FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(thetpm)
		FlushContext{FlushHandle: srk.ObjectHandle}.Execute(thetpm)
	}
	return NamedHandle{Handle: loaded.ObjectHandle, Name: loaded.Name}, cleanup
}

func TestMAC(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	key, cleanup := loadCMACKey(t, thetpm)
	defer cleanup()

	for _, v := range cmacVectors {
		t.Run(v.name, func(t *testing.T) {
			rsp, err := MAC{
				Handle: AuthHandle{
					Handle: key.Handle,
					Name:   key.Name,
					Auth:   PasswordAuth(nil),
				},
				Buffer:   TPM2BMaxBuffer{Buffer: mustHex(v.msg)},
				InScheme: TPMAlgCMAC,
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("MAC failed: %v", err)
			}
			if want := mustHex(v.mac); !bytes.Equal(rsp.OutMAC.Buffer, want) {
				t.Errorf("MAC = %x, want %x", rsp.OutMAC.Buffer, want)
			}
		})
	}
}

func TestMACSequence(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	key, cleanup := loadCMACKey(t, thetpm)
	defer cleanup()

	password := []byte("sequence")
	// The 64-byte vector, fed to the sequence one block at a time.
	v := cmacVectors[3]
	data := mustHex(v.msg)
	const chunk = 16

	rspStart, err := MACStart{
		Handle: AuthHandle{
			Handle: key.Handle,
			Name:   key.Name,
			Auth:   PasswordAuth(nil),
		},
		Auth:     TPM2BAuth{Buffer: password},
		InScheme: TPMAlgCMAC,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("MACStart failed: %v", err)
	}
	seq := AuthHandle{
		Handle: rspStart.SequenceHandle,
		Auth:   PasswordAuth(password),
	}

	for len(data) > chunk {
		if _, err := (SequenceUpdate{
			SequenceHandle: seq,
			Buffer:         TPM2BMaxBuffer{Buffer: data[:chunk]},
		}).Execute(thetpm); err != nil {
			t.Fatalf("SequenceUpdate failed: %v", err)
		}
		data = data[chunk:]
	}

	rspComplete, err := SequenceComplete{
		SequenceHandle: seq,
		Buffer:         TPM2BMaxBuffer{Buffer: data},
		Hierarchy:      TPMRHNull,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("SequenceComplete failed: %v", err)
	}
	if want := mustHex(v.mac); !bytes.Equal(rspComplete.Result.Buffer, want) {
		t.Errorf("sequence MAC = %x, want %x", rspComplete.Result.Buffer, want)
	}
}

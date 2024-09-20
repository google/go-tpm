package tpm2test

import (
	"bytes"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestRSAEncryption(t *testing.T) {
	theTpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	t.Cleanup(func() {
		if err := theTpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	createPrimaryCmd := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(RSASRKTemplate),
	}
	createPrimaryRsp, err := createPrimaryCmd.Execute(theTpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Cleanup(func() {
		flushContextCmd := FlushContext{FlushHandle: createPrimaryRsp.ObjectHandle}
		if _, err := flushContextCmd.Execute(theTpm); err != nil {
			t.Errorf("%v", err)
		}
	})

	createCmd := Create{
		ParentHandle: NamedHandle{
			Handle: createPrimaryRsp.ObjectHandle,
			Name:   createPrimaryRsp.Name,
		},
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgRSA,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:             true,
				STClear:              false,
				FixedParent:          true,
				SensitiveDataOrigin:  true,
				UserWithAuth:         true,
				AdminWithPolicy:      false,
				NoDA:                 true,
				EncryptedDuplication: false,
				Restricted:           false,
				Decrypt:              true,
				SignEncrypt:          true,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgRSA,
				&TPMSRSAParms{
					KeyBits: 2048,
				},
			),
			Unique: NewTPMUPublicID(
				TPMAlgRSA,
				&TPM2BPublicKeyRSA{
					Buffer: make([]byte, 256),
				},
			),
		}),
	}
	createRsp, err := createCmd.Execute(theTpm)
	if err != nil {
		t.Fatalf("%v", err)
	}

	loadCmd := Load{
		ParentHandle: NamedHandle{
			Handle: createPrimaryRsp.ObjectHandle,
			Name:   createPrimaryRsp.Name,
		},
		InPrivate: createRsp.OutPrivate,
		InPublic:  createRsp.OutPublic,
	}
	loadRsp, err := loadCmd.Execute(theTpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Cleanup(func() {
		flushContextCmd := FlushContext{FlushHandle: loadRsp.ObjectHandle}
		if _, err := flushContextCmd.Execute(theTpm); err != nil {
			t.Errorf("%v", err)
		}
	})

	message := []byte("secret")

	encryptCmd := RSAEncrypt{
		KeyHandle: loadRsp.ObjectHandle,
		Message:   TPM2BPublicKeyRSA{Buffer: message},
		InScheme: TPMTRSADecrypt{
			Scheme: TPMAlgOAEP,
			Details: NewTPMUAsymScheme(
				TPMAlgOAEP,
				&TPMSEncSchemeOAEP{
					HashAlg: TPMAlgSHA256,
				},
			),
		},
	}
	encryptRsp, err := encryptCmd.Execute(theTpm)
	if err != nil {
		t.Fatalf("%v", err)
	}

	decryptCmd := RSADecrypt{
		KeyHandle: NamedHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
		},
		CipherText: TPM2BPublicKeyRSA{Buffer: encryptRsp.OutData.Buffer},
		InScheme: TPMTRSADecrypt{
			Scheme: TPMAlgOAEP,
			Details: NewTPMUAsymScheme(
				TPMAlgOAEP,
				&TPMSEncSchemeOAEP{
					HashAlg: TPMAlgSHA256,
				},
			),
		},
	}
	decryptRsp, err := decryptCmd.Execute(theTpm)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(message, decryptRsp.Message.Buffer) {
		t.Errorf("want %x got %x", message, decryptRsp.Message.Buffer)
	}
}

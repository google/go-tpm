package tpm2test

import (
	"bytes"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestRSAEncryptDecrypt(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	srkAuth := []byte("pass")
	createSRKCmd := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: &TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
					Buffer: srkAuth,
				},
			},
		},
		InPublic: New2B(RSASRKTemplate),
	}
	createSRKRsp, err := createSRKCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("%v", err)
	}

	defer func() {
		flushSRKCmd := FlushContext{FlushHandle: createSRKRsp.ObjectHandle}
		if _, err := flushSRKCmd.Execute(thetpm); err != nil {
			t.Errorf("%v", err)
		}
	}()

	createCMD := Create{
		ParentHandle: AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   PasswordAuth(srkAuth),
		},
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: &TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
					Buffer: srkAuth,
				},
			},
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
				NoDA:                 false,
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

	createResp, err := createCMD.Execute(thetpm)
	if err != nil {
		t.Errorf("Error executing create: %v\n", err)
	}

	loadCMD := Load{
		ParentHandle: AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   HMAC(TPMAlgSHA256, 16, Auth(srkAuth)),
		},
		InPrivate: createResp.OutPrivate,
		InPublic:  createResp.OutPublic,
	}
	loadResp, err := loadCMD.Execute(thetpm)
	if err != nil {
		t.Errorf("Error executing load: %v\n", err)
	}

	message := []byte("my message")

	RSAEncryptCMD := RSAEncrypt{
		KeyHandle: loadResp.ObjectHandle,
		Message: TPM2BPublicKeyRSA{
			Buffer: message,
		},
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

	RSAEncryptResp, err := RSAEncryptCMD.Execute(thetpm)
	if err != nil {
		t.Errorf("Error executing rsaencrypt: %v\n", err)
	}

	RSADecryptCMD := RSADecrypt{
		KeyHandle: AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
			Auth:   PasswordAuth(srkAuth),
		},
		CipherText: TPM2BPublicKeyRSA{
			Buffer: RSAEncryptResp.OutData.Buffer,
		},
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
	RSADecryptResp, err := RSADecryptCMD.Execute(thetpm)
	if err != nil {
		t.Errorf("Error executing rsadecrypt: %v\n", err)
	}

	if !bytes.Equal(RSADecryptResp.Message.Buffer, message) {
		t.Errorf("want %x got %x", message, RSADecryptResp.Message.Buffer)
	}
}

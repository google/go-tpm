package tpm2test

import (
	"bytes"
	"crypto/rand"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// p384Template is an SRK-like ECDH-P384 key based on the P384 EK template.
// The main purpose of this key is to have a different Name algorithm than the other keys involved in this test.
var p384Template = TPMTPublic{
	Type:    TPMAlgECC,
	NameAlg: TPMAlgSHA384,
	ObjectAttributes: TPMAObject{
		FixedTPM:             true,
		STClear:              false,
		FixedParent:          true,
		SensitiveDataOrigin:  true,
		UserWithAuth:         true,
		AdminWithPolicy:      false,
		NoDA:                 false,
		EncryptedDuplication: false,
		Restricted:           true,
		Decrypt:              true,
		SignEncrypt:          false,
	},
	Parameters: NewTPMUPublicParms(
		TPMAlgECC,
		&TPMSECCParms{
			Symmetric: TPMTSymDefObject{
				Algorithm: TPMAlgAES,
				KeyBits: NewTPMUSymKeyBits(
					TPMAlgAES,
					TPMKeyBits(256),
				),
				Mode: NewTPMUSymMode(
					TPMAlgAES,
					TPMAlgCFB,
				),
			},
			CurveID: TPMECCNistP384,
		},
	),
	Unique: NewTPMUPublicID(
		TPMAlgECC,
		&TPMSECCPoint{
			X: TPM2BECCParameter{
				Buffer: nil,
			},
			Y: TPM2BECCParameter{
				Buffer: nil,
			},
		},
	),
}

// This test checks that ActivateCredential can decrypt a credential created by the TPM in MakeCredential.
func TestActivateTPMCredential(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	ekCreate := CreatePrimary{
		PrimaryHandle: TPMRHEndorsement,
		InPublic:      New2B(ECCEKTemplate),
	}

	ekCreateRsp, err := ekCreate.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not generate EK: %v", err)
	}
	defer func() {
		flush := FlushContext{
			FlushHandle: ekCreateRsp.ObjectHandle,
		}
		_, err := flush.Execute(thetpm)
		if err != nil {
			t.Fatalf("could not flush EK: %v", err)
		}
	}()

	srkCreate := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(ECCSRKTemplate),
	}

	srkCreateRsp, err := srkCreate.Execute(thetpm)
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

	secret := TPM2BDigest{Buffer: []byte("Secrets!!!")}

	mc := MakeCredential{
		Handle:     ekCreateRsp.ObjectHandle,
		Credential: secret,
		ObjectName: srkCreateRsp.Name,
	}
	mcRsp, err := mc.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not make credential: %v", err)
	}

	ac := ActivateCredential{
		ActivateHandle: NamedHandle{
			Handle: srkCreateRsp.ObjectHandle,
			Name:   srkCreateRsp.Name,
		},
		KeyHandle: AuthHandle{
			Handle: ekCreateRsp.ObjectHandle,
			Name:   ekCreateRsp.Name,
			Auth:   Policy(TPMAlgSHA256, 16, ekPolicy),
		},
		CredentialBlob: mcRsp.CredentialBlob,
		Secret:         mcRsp.Secret,
	}
	acRsp, err := ac.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not activate credential: %v", err)
	}

	if !bytes.Equal(acRsp.CertInfo.Buffer, secret.Buffer) {
		t.Errorf("want %x got %x", secret.Buffer, acRsp.CertInfo.Buffer)
	}
}

// This test checks that ActivateCredential can decrypt a credential created by a remote server using CreateCredential.
func TestActivateSWCredential(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("OpenSimulator() = %v", err)
	}
	defer tpm.Close()

	for _, tc := range []struct {
		// Name of the test case
		name string
		// Storage key template
		pubTemplate TPMTPublic
		// Credentialed object template
		subTemplate TPMTPublic
	}{
		{
			name:        "ECDH-P256 SRK activating RSA SRK",
			pubTemplate: ECCSRKTemplate,
			subTemplate: RSASRKTemplate,
		},
		{
			name:        "RSA-2048 SRK activating P256 SRK",
			pubTemplate: RSASRKTemplate,
			subTemplate: ECCSRKTemplate,
		},
		{
			name:        "ECDH-P256 SRK activating P384 key",
			pubTemplate: ECCSRKTemplate,
			subTemplate: p384Template,
		},
		{
			name:        "RSA-2048 SRK activating P384 key",
			pubTemplate: RSASRKTemplate,
			subTemplate: p384Template,
		},
		{
			name:        "P384 key activating P256 SRK",
			pubTemplate: p384Template,
			subTemplate: ECCSRKTemplate,
		},
		{
			name:        "P384 key activating RSA SRK",
			pubTemplate: p384Template,
			subTemplate: RSASRKTemplate,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Create the key that is going to decrypt the credential challenge.
			primary, err := CreatePrimary{
				PrimaryHandle: TPMRHOwner,
				InPublic:      New2B(tc.pubTemplate),
			}.Execute(tpm)
			if err != nil {
				t.Fatalf("CreatePrimary() = %v", err)
			}
			defer FlushContext{FlushHandle: primary.ObjectHandle}.Execute(tpm)

			public, err := primary.OutPublic.Contents()
			if err != nil {
				t.Fatalf("OutPublic.Contents() = %v", err)
			}

			key, err := ImportEncapsulationKey(public)
			if err != nil {
				t.Fatalf("ImportEncapsulationKey() = %v", err)
			}

			// Create the key that is going to be named in the challenge.
			subject, err := CreatePrimary{
				PrimaryHandle: TPMRHOwner,
				InPublic:      New2B(tc.subTemplate),
			}.Execute(tpm)
			if err != nil {
				t.Fatalf("CreatePrimary() = %v", err)
			}
			defer FlushContext{FlushHandle: subject.ObjectHandle}.Execute(tpm)

			// Create the challenge.
			plaintext := []byte("hello, credential")
			idObject, encSecret, err := CreateCredential(rand.Reader, key, subject.Name.Buffer, plaintext)
			if err != nil {
				t.Fatalf("CreateCredential() = %v", err)
			}

			// Get the challenge decrypted.
			activate, err := ActivateCredential{
				KeyHandle: NamedHandle{
					Handle: primary.ObjectHandle,
					Name:   primary.Name,
				},
				ActivateHandle: NamedHandle{
					Handle: subject.ObjectHandle,
					Name:   subject.Name,
				},
				CredentialBlob: TPM2BIDObject{
					Buffer: idObject,
				},
				Secret: TPM2BEncryptedSecret{
					Buffer: encSecret,
				},
			}.Execute(tpm)
			if err != nil {
				t.Fatalf("ActivateCredential() = %v", err)
			}

			if !bytes.Equal(activate.CertInfo.Buffer, plaintext) {
				t.Errorf("ActivateCredential() = %x, want %x", activate.CertInfo.Buffer, plaintext)
			}
		})
	}
}

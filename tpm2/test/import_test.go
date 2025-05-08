package tpm2test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// This test checks that Import can import an object in the clear.
func TestCleartextImport(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

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

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	sens2B := Marshal(TPMTSensitive{
		SensitiveType: TPMAlgECC,
		Sensitive: NewTPMUSensitiveComposite(
			TPMAlgECC,
			&TPM2BECCParameter{Buffer: pk.D.FillBytes(make([]byte, 32))},
		),
	})

	l := Marshal(TPM2BPrivate{Buffer: sens2B})

	_, err = Import{
		ParentHandle: &AuthHandle{
			Handle: srkCreateRsp.ObjectHandle,
			Name:   srkCreateRsp.Name,
			Auth:   PasswordAuth(nil),
		},
		Duplicate: TPM2BPrivate{Buffer: l},
		ObjectPublic: New2B(TPMTPublic{
			Type:    TPMAlgECC,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				SignEncrypt:          true,
				SensitiveDataOrigin:  false,
				EncryptedDuplication: false,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgECC,
				&TPMSECCParms{
					CurveID: TPMECCNistP256,
					Scheme: TPMTECCScheme{
						Scheme: TPMAlgECDSA,
						Details: NewTPMUAsymScheme(
							TPMAlgECDSA,
							&TPMSSigSchemeECDSA{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
				},
			),
			Unique: NewTPMUPublicID(
				TPMAlgECC,
				&TPMSECCPoint{
					X: TPM2BECCParameter{
						Buffer: pk.X.FillBytes(make([]byte, 32)),
					},
					Y: TPM2BECCParameter{
						Buffer: pk.Y.FillBytes(make([]byte, 32)),
					},
				},
			),
		}),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not import: %v", err)
	}
}

func makeSealedBlob(t *testing.T, nameAlg TPMIAlgHash, obfuscation []byte, contents []byte) (*TPMTPublic, []byte) {
	t.Helper()
	// Unique for a KEYEDHASH object is H_nameAlg(obfuscate | key)
	// See Part 1, "Public Area Creation"
	h, err := nameAlg.Hash()
	if err != nil {
		t.Fatalf("nameAlg.Hash() = %v", err)
	}
	uniqueHash := h.New()
	uniqueHash.Write(obfuscation)
	uniqueHash.Write(contents)
	public := TPMTPublic{
		Type:    TPMAlgKeyedHash,
		NameAlg: nameAlg,
		ObjectAttributes: TPMAObject{
			UserWithAuth: true,
			NoDA:         true,
		},
		Parameters: NewTPMUPublicParms(TPMAlgKeyedHash, &TPMSKeyedHashParms{}),
		Unique:     NewTPMUPublicID(TPMAlgKeyedHash, &TPM2BDigest{Buffer: uniqueHash.Sum(nil)}),
	}
	sensitive := TPMTSensitive{
		SensitiveType: TPMAlgKeyedHash,
		SeedValue: TPM2BDigest{
			Buffer: obfuscation,
		},
		Sensitive: NewTPMUSensitiveComposite(TPMAlgKeyedHash, &TPM2BSensitiveData{
			Buffer: contents,
		}),
	}
	return &public, Marshal(sensitive)
}

// This test checks that Import can import an object created by a remote server using CreateDuplicate.
func TestSWDuplicateImport(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("OpenSimulator() = %v", err)
	}
	defer tpm.Close()

	for _, tc := range []struct {
		name        string
		pubTemplate TPMTPublic
	}{
		{
			name:        "ECDH-P256",
			pubTemplate: ECCSRKTemplate,
		},
		{
			name:        "RSA-2048",
			pubTemplate: RSASRKTemplate,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			plaintext := []byte("hello, unseal")
			sealedPub, sealedPriv := makeSealedBlob(t, TPMAlgSHA256, make([]byte, 32), plaintext)
			sealedName, err := ObjectName(sealedPub)
			if err != nil {
				t.Fatalf("ObjectName() = %v", err)
			}
			duplicate, encSecret, err := CreateDuplicate(rand.Reader, key, sealedName.Buffer, sealedPriv)
			if err != nil {
				t.Fatalf("MakeDuplicate() = %v", err)
			}

			impo, err := Import{
				ParentHandle: NamedHandle{
					Handle: primary.ObjectHandle,
					Name:   primary.Name,
				},
				ObjectPublic: New2B(*sealedPub),
				Duplicate:    TPM2BPrivate{Buffer: duplicate},
				InSymSeed:    TPM2BEncryptedSecret{Buffer: encSecret},
			}.Execute(tpm)
			if err != nil {
				t.Fatalf("Import() = %v", err)
			}

			load, err := Load{
				ParentHandle: NamedHandle{
					Handle: primary.ObjectHandle,
					Name:   primary.Name,
				},
				InPublic:  New2B(*sealedPub),
				InPrivate: impo.OutPrivate,
			}.Execute(tpm)
			if err != nil {
				t.Fatalf("Import() = %v", err)
			}
			defer FlushContext{FlushHandle: load.ObjectHandle}.Execute(tpm)

			unseal, err := Unseal{
				ItemHandle: NamedHandle{
					Handle: load.ObjectHandle,
					Name:   *sealedName,
				},
			}.Execute(tpm)
			if err != nil {
				t.Fatalf("Unseal() = %v", err)
			}

			if !bytes.Equal(unseal.OutData.Buffer, plaintext) {
				t.Errorf("Unseal() = %x, want %x", unseal.OutData.Buffer, plaintext)
			}
		})
	}
}

package tpm2test

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestHMAC(t *testing.T) {
	// connect to TPM simulator
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// create HMAC key
	createPrimary := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgKeyedHash,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				SignEncrypt:         true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: NewTPMUPublicParms(TPMAlgKeyedHash,
				&TPMSKeyedHashParms{
					Scheme: TPMTKeyedHashScheme{
						Scheme: TPMAlgHMAC,
						Details: NewTPMUSchemeKeyedHash(TPMAlgHMAC,
							&TPMSSchemeHMAC{
								HashAlg: TPMAlgSHA256,
							}),
					},
				}),
		}),
	}

	rspCP, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary HMAC key failed: %v", err)
	}

	flushContext := FlushContext{FlushHandle: rspCP.ObjectHandle}
	defer func() {
		_, _ = flushContext.Execute(thetpm)
	}()

	data := []byte("test")

	hmacCmd := Hmac{
		Handle: AuthHandle{
			Handle: rspCP.ObjectHandle,
			Name:   rspCP.Name,
			Auth:   PasswordAuth(nil),
		},
		Buffer:  TPM2BMaxBuffer{Buffer: data},
		HashAlg: TPMAlgSHA256,
	}

	// HMAC Key is not exportable and cannot be known.
	// Calculate HMAC twice and confirm they are the same.
	hmac1, err := hmacCmd.Execute(thetpm)
	if err != nil {
		t.Errorf("TPM2_HMAC failed: %v", err)
	}
	hmac2, err := hmacCmd.Execute(thetpm)
	if err != nil {
		t.Errorf("TPM2_HMAC failed: %v", err)
	}
	if !bytes.Equal(hmac1.OutHMAC.Buffer, hmac2.OutHMAC.Buffer) {
		t.Errorf("TPM2_HMAC failed: hmacs are different")
	}
}

func TestImportedHMACKey(t *testing.T) {
	// configurable values
	data := []byte("input data")
	keySensitive := []byte("the hmac key")
	persistentHandle := TPMHandle(0x81000000)

	// connect to TPM simulator
	theTPM, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer theTPM.Close()

	// create primary key
	primaryKey, err := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(RSASRKTemplate),
	}.Execute(theTPM)

	if err != nil {
		t.Fatalf("could not generate SRK: %v", err)
	}

	// hmac template
	sv := make([]byte, 32)
	io.ReadFull(rand.Reader, sv)
	privHash := crypto.SHA256.New()
	privHash.Write(sv)
	privHash.Write(keySensitive)

	hmacTemplate := TPMTPublic{
		Type:    TPMAlgKeyedHash,
		NameAlg: TPMAlgSHA256,
		ObjectAttributes: TPMAObject{
			UserWithAuth: true,
			SignEncrypt:  true,
		},
		AuthPolicy: TPM2BDigest{},
		Parameters: NewTPMUPublicParms(TPMAlgKeyedHash,
			&TPMSKeyedHashParms{
				Scheme: TPMTKeyedHashScheme{
					Scheme: TPMAlgHMAC,
					Details: NewTPMUSchemeKeyedHash(TPMAlgHMAC,
						&TPMSSchemeHMAC{
							HashAlg: TPMAlgSHA256,
						}),
				},
			}),
		Unique: NewTPMUPublicID(
			TPMAlgKeyedHash,
			&TPM2BDigest{
				Buffer: privHash.Sum(nil),
			},
		),
	}

	// sensitive data
	sens2B := Marshal(TPMTSensitive{
		SensitiveType: TPMAlgKeyedHash,
		AuthValue:     TPM2BAuth{},
		SeedValue: TPM2BDigest{
			Buffer: sv,
		},
		Sensitive: NewTPMUSensitiveComposite(
			TPMAlgKeyedHash,
			&TPM2BSensitiveData{Buffer: keySensitive},
		),
	})

	l := Marshal(TPM2BPrivate{Buffer: sens2B})

	// import hmac key
	importResponse, err := Import{
		ParentHandle: AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   PasswordAuth(nil),
		},
		ObjectPublic: New2B(hmacTemplate),
		Duplicate:    TPM2BPrivate{Buffer: l},
	}.Execute(theTPM)
	if err != nil {
		t.Fatalf("could not import hmac key: %v", err)
	}

	// load hmac key
	hmacKey, err := Load{
		ParentHandle: AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   PasswordAuth(nil),
		},
		InPublic:  New2B(hmacTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(theTPM)
	if err != nil {
		t.Fatalf("could not load hmac key: %v", err)
	}

	FlushContext{FlushHandle: primaryKey.ObjectHandle}.Execute(theTPM)

	// persist hmac key
	_, err = EvictControl{
		Auth: TPMRHOwner,
		ObjectHandle: &NamedHandle{
			Handle: hmacKey.ObjectHandle,
			Name:   hmacKey.Name,
		},
		PersistentHandle: persistentHandle,
	}.Execute(theTPM)
	if err != nil {
		t.Fatalf("could not persist hmac key: %v", err)
	}

	FlushContext{FlushHandle: hmacKey.ObjectHandle}.Execute(theTPM)

	// calculate hmac using TPM
	hmacCmd := Hmac{
		Handle: AuthHandle{
			Handle: persistentHandle,
			Name:   ReadPublicName(t, persistentHandle, theTPM),
			Auth:   PasswordAuth(nil),
		},
		Buffer:  TPM2BMaxBuffer{Buffer: data},
		HashAlg: TPMAlgSHA256,
	}

	rspHMAC, err := hmacCmd.Execute(theTPM)
	if err != nil {
		t.Fatalf("TPM2_HMAC failed: %v", err)
	}

	// calculate hmac in usual way
	hmacSha256 := hmac.New(sha256.New, keySensitive)
	hmacSha256.Write(data)
	result := hmacSha256.Sum(nil)

	// compare hmac results
	if !bytes.Equal(result, rspHMAC.OutHMAC.Buffer) {
		t.Errorf("want %x got %x", result, rspHMAC.OutHMAC.Buffer)
	}
}

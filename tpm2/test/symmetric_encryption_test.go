package tpm2test

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"io"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

const maxDigestBuffer = 1024

func TestAESEncryption(t *testing.T) {
	theTpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	t.Cleanup(func() {
		if err := theTpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	primary, err := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgSymCipher,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				UserWithAuth:        true,
				SensitiveDataOrigin: true,
				Decrypt:             true,
				SignEncrypt:         true,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgSymCipher,
				&TPMSSymCipherParms{
					Sym: TPMTSymDefObject{
						Algorithm: TPMAlgAES,
						Mode:      NewTPMUSymMode(TPMAlgAES, TPMAlgCFB),
						KeyBits: NewTPMUSymKeyBits(
							TPMAlgAES,
							TPMKeyBits(128),
						),
					},
				},
			),
		}),
	}.Execute(theTpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Cleanup(func() {
		flushContextCmd := FlushContext{FlushHandle: primary.ObjectHandle}
		if _, err := flushContextCmd.Execute(theTpm); err != nil {
			t.Errorf("%v", err)
		}
	})

	message := []byte("secret")

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		t.Errorf("%v", err)
	}

	keyAuth := AuthHandle{
		Handle: primary.ObjectHandle,
		Name:   primary.Name,
		Auth:   PasswordAuth(nil),
	}

	// test encryption
	encryptRsp, err := EncryptDecrypt2{
		KeyHandle: keyAuth,
		Message: TPM2BMaxBuffer{
			Buffer: message,
		},
		Mode:    TPMAlgCFB,
		Decrypt: false,
		IV: TPM2BIV{
			Buffer: iv,
		},
	}.Execute(theTpm)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// test decryption
	decryptRsp, err := EncryptDecrypt2{
		KeyHandle: keyAuth,
		Message: TPM2BMaxBuffer{
			Buffer: encryptRsp.OutData.Buffer,
		},
		Mode:    TPMAlgCFB,
		Decrypt: true,
		IV: TPM2BIV{
			Buffer: iv,
		},
	}.Execute(theTpm)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(message, decryptRsp.OutData.Buffer) {
		t.Errorf("want %x got %x", message, decryptRsp.OutData.Buffer)
	}
}

func TestAESEncryptionBlock(t *testing.T) {
	theTpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	t.Cleanup(func() {
		if err := theTpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	primary, err := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgSymCipher,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				UserWithAuth:        true,
				SensitiveDataOrigin: true,
				Decrypt:             true,
				SignEncrypt:         true,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgSymCipher,
				&TPMSSymCipherParms{
					Sym: TPMTSymDefObject{
						Algorithm: TPMAlgAES,
						Mode:      NewTPMUSymMode(TPMAlgAES, TPMAlgCFB),
						KeyBits: NewTPMUSymKeyBits(
							TPMAlgAES,
							TPMKeyBits(128),
						),
					},
				},
			),
		}),
	}.Execute(theTpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Cleanup(func() {
		flushContextCmd := FlushContext{FlushHandle: primary.ObjectHandle}
		if _, err := flushContextCmd.Execute(theTpm); err != nil {
			t.Errorf("%v", err)
		}
	})

	message := make([]byte, 2048)
	_, err = rand.Read(message)
	if err != nil {
		t.Errorf("%v", err)
	}

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		t.Errorf("%v", err)
	}

	keyAuth := AuthHandle{
		Handle: primary.ObjectHandle,
		Name:   primary.Name,
		Auth:   PasswordAuth(nil),
	}

	// test encryption

	encrypted, err := encryptDecryptSymmetric(theTpm, keyAuth, iv, message, TPMAlgCFB, false)
	if err != nil {
		t.Errorf("%v", err)
	}

	decrypted, err := encryptDecryptSymmetric(theTpm, keyAuth, iv, encrypted, TPMAlgCFB, true)
	if err != nil {
		t.Errorf("%v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Errorf("want %x got %x", message, decrypted)
	}
}

func encryptDecryptSymmetric(rwr transport.TPM, keyAuth AuthHandle, iv, data []byte, mode TPMAlgID, decrypt bool) ([]byte, error) {
	var out, block []byte

	for rest := data; len(rest) > 0; {
		if len(rest) > maxDigestBuffer {
			block, rest = rest[:maxDigestBuffer], rest[maxDigestBuffer:]
		} else {
			block, rest = rest, nil
		}
		r, err := EncryptDecrypt2{
			KeyHandle: keyAuth,
			Message: TPM2BMaxBuffer{
				Buffer: block,
			},
			Mode:    mode,
			Decrypt: decrypt,
			IV: TPM2BIV{
				Buffer: iv,
			},
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		block = r.OutData.Buffer
		iv = r.IV.Buffer
		out = append(out, block...)
	}
	return out, nil
}

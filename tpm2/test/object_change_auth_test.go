package tpm2test

import (
	"bytes"
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestObjectChangeAuth(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// Create the SRK
	// Put a password on the SRK to test more of the flows.
	createSRKCmd := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: &TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
		InPublic: New2B(ECCSRKTemplate),
	}
	createSRKRsp, err := createSRKCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the SRK
		flushSRKCmd := FlushContext{FlushHandle: createSRKRsp.ObjectHandle}
		if _, err := flushSRKCmd.Execute(thetpm); err != nil {
			t.Errorf("%v", err)
		}
	}()

	// Data we are sealing
	data := []byte("secrets")

	// Original auth for the key
	auth := []byte("oldauth")

	// New auth we are changing to
	newauth := []byte("newauth")

	// Create a sealed blob under the SRK
	createBlobCmd := Create{
		ParentHandle: AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   PasswordAuth(nil),
		},
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: &TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
					Buffer: auth,
				},
				Data: NewTPMUSensitiveCreate(&TPM2BSensitiveData{
					Buffer: data,
				}),
			},
		},
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgKeyedHash,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				NoDA:         true,
			},
		}),
	}

	var createBlobRsp *CreateResponse

	t.Run("Create", func(t *testing.T) {
		createBlobRsp, err = createBlobCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	loadBlobCmd := Load{
		ParentHandle: AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   PasswordAuth(nil),
		},
		InPrivate: createBlobRsp.OutPrivate,
		InPublic:  createBlobRsp.OutPublic,
	}
	loadBlobRsp, err := loadBlobCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the blob
		flushBlobCmd := FlushContext{FlushHandle: loadBlobRsp.ObjectHandle}
		if _, err := flushBlobCmd.Execute(thetpm); err != nil {
			t.Errorf("%v", err)
		}
	}()

	unsealCmd := Unseal{
		ItemHandle: NamedHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
		},
	}

	// Unseal the blob with a password session
	t.Run("WithPassword", func(t *testing.T) {
		unsealCmd.ItemHandle = AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth:   PasswordAuth(auth),
		}
		unsealRsp, err := unsealCmd.Execute(thetpm)
		if err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Change the auth of the object
	t.Run("ObjectChangeAuth", func(t *testing.T) {
		oca := ObjectChangeAuth{
			ObjectHandle: AuthHandle{
				Handle: loadBlobRsp.ObjectHandle,
				Name:   loadBlobRsp.Name,
				Auth:   PasswordAuth(auth),
			},
			ParentHandle: NamedHandle{
				Handle: createSRKRsp.ObjectHandle,
				Name:   createSRKRsp.Name,
			},
			NewAuth: TPM2BAuth{
				Buffer: newauth,
			},
		}

		ocaRsp, err := oca.Execute(thetpm)
		if err != nil {
			t.Fatalf("failed objectchangeauthrequest: %v", err)
		}

		// Flush the old handle
		flushBlobCmd := FlushContext{FlushHandle: loadBlobRsp.ObjectHandle}
		if _, err := flushBlobCmd.Execute(thetpm); err != nil {
			t.Errorf("%v", err)
		}

		// Load the new private blob, and the old public blob
		loadBlobCmd := Load{
			ParentHandle: AuthHandle{
				Handle: createSRKRsp.ObjectHandle,
				Name:   createSRKRsp.Name,
				Auth:   PasswordAuth(nil),
			},
			InPrivate: ocaRsp.OutPrivate,
			InPublic:  createBlobRsp.OutPublic,
		}
		loadBlobRsp, err = loadBlobCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Unseal the blob with a password session
	t.Run("WithOldPassword", func(t *testing.T) {
		unsealCmd.ItemHandle = AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth:   PasswordAuth(auth),
		}
		_, err := unsealCmd.Execute(thetpm)
		if !errors.Is(err, TPMRCBadAuth) {
			t.Errorf("want TPM_RC_BAD_AUTH, got %v", err)
		}
		var fmt1 TPMFmt1Error
		if !errors.As(err, &fmt1) {
			t.Errorf("want a Fmt1Error, got %v", err)
		} else if isSession, session := fmt1.Session(); !isSession || session != 1 {
			t.Errorf("want TPM_RC_BAD_AUTH on session 1, got %v", err)
		}
	})

	t.Run("WithNewPassword", func(t *testing.T) {
		unsealCmd.ItemHandle = AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth:   PasswordAuth(newauth),
		}
		unsealRsp, err := unsealCmd.Execute(thetpm)
		if err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})
}

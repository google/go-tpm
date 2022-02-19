package tpm2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	"github.com/google/go-tpm/direct/templates"
	"github.com/google/go-tpm/direct/transport/simulator"
)

// Test creating and unsealing a sealed data blob with a password and HMAC.
func TestUnseal(t *testing.T) {
	templates := map[string]tpm2b.Public{
		"RSA": templates.RSASRKTemplate,
		"ECC": templates.ECCSRKTemplate,
	}

	// Run the whole test for each of RSA and ECC SRKs.
	for name, srkTemplate := range templates {
		t.Run(name, func(t *testing.T) {
			unsealingTest(t, srkTemplate)
		})
	}
}

func unsealingTest(t *testing.T, srkTemplate tpm2b.Public) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// Create the SRK
	// Put a password on the SRK to test more of the flows.
	srkAuth := []byte("mySRK")
	createSRKCmd := CreatePrimary{
		PrimaryHandle: tpm.RHOwner,
		InSensitive: tpm2b.SensitiveCreate{
			Sensitive: tpms.SensitiveCreate{
				UserAuth: tpm2b.Auth{
					Buffer: srkAuth,
				},
			},
		},
		InPublic: srkTemplate,
	}
	createSRKRsp, err := createSRKCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("SRK name: %x", createSRKRsp.Name)
	defer func() {
		// Flush the SRK
		flushSRKCmd := FlushContext{createSRKRsp.ObjectHandle}
		if _, err := flushSRKCmd.Execute(thetpm); err != nil {
			t.Errorf("%v", err)
		}
	}()

	// Create a sealed blob under the SRK
	data := []byte("secrets")
	// Include some trailing zeros to exercise the TPM's trimming of them from auth values.
	auth := []byte("p@ssw0rd\x00\x00")
	auth2 := []byte("p@ssw0rd")
	createBlobCmd := Create{
		ParentHandle: AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   PasswordAuth(srkAuth),
		},
		InSensitive: tpm2b.SensitiveCreate{
			Sensitive: tpms.SensitiveCreate{
				UserAuth: tpm2b.Auth{
					Buffer: auth,
				},
				Data: tpm2b.Data{
					Buffer: data,
				},
			},
		},
		InPublic: tpm2b.Public{
			PublicArea: tpmt.Public{
				Type:    tpm.AlgKeyedHash,
				NameAlg: tpm.AlgSHA256,
				ObjectAttributes: tpma.Object{
					FixedTPM:     true,
					FixedParent:  true,
					UserWithAuth: true,
					NoDA:         true,
				},
			},
		},
	}
	var createBlobRsp *CreateResponse

	// Create the blob with password auth, without any session encryption
	t.Run("Create", func(t *testing.T) {
		createBlobRsp, err = createBlobCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob using an hmac auth session also for audit
	t.Run("CreateAudit", func(t *testing.T) {
		createBlobCmd.ParentHandle = AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   HMAC(tpm.AlgSHA256, 16, Auth(srkAuth), AuditExclusive()),
		}

		createBlobRsp, err = createBlobCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, using the auth session also for decryption
	t.Run("CreateDecrypt", func(t *testing.T) {
		createBlobCmd.ParentHandle = AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   HMAC(tpm.AlgSHA256, 16, Auth(srkAuth), AESEncryption(128, EncryptIn)),
		}
		createBlobRsp, err = createBlobCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, using the auth session also for encryption
	t.Run("CreateEncrypt", func(t *testing.T) {
		createBlobCmd.ParentHandle = AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   HMAC(tpm.AlgSHA256, 16, Auth(srkAuth), AESEncryption(128, EncryptOut)),
		}
		createBlobRsp, err = createBlobCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, using the auth session also for decrypt and encrypt
	t.Run("CreateDecryptEncrypt", func(t *testing.T) {
		createBlobCmd.ParentHandle = AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   HMAC(tpm.AlgSHA256, 16, Auth(srkAuth), AESEncryption(128, EncryptInOut)),
		}
		createBlobRsp, err = createBlobCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with decrypt and encrypt session
	t.Run("CreateDecryptEncryptAudit", func(t *testing.T) {
		createBlobCmd.ParentHandle = AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth: HMAC(tpm.AlgSHA256, 16, Auth(srkAuth),
				AESEncryption(128, EncryptInOut),
				Audit()),
		}
		createBlobRsp, err = createBlobCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with decrypt and encrypt session bound to SRK
	t.Run("CreateDecryptEncryptSalted", func(t *testing.T) {
		createBlobCmd.ParentHandle = AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth: HMAC(tpm.AlgSHA256, 16, Auth(srkAuth),
				AESEncryption(128, EncryptInOut),
				Salted(createSRKRsp.ObjectHandle, createSRKRsp.OutPublic.PublicArea)),
		}
		createBlobRsp, err = createBlobCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Use HMAC auth to authorize the rest of the Create commands
	// Exercise re-using a use-once HMAC structure (which will spin up the session each time)
	createBlobCmd.ParentHandle = AuthHandle{
		Handle: createSRKRsp.ObjectHandle,
		Name:   createSRKRsp.Name,
		Auth:   HMAC(tpm.AlgSHA256, 16, Auth(srkAuth)),
	}
	// Create the blob with a separate decrypt and encrypt session
	t.Run("CreateDecryptEncryptSeparate", func(t *testing.T) {
		createBlobRsp, err = createBlobCmd.Execute(thetpm,
			HMAC(tpm.AlgSHA256, 16, AESEncryption(128, EncryptInOut)))
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with a separate decrypt and encrypt session, and another for audit
	t.Run("CreateDecryptEncryptAuditSeparate", func(t *testing.T) {
		createBlobRsp, err = createBlobCmd.Execute(thetpm,
			HMAC(tpm.AlgSHA256, 16, AESEncryption(128, EncryptInOut)),
			HMAC(tpm.AlgSHA256, 16, Audit()))
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with a separate decrypt and encrypt session, and another for exclusive audit
	t.Run("CreateDecryptEncryptAuditExclusiveSeparate", func(t *testing.T) {
		createBlobRsp, err = createBlobCmd.Execute(thetpm,
			HMAC(tpm.AlgSHA256, 16, AESEncryption(128, EncryptInOut)),
			HMAC(tpm.AlgSHA256, 16, AuditExclusive()))
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with separate decrypt and encrypt sessions.
	t.Run("CreateDecryptEncrypt2Separate", func(t *testing.T) {
		createBlobRsp, err = createBlobCmd.Execute(thetpm,
			// Get weird with the algorithm and nonce choices. Mix lots of things together.
			HMAC(tpm.AlgSHA1, 20, AESEncryption(128, EncryptIn)),
			HMAC(tpm.AlgSHA384, 23, AESEncryption(128, EncryptOut)))
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with separate encrypt and decrypt sessions.
	// (The TPM spec orders some extra nonces included in the first session in the order
	// nonceTPM_decrypt, nonceTPM_encrypt, so this exercises that)
	t.Run("CreateDecryptEncrypt2Separate", func(t *testing.T) {
		createBlobRsp, err = createBlobCmd.Execute(thetpm,
			HMAC(tpm.AlgSHA1, 17, AESEncryption(128, EncryptOut)),
			HMAC(tpm.AlgSHA256, 32, AESEncryption(128, EncryptIn)))
		if err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Load the sealed blob
	loadBlobCmd := Load{
		ParentHandle: AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   HMAC(tpm.AlgSHA256, 16, Auth(srkAuth)),
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
		flushBlobCmd := FlushContext{loadBlobRsp.ObjectHandle}
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

	// Unseal the blob with an incorrect password session
	t.Run("WithWrongPassword", func(t *testing.T) {
		unsealCmd.ItemHandle = AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth:   PasswordAuth([]byte("NotThePassword")),
		}
		_, err := unsealCmd.Execute(thetpm)
		if !errors.Is(err, tpm.RCBadAuth) {
			t.Errorf("want TPM_RC_BAD_AUTH, got %v", err)
		}
		var fmt1 tpm.Fmt1Error
		if !errors.As(err, &fmt1) {
			t.Errorf("want a Fmt1Error, got %v", err)
		} else if isSession, session := fmt1.Session(); !isSession || session != 1 {
			t.Errorf("want TPM_RC_BAD_AUTH on session 1, got %v", err)
		}
	})

	// Unseal the blob with a use-once HMAC session
	t.Run("WithHMAC", func(t *testing.T) {
		unsealCmd.ItemHandle = AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth:   HMAC(tpm.AlgSHA256, 16, Auth(auth2)),
		}
		unsealRsp, err := unsealCmd.Execute(thetpm)
		if err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Unseal the blob with a use-once HMAC session with encryption
	t.Run("WithHMACEncrypt", func(t *testing.T) {
		unsealCmd.ItemHandle = AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth: HMAC(tpm.AlgSHA256, 16, Auth(auth2),
				AESEncryption(128, EncryptOut)),
		}
		unsealRsp, err := unsealCmd.Execute(thetpm)
		if err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Unseal the blob with a standalone HMAC session, re-using the session.
	t.Run("WithHMACSession", func(t *testing.T) {
		sess, cleanup, err := HMACSession(thetpm, tpm.AlgSHA1, 20, Auth(auth2))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup()
		unsealCmd.ItemHandle = AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth:   sess,
		}

		// It should be possible to use the session multiple times.
		for i := 0; i < 3; i++ {
			unsealRsp, err := unsealCmd.Execute(thetpm)
			if err != nil {
				t.Errorf("%v", err)
			}
			if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
				t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
			}
		}
	})

	// Unseal the blob with a standalone bound HMAC session, re-using the session.
	// Also, use session encryption.
	t.Run("WithHMACSessionEncrypt", func(t *testing.T) {
		sess, cleanup, err := HMACSession(thetpm, tpm.AlgSHA256, 16, Auth(auth2),
			AESEncryption(128, EncryptOut),
			Bound(createSRKRsp.ObjectHandle, createSRKRsp.Name, srkAuth))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup()
		unsealCmd.ItemHandle = AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth:   sess,
		}

		// It should be possible to use the session multiple times.
		for i := 0; i < 3; i++ {
			unsealRsp, err := unsealCmd.Execute(thetpm)
			if err != nil {
				t.Errorf("%v", err)
			}
			if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
				t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
			}
		}
	})

	// Unseal the blob with a standalone HMAC session, re-using the session.
	// Spin up another bound session for encryption.
	t.Run("WithHMACSessionEncryptSeparate", func(t *testing.T) {
		sess1, cleanup1, err := HMACSession(thetpm, tpm.AlgSHA1, 16, Auth(auth2))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup1()
		sess2, cleanup2, err := HMACSession(thetpm, tpm.AlgSHA384, 16,
			AESEncryption(128, EncryptOut),
			Bound(createSRKRsp.ObjectHandle, createSRKRsp.Name, srkAuth))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup2()
		unsealCmd.ItemHandle = AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth:   sess1,
		}

		// It should be possible to use the sessions multiple times.
		for i := 0; i < 3; i++ {
			unsealRsp, err := unsealCmd.Execute(thetpm, sess2)
			if err != nil {
				t.Errorf("%v", err)
			}
			if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
				t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
			}
		}
	})
}

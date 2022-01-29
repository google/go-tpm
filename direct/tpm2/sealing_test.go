package tpm2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
)

// Test creating and unsealing a sealed data blob with a password and HMAC.
func TestUnseal(t *testing.T) {
	templates := map[string]TPM2BPublic{
		"RSA": RSASRKTemplate,
		"ECC": ECCSRKTemplate,
	}

	// Run the whole test for each of RSA and ECC SRKs.
	for name, srkTemplate := range templates {
		t.Run(name, func(t *testing.T) {
			unsealingTest(t, srkTemplate)
		})
	}
}

func unsealingTest(t *testing.T, srkTemplate TPM2BPublic) {
	sim, err := simulator.Get()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	tpm := NewTPM(sim)
	defer tpm.Close()

	// Create the SRK
	// Put a password on the SRK to test more of the flows.
	srkAuth := []byte("mySRK")
	createSRKCmd := CreatePrimaryCommand{
		PrimaryHandle: AuthHandle{
			Handle: TPMRHOwner,
		},
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
					Buffer: srkAuth,
				},
			},
		},
		InPublic: srkTemplate,
	}
	var createSRKRsp CreatePrimaryResponse
	if err := tpm.Execute(&createSRKCmd, &createSRKRsp); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("SRK name: %x", createSRKRsp.Name)
	defer func() {
		// Flush the SRK
		flushSRKCmd := FlushContextCommand{
			FlushHandle: createSRKRsp.ObjectHandle,
		}
		var flushSRKRsp FlushContextResponse
		if err := tpm.Execute(&flushSRKCmd, &flushSRKRsp); err != nil {
			t.Errorf("%v", err)
		}
	}()

	// Create a sealed blob under the SRK
	data := []byte("secrets")
	// Include some trailing zeros to exercise the TPM's trimming of them from auth values.
	auth := []byte("p@ssw0rd\x00\x00")
	auth2 := []byte("p@ssw0rd")
	createBlobCmd := CreateCommand{
		ParentHandle: AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   PasswordAuth(srkAuth),
		},
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
					Buffer: auth,
				},
				Data: TPM2BData{
					Buffer: data,
				},
			},
		},
		InPublic: TPM2BPublic{
			PublicArea: TPMTPublic{
				Type:    TPMAlgKeyedHash,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					FixedTPM:     true,
					FixedParent:  true,
					UserWithAuth: true,
					NoDA:         true,
				},
			},
		},
	}
	var createBlobRsp CreateResponse

	// Create the blob with password auth, without any session encryption
	t.Run("Create", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob using an hmac auth session also for audit
	t.Run("CreateAudit", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			HMAC(TPMAlgSHA256, 16, Auth(srkAuth),
				AuditExclusive())
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, using the auth session also for decryption
	t.Run("CreateDecrypt", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			HMAC(TPMAlgSHA256, 16, Auth(srkAuth),
				AESEncryption(128, EncryptIn))
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, using the auth session also for encryption
	t.Run("CreateEncrypt", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			HMAC(TPMAlgSHA256, 16, Auth(srkAuth),
				AESEncryption(128, EncryptOut))
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob, using the auth session also for decrypt and encrypt
	t.Run("CreateDecryptEncrypt", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			HMAC(TPMAlgSHA256, 16, Auth(srkAuth),
				AESEncryption(128, EncryptInOut))
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with decrypt and encrypt session
	t.Run("CreateDecryptEncryptAudit", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			HMAC(TPMAlgSHA256, 16, Auth(srkAuth),
				AESEncryption(128, EncryptInOut),
				Audit())
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with decrypt and encrypt session bound to SRK
	t.Run("CreateDecryptEncryptSalted", func(t *testing.T) {
		createBlobCmd.ParentHandle.Auth =
			HMAC(TPMAlgSHA256, 16, Auth(srkAuth),
				AESEncryption(128, EncryptInOut),
				Salted(createSRKRsp.ObjectHandle, createSRKRsp.OutPublic.PublicArea))
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Use HMAC auth to authorize the rest of the Create commands
	// Exercise re-using a use-once HMAC structure (which will spin up the session each time)
	createBlobCmd.ParentHandle.Auth = HMAC(TPMAlgSHA256, 16, Auth(srkAuth))
	// Create the blob with a separate decrypt and encrypt session
	t.Run("CreateDecryptEncryptSeparate", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			HMAC(TPMAlgSHA256, 16, AESEncryption(128, EncryptInOut))); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with a separate decrypt and encrypt session, and another for audit
	t.Run("CreateDecryptEncryptAuditSeparate", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			HMAC(TPMAlgSHA256, 16, AESEncryption(128, EncryptInOut)),
			HMAC(TPMAlgSHA256, 16, Audit())); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with a separate decrypt and encrypt session, and another for exclusive audit
	t.Run("CreateDecryptEncryptAuditExclusiveSeparate", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			HMAC(TPMAlgSHA256, 16, AESEncryption(128, EncryptInOut)),
			HMAC(TPMAlgSHA256, 16, AuditExclusive())); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with separate decrypt and encrypt sessions.
	t.Run("CreateDecryptEncrypt2Separate", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			// Get weird with the algorithm and nonce choices. Mix lots of things together.
			HMAC(TPMAlgSHA1, 20, AESEncryption(128, EncryptIn)),
			HMAC(TPMAlgSHA384, 23, AESEncryption(128, EncryptOut))); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Create the blob with separate encrypt and decrypt sessions.
	// (The TPM spec orders some extra nonces included in the first session in the order
	// nonceTPM_decrypt, nonceTPM_encrypt, so this exercises that)
	t.Run("CreateDecryptEncrypt2Separate", func(t *testing.T) {
		if err := tpm.Execute(&createBlobCmd, &createBlobRsp,
			HMAC(TPMAlgSHA1, 17, AESEncryption(128, EncryptOut)),
			HMAC(TPMAlgSHA256, 32, AESEncryption(128, EncryptIn))); err != nil {
			t.Fatalf("%v", err)
		}
	})

	// Load the sealed blob
	loadBlobCmd := LoadCommand{
		ParentHandle: AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   HMAC(TPMAlgSHA256, 16, Auth(srkAuth)),
		},
		InPrivate: createBlobRsp.OutPrivate,
		InPublic:  createBlobRsp.OutPublic,
	}
	var loadBlobRsp LoadResponse
	if err := tpm.Execute(&loadBlobCmd, &loadBlobRsp); err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the blob
		flushBlobCmd := FlushContextCommand{
			FlushHandle: loadBlobRsp.ObjectHandle,
		}
		var flushBlobRsp FlushContextResponse
		if err := tpm.Execute(&flushBlobCmd, &flushBlobRsp); err != nil {
			t.Errorf("%v", err)
		}
	}()

	unsealCmd := UnsealCommand{
		ItemHandle: AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
		},
	}
	var unsealRsp UnsealResponse
	// Unseal the blob with a password session
	t.Run("WithPassword", func(t *testing.T) {
		unsealCmd.ItemHandle.Auth = PasswordAuth(auth)
		if err := tpm.Execute(&unsealCmd, &unsealRsp); err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Unseal the blob with an incorrect password session
	t.Run("WithWrongPassword", func(t *testing.T) {
		unsealCmd.ItemHandle.Auth = PasswordAuth([]byte("NotThePassword"))
		err := tpm.Execute(&unsealCmd, &unsealRsp)
		if err == nil {
			t.Errorf("want TPM_RC_BAD_AUTH, got nil")
		}
		if !errors.Is(err, TPMRCBadAuth) {
			t.Errorf("want TPM_RC_BAD_AUTH, got %v", err)
		}
		var fmt1 Fmt1Error
		if !errors.As(err, &fmt1) {
			t.Errorf("want a Fmt1Error, got %v", err)
		} else if isSession, session := fmt1.Session(); !isSession || session != 1 {
			t.Errorf("want TPM_RC_BAD_AUTH on session 1, got %v", err)
		}
	})

	// Unseal the blob with a use-once HMAC session
	t.Run("WithHMAC", func(t *testing.T) {
		unsealCmd.ItemHandle.Auth = HMAC(TPMAlgSHA256, 16, Auth(auth2))
		if err := tpm.Execute(&unsealCmd, &unsealRsp); err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Unseal the blob with a use-once HMAC session with encryption
	t.Run("WithHMACEncrypt", func(t *testing.T) {
		unsealCmd.ItemHandle.Auth = HMAC(TPMAlgSHA256, 16, Auth(auth2),
			AESEncryption(128, EncryptOut))
		if err := tpm.Execute(&unsealCmd, &unsealRsp); err != nil {
			t.Errorf("%v", err)
		}
		if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
			t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
		}
	})

	// Unseal the blob with a standalone HMAC session, re-using the session.
	t.Run("WithHMACSession", func(t *testing.T) {
		sess, cleanup, err := HMACSession(tpm, TPMAlgSHA1, 20, Auth(auth2))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup()
		unsealCmd.ItemHandle.Auth = sess

		// It should be possible to use the session multiple times.
		for i := 0; i < 3; i++ {
			if err := tpm.Execute(&unsealCmd, &unsealRsp); err != nil {
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
		sess, cleanup, err := HMACSession(tpm, TPMAlgSHA256, 16, Auth(auth2),
			AESEncryption(128, EncryptOut),
			Bound(createSRKRsp.ObjectHandle, createSRKRsp.Name, srkAuth))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup()
		unsealCmd.ItemHandle.Auth = sess

		// It should be possible to use the session multiple times.
		for i := 0; i < 3; i++ {
			if err := tpm.Execute(&unsealCmd, &unsealRsp); err != nil {
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
		sess1, cleanup1, err := HMACSession(tpm, TPMAlgSHA1, 16, Auth(auth2))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup1()
		sess2, cleanup2, err := HMACSession(tpm, TPMAlgSHA384, 16,
			AESEncryption(128, EncryptOut),
			Bound(createSRKRsp.ObjectHandle, createSRKRsp.Name, srkAuth))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer cleanup2()
		unsealCmd.ItemHandle.Auth = sess1

		// It should be possible to use the sessions multiple times.
		for i := 0; i < 3; i++ {
			if err := tpm.Execute(&unsealCmd, &unsealRsp, sess2); err != nil {
				t.Errorf("%v", err)
			}
			if !bytes.Equal(unsealRsp.OutData.Buffer, data) {
				t.Errorf("want %x got %x", data, unsealRsp.OutData.Buffer)
			}
		}
	})
}

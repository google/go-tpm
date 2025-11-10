package tpm2test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestAuditSession(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// Create the audit session
	sess, cleanup, err := HMACSession(thetpm, TPMAlgSHA256, 16, Audit())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer cleanup()

	// Create the AK for audit
	createAKCmd := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgECC,
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
				Restricted:           true,
				Decrypt:              false,
				SignEncrypt:          true,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgECC,
				&TPMSECCParms{
					Scheme: TPMTECCScheme{
						Scheme: TPMAlgECDSA,
						Details: NewTPMUAsymScheme(
							TPMAlgECDSA,
							&TPMSSigSchemeECDSA{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
					CurveID: TPMECCNistP256,
				},
			),
		},
		),
	}
	createAKRsp, err := createAKCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the AK
		flush := FlushContext{FlushHandle: createAKRsp.ObjectHandle}
		if _, err := flush.Execute(thetpm); err != nil {
			t.Errorf("%v", err)
		}
	}()

	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("%v", err)
	}
	audit2, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var accumulatedDigest []byte
	if h, err := TPMAlgSHA256.Hash(); err == nil {
		accumulatedDigest = make([]byte, h.Size())
	} else {
		t.Fatalf("TPMAlgSHA256.Hash(): %v", err)
	}
	// Call GetCapability a bunch of times with the audit session and make sure it extends like
	// we expect it to.
	props := []TPMPT{
		TPMPTFamilyIndicator,
		TPMPTLevel,
		TPMPTRevision,
		TPMPTDayofYear,
		TPMPTYear,
		TPMPTManufacturer,
	}
	for _, prop := range props {
		getCmd := GetCapability{
			Capability:    TPMCapTPMProperties,
			Property:      uint32(prop),
			PropertyCount: 1,
		}
		getRsp, err := getCmd.Execute(thetpm, sess)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if err := AuditCommand(audit, getCmd, getRsp); err != nil {
			t.Fatalf("%v", err)
		}

		// mimic an external audit log
		auditLog := struct {
			command  []byte
			response []byte
		}{}

		cmdBytes, err := MarshalCommand(getCmd)
		if err != nil {
			t.Fatalf("MarshalCommand: %v", err)
		}
		rspBytes, err := MarshalResponse(getCmd, getRsp)
		if err != nil {
			t.Fatalf("MarshalResponse: %v", err)
		}
		auditLog.command = cmdBytes
		auditLog.response = rspBytes

		// Get the audit digest signed by the AK
		getAuditCmd := GetSessionAuditDigest{
			PrivacyAdminHandle: TPMRHEndorsement,
			SignHandle: NamedHandle{
				Handle: createAKRsp.ObjectHandle,
				Name:   createAKRsp.Name,
			},
			SessionHandle:  sess.Handle(),
			QualifyingData: TPM2BData{Buffer: []byte("foobar")},
		}
		getAuditRsp, err := getAuditCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("%v", err)
		}
		// TODO check the signature with the AK pub
		attest, err := getAuditRsp.AuditInfo.Contents()
		if err != nil {
			t.Fatalf("%v", err)
		}
		aud, err := attest.Attested.SessionAudit()
		if err != nil {
			t.Fatalf("%v", err)
		}
		want := audit.Digest()
		got := aud.SessionDigest.Buffer
		if !bytes.Equal(want, got) {
			t.Errorf("unexpected audit value:\ngot %x\nwant %x", got, want)
		}

		// This demonstrates that audit value can be replayed from an audit log
		cmd, err := UnmarshalCommand[GetCapability](auditLog.command)
		if err != nil {
			t.Fatalf("UnmarshalCommand: %v", err)
		}
		rsp, err := UnmarshalResponse[GetCapabilityResponse](auditLog.response)
		if err != nil {
			t.Fatalf("UnmarshalResponse: %v", err)
		}
		if err := AuditCommand(audit2, cmd, rsp); err != nil {
			t.Fatalf("AuditCommand: %v", err)
		}
		got2 := audit2.Digest()
		if !bytes.Equal(want, got2) {
			t.Errorf("unexpected audit value from replay:\ngot %x\nwant %x", got2, want)
		}

		// This demonstrates that MarshalCommand/MarshalResponse provide everything needed
		cpHashFromBytes := sha256.Sum256(cmdBytes)
		rpHashFromBytes := sha256.Sum256(rspBytes)

		h := sha256.New()
		h.Write(accumulatedDigest)
		h.Write(cpHashFromBytes[:])
		h.Write(rpHashFromBytes[:])
		accumulatedDigest = h.Sum(nil)

		if !bytes.Equal(want, accumulatedDigest) {
			t.Errorf("unexpected audit value from direct hash reconstruction:\ngot %x\nwant %x", want, accumulatedDigest)
		}
	}

}

// TestAuditSessionWithCertify tests audit session with a more complex command (Certify)
// which has two AuthHandles
func TestAuditSessionWithCertify(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// Create the audit session
	sess, cleanup, err := HMACSession(thetpm, TPMAlgSHA256, 16, Audit())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer cleanup()

	Auth := []byte("password")

	// Create the AK for audit
	createAKCmd := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgECC,
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
				Restricted:           true,
				Decrypt:              false,
				SignEncrypt:          true,
			},

			Parameters: NewTPMUPublicParms(
				TPMAlgECC,
				&TPMSECCParms{
					Scheme: TPMTECCScheme{
						Scheme: TPMAlgECDSA,
						Details: NewTPMUAsymScheme(
							TPMAlgECDSA,
							&TPMSSigSchemeECDSA{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
					CurveID: TPMECCNistP256,
				},
			),
		}),
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: &TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
					Buffer: Auth,
				},
			},
		},
	}

	createAKRsp, err := createAKCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the AK
		flush := FlushContext{FlushHandle: createAKRsp.ObjectHandle}
		if _, err := flush.Execute(thetpm); err != nil {
			t.Errorf("%v", err)
		}
	}()

	// Create a key to certify
	createKeyCmd := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgRSA,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Decrypt:             true,
				SignEncrypt:         true,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgRSA,
				&TPMSRSAParms{
					KeyBits: 2048,
				},
			),
		}),
	}
	createKeyRsp, err := createKeyCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		flush := FlushContext{FlushHandle: createKeyRsp.ObjectHandle}
		if _, err := flush.Execute(thetpm); err != nil {
			t.Errorf("%v", err)
		}
	}()

	originalCmd := Certify{
		ObjectHandle: AuthHandle{
			Handle: createKeyRsp.ObjectHandle,
			Name:   createKeyRsp.Name,
			Auth:   PasswordAuth(nil),
		},
		SignHandle: AuthHandle{
			Handle: createAKRsp.ObjectHandle,
			Name:   createAKRsp.Name,
			Auth:   PasswordAuth(Auth),
		},
		QualifyingData: TPM2BData{Buffer: []byte("test")},
		InScheme: TPMTSigScheme{
			Scheme: TPMAlgECDSA,
			Details: NewTPMUSigScheme(
				TPMAlgECDSA,
				&TPMSSchemeHash{
					HashAlg: TPMAlgSHA256,
				},
			),
		},
	}
	t.Logf("=== ORIGINAL COMMAND ===")
	t.Logf("ObjectHandle: %#v", originalCmd.ObjectHandle)
	t.Logf("SignHandle: %#v", originalCmd.SignHandle)

	// Execute the command with audit session
	originalRsp, err := originalCmd.Execute(thetpm, sess)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Calculate audit digest with the command/response
	audit, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := AuditCommand(audit, originalCmd, originalRsp); err != nil {
		t.Fatalf("AuditCommand: %v", err)
	}

	// Get the audit digest signed by the AK
	getAuditCmd := GetSessionAuditDigest{
		PrivacyAdminHandle: TPMRHEndorsement,
		SignHandle: AuthHandle{
			Handle: createAKRsp.ObjectHandle,
			Name:   createAKRsp.Name,
			Auth:   PasswordAuth(Auth),
		},
		SessionHandle:  sess.Handle(),
		QualifyingData: TPM2BData{Buffer: []byte("foobar")},
	}
	getAuditRsp, err := getAuditCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Verify the TPM's audit digest matches our calculated digest
	attest, err := getAuditRsp.AuditInfo.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	aud, err := attest.Attested.SessionAudit()
	if err != nil {
		t.Fatalf("%v", err)
	}
	want := aud.SessionDigest.Buffer
	got := audit.Digest()
	if !bytes.Equal(want, got) {
		t.Errorf("TPM audit digest doesn't match calculated digest:\nTPM:        %x\ncalculated: %x", want, got)
	}

	// Marshal the command and response
	cmdBytes, err := MarshalCommand(originalCmd)
	if err != nil {
		t.Fatalf("MarshalCommand: %v", err)
	}

	rspBytes, err := MarshalResponse(originalCmd, originalRsp)
	if err != nil {
		t.Fatalf("MarshalResponse: %v", err)
	}

	// Unmarshal the command
	unmarshalledCmd, err := UnmarshalCommand[Certify](cmdBytes)
	if err != nil {
		t.Fatalf("UnmarshalCommand: %v", err)
	}

	t.Logf("=== UNMARSHALLED COMMAND ===")
	t.Logf("ObjectHandle: %#v", unmarshalledCmd.ObjectHandle)
	t.Logf("SignHandle: %#v", unmarshalledCmd.SignHandle)

	// Unmarshal the response
	unmarshalledRsp, err := UnmarshalResponse[CertifyResponse](rspBytes)
	if err != nil {
		t.Fatalf("UnmarshalResponse: %v", err)
	}

	// Calculate audit digest with unmarshalled command/response
	audit2, err := NewAudit(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := AuditCommand(audit2, unmarshalledCmd, unmarshalledRsp); err != nil {
		t.Fatalf("AuditCommand (unmarshalled): %v", err)
	}
	got2 := audit2.Digest()

	// Verify unmarshalled digest matches the original calculated digest
	if !bytes.Equal(want, got2) {
		t.Errorf("unmarshalled audit digest doesn't match original:\noriginal:     %x\nunmarshalled: %x", want, got2)
	}
}

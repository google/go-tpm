package direct

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
)

func TestAuditSession(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	tpm := NewTPM(sim)
	defer tpm.Close()

	// Create the audit session
	sess, cleanup, err := HMACSession(tpm, TPMAlgSHA256, 16, Audit())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer cleanup()

	// Create the AK for audit
	createAKCmd := CreatePrimaryCommand{
		PrimaryHandle: AuthHandle{
			Handle: TPMRHOwner,
		},
		InPublic: TPM2BPublic{
			PublicArea: TPMTPublic{
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
				Parameters: TPMUPublicParms{
					ECCDetail: &TPMSECCParms{
						Scheme: TPMTECCScheme{
							Scheme: TPMAlgECDSA,
							Details: TPMUAsymScheme{
								ECDSA: &TPMSSigSchemeECDSA{
									HashAlg: TPMAlgSHA256,
								},
							},
						},
						CurveID: TPMECCNistP256,
					},
				},
			},
		},
	}
	var createAKRsp CreatePrimaryResponse
	if err := tpm.Execute(&createAKCmd, &createAKRsp); err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the AK
		flushCmd := FlushContextCommand{
			FlushHandle: createAKRsp.ObjectHandle,
		}
		var flushRsp FlushContextResponse
		if err := tpm.Execute(&flushCmd, &flushRsp); err != nil {
			t.Errorf("%v", err)
		}
	}()

	audit := NewAudit(TPMAlgSHA256)
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
		getCmd := GetCapabilityCommand{
			Capability:    TPMCapTPMProperties,
			Property:      uint32(prop),
			PropertyCount: 1,
		}
		var getRsp GetCapabilityResponse
		if err := tpm.Execute(&getCmd, &getRsp, sess); err != nil {
			t.Fatalf("%v", err)
		}
		if err := audit.Extend(&getCmd, &getRsp); err != nil {
			t.Fatalf("%v", err)
		}
		// Get the audit digest signed by the AK
		getAuditCmd := GetSessionAuditDigestCommand{
			PrivacyAdminHandle: AuthHandle{
				Handle: TPMRHEndorsement,
			},
			SignHandle: AuthHandle{
				Handle: createAKRsp.ObjectHandle,
			},
			SessionHandle:  sess.Handle(),
			QualifyingData: TPM2BData{[]byte("foobar")},
		}
		var getAuditRsp GetSessionAuditDigestResponse
		if err := tpm.Execute(&getAuditCmd, &getAuditRsp); err != nil {
			t.Errorf("%v", err)
		}
		// TODO check the signature with the AK pub
		aud := getAuditRsp.AuditInfo.AttestationData.Attested.SessionAudit
		if aud == nil {
			t.Fatalf("got nil session audit attestation")
		}
		want := audit.Digest()
		got := aud.SessionDigest.Buffer
		if !bytes.Equal(want, got) {
			t.Errorf("unexpected audit value:\ngot %x\nwant %x", got, want)
		}
	}

}

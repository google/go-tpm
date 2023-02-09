package tpm2test

import (
	"bytes"
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
	}

}

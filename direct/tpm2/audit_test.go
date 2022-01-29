package tpm2

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	"github.com/google/go-tpm/direct/structures/tpmu"
)

func TestAuditSession(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	thetpm := NewTPM(sim)
	defer thetpm.Close()

	// Create the audit session
	sess, cleanup, err := HMACSession(thetpm, tpm.AlgSHA256, 16, Audit())
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer cleanup()

	// Create the AK for audit
	createAKCmd := CreatePrimaryCommand{
		PrimaryHandle: AuthHandle{
			Handle: tpm.RHOwner,
		},
		InPublic: tpm2b.Public{
			PublicArea: tpmt.Public{
				Type:    tpm.AlgECC,
				NameAlg: tpm.AlgSHA256,
				ObjectAttributes: tpma.Object{
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
				Parameters: tpmu.PublicParms{
					ECCDetail: &tpms.ECCParms{
						Scheme: tpmt.ECCScheme{
							Scheme: tpm.AlgECDSA,
							Details: tpmu.AsymScheme{
								ECDSA: &tpms.SigSchemeECDSA{
									HashAlg: tpm.AlgSHA256,
								},
							},
						},
						CurveID: tpm.ECCNistP256,
					},
				},
			},
		},
	}
	var createAKRsp CreatePrimaryResponse
	if err := thetpm.Execute(&createAKCmd, &createAKRsp); err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		// Flush the AK
		flushCmd := FlushContextCommand{
			FlushHandle: createAKRsp.ObjectHandle,
		}
		var flushRsp FlushContextResponse
		if err := thetpm.Execute(&flushCmd, &flushRsp); err != nil {
			t.Errorf("%v", err)
		}
	}()

	audit := NewAudit(tpm.AlgSHA256)
	// Call GetCapability a bunch of times with the audit session and make sure it extends like
	// we expect it to.
	props := []tpm.PT{
		tpm.PTFamilyIndicator,
		tpm.PTLevel,
		tpm.PTRevision,
		tpm.PTDayofYear,
		tpm.PTYear,
		tpm.PTManufacturer,
	}
	for _, prop := range props {
		getCmd := GetCapabilityCommand{
			Capability:    tpm.CapTPMProperties,
			Property:      uint32(prop),
			PropertyCount: 1,
		}
		var getRsp GetCapabilityResponse
		if err := thetpm.Execute(&getCmd, &getRsp, sess); err != nil {
			t.Fatalf("%v", err)
		}
		if err := audit.Extend(&getCmd, &getRsp); err != nil {
			t.Fatalf("%v", err)
		}
		// Get the audit digest signed by the AK
		getAuditCmd := GetSessionAuditDigestCommand{
			PrivacyAdminHandle: AuthHandle{
				Handle: tpm.RHEndorsement,
			},
			SignHandle: AuthHandle{
				Handle: createAKRsp.ObjectHandle,
			},
			SessionHandle:  sess.Handle(),
			QualifyingData: tpm2b.Data{[]byte("foobar")},
		}
		var getAuditRsp GetSessionAuditDigestResponse
		if err := thetpm.Execute(&getAuditCmd, &getAuditRsp); err != nil {
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

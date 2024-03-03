package tpm2test

import (
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// TestDuplicate creates an object under Owner->SRK and duplicates it to
// Endorsement->SRK.
func TestDuplicate(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	t.Log("### Create Owner SRK")
	srkCreateResp, err := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(ECCSRKTemplate),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not generate SRK: %v", err)
	}

	srk := NamedHandle{
		Handle: srkCreateResp.ObjectHandle,
		Name:   srkCreateResp.Name,
	}

	policy, err := dupPolicyDigest(thetpm)
	if err != nil {
		t.Fatalf("dupPolicyDigest: %v", err)
	}

	keyPass := []byte("foo")

	t.Log("### Create Object to be duplicated")
	objectCreateLoadedResp, err := CreateLoaded{
		ParentHandle: srk,
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: &TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
					Buffer: keyPass,
				},
			},
		},
		InPublic: New2BTemplate(&TPMTPublic{
			Type:    TPMAlgECC,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:            false,
				FixedParent:         false,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Decrypt:             true,
				SignEncrypt:         true,
			},
			AuthPolicy: TPM2BDigest{Buffer: policy},
			Parameters: NewTPMUPublicParms(
				TPMAlgECC,
				&TPMSECCParms{
					CurveID: TPMECCNistP256,
				},
			),
			Unique: NewTPMUPublicID(
				TPMAlgECC,
				&TPMSECCPoint{
					X: TPM2BECCParameter{Buffer: make([]byte, 32)},
					Y: TPM2BECCParameter{Buffer: make([]byte, 32)},
				},
			),
		}),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("TPM2_CreateLoaded: %v", err)
	}

	// We don't need the owner SRK handle anymore.
	FlushContext{FlushHandle: srkCreateResp.ObjectHandle}.Execute(thetpm)

	t.Log("### Create Endorsement SRK (New Parent)")
	srk2CreateResp, err := CreatePrimary{
		PrimaryHandle: TPMRHEndorsement,
		InPublic:      New2B(ECCSRKTemplate),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not generate SRK: %v", err)
	}
	defer FlushContext{FlushHandle: srk2CreateResp.ObjectHandle}.Execute(thetpm)

	srk2 := NamedHandle{
		Handle: srk2CreateResp.ObjectHandle,
		Name:   srk2CreateResp.Name,
	}

	t.Log("### Duplicate Object")
	duplicateResp, err := Duplicate{
		ObjectHandle: AuthHandle{
			Handle: objectCreateLoadedResp.ObjectHandle,
			Name:   objectCreateLoadedResp.Name,
			Auth: Policy(TPMAlgSHA256, 16, PolicyCallback(func(tpm transport.TPM, handle TPMISHPolicy, _ TPM2BNonce) error {
				_, err := PolicyCommandCode{
					PolicySession: handle,
					Code:          TPMCCDuplicate,
				}.Execute(tpm)
				return err
			})),
		},
		NewParentHandle: srk2,
		Symmetric: TPMTSymDef{
			Algorithm: TPMAlgNull,
		},
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("TPM2_Duplicate: %v", err)
	}

	// We don't need the original object handle anymore.
	FlushContext{FlushHandle: objectCreateLoadedResp.ObjectHandle}.Execute(thetpm)

	t.Log("### Import Object")
	importResp, err := Import{
		ParentHandle: AuthHandle{
			Handle: srk2.Handle,
			Name:   srk2.Name,
			Auth:   PasswordAuth(nil),
		},
		ObjectPublic: objectCreateLoadedResp.OutPublic,
		Duplicate:    duplicateResp.Duplicate,
		InSymSeed:    duplicateResp.OutSymSeed,
		Symmetric: TPMTSymDef{
			Algorithm: TPMAlgNull,
		},
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("TPM2_Import: %v", err)
	}

	t.Log("### Load Imported Object")
	loadResp, err := Load{
		ParentHandle: srk2,
		InPrivate:    importResp.OutPrivate,
		InPublic:     objectCreateLoadedResp.OutPublic,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("TPM2_Load: %v", err)
	}
	defer FlushContext{FlushHandle: loadResp.ObjectHandle}.Execute(thetpm)
}

func dupPolicyDigest(thetpm transport.TPM) ([]byte, error) {
	sess, cleanup, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		return nil, err
	}
	defer cleanup()

	_, err = PolicyCommandCode{
		PolicySession: sess.Handle(),
		Code:          TPMCCDuplicate,
	}.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	pgd, err := PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(thetpm)
	if err != nil {
		return nil, err
	}
	_, err = FlushContext{FlushHandle: sess.Handle()}.Execute(thetpm)
	if err != nil {
		return nil, err
	}
	return pgd.PolicyDigest.Buffer, nil
}

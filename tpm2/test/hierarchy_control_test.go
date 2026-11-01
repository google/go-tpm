package tpm2test

import (
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

// The bits of TPMA_STARTUP_CLEAR, the value of TPM_PT_STARTUP_CLEAR.
const (
	phEnable uint32 = 1 << 0
	shEnable uint32 = 1 << 1
	ehEnable uint32 = 1 << 2
)

func startupClear(t *testing.T, thetpm transport.TPM) uint32 {
	t.Helper()
	rsp, err := GetCapability{
		Capability:    TPMCapTPMProperties,
		Property:      uint32(TPMPTStartupClear),
		PropertyCount: 1,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("failed GetCapability: %v", err)
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		t.Fatalf("failed TPMProperties: %v", err)
	}
	if len(props.TPMProperty) != 1 || props.TPMProperty[0].Property != TPMPTStartupClear {
		t.Fatalf("no TPM_PT_STARTUP_CLEAR in %+v", props.TPMProperty)
	}
	return props.TPMProperty[0].Value
}

func wantEnables(t *testing.T, thetpm transport.TPM, want uint32) {
	t.Helper()
	const mask = phEnable | shEnable | ehEnable
	if got := startupClear(t, thetpm) & mask; got != want {
		t.Errorf("TPM_PT_STARTUP_CLEAR enables: want %#x, got %#x", want, got)
	}
}

func createPrimaryIn(thetpm transport.TPM, hierarchy TPMHandle) error {
	rsp, err := CreatePrimary{
		PrimaryHandle: hierarchy,
		InPublic:      New2B(ECCSRKTemplate),
	}.Execute(thetpm)
	if err != nil {
		return err
	}
	_, err = FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(thetpm)
	return err
}

func TestHierarchyControl(t *testing.T) {
	const all = phEnable | shEnable | ehEnable

	t.Run("OwnerClearsShEnable", func(t *testing.T) {
		thetpm := testhelper.Open(t)
		defer thetpm.Close()

		wantEnables(t, thetpm, all)
		if err := createPrimaryIn(thetpm, TPMRHOwner); err != nil {
			t.Fatalf("failed CreatePrimary before the clear: %v", err)
		}

		_, err := HierarchyControl{
			AuthHandle: TPMRHOwner,
			Enable:     TPMRHOwner,
			State:      false,
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("failed HierarchyControl: %v", err)
		}
		wantEnables(t, thetpm, all&^shEnable)

		if err := createPrimaryIn(thetpm, TPMRHOwner); !errors.Is(err, TPMRCHierarchy) {
			t.Errorf("CreatePrimary with shEnable clear: want TPM_RC_HIERARCHY, got %v", err)
		}
		if err := createPrimaryIn(thetpm, TPMRHEndorsement); err != nil {
			t.Errorf("failed CreatePrimary in the endorsement hierarchy: %v", err)
		}

		// The owner's authorization is of a hierarchy that is off.
		_, err = HierarchyControl{
			AuthHandle: TPMRHOwner,
			Enable:     TPMRHOwner,
			State:      true,
		}.Execute(thetpm)
		if !errors.Is(err, TPMRCHierarchy) {
			t.Errorf("owner setting shEnable: want TPM_RC_HIERARCHY, got %v", err)
		}
		wantEnables(t, thetpm, all&^shEnable)

		_, err = HierarchyControl{
			AuthHandle: TPMRHPlatform,
			Enable:     TPMRHOwner,
			State:      true,
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("platform setting shEnable: %v", err)
		}
		wantEnables(t, thetpm, all)
		if err := createPrimaryIn(thetpm, TPMRHOwner); err != nil {
			t.Errorf("failed CreatePrimary after shEnable is set again: %v", err)
		}
	})

	t.Run("OwnerSetsOnlyShEnable", func(t *testing.T) {
		thetpm := testhelper.Open(t)
		defer thetpm.Close()

		for _, enable := range []TPMHandle{TPMRHEndorsement, TPMRHPlatform, TPMRHPlatformNV} {
			_, err := HierarchyControl{
				AuthHandle: TPMRHOwner,
				Enable:     enable,
				State:      false,
			}.Execute(thetpm)
			if !errors.Is(err, TPMRCAuthType) {
				t.Errorf("owner clearing %#x: want TPM_RC_AUTH_TYPE, got %v", uint32(enable), err)
			}
		}
		wantEnables(t, thetpm, all)
	})

	t.Run("WithPassword", func(t *testing.T) {
		thetpm := testhelper.Open(t)
		defer thetpm.Close()

		ownerAuth := []byte("ownerauth")
		_, err := HierarchyChangeAuth{
			AuthHandle: TPMRHOwner,
			NewAuth:    TPM2BAuth{Buffer: ownerAuth},
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("failed HierarchyChangeAuth: %v", err)
		}

		_, err = HierarchyControl{
			AuthHandle: TPMRHOwner,
			Enable:     TPMRHOwner,
			State:      false,
		}.Execute(thetpm)
		if !errors.Is(err, TPMRCBadAuth) {
			t.Errorf("empty owner auth: want TPM_RC_BAD_AUTH, got %v", err)
		}
		wantEnables(t, thetpm, all)

		_, err = HierarchyControl{
			AuthHandle: AuthHandle{
				Handle: TPMRHOwner,
				Auth:   PasswordAuth(ownerAuth),
			},
			Enable: TPMRHOwner,
			State:  false,
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("failed HierarchyControl with the owner's password: %v", err)
		}
		wantEnables(t, thetpm, all&^shEnable)
	})

	t.Run("WithHMAC", func(t *testing.T) {
		thetpm := testhelper.Open(t)
		defer thetpm.Close()

		_, err := HierarchyControl{
			AuthHandle: AuthHandle{
				Handle: TPMRHPlatform,
				Auth:   HMAC(TPMAlgSHA256, 16, Auth(nil)),
			},
			Enable: TPMRHEndorsement,
			State:  false,
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("failed HierarchyControl with an HMAC session: %v", err)
		}
		wantEnables(t, thetpm, all&^ehEnable)
	})

	t.Run("EhEnable", func(t *testing.T) {
		thetpm := testhelper.Open(t)
		defer thetpm.Close()

		_, err := HierarchyControl{
			AuthHandle: TPMRHEndorsement,
			Enable:     TPMRHEndorsement,
			State:      false,
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("endorsement clearing ehEnable: %v", err)
		}
		wantEnables(t, thetpm, all&^ehEnable)
		if err := createPrimaryIn(thetpm, TPMRHEndorsement); !errors.Is(err, TPMRCHierarchy) {
			t.Errorf("CreatePrimary with ehEnable clear: want TPM_RC_HIERARCHY, got %v", err)
		}
		if err := createPrimaryIn(thetpm, TPMRHOwner); err != nil {
			t.Errorf("failed CreatePrimary in the owner hierarchy: %v", err)
		}

		_, err = HierarchyControl{
			AuthHandle: TPMRHPlatform,
			Enable:     TPMRHEndorsement,
			State:      true,
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("platform setting ehEnable: %v", err)
		}
		wantEnables(t, thetpm, all)
	})

	t.Run("PhEnable", func(t *testing.T) {
		thetpm := testhelper.Open(t)
		defer thetpm.Close()

		_, err := HierarchyControl{
			AuthHandle: TPMRHPlatform,
			Enable:     TPMRHPlatform,
			State:      false,
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("platform clearing phEnable: %v", err)
		}
		wantEnables(t, thetpm, all&^phEnable)
		if err := createPrimaryIn(thetpm, TPMRHPlatform); !errors.Is(err, TPMRCHierarchy) {
			t.Errorf("CreatePrimary with phEnable clear: want TPM_RC_HIERARCHY, got %v", err)
		}

		// Only a TPM2_Startup sets it again: the command has no way to.
		_, err = HierarchyControl{
			AuthHandle: TPMRHPlatform,
			Enable:     TPMRHPlatform,
			State:      true,
		}.Execute(thetpm)
		if !errors.Is(err, TPMRCHierarchy) {
			t.Errorf("setting phEnable: want TPM_RC_HIERARCHY, got %v", err)
		}
		wantEnables(t, thetpm, all&^phEnable)

		// And with it the platform's power to set the others is gone.
		_, err = HierarchyControl{
			AuthHandle: TPMRHOwner,
			Enable:     TPMRHOwner,
			State:      false,
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("owner clearing shEnable: %v", err)
		}
		_, err = HierarchyControl{
			AuthHandle: TPMRHPlatform,
			Enable:     TPMRHOwner,
			State:      true,
		}.Execute(thetpm)
		if !errors.Is(err, TPMRCHierarchy) {
			t.Errorf("platform setting shEnable with phEnable clear: want TPM_RC_HIERARCHY, got %v", err)
		}
		wantEnables(t, thetpm, ehEnable)
	})
}

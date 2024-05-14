package tpm2test

import (
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestHierarchyChangeAuth(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	authKey := []byte("authkey")
	newAuthKey := []byte("newAuthKey")

	t.Run("HierarchyChangeAuthOwner", func(t *testing.T) {
		hca := HierarchyChangeAuth{
			AuthHandle: TPMRHOwner,
			NewAuth: TPM2BAuth{
				Buffer: authKey,
			},
		}

		_, err := hca.Execute(thetpm)
		if err != nil {
			t.Errorf("failed HierarchyChangeAuth: %v", err)
		}
	})

	t.Run("HierarchyChangeAuthOwnerUnauth", func(t *testing.T) {
		hca := HierarchyChangeAuth{
			AuthHandle: TPMRHOwner,
			NewAuth: TPM2BAuth{
				Buffer: newAuthKey,
			},
		}

		_, err := hca.Execute(thetpm)
		if !errors.Is(err, TPMRCBadAuth) {
			t.Errorf("failed HierarchyChangeAuthWithoutAuth: want TPM_RC_BAD_AUTH, got %v", err)
		}
	})

	t.Run("HierarchyChangeAuthOwnerAuth", func(t *testing.T) {
		hca := HierarchyChangeAuth{
			AuthHandle: AuthHandle{
				Handle: TPMRHOwner,
				Auth:   PasswordAuth(authKey),
			},
			NewAuth: TPM2BAuth{
				Buffer: newAuthKey,
			},
		}

		_, err := hca.Execute(thetpm)
		if err != nil {
			t.Errorf("failed HierarchyChangeAuthWithAuth: %v", err)
		}
	})
}

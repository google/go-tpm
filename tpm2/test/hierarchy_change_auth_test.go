package tpm2test

import (
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

func TestHierarchyChangeAuth(t *testing.T) {
	thetpm := testhelper.Open(t)
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

	t.Run("HierarchyChangeAuthOwnerHMAC", func(t *testing.T) {
		// The TPM computes the response HMAC with the new auth value.
		hca := HierarchyChangeAuth{
			AuthHandle: AuthHandle{
				Handle: TPMRHOwner,
				Auth:   HMAC(TPMAlgSHA256, 16, Auth(newAuthKey)),
			},
			NewAuth: TPM2BAuth{
				Buffer: authKey,
			},
		}

		_, err := hca.Execute(thetpm)
		if err != nil {
			t.Errorf("failed HierarchyChangeAuthWithHMAC: %v", err)
		}
	})

	t.Run("HierarchyChangeAuthOwnerHMACEmpty", func(t *testing.T) {
		hca := HierarchyChangeAuth{
			AuthHandle: AuthHandle{
				Handle: TPMRHOwner,
				Auth:   HMAC(TPMAlgSHA256, 16, Auth(authKey)),
			},
			NewAuth: TPM2BAuth{
				Buffer: nil,
			},
		}

		_, err := hca.Execute(thetpm)
		if err != nil {
			t.Errorf("failed HierarchyChangeAuthWithHMAC to the empty auth value: %v", err)
		}
	})
}

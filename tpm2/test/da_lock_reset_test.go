package tpm2test

import (
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

func TestDictionaryAttackLockReset(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	reset := DictionaryAttackLockReset{
		LockHandle: AuthHandle{
			Handle: TPMRHLockout,
			Auth:   PasswordAuth(nil),
		},
	}
	if _, err := reset.Execute(thetpm); err != nil {
		t.Fatalf("DictionaryAttackLockReset failed: %v", err)
	}
}

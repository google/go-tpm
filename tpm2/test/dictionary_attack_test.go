package tpm2test

import (
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

// getTPMProperties reads count TPM properties starting at prop.
func getTPMProperties(t *testing.T, thetpm transport.TPM, prop TPMPT, count uint32) []TPMSTaggedProperty {
	t.Helper()

	getCap := GetCapability{
		Capability:    TPMCapTPMProperties,
		Property:      uint32(prop),
		PropertyCount: count,
	}
	getCapRsp, err := getCap.Execute(thetpm)
	if err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	}
	props, err := getCapRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		t.Fatalf("TPMProperties failed: %v", err)
	}
	if len(props.TPMProperty) != int(count) {
		t.Fatalf("GetCapability returned %d properties, want %d", len(props.TPMProperty), count)
	}
	return props.TPMProperty
}

func TestDictionaryAttackParameters(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	testCases := []struct {
		name            string
		maxTries        uint32
		recoveryTime    uint32
		lockoutRecovery uint32
	}{
		{
			name:            "0 0 0",
			maxTries:        0,
			recoveryTime:    0,
			lockoutRecovery: 0,
		},
		{
			name:            "5 10 10",
			maxTries:        5,
			recoveryTime:    10,
			lockoutRecovery: 10,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			daParams := DictionaryAttackParameters{
				AuthHandle: AuthHandle{
					Handle: TPMRHLockout,
					Auth:   PasswordAuth(nil),
				},
				MaxTries:        tc.maxTries,
				RecoveryTime:    tc.recoveryTime,
				LockoutRecovery: tc.lockoutRecovery,
			}
			if _, err := daParams.Execute(thetpm); err != nil {
				t.Fatalf("DictionaryAttackParameters failed: %v", err)
			}

			// TPM_PT_MAX_AUTH_FAIL, TPM_PT_LOCKOUT_INTERVAL and
			// TPM_PT_LOCKOUT_RECOVERY are consecutive properties.
			props := getTPMProperties(t, thetpm, TPMPTMaxAuthFail, 3)
			if props[0].Property != TPMPTMaxAuthFail || props[0].Value != tc.maxTries {
				t.Errorf("TPM_PT_MAX_AUTH_FAIL: got %d, want %d", props[0].Value, tc.maxTries)
			}
			if props[1].Property != TPMPTLockoutInterval || props[1].Value != tc.recoveryTime {
				t.Errorf("TPM_PT_LOCKOUT_INTERVAL: got %d, want %d", props[1].Value, tc.recoveryTime)
			}
			if props[2].Property != TPMPTLockoutRecovery || props[2].Value != tc.lockoutRecovery {
				t.Errorf("TPM_PT_LOCKOUT_RECOVERY: got %d, want %d", props[2].Value, tc.lockoutRecovery)
			}
		})
	}
}

func TestDictionaryAttackLockReset(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	lockoutAuth := AuthHandle{
		Handle: TPMRHLockout,
		Auth:   PasswordAuth(nil),
	}

	daParams := DictionaryAttackParameters{
		AuthHandle:      lockoutAuth,
		MaxTries:        5,
		RecoveryTime:    60,
		LockoutRecovery: 60,
	}
	if _, err := daParams.Execute(thetpm); err != nil {
		t.Fatalf("DictionaryAttackParameters failed: %v", err)
	}

	// Create a DA-protected primary key with a password.
	srkAuth := []byte("mySRK")
	srkTemplate := ECCSRKTemplate
	srkTemplate.ObjectAttributes.NoDA = false
	createSRKCmd := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InSensitive: TPM2BSensitiveCreate{
			Sensitive: &TPMSSensitiveCreate{
				UserAuth: TPM2BAuth{
					Buffer: srkAuth,
				},
			},
		},
		InPublic: New2B(srkTemplate),
	}
	createSRKRsp, err := createSRKCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not generate SRK: %v", err)
	}
	defer func() {
		flushSRKCmd := FlushContext{FlushHandle: createSRKRsp.ObjectHandle}
		if _, err := flushSRKCmd.Execute(thetpm); err != nil {
			t.Errorf("could not flush SRK: %v", err)
		}
	}()

	// Use the key with a wrong password to increment the lockout counter.
	createCmd := Create{
		ParentHandle: AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   PasswordAuth([]byte("NotThePassword")),
		},
		InPublic: New2B(ECCSRKTemplate),
	}
	if _, err := createCmd.Execute(thetpm); !errors.Is(err, TPMRCAuthFail) {
		t.Fatalf("want TPM_RC_AUTH_FAIL, got %v", err)
	}

	props := getTPMProperties(t, thetpm, TPMPTLockoutCounter, 1)
	if props[0].Value != 1 {
		t.Fatalf("TPM_PT_LOCKOUT_COUNTER: got %d, want 1", props[0].Value)
	}

	daLockReset := DictionaryAttackLockReset{
		LockHandle: lockoutAuth,
	}
	if _, err := daLockReset.Execute(thetpm); err != nil {
		t.Fatalf("DictionaryAttackLockReset failed: %v", err)
	}

	props = getTPMProperties(t, thetpm, TPMPTLockoutCounter, 1)
	if props[0].Value != 0 {
		t.Errorf("TPM_PT_LOCKOUT_COUNTER: got %d, want 0", props[0].Value)
	}
}

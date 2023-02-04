package tpm2test

import (
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// Test creating a sealed data blob on the standard-template EK using its policy.
func TestEKPolicy(t *testing.T) {
	templates := map[string]TPMTPublic{
		"RSA": RSAEKTemplate,
		"ECC": ECCEKTemplate,
	}

	// Run the whole test for each of RSA and ECC EKs.
	for name, ekTemplate := range templates {
		t.Run(name, func(t *testing.T) {
			ekTest(t, ekTemplate)
		})
	}
}

func ekPolicy(t transport.TPM, handle TPMISHPolicy, nonceTPM TPM2BNonce) error {
	cmd := PolicySecret{
		AuthHandle:    TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	return err
}

// This function tests a lot of combinations of authorizing the EK policy.
func ekTest(t *testing.T, ekTemplate TPMTPublic) {
	type ekTestCase struct {
		name string
		// Use Policy instead of PolicySession, passing the callback instead of
		// managing it ourselves?
		jitPolicySession bool
		// Use the policy session for decrypt? (Incompatible with decryptAnotherSession)
		decryptPolicySession bool
		// Use another session for decrypt? (Incompatible with decryptPolicySession)
		decryptAnotherSession bool
		// Use a bound session?
		bound bool
		// Use a salted session?
		salted bool
	}
	var cases []ekTestCase
	for jit := 0; jit < 2; jit++ {
		for decryptPol := 0; decryptPol < 2; decryptPol++ {
			for decryptAnother := 0; decryptAnother < 2; decryptAnother++ {
				if decryptPol != 0 && decryptAnother != 0 {
					continue
				}
				for bound := 0; bound < 2; bound++ {
					for salted := 0; salted < 2; salted++ {
						nextCase := ekTestCase{
							name:                  "test",
							jitPolicySession:      jit != 0,
							decryptPolicySession:  decryptPol != 0,
							decryptAnotherSession: decryptAnother != 0,
							bound:                 bound != 0,
							salted:                salted != 0,
						}
						if nextCase.jitPolicySession {
							nextCase.name += "-jit"
						} else {
							nextCase.name += "-standalone"
						}
						if nextCase.decryptPolicySession {
							nextCase.name += "-decrypt-same"
						}
						if nextCase.decryptAnotherSession {
							nextCase.name += "-decrypt-another"
						}
						if nextCase.bound {
							nextCase.name += "-bound"
						}
						if nextCase.salted {
							nextCase.name += "-salted"
						}
						cases = append(cases, nextCase)
					}
				}
			}
		}
	}

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Create the EK
			createEKCmd := CreatePrimary{
				PrimaryHandle: TPMRHEndorsement,
				InPublic:      New2B(ekTemplate),
			}
			createEKRsp, err := createEKCmd.Execute(thetpm)
			if err != nil {
				t.Fatalf("%v", err)
			}
			outPub, err := createEKRsp.OutPublic.Contents()
			if err != nil {
				t.Fatalf("%v", err)
			}
			switch outPub.Type {
			case TPMAlgRSA:
				rsa, err := outPub.Unique.RSA()
				if err != nil {
					t.Fatalf("%v", err)
				}
				t.Logf("EK pub:\n%x\n", rsa.Buffer)
			case TPMAlgECC:
				ecc, err := outPub.Unique.ECC()
				if err != nil {
					t.Fatalf("%v", err)
				}
				t.Logf("EK pub:\n%x\n%x\n", ecc.X, ecc.Y)
			}
			t.Logf("EK name: %x", createEKRsp.Name)
			defer func() {
				// Flush the EK
				flush := FlushContext{FlushHandle: createEKRsp.ObjectHandle}
				if _, err := flush.Execute(thetpm); err != nil {
					t.Errorf("%v", err)
				}
			}()

			// Exercise the EK's auth policy (PolicySecret[RH_ENDORSEMENT])
			// by creating an object under it
			data := []byte("secrets")
			createBlobCmd := Create{
				ParentHandle: NamedHandle{
					Handle: createEKRsp.ObjectHandle,
					Name:   createEKRsp.Name,
				},
				InSensitive: TPM2BSensitiveCreate{
					Sensitive: &TPMSSensitiveCreate{
						Data: NewTPMUSensitiveCreate(&TPM2BSensitiveData{
							Buffer: data,
						}),
					},
				},
				InPublic: New2B(TPMTPublic{
					Type:    TPMAlgKeyedHash,
					NameAlg: TPMAlgSHA256,
					ObjectAttributes: TPMAObject{
						FixedTPM:     true,
						FixedParent:  true,
						UserWithAuth: true,
						NoDA:         true,
					},
				}),
			}

			var sessions []Session
			if c.decryptAnotherSession {
				sessions = append(sessions, HMAC(TPMAlgSHA1, 16, AESEncryption(128, EncryptIn)))
			}

			var options []AuthOption
			if c.decryptPolicySession {
				options = append(options, AESEncryption(128, EncryptIn))
			}
			if c.bound {
				options = append(options, Bound(createEKRsp.ObjectHandle, createEKRsp.Name, nil))
			}
			if c.salted {
				options = append(options, Salted(createEKRsp.ObjectHandle, *outPub))
			}

			var s Session
			if c.jitPolicySession {
				// Use the convenience function to pass a policy callback.
				s = Policy(TPMAlgSHA256, 16, ekPolicy, options...)
			} else {
				// Set up a session we have to execute and clean up ourselves.
				var cleanup func() error
				var err error
				s, cleanup, err = PolicySession(thetpm, TPMAlgSHA256, 16, options...)
				if err != nil {
					t.Fatalf("creating session: %v", err)
				}
				// Clean up the session at the end of the test.
				defer func() {
					if err := cleanup(); err != nil {
						t.Fatalf("cleaning up policy session: %v", err)
					}
				}()
				// Execute the same callback ourselves.
				if err = ekPolicy(thetpm, s.Handle(), s.NonceTPM()); err != nil {
					t.Fatalf("executing EK policy: %v", err)
				}
			}
			createBlobCmd.ParentHandle = AuthHandle{
				Handle: createEKRsp.ObjectHandle,
				Name:   createEKRsp.Name,
				Auth:   s,
			}

			if _, err := createBlobCmd.Execute(thetpm, sessions...); err != nil {
				t.Fatalf("%v", err)
			}

			if !c.jitPolicySession {
				// If we're not using a "just-in-time" session with a callback,
				// we have to re-initialize the session.
				if err = ekPolicy(thetpm, s.Handle(), s.NonceTPM()); err != nil {
					t.Fatalf("executing EK policy: %v", err)
				}
			}

			// Try again and make sure it succeeds again.
			if _, err = createBlobCmd.Execute(thetpm, sessions...); err != nil {
				t.Fatalf("%v", err)
			}

			if !c.jitPolicySession {
				// Finally, for non-JIT policy sessions, make sure we fail if
				// we don't re-initialize the session.
				// This is because after using a policy session, it's as if
				// PolicyRestart was called.
				_, err = createBlobCmd.Execute(thetpm, sessions...)
				if !errors.Is(err, TPMRCPolicyFail) {
					t.Errorf("want TPM_RC_POLICY_FAIL, got %v", err)
				}
				var fmt1 TPMFmt1Error
				if !errors.As(err, &fmt1) {
					t.Errorf("want a Fmt1Error, got %v", err)
				} else if isSession, session := fmt1.Session(); !isSession || session != 1 {
					t.Errorf("want TPM_RC_POLICY_FAIL on session 1, got %v", err)
				}
			}
		})
	}

}

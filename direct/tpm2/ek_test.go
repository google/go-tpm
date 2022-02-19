package tpm2

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpmi"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	"github.com/google/go-tpm/direct/templates"
	"github.com/google/go-tpm/direct/transport"
	"github.com/google/go-tpm/direct/transport/simulator"
)

// Test creating a sealed data blob on the standard-template EK using its policy.
func TestEKPolicy(t *testing.T) {
	templates := map[string]tpm2b.Public{
		"RSA": templates.RSAEKTemplate,
		"ECC": templates.ECCEKTemplate,
	}

	// Run the whole test for each of RSA and ECC EKs.
	for name, ekTemplate := range templates {
		t.Run(name, func(t *testing.T) {
			ekTest(t, ekTemplate)
		})
	}
}

func ekPolicy(t transport.TPM, handle tpmi.SHPolicy, nonceTPM tpm2b.Nonce) error {
	cmd := PolicySecret{
		AuthHandle:    tpm.RHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	return err
}

// This function tests a lot of combinations of authorizing the EK policy.
func ekTest(t *testing.T, ekTemplate tpm2b.Public) {
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
				PrimaryHandle: tpm.RHEndorsement,
				InPublic:      ekTemplate,
			}
			createEKRsp, err := createEKCmd.Execute(thetpm)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if createEKRsp.OutPublic.PublicArea.Unique.ECC != nil {
				t.Logf("EK pub:\n%x\n%x\n", createEKRsp.OutPublic.PublicArea.Unique.ECC.X, createEKRsp.OutPublic.PublicArea.Unique.ECC.Y)
				t.Logf("EK name: %x", createEKRsp.Name)
			}
			defer func() {
				// Flush the EK
				flushEKCmd := FlushContext{createEKRsp.ObjectHandle}
				if _, err := flushEKCmd.Execute(thetpm); err != nil {
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
				InSensitive: tpm2b.SensitiveCreate{
					Sensitive: tpms.SensitiveCreate{
						Data: tpm2b.Data{
							Buffer: data,
						},
					},
				},
				InPublic: tpm2b.Public{
					PublicArea: tpmt.Public{
						Type:    tpm.AlgKeyedHash,
						NameAlg: tpm.AlgSHA256,
						ObjectAttributes: tpma.Object{
							FixedTPM:     true,
							FixedParent:  true,
							UserWithAuth: true,
							NoDA:         true,
						},
					},
				},
			}

			var sessions []Session
			if c.decryptAnotherSession {
				sessions = append(sessions, HMAC(tpm.AlgSHA1, 16, AESEncryption(128, EncryptIn)))
			}

			var options []AuthOption
			if c.decryptPolicySession {
				options = append(options, AESEncryption(128, EncryptIn))
			}
			if c.bound {
				options = append(options, Bound(createEKRsp.ObjectHandle, createEKRsp.Name, nil))
			}
			if c.salted {
				options = append(options, Salted(createEKRsp.ObjectHandle, createEKRsp.OutPublic.PublicArea))
			}

			var s Session
			if c.jitPolicySession {
				// Use the convenience function to pass a policy callback.
				s = Policy(tpm.AlgSHA256, 16, ekPolicy, options...)
			} else {
				// Set up a session we have to execute and clean up ourselves.
				var cleanup func() error
				var err error
				s, cleanup, err = PolicySession(thetpm, tpm.AlgSHA256, 16, options...)
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
				if !errors.Is(err, tpm.RCPolicyFail) {
					t.Errorf("want TPM_RC_POLICY_FAIL, got %v", err)
				}
				var fmt1 tpm.Fmt1Error
				if !errors.As(err, &fmt1) {
					t.Errorf("want a Fmt1Error, got %v", err)
				} else if isSession, session := fmt1.Session(); !isSession || session != 1 {
					t.Errorf("want TPM_RC_POLICY_FAIL on session 1, got %v", err)
				}
			}
		})
	}

}

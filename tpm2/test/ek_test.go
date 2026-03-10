package tpm2test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// Decodes the provided hex strings into a byte array. Panics on non-hex chars.
func hexToBytes(hexStrings ...string) []byte {
	buf, err := []byte{}, error(nil)
	for _, s := range hexStrings {
		buf, err = hex.AppendDecode(buf, []byte(s))
		if err != nil {
			panic(err)
		}
	}
	return buf
}

// Values for the various EK Policies and Templates specified in:
// TCG EK Credential Profile For TPM Family 2.0; Level 0, Version 2.7
var (
	// PolicyA values from "Computing PolicyA" section
	PolicyA = map[TPMIAlgHash]TPM2BDigest{
		TPMAlgSHA256: {Buffer: hexToBytes(
			"837197674484b3f81a90cc8d46a5d724",
			"fd52d76e06520b64f2a1da1b331469aa",
		)},
		TPMAlgSHA384: {Buffer: hexToBytes(
			"8bbf2266537c171cb56e403c4dc1d4b6",
			"4f432611dc386e6f532050c3278c930e",
			"143e8bb1133824ccb431053871c6db53",
		)},
		TPMAlgSHA512: {Buffer: hexToBytes(
			"1e3b76502c8a1425aa0b7b3fc646a1b0",
			"fae063b03b5368f9c4cddecaff0891dd",
			"682bac1a85d4d832b781ea451915de5f",
			"c5bf0dc4a1917cd42fa041e3f998e0ee",
		)},
	}
	// Policy NV Indices from "Handle Values" section
	PolicyIndex = map[TPMIAlgHash]TPMIRHNVIndex{
		TPMAlgSHA256: 0x01C07F01,
		TPMAlgSHA384: 0x01C07F02,
		TPMAlgSHA512: 0x01C07F03,
	}
	// Policy Index Names from "Computing Policy Index Names" section
	PolicyIndexName = map[TPMIAlgHash]TPM2BName{
		TPMAlgSHA256: {Buffer: hexToBytes(
			"000b", // TPM_ALG_SHA256
			"0c9d717e9c3fe69fda41769450bb1459",
			"57f8b3610e084dbf65591a5d11ecd83f",
		)},
		TPMAlgSHA384: {Buffer: hexToBytes(
			"000c", // TPM_ALG_SHA384
			"db62fca346612c976732ff4e8621fb4e",
			"858be82586486504f7d02e621f8d7d61",
			"ae32cfc60c4d120609ed6768afcf090c",
		)},
		TPMAlgSHA512: {Buffer: hexToBytes(
			"000d", // TPM_ALG_SHA512
			"1c47c0bbcbd3cf7d7cae6987d31937c1",
			"71015dde3b7f0d3c869bca1f7e8a223b",
			"9acfadb49b7c9cf14d450f41e9327de3",
			"4d9291eece2c58ab1dc10e9059cce560",
		)},
	}
	// PolicyC values from "Computing PolicyC" section
	PolicyC = map[TPMIAlgHash]TPM2BDigest{
		TPMAlgSHA256: {Buffer: hexToBytes(
			"3767e2edd43ff45a3a7e1eaefcef7864",
			"3dca964632e7aad82c673a30d8633fde",
		)},
		TPMAlgSHA384: {Buffer: hexToBytes(
			"d6032ce61f2fb3c240eb3cf6a33237ef",
			"2b6a16f4293c22b455e261cffd217ad5",
			"b4947c2d73e63005eed2dc2b3593d165",
		)},
		TPMAlgSHA512: {Buffer: hexToBytes(
			"589ee1e146544716e8deafe6db247b01",
			"b81e9f9c7dd16b814aa159138749105f",
			"ba5388dd1dea702f35240c184933121e",
			"2c61b8f50d3ef91393a49a38c3f73fc8",
		)},
	}
	// PolicyB values from "Computing PolicyB" section
	PolicyB = map[TPMIAlgHash]TPM2BDigest{
		TPMAlgSHA256: {Buffer: hexToBytes(
			"ca3d0a99a2b93906f7a3342414efcfb3",
			"a385d44cd1fd459089d19b5071c0b7a0",
		)},
		TPMAlgSHA384: {Buffer: hexToBytes(
			"b26e7d28d11a50bc53d882bcf5fd3a1a",
			"074148bb35d3b4e4cb1c0ad9bde419ca",
			"cb47ba09699646150f9fc000f3f80e12",
		)},
		TPMAlgSHA512: {Buffer: hexToBytes(
			"b8221ca69e8550a4914de3faa6a18c07",
			"2cc01208073a928d5d66d59ef79e49a4",
			"29c41a6b269571d57edb25fbdb183842",
			"5608b413cd616a5f6db5b6071af99bea",
		)},
	}
)

// Test that PolicyCalculator correctly computes PolicyA for all hashes.
func TestCalculatePolicyA(t *testing.T) {
	// PolicyA only makes use of TPM2_PolicySecret(TPM_RH_ENDORSEMENT).
	policySecretCmd := PolicySecret{
		AuthHandle: TPMRHEndorsement,
	}

	for alg, policy := range PolicyA {
		hash, err := alg.Hash()
		if err != nil {
			t.Fatalf("%v", err)
		}
		t.Run(hash.String(), func(t *testing.T) {
			pol, err := NewPolicyCalculator(alg)
			if err != nil {
				t.Fatalf("creating policy calculator: %v", err)
			}
			if err = policySecretCmd.Update(pol); err != nil {
				t.Fatalf("error updating policy calculator: %v", err)
			}
			digest := pol.Hash().Digest
			if !bytes.Equal(digest, policy.Buffer) {
				t.Errorf("PolicyA = %x,\nwant %x", digest, policy.Buffer)
			}
		})
	}
}

// Test our Name calculation for the Policy NV Index (part of PolicyC).
func TestCalculatePolicyIndexName(t *testing.T) {
	for alg, name := range PolicyIndexName {
		hash, err := alg.Hash()
		if err != nil {
			t.Fatalf("%v", err)
		}
		t.Run(hash.String(), func(t *testing.T) {
			nvPub := TPMSNVPublic{
				NVIndex: PolicyIndex[alg],
				NameAlg: alg,
				Attributes: TPMANV{
					PolicyWrite: true,
					WriteAll:    true,
					PPRead:      true,
					OwnerRead:   true,
					AuthRead:    true,
					PolicyRead:  true,
					NoDA:        true,
					Written:     true,
				},
				AuthPolicy: PolicyA[alg],
				DataSize:   uint16(hash.Size() + 2),
			}
			nvName, err := NVName(&nvPub)
			if err != nil {
				t.Fatalf("computing NV Name: %v", err)
			}
			if !bytes.Equal(nvName.Buffer, name.Buffer) {
				t.Errorf("NVName = %x,\nwant %x", nvName.Buffer, name.Buffer)
			}
		})
	}
}

// Test that PolicyCalculator correctly computes PolicyC for all hashes.
func TestCalculatePolicyC(t *testing.T) {
	for alg, policy := range PolicyC {
		hash, err := alg.Hash()
		if err != nil {
			t.Fatalf("%v", err)
		}
		t.Run(hash.String(), func(t *testing.T) {
			pol, err := NewPolicyCalculator(alg)
			if err != nil {
				t.Fatalf("creating policy calculator: %v", err)
			}
			// PolicyC uses TPM2_PolicyAuthorizeNV(idx) to delegate policy.
			authNVCmd := PolicyAuthorizeNV{
				NVIndex: NamedHandle{
					Handle: PolicyIndex[alg],
					Name:   PolicyIndexName[alg],
				},
			}
			if err = authNVCmd.Update(pol); err != nil {
				t.Fatalf("error updating policy calculator: %v", err)
			}
			digest := pol.Hash().Digest
			if !bytes.Equal(digest, policy.Buffer) {
				t.Errorf("PolicyC = %x,\nwant %x", digest, policy.Buffer)
			}
		})
	}
}

// Test that PolicyCalculator correctly computes PolicyB for all hashes.
func TestCalculatePolicyB(t *testing.T) {
	for alg, policy := range PolicyB {
		hash, err := alg.Hash()
		if err != nil {
			t.Fatalf("%v", err)
		}
		t.Run(hash.String(), func(t *testing.T) {
			pol, err := NewPolicyCalculator(alg)
			if err != nil {
				t.Fatalf("creating policy calculator: %v", err)
			}
			// PolicyB is just the TPM2_PolicyOR of PolicyA and PolicyC.
			digests := []TPM2BDigest{PolicyA[alg], PolicyC[alg]}
			orCmd := PolicyOr{PHashList: TPMLDigest{Digests: digests}}
			if err = orCmd.Update(pol); err != nil {
				t.Fatalf("error updating policy calculator: %v", err)
			}
			digest := pol.Hash().Digest
			if !bytes.Equal(digest, policy.Buffer) {
				t.Errorf("PolicyC = %x,\nwant %x", digest, policy.Buffer)
			}
		})
	}
}

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
	// Before using the EK, ensure it has the expected policy.
	policy := ekTemplate.AuthPolicy
	expected := PolicyA[ekTemplate.NameAlg]
	if !bytes.Equal(policy.Buffer, expected.Buffer) {
		t.Errorf("AuthPolicy = %x,\nwant %x", policy.Buffer, expected.Buffer)
	}

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

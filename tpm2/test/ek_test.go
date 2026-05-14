package tpm2test

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/test/templates"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

var testedHashAlgs = []TPMIAlgHash{
	TPMAlgSHA256,
	TPMAlgSHA384,
	TPMAlgSHA512,
	// https://pkg.go.dev/crypto#Hash does not support SM3
	// TPMAlgSM3256,
}

// Test that PolicyCalculator correctly computes PolicyA for all hashes.
func TestCalculatePolicyA(t *testing.T) {
	for _, alg := range testedHashAlgs {
		hash, _ := alg.Hash()
		t.Run(hash.String(), func(t *testing.T) {
			policyA, _ := AuthPolicyA(alg)

			// PolicyA only makes use of TPM2_PolicySecret(TPM_RH_ENDORSEMENT).
			policySecretCmd := PolicySecret{
				AuthHandle: TPMRHEndorsement,
			}

			pol, _ := NewPolicyCalculator(alg)
			policySecretCmd.Update(pol)
			digest := pol.Hash().Digest

			if !bytes.Equal(digest, policyA.Buffer) {
				t.Errorf("PolicyA = %x,\nwant %x", digest, policyA.Buffer)
			}
		})
	}
}

// Test that PolicyCalculator correctly computes PolicyC for all hashes.
func TestCalculatePolicyC(t *testing.T) {
	for _, alg := range testedHashAlgs {
		hash, _ := alg.Hash()
		t.Run(hash.String(), func(t *testing.T) {
			policyC, _ := AuthPolicyC(alg)
			nvPublic, _ := AuthPolicyNVPublic(alg)
			nvName, _ := NVName(&nvPublic)
			nvHandle := NamedHandle{
				Handle: nvPublic.NVIndex,
				Name:   *nvName,
			}

			// PolicyC uses TPM2_PolicyAuthorizeNV(idx) to delegate policy.
			authNVCmd := PolicyAuthorizeNV{
				AuthHandle: nvHandle,
				NVIndex:    nvHandle,
			}

			pol, _ := NewPolicyCalculator(alg)
			authNVCmd.Update(pol)
			digest := pol.Hash().Digest

			if !bytes.Equal(digest, policyC.Buffer) {
				t.Errorf("PolicyC = %x,\nwant %x", digest, policyC.Buffer)
			}
		})
	}
}

// Test that PolicyCalculator correctly computes PolicyB for all hashes.
func TestCalculatePolicyB(t *testing.T) {
	for _, alg := range testedHashAlgs {
		hash, _ := alg.Hash()
		t.Run(hash.String(), func(t *testing.T) {
			policyA, _ := AuthPolicyA(alg)
			policyB, _ := AuthPolicyB(alg)
			policyC, _ := AuthPolicyC(alg)

			// PolicyB is just the TPM2_PolicyOR of PolicyA and PolicyC.
			digests := []TPM2BDigest{policyA, policyC}
			orCmd := PolicyOr{PHashList: TPMLDigest{Digests: digests}}

			pol, _ := NewPolicyCalculator(alg)
			orCmd.Update(pol)
			digest := pol.Hash().Digest

			if !bytes.Equal(digest, policyB.Buffer) {
				t.Errorf("PolicyB = %x,\nwant %x", digest, policyB.Buffer)
			}
		})
	}
}

var testedTemplates = []Template{
	TemplateL1,
	TemplateL2,
	TemplateH1,
	TemplateH2,
	TemplateH3,
	TemplateH4,
	TemplateH5,
	TemplateH6,
	TemplateH7,
}

// Test that EKs and SRKs marshal to their expected values
func TestMarshalTemplates(t *testing.T) {
	for _, template := range testedTemplates {
		t.Run(template.String(), func(t *testing.T) {
			// Check marshaled EK against expected if we have one.
			ekBytes := Marshal(template.PublicEK())
			if expected, ok := templates.EKBytes[template]; ok {
				if !bytes.Equal(ekBytes, expected) {
					t.Errorf("EK bytes mismatch\ngot: %x\nwant: %x", ekBytes, expected)
				}
			}
			// Check marshaled SRK against expected if we have one.
			srkBytes := Marshal(template.PublicSRK())
			if expected, ok := templates.SRKBytes[template]; ok {
				if !bytes.Equal(srkBytes, expected) {
					t.Errorf("SRK bytes mismatch\ngot: %x\nwant: %x", srkBytes, expected)
				}
			}
		})
	}
}

// Test creating a sealed data blob on the standard-template EK using its policy.
func TestAuthEK(t *testing.T) {
	for _, template := range testedTemplates {
		t.Run(template.String(), func(t *testing.T) {
			ekTemplate := template.PublicEK()
			checkSupported(t, ekTemplate)

			if template.IsLowRange() {
				// Low-Range EKs can only use PolicyA
				for _, tc := range []authTestCase{
					{name: "PolicyA", hierarchy: TPMRHEndorsement, public: ekTemplate, policyFn: ekPolicyA},
				} {
					t.Run(tc.name, tc.Run)
				}
				return
			}

			// We use TPM2_PolicySecret(TPM_RH_OWNER) as our stored NV Policy.
			customPolicyCmd := PolicySecret{
				AuthHandle: TPMRHOwner,
			}
			pol, _ := NewPolicyCalculator(ekTemplate.NameAlg)
			customPolicyCmd.Update(pol)
			customPolicy := pol.Hash()

			customPolicyCallback := func(t transport.TPM, handle TPMISHPolicy, _ TPM2BNonce) error {
				customPolicyCmd.PolicySession = handle
				_, err := customPolicyCmd.Execute(t)
				return err
			}

			// High-Range EKs use PolicyB, which delegates to either PolicyA or PolicyC.
			// It may also be used with an AuthValue instead of a policy.
			for _, tc := range []authTestCase{
				{name: "AuthNil", hierarchy: TPMRHEndorsement, public: ekTemplate, authValue: nil},
				{name: "AuthVal", hierarchy: TPMRHEndorsement, public: ekTemplate, authValue: []byte("ek_auth")},
				{
					name:      "PolicyBviaA",
					hierarchy: TPMRHEndorsement, public: ekTemplate,
					policyFn: ekPolicyBviaA(ekTemplate.NameAlg),
				},
				{
					name:      "PolicyBviaC",
					hierarchy: TPMRHEndorsement, public: ekTemplate,
					policyFn: ekPolicyBviaC(ekTemplate.NameAlg, customPolicyCallback),
					nvPolicy: customPolicy,
				},
			} {
				t.Run(tc.name, tc.Run)
			}
		})
	}
}

// Test creating a sealed data blob on the standard-template SRK.
func TestAuthSRK(t *testing.T) {
	for _, template := range testedTemplates {
		t.Run(template.String(), func(t *testing.T) {
			srkTemplate := template.PublicSRK()
			checkSupported(t, srkTemplate)

			// All SRKs can only use an AuthValue
			for _, tc := range []authTestCase{
				{name: "AuthNil", hierarchy: TPMRHOwner, public: srkTemplate, authValue: nil},
				{name: "AuthVal", hierarchy: TPMRHOwner, public: srkTemplate, authValue: []byte("srk_auth")},
			} {
				t.Run(tc.name, tc.Run)
			}
		})
	}
}

// Skip test if [tpm2.TPMTPublic.Parameters] is not supported by the Simulator.
func checkSupported(t *testing.T, public TPMTPublic) {
	t.Helper()
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("Closing the TPM: %v", err)
		}
	}()

	cmd := TestParms{Parameters: TPMTPublicParms{
		Type:       public.Type,
		Parameters: public.Parameters,
	}}
	if _, err := cmd.Execute(thetpm); err != nil {
		for _, skipErr := range []TPMRC{TPMRCValue, TPMRCSymmetric, TPMRCHash} {
			if errors.Is(err, skipErr) {
				t.Skipf("Checking parameter support: %v", err)
			}
		}
		t.Fatalf("Checking parameter support: %v", err)
	}
}

type authTestCase struct {
	name      string          // Name of the sub-test
	hierarchy TPMIRHHierarchy // Hierarchy to create the primary key (e.g., TPM_RH_OWNER)
	public    TPMTPublic      // The Template mapped to the primary key
	authValue []byte          // Optional auth value for the key
	policyFn  PolicyCallback  // Callback logic strategy to satisfy the key's policy
	nvPolicy  *TPMTHA         // Optional NV state provisioned before sealing
}

// Create a primary key and attempt to seal a data blob to it.
func (tc *authTestCase) Run(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Could not connect to TPM simulator: %v", err)
	}
	defer func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("Closing the TPM: %v", err)
		}
	}()

	// Create our EK or SRK with the specified AuthValue if appropriate
	createPrimaryCmd := CreatePrimary{
		PrimaryHandle: tc.hierarchy,
		InPublic:      New2B(tc.public),
	}
	if tc.authValue != nil {
		createPrimaryCmd.InSensitive.Sensitive = &TPMSSensitiveCreate{
			UserAuth: TPM2BAuth{Buffer: tc.authValue},
		}
	}
	createPrimaryRsp, err := createPrimaryCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary: %v", err)
	}
	defer func() { // Flush the key
		flushCmd := FlushContext{FlushHandle: createPrimaryRsp.ObjectHandle}
		if _, err := flushCmd.Execute(thetpm); err != nil {
			t.Errorf("Flushing key: %v", err)
		}
	}()

	// Log the key (to help with debugging)
	key := NamedHandle{
		Handle: createPrimaryRsp.ObjectHandle,
		Name:   createPrimaryRsp.Name,
	}
	t.Logf("Key handle: %x", key.Handle)
	t.Logf("Key name:\n%x", key.Name.Buffer)
	outPub, err := createPrimaryRsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if rsa, err := outPub.Unique.RSA(); err == nil {
		t.Logf("RSA pub:\n%x", rsa.Buffer)
	}
	if ecc, err := outPub.Unique.ECC(); err == nil {
		t.Logf("ECC pub:\n%x\n%x", ecc.X.Buffer, ecc.Y.Buffer)
	}

	// Setup NV-based policy if needed
	if tc.nvPolicy != nil {
		tc.provisionNVPolicy(t, thetpm)
	}

	// We will create a sealed blob under the primary key
	createBlobCmd := Create{
		ParentHandle: key,
		InSensitive: TPM2BSensitiveCreate{Sensitive: &TPMSSensitiveCreate{
			Data: NewTPMUSensitiveCreate(&TPM2BSensitiveData{
				Buffer: []byte("secret_sealed_data"),
			}),
		}},
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
	if tc.authValue != nil {
		createBlobCmd.ParentHandle = AuthHandle{
			Handle: key.Handle,
			Name:   key.Name,
			Auth:   PasswordAuth(tc.authValue),
		}
	}

	// Run a subtest for each different policy configuration.
	for _, opts := range tc.generatePolicySubtests(key, outPub) {
		t.Run(opts.name, func(t *testing.T) {
			cmd := createBlobCmd

			var s Session
			// Nonce size must be >= 16, but can be shorter than hash digest.
			nonceSize := 16

			if opts.policyJIT {
				// Use just-in-time policy session creation.
				s = Policy(tc.public.NameAlg, nonceSize, tc.policyFn, opts.authOpts...)
			} else if opts.policyCmd {
				// Use explicit policy session creation.
				var cleanup func() error
				var err error
				s, cleanup, err = PolicySession(
					thetpm, tc.public.NameAlg, nonceSize, opts.authOpts...,
				)
				if err != nil {
					t.Fatalf("Creating policy session: %v", err)
				}
				defer func() {
					if err := cleanup(); err != nil {
						t.Errorf("Cleanup policy session: %v", err)
					}
				}()

				// Manually execute the policy callback
				err = tc.policyFn(thetpm, s.Handle(), s.NonceTPM())
				if err != nil {
					t.Fatalf("Authorizing EK policy: %v", err)
				}
			}
			if s != nil {
				cmd.ParentHandle = AuthHandle{
					Handle: key.Handle,
					Name:   key.Name,
					Auth:   s,
				}
			}

			if _, err := cmd.Execute(thetpm, opts.sessions...); err != nil {
				t.Errorf("1st Create blob: %v", err)
			}

			if opts.policyCmd {
				// For manual commands, reauthorization is required.
				_, err = cmd.Execute(thetpm, opts.sessions...)
				if !errors.Is(err, TPMRCPolicyFail) {
					t.Errorf("want TPM_RC_POLICY_FAIL, got %v", err)
				}
				// Explicitly reauthorize command so the 2nd Create call works.
				err = tc.policyFn(thetpm, s.Handle(), s.NonceTPM())
				if err != nil {
					t.Fatalf("Reauthorizing EK policy: %v", err)
				}
			}

			if _, err := cmd.Execute(thetpm, opts.sessions...); err != nil {
				t.Errorf("2nd Create blob: %v", err)
			}
		})
	}
}

// Provision [authTestCase.nvPolicy] to the appropriate NV index.
func (tc *authTestCase) provisionNVPolicy(t *testing.T, thetpm transport.TPM) {
	t.Helper()
	nvPublic, _ := AuthPolicyNVPublic(tc.public.NameAlg)

	// When creating the policy NV Index, Written is initially false,
	// before becoming true after the first write.
	nvPublic.Attributes.Written = false
	nvName, _ := NVName(&nvPublic)

	defCmd := NVDefineSpace{
		AuthHandle: TPMRHOwner,
		PublicInfo: New2B(nvPublic),
	}
	if _, err := defCmd.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	writeCmd := NVWrite{
		AuthHandle: AuthHandle{
			Handle: nvPublic.NVIndex,
			Name:   *nvName,
			Auth:   Policy(tc.public.NameAlg, 16, ekPolicyA),
		},
		NVIndex: NamedHandle{
			Handle: nvPublic.NVIndex,
			Name:   *nvName,
		},
		Data: TPM2BMaxNVBuffer{
			Buffer: Marshal(tc.nvPolicy),
		},
	}
	if _, err := writeCmd.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_Write: %v", err)
	}
}

type policyOptions struct {
	name      string       // Name of the sub-sub-test
	policyJIT bool         // Use just-in-time policy session creation
	policyCmd bool         // Use explicit policy session creation
	authOpts  []AuthOption // Auth options for the policy session
	sessions  []Session    // Additional sessions for the command
}

// Generates all the different policy subtests for the given test case.
func (tc *authTestCase) generatePolicySubtests(key NamedHandle, outPub *TPMTPublic) []policyOptions {
	var subtests []policyOptions
	if tc.policyFn == nil {
		subtests = []policyOptions{{name: "PolicyNone"}}
	} else {
		subtests = []policyOptions{
			{name: "PolicyJIT", policyJIT: true},
			{name: "PolicyCmd", policyCmd: true},
		}

		// Add additional subtests for bound sessions
		for _, opts := range slices.Clone(subtests) {
			opts.name += "-bound"
			boundOpt := Bound(key.Handle, key.Name, nil)
			opts.authOpts = append(opts.authOpts, boundOpt)
			subtests = append(subtests, opts)
		}
		// Add additional subtests for salted sessions
		for _, opts := range slices.Clone(subtests) {
			opts.name += "-salted"
			saltedOpt := Salted(key.Handle, *outPub)
			opts.authOpts = append(opts.authOpts, saltedOpt)
			subtests = append(subtests, opts)
		}
	}

	clonedSubtests := slices.Clone(subtests)
	// Add additional subtests for decrypting with an extra session
	for _, opts := range clonedSubtests {
		opts.name += "-decrypt-extra"
		decryptSession := HMAC(TPMAlgSHA256, 16, AESEncryption(128, EncryptIn))
		opts.sessions = append(opts.sessions, decryptSession)
		subtests = append(subtests, opts)
	}
	if tc.policyFn != nil {
		// Add additional subtests for decrypting with the policy session
		for _, opts := range clonedSubtests {
			opts.name += "-decrypt-policy"
			decryptOpt := AESEncryption(128, EncryptIn)
			opts.authOpts = append(opts.authOpts, decryptOpt)
			subtests = append(subtests, opts)
		}
	}
	return subtests
}

// Satisfy PolicyA by calling [tpm2.PolicySecret] on [tpm2.TPMRHEndorsement].
func ekPolicyA(t transport.TPM, handle TPMISHPolicy, nonce TPM2BNonce) error {
	cmd := PolicySecret{
		AuthHandle:    TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonce,
	}
	_, err := cmd.Execute(t)
	return err
}

// Create a [tpm2.PolicyCallback] which satisfies PolicyB via PolicyA.
func ekPolicyBviaA(alg TPMIAlgHash) PolicyCallback {
	return func(t transport.TPM, handle TPMISHPolicy, nonce TPM2BNonce) error {
		if err := ekPolicyA(t, handle, nonce); err != nil {
			return err
		}
		return ekPolicyB(t, handle, alg)
	}
}

// Create a [tpm2.PolicyCallback] which satisfies PolicyB via PolicyC.
func ekPolicyBviaC(alg TPMIAlgHash, nvCallback PolicyCallback) PolicyCallback {
	nvPublic, _ := AuthPolicyNVPublic(alg)
	nvName, _ := NVName(&nvPublic)
	nvHandle := NamedHandle{
		Handle: nvPublic.NVIndex,
		Name:   *nvName,
	}

	return func(t transport.TPM, handle TPMISHPolicy, nonce TPM2BNonce) error {
		if err := nvCallback(t, handle, nonce); err != nil {
			return err
		}
		// PolicyAuthorizeNV updates the digest to a value that only depends on the
		// nvHandle and NOT the previous digest state. This is why it produces the
		// same digest as TestCalculatePolicyC which starts with an empty digest.
		cmd := PolicyAuthorizeNV{
			AuthHandle:    nvHandle,
			NVIndex:       nvHandle,
			PolicySession: handle,
		}
		if _, err := cmd.Execute(t); err != nil {
			return err
		}

		return ekPolicyB(t, handle, alg)
	}
}

// Satisfy PolicyB by calling [tpm2.PolicyOr] with PolicyA and PolicyC.
func ekPolicyB(t transport.TPM, handle TPMISHPolicy, alg TPMIAlgHash) error {
	policyA, _ := AuthPolicyA(alg)
	policyC, _ := AuthPolicyC(alg)
	digests := []TPM2BDigest{policyA, policyC}

	policyOrCmd := PolicyOr{
		PolicySession: handle,
		PHashList:     TPMLDigest{Digests: digests},
	}
	_, err := policyOrCmd.Execute(t)
	return err
}

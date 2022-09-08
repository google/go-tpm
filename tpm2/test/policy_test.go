package tpm2test

import (
	"bytes"
	"crypto/sha1"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func signingKey(t *testing.T, thetpm transport.TPM) (NamedHandle, func()) {
	t.Helper()
	createPrimary := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic: *NewTPM2BPublic(&TPMTPublic{
			Type:    TPMAlgECC,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			Parameters: TPMUPublicParms{
				ECCDetail: &TPMSECCParms{
					Scheme: TPMTECCScheme{
						Scheme: TPMAlgECDSA,
						Details: *NewTPMUAsymScheme(
							TPMAlgECDSA,
							&TPMSSigSchemeECDSA{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
					CurveID: TPMECCNistP256,
				},
			},
		}),
	}
	rsp, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not create key: %v", err)
	}
	cleanup := func() {
		t.Helper()
		flush := FlushContext{
			FlushHandle: rsp.ObjectHandle,
		}
		if err := flush.Execute(thetpm); err != nil {
			t.Errorf("could not flush signing key: %v", err)
		}
	}
	return NamedHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
	}, cleanup
}

func nvIndex(t *testing.T, thetpm transport.TPM) (NamedHandle, func()) {
	t.Helper()
	defSpace := NVDefineSpace{
		AuthHandle: TPMRHOwner,
		PublicInfo: *NewTPM2BNVPublic(
			&TPMSNVPublic{
				NVIndex: 0x01800001,
				NameAlg: TPMAlgSHA256,
				Attributes: TPMANV{
					OwnerWrite: true,
					AuthRead:   true,
					NT:         TPMNTOrdinary,
				},
			}),
	}
	if err := defSpace.Execute(thetpm); err != nil {
		t.Fatalf("could not create NV index: %v", err)
	}
	readPub := NVReadPublic{
		NVIndex: defSpace.PublicInfo.Contents().Unwrap().NVIndex,
	}
	readRsp, err := readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not read NV index public info: %v", err)
	}
	cleanup := func() {
		t.Helper()
		undefine := NVUndefineSpace{
			AuthHandle: TPMRHOwner,
			NVIndex: NamedHandle{
				Handle: defSpace.PublicInfo.Contents().Unwrap().NVIndex,
				Name:   readRsp.NVName,
			},
		}
		if err := undefine.Execute(thetpm); err != nil {
			t.Errorf("could not undefine NV index: %v", err)
		}
	}
	return NamedHandle{
		Handle: defSpace.PublicInfo.Contents().Unwrap().NVIndex,
		Name:   readRsp.NVName,
	}, cleanup
}

func TestPolicySignedUpdate(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	sk, cleanup := signingKey(t, thetpm)
	defer cleanup()

	// Use a trial session to calculate this policy
	sess, cleanup2, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer func() {
		t.Helper()
		if err := cleanup2(); err != nil {
			t.Errorf("cleaning up policy session: %v", err)
		}
	}()

	policySigned := PolicySigned{
		AuthObject:    sk,
		PolicySession: sess.Handle(),
		PolicyRef:     TPM2BNonce{Buffer: []byte{5, 6, 7, 8}},
		Auth: TPMTSignature{
			SigAlg: TPMAlgECDSA,
			Signature: TPMUSignature{
				ECDSA: &TPMSSignatureECC{
					Hash: TPMAlgSHA256,
				},
			},
		},
	}

	if _, err := policySigned.Execute(thetpm); err != nil {
		t.Fatalf("executing PolicySigned: %v", err)
	}

	pgd := PolicyGetDigest{
		PolicySession: sess.Handle(),
	}
	want, err := pgd.Execute(thetpm)
	if err != nil {
		t.Fatalf("executing PolicyGetDigest: %v", err)
	}

	// Use the policy helper to calculate the same policy
	pol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	policySigned.Update(pol)
	got := pol.Hash()

	if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
		t.Errorf("policySigned.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
	}
}

func TestPolicySecretUpdate(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	sk, cleanup := signingKey(t, thetpm)
	defer cleanup()

	// Use a trial session to calculate this policy
	sess, cleanup2, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer func() {
		t.Helper()
		if err := cleanup2(); err != nil {
			t.Errorf("cleaning up policy session: %v", err)
		}
	}()

	policySecret := PolicySecret{
		AuthHandle: NamedHandle{
			Handle: sk.Handle,
			Name:   sk.Name,
		},
		PolicySession: sess.Handle(),
		PolicyRef:     TPM2BNonce{Buffer: []byte{5, 6, 7, 8}},
	}

	if _, err := policySecret.Execute(thetpm); err != nil {
		t.Fatalf("executing PolicySecret: %v", err)
	}

	pgd := PolicyGetDigest{
		PolicySession: sess.Handle(),
	}
	want, err := pgd.Execute(thetpm)
	if err != nil {
		t.Fatalf("executing PolicyGetDigest: %v", err)
	}

	// Use the policy helper to calculate the same policy
	pol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	policySecret.Update(pol)
	got := pol.Hash()

	if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
		t.Errorf("policySecret.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
	}
}

func TestPolicyOrUpdate(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// Use a trial session to calculate this policy
	sess, cleanup2, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer func() {
		t.Helper()
		if err := cleanup2(); err != nil {
			t.Errorf("cleaning up policy session: %v", err)
		}
	}()

	policyOr := PolicyOr{
		PolicySession: sess.Handle(),
		PHashList: TPMLDigest{
			Digests: []TPM2BDigest{
				{Buffer: []byte{1, 2, 3}},
				{Buffer: []byte{4, 5, 6}},
			},
		},
	}

	if err := policyOr.Execute(thetpm); err != nil {
		t.Fatalf("executing PolicyOr: %v", err)
	}

	pgd := PolicyGetDigest{
		PolicySession: sess.Handle(),
	}
	want, err := pgd.Execute(thetpm)
	if err != nil {
		t.Fatalf("executing PolicyGetDigest: %v", err)
	}

	// Use the policy helper to calculate the same policy
	pol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	policyOr.Update(pol)
	got := pol.Hash()

	if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
		t.Errorf("policyOr.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
	}
}

func getExpectedPCRDigest(t *testing.T, thetpm transport.TPM, selection TPMLPCRSelection, hashAlg TPMAlgID) []byte {
	t.Helper()
	pcrRead := PCRRead{
		PCRSelectionIn: selection,
	}

	pcrReadRsp, err := pcrRead.Execute(thetpm)
	if err != nil {
		t.Fatalf("failed to read PCRs")
	}

	var expectedVal []byte
	for _, digest := range pcrReadRsp.PCRValues.Digests {
		expectedVal = append(expectedVal, digest.Buffer...)
	}

	cryptoHashAlg, err := hashAlg.Hash()
	if err != nil {
		t.Fatalf("failed to get crypto hash")
	}

	hash := cryptoHashAlg.New()
	hash.Write(expectedVal)
	return hash.Sum(nil)
}

func TestPolicyPCR(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	PCRs, err := CreatePCRSelection([]int{0, 1, 2, 3, 7})
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}

	selection := TPMLPCRSelection{
		PCRSelections: []TPMSPCRSelection{
			{
				Hash:      TPMAlgSHA1,
				PCRSelect: PCRs,
			},
		},
	}

	expectedDigest := getExpectedPCRDigest(t, thetpm, selection, TPMAlgSHA1)

	wrongDigest := sha1.Sum(expectedDigest[:])

	tests := []struct {
		name              string
		authOption        []AuthOption
		pcrDigest         []byte
		callShouldSucceed bool
	}{
		{"TrialCorrect", []AuthOption{Trial()}, expectedDigest, true},
		{"TrialIncorrect", []AuthOption{Trial()}, wrongDigest[:], true},
		{"TrialEmpty", []AuthOption{Trial()}, nil, true},
		{"RealCorrect", nil, expectedDigest, true},
		{"RealIncorrect", nil, wrongDigest[:], false},
		{"RealEmpty", nil, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, cleanup2, err := PolicySession(thetpm, TPMAlgSHA1, 16, tt.authOption...)

			if err != nil {
				t.Fatalf("setting up policy session: %v", err)
			}

			policyPCR := PolicyPCR{
				PolicySession: sess.Handle(),
				PcrDigest: TPM2BDigest{
					Buffer: tt.pcrDigest,
				},
				Pcrs: selection,
			}

			err = policyPCR.Execute(thetpm)
			if tt.callShouldSucceed {
				if err != nil {
					t.Fatalf("executing PolicyPCR: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected PolicyPCR to return error, got nil")
				}
				return
			}

			pgd := PolicyGetDigest{
				PolicySession: sess.Handle(),
			}
			want, err := pgd.Execute(thetpm)
			if err != nil {
				t.Fatalf("executing PolicyGetDigest: %v", err)
			}

			// If the pcrDigest is empty: see TPM 2.0 Part 3, 23.7.
			if tt.pcrDigest == nil {
				expectedDigest := getExpectedPCRDigest(t, thetpm, selection, TPMAlgSHA1)
				t.Logf("expectedDigest=%x", expectedDigest)

				// Create a populated policyPCR for the PolicyCalculator
				policyPCR.PcrDigest.Buffer = expectedDigest[:]
			}

			// Use the policy helper to calculate the same policy
			pol, err := NewPolicyCalculator(TPMAlgSHA1)
			if err != nil {
				t.Fatalf("creating policy calculator: %v", err)
			}
			policyPCR.Update(pol)
			got := pol.Hash()

			if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
				t.Errorf("policyPCR.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
			}

			if err := cleanup2(); err != nil {
				t.Errorf("cleaning up policy session: %v", err)
			}
		})
	}

}

func TestPolicyCpHashUpdate(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// Use a trial session to calculate this policy
	sess, cleanup2, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer func() {
		t.Helper()
		if err := cleanup2(); err != nil {
			t.Errorf("cleaning up policy session: %v", err)
		}
	}()

	policyCpHash := PolicyCPHash{
		PolicySession: sess.Handle(),
		CPHashA: TPM2BDigest{Buffer: []byte{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
	}

	if err := policyCpHash.Execute(thetpm); err != nil {
		t.Fatalf("executing PolicyCpHash: %v", err)
	}

	pgd := PolicyGetDigest{
		PolicySession: sess.Handle(),
	}
	want, err := pgd.Execute(thetpm)
	if err != nil {
		t.Fatalf("executing PolicyGetDigest: %v", err)
	}

	// Use the policy helper to calculate the same policy
	pol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	policyCpHash.Update(pol)
	got := pol.Hash()

	if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
		t.Errorf("policyCpHash.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
	}
}

func TestPolicyAuthorizeUpdate(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// Use a trial session to calculate this policy
	sess, cleanup2, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer func() {
		t.Helper()
		if err := cleanup2(); err != nil {
			t.Errorf("cleaning up policy session: %v", err)
		}
	}()

	sk, cleanup := signingKey(t, thetpm)
	defer cleanup()

	policyAuthorize := PolicyAuthorize{
		PolicySession: sess.Handle(),
		PolicyRef:     TPM2BDigest{Buffer: []byte{5, 6, 7, 8}},
		KeySign:       sk.Name,
		CheckTicket: TPMTTKVerified{
			Tag:       TPMSTVerified,
			Hierarchy: TPMRHEndorsement,
		},
	}

	if err := policyAuthorize.Execute(thetpm); err != nil {
		t.Fatalf("executing PolicyAuthorize: %v", err)
	}

	pgd := PolicyGetDigest{
		PolicySession: sess.Handle(),
	}
	want, err := pgd.Execute(thetpm)
	if err != nil {
		t.Fatalf("executing PolicyGetDigest: %v", err)
	}

	// Use the policy helper to calculate the same policy
	pol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	policyAuthorize.Update(pol)
	got := pol.Hash()

	if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
		t.Errorf("policyAuthorize.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
	}
}

func TestPolicyNVWrittenUpdate(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// Use a trial session to calculate this policy
	sess, cleanup2, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer func() {
		t.Helper()
		if err := cleanup2(); err != nil {
			t.Errorf("cleaning up policy session: %v", err)
		}
	}()

	policyNVWritten := PolicyNVWritten{
		PolicySession: sess.Handle(),
		WrittenSet:    true,
	}

	if _, err := policyNVWritten.Execute(thetpm); err != nil {
		t.Fatalf("executing PolicyNVWritten: %v", err)
	}

	pgd := PolicyGetDigest{
		PolicySession: sess.Handle(),
	}
	want, err := pgd.Execute(thetpm)
	if err != nil {
		t.Fatalf("executing PolicyGetDigest: %v", err)
	}

	// Use the policy helper to calculate the same policy
	pol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	policyNVWritten.Update(pol)
	got := pol.Hash()

	if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
		t.Errorf("PolicyNVWritten.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
	}
}

func TestPolicyNVUpdate(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	nv, cleanup := nvIndex(t, thetpm)
	defer cleanup()

	// Use a trial session to calculate this policy
	sess, cleanup2, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer func() {
		t.Helper()
		if err := cleanup2(); err != nil {
			t.Errorf("cleaning up policy session: %v", err)
		}
	}()

	policyNV := PolicyNV{
		AuthHandle:    NamedHandle{Handle: nv.Handle, Name: nv.Name},
		PolicySession: sess.Handle(),
		NVIndex:       nv,
		OperandB:      TPM2BOperand{Buffer: []byte("operandB")},
		Offset:        2,
		Operation:     TPMEOSignedLE,
	}

	if err := policyNV.Execute(thetpm); err != nil {
		t.Fatalf("executing PolicyAuthorizeNV: %v", err)
	}

	pgd := PolicyGetDigest{
		PolicySession: sess.Handle(),
	}
	want, err := pgd.Execute(thetpm)
	if err != nil {
		t.Fatalf("executing PolicyGetDigest: %v", err)
	}

	// Use the policy helper to calculate the same policy
	pol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	policyNV.Update(pol)
	got := pol.Hash()

	if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
		t.Errorf("PolicyAuthorizeNV.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
	}
}

func TestPolicyAuthorizeNVUpdate(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	nv, cleanup := nvIndex(t, thetpm)
	defer cleanup()

	// Use a trial session to calculate this policy
	sess, cleanup2, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer func() {
		t.Helper()
		if err := cleanup2(); err != nil {
			t.Errorf("cleaning up policy session: %v", err)
		}
	}()

	policyAuthorizeNV := PolicyAuthorizeNV{
		AuthHandle:    NamedHandle{Handle: nv.Handle, Name: nv.Name},
		PolicySession: sess.Handle(),
		NVIndex:       nv,
	}

	if err := policyAuthorizeNV.Execute(thetpm); err != nil {
		t.Fatalf("executing PolicyAuthorizeNV: %v", err)
	}

	pgd := PolicyGetDigest{
		PolicySession: sess.Handle(),
	}
	want, err := pgd.Execute(thetpm)
	if err != nil {
		t.Fatalf("executing PolicyGetDigest: %v", err)
	}

	// Use the policy helper to calculate the same policy
	pol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	policyAuthorizeNV.Update(pol)
	got := pol.Hash()

	if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
		t.Errorf("PolicyAuthorizeNV.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
	}
}

func TestPolicyCommandCodeUpdate(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// Use a trial session to calculate this policy
	sess, cleanup2, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
	if err != nil {
		t.Fatalf("setting up policy session: %v", err)
	}
	defer func() {
		t.Helper()
		if err := cleanup2(); err != nil {
			t.Errorf("cleaning up policy session: %v", err)
		}
	}()

	pcc := PolicyCommandCode{
		PolicySession: sess.Handle(),
		Code:          TPMCCCreate,
	}
	if err := pcc.Execute(thetpm); err != nil {
		t.Fatalf("executing PolicyCommandCode: %v", err)
	}

	pgd := PolicyGetDigest{
		PolicySession: sess.Handle(),
	}
	want, err := pgd.Execute(thetpm)
	if err != nil {
		t.Fatalf("executing PolicyGetDigest: %v", err)
	}

	// Use the policy helper to calculate the same policy
	pol, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	pcc.Update(pol)
	got := pol.Hash()

	if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
		t.Errorf("PolicyCommandCode.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
	}
}

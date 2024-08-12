package tpm2test

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// This test isn't interesting, but it checks that you can omit the handles on `StartAuthSession`.
func TestCreatePolicySession(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  TPMSE
	}{
		{
			"trial",
			TPMSETrial,
		},
		{
			"policy",
			TPMSEPolicy,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			thetpm, err := simulator.OpenSimulator()
			if err != nil {
				t.Fatalf("could not connect to TPM simulator: %v", err)
			}
			defer thetpm.Close()

			sas, err := StartAuthSession{
				SessionType: tc.typ,
				AuthHash:    TPMAlgSHA256,
				NonceCaller: TPM2BNonce{
					Buffer: make([]byte, 16),
				},
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("StartAuthSession() = %v", err)
			}

			pgd, err := PolicyGetDigest{
				PolicySession: sas.SessionHandle,
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("PolicyGetDigest() = %v", err)
			}
			if digest := pgd.PolicyDigest.Buffer; !bytes.Equal(digest, make([]byte, len(digest))) {
				t.Errorf("PolicyGetDigest() = %x, want all zeros", digest)
			}

			_, err = FlushContext{
				FlushHandle: sas.SessionHandle,
			}.Execute(thetpm)
			if err != nil {
				t.Errorf("FlushContext() = %v", err)
			}
		})
	}
}

func signingKey(t *testing.T, thetpm transport.TPM) (NamedHandle, func()) {
	t.Helper()
	createPrimary := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgECC,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgECC,
				&TPMSECCParms{
					Scheme: TPMTECCScheme{
						Scheme: TPMAlgECDSA,
						Details: NewTPMUAsymScheme(
							TPMAlgECDSA,
							&TPMSSigSchemeECDSA{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
					CurveID: TPMECCNistP256,
				},
			),
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
		if _, err := flush.Execute(thetpm); err != nil {
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
		PublicInfo: New2B(
			TPMSNVPublic{
				NVIndex: 0x01800001,
				NameAlg: TPMAlgSHA256,
				Attributes: TPMANV{
					OwnerWrite: true,
					AuthRead:   true,
					NT:         TPMNTOrdinary,
				},
			}),
	}
	if _, err := defSpace.Execute(thetpm); err != nil {
		t.Fatalf("could not create NV index: %v", err)
	}
	pub, err := defSpace.PublicInfo.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	readPub := NVReadPublic{
		NVIndex: pub.NVIndex,
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
				Handle: pub.NVIndex,
				Name:   readRsp.NVName,
			},
		}
		if _, err := undefine.Execute(thetpm); err != nil {
			t.Errorf("could not undefine NV index: %v", err)
		}
	}
	return NamedHandle{
		Handle: pub.NVIndex,
		Name:   readRsp.NVName,
	}, cleanup
}

func primaryRSASRK(t *testing.T, thetpm transport.TPM) (NamedHandle, func()) {
	t.Helper()
	createPrimary := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(RSASRKTemplate),
	}
	rsp, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not create primary key: %v", err)
	}
	cleanup := func() {
		t.Helper()
		flush := FlushContext{
			FlushHandle: rsp.ObjectHandle,
		}
		if _, err := flush.Execute(thetpm); err != nil {
			t.Errorf("could not flush primary key: %v", err)
		}
	}
	return NamedHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
	}, cleanup
}

func primaryRSAEK(t *testing.T, thetpm transport.TPM) (NamedHandle, func()) {
	t.Helper()
	createPrimary := CreatePrimary{
		PrimaryHandle: TPMRHEndorsement,
		InPublic:      New2B(RSAEKTemplate),
	}
	rsp, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not create primary key: %v", err)
	}
	cleanup := func() {
		t.Helper()
		flush := FlushContext{
			FlushHandle: rsp.ObjectHandle,
		}
		if _, err := flush.Execute(thetpm); err != nil {
			t.Errorf("could not flush primary key: %v", err)
		}
	}
	return NamedHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
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
			Signature: NewTPMUSignature(
				TPMAlgECDSA,
				&TPMSSignatureECC{
					Hash: TPMAlgSHA256,
				},
			),
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

	if _, err := policyOr.Execute(thetpm); err != nil {
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

	selection := TPMLPCRSelection{
		PCRSelections: []TPMSPCRSelection{
			{
				Hash:      TPMAlgSHA1,
				PCRSelect: PCClientCompatible.PCRs(0, 1, 2, 3, 7),
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

			_, err = policyPCR.Execute(thetpm)
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

	if _, err := policyCpHash.Execute(thetpm); err != nil {
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

	if _, err := policyAuthorize.Execute(thetpm); err != nil {
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

	if _, err := policyNV.Execute(thetpm); err != nil {
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

	if _, err := policyAuthorizeNV.Execute(thetpm); err != nil {
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
	if _, err := pcc.Execute(thetpm); err != nil {
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

func TestPolicyAuthValue(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	password := []byte("foo")
	wrongPassword := []byte("bar")

	tests := []struct {
		name              string
		password          []byte
		authOption        []AuthOption
		callShouldSucceed bool
	}{
		{"PasswordCorrect", password, []AuthOption{Auth(password)}, true},
		{"PasswordIncorrect", wrongPassword, []AuthOption{Auth(password)}, false},
		{"PasswordEmpty", nil, []AuthOption{Auth(password)}, false},
		{"AuthOptionEmpty", password, []AuthOption{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			pk, pkcleanup := primaryRSASRK(t, thetpm)
			defer pkcleanup()

			// create a trial policy with PolicyAuthValue
			sess, cleanup1, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
			if err != nil {
				t.Fatalf("setting up trial session: %v", err)
			}
			defer func() {
				t.Helper()
				if err := cleanup1(); err != nil {
					t.Errorf("cleaning up trial session: %v", err)
				}
			}()

			pav := PolicyAuthValue{
				PolicySession: sess.Handle(),
			}
			_, err = pav.Execute(thetpm)
			if err != nil {
				t.Fatalf("error executing policyAuthValue: %v", err)
			}

			// verify the digest
			pgd, err := PolicyGetDigest{
				PolicySession: sess.Handle(),
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("error executing PolicyGetDigest: %v", pgd)
			}

			// Use the policy helper to calculate the same policy
			pol, err := NewPolicyCalculator(TPMAlgSHA256)
			if err != nil {
				t.Fatalf("creating policy calculator: %v", err)
			}
			pav.Update(pol)
			got := pol.Hash()

			if !bytes.Equal(got.Digest, pgd.PolicyDigest.Buffer) {
				t.Errorf("PolicyAuthValue.Hash() = %x,\nwant %x", got.Digest, pgd.PolicyDigest.Buffer)
			}

			// now apply the policy to a new key
			rsaTemplate := TPMTPublic{
				Type:    TPMAlgRSA,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					SignEncrypt:         true,
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
				},
				AuthPolicy: pgd.PolicyDigest,
				Parameters: NewTPMUPublicParms(
					TPMAlgRSA,
					&TPMSRSAParms{
						Scheme: TPMTRSAScheme{
							Scheme: TPMAlgRSASSA,
							Details: NewTPMUAsymScheme(
								TPMAlgRSASSA,
								&TPMSSigSchemeRSASSA{
									HashAlg: TPMAlgSHA256,
								},
							),
						},
						KeyBits: 2048,
					},
				),
			}

			k, err := CreateLoaded{
				ParentHandle: AuthHandle{
					Handle: pk.Handle,
					Name:   pk.Name,
					Auth:   PasswordAuth(nil),
				},
				InPublic: New2BTemplate(&rsaTemplate),
				InSensitive: TPM2BSensitiveCreate{
					Sensitive: &TPMSSensitiveCreate{
						UserAuth: TPM2BAuth{
							Buffer: tt.password,
						},
					},
				},
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("error creating key %v", err)
			}
			defer func() {
				t.Helper()
				_, err := FlushContext{
					FlushHandle: k.ObjectHandle,
				}.Execute(thetpm)
				if err != nil {
					t.Errorf("error cleaning up key: %v", err)
				}
			}()

			// create a real policy session and use the password through the authOption
			sess2, cleanup2, err := PolicySession(thetpm, TPMAlgSHA256, 16, tt.authOption...)
			if err != nil {
				t.Fatalf("setting up policy session: %v", err)
			}
			defer cleanup2()

			policyAuthValue2 := PolicyAuthValue{
				PolicySession: sess2.Handle(),
			}

			_, err = policyAuthValue2.Execute(thetpm)
			if err != nil {
				t.Fatalf("executing policyAuthValue: %v", err)
			}

			// sign some data with the key using the session
			data := []byte("somedata")
			digest := sha256.Sum256(data)

			sign := Sign{
				KeyHandle: AuthHandle{
					Handle: k.ObjectHandle,
					Name:   k.Name,
					Auth:   sess2,
				},
				Digest: TPM2BDigest{
					Buffer: digest[:],
				},
				InScheme: TPMTSigScheme{
					Scheme: TPMAlgRSASSA,
					Details: NewTPMUSigScheme(
						TPMAlgRSASSA,
						&TPMSSchemeHash{
							HashAlg: TPMAlgSHA256,
						},
					),
				},
				Validation: TPMTTKHashCheck{
					Tag: TPMSTHashCheck,
				},
			}

			_, err = sign.Execute(thetpm)
			if tt.callShouldSucceed {
				if err != nil {
					t.Fatalf("expected no error for PolicyAuthValue but got: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error for PolicyAuthValue, got nil")
				}
				return
			}
		})
	}

}

func TestPolicyDuplicationSelectUpdate(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	ek, ekcleanup := primaryRSAEK(t, thetpm)
	defer ekcleanup()

	pk, pkcleanup := primaryRSASRK(t, thetpm)
	defer pkcleanup()

	k, err := CreateLoaded{
		ParentHandle: AuthHandle{
			Handle: pk.Handle,
			Name:   pk.Name,
			Auth:   PasswordAuth(nil),
		},
		InPublic: New2BTemplate(&TPMTPublic{
			Type:    TPMAlgRSA,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				FixedTPM:            false,
				FixedParent:         false,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgRSA,
				&TPMSRSAParms{
					Scheme: TPMTRSAScheme{
						Scheme: TPMAlgRSASSA,
						Details: NewTPMUAsymScheme(
							TPMAlgRSASSA,
							&TPMSSigSchemeRSASSA{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
					KeyBits: 2048,
				},
			),
		}),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("error creating key %v", err)
	}
	defer func() {
		t.Helper()
		_, err := FlushContext{
			FlushHandle: k.ObjectHandle,
		}.Execute(thetpm)
		if err != nil {
			t.Errorf("error cleaning up key: %v", err)
		}
	}()

	tests := []struct {
		name          string
		objectName    TPM2BName
		includeObject bool
	}{
		{"IncludeObjectFalse", TPM2BName{}, false},
		{"IncludeObjectTrue", k.Name, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// create a trial policy with PolicyDuplicationSelect
			sess, cleanup1, err := PolicySession(thetpm, TPMAlgSHA256, 16, Trial())
			if err != nil {
				t.Fatalf("error setting up trial session: %v", err)
			}
			defer func() {
				t.Helper()
				if err := cleanup1(); err != nil {
					t.Errorf("error cleaning up trial session: %v", err)
				}
			}()

			pds := PolicyDuplicationSelect{
				PolicySession: sess.Handle(),
				NewParentName: ek.Name,
				ObjectName:    tt.objectName,
				IncludeObject: tt.includeObject,
			}
			_, err = pds.Execute(thetpm)
			if err != nil {
				t.Fatalf("error executing PolicyDuplicationSelect: %v", err)
			}

			pdr, err := PolicyGetDigest{
				PolicySession: sess.Handle(),
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("error executing PolicyGetDigest: %v", pdr)
			}

			// Use the policy helper to calculate the same policy
			pol, err := NewPolicyCalculator(TPMAlgSHA256)
			if err != nil {
				t.Fatalf("creating policy calculator: %v", err)
			}
			err = pds.Update(pol)
			if err != nil {
				t.Fatalf("error updating policy calculator: %v", err)
			}
			got := pol.Hash()

			if !bytes.Equal(got.Digest, pdr.PolicyDigest.Buffer) {
				t.Errorf("PolicyAuthValue.Hash() = %x,\nwant %x", got.Digest, pdr.PolicyDigest.Buffer)
			}
		})
	}
}

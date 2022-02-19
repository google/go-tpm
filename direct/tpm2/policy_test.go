package tpm2

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpml"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	"github.com/google/go-tpm/direct/structures/tpmu"
	"github.com/google/go-tpm/direct/transport"
	"github.com/google/go-tpm/direct/transport/simulator"
)

func signingKey(t *testing.T, thetpm transport.TPM) (NamedHandle, func()) {
	t.Helper()
	createPrimary := CreatePrimary{
		PrimaryHandle: tpm.RHOwner,
		InPublic: tpm2b.Public{
			PublicArea: tpmt.Public{
				Type:    tpm.AlgECC,
				NameAlg: tpm.AlgSHA256,
				ObjectAttributes: tpma.Object{
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
					SignEncrypt:         true,
				},
				Parameters: tpmu.PublicParms{
					ECCDetail: &tpms.ECCParms{
						Scheme: tpmt.ECCScheme{
							Scheme: tpm.AlgECDSA,
							Details: tpmu.AsymScheme{
								ECDSA: &tpms.SigSchemeECDSA{
									HashAlg: tpm.AlgSHA256,
								},
							},
						},
						CurveID: tpm.ECCNistP256,
					},
				},
			},
		},
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
		AuthHandle: tpm.RHOwner,
		PublicInfo: tpm2b.NVPublic{
			NVPublic: tpms.NVPublic{
				NVIndex: 0x01800001,
				NameAlg: tpm.AlgSHA256,
				Attributes: tpma.NV{
					OwnerWrite: true,
					AuthRead:   true,
					NT:         tpm.NTOrdinary,
				},
			},
		},
	}
	if err := defSpace.Execute(thetpm); err != nil {
		t.Fatalf("could not create NV index: %v", err)
	}
	readPub := NVReadPublic{
		NVIndex: defSpace.PublicInfo.NVPublic.NVIndex,
	}
	readRsp, err := readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not read NV index public info: %v", err)
	}
	cleanup := func() {
		t.Helper()
		undefine := NVUndefineSpace{
			AuthHandle: tpm.RHOwner,
			NVIndex: NamedHandle{
				defSpace.PublicInfo.NVPublic.NVIndex,
				readRsp.NVName,
			},
		}
		if err := undefine.Execute(thetpm); err != nil {
			t.Errorf("could not undefine NV index: %v", err)
		}
	}
	return NamedHandle{
		Handle: defSpace.PublicInfo.NVPublic.NVIndex,
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
	sess, cleanup2, err := PolicySession(thetpm, tpm.AlgSHA256, 16, Trial())
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
		PolicyRef:     tpm2b.Nonce{Buffer: []byte{5, 6, 7, 8}},
		Auth: tpmt.Signature{
			SigAlg: tpm.AlgECDSA,
			Signature: tpmu.Signature{
				ECDSA: &tpms.SignatureECC{
					Hash: tpm.AlgSHA256,
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
	pol, err := NewPolicyCalculator(tpm.AlgSHA256)
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
	sess, cleanup2, err := PolicySession(thetpm, tpm.AlgSHA256, 16, Trial())
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
		PolicyRef:     tpm2b.Nonce{Buffer: []byte{5, 6, 7, 8}},
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
	pol, err := NewPolicyCalculator(tpm.AlgSHA256)
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
	sess, cleanup2, err := PolicySession(thetpm, tpm.AlgSHA256, 16, Trial())
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
		PHashList: tpml.Digest{
			Digests: []tpm2b.Digest{
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
	pol, err := NewPolicyCalculator(tpm.AlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	policyOr.Update(pol)
	got := pol.Hash()

	if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
		t.Errorf("policyOr.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
	}
}

func TestPolicyCpHashUpdate(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// Use a trial session to calculate this policy
	sess, cleanup2, err := PolicySession(thetpm, tpm.AlgSHA256, 16, Trial())
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
		CPHashA: tpm2b.Digest{Buffer: []byte{
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
	pol, err := NewPolicyCalculator(tpm.AlgSHA256)
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
	sess, cleanup2, err := PolicySession(thetpm, tpm.AlgSHA256, 16, Trial())
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
		PolicyRef:     tpm2b.Digest{Buffer: []byte{5, 6, 7, 8}},
		KeySign:       sk.Name,
		CheckTicket: tpmt.TKVerified{
			Tag:       tpm.STVerified,
			Hierarchy: tpm.RHEndorsement,
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
	pol, err := NewPolicyCalculator(tpm.AlgSHA256)
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
	sess, cleanup2, err := PolicySession(thetpm, tpm.AlgSHA256, 16, Trial())
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
	pol, err := NewPolicyCalculator(tpm.AlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	policyNVWritten.Update(pol)
	got := pol.Hash()

	if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
		t.Errorf("PolicyNVWritten.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
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
	sess, cleanup2, err := PolicySession(thetpm, tpm.AlgSHA256, 16, Trial())
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
	pol, err := NewPolicyCalculator(tpm.AlgSHA256)
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
	sess, cleanup2, err := PolicySession(thetpm, tpm.AlgSHA256, 16, Trial())
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
		Code:          tpm.CCCreate,
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
	pol, err := NewPolicyCalculator(tpm.AlgSHA256)
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}
	pcc.Update(pol)
	got := pol.Hash()

	if !bytes.Equal(got.Digest, want.PolicyDigest.Buffer) {
		t.Errorf("PolicyCommandCode.Hash() = %x,\nwant %x", got.Digest, want.PolicyDigest.Buffer)
	}
}

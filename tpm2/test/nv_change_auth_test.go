package tpm2test

import (
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

func TestNVChangeAuth(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	// The SRK salts the session that encrypts the new auth value.
	createSRKCmd := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(ECCSRKTemplate),
	}
	createSRKRsp, err := createSRKCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() {
		flushSRKCmd := FlushContext{FlushHandle: createSRKRsp.ObjectHandle}
		if _, err := flushSRKCmd.Execute(thetpm); err != nil {
			t.Errorf("%v", err)
		}
	}()
	srkPub, err := createSRKRsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}

	testCases := []struct {
		name string
		// The auth value the index is defined with.
		oldAuth []byte
		// Whether the ADMIN policy includes TPM2_PolicyAuthValue.
		authValue bool
		// Whether the session is salted and encrypts the new auth value.
		encrypted bool
	}{
		{
			name:      "PolicyAuthValue",
			oldAuth:   []byte("oldAuth"),
			authValue: true,
		},
		{
			name:      "PolicyAuthValueEncrypted",
			oldAuth:   []byte("oldAuth"),
			authValue: true,
			encrypted: true,
		},
		{
			name:      "PolicyAuthValueEmptyOldAuth",
			oldAuth:   nil,
			authValue: true,
		},
		{
			name:    "PolicyCommandCodeOnly",
			oldAuth: []byte("oldAuth"),
		},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			newAuth := []byte("newAuth")

			adminPolicy := func(tpm transport.TPM, handle TPMISHPolicy, _ TPM2BNonce) error {
				pcc := PolicyCommandCode{
					PolicySession: handle,
					Code:          TPMCCNVChangeAuth,
				}
				if _, err := pcc.Execute(tpm); err != nil {
					return err
				}
				if tc.authValue {
					pav := PolicyAuthValue{
						PolicySession: handle,
					}
					if _, err := pav.Execute(tpm); err != nil {
						return err
					}
				}
				return nil
			}
			pol, err := NewPolicyCalculator(TPMAlgSHA256)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if err := (PolicyCommandCode{Code: TPMCCNVChangeAuth}).Update(pol); err != nil {
				t.Fatalf("%v", err)
			}
			if tc.authValue {
				if err := (PolicyAuthValue{}).Update(pol); err != nil {
					t.Fatalf("%v", err)
				}
			}

			def := NVDefineSpace{
				AuthHandle: TPMRHOwner,
				Auth: TPM2BAuth{
					Buffer: tc.oldAuth,
				},
				PublicInfo: New2B(
					TPMSNVPublic{
						NVIndex: TPMHandle(0x01800010 + i),
						NameAlg: TPMAlgSHA256,
						Attributes: TPMANV{
							AuthWrite: true,
							AuthRead:  true,
							NT:        TPMNTOrdinary,
							NoDA:      true,
						},
						AuthPolicy: TPM2BDigest{
							Buffer: pol.Hash().Digest,
						},
						DataSize: 4,
					}),
			}
			if _, err := def.Execute(thetpm); err != nil {
				t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
			}
			pub, err := def.PublicInfo.Contents()
			if err != nil {
				t.Fatalf("%v", err)
			}
			nvName, err := NVName(pub)
			if err != nil {
				t.Fatalf("Calculating name of NV index: %v", err)
			}
			defer func() {
				undefine := NVUndefineSpace{
					AuthHandle: TPMRHOwner,
					NVIndex: NamedHandle{
						Handle: pub.NVIndex,
						Name:   *nvName,
					},
				}
				if _, err := undefine.Execute(thetpm); err != nil {
					t.Errorf("Calling TPM2_NV_UndefineSpace: %v", err)
				}
			}()

			var opts []AuthOption
			if tc.authValue {
				opts = append(opts, Auth(tc.oldAuth))
			}
			if tc.encrypted {
				opts = append(opts,
					Salted(createSRKRsp.ObjectHandle, *srkPub),
					AESEncryption(128, EncryptIn))
			}
			changeAuth := NVChangeAuth{
				NVIndex: AuthHandle{
					Handle: pub.NVIndex,
					Name:   *nvName,
					Auth:   Policy(TPMAlgSHA256, 16, adminPolicy, opts...),
				},
				NewAuth: TPM2BAuth{
					Buffer: newAuth,
				},
			}
			if _, err := changeAuth.Execute(thetpm); err != nil {
				t.Fatalf("Calling TPM2_NV_ChangeAuth: %v", err)
			}

			write := func(auth []byte) error {
				write := NVWrite{
					AuthHandle: AuthHandle{
						Handle: pub.NVIndex,
						Name:   *nvName,
						Auth:   HMAC(TPMAlgSHA256, 16, Auth(auth)),
					},
					NVIndex: NamedHandle{
						Handle: pub.NVIndex,
						Name:   *nvName,
					},
					Data: TPM2BMaxNVBuffer{
						Buffer: []byte{0x01, 0x02, 0x03, 0x04},
					},
				}
				_, err := write.Execute(thetpm)
				return err
			}
			if err := write(tc.oldAuth); !errors.Is(err, TPMRCBadAuth) {
				t.Errorf("TPM2_NV_Write with the old auth value: want TPM_RC_BAD_AUTH, got %v", err)
			}
			if err := write(newAuth); err != nil {
				t.Errorf("TPM2_NV_Write with the new auth value: %v", err)
			}
		})
	}
}

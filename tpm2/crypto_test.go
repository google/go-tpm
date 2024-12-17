package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestPriv(t *testing.T) {

	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	seed := make([]byte, crypto.SHA256.New().Size())
	rand.Read(seed)

	tests := map[string]struct {
		sensitive TPMTSensitive
		public    TPMTPublic
		result    bool
	}{
		"valid rsa": {
			sensitive: TPMTSensitive{
				SensitiveType: TPMAlgRSA,
				AuthValue: TPM2BAuth{
					Buffer: nil,
				},
				SeedValue: TPM2BDigest{
					Buffer: seed,
				},
				Sensitive: NewTPMUSensitiveComposite(
					TPMAlgRSA,
					&TPM2BPrivateKeyRSA{
						Buffer: rsaKey.Primes[0].Bytes(),
					},
				),
			},
			public: TPMTPublic{
				Type:    TPMAlgRSA,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					FixedTPM:             true,
					STClear:              false,
					FixedParent:          true,
					SensitiveDataOrigin:  true,
					UserWithAuth:         true,
					AdminWithPolicy:      false,
					NoDA:                 false,
					EncryptedDuplication: false,
					Restricted:           true,
					Decrypt:              true,
					SignEncrypt:          false,
				},
				Parameters: NewTPMUPublicParms(
					TPMAlgRSA,
					&TPMSRSAParms{
						KeyBits:  TPMKeyBits(rsaKey.PublicKey.N.BitLen()),
						Exponent: 0,
						Symmetric: TPMTSymDefObject{
							Algorithm: TPMAlgAES,
							Mode: NewTPMUSymMode(
								TPMAlgAES,
								TPMAlgCFB,
							),
							KeyBits: NewTPMUSymKeyBits(
								TPMAlgAES,
								TPMKeyBits(128),
							),
						},
					},
				),
				Unique: NewTPMUPublicID(
					TPMAlgRSA,
					&TPM2BPublicKeyRSA{
						Buffer: rsaKey.PublicKey.N.Bytes(),
					},
				),
			},
			result: true,
		},
		"valid ecdsa": {
			sensitive: TPMTSensitive{
				SensitiveType: TPMAlgECC,
				AuthValue: TPM2BAuth{
					Buffer: nil,
				},
				SeedValue: TPM2BDigest{
					Buffer: seed,
				},
				Sensitive: NewTPMUSensitiveComposite(
					TPMAlgECC,
					&TPM2BECCParameter{Buffer: ecdsaKey.D.FillBytes(make([]byte, len(ecdsaKey.D.Bytes())))},
				),
			},
			public: TPMTPublic{
				Type:    TPMAlgECC,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					FixedTPM:             true,
					STClear:              false,
					FixedParent:          true,
					SensitiveDataOrigin:  true,
					UserWithAuth:         true,
					AdminWithPolicy:      false,
					NoDA:                 false,
					EncryptedDuplication: false,
					Restricted:           true,
					Decrypt:              true,
					SignEncrypt:          false,
				},
				Parameters: NewTPMUPublicParms(
					TPMAlgECC,
					&TPMSECCParms{
						CurveID: TPMECCNistP256,
						Scheme: TPMTECCScheme{
							Scheme: TPMAlgECDSA,
							Details: NewTPMUAsymScheme(
								TPMAlgECDSA,
								&TPMSSigSchemeECDSA{
									HashAlg: TPMAlgSHA256,
								},
							),
						},
					},
				),
				Unique: NewTPMUPublicID(
					TPMAlgECC,
					&TPMSECCPoint{
						X: TPM2BECCParameter{
							Buffer: ecdsaKey.X.Bytes(),
						},
						Y: TPM2BECCParameter{
							Buffer: ecdsaKey.Y.Bytes(),
						},
					},
				),
			},
			result: true,
		},
		"public error": {
			sensitive: TPMTSensitive{},
			public: TPMTPublic{
				Type: TPMAlgAES,
			},
			result: false,
		},
	}

	for name, test := range tests {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, err := Priv(test.public, test.sensitive)

			if (key != nil) != test.result {
				t.Errorf("Not equal: \n"+
					"expected: %v\n"+
					"actual  : %v",
					test.result,
					key != nil,
				)
			}

			if (err == nil) != test.result {
				t.Errorf("Not equal: \n"+
					"expected: %v\n"+
					"actual  : %v",
					test.result,
					err == nil,
				)
			}

			if key != nil {
				switch key := key.(type) {
				case *rsa.PrivateKey:
					if !reflect.DeepEqual(rsaKey, key) {
						t.Errorf("Not equal: \n"+
							"expected: %v\n"+
							"actual  : %v",
							rsaKey,
							key,
						)
					}
				case *ecdsa.PrivateKey:
					if !reflect.DeepEqual(ecdsaKey, key) {
						t.Errorf("Not equal: \n"+
							"expected: %v\n"+
							"actual  : %v",
							ecdsaKey,
							key,
						)
					}
				default:
					t.Fatalf("unexpected case")
				}
			}
		})
	}
}

func TestPub(t *testing.T) {

	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := map[string]struct {
		public TPMTPublic
		result bool
	}{
		"valid rsa": {
			public: TPMTPublic{
				Type:    TPMAlgRSA,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					FixedTPM:             true,
					STClear:              false,
					FixedParent:          true,
					SensitiveDataOrigin:  true,
					UserWithAuth:         true,
					AdminWithPolicy:      false,
					NoDA:                 false,
					EncryptedDuplication: false,
					Restricted:           true,
					Decrypt:              true,
					SignEncrypt:          false,
				},
				Parameters: NewTPMUPublicParms(
					TPMAlgRSA,
					&TPMSRSAParms{
						KeyBits:  TPMKeyBits(rsaKey.PublicKey.N.BitLen()),
						Exponent: 0,
						Symmetric: TPMTSymDefObject{
							Algorithm: TPMAlgAES,
							Mode: NewTPMUSymMode(
								TPMAlgAES,
								TPMAlgCFB,
							),
							KeyBits: NewTPMUSymKeyBits(
								TPMAlgAES,
								TPMKeyBits(128),
							),
						},
					},
				),
				Unique: NewTPMUPublicID(
					TPMAlgRSA,
					&TPM2BPublicKeyRSA{
						Buffer: rsaKey.PublicKey.N.Bytes(),
					},
				),
			},
			result: true,
		},
		"valid ecdsa": {
			public: TPMTPublic{
				Type:    TPMAlgECC,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					FixedTPM:             true,
					STClear:              false,
					FixedParent:          true,
					SensitiveDataOrigin:  true,
					UserWithAuth:         true,
					AdminWithPolicy:      false,
					NoDA:                 false,
					EncryptedDuplication: false,
					Restricted:           true,
					Decrypt:              true,
					SignEncrypt:          false,
				},
				Parameters: NewTPMUPublicParms(
					TPMAlgECC,
					&TPMSECCParms{
						CurveID: TPMECCNistP256,
						Scheme: TPMTECCScheme{
							Scheme: TPMAlgECDSA,
							Details: NewTPMUAsymScheme(
								TPMAlgECDSA,
								&TPMSSigSchemeECDSA{
									HashAlg: TPMAlgSHA256,
								},
							),
						},
					},
				),
				Unique: NewTPMUPublicID(
					TPMAlgECC,
					&TPMSECCPoint{
						X: TPM2BECCParameter{
							Buffer: ecdsaKey.X.Bytes(),
						},
						Y: TPM2BECCParameter{
							Buffer: ecdsaKey.Y.Bytes(),
						},
					},
				),
			},
			result: true,
		},
		"unsupported algorithm": {
			public: TPMTPublic{
				Type: TPMAlgAES,
			},
			result: false,
		},
	}

	for name, test := range tests {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, err := Pub(test.public)

			if (key != nil) != test.result {
				t.Errorf("Not equal: \n"+
					"expected: %v\n"+
					"actual  : %v",
					test.result,
					key != nil,
				)
			}

			if (err == nil) != test.result {
				t.Errorf("Not equal: \n"+
					"expected: %v\n"+
					"actual  : %v",
					test.result,
					err == nil,
				)
			}

			if key != nil {
				switch key := key.(type) {
				case *rsa.PublicKey:
					if !reflect.DeepEqual(rsaKey.PublicKey, *key) {
						t.Errorf("Not equal: \n"+
							"expected: %v\n"+
							"actual  : %v",
							rsaKey.PublicKey,
							key,
						)
					}
				case *ecdsa.PublicKey:
					if !reflect.DeepEqual(ecdsaKey.PublicKey, *key) {
						t.Errorf("Not equal: \n"+
							"expected: %v\n"+
							"actual  : %v",
							ecdsaKey.PublicKey,
							key,
						)
					}
				default:
					t.Fatalf("unexpected case")
				}
			}
		})
	}
}

// A duplication policy callback.
func duplicationPolicy(tpm transport.TPM, handle TPMISHPolicy, _ TPM2BNonce) error {
	_, err := PolicyCommandCode{
		PolicySession: handle,
		Code:          TPMCCDuplicate,
	}.Execute(tpm)
	return err
}

func duplicationPolicyHash() TPM2BDigest {
	pc, err := NewPolicyCalculator(TPMAlgSHA256)
	if err != nil {
		panic(err)
	}
	pcc := PolicyCommandCode{
		Code: TPMCCDuplicate,
	}
	if err := pcc.Update(pc); err != nil {
		panic(err)
	}
	return TPM2BDigest{
		Buffer: pc.Hash().Digest,
	}
}

func TestRoundTrip(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer tpm.Close()

	srkCreate, err := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("could not create SRK: %v", err)
	}

	defer FlushContext{
		FlushHandle: srkCreate.ObjectHandle,
	}.Execute(tpm)

	for _, tc := range []struct {
		name string
		alg  TPMAlgID
		pub  TPM2BPublic
	}{
		{
			name: "rsa_2k_pkcs",
			alg:  TPMAlgRSA,
			pub: New2B(TPMTPublic{
				Type:    TPMAlgRSA,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					FixedTPM:             false,
					STClear:              false,
					FixedParent:          false,
					SensitiveDataOrigin:  true,
					UserWithAuth:         true,
					AdminWithPolicy:      true,
					NoDA:                 true,
					EncryptedDuplication: false,
					Restricted:           false,
					Decrypt:              false,
					SignEncrypt:          true,
				},
				AuthPolicy: duplicationPolicyHash(),
				Parameters: NewTPMUPublicParms(
					TPMAlgRSA,
					&TPMSRSAParms{
						KeyBits: 2048,
						Scheme: TPMTRSAScheme{
							Scheme: TPMAlgRSASSA,
							Details: NewTPMUAsymScheme(
								TPMAlgRSASSA,
								&TPMSSigSchemeRSASSA{
									HashAlg: TPMAlgSHA256,
								},
							),
						},
					},
				),
			}),
		},
		{
			name: "ecdsa_p256",
			alg:  TPMAlgECDSA,
			pub: New2B(TPMTPublic{
				Type:    TPMAlgECC,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					FixedTPM:             false,
					STClear:              false,
					FixedParent:          false,
					SensitiveDataOrigin:  true,
					UserWithAuth:         true,
					AdminWithPolicy:      true,
					NoDA:                 true,
					EncryptedDuplication: false,
					Restricted:           false,
					Decrypt:              false,
					SignEncrypt:          true,
				},
				AuthPolicy: duplicationPolicyHash(),
				Parameters: NewTPMUPublicParms(
					TPMAlgECC,
					&TPMSECCParms{
						CurveID: TPMECCNistP256,
						Scheme: TPMTECCScheme{
							Scheme: TPMAlgECDSA,
							Details: NewTPMUAsymScheme(
								TPMAlgECDSA,
								&TPMSSigSchemeECDSA{
									HashAlg: TPMAlgSHA256,
								},
							),
						},
					},
				),
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Create an exportable signing key and then export it.
			create, err := Create{
				ParentHandle: NamedHandle{
					Handle: srkCreate.ObjectHandle,
					Name:   srkCreate.Name,
				},
				InPublic: tc.pub,
			}.Execute(tpm)
			if err != nil {
				t.Fatalf("could not create key: %v", err)
			}

			load, err := Load{
				ParentHandle: NamedHandle{
					Handle: srkCreate.ObjectHandle,
					Name:   srkCreate.Name,
				},
				InPrivate: create.OutPrivate,
				InPublic:  create.OutPublic,
			}.Execute(tpm)
			if err != nil {
				t.Fatalf("could not load key: %v", err)
			}
			defer FlushContext{
				FlushHandle: load.ObjectHandle,
			}.Execute(tpm)

			pub, priv := duplicateToSoftware(t, tpm, load.ObjectHandle)
			checkSignVerify(t, tpm, NamedHandle{
				Handle: load.ObjectHandle,
				Name:   load.Name,
			}, tc.alg, pub, priv)
		})
	}
}

// Uses the `Pub` and `Priv` helpers to import the public and private key.
// Note that in practice, one could just use `crypto.PrivateKey.Public()` to
// derive the public key from the private key. This helper uses the `Pub`
// routine to validate that function specifically while we test the rest.
func duplicateToSoftware(t *testing.T, tpm transport.TPM, h TPMHandle) (crypto.PublicKey, crypto.PrivateKey) {
	t.Helper()

	readPublic, err := ReadPublic{
		ObjectHandle: h,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("could not ReadPublic: %v", err)
	}

	pub, err := readPublic.OutPublic.Contents()
	if err != nil {
		t.Fatalf("could not unmarshal TPMT_PUBLIC: %v", err)
	}

	publicKey, err := Pub(*pub)
	if err != nil {
		t.Fatalf("could not load public key: %v", err)
	}

	dup, err := Duplicate{
		ObjectHandle: AuthHandle{
			Handle: h,
			Name:   readPublic.Name,
			Auth:   Policy(TPMAlgSHA256, 16, duplicationPolicy),
		},
		NewParentHandle: TPMRHNull,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("could not duplicate key: %v", err)
	}

	sens, err := Unmarshal[TPM2BSensitive](dup.Duplicate.Buffer)
	if err != nil {
		t.Fatalf("could not unmarshal TPM2B_SENSITIVE: %v", err)
	}

	priv, err := sens.Contents()
	if err != nil {
		t.Fatalf("could not unmarshal TPMT_SENSITIVE: %v", err)
	}

	privateKey, err := Priv(*pub, *priv)
	if err != nil {
		t.Fatalf("could not load private key: %v", err)
	}
	return publicKey, privateKey
}

func checkSignVerify(t *testing.T, tpm transport.TPM, h NamedHandle, alg TPMAlgID, pub crypto.PublicKey, priv crypto.PrivateKey) {
	t.Helper()

	msg := "Something I signed."
	msgDigest := sha256.Sum256([]byte(msg))

	// Sign with the TPM and with software.
	sign, err := Sign{
		KeyHandle: h,
		Digest: TPM2BDigest{
			Buffer: msgDigest[:],
		},
		Validation: TPMTTKHashCheck{
			Tag:       TPMSTHashCheck,
			Hierarchy: TPMRHNull,
		},
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("could not Sign: %v", err)
	}
	tpmSig := sign.Signature

	swSig := signSoftware(t, msgDigest[:], priv)

	// Verify the software signature with the TPM.
	_, err = VerifySignature{
		KeyHandle: h,
		Digest: TPM2BDigest{
			Buffer: msgDigest[:],
		},
		Signature: *swSig,
	}.Execute(tpm)
	if err != nil {
		t.Errorf("TPM2_VerifySignature = %v", err)
	}

	// Verify the TPM signature with software.
	verify(t, msgDigest[:], &tpmSig, pub, alg)
}

func signSoftware(t *testing.T, digest []byte, priv crypto.PrivateKey) *TPMTSignature {
	t.Helper()

	switch v := priv.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, v, crypto.SHA256, digest)
		if err != nil {
			t.Fatalf("could not sign RSA in software: %v", err)
		}
		return tpmSignatureFromSignatureRSA(t, sig)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, v, digest)
		if err != nil {
			t.Fatalf("could not sign ECDSA in software: %v", err)
		}
		return tpmSignatureFromSignatureECDSA(t, r, s)
	default:
		t.Fatalf("unsupported algorithm")
	}
	return nil
}

func tpmSignatureFromSignatureRSA(t *testing.T, sig []byte) *TPMTSignature {
	t.Helper()

	return &TPMTSignature{
		SigAlg: TPMAlgRSASSA,
		Signature: NewTPMUSignature(
			TPMAlgRSASSA,
			&TPMSSignatureRSA{
				Hash: TPMAlgSHA256,
				Sig: TPM2BPublicKeyRSA{
					Buffer: sig,
				},
			},
		),
	}
}

func tpmSignatureFromSignatureECDSA(t *testing.T, r, s *big.Int) *TPMTSignature {
	t.Helper()

	return &TPMTSignature{
		SigAlg: TPMAlgECDSA,
		Signature: NewTPMUSignature(
			TPMAlgECDSA,
			&TPMSSignatureECC{
				Hash: TPMAlgSHA256,
				SignatureR: TPM2BECCParameter{
					Buffer: r.FillBytes(make([]byte, 32)),
				},
				SignatureS: TPM2BECCParameter{
					Buffer: s.FillBytes(make([]byte, 32)),
				},
			},
		),
	}
}

func verify(t *testing.T, msgDigest []byte, sig *TPMTSignature, pub crypto.PublicKey, alg TPMAlgID) {
	t.Helper()

	switch alg {
	case TPMAlgRSA:
		verifyRSA(t, msgDigest, sig, pub)
	case TPMAlgECDSA:
		verifyECDSA(t, msgDigest, sig, pub)
	default:
		t.Fatalf("unsupported signature algorithm %v", alg)
	}
}

func verifyRSA(t *testing.T, msgDigest []byte, sig *TPMTSignature, pub crypto.PublicKey) {
	t.Helper()

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("not an RSA public key")
	}
	rsaSig, err := sig.Signature.RSASSA()
	if err != nil {
		t.Fatalf("not an RSASSA signature: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, msgDigest, rsaSig.Sig.Buffer); err != nil {
		t.Errorf("rsa.VerifyPKCS1v15() = %v", err)
	}
}

func verifyECDSA(t *testing.T, msgDigest []byte, sig *TPMTSignature, pub crypto.PublicKey) {
	t.Helper()

	eccPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("not an RSA public key")
	}
	eccSig, err := sig.Signature.ECDSA()
	if err != nil {
		t.Fatalf("not an ECDSA signature: %v", err)
	}
	r := new(big.Int).SetBytes(eccSig.SignatureR.Buffer)
	s := new(big.Int).SetBytes(eccSig.SignatureS.Buffer)

	if !ecdsa.Verify(eccPub, msgDigest, r, s) {
		t.Error("ecdsa.Verify() = false")
	}
}

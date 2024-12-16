package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
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

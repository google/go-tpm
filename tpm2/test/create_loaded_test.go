package tpm2test

import (
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func getDeriver(t *testing.T, thetpm transport.TPM) NamedHandle {
	t.Helper()

	cl := CreateLoaded{
		ParentHandle: TPMRHOwner,
		InPublic: *NewTPM2BTemplate(
			NewTPMUTemplate(&TPMTPublic{
				Type:    TPMAlgKeyedHash,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
					Decrypt:             true,
					Restricted:          true,
				},
				Parameters: TPMUPublicParms{
					KeyedHashDetail: &TPMSKeyedHashParms{
						Scheme: TPMTKeyedHashScheme{
							Scheme: TPMAlgXOR,
							Details: *NewTPMUSchemeKeyedHash(
								TPMAlgXOR,
								&TPMSSchemeXOR{
									HashAlg: TPMAlgSHA256,
									KDF:     TPMAlgKDF1SP800108,
								},
							),
						},
					},
				},
			})),
	}
	rsp, err := cl.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not create derivation parent: %v:", err)
	}
	return NamedHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
	}
}

func TestCreateLoaded(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	deriver := getDeriver(t, thetpm)

	createLoadeds := map[string]*CreateLoaded{
		"PrimaryKey": {
			ParentHandle: TPMRHEndorsement,
			InPublic:     *NewTPM2BTemplate(NewTPMUTemplate(&ECCEKTemplate)),
		},
		"OrdinaryKey": {
			ParentHandle: TPMRHOwner,
			InSensitive: *NewTPM2BSensitiveCreate(
				&TPMSSensitiveCreate{
					UserAuth: TPM2BAuth{
						Buffer: []byte("p@ssw0rd"),
					},
				}),
			InPublic: *NewTPM2BTemplate(
				NewTPMUTemplate(&TPMTPublic{
					Type:    TPMAlgECC,
					NameAlg: TPMAlgSHA256,
					ObjectAttributes: TPMAObject{
						SensitiveDataOrigin: true,
						UserWithAuth:        true,
						SignEncrypt:         true,
					},
					Parameters: TPMUPublicParms{
						ECCDetail: &TPMSECCParms{
							CurveID: TPMECCNistP256,
						},
					},
				})),
		},
		"DataBlob": {
			ParentHandle: TPMRHOwner,
			InSensitive: *NewTPM2BSensitiveCreate(
				&TPMSSensitiveCreate{
					UserAuth: TPM2BAuth{
						Buffer: []byte("p@ssw0rd"),
					},
					Data: *NewTPMUSensitiveCreate(&TPM2BSensitiveData{
						Buffer: []byte("secrets"),
					}),
				}),
			InPublic: *NewTPM2BTemplate(
				NewTPMUTemplate(&TPMTPublic{
					Type:    TPMAlgKeyedHash,
					NameAlg: TPMAlgSHA256,
					ObjectAttributes: TPMAObject{
						UserWithAuth: true,
					},
				})),
		},
		"Derived": {
			ParentHandle: deriver,
			InSensitive: *NewTPM2BSensitiveCreate(
				&TPMSSensitiveCreate{
					UserAuth: TPM2BAuth{
						Buffer: []byte("p@ssw0rd"),
					},
					Data: *NewTPMUSensitiveCreate(NewTPM2BDerive(
						&TPMSDerive{
							Label: TPM2BLabel{
								Buffer: []byte("label"),
							},
							Context: TPM2BLabel{
								Buffer: []byte("context"),
							},
						})),
				}),
			InPublic: *NewTPM2BTemplate(
				NewTPMUTemplate(&TPMTPublic{
					Type:    TPMAlgECC,
					NameAlg: TPMAlgSHA256,
					ObjectAttributes: TPMAObject{
						FixedParent:  true,
						UserWithAuth: true,
						SignEncrypt:  true,
					},
					Parameters: TPMUPublicParms{
						ECCDetail: &TPMSECCParms{
							CurveID: TPMECCNistP256,
						},
					},
				})),
		},
	}

	for name, createLoaded := range createLoadeds {
		t.Run(name, func(t *testing.T) {
			rsp, err := createLoaded.Execute(thetpm)
			if err != nil {
				t.Fatalf("error from CreateLoaded: %v", err)
			}
			if err = (&FlushContext{FlushHandle: rsp.ObjectHandle}).Execute(thetpm); err != nil {
				t.Errorf("error from FlushContext: %v", err)
			}
		})
	}
}

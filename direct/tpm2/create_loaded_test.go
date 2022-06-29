package tpm2

import (
	"testing"

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpma"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	"github.com/google/go-tpm/direct/structures/tpmu"
	"github.com/google/go-tpm/direct/templates"
	"github.com/google/go-tpm/direct/transport"
	"github.com/google/go-tpm/direct/transport/simulator"
)

func getDeriver(t *testing.T, thetpm transport.TPM) NamedHandle {
	t.Helper()

	cl := CreateLoaded{
		ParentHandle: tpm.RHOwner,
		InPublic: tpm2b.Template{
			Template: tpmt.Public{
				Type:    tpm.AlgKeyedHash,
				NameAlg: tpm.AlgSHA256,
				ObjectAttributes: tpma.Object{
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
					Decrypt:             true,
					Restricted:          true,
				},
				Parameters: tpmu.PublicParms{
					KeyedHashDetail: &tpms.KeyedHashParms{
						Scheme: tpmt.KeyedHashScheme{
							Scheme: tpm.AlgXOR,
							Details: tpmu.SchemeKeyedHash{
								XOR: &tpms.SchemeXOR{
									HashAlg: tpm.AlgSHA256,
									KDF:     tpm.AlgKDF1SP800108,
								},
							},
						},
					},
				},
			},
		},
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
			ParentHandle: tpm.RHEndorsement,
			InPublic: tpm2b.Template{
				Template: templates.ECCEKTemplate,
			},
		},
		"OrdinaryKey": {
			ParentHandle: tpm.RHOwner,
			InSensitive: tpm2b.SensitiveCreate{
				Sensitive: tpms.SensitiveCreate{
					UserAuth: tpm2b.Auth{
						Buffer: []byte("p@ssw0rd"),
					},
				},
			},
			InPublic: tpm2b.Template{
				Template: tpmt.Public{
					Type:    tpm.AlgECC,
					NameAlg: tpm.AlgSHA256,
					ObjectAttributes: tpma.Object{
						SensitiveDataOrigin: true,
						UserWithAuth:        true,
						SignEncrypt:         true,
					},
					Parameters: tpmu.PublicParms{
						ECCDetail: &tpms.ECCParms{
							CurveID: tpm.ECCNistP256,
						},
					},
				},
			},
		},
		"DataBlob": {
			ParentHandle: tpm.RHOwner,
			InSensitive: tpm2b.SensitiveCreate{
				Sensitive: tpms.SensitiveCreate{
					UserAuth: tpm2b.Auth{
						Buffer: []byte("p@ssw0rd"),
					},
					Data: tpm2b.SensitiveData{
						Buffer: []byte("secrets"),
					},
				},
			},
			InPublic: tpm2b.Template{
				Template: tpmt.Public{
					Type:    tpm.AlgKeyedHash,
					NameAlg: tpm.AlgSHA256,
					ObjectAttributes: tpma.Object{
						UserWithAuth: true,
					},
				},
			},
		},
		"Derived": {
			ParentHandle: deriver,
			InSensitive: tpm2b.SensitiveCreate{
				Sensitive: tpms.SensitiveCreate{
					UserAuth: tpm2b.Auth{
						Buffer: []byte("p@ssw0rd"),
					},
					Data: tpm2b.Derive{
						Buffer: tpms.Derive{
							Label: tpm2b.Label{
								Buffer: []byte("label"),
							},
							Context: tpm2b.Label{
								Buffer: []byte("context"),
							},
						},
					},
				},
			},
			InPublic: tpm2b.Template{
				Template: tpmt.Public{
					Type:    tpm.AlgECC,
					NameAlg: tpm.AlgSHA256,
					ObjectAttributes: tpma.Object{
						FixedParent:  true,
						UserWithAuth: true,
						SignEncrypt:  true,
					},
					Parameters: tpmu.PublicParms{
						ECCDetail: &tpms.ECCParms{
							CurveID: tpm.ECCNistP256,
						},
					},
				},
			},
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

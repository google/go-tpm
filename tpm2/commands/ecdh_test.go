package tpm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm/tpm2/structures/tpm"
	"github.com/google/go-tpm/tpm2/structures/tpm2b"
	"github.com/google/go-tpm/tpm2/structures/tpma"
	"github.com/google/go-tpm/tpm2/structures/tpms"
	"github.com/google/go-tpm/tpm2/structures/tpmt"
	"github.com/google/go-tpm/tpm2/structures/tpmu"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestECDH(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	// Create a TPM ECDH key
	tpmCreate := CreatePrimary{
		PrimaryHandle: tpm.RHOwner,
		InPublic: tpm2b.Public{
			PublicArea: tpmt.Public{
				Type:    tpm.AlgECC,
				NameAlg: tpm.AlgSHA256,
				ObjectAttributes: tpma.Object{
					FixedTPM:             true,
					STClear:              false,
					FixedParent:          true,
					SensitiveDataOrigin:  true,
					UserWithAuth:         true,
					AdminWithPolicy:      false,
					NoDA:                 true,
					EncryptedDuplication: false,
					Restricted:           false,
					Decrypt:              true,
					SignEncrypt:          false,
					X509Sign:             false,
				},
				Parameters: tpmu.PublicParms{
					ECCDetail: &tpms.ECCParms{
						CurveID: tpm.ECCNistP256,
						Scheme: tpmt.ECCScheme{
							Scheme: tpm.AlgECDH,
							Details: tpmu.AsymScheme{
								ECDH: &tpms.KeySchemeECDH{
									HashAlg: tpm.AlgSHA256,
								},
							},
						},
					},
				},
			},
		},
	}

	tpmCreateRsp, err := tpmCreate.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not create the TPM key: %v", err)
	}
	tpmPub := tpmCreateRsp.OutPublic.PublicArea.Unique.ECC
	tpmX := big.NewInt(0).SetBytes(tpmPub.X.Buffer)
	tpmY := big.NewInt(0).SetBytes(tpmPub.Y.Buffer)

	// Create a SW ECDH key
	priv, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not create the SW key: %v", err)
	}
	swPub := tpms.ECCPoint{
		X: tpm2b.ECCParameter{Buffer: x.FillBytes(make([]byte, 32))},
		Y: tpm2b.ECCParameter{Buffer: y.FillBytes(make([]byte, 32))},
	}

	// Calculate Z based on the SW priv * TPM pub
	zx, zy := elliptic.P256().ScalarMult(tpmX, tpmY, priv)
	z := tpms.ECCPoint{
		X: tpm2b.ECCParameter{Buffer: zx.FillBytes(make([]byte, 32))},
		Y: tpm2b.ECCParameter{Buffer: zy.FillBytes(make([]byte, 32))},
	}

	// Calculate Z based on TPM priv * SW pub
	ecdh := ECDHZGen{
		KeyHandle: AuthHandle{
			Handle: tpmCreateRsp.ObjectHandle,
			Name:   tpmCreateRsp.Name,
			Auth:   PasswordAuth(nil),
		},
		InPoint: tpm2b.ECCPoint{
			Point: swPub,
		},
	}
	ecdhRsp, err := ecdh.Execute(thetpm)
	if err != nil {
		t.Fatalf("ECDH_ZGen failed: %v", err)
	}

	if !cmp.Equal(z, ecdhRsp.OutPoint.Point) {
		t.Errorf("want %x got %x", z, ecdhRsp.OutPoint.Point)
	}
}

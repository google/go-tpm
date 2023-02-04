package tpm2test

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	. "github.com/google/go-tpm/tpm2"
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
		PrimaryHandle: TPMRHOwner,
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgECC,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
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
			Parameters: NewTPMUPublicParms(
				TPMAlgECC,
				&TPMSECCParms{
					CurveID: TPMECCNistP256,
					Scheme: TPMTECCScheme{
						Scheme: TPMAlgECDH,
						Details: NewTPMUAsymScheme(
							TPMAlgECDH,
							&TPMSKeySchemeECDH{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
				},
			),
		}),
	}

	tpmCreateRsp, err := tpmCreate.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not create the TPM key: %v", err)
	}
	outPub, err := tpmCreateRsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	tpmPub, err := outPub.Unique.ECC()
	if err != nil {
		t.Fatalf("%v", err)
	}
	tpmX := big.NewInt(0).SetBytes(tpmPub.X.Buffer)
	tpmY := big.NewInt(0).SetBytes(tpmPub.Y.Buffer)

	// Create a SW ECDH key
	priv, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not create the SW key: %v", err)
	}
	swPub := TPMSECCPoint{
		X: TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, 32))},
		Y: TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, 32))},
	}

	// Calculate Z based on the SW priv * TPM pub
	zx, zy := elliptic.P256().ScalarMult(tpmX, tpmY, priv)
	z := TPMSECCPoint{
		X: TPM2BECCParameter{Buffer: zx.FillBytes(make([]byte, 32))},
		Y: TPM2BECCParameter{Buffer: zy.FillBytes(make([]byte, 32))},
	}

	// Calculate Z based on TPM priv * SW pub
	ecdh := ECDHZGen{
		KeyHandle: AuthHandle{
			Handle: tpmCreateRsp.ObjectHandle,
			Name:   tpmCreateRsp.Name,
			Auth:   PasswordAuth(nil),
		},
		InPoint: New2B(swPub),
	}
	ecdhRsp, err := ecdh.Execute(thetpm)
	if err != nil {
		t.Fatalf("ECDH_ZGen failed: %v", err)
	}

	outPoint, err := ecdhRsp.OutPoint.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !cmp.Equal(z.X, outPoint.X, cmpopts.IgnoreUnexported(z.X)) {
		t.Errorf("want %x got %x", z, outPoint)
	}
}

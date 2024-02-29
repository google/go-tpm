package tpm2test

import (
	"crypto/ecdh"
	"crypto/rand"
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

	// Use NIST P-256
	curve := ecdh.P256()

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
	tpmPubKey, err := ECDHPubKey(curve, tpmPub)
	if err != nil {
		t.Fatalf("could not unmarshall pubkey: %v", err)
	}

	// Create a SW ECDH key
	swPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not create the SW key: %v", err)
	}
	x, y, err := ECCPoint(swPriv.PublicKey())
	if err != nil {
		t.Fatalf("could not get SW key point: %v", err)
	}
	swPub := TPMSECCPoint{
		X: TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, 32))},
		Y: TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, 32))},
	}

	// Calculate Z based on the SW priv * TPM pub
	zx, err := swPriv.ECDH(tpmPubKey)
	if err != nil {
		t.Fatalf("ecdh exchange: %v", err)
	}

	z := TPMSECCPoint{
		X: TPM2BECCParameter{Buffer: zx},
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

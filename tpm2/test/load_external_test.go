package tpm2test

import (
	"encoding/hex"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func decodeHex(t *testing.T, h string) []byte {
	t.Helper()
	data, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("could not decode '%v' as hex data: %v", h, err)
	}
	return data
}

func TestLoadExternal(t *testing.T) {
	loads := map[string]*LoadExternal{
		"ECCNoSensitive": {
			InPublic: New2B(TPMTPublic{
				Type:    TPMAlgECC,
				NameAlg: TPMAlgSHA256,
				ObjectAttributes: TPMAObject{
					SignEncrypt: true,
				},
				Parameters: NewTPMUPublicParms(
					TPMAlgECC,
					&TPMSECCParms{
						CurveID: TPMECCNistP256,
					},
				),
				Unique: NewTPMUPublicID(
					// This happens to be a P256 EKpub from the simulator
					TPMAlgECC,
					&TPMSECCPoint{
						X: TPM2BECCParameter{Buffer: decodeHex(t, "9855efa3514873b88067ab127b2d4692864a395db3d9e4ccad0592478a245c16")},
						Y: TPM2BECCParameter{Buffer: decodeHex(t, "e802a26649839a2d7b13c812a5dc0b61c110cbe62db784d96e60a823448c8993")},
					},
				),
			}),
		},
		"KeyedHashSensitive": {
			InPrivate: New2B(
				TPMTSensitive{
					SensitiveType: TPMAlgKeyedHash,
					SeedValue: TPM2BDigest{
						Buffer: []byte("obfuscation is my middle name!!!"),
					},
					Sensitive: NewTPMUSensitiveComposite(
						TPMAlgKeyedHash,
						&TPM2BSensitiveData{
							Buffer: []byte("secrets"),
						},
					),
				}),
			InPublic: New2B(
				TPMTPublic{
					Type:    TPMAlgKeyedHash,
					NameAlg: TPMAlgSHA256,
					Unique: NewTPMUPublicID(
						TPMAlgKeyedHash,
						&TPM2BDigest{
							// SHA256("obfuscation is my middle name!!!secrets")
							Buffer: decodeHex(t, "ed4fe8e2bff97665e7bfbe27c2365d07a9be91dd92d997cd91cc706b6074eb08"),
						},
					),
				}),
		},
	}

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	for name, load := range loads {
		t.Run(name, func(t *testing.T) {
			rsp, err := load.Execute(thetpm)
			if err != nil {
				t.Fatalf("error from LoadExternal: %v", err)
			}
			if _, err = (FlushContext{FlushHandle: rsp.ObjectHandle}).Execute(thetpm); err != nil {
				t.Errorf("error from FlushContext: %v", err)
			}
		})
	}
}

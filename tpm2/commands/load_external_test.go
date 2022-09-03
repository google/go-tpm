package tpm2

import (
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2/structures/tpm"
	"github.com/google/go-tpm/tpm2/structures/tpm2b"
	"github.com/google/go-tpm/tpm2/structures/tpma"
	"github.com/google/go-tpm/tpm2/structures/tpms"
	"github.com/google/go-tpm/tpm2/structures/tpmt"
	"github.com/google/go-tpm/tpm2/structures/tpmu"
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
			InPublic: tpm2b.Public{
				PublicArea: tpmt.Public{
					Type:    tpm.AlgECC,
					NameAlg: tpm.AlgSHA256,
					ObjectAttributes: tpma.Object{
						SignEncrypt: true,
					},
					Parameters: tpmu.PublicParms{
						ECCDetail: &tpms.ECCParms{
							CurveID: tpm.ECCNistP256,
						},
					},
					Unique: tpmu.PublicID{
						// This happens to be a P256 EKpub from the simulator
						ECC: &tpms.ECCPoint{
							X: tpm2b.ECCParameter{Buffer: decodeHex(t, "9855efa3514873b88067ab127b2d4692864a395db3d9e4ccad0592478a245c16")},
							Y: tpm2b.ECCParameter{Buffer: decodeHex(t, "e802a26649839a2d7b13c812a5dc0b61c110cbe62db784d96e60a823448c8993")},
						},
					},
				},
			},
		},
		"KeyedHashSensitive": {
			InPrivate: &tpm2b.Sensitive{
				SensitiveArea: tpmt.Sensitive{
					SensitiveType: tpm.AlgKeyedHash,
					SeedValue: tpm2b.Digest{
						Buffer: []byte("obfuscation is my middle name!!!"),
					},
					Sensitive: tpmu.SensitiveComposite{
						Bits: &tpm2b.SensitiveData{
							Buffer: []byte("secrets"),
						},
					},
				},
			},
			InPublic: tpm2b.Public{
				PublicArea: tpmt.Public{
					Type:    tpm.AlgKeyedHash,
					NameAlg: tpm.AlgSHA256,
					Unique: tpmu.PublicID{
						KeyedHash: &tpm2b.Digest{
							// SHA256("obfuscation is my middle name!!!secrets")
							Buffer: decodeHex(t, "ed4fe8e2bff97665e7bfbe27c2365d07a9be91dd92d997cd91cc706b6074eb08"),
						},
					},
				},
			},
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
			if err = (&FlushContext{FlushHandle: rsp.ObjectHandle}).Execute(thetpm); err != nil {
				t.Errorf("error from FlushContext: %v", err)
			}
		})
	}
}

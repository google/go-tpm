package tpm2test

import (
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestTestParms(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	for _, tt := range []struct {
		name       string
		parms      TPMTPublicParms
		shouldfail bool
	}{
		{
			"p256",
			TPMTPublicParms{
				Type: TPMAlgECC,
				Parameters: NewTPMUPublicParms(
					TPMAlgECC,
					&TPMSECCParms{
						CurveID: TPMECCNistP256,
					},
				),
			},
			false,
		},
		{
			"p364",
			TPMTPublicParms{
				Type: TPMAlgECC,
				Parameters: NewTPMUPublicParms(
					TPMAlgECC,
					&TPMSECCParms{
						CurveID: TPMECCNistP384,
					},
				),
			},
			false,
		},
		{
			"p521",
			TPMTPublicParms{
				Type: TPMAlgECC,
				Parameters: NewTPMUPublicParms(
					TPMAlgECC,
					&TPMSECCParms{
						CurveID: TPMECCNistP521,
					},
				),
			},
			false,
		},
		{
			"rsa2048",
			TPMTPublicParms{
				Type: TPMAlgRSA,
				Parameters: NewTPMUPublicParms(
					TPMAlgRSA,
					&TPMSRSAParms{
						KeyBits: 2048,
					},
				),
			},
			false,
		},
		{
			"rsa3072 - unsupported",
			TPMTPublicParms{
				Type: TPMAlgRSA,
				Parameters: NewTPMUPublicParms(
					TPMAlgRSA,
					&TPMSRSAParms{
						KeyBits: 3072,
					},
				),
			},
			true,
		},
		{
			"rsa4096 - unsupported",
			TPMTPublicParms{
				Type: TPMAlgRSA,
				Parameters: NewTPMUPublicParms(
					TPMAlgRSA,
					&TPMSRSAParms{
						KeyBits: 4096,
					},
				),
			},
			true,
		},
	} {
		grc := TestParms{Paramteres: tt.parms}
		_, err := grc.Execute(thetpm)

		if err == nil && tt.shouldfail {
			t.Fatalf("TestParms failed should have failed, didn't")
		}

		if err != nil && !tt.shouldfail {
			t.Fatalf("TestParms failed: %v", err)
		}
	}
}

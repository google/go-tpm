package tpm2test

import (
	"errors"
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
		name    string
		parms   TPMTPublicParms
		wantErr error
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
			nil,
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
			nil,
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
			nil,
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
			nil,
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
			TPMRCValue,
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
			TPMRCValue,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			grc := TestParms{Parameters: tt.parms}
			_, err := grc.Execute(thetpm)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("TestParms failed failed. Expecting err %v got %v", tt.wantErr, err)
			}
		})
	}
}

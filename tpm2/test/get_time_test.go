package tpm2test

import (
	"bytes"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestGetTime(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	createPrimary := CreatePrimary{
		PrimaryHandle: TPMRHEndorsement,
		InPublic: New2B(TPMTPublic{
			Type:    TPMAlgRSA,
			NameAlg: TPMAlgSHA256,
			ObjectAttributes: TPMAObject{
				SignEncrypt:         true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: NewTPMUPublicParms(
				TPMAlgRSA,
				&TPMSRSAParms{
					Scheme: TPMTRSAScheme{
						Scheme: TPMAlgRSASSA,
						Details: NewTPMUAsymScheme(
							TPMAlgRSASSA,
							&TPMSSigSchemeRSASSA{
								HashAlg: TPMAlgSHA256,
							},
						),
					},
					KeyBits: 2048,
				},
			),
		}),
	}

	rspCP, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not create key: %v", err)
	}

	flushContext := FlushContext{FlushHandle: rspCP.ObjectHandle}
	defer flushContext.Execute(thetpm)

	qualifyingData := []byte("migrationpains")

	getTimeCommand := GetTime{
		PrivacyAdminHandle: TPMRHEndorsement,
		SignHandle:         NamedHandle{Handle: rspCP.ObjectHandle, Name: rspCP.Name},
		QualifyingData:     TPM2BData{Buffer: qualifyingData},
	}
	getTimeResponse, err := getTimeCommand.Execute(thetpm)
	if err != nil {
		t.Fatalf("GetTime failed: %v", err)
	}

	tpmsAttest, err := getTimeResponse.TimeInfo.Contents()

	if err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	tpmsTimeAttestInfo, err := tpmsAttest.Attested.Time()

	if err != nil {
		t.Fatalf("union typed field did not have expected concrete type: %v", err)
	}

	if tpmsTimeAttestInfo.Time.ClockInfo.Clock != tpmsAttest.ClockInfo.Clock {
		t.Errorf("clockInfo does not match in tpmsTimeAttestInfo (%x) vs tpmsAttest (%x)",
			tpmsTimeAttestInfo.Time.ClockInfo.Clock, tpmsAttest.ClockInfo.Clock)
	}

	if tpmsTimeAttestInfo.Time.ClockInfo.ResetCount != tpmsAttest.ClockInfo.ResetCount {
		t.Errorf("resetCount does not match in tpmsTimeAttestInfo (%x) vs tpmsAttest (%x)",
			tpmsTimeAttestInfo.Time.ClockInfo.ResetCount, tpmsAttest.ClockInfo.ResetCount)
	}

	if tpmsTimeAttestInfo.Time.ClockInfo.RestartCount != tpmsAttest.ClockInfo.RestartCount {
		t.Errorf("restartCount does not match in tpmsTimeAttestInfo (%x) vs tpmsAttest (%x)",
			tpmsTimeAttestInfo.Time.ClockInfo.RestartCount, tpmsAttest.ClockInfo.RestartCount)
	}

	if !bytes.Equal(tpmsAttest.ExtraData.Buffer, qualifyingData) {
		t.Errorf("extraData does not match. Saw (%v), expected (%v)",
			tpmsAttest.ExtraData.Buffer,
			qualifyingData)
	}
}

package tpm2test

import (
	"bytes"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestActivateCredential(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	ekCreate := CreatePrimary{
		PrimaryHandle: TPMRHEndorsement,
		InPublic:      New2B(ECCEKTemplate),
	}

	ekCreateRsp, err := ekCreate.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not generate EK: %v", err)
	}
	defer func() {
		flush := FlushContext{
			FlushHandle: ekCreateRsp.ObjectHandle,
		}
		_, err := flush.Execute(thetpm)
		if err != nil {
			t.Fatalf("could not flush EK: %v", err)
		}
	}()

	srkCreate := CreatePrimary{
		PrimaryHandle: TPMRHOwner,
		InPublic:      New2B(ECCSRKTemplate),
	}

	srkCreateRsp, err := srkCreate.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not generate SRK: %v", err)
	}
	defer func() {
		flush := FlushContext{
			FlushHandle: srkCreateRsp.ObjectHandle,
		}
		_, err := flush.Execute(thetpm)
		if err != nil {
			t.Fatalf("could not flush SRK: %v", err)
		}
	}()

	secret := TPM2BDigest{Buffer: []byte("Secrets!!!")}

	mc := MakeCredential{
		Handle:      ekCreateRsp.ObjectHandle,
		Credential:  secret,
		ObjectNamae: srkCreateRsp.Name,
	}
	mcRsp, err := mc.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not make credential: %v", err)
	}

	ac := ActivateCredential{
		ActivateHandle: NamedHandle{
			Handle: srkCreateRsp.ObjectHandle,
			Name:   srkCreateRsp.Name,
		},
		KeyHandle: AuthHandle{
			Handle: ekCreateRsp.ObjectHandle,
			Name:   ekCreateRsp.Name,
			Auth:   Policy(TPMAlgSHA256, 16, ekPolicy),
		},
		CredentialBlob: mcRsp.CredentialBlob,
		Secret:         mcRsp.Secret,
	}
	acRsp, err := ac.Execute(thetpm)
	if err != nil {
		t.Fatalf("could not activate credential: %v", err)
	}

	if !bytes.Equal(acRsp.CertInfo.Buffer, secret.Buffer) {
		t.Errorf("want %x got %x", secret.Buffer, acRsp.CertInfo.Buffer)
	}
}

package tpm2

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/transport/simulator"
)

func TestHash(t *testing.T) {

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	hashF := Hash{
		Data:      tpm2b.MaxBuffer{Buffer: []byte("fiona")},
		HashAlg:   tpm.AlgSHA256,
		Hierarchy: tpm.RHOwner,
	}
	rspF, err := hashF.Execute(thetpm)

	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	hashC := Hash{
		Data:      tpm2b.MaxBuffer{Buffer: []byte("charlie")},
		HashAlg:   tpm.AlgSHA256,
		Hierarchy: tpm.RHOwner,
	}
	rspC, err := hashC.Execute(thetpm)

	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if cmp.Equal(rspC, rspF) {
		t.Fatalf("Hash not collision resistant")
	}

	if !cmp.Equal(rspF.Validation.Hierarchy, tpm.RHOwner) {
		t.Fatalf("Reponse Handle doesn't match Input Handle")
	}
}

func TestHashSequence(t *testing.T) {

	maxDigestBuffer := 1024

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	Auth := []byte("password")
	hashSequenceStart := HashSequenceStart{
		Auth: tpm2b.Auth{
			Buffer: Auth,
		},
		HashAlg: tpm.AlgSHA256,
	}

	rspHSS, err := hashSequenceStart.Execute(thetpm)
	if err != nil {
		t.Fatalf("HashSequenceStart failed: %v", err)
	}

	authHandle := AuthHandle{
		Handle: rspHSS.SequenceHandle,
		Name: tpm2b.Name{
			Buffer: Auth,
		},
		Auth: PasswordAuth(Auth),
	}

	data := make([]byte, 2048)
	rand.Read(data)

	wantDigest := sha256.Sum256(data)

	for len(data) > maxDigestBuffer {
		sequenceUpdate := SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2b.MaxBuffer{
				Buffer: data[:maxDigestBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(thetpm)
		if err != nil {
			t.Fatalf("SequenceUpdate failed: %v", err)
		}

		data = data[maxDigestBuffer:]
	}

	sequenceComplete := SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2b.MaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm.RHOwner,
	}

	rspSC, err := sequenceComplete.Execute(thetpm)
	if err != nil {
		t.Fatalf("SequenceComplete failed: %v", err)
	}

	gotDigest := rspSC.Result.Buffer

	if !bytes.Equal(gotDigest, wantDigest[:]) {
		t.Errorf("The resulting digest %x, is not expectied %x", gotDigest, wantDigest)
	}
}

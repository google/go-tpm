package tpm2

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"testing"

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/transport"
	"github.com/google/go-tpm/direct/transport/simulator"
)

func TestHash(t *testing.T) {

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	run := func(t *testing.T, data []byte, hierarchy tpm.Handle, thetpm transport.TPM) {
		hash := Hash{
			Data:      tpm2b.MaxBuffer{Buffer: data},
			HashAlg:   tpm.AlgSHA256,
			Hierarchy: hierarchy,
		}
		rspHash, err := hash.Execute(thetpm)
		if err != nil {
			t.Fatalf("Hash failed: %v", err)
		}
		gotDigest := rspHash.OutHash.Buffer
		wantDigest := sha256.Sum256(data)

		if !bytes.Equal(gotDigest, wantDigest[:]) {
			t.Errorf("Hash(%q) returned digest %x, want %x", data, gotDigest, wantDigest)
		}
	}

	t.Run("Null hierarchy", func(t *testing.T) {
		run(t, []byte("fiona"), tpm.RHNull, thetpm)
	})

	t.Run("Owner hierarchy", func(t *testing.T) {
		run(t, []byte("charlie"), tpm.RHOwner, thetpm)
	})
}

func TestHashSequence(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	run := func(t *testing.T, bufferSize int, password string, hierarchy tpm.Handle, thetpm transport.TPM) {
		maxDigestBuffer := 1024
		Auth := []byte(password)

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

		data := make([]byte, bufferSize)
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
			t.Errorf("The resulting digest %x, is not expected %x", gotDigest, wantDigest)
		}
	}
	//  t *testing.T, bufferSize int, password string, hierarchy tpm.Handle, thetpm transport.TPM
	bufferSizes := []int{512, 1024, 2048, 4096}
	password := "password"
	for _, bufferSize := range bufferSizes {
		t.Run(fmt.Sprintf("Null hierarchy [bufferSize=%d]", bufferSize), func(t *testing.T) {
			run(t, bufferSize, password, tpm.RHNull, thetpm)
		})
		t.Run(fmt.Sprintf("Owner hierarchy [bufferSize=%d]", bufferSize), func(t *testing.T) {
			run(t, bufferSize, password, tpm.RHOwner, thetpm)
		})
	}
}

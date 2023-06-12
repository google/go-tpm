package tpm2test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestHash(t *testing.T) {

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	run := func(t *testing.T, data []byte, hierarchy TPMHandle, thetpm transport.TPM) {
		hash := Hash{
			Data:      TPM2BMaxBuffer{Buffer: data},
			HashAlg:   TPMAlgSHA256,
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
		run(t, []byte("fiona"), TPMRHNull, thetpm)
	})

	t.Run("Owner hierarchy", func(t *testing.T) {
		run(t, []byte("charlie"), TPMRHOwner, thetpm)
	})
}

func TestHashNullHierarchy(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	data := []byte("carolyn")
	hash := Hash{
		Data:    TPM2BMaxBuffer{Buffer: data},
		HashAlg: TPMAlgSHA256,
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

func TestHashSequence(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	run := func(t *testing.T, bufferSize int, password string, hierarchy TPMHandle, thetpm transport.TPM) {
		maxDigestBuffer := 1024
		Auth := []byte(password)

		hashSequenceStart := HashSequenceStart{
			Auth: TPM2BAuth{
				Buffer: Auth,
			},
			HashAlg: TPMAlgSHA256,
		}

		rspHSS, err := hashSequenceStart.Execute(thetpm)
		if err != nil {
			t.Fatalf("HashSequenceStart failed: %v", err)
		}

		authHandle := AuthHandle{
			Handle: rspHSS.SequenceHandle,
			Name: TPM2BName{
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
				Buffer: TPM2BMaxBuffer{
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
			Buffer: TPM2BMaxBuffer{
				Buffer: data,
			},
			Hierarchy: hierarchy,
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
	bufferSizes := []int{512, 1024, 2048, 4096}
	password := "password"
	for _, bufferSize := range bufferSizes {
		t.Run(fmt.Sprintf("Null hierarchy [bufferSize=%d]", bufferSize), func(t *testing.T) {
			run(t, bufferSize, password, TPMRHNull, thetpm)
		})
		t.Run(fmt.Sprintf("Owner hierarchy [bufferSize=%d]", bufferSize), func(t *testing.T) {
			run(t, bufferSize, password, TPMRHOwner, thetpm)
		})
	}
}

func TestHashSequenceNullHierarchy(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	run := func(t *testing.T, bufferSize int, password string, thetpm transport.TPM) {
		maxDigestBuffer := 1024
		Auth := []byte(password)

		hashSequenceStart := HashSequenceStart{
			Auth: TPM2BAuth{
				Buffer: Auth,
			},
			HashAlg: TPMAlgSHA256,
		}

		rspHSS, err := hashSequenceStart.Execute(thetpm)
		if err != nil {
			t.Fatalf("HashSequenceStart failed: %v", err)
		}

		authHandle := AuthHandle{
			Handle: rspHSS.SequenceHandle,
			Name: TPM2BName{
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
				Buffer: TPM2BMaxBuffer{
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
			Buffer: TPM2BMaxBuffer{
				Buffer: data,
			},
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
	//  t *testing.T, bufferSize int, password string, hierarchy TPMHandle, thetpm transport.TPM
	bufferSizes := []int{512, 1024, 2048, 4096}
	password := "password"
	for _, bufferSize := range bufferSizes {
		t.Run(fmt.Sprintf("Null hierarchy [bufferSize=%d]", bufferSize), func(t *testing.T) {
			run(t, bufferSize, password, thetpm)
		})
	}
}

package tpm2test

import (
	"crypto/rand"
	"io"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

func TestStirRandom(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		t.Fatalf("reading seed: %v", err)
	}

	stir := StirRandom{
		InData: TPM2BSensitiveData{Buffer: seed},
	}
	if _, err := stir.Execute(thetpm); err != nil {
		t.Fatalf("StirRandom failed: %v", err)
	}

	// The TPM must still hand out random bytes after being stirred.
	rsp, err := GetRandom{BytesRequested: 16}.Execute(thetpm)
	if err != nil {
		t.Fatalf("GetRandom after StirRandom failed: %v", err)
	}
	if len(rsp.RandomBytes.Buffer) != 16 {
		t.Errorf("GetRandom returned %d bytes, want 16", len(rsp.RandomBytes.Buffer))
	}
}

func TestStirRandomTooLarge(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	// TPM2B_SENSITIVE_DATA is bounded by MAX_SYM_DATA (128 in the reference
	// implementation), so 129 bytes must be rejected rather than truncated.
	stir := StirRandom{
		InData: TPM2BSensitiveData{Buffer: make([]byte, 129)},
	}
	if _, err := stir.Execute(thetpm); err == nil {
		t.Errorf("StirRandom with 129 bytes succeeded, want an error")
	}
}

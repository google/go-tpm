package tpm2test

import (
	"errors"
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

func TestStirRandom(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	src := StirRandom{
		InData: TPM2BSensitiveData{
			Buffer: []byte("wombat"),
		},
	}

	if _, err := src.Execute(thetpm); err != nil {
		t.Fatalf("StirRandom failed: %v", err)
	}

	// The TPM must still be able to produce random data afterwards.
	grc := GetRandom{
		BytesRequested: 16,
	}

	rsp, err := grc.Execute(thetpm)
	if err != nil {
		t.Fatalf("GetRandom failed: %v", err)
	}
	if len(rsp.RandomBytes.Buffer) != 16 {
		t.Errorf("GetRandom returned %v bytes, want 16", len(rsp.RandomBytes.Buffer))
	}
}

// TestStirRandomSize pins the bound on inData. It comes from TPM2B_SENSITIVE_DATA
// holding at most MAX_SYM_DATA (128) octets, not from TPM2_StirRandom itself.
func TestStirRandomSize(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	for _, tc := range []struct {
		name string
		size int
		want error
	}{
		{"Empty", 0, nil},
		{"MaxSymData", 128, nil},
		{"TooBig", 129, TPMRCSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := StirRandom{
				InData: TPM2BSensitiveData{
					Buffer: make([]byte, tc.size),
				},
			}

			_, err := src.Execute(thetpm)
			if tc.want == nil {
				if err != nil {
					t.Errorf("StirRandom with %v octets failed: %v", tc.size, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("StirRandom with %v octets = %v, want %v", tc.size, err, tc.want)
			}
		})
	}
}

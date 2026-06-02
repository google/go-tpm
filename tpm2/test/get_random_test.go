package tpm2test

import (
	"testing"

	. "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/testhelper"
)

func TestGetRandom(t *testing.T) {
	thetpm := testhelper.Open(t)
	defer thetpm.Close()

	grc := GetRandom{
		BytesRequested: 16,
	}

	if _, err := grc.Execute(thetpm); err != nil {
		t.Fatalf("GetRandom failed: %v", err)
	}
}

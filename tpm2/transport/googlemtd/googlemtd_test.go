//go:build !windows

package googlemtd

import (
	"testing"
)

func TestGetTitanMtdTPM(t *testing.T) {
	// Use a non-existent path to ensure it fails.
	opts := Options{
		Path: "/dev/non_existent_mtd_device_path",
	}
	tpm, err := Open(opts)
	if tpm != nil {
		t.Errorf("Expected a nil TPM.")
	}
	if err == nil {
		t.Errorf("Expected a non-nil error.")
	}
}

// Package testhelper provides some helper code for TPM transport tests.
package testhelper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// RunTest checks that the connection to the given TPM seems to be working.
func RunTest(t *testing.T, skipErrs []error, tpmOpener func() (transport.TPMCloser, error)) {
	tpm, err := tpmOpener()
	for _, skipErr := range skipErrs {
		if errors.Is(err, skipErr) {
			t.Skipf("%v", err)
		}
	}
	if err != nil {
		t.Fatalf("Failed to open TPM: %v", err)
	}
	defer func(tpm transport.TPMCloser) {
		if err := tpm.Close(); err != nil {
			t.Fatalf("tpm.Close() = %v", err)
		}
	}(tpm)

	// Ping the TPM to ask it what the manufacturer is, as a basic consistency check.
	cap, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTManufacturer),
		PropertyCount: 1,
	}.Execute(tpm)

	// We might run into one of the known "skip if this error" cases.
	for _, skipErr := range skipErrs {
		if errors.Is(err, skipErr) {
			t.Skipf("%v", err)
		}
	}
	if err != nil {
		t.Fatalf("GetCapability() = %v", err)
	}
	props, err := cap.CapabilityData.Data.TPMProperties()
	if err != nil {
		t.Fatalf("cap.TPMProperties() = %v", err)
	}
	if len(props.TPMProperty) != 1 {
		t.Fatalf("GetCapability() = %v properties, want 1", len(props.TPMProperty))
	}

	var idBuf bytes.Buffer
	idBuf.Grow(4)
	binary.Write(&idBuf, binary.BigEndian, props.TPMProperty[0].Value)
	t.Logf("Manufacturer ID: %q", idBuf.String())
}

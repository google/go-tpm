// Package tpm2 implements an adapter layer expected by github.com/google/go-tpm-tools/simulator
// TODO: after release, we can update simulator to use the new API
package tpm2

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

// StartupClear tells the TPM to perform a Reset and not a Restart.
var StartupClear = tpm2.StartupClear

// Startup initializes the TPM
func Startup(rw io.ReadWriter, typ tpm2.StartupType) error {
	return tpm2.Startup(rw, typ)
}

// Shutdown prepares the TPM for a power loss.
func Shutdown(rw io.ReadWriter, typ tpm2.StartupType) error {
	return tpm2.Shutdown(rw, typ)
}

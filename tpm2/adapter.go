// package tpm2 implements an adapter layer expected by github.com/google/go-tpm-tools/simulator
// TODO: after release, we can update simulator to use the new API
package tpm2

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

var StartupClear = tpm2.StartupClear

func Startup(rw io.ReadWriter, typ tpm2.StartupType) error {
	return tpm2.Startup(rw, typ)
}

func Shutdown(rw io.ReadWriter, typ tpm2.StartupType) error {
	return tpm2.Shutdown(rw, typ)
}

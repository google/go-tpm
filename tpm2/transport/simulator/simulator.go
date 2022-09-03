// Package simulator provides access to a local simulator for TPM testing.
package simulator

import (
	"io"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// TPM represents a connection to a TPM simulator.
type TPM struct {
	transport io.ReadWriteCloser
}

// Send implements the TPM interface.
func (t *TPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// OpenSimulator starts and opens a TPM simulator.
func OpenSimulator() (transport.TPMCloser, error) {
	sim, err := simulator.Get()
	if err != nil {
		return nil, err
	}
	return &TPM{
		transport: sim,
	}, nil
}

// Close implements the TPM interface.
func (t *TPM) Close() error {
	return t.transport.Close()
}

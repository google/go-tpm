// package transport implements types for physically talking to TPMs.
package transport

import (
	"io"

	"github.com/google/go-tpm/tpmutil"
)

// TPM represents a logical connection to a TPM.
type TPM interface {
	Send(input []byte) ([]byte, error)
}

// TPMCloser represents a logical connection to a TPM and you can close it!!!.
type TPMCloser interface {
	TPM
	Close() error
}

type tempTPM struct {
	transport io.ReadWriter
}

// LocalTPM represents a connection to the local TPM.
type LocalTPM struct {
	transport io.ReadWriteCloser
}

func WrapReadWrite(rw io.ReadWriter) (TPM, error) {
	return &tempTPM{transport: rw}, nil
}

// Send implements the TPM interface.
func (t *tempTPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// Send implements the TPM interface.
func (t *LocalTPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// Close implements the TPM interface.
func (t *LocalTPM) Close() error {
	return t.transport.Close()
}

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

// TPMCloser represents a logical connection to a TPM and you can close it.
type TPMCloser interface {
	TPM
	io.Closer
}

// The wrappedRW represents a struct that wraps an io.ReadWriter
// to function like a transport.TPM.
type wrappedRW struct {
	transport io.ReadWriter
}

// The wrappedRWC represents a struct that wraps an io.ReadWriteCloser
// to function like a transport.TPM with the close function.
type wrappedRWC struct {
	transport io.ReadWriteCloser
}

// The wrappedTPM represents a struct that wraps a transport.TPM 
// to function like a io.ReadWriter
type wrappedTPM struct {
	response []byte
	tpm      TPM
}

// FromReadWritter takes in a io.ReadWriter TPM and returns a
// transport.TPm wrapping the io.ReadWriter.
func FromReadWriter(rw io.ReadWriter) TPM {
	return &wrappedRW{transport: rw}
}

// ToReadWritter takes in a transport TPM and returns an
// io.ReadWriter wrapping the transport TPM.
func ToReadWriter(tpm TPM) io.ReadWriter {
	return &wrappedTPM{tpm: tpm}
}

// Read copies t.response into the p buffer and return the appropriate length.
func (t *wrappedTPM) Read(p []byte) (n int, err error) {
	p = t.response
	return len(p), nil
}

// Write writes len(p) bytes from p to the underlying data stream.
// It returns the number of bytes written from p (0 <= n <= len(p))
// and any error encountered that caused the write to stop early.
// Write must return a non-nil error if it returns n < len(p).
// Write must not modify the slice data, even temporarily.
//
// Implementations must not retain p.
func (t *wrappedTPM) Write(p []byte) (n int, err error) {
	t.response, err = t.tpm.Send(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Send implements the TPM interface.
func (t *wrappedRW) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// Send implements the TPM interface.
func (t *wrappedRWC) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// Close implements the TPM interface.
func (t *wrappedRWC) Close() error {
	return t.transport.Close()
}

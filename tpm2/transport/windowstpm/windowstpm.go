//go:build windows

// Package windowstpm implements the TPM transport on Windows using tbs.dll.
package windowstpm

import (
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil/tbs"
)

var (
	// ErrNotTPM20 indicates that a TPM 2.0 was not found.
	ErrNotTPM20 = errors.New("device is not a TPM 2.0")
)

const (
	maxTPMResponse = 4096
)

// Open opens a channel to the TPM via TBS.
func Open() (transport.TPMCloser, error) {
	info, err := tbs.GetDeviceInfo()
	if err != nil {
		return nil, err
	}

	if info.TPMVersion != tbs.TPMVersion20 {
		return nil, fmt.Errorf("%w: %v", ErrNotTPM20, info.TPMVersion)
	}

	tpmContext, err := tbs.CreateContext(tbs.TPMVersion20, tbs.IncludeTPM20)
	rwc := &winTPMBuffer{
		context:   tpmContext,
		outBuffer: make([]byte, 0, maxTPMResponse),
	}
	return transport.FromReadWriteCloser(rwc), err
}

// winTPMBuffer is a ReadWriteCloser to access the TPM in Windows.
type winTPMBuffer struct {
	context   tbs.Context
	outBuffer []byte
}

// Write implements the io.Writer interface.
//
// Executes the TPM command specified by commandBuffer (at Normal Priority), returning the number
// of bytes in the command and any error code returned by executing the TPM command. Command
// response can be read by calling Read().
func (rwc *winTPMBuffer) Write(commandBuffer []byte) (int, error) {
	// TPM spec defines longest possible response to be maxTPMResponse.
	rwc.outBuffer = rwc.outBuffer[:maxTPMResponse]

	outBufferLen, err := rwc.context.SubmitCommand(
		tbs.NormalPriority,
		commandBuffer,
		rwc.outBuffer,
	)

	if err != nil {
		rwc.outBuffer = rwc.outBuffer[:0]
		return 0, err
	}
	// Shrink outBuffer so it is length of response.
	rwc.outBuffer = rwc.outBuffer[:outBufferLen]
	return len(commandBuffer), nil
}

// Read implements the io.Reader interface.
//
// Provides TPM response from the command called in the last Write call.
func (rwc *winTPMBuffer) Read(responseBuffer []byte) (int, error) {
	if len(rwc.outBuffer) == 0 {
		return 0, io.EOF
	}
	lenCopied := copy(responseBuffer, rwc.outBuffer)
	// Cut out the piece of slice which was just read out, maintaining original slice capacity.
	rwc.outBuffer = append(rwc.outBuffer[:0], rwc.outBuffer[lenCopied:]...)
	return lenCopied, nil
}

// Close implements the io.Closer interface.
func (rwc *winTPMBuffer) Close() error {
	return rwc.context.Close()
}

//go:build !windows

// Package linuxudstpm provides access to a TPM device via a Unix domain socket.
package linuxudstpm

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
)

var (
	// ErrFileIsNotSocket indicates that the TPM file is not a socket.
	ErrFileIsNotSocket = errors.New("TPM file is not a socket")
	// ErrMustCallWriteThenRead indicates that the file was not written-then-read in the expected pattern.
	ErrMustCallWriteThenRead = errors.New("must call Write then Read in an alternating sequence")
	// ErrNotOpen indicates that the TPM file is not currently open.
	ErrNotOpen = errors.New("no connection is open")
)

// Open opens the TPM socket at the given path.
func Open(path string) (transport.TPMCloser, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if fi.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("%w: %s (%s)", ErrFileIsNotSocket, fi.Mode().String(), path)
	}
	return transport.FromReadWriteCloser(newEmulatorReadWriteCloser(path)), nil
}

// dialer abstracts the net.Dial call so test code can provide its own net.Conn
// implementation.
type dialer func(network, path string) (net.Conn, error)

// emulatorReadWriteCloser manages connections with a TPM emulator over a Unix
// domain socket. These emulators often operate in a write/read/disconnect
// sequence, so the Write method always connects, and the Read method always
// closes. emulatorReadWriteCloser is not thread safe.
type emulatorReadWriteCloser struct {
	path   string
	conn   net.Conn
	dialer dialer
}

// newEmulatorReadWriteCloser stores information about a Unix domain socket to
// write to and read from.
func newEmulatorReadWriteCloser(path string) *emulatorReadWriteCloser {
	return &emulatorReadWriteCloser{
		path:   path,
		dialer: net.Dial,
	}
}

// Read implements the io.Reader interface.
func (erw *emulatorReadWriteCloser) Read(p []byte) (int, error) {
	// Read is always the second operation in a Write/Read sequence.
	if erw.conn == nil {
		return 0, ErrMustCallWriteThenRead
	}
	n, err := erw.conn.Read(p)
	erw.conn.Close()
	erw.conn = nil
	return n, err
}

// Write implements the io.Writer interface.
func (erw *emulatorReadWriteCloser) Write(p []byte) (int, error) {
	if erw.conn != nil {
		return 0, ErrMustCallWriteThenRead
	}
	var err error
	erw.conn, err = erw.dialer("unix", erw.path)
	if err != nil {
		return 0, err
	}
	return erw.conn.Write(p)
}

// Close implements the io.Closer interface.
func (erw *emulatorReadWriteCloser) Close() error {
	if erw.conn == nil {
		// This is an expected possible state, e.g., if someone sent the TPM a command and didn't read the response.
		return nil
	}
	err := erw.conn.Close()
	erw.conn = nil
	return err
}

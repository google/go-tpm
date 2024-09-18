//go:build !windows

// Package linuxtpm provides access to a physical TPM device via the device file.
package linuxtpm

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
)

var (
	// ErrFileIsNotDevice indicates that the TPM file mode was not a device.
	ErrFileIsNotDevice = errors.New("TPM file is not a device")
)

// Open opens the TPM device file at the given path.
func Open(path string) (transport.TPMCloser, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if fi.Mode()&os.ModeDevice == 0 {
		return nil, fmt.Errorf("%w: %s (%s)", ErrFileIsNotDevice, fi.Mode().String(), path)
	}
	var f *os.File
	f, err = os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}

	return transport.FromReadWriteCloser(f), nil
}

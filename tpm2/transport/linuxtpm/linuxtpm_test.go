//go:build !windows

package linuxtpm

import (
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	testhelper "github.com/google/go-tpm/tpm2/transport/test"
)

func open(path string) func() (transport.TPMCloser, error) {
	return func() (transport.TPMCloser, error) {
		return Open(path)
	}
}

func TestLocalTPM(t *testing.T) {
	testhelper.RunTest(t, []error{os.ErrNotExist, os.ErrPermission, ErrFileIsNotDevice}, open("/dev/tpm0"))
}

func TestLocalResourceManagedTPM(t *testing.T) {
	testhelper.RunTest(t, []error{os.ErrNotExist, os.ErrPermission, ErrFileIsNotDevice}, open("/dev/tpmrm0"))
}

//go:build !windows

package linuxudstpm

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

func TestLocalUDSTPM(t *testing.T) {
	testhelper.RunTest(t, []error{os.ErrNotExist, os.ErrPermission, ErrFileIsNotSocket}, open("/dev/tpm0"))
}

func TestLocalResourceManagedUDSTPM(t *testing.T) {
	testhelper.RunTest(t, []error{os.ErrNotExist, os.ErrPermission, ErrFileIsNotSocket}, open("/dev/tpmrm0"))
}

//go:build !windows

package linuxudstpm

import (
	"flag"
	"os"
	"syscall"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	testhelper "github.com/google/go-tpm/tpm2/transport/test"
)

var tpmSocket = flag.String("tpm_socket", "/dev/tpm0", "path to the TPM simulator UDS")

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func open() func() (transport.TPMCloser, error) {
	return func() (transport.TPMCloser, error) {
		return Open(*tpmSocket)
	}
}

func TestLocalUDSTPM(t *testing.T) {
	testhelper.RunTest(t, []error{os.ErrNotExist, os.ErrPermission, ErrFileIsNotSocket, syscall.ECONNREFUSED}, open())
}

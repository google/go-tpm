//go:build windows

package windowstpm

import (
	"os"
	"testing"

	testhelper "github.com/google/go-tpm/tpm2/transport/test"
	"github.com/google/go-tpm/tpmutil/tbs"
)

func TestLocalTPM(t *testing.T) {
	testhelper.RunTest(t, []error{os.ErrNotExist, os.ErrPermission, ErrNotTPM20, tbs.ErrTPMNotFound}, Open)
}

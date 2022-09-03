package helpers

import (
	"encoding/binary"

	"github.com/google/go-tpm/tpm2/structures/tpm"
)

// PrimaryHandleName returns the TPM Name of a primary handle.
func PrimaryHandleName(h tpm.Handle) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(h))
	return result
}

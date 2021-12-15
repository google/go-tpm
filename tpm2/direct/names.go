package direct

import (
	"encoding/binary"
)

func PrimaryHandleName(h TPMHandle) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(h))
	return result
}

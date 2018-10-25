package tpm2

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
)

// KDFa implements TPM 2.0's default key derivation function, as defined in
// section 11.4.9.2 of the TPM revision 2 specification part 1.
func KDFa(hashAlg Algorithm, key []byte, label string, contextU, contextV []byte, bits int) ([]byte, error) {
	var counter uint32
	remaining := (bits + 7) / 8 // As per note at the bottom of page 44.
	var out []byte

	for remaining > 0 {
		counter++
		var mac hash.Hash
		switch hashAlg {
		case AlgSHA1:
			mac = hmac.New(sha1.New, key)
		case AlgSHA256:
			mac = hmac.New(sha256.New, key)
		default:
			return nil, fmt.Errorf("hash algorithm 0x%x is not supported", hashAlg)
		}

		var d bytes.Buffer

		if err := binary.Write(&d, binary.BigEndian, counter); err != nil {
			return nil, fmt.Errorf("pack counter: %v", err)
		}
		d.WriteString(label)
		d.WriteByte(0) // Terminating null chacter for C-string.
		d.Write(contextU)
		d.Write(contextV)
		if err := binary.Write(&d, binary.BigEndian, uint32(bits)); err != nil {
			return nil, fmt.Errorf("pack bits: %v", err)
		}

		mac.Write(d.Bytes())
		out = append(out, mac.Sum(nil)...)
		remaining -= mac.Size()
	}

	return out, nil
}

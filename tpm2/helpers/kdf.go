package helpers

import (
	"crypto"
	"crypto/hmac"
	"encoding/binary"
	"hash"
)

// KDFaHash implements TPM 2.0's default key derivation function, as defined in
// section 11.4.9.2 of the TPM revision 2 specification part 1.
// See: https://trustedcomputinggroup.org/resource/tpm-library-specification/
// The key & label parameters must not be zero length.
// The label parameter is a non-null-terminated string.
// The contextU & contextV parameters are optional.
func KDFaHash(h crypto.Hash, key []byte, label string, contextU, contextV []byte, bits int) []byte {
	mac := hmac.New(h.New, key)

	out := kdf(mac, bits, func() {
		mac.Write([]byte(label))
		mac.Write([]byte{0}) // Terminating null character for C-string.
		mac.Write(contextU)
		mac.Write(contextV)
		binary.Write(mac, binary.BigEndian, uint32(bits))
	})
	return out
}

// KDFeHash implements TPM 2.0's ECDH key derivation function, as defined in
// section 11.4.9.3 of the TPM revision 2 specification part 1.
// See: https://trustedcomputinggroup.org/resource/tpm-library-specification/
// The z parameter is the x coordinate of one party's private ECC key multiplied
// by the other party's public ECC point.
// The use parameter is a non-null-terminated string.
// The partyUInfo and partyVInfo are the x coordinates of the initiator's and
// the responder's ECC points, respectively.
func KDFeHash(h crypto.Hash, z []byte, use string, partyUInfo, partyVInfo []byte, bits int) []byte {
	hash := h.New()

	out := kdf(hash, bits, func() {
		hash.Write(z)
		hash.Write([]byte(use))
		hash.Write([]byte{0}) // Terminating null character for C-string.
		hash.Write(partyUInfo)
		hash.Write(partyVInfo)
	})
	return out
}

func kdf(h hash.Hash, bits int, update func()) []byte {
	bytes := (bits + 7) / 8
	out := []byte{}

	for counter := 1; len(out) < bytes; counter++ {
		h.Reset()
		binary.Write(h, binary.BigEndian, uint32(counter))
		update()

		out = h.Sum(out)
	}
	// out's length is a multiple of hash size, so there will be excess
	// bytes if bytes isn't a multiple of hash size.
	out = out[:bytes]

	// As mentioned in the KDFa and KDFe specs mentioned above,
	// the unused bits of the most significant octet are masked off.
	if maskBits := uint8(bits % 8); maskBits > 0 {
		out[0] &= (1 << maskBits) - 1
	}
	return out
}

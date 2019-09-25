// Copyright (c) 2018, Google LLC All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tpm2

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
)

// KDFa implements TPM 2.0's default key derivation function, as defined in
// section 11.4.9.2 of the TPM revision 2 specification part 1.
// See: https://trustedcomputinggroup.org/resource/tpm-library-specification/
// The key & label parameters must not be zero length, but contextU &
// contextV may be.
func KDFa(hashAlg Algorithm, key []byte, label string, contextU, contextV []byte, bits int) ([]byte, error) {
	h, err := hashAlg.HashConstructor()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(h, key)
	return kdf(mac, func() error {
		mac.Write([]byte(label))
		mac.Write([]byte{0}) // Terminating null character for C-string.
		mac.Write(contextU)
		mac.Write(contextV)
		if err := binary.Write(mac, binary.BigEndian, uint32(bits)); err != nil {
			return fmt.Errorf("pack bits: %v", err)
		}
		return nil
	}, bits)
}

// KDFe implements TPM 2.0's ECDH key derivation function, as defined in
// section 11.4.9.3 of the TPM revision 2 specification part 1.
// See: https://trustedcomputinggroup.org/resource/tpm-library-specification/
// The z parameter is the x coordinate of one parties private ECC key and the other parties public ECC key.
// The partyUInfo and partyVInfo are the x coordinate of the initiators and the responders ECC points respectively.
func KDFe(hashAlg Algorithm, z []byte, use string, partyUInfo, partyVInfo []byte, bits int) ([]byte, error) {
	createHash, err := hashAlg.HashConstructor()
	if err != nil {
		return nil, err
	}
	h := createHash()
	return kdf(h, func() error {
		h.Write(z)
		h.Write([]byte(use))
		h.Write([]byte{0}) // Terminating null character for C-string.
		h.Write(partyUInfo)
		h.Write(partyVInfo)
		return nil
	}, bits)
}

func kdf(h hash.Hash, update func() error, bits int) ([]byte, error) {
	var counter uint32
	bytes := (bits + 7) / 8
	var out []byte

	for remaining := 0; remaining < bytes; remaining += h.Size() {
		counter++
		if err := binary.Write(h, binary.BigEndian, counter); err != nil {
			return nil, fmt.Errorf("pack counter: %v", err)
		}
		err := update()
		if err != nil {
			return nil, err
		}
		out = h.Sum(out)
		h.Reset()
	}
	// out's length is a multiple of hash size. If bytes isn't a multiple of hash size, strip excess.
	if len(out) > bytes {
		out = out[:bytes]
	}
	// If bits isn't a multiple of 8, mask off excess most significant bits from zeroth byte.
	if bits%8 != 0 {
		out[0] &= ((1 << (uint(bits) % 8)) - 1)
	}
	return out, nil
}

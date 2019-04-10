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
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
)

// KDFa implements TPM 2.0's default key derivation function, as defined in
// section 11.4.9.2 of the TPM revision 2 specification part 1.
// See: https://trustedcomputinggroup.org/resource/tpm-library-specification/
// The key & label parameters must not be zero length, but contextU &
// contextV may be.
// Only SHA1 & SHA256 hash algorithms are implemented at this time.
func KDFa(hashAlg Algorithm, key []byte, label string, contextU, contextV []byte, bits int) ([]byte, error) {
	var counter uint32
	remaining := (bits + 7) / 8 // As per note at the bottom of page 44.
	var out []byte

	var mac hash.Hash
	switch hashAlg {
	case AlgSHA1:
		mac = hmac.New(sha1.New, key)
	case AlgSHA256:
		mac = hmac.New(sha256.New, key)
	default:
		return nil, fmt.Errorf("hash algorithm 0x%x is not supported", hashAlg)
	}

	for remaining > 0 {
		counter++
		if err := binary.Write(mac, binary.BigEndian, counter); err != nil {
			return nil, fmt.Errorf("pack counter: %v", err)
		}
		mac.Write([]byte(label))
		mac.Write([]byte{0}) // Terminating null character for C-string.
		mac.Write(contextU)
		mac.Write(contextV)
		if err := binary.Write(mac, binary.BigEndian, uint32(bits)); err != nil {
			return nil, fmt.Errorf("pack bits: %v", err)
		}

		out = mac.Sum(out)
		remaining -= mac.Size()
		mac.Reset()
	}

	if len(out) > bits/8 {
		out = out[:bits/8]
	}

	return out, nil
}

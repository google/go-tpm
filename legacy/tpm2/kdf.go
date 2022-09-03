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
	"github.com/google/go-tpm/tpm2/helpers"
)

// KDFa implements TPM 2.0's default key derivation function, as defined in
// section 11.4.9.2 of the TPM revision 2 specification part 1.
// See: https://trustedcomputinggroup.org/resource/tpm-library-specification/
// The key & label parameters must not be zero length.
// The label parameter is a non-null-terminated string.
// The contextU & contextV parameters are optional.
// Deprecated: Use KDFaHash.
func KDFa(hashAlg Algorithm, key []byte, label string, contextU, contextV []byte, bits int) ([]byte, error) {
	h, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}
	return helpers.KDFaHash(h, key, label, contextU, contextV, bits), nil
}

// KDFe implements TPM 2.0's ECDH key derivation function, as defined in
// section 11.4.9.3 of the TPM revision 2 specification part 1.
// See: https://trustedcomputinggroup.org/resource/tpm-library-specification/
// The z parameter is the x coordinate of one party's private ECC key multiplied
// by the other party's public ECC point.
// The use parameter is a non-null-terminated string.
// The partyUInfo and partyVInfo are the x coordinates of the initiator's and
// Deprecated: Use KDFeHash.
func KDFe(hashAlg Algorithm, z []byte, use string, partyUInfo, partyVInfo []byte, bits int) ([]byte, error) {
	h, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}
	return helpers.KDFeHash(h, z, use, partyUInfo, partyVInfo, bits), nil
}

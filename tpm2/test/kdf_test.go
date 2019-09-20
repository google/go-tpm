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
	"bytes"
	"testing"

	. "github.com/google/go-tpm/tpm2"
)

func TestKDFa(t *testing.T) {
	tcs := []struct {
		hashAlg  Algorithm
		key      []byte
		contextU []byte
		contextV []byte
		label    string
		bits     int
		expected []byte
	}{
		{
			hashAlg:  AlgSHA256,
			key:      []byte{'y', 'o', 'l', 'o', 0},
			contextU: []byte{'k', 'e', 'k', 0},
			contextV: []byte{'y', 'o', 'y', 'o', 0},
			label:    "IDENTITY",
			bits:     128,
			expected: []byte{0xd2, 0xd7, 0x2c, 0xc7, 0xa8, 0xa5, 0xeb, 0x09, 0xe8, 0xc7, 0x90, 0x12, 0xe2, 0xda, 0x9f, 0x22},
		},
		{
			hashAlg:  AlgSHA256,
			key:      []byte{'c', 'a', 0},
			contextU: []byte{'a', 'b', 'c', 0},
			label:    "IDENTITY",
			bits:     1024,
			expected: []byte{0x1a, 0xae, 0x71, 0x51, 0xac, 0x1a, 0x56, 0x90, 0xed, 0xa7, 0xdc, 0xab, 0xd5, 0x68, 0x00, 0xc1, 0x1c, 0x56, 0xa3, 0x81, 0x0b, 0xa0, 0x59, 0x82, 0x6f, 0xe4, 0x77, 0x63, 0x48, 0xd6, 0xae, 0x8e, 0x5d, 0x5d, 0x18, 0xc7, 0xcc, 0xf8, 0x37, 0x3f, 0x7b, 0x94, 0x2a, 0xda, 0x8b, 0x91, 0x2b, 0x12, 0xda, 0x56, 0xfb, 0x37, 0xf6, 0x4b, 0x93, 0x58, 0x72, 0x84, 0x1e, 0xc0, 0x7d, 0x38, 0xe1, 0xfb, 0x8e, 0x7e, 0xc8, 0x6e, 0xfc, 0xbf, 0xb4, 0x44, 0x75, 0x6b, 0xc8, 0x86, 0x3f, 0x85, 0x8d, 0x26, 0x90, 0xa6, 0x21, 0xc9, 0xaf, 0xb9, 0x83, 0xcd, 0x77, 0xe7, 0xa1, 0x04, 0x8a, 0xe1, 0xa7, 0x59, 0x8a, 0xc8, 0x95, 0x32, 0x3d, 0x44, 0xc1, 0x02, 0x27, 0xaf, 0x0a, 0x00, 0x14, 0x4c, 0xab, 0x55, 0x11, 0x10, 0x75, 0xdc, 0x6b, 0x72, 0xad, 0x6e, 0xb1, 0x63, 0xc7, 0x45, 0x8b, 0x87, 0x8e, 0x8c},
		},
		{
			hashAlg:  AlgSHA1,
			key:      []byte{'c', 'a', 0},
			contextU: []byte{'a', 'b', 'c', 0},
			label:    "IDENTITY",
			bits:     256,
			expected: []byte{0x83, 0xf3, 0x54, 0xaf, 0xcf, 0x92, 0x3d, 0xe2, 0x11, 0x2e, 0x08, 0x91, 0x43, 0x4c, 0xd0, 0xbd, 0xc8, 0xac, 0xbf, 0x01, 0xb8, 0x11, 0xc0, 0xe8, 0xcd, 0x06, 0x2d, 0xed, 0x39, 0xe3, 0x1f, 0x7f},
		},
	}

	for _, tc := range tcs {
		o, err := KDFa(tc.hashAlg, tc.key, tc.label, tc.contextU, tc.contextV, tc.bits)
		if err != nil {
			t.Fatalf("KDFa(%v, %v, %q, %v, %v, %v) returned error: %v", tc.hashAlg, tc.key, tc.label, tc.contextU, tc.contextV, tc.bits, err)
		}
		if !bytes.Equal(tc.expected, o) {
			t.Errorf("Test with KDFa(%v, %v, %q, %v, %v, %v) returned incorrect result", tc.hashAlg, tc.key, tc.label, tc.contextU, tc.contextV, tc.bits)
			t.Logf("  Got:  %v", o)
			t.Logf("  Want: %v", tc.expected)
		}
	}
}

func TestKDFe(t *testing.T) {
	hashAlg := AlgSHA256
	bits := 256
	z := []byte{107, 221, 138, 84, 47, 13, 21, 83, 41, 230, 59, 228, 20, 7, 224, 139, 197, 187, 118, 203, 141, 130, 104, 165, 145, 202, 123, 133, 32, 114, 231, 36}
	partyUInfo := []byte{93, 178, 236, 143, 87, 209, 203, 20, 249, 84, 151, 225, 140, 175, 25, 48, 149, 27, 150, 22, 119, 130, 209, 124, 93, 194, 40, 115, 201, 217, 209, 125}
	partyVInfo := []byte{77, 81,152, 250, 15, 188, 140, 252, 81, 165, 143, 217, 205, 159, 253, 222, 151, 118, 71, 163, 242, 197, 152, 61, 14, 44, 51, 168, 211, 96, 204, 195}
	label := "DUPLICATE"

	expected := []byte{85, 65, 97, 129, 162, 205, 140, 231, 5, 213, 154, 156, 58, 72, 246, 31, 186, 187, 12, 125, 222, 73, 103, 176, 119, 131, 245, 225, 145, 238, 139, 87}

	result, err := KDFe(hashAlg, z, label, partyUInfo, partyVInfo, bits)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(result, expected) {
		t.Errorf("got: %v\n expected: %v", result, expected)
	}
}

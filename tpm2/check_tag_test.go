// Copyright 2026 The Go-TPM Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// buildAttestBlob constructs a minimal TPMSAttest blob with an attacker-chosen
// Magic value. The remaining fields are populated with zeros so that the blob
// is otherwise unmarshallable (TPMSAttest is a fixed-shape struct apart from
// its Attested union, for which we select TPM_ST_ATTEST_QUOTE and supply an
// empty PCRSelect + empty PCRDigest).
func buildAttestBlob(t *testing.T, magic uint32) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, magic)
	binary.Write(buf, binary.BigEndian, uint16(0x8018)) // Type = TPM_ST_ATTEST_QUOTE
	binary.Write(buf, binary.BigEndian, uint16(0))      // QualifiedSigner TPM2B_NAME size=0
	binary.Write(buf, binary.BigEndian, uint16(0))      // ExtraData TPM2B_DATA size=0
	buf.Write(make([]byte, 17))                         // ClockInfo (8+4+4+1)
	binary.Write(buf, binary.BigEndian, uint64(0))      // FirmwareVersion
	binary.Write(buf, binary.BigEndian, uint32(0))      // PCRSelect count=0
	binary.Write(buf, binary.BigEndian, uint16(0))      // PCRDigest size=0
	return buf.Bytes()
}

// TestUnmarshalAttest_RejectsWrongMagic asserts that the reflection-based
// unmarshaller in this package honours the `gotpm:"check"` tag on
// TPMSAttest.Magic and refuses to return a populated struct when the Magic
// field does not equal TPM_GENERATED_VALUE.
//
// Prior to wiring the `check` tag into unmarshalStructField, the tag was
// silently ignored. TPMSAttest.Magic is the only field carrying the tag, and
// is exactly the boundary between "TPM-generated attestation" and "arbitrary
// bytes signed by any key the verifier trusts". A verifier following the
// pattern in tpm2/test/certify_test.go would have accepted forged quotes /
// certifies whose Magic was zero (or any other attacker-chosen value), as
// long as the surrounding signature verified — which it can, when the
// signing key is a non-restricted signing key on the same TPM, a leaked
// previously-trusted AK reused for ad-hoc Sign, or any cross-tenant signing
// oracle.
func TestUnmarshalAttest_RejectsWrongMagic(t *testing.T) {
	cases := []struct {
		name  string
		magic uint32
	}{
		{"zero", 0x00000000},
		{"deadbeef", 0xdeadbeef},
		{"low-byte-collision", 0x47ff5443}, // byte-swapped TPM_GENERATED_VALUE
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob := buildAttestBlob(t, tc.magic)
			got, err := Unmarshal[TPMSAttest](blob)
			if err == nil {
				t.Fatalf("Unmarshal accepted Magic=0x%08x; this is the regression. Parsed Magic=0x%08x",
					tc.magic, got.Magic)
			}
			if !strings.Contains(err.Error(), "TPM_GENERATED") {
				t.Errorf("expected error to reference the TPM_GENERATED check; got: %v", err)
			}
		})
	}
}

// TestUnmarshalAttest_AcceptsCorrectMagic asserts that the post-fix
// unmarshaller does not regress the happy path: a blob whose Magic is
// exactly TPM_GENERATED_VALUE (0xff544347) still unmarshalls.
func TestUnmarshalAttest_AcceptsCorrectMagic(t *testing.T) {
	blob := buildAttestBlob(t, uint32(TPMGeneratedValue))
	got, err := Unmarshal[TPMSAttest](blob)
	if err != nil {
		t.Fatalf("Unmarshal rejected a correct Magic value: %v", err)
	}
	if got.Magic != TPMGeneratedValue {
		t.Fatalf("Magic round-trip wrong: got 0x%08x want 0x%08x", got.Magic, TPMGeneratedValue)
	}
}

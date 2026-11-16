package tpm2

import (
	"bytes"
	"reflect"
	"testing"
)

func TestKDFSchemeAccessors(t *testing.T) {
	typeOfUnion := reflect.TypeOf((*TPMUKDFScheme)(nil))
	for _, name := range []string{"RSA", "ECC", "Bits", "Sym"} {
		t.Run("No"+name, func(t *testing.T) {
			if _, ok := typeOfUnion.MethodByName(name); ok {
				t.Errorf("TPMUKDFScheme has non-KDF accessor %s", name)
			}
		})
	}
}

func TestKDFSchemeRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		selector TPMAlgID
		details  TPMUKDFScheme
	}{
		{"MGF1", TPMAlgMGF1, NewTPMUKDFScheme(TPMAlgMGF1, &TPMSKDFSchemeMGF1{HashAlg: TPMAlgSHA256})},
		{"ECDH", TPMAlgECDH, NewTPMUKDFScheme(TPMAlgECDH, &TPMSKDFSchemeECDH{HashAlg: TPMAlgSHA256})},
		{"KDF1SP80056A", TPMAlgKDF1SP80056A, NewTPMUKDFScheme(TPMAlgKDF1SP80056A, &TPMSKDFSchemeKDF1SP80056A{HashAlg: TPMAlgSHA256})},
		{"KDF2", TPMAlgKDF2, NewTPMUKDFScheme(TPMAlgKDF2, &TPMSKDFSchemeKDF2{HashAlg: TPMAlgSHA256})},
		{"KDF1SP800108", TPMAlgKDF1SP800108, NewTPMUKDFScheme(TPMAlgKDF1SP800108, &TPMSKDFSchemeKDF1SP800108{HashAlg: TPMAlgSHA256})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := TPMTKDFScheme{Scheme: tc.selector, Details: tc.details}
			wire := Marshal(in)
			want := []byte{byte(tc.selector >> 8), byte(tc.selector), 0, byte(TPMAlgSHA256)}
			if !bytes.Equal(wire, want) {
				t.Fatalf("Marshal() = %x, want %x", wire, want)
			}
			out, err := Unmarshal[TPMTKDFScheme](wire)
			if err != nil {
				t.Fatalf("Unmarshal() = %v", err)
			}
			if !reflect.DeepEqual(*out, in) {
				t.Errorf("round trip = %#v, want %#v", *out, in)
			}
			for _, name := range []string{"MGF1", "ECDH", "KDF1SP80056A", "KDF2", "KDF1SP800108"} {
				result := reflect.ValueOf(&out.Details).MethodByName(name).Call(nil)
				if name != tc.name {
					if !result[0].IsNil() || result[1].IsNil() {
						t.Errorf("%s() for %s should return nil and an error", name, tc.name)
					}
					continue
				}
				if !result[1].IsNil() {
					t.Fatalf("%s() = %v", name, result[1].Interface())
				}
				if !reflect.DeepEqual(result[0].Interface(), tc.details.contents) {
					t.Errorf("%s() = %v, want %v", name, result[0].Interface(), tc.details.contents)
				}
			}
		})
	}
}

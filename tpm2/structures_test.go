package tpm2

import "testing"

func TestUnionAccessors(t *testing.T) {
	t.Run("ACTData", func(t *testing.T) {
		u := NewTPMUCapabilities(TPMCapACT, &TPMLACTData{})
		if _, err := u.ACTData(); err != nil {
			t.Errorf("ACTData() = %v", err)
		}
	})
	t.Run("KDF1SP80056A", func(t *testing.T) {
		u := NewTPMUKDFScheme(TPMAlgKDF1SP80056A, &TPMSKDFSchemeKDF1SP80056A{HashAlg: TPMAlgSHA256})
		if _, err := u.KDF1SP80056A(); err != nil {
			t.Errorf("KDF1SP80056A() = %v", err)
		}
	})
	t.Run("KDF2", func(t *testing.T) {
		u := NewTPMUKDFScheme(TPMAlgKDF2, &TPMSKDFSchemeKDF2{HashAlg: TPMAlgSHA256})
		if _, err := u.KDF2(); err != nil {
			t.Errorf("KDF2() = %v", err)
		}
	})
	t.Run("KDF1SP800108", func(t *testing.T) {
		u := NewTPMUKDFScheme(TPMAlgKDF1SP800108, &TPMSKDFSchemeKDF1SP800108{HashAlg: TPMAlgSHA256})
		if _, err := u.KDF1SP800108(); err != nil {
			t.Errorf("KDF1SP800108() = %v", err)
		}
	})
	t.Run("ECDH", func(t *testing.T) {
		u := NewTPMUAsymScheme(TPMAlgECDH, &TPMSKeySchemeECDH{HashAlg: TPMAlgSHA256})
		if _, err := u.ECDH(); err != nil {
			t.Errorf("ECDH() = %v", err)
		}
	})
	t.Run("WrongMember", func(t *testing.T) {
		u := NewTPMUKDFScheme(TPMAlgMGF1, &TPMSKDFSchemeMGF1{HashAlg: TPMAlgSHA256})
		if _, err := u.KDF2(); err == nil {
			t.Error("KDF2() on an MGF1 union did not return an error")
		}
	})
}

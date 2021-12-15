package direct

// This file provides wrapper functions for concrete types used by tpm2, for
// setting union member pointers.

// NewTPMKeyBits allocates and returns the address of a new TPMKeyBits.
func NewTPMKeyBits(v TPMKeyBits) *TPMKeyBits { return &v }

// NewTPMAlgID allocates and returns the address of a new TPMAlgID.
func NewTPMAlgID(v TPMAlgID) *TPMAlgID { return &v }

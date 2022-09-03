package tpm2

// This file provides wrapper functions for concrete types used by tpm2, for
// setting union member pointers.

// NewKeyBits allocates and returns the address of a new TPMKeyBits.
func NewKeyBits(v TPMKeyBits) *TPMKeyBits { return &v }

// NewAlgID allocates and returns the address of a new TPMAlgID.
func NewAlgID(v TPMAlgID) *TPMAlgID { return &v }

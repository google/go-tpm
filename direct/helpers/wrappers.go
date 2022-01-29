package helpers

import "github.com/google/go-tpm/direct/structures/tpm"

// This file provides wrapper functions for concrete types used by tpm2, for
// setting union member pointers.

// NewKeyBits allocates and returns the address of a new tpm.KeyBits.
func NewKeyBits(v tpm.KeyBits) *tpm.KeyBits { return &v }

// NewAlgID allocates and returns the address of a new tpm.AlgID.
func NewAlgID(v tpm.AlgID) *tpm.AlgID { return &v }

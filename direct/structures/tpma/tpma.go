// package tpma contains the TPM 2.0 structures prefixed by "TPMA_"
package tpma

import (
	"github.com/google/go-tpm/direct/structures/internal"
)

type Bitfield = internal.Bitfield
type BitSetter = internal.BitSetter
type BitGetter = internal.BitGetter

// Algorithm represents a TPMA_ALGORITHM.
// See definition in Part 2: Structures, section 8.2.
type Algorithm = internal.TPMAAlgorithm

// Object represents a TPMA_OBJECT.
// See definition in Part 2: Structures, section 8.3.2.
type Object = internal.TPMAObject

// Session represents a TPMA_SESSION.
// See definition in Part 2: Structures, section 8.4.
type Session = internal.TPMASession

// Locality represents a TPMA_LOCALITY.
// See definition in Part 2: Structures, section 8.5.
type Locality = internal.TPMALocality

// CC represents a TPMA_CC.
// See definition in Part 2: Structures, section 8.9.
type CC = internal.TPMACC

// ACT represents a TPMA_ACT.
// See definition in Part 2: Structures, section 8.12.
type ACT = internal.TPMAACT

// NV represents a TPMA_NV.
// See definition in Part 2: Structures, section 13.4.
type NV = internal.TPMANV

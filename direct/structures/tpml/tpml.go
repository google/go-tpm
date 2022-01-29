// package tpml contains TPM 2.0 structures prefixed with "TPML_"
package tpml

import (
	"github.com/google/go-tpm/direct/structures/internal"
)

// CC represents a TPML_CC.
// See definition in Part 2: Structures, section 10.9.1.
type CC = internal.TPMLCC

// CCA represents a TPML_CCA.
// See definition in Part 2: Structures, section 10.9.2.
type CCA = internal.TPMLCCA

// Alg represents a TPMLALG.
// See definition in Part 2: Structures, section 10.9.3.
type Alg = internal.TPMLAlg

// Handle represents a TPML_HANDLE.
// See definition in Part 2: Structures, section 10.9.4.
type Handle = internal.TPMLHandle

// Digest represents a TPML_DIGEST.
// See definition in Part 2: Structures, section 10.9.5.
type Digest = internal.TPMLDigest

// DigestValues represents a TPML_DIGEST_VALUES.
// See definition in Part 2: Structures, section 10.9.6.
type DigestValues = internal.TPMLDigestValues

// PCRSelection represents a TPML_PCRzSELECTION.
// See definition in Part 2: Structures, section 10.9.7.
type PCRSelection = internal.TPMLPCRSelection

// AlgProperty represents a TPML_ALGzPROPERTY.
// See definition in Part 2: Structures, section 10.9.8.
type AlgProperty = internal.TPMLAlgProperty

// TaggedTPMProperty represents a TPML_TAGGED_TPM_PROPERTY.
// See definition in Part 2: Structures, section 10.9.9.
type TaggedTPMProperty = internal.TPMLTaggedTPMProperty

// TaggedPCRProperty represents a TPML_TAGGED_PCR_PROPERTY.
// See definition in Part 2: Structures, section 10.9.10.
type TaggedPCRProperty = internal.TPMLTaggedPCRProperty

// ECCCurve represents a TPML_ECC_CURVE.
// See definition in Part 2: Structures, section 10.9.11.
type ECCCurve = internal.TPMLECCCurve

// TaggedPolicy represents a TPML_TAGGED_POLICY.
// See definition in Part 2: Structures, section 10.9.12.
type TaggedPolicy = internal.TPMLTaggedPolicy

// ACTData represents a TPML_ACT_DATA.
// See definition in Part 2: Structures, section 10.9.13.
type ACTData = internal.TPMLACTData

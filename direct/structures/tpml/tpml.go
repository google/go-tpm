// package tpml contains TPM 2.0 structures prefixed with "TPML_"
package tpml

import "fmt"
	// the bit map of PCR with the identified property
	PCRSelect []byte `gotpm:"sized8"`
}

// CC represents a TPML_CC.
// See definition in Part 2: Structures, section 10.9.1.
type CC struct {
	CommandCodes []tpm.CC `gotpm:"list"`
}

// CCA represents a TPML_CCA.
// See definition in Part 2: Structures, section 10.9.2.
type CCA struct {
	CommandAttributes []tpma.CC `gotpm:"list"`
}

// Alg represents a TPMLALG.
// See definition in Part 2: Structures, section 10.9.3.
type Alg struct {
	Algorithms []tpm.AlgID `gotpm:"list"`
}

// Handle represents a TPML_HANDLE.
// See definition in Part 2: Structures, section 10.9.4.
type Handle struct {
	Handle []tpm.Handle `gotpm:"list"`
}

// Digest represents a TPML_DIGEST.
// See definition in Part 2: Structures, section 10.9.5.
type Digest struct {
	// a list of digests
	Digests []tpm2b.Digest `gotpm:"list"`
}

// DigestValues represents a TPML_DIGEST_VALUES.
// See definition in Part 2: Structures, section 10.9.6.
type DigestValues struct {
	// a list of tagged digests
	Digests []tpmt.HA `gotpm:"list"`
}

// PCRSelection represents a TPML_PCRzSELECTION.
// See definition in Part 2: Structures, section 10.9.7.
type PCRSelection struct {
	PCRSelections []tpms.PCRSelection `gotpm:"list"`
}

// AlgProperty represents a TPML_ALGzPROPERTY.
// See definition in Part 2: Structures, section 10.9.8.
type AlgProperty struct {
	AlgProperties []tpms.AlgProperty `gotpm:"list"`
}

// TaggedTPMProperty represents a TPML_TAGGED_TPM_PROPERTY.
// See definition in Part 2: Structures, section 10.9.9.
type TaggedTPMProperty struct {
	TPMProperty []tpms.TaggedProperty `gotpm:"list"`
}

// TaggedPCRProperty represents a TPML_TAGGED_PCR_PROPERTY.
// See definition in Part 2: Structures, section 10.9.10.
type TaggedPCRProperty struct {
	PCRProperty []tpms.TaggedPCRSelect `gotpm:"list"`
}

// ECCCurve represents a TPML_ECC_CURVE.
// See definition in Part 2: Structures, section 10.9.11.
type ECCCurve struct {
	ECCCurves []tpm.ECCCurve `gotpm:"list"`
}

// TaggedPolicy represents a TPML_TAGGED_POLICY.
// See definition in Part 2: Structures, section 10.9.12.
type TaggedPolicy struct {
	Policies []tpms.TaggedPolicy `gotpm:"list"`
}

// ACTData represents a TPML_ACT_DATA.
// See definition in Part 2: Structures, section 10.9.13.
type ACTData struct {
	ACTData []tpms.ACTData `gotpm:"list"`
}


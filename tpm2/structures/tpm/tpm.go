// Package tpm contains the TPM 2.0 structures prefixed with "TPM_"
package tpm

import (
	"github.com/google/go-tpm/tpm2/structures/internal"
)

// CmdHeader is the header structure in front of any TPM command.
// It is described in Part 1, Architecture.
type CmdHeader = internal.TPMCmdHeader

// RspHeader is the header structure in front of any TPM response.
// It is described in Part 1, Architecture.
type RspHeader = internal.TPMRspHeader

// AlgorithmID represents a TPM_ALGORITHM_ID
// this is the 1.2 compatible form of the TPM_ALG_ID
// See definition in Part 2, Structures, section 5.3.
type AlgorithmID = internal.TPMAlgorithmID

// ModifierIndicator represents a TPM_MODIFIER_INDICATOR.
// See definition in Part 2, Structures, section 5.3.
type ModifierIndicator = internal.TPMModifierIndicator

// AuthorizationSize represents a TPM_AUTHORIZATION_SIZE.
// the authorizationSize parameter in a command
// See definition in Part 2, Structures, section 5.3.
type AuthorizationSize = internal.TPMAuthorizationSize

// ParameterSize represents a TPM_PARAMETER_SIZE.
// the parameterSize parameter in a command
// See definition in Part 2, Structures, section 5.3.
type ParameterSize = internal.TPMParameterSize

// KeySize represents a TPM_KEY_SIZE.
// a key size in octets
// See definition in Part 2, Structures, section 5.3.
type KeySize = internal.TPMKeySize

// KeyBits represents a TPM_KEY_BITS.
// a key size in bits
// See definition in Part 2, Structures, section 5.3.
type KeyBits = internal.TPMKeyBits

// Generated represents a TPM_GENERATED.
// See definition in Part 2: Structures, section 6.2.
type Generated = internal.TPMGenerated

// AlgID represents a TPM_ALG_ID.
// See definition in Part 2: Structures, section 6.3.
type AlgID = internal.TPMAlgID

// ECCCurve represents a TPM_ECC_Curve.
// See definition in Part 2: Structures, section 6.4.
type ECCCurve = internal.TPMECCCurve

// CC represents a TPM_CC.
// See definition in Part 2: Structures, section 6.5.2.
type CC = internal.TPMCC

// RC represents a TPM_RC.
// See definition in Part 2: Structures, section 6.6.
type RC = internal.TPMRC

// Fmt1Error represents a TPM 2.0 format-1 error, with additional information.
type Fmt1Error = internal.TPMFmt1Error

// EO represents a TPM_EO.
// See definition in Part 2: Structures, section 6.8.
type EO = internal.TPMEO

// ST represents a TPM_ST.
// See definition in Part 2: Structures, section 6.9.
type ST = internal.TPMST

// SU represents a TPM_SU.
// See definition in Part 2: Structures, section 6.10.
type SU = internal.TPMSU

// SE represents a TPM_SE.
// See definition in Part 2: Structures, section 6.11.
type SE = internal.TPMSE

// Cap represents a TPM_CAP.
// See definition in Part 2: Structures, section 6.12.
type Cap = internal.TPMCap

// PT represents a TPM_PT.
// See definition in Part 2: Structures, section 6.13.
type PT = internal.TPMPT

// PTPCR represents a TPM_PT_PCR.
// See definition in Part 2: Structures, section 6.14.
type PTPCR = internal.TPMPTPCR

// Handle represents a TPM_HANDLE.
// See definition in Part 2: Structures, section 7.1.
type Handle = internal.TPMHandle

// NT represents a TPM_NT.
// See definition in Part 2: Structures, section 13.4.
type NT = internal.TPMNT

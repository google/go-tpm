// package tpm contains the TPM 2.0 structures prefixed with "TPM_"
package tpm

import (
	"fmt"

	"github.com/google/go-tpm/direct/structures/tpmi"
)

// CmdHeader is the header structure in front of any TPM command.
// It is described in Part 1, Architecture.
type CmdHeader struct {
	Tag         tpmi.STCommandTag
	Length      uint32
	CommandCode CC
}

// RspHeader is the header structure in front of any TPM response.
// It is described in Part 1, Architecture.
type RspHeader struct {
	Tag          tpmi.STCommandTag
	Length       uint32
	ResponseCode RC
}

// AlgorithmID represents a TPM_ALGORITHM_ID
// this is the 1.2 compatible form of the TPM_ALG_ID
// See definition in Part 2, Structures, section 5.3.
type AlgorithmID uint32

// ModifierIndicator represents a TPM_MODIFIER_INDICATOR.
// See definition in Part 2, Structures, section 5.3.
type ModifierIndicator uint32

// AuthorizationSize represents a TPM_AUTHORIZATION_SIZE.
// the authorizationSize parameter in a command
// See definition in Part 2, Structures, section 5.3.
type AuthorizationSize uint32

// ParameterSize represents a TPM_PARAMETER_SIZE.
// the parameterSize parameter in a command
// See definition in Part 2, Structures, section 5.3.
type ParameterSize uint32

// KeySize represents a TPM_KEY_SIZE.
// a key size in octets
// See definition in Part 2, Structures, section 5.3.
type KeySize uint16

// KeyBits represents a TPM_KEY_BITS.
// a key size in bits
// See definition in Part 2, Structures, section 5.3.
type KeyBits uint16

// Generated represents a TPM_GENERATED.
// See definition in Part 2: Structures, section 6.2.
type Generated uint32

// Check verifies that a TPMGenerated value is correct, and returns an error
// otherwise.
func (g Generated) Check() error {
	if g != GeneratedValue {
		return fmt.Errorf("TPM_GENERATED value should be 0x%x, was 0x%x", GeneratedValue, g)
	}
	return nil
}

// AlgID represents a TPM_ALG_ID.
// See definition in Part 2: Structures, section 6.3.
type AlgID uint16

// ECCCurve represents a TPM_ECC_Curve.
// See definition in Part 2: Structures, section 6.4.
type ECCCurve uint16

// CC represents a TPM_CC.
// See definition in Part 2: Structures, section 6.5.2.
type CC uint32

// RC represents a TPM_RC.
// See definition in Part 2: Structures, section 6.6.
type RC uint32

// ST represents a TPM_ST.
// See definition in Part 2: Structures, section 6.9.
type ST uint16

// SE represents a TPM_SE.
// See definition in Part 2: Structures, section 6.11.
type SE uint8

// Cap represents a TPM_CAP.
// See definition in Part 2: Structures, section 6.12.
type Cap uint32

// PT represents a TPM_PT.
// See definition in Part 2: Structures, section 6.13.
type PT uint32

// PTPCR represents a TPM_PT_PCR.
// See definition in Part 2: Structures, section 6.14.
type PTPCR uint32

// Handle represents a TPM_HANDLE.
// See definition in Part 2: Structures, section 7.1.
type Handle uint32

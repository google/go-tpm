package tpm2

import (
	"fmt"

	"github.com/google/go-tpm/tpmutil"
)

type (
	RcFmt0  uint8 // Format 0 error codes
	RcFmt1  uint8 // Format 1 error codes
	RcWarn  uint8 // Warning codes
	RcIndex uint8 // Indexes for arguments, handles and sessions in errors
)

// Format 0 error codes.
const (
	RcInitialize      RcFmt0 = 0x00
	RcFailure                = 0x01
	RcSequence               = 0x03
	RcPrivate                = 0x0B
	RcHMAC                   = 0x19
	RcDisabled               = 0x20
	RcExclusive              = 0x21
	RcAuthType               = 0x24
	RcAuthMissing            = 0x25
	RcPolicy                 = 0x26
	RcPCR                    = 0x27
	RcPCRChanged             = 0x28
	RcUpgrade                = 0x2D
	RcTooManyContexts        = 0x2E
	RcAuthUnavailable        = 0x2F
	RcReboot                 = 0x30
	RcUnbalanced             = 0x31
	RcCommandSize            = 0x42
	RcCommandCode            = 0x43
	RcAuthSize               = 0x44
	RcAuthContext            = 0x45
	RcNVRange                = 0x46
	RcNVSize                 = 0x47
	RcNVLocked               = 0x48
	RcNVAuthorization        = 0x49
	RcNVUninitialized        = 0x4A
	RcNVSpace                = 0x4B
	RcNVDefined              = 0x4C
	RcBadContext             = 0x50
	RcCPHash                 = 0x51
	RcParent                 = 0x52
	RcNeedsTest              = 0x53
	RcNoResult               = 0x54
	RcSensitive              = 0x55
)

var fmt0Msg = map[RcFmt0]string{
	RcInitialize:      "TPM not initialized by TPM2_Startup or already initialized",
	RcFailure:         "commands not being accepted because of a TPM failure",
	RcSequence:        "improper use of a sequence handle",
	RcPrivate:         "not currently used",
	RcHMAC:            "not currently used",
	RcDisabled:        "the command is disabled",
	RcExclusive:       "command failed because audit sequence required exclusivity",
	RcAuthType:        "authorization handle is not correct for command",
	RcAuthMissing:     "5 command requires an authorization session for handle and it is not present.",
	RcPolicy:          "policy failure in math operation or an invalid authPolicy value",
	RcPCR:             "PCR check fail",
	RcPCRChanged:      "PCR have changed since checked",
	RcUpgrade:         "TPM is in field upgrade mode unless called via TPM2_FieldUpgradeData(), then it is not in field upgrade mode",
	RcTooManyContexts: "context ID counter is at maximum",
	RcAuthUnavailable: "authValue or authPolicy is not available for selected entity",
	RcReboot:          "a _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation",
	RcUnbalanced:      "the protection algorithms (hash and symmetric) are not reasonably balanced. The digest size of the hash must be larger than the key size of the symmetric algorithm.",
	RcCommandSize:     "command commandSize value is inconsistent with contents of the command buffer; either the size is not the same as the octets loaded by the hardware interface layer or the value is not large enough to hold a command header",
	RcCommandCode:     "command code not supported",
	RcAuthSize:        "the value of authorizationSize is out of range or the number of octets in the Authorization Area is greater than required",
	RcAuthContext:     "use of an authorization session with a context command or another command that cannot have an authorization session",
	RcNVRange:         "NV offset+size is out of range",
	RcNVSize:          "Requested allocation size is larger than allowed",
	RcNVLocked:        "NV access locked",
	RcNVAuthorization: "NV access authorization fails in command actions",
	RcNVUninitialized: "an NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored",
	RcNVSpace:         "insufficient space for NV allocation",
	RcNVDefined:       "NV Index or persistent object already defined",
	RcBadContext:      "context in TPM2_ContextLoad() is not valid",
	RcCPHash:          "cpHash value already set or not correct for use",
	RcParent:          "handle for parent is not a valid parent",
	RcNeedsTest:       "some function needs testing",
	RcNoResult:        "returned when an internal function cannot process a request due to an unspecified problem. This code is usually related to invalid parameters that are not properly filtered by the input unmarshaling code",
	RcSensitive:       "the sensitive area did not unmarshal correctly after decryption",
}

// Format 1 error codes.
const (
	RcAsymmetric   = 0x01
	RcAttributes   = 0x02
	RcHash         = 0x03
	RcValue        = 0x04
	RcHierarchy    = 0x05
	RcKeySize      = 0x07
	RcMGF          = 0x08
	RcMode         = 0x09
	RcType         = 0x0A
	RcHandle       = 0x0B
	RcKDF          = 0x0C
	RcRange        = 0x0D
	RcAuthFail     = 0x0E
	RcNonce        = 0x0F
	RcPP           = 0x10
	RcScheme       = 0x12
	RcSize         = 0x15
	RcSymmetric    = 0x16
	RcTag          = 0x17
	RcSelector     = 0x18
	RcInsufficient = 0x1A
	RcSignature    = 0x1B
	RcKey          = 0x1C
	RcPolicyFail   = 0x1D
	RcIntegrity    = 0x1F
	RcTicket       = 0x20
	RcReservedBits = 0x21
	RcBadAuth      = 0x22
	RcExpired      = 0x23
	RcPolicyCC     = 0x24
	RcBinding      = 0x25
	RcCurve        = 0x26
	RcECCPoint     = 0x27
)

var fmt1Msg = map[RcFmt1]string{
	RcAsymmetric:   "asymmetric algorithm not supported or not correct",
	RcAttributes:   "inconsistent attributes",
	RcHash:         "hash algorithm not supported or not appropriate",
	RcValue:        "value is out of range or is not correct for the context",
	RcHierarchy:    "hierarchy is not enabled or is not correct for the use",
	RcKeySize:      "key size is not supported",
	RcMGF:          "mask generation function not supported",
	RcMode:         "mode of operation not supported",
	RcType:         "the type of the value is not appropriate for the use",
	RcHandle:       "the handle is not correct for the use",
	RcKDF:          "unsupported key derivation function or function not appropriate for use",
	RcRange:        "value was out of allowed range",
	RcAuthFail:     "the authorization HMAC check failed and DA counter incremented",
	RcNonce:        "invalid nonce size or nonce value mismatch",
	RcPP:           "authorization requires assertion of PP",
	RcScheme:       "unsupported or incompatible scheme",
	RcSize:         "structure is the wrong size",
	RcSymmetric:    "unsupported symmetric algorithm or key size, or not appropriate for instance",
	RcTag:          "incorrect structure tag",
	RcSelector:     "union selector is incorrect",
	RcInsufficient: "the TPM was unable to unmarshal a value because there were not enough octets in the input buffer",
	RcSignature:    "the signature is not valid",
	RcKey:          "key fields are not compatible with the selected use",
	RcPolicyFail:   "a policy check failed",
	RcIntegrity:    "integrity check failed",
	RcTicket:       "invalid ticket",
	RcReservedBits: "reserved bits not set to zero as required",
	RcBadAuth:      "authorization failure without DA implications",
	RcExpired:      "the policy has expired",
	RcPolicyCC:     "the commandCode in the policy is not the commandCode of the command or the command code in a policy command references a command that is not implemented",
	RcBinding:      "public and sensitive portions of an object are not cryptographically bound",
	RcCurve:        "curve not supported",
	RcECCPoint:     "point is not on the required curve",
}

// Warning codes.
const (
	RcContextGap     RcWarn = 0x01
	RcObjectMemory          = 0x02
	RcSessionMemory         = 0x03
	RcMemory                = 0x04
	RcSessionHandles        = 0x05
	RcObjectHandles         = 0x06
	RcLocality              = 0x07
	RcYielded               = 0x08
	RcCanceled              = 0x09
	RcTesting               = 0x0A
	RcReferenceH0           = 0x10
	RcReferenceH1           = 0x11
	RcReferenceH2           = 0x12
	RcReferenceH3           = 0x13
	RcReferenceH4           = 0x14
	RcReferenceH5           = 0x15
	RcReferenceH6           = 0x16
	RcReferenceS0           = 0x18
	RcReferenceS1           = 0x19
	RcReferenceS2           = 0x1A
	RcReferenceS3           = 0x1B
	RcReferenceS4           = 0x1C
	RcReferenceS5           = 0x1D
	RcReferenceS6           = 0x1E
	RcNVRate                = 0x20
	RcLockout               = 0x21
	RcRetry                 = 0x22
	RcNVUnavailable         = 0x23
)

var warnMgs = map[RcWarn]string{
	RcContextGap:     "gap for context ID is too large",
	RcObjectMemory:   "out of memory for object contexts",
	RcSessionMemory:  "out of memory for session contexts",
	RcMemory:         "out of shared object/session memory or need space for internal operations",
	RcSessionHandles: "out of session handles",
	RcObjectHandles:  "out of object handles",
	RcLocality:       "bad locality",
	RcYielded:        "the TPM has suspended operation on the command; forward progress was made and the command may be retried",
	RcCanceled:       "the command was canceled",
	RcTesting:        "TPM is performing self-tests",
	RcReferenceH0:    "the 1st handle in the handle area references a transient object or session that is not loaded",
	RcReferenceH1:    "the 2nd handle in the handle area references a transient object or session that is not loaded",
	RcReferenceH2:    "the 3rd handle in the handle area references a transient object or session that is not loaded",
	RcReferenceH3:    "the 4th handle in the handle area references a transient object or session that is not loaded",
	RcReferenceH4:    "the 5th handle in the handle area references a transient object or session that is not loaded",
	RcReferenceH5:    "the 6th handle in the handle area references a transient object or session that is not loaded",
	RcReferenceH6:    "the 7th handle in the handle area references a transient object or session that is not loaded",
	RcReferenceS0:    "the 1st authorization session handle references a session that is not loaded",
	RcReferenceS1:    "the 2nd authorization session handle references a session that is not loaded",
	RcReferenceS2:    "the 3rd authorization session handle references a session that is not loaded",
	RcReferenceS3:    "the 4th authorization session handle references a session that is not loaded",
	RcReferenceS4:    "the 5th authorization session handle references a session that is not loaded",
	RcReferenceS5:    "the 6th authorization session handle references a session that is not loaded",
	RcReferenceS6:    "the 7th authorization session handle references a session that is not loaded",
	RcNVRate:         "the TPM is rate-limiting accesses to prevent wearout of NV",
	RcLockout:        "authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode",
	RcRetry:          "the TPM was not able to start the command",
	RcNVUnavailable:  "the command may require writing of NV and NV is not current accessible",
}

// Indexes for arguments, handles and sessions.
const (
	Rc1 RcIndex = 0x01
	Rc2         = 0x02
	Rc3         = 0x03
	Rc4         = 0x04
	Rc5         = 0x05
	Rc6         = 0x06
	Rc7         = 0x07
	Rc8         = 0x08
	Rc9         = 0x09
	RcA         = 0x0A
	RcB         = 0x0B
	RcC         = 0x0C
	RcD         = 0x0D
	RcE         = 0x0E
	RcF         = 0x0F
)

type Error struct {
	Code RcFmt0
}

func (e Error) Error() string {
	return fmt.Sprintf("error code 0x%x : %s", e.Code, fmt0Msg[e.Code])
}

type VendorError struct {
	Code uint32
}

func (e VendorError) Error() string {
	return fmt.Sprintf("vendor error code 0x%x", e.Code)
}

type Warning struct {
	Code RcWarn
}

func (w Warning) Error() string {
	return fmt.Sprintf("warning code 0x%x : %s", w.Code, warnMgs[w.Code])
}

type ParameterError struct {
	Code      RcFmt1
	Parameter RcIndex
}

func (e ParameterError) Error() string {
	return fmt.Sprintf("parameter %d, error code 0x%x : %s", e.Parameter, e.Code, fmt1Msg[e.Code])
}

type HandleError struct {
	Code   RcFmt1
	Handle RcIndex
}

func (e HandleError) Error() string {
	return fmt.Sprintf("handle %d, error code 0x%x : %s", e.Handle, e.Code, fmt1Msg[e.Code])
}

type SessionError struct {
	Code    RcFmt1
	Session RcIndex
}

func (e SessionError) Error() string {
	return fmt.Sprintf("session %d, error code 0x%x : %s", e.Session, e.Code, fmt1Msg[e.Code])
}

// Decode a TPM2 response code and return the appropriate error. Logic
// according to the "Response Code Evaluation" chart in Part 1 of the TPM 2.0
// spec.
func decodeResponse(code tpmutil.ResponseCode) error {
	if code == tpmutil.RCSuccess {
		return nil
	}
	if code&0x180 == 0 { // Bits 7:8 == 0 is a TPM1 error
		return fmt.Errorf("response status 0x%x", code)
	}
	if code&0x80 == 0 { // Bit 7 unset
		if code&0x400 > 0 { // Bit 10 set, vendor specific code
			return VendorError{uint32(code)}
		}
		if code&0x800 > 0 { // Bit 11 set, warning with code in bit 0:6
			return Warning{RcWarn(code & 0x7f)}
		}
		// error with code in bit 0:6
		return Error{RcFmt0(code & 0x7f)}
	}
	if code&0x40 > 0 { // Bit 6 set, parameter number in 8:11, code in 0:5
		return ParameterError{RcFmt1(code & 0x3f), RcIndex((code & 0xf00) >> 8)}
	}
	if code&0x800 == 0 { // Bit 11 unset, handle in 8:10, code in 0:5
		return HandleError{RcFmt1(code & 0x3f), RcIndex((code & 0x700) >> 8)}
	}
	// Session in 8:10, code in 0:5
	return SessionError{RcFmt1(code & 0x3f), RcIndex((code & 0x700) >> 8)}
}

package direct

import (
	"fmt"
)

type errorDesc struct {
	name        string
	description string
}

var fmt0Descs = map[TPMRC]errorDesc{
	TPMRCFailure: errorDesc{
		name:        "TPM_RC_FAILURE",
		description: "commands not being accepted because of a TPM failure",
	},
	TPMRCSequence: errorDesc{
		name:        "TPM_RC_SEQUENCE",
		description: "improper use of a sequence handle",
	},
	TPMRCPrivate: errorDesc{
		name:        "TPM_RC_PRIVATE",
		description: "not currently used",
	},
	TPMRCHMAC: errorDesc{
		name:        "TPM_RC_HMAC",
		description: "not currently used",
	},
	TPMRCDisabled: errorDesc{
		name:        "TPM_RC_DISABLED",
		description: "the command is disabled",
	},
	TPMRCExclusive: errorDesc{
		name:        "TPM_RC_EXCLUSIVE",
		description: "command failed because audit sequence required exclusivity",
	},
	TPMRCAuthType: errorDesc{
		name:        "TPM_RC_AUTH_TYPE",
		description: "authorization handle is not correct for command",
	},
	TPMRCAuthMissing: errorDesc{
		name:        "TPM_RC_AUTH_MISSING",
		description: "command requires an authorization session for handle and it is not present.",
	},
	TPMRCPolicy: errorDesc{
		name:        "TPM_RC_POLICY",
		description: "policy failure in math operation or an invalid authPolicy value",
	},
	TPMRCPCR: errorDesc{
		name:        "TPM_RC_PCR",
		description: "PCR check fail",
	},
	TPMRCPCRChanged: errorDesc{
		name:        "TPM_RC_PCR_CHANGED",
		description: "PCR have changed since checked.",
	},
	TPMRCUpgrade: errorDesc{
		name:        "TPM_RC_UPGRADE",
		description: "for all commands other than TPM2_FieldUpgradeData(), this code indicates that the TPM is in field upgrade mode; for TPM2_FieldUpgradeData(), this code indicates that the TPM is not in field upgrade mode",
	},
	TPMRCTooManyContexts: errorDesc{
		name:        "TPM_RC_TOO_MANY_CONTEXTS",
		description: "context ID counter is at maximum.",
	},
	TPMRCAuthUnavailable: errorDesc{
		name:        "TPM_RC_AUTH_UNAVAILABLE",
		description: "authValue or authPolicy is not available for selected entity.",
	},
	TPMRCReboot: errorDesc{
		name:        "TPM_RC_REBOOT",
		description: "a _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation.",
	},
	TPMRCUnbalanced: errorDesc{
		name:        "TPM_RC_UNBALANCED",
		description: "the protection algorithms (hash and symmetric) are not reasonably balanced. The digest size of the hash must be larger than the key size of the symmetric algorithm.",
	},
	TPMRCCommandSize: errorDesc{
		name:        "TPM_RC_COMMAND_SIZE",
		description: "command commandSize value is inconsistent with contents of the command buffer; either the size is not the same as the octets loaded by the hardware interface layer or the value is not large enough to hold a command header",
	},
	TPMRCCommandCode: errorDesc{
		name:        "TPM_RC_COMMAND_CODE",
		description: "command code not supported",
	},
	TPMRCAuthSize: errorDesc{
		name:        "TPM_RC_AUTHSIZE",
		description: "the value of authorizationSize is out of range or the number of octets in the Authorization Area is greater than required",
	},
	TPMRCAuthContext: errorDesc{
		name:        "TPM_RC_AUTH_CONTEXT",
		description: "use of an authorization session with a context command or another command that cannot have an authorization session.",
	},
	TPMRCNVRange: errorDesc{
		name:        "TPM_RC_NV_RANGE",
		description: "NV offset+size is out of range.",
	},
	TPMRCNVSize: errorDesc{
		name:        "TPM_RC_NV_SIZE",
		description: "Requested allocation size is larger than allowed.",
	},
	TPMRCNVLocked: errorDesc{
		name:        "TPM_RC_NV_LOCKED",
		description: "NV access locked.",
	},
	TPMRCNVAuthorization: errorDesc{
		name:        "TPM_RC_NV_AUTHORIZATION",
		description: "NV access authorization fails in command actions (this failure does not affect lockout.action)",
	},
	TPMRCNVUninitialized: errorDesc{
		name:        "TPM_RC_NV_UNINITIALIZED",
		description: "an NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored",
	},
	TPMRCNVSpace: errorDesc{
		name:        "TPM_RC_NV_SPACE",
		description: "insufficient space for NV allocation",
	},
	TPMRCNVDefined: errorDesc{
		name:        "TPM_RC_NV_DEFINED",
		description: "NV Index or persistent object already defined",
	},
	TPMRCBadContext: errorDesc{
		name:        "TPM_RC_BAD_CONTEXT",
		description: "context in TPM2_ContextLoad() is not valid",
	},
	TPMRCCPHash: errorDesc{
		name:        "TPM_RC_CPHASH",
		description: "cpHash value already set or not correct for use",
	},
	TPMRCParent: errorDesc{
		name:        "TPM_RC_PARENT",
		description: "handle for parent is not a valid parent",
	},
	TPMRCNeedsTest: errorDesc{
		name:        "TPM_RC_NEEDS_TEST",
		description: "some function needs testing.",
	},
	TPMRCNoResult: errorDesc{
		name:        "TPM_RC_NO_RESULT",
		description: "an internal function cannot process a request due to an unspecified problem. This code is usually related to invalid parameters that are not properly filtered by the input unmarshaling code.",
	},
	TPMRCSensitive: errorDesc{
		name:        "TPM_RC_SENSITIVE",
		description: "the sensitive area did not unmarshal correctly after decryption – this code is used in lieu of the other unmarshaling errors so that an attacker cannot determine where the unmarshaling error occurred",
	},
}

var fmt1Descs = map[TPMRC]errorDesc{
	TPMRCAsymmetric: errorDesc{
		name:        "TPM_RC_ASYMMETRIC RC_FMT1",
		description: "asymmetric algorithm not supported or not correct",
	},
	TPMRCAttributes: errorDesc{
		name:        "TPM_RC_ATTRIBUTES",
		description: "inconsistent attributes",
	},
	TPMRCHash: errorDesc{
		name:        "TPM_RC_HASH",
		description: "hash algorithm not supported or not appropriate",
	},
	TPMRCValue: errorDesc{
		name:        "TPM_RC_VALUE",
		description: "value is out of range or is not correct for the context",
	},
	TPMRCHierarchy: errorDesc{
		name:        "TPM_RC_HIERARCHY",
		description: "hierarchy is not enabled or is not correct for the use",
	},
	TPMRCKeySize: errorDesc{
		name:        "TPM_RC_KEY_SIZE",
		description: "key size is not supported",
	},
	TPMRCMGF: errorDesc{
		name:        "TPM_RC_MGF",
		description: "mask generation function not supported",
	},
	TPMRCMode: errorDesc{
		name:        "TPM_RC_MODE",
		description: "mode of operation not supported",
	},
	TPMRCType: errorDesc{
		name:        "TPM_RC_TYPE",
		description: "the type of the value is not appropriate for the use",
	},
	TPMRCHandle: errorDesc{
		name:        "TPM_RC_HANDLE",
		description: "the handle is not correct for the use",
	},
	TPMRCKDF: errorDesc{
		name:        "TPM_RC_KDF",
		description: "unsupported key derivation function or function not appropriate for use",
	},
	TPMRCRange: errorDesc{
		name:        "TPM_RC_RANGE",
		description: "value was out of allowed range.",
	},
	TPMRCAuthFail: errorDesc{
		name:        "TPM_RC_AUTH_FAIL",
		description: "the authorization HMAC check failed and DA counter incremented",
	},
	TPMRCNonce: errorDesc{
		name:        "TPM_RC_NONCE",
		description: "invalid nonce size or nonce value mismatch",
	},
	TPMRCPP: errorDesc{
		name:        "TPM_RC_PP",
		description: "authorization requires assertion of PP",
	},
	TPMRCScheme: errorDesc{
		name:        "TPM_RC_SCHEME",
		description: "unsupported or incompatible scheme",
	},
	TPMRCSize: errorDesc{
		name:        "TPM_RC_SIZE",
		description: "structure is the wrong size",
	},
	TPMRCSymmetric: errorDesc{
		name:        "TPM_RC_SYMMETRIC",
		description: "unsupported symmetric algorithm or key size, or not appropriate for instance",
	},
	TPMRCTag: errorDesc{
		name:        "TPM_RC_TAG",
		description: "incorrect structure tag",
	},
	TPMRCSelector: errorDesc{
		name:        "TPM_RC_SELECTOR",
		description: "union selector is incorrect",
	},
	TPMRCInsufficient: errorDesc{
		name:        "TPM_RC_INSUFFICIENT",
		description: "the TPM was unable to unmarshal a value because there were not enough octets in the input buffer",
	},
	TPMRCSignature: errorDesc{
		name:        "TPM_RC_SIGNATURE",
		description: "the signature is not valid",
	},
	TPMRCKey: errorDesc{
		name:        "TPM_RC_KEY",
		description: "key fields are not compatible with the selected use",
	},
	TPMRCPolicyFail: errorDesc{
		name:        "TPM_RC_POLICY_FAIL",
		description: "a policy check failed",
	},
	TPMRCIntegrity: errorDesc{
		name:        "TPM_RC_INTEGRITY",
		description: "integrity check failed",
	},
	TPMRCTicket: errorDesc{
		name:        "TPM_RC_TICKET",
		description: "invalid ticket",
	},
	TPMRCReservedBits: errorDesc{
		name:        "TPM_RC_RESERVED_BITS",
		description: "reserved bits not set to zero as required",
	},
	TPMRCBadAuth: errorDesc{
		name:        "TPM_RC_BAD_AUTH",
		description: "authorization failure without DA implications",
	},
	TPMRCExpired: errorDesc{
		name:        "TPM_RC_EXPIRED",
		description: "the policy has expired",
	},
	TPMRCPolicyCC: errorDesc{
		name:        "TPM_RC_POLICY_CC",
		description: "the commandCode in the policy is not the commandCode of the command or the command code in a policy command references a command that is not implemented",
	},
	TPMRCBinding: errorDesc{
		name:        "TPM_RC_BINDING",
		description: "public and sensitive portions of an object are not cryptographically bound",
	},
	TPMRCCurve: errorDesc{
		name:        "TPM_RC_CURVE",
		description: "curve not supported",
	},
	TPMRCECCPoint: errorDesc{
		name:        "TPM_RC_ECC_POINT",
		description: "point is not on the required curve.",
	},
}

var warnDescs = map[TPMRC]errorDesc{
	TPMRCContextGap: errorDesc{
		name:        "TPM_RC_CONTEXT_GAP",
		description: "gap for context ID is too large",
	},
	TPMRCObjectMemory: errorDesc{
		name:        "TPM_RC_OBJECT_MEMORY",
		description: "out of memory for object contexts",
	},
	TPMRCSessionMemory: errorDesc{
		name:        "TPM_RC_SESSION_MEMORY",
		description: "out of memory for session contexts",
	},
	TPMRCMemory: errorDesc{
		name:        "TPM_RC_MEMORY",
		description: "out of shared object/session memory or need space for internal operations",
	},
	TPMRCSessionHandles: errorDesc{
		name:        "TPM_RC_SESSION_HANDLES",
		description: "out of session handles – a session must be flushed before a new session may be created",
	},
	TPMRCObjectHandles: errorDesc{
		name:        "TPM_RC_OBJECT_HANDLES",
		description: "out of object handles – the handle space for objects is depleted and a reboot is required",
	},
	TPMRCLocality: errorDesc{
		name:        "TPM_RC_LOCALITY",
		description: "bad locality",
	},
	TPMRCYielded: errorDesc{
		name:        "TPM_RC_YIELDED",
		description: "the TPM has suspended operation on the command; forward progress was made and the command may be retried",
	},
	TPMRCCanceled: errorDesc{
		name:        "TPM_RC_CANCELED",
		description: "the command was canceled",
	},
	TPMRCTesting: errorDesc{
		name:        "TPM_RC_TESTING",
		description: "TPM is performing self-tests",
	},
	TPMRCReferenceH0: errorDesc{
		name:        "TPM_RC_REFERENCE_H0",
		description: "the 1st handle in the handle area references a transient object or session that is not loaded",
	},
	TPMRCReferenceH1: errorDesc{
		name:        "TPM_RC_REFERENCE_H1",
		description: "the 2nd handle in the handle area references a transient object or session that is not loaded",
	},
	TPMRCReferenceH2: errorDesc{
		name:        "TPM_RC_REFERENCE_H2",
		description: "the 3rd handle in the handle area references a transient object or session that is not loaded",
	},
	TPMRCReferenceH3: errorDesc{
		name:        "TPM_RC_REFERENCE_H3",
		description: "the 4th handle in the handle area references a transient object or session that is not loaded",
	},
	TPMRCReferenceH4: errorDesc{
		name:        "TPM_RC_REFERENCE_H4",
		description: "the 5th handle in the handle area references a transient object or session that is not loaded",
	},
	TPMRCReferenceH5: errorDesc{
		name:        "TPM_RC_REFERENCE_H5",
		description: "the 6th handle in the handle area references a transient object or session that is not loaded",
	},
	TPMRCReferenceH6: errorDesc{
		name:        "TPM_RC_REFERENCE_H6",
		description: "the 7th handle in the handle area references a transient object or session that is not loaded",
	},
	TPMRCReferenceS0: errorDesc{
		name:        "TPM_RC_REFERENCE_S0",
		description: "the 1st authorization session handle references a session that is not loaded",
	},
	TPMRCReferenceS1: errorDesc{
		name:        "TPM_RC_REFERENCE_S1",
		description: "the 2nd authorization session handle references a session that is not loaded",
	},
	TPMRCReferenceS2: errorDesc{
		name:        "TPM_RC_REFERENCE_S2",
		description: "the 3rd authorization session handle references a session that is not loaded",
	},
	TPMRCReferenceS3: errorDesc{
		name:        "TPM_RC_REFERENCE_S3",
		description: "the 4th authorization session handle references a session that is not loaded",
	},
	TPMRCReferenceS4: errorDesc{
		name:        "TPM_RC_REFERENCE_S4",
		description: "the 5th session handle references a session that is not loaded",
	},
	TPMRCReferenceS5: errorDesc{
		name:        "TPM_RC_REFERENCE_S5",
		description: "the 6th session handle references a session that is not loaded",
	},
	TPMRCReferenceS6: errorDesc{
		name:        "TPM_RC_REFERENCE_S6",
		description: "the 7th authorization session handle references a session that is not loaded",
	},
	TPMRCNVRate: errorDesc{
		name:        "TPM_RC_NV_RATE",
		description: "the TPM is rate-limiting accesses to prevent wearout of NV",
	},
	TPMRCLockout: errorDesc{
		name:        "TPM_RC_LOCKOUT",
		description: "authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode",
	},
	TPMRCRetry: errorDesc{
		name:        "TPM_RC_RETRY",
		description: "the TPM was not able to start the command",
	},
	TPMRCNVUnavailable: errorDesc{
		name:        "TPM_RC_NV_UNAVAILABLE",
		description: "the command may require writing of NV and NV is not current accessible",
	},
}

// subject represents a subject of a TPM error code with additional details
// (i.e., FMT1 codes)
type subject int

const (
	handle subject = iota + 1
	parameter
	session
)

// String returns the string representation of the ErrorSubject.
func (s subject) String() string {
	switch s {
	case handle:
		return "handle"
	case parameter:
		return "parameter"
	case session:
		return "session"
	default:
		return "unknown subject"
	}
}

// Fmt1Error represents a TPM 2.0 format-1 error, with additional information.
type Fmt1Error struct {
	// The canonical TPM error code, with handle/parameter/session info
	// stripped out.
	canonical TPMRC
	// Whether this was a handle, parameter, or session error.
	subject subject
	// Which handle, parameter, or session was in error
	index int
}

// Error returns the string representation of the error.
func (e Fmt1Error) Error() string {
	desc, ok := fmt1Descs[e.canonical]
	if !ok {
		return fmt.Sprintf("unknown format-1 error: %s %d (%x)", e.subject, e.index, uint32(e.canonical))
	}
	return fmt.Sprintf("%s (%v %d): %s", desc.name, e.subject, e.index, desc.description)
}

// Handle returns whether the error is handle-related and if so, which handle is
// in error.
func (e Fmt1Error) Handle() (bool, int) {
	if e.subject != handle {
		return false, 0
	}
	return true, e.index
}

// Parameter returns whether the error is handle-related and if so, which handle
// is in error.
func (e Fmt1Error) Parameter() (bool, int) {
	if e.subject != parameter {
		return false, 0
	}
	return true, e.index
}

// Session returns whether the error is handle-related and if so, which handle
// is in error.
func (e Fmt1Error) Session() (bool, int) {
	if e.subject != session {
		return false, 0
	}
	return true, e.index
}

// isFmt0Error returns true if the result is a format-0 error.
func (r TPMRC) isFmt0Error() bool {
	return (r&rcVer1) == rcVer1 && (r&rcWarn) != rcWarn
}

// isFmt1Error returns true and a format-1 error structure if the error is a
// format-1 error.
func (r TPMRC) isFmt1Error() (bool, Fmt1Error) {
	if (r & rcFmt1) != rcFmt1 {
		return false, Fmt1Error{}
	}
	subj := handle
	if (r & rcP) == rcP {
		subj = parameter
		r ^= rcP
	} else if (r & rcS) == rcS {
		subj = session
		r ^= rcS
	}
	idx := int((r & 0xF00) >> 8)
	r &= 0xFFFFF0FF
	return true, Fmt1Error{
		canonical: r,
		subject:   subj,
		index:     idx,
	}
}

// IsWarning returns true if the error is a warning code.
// This usually indicates a problem with the TPM state, and not the command.
// Retrying the command later may succeed.
func (r TPMRC) IsWarning() bool {
	if isFmt1, _ := r.isFmt1Error(); isFmt1 {
		// There aren't any format-1 warnings.
		return false
	}
	return (r&rcVer1) == rcVer1 && (r&rcWarn) == rcWarn
}

// Error produces a nice human-readable representation of the error, parsing TPM
// FMT1 errors as needed.
func (r TPMRC) Error() string {
	if isFmt1, fmt1 := r.isFmt1Error(); isFmt1 {
		return fmt1.Error()
	}
	if r.isFmt0Error() {
		desc, ok := fmt0Descs[r]
		if !ok {
			return fmt.Sprintf("unknown format-0 error code (0x%x)", uint32(r))
		}
		return fmt.Sprintf("%s: %s", desc.name, desc.description)
	}
	if r.IsWarning() {
		desc, ok := warnDescs[r]
		if !ok {
			return fmt.Sprintf("unknown warning (0x%x)", uint32(r))
		}
		return fmt.Sprintf("%s: %s", desc.name, desc.description)
	}
	return fmt.Sprintf("unrecognized error code (0x%x)", uint32(r))
}

// Is returns whether the TPMRC (which may be a FMT1 error) is equal to the
// given canonical error.
func (r TPMRC) Is(target error) bool {
	targetRC, ok := target.(TPMRC)
	if !ok {
		return false
	}
	if isFmt1, fmt1 := r.isFmt1Error(); isFmt1 {
		return fmt1.canonical == targetRC
	}
	return r == targetRC
}

// As returns whether the error can be assigned to the given interface type.
// If supported, it updates the value pointed at by target.
// Supports the Fmt1Error type.
func (r TPMRC) As(target interface{}) bool {
	pFmt1, ok := target.(*Fmt1Error)
	if !ok {
		return false
	}
	isFmt1, fmt1 := r.isFmt1Error()
	if !isFmt1 {
		return false
	}
	*pFmt1 = fmt1
	return true
}

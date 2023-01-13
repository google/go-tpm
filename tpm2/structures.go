// Package tpm2 defines all the TPM 2.0 structures together to avoid import cycles
package tpm2

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"encoding/binary"
	"reflect"

	// Register the relevant hash implementations.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
)

// TPMCmdHeader is the header structure in front of any TPM command.
// It is described in Part 1, Architecture.
type TPMCmdHeader struct {
	marshalByReflection
	Tag         TPMISTCommandTag
	Length      uint32
	CommandCode TPMCC
}

// TPMRspHeader is the header structure in front of any TPM response.
// It is described in Part 1, Architecture.
type TPMRspHeader struct {
	marshalByReflection
	Tag          TPMISTCommandTag
	Length       uint32
	ResponseCode TPMRC
}

// TPMAlgorithmID represents a TPM_ALGORITHM_ID
// this is the 1.2 compatible form of the TPM_ALG_ID
// See definition in Part 2, Structures, section 5.3.
type TPMAlgorithmID uint32

// TPMModifierIndicator represents a TPM_MODIFIER_INDICATOR.
// See definition in Part 2, Structures, section 5.3.
type TPMModifierIndicator uint32

// TPMAuthorizationSize represents a TPM_AUTHORIZATION_SIZE.
// the authorizationSize parameter in a command
// See definition in Part 2, Structures, section 5.3.
type TPMAuthorizationSize uint32

// TPMParameterSize represents a TPM_PARAMETER_SIZE.
// the parameterSize parameter in a command
// See definition in Part 2, Structures, section 5.3.
type TPMParameterSize uint32

// TPMKeySize represents a TPM_KEY_SIZE.
// a key size in octets
// See definition in Part 2, Structures, section 5.3.
type TPMKeySize uint16

// TPMKeyBits represents a TPM_KEY_BITS.
// a key size in bits
// See definition in Part 2, Structures, section 5.3.
type TPMKeyBits uint16

// TPMGenerated represents a TPM_GENERATED.
// See definition in Part 2: Structures, section 6.2.
type TPMGenerated uint32

// Generated values come from Part 2: Structures, section 6.2.
const (
	TPMGeneratedValue TPMGenerated = 0xff544347
)

// Check verifies that a TPMGenerated value is correct, and returns an error
// otherwise.
func (g TPMGenerated) Check() error {
	if g != TPMGeneratedValue {
		return fmt.Errorf("TPM_GENERATED value should be 0x%x, was 0x%x", TPMGeneratedValue, g)
	}
	return nil
}

// TPMAlgID represents a TPM_ALG_ID.
// See definition in Part 2: Structures, section 6.3.
type TPMAlgID uint16

// TPMECCCurve represents a TPM_ECC_Curve.
// See definition in Part 2: Structures, section 6.4.
type TPMECCCurve uint16

// Curve returns the elliptic.Curve associated with a TPMECCCurve.
func (c TPMECCCurve) Curve() (elliptic.Curve, error) {
	switch c {
	case TPMECCNistP224:
		return elliptic.P224(), nil
	case TPMECCNistP256:
		return elliptic.P256(), nil
	case TPMECCNistP384:
		return elliptic.P384(), nil
	case TPMECCNistP521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ECC curve: %v", c)
	}
}

// TPMCC represents a TPM_CC.
// See definition in Part 2: Structures, section 6.5.2.
type TPMCC uint32

// TPMRC represents a TPM_RC.
// See definition in Part 2: Structures, section 6.6.
type TPMRC uint32

// TPMEO represents a TPM_EO.
// See definition in Part 2: Structures, section 6.8.
type TPMEO uint16

// TPMST represents a TPM_ST.
// See definition in Part 2: Structures, section 6.9.
type TPMST uint16

// TPMSU represents a TPM_SU.
// See definition in Part 2: Structures, section 6.10.
type TPMSU uint16

// TPMSE represents a TPM_SE.
// See definition in Part 2: Structures, section 6.11.
type TPMSE uint8

// TPMCap represents a TPM_CAP.
// See definition in Part 2: Structures, section 6.12.
type TPMCap uint32

// TPMPT represents a TPM_PT.
// See definition in Part 2: Structures, section 6.13.
type TPMPT uint32

// TPMPTPCR represents a TPM_PT_PCR.
// See definition in Part 2: Structures, section 6.14.
type TPMPTPCR uint32

// TPMHandle represents a TPM_HANDLE.
// See definition in Part 2: Structures, section 7.1.
type TPMHandle uint32

// HandleValue returns the handle value. This behavior is intended to satisfy
// an interface that can be implemented by other, more complex types as well.
func (h TPMHandle) HandleValue() uint32 {
	return uint32(h)
}

// KnownName returns the TPM Name associated with the handle, if it can be known
// based only on the handle. This depends upon the value of the handle:
// only PCR, session, and permanent values have known constant Names.
// See definition in part 1: Architecture, section 16.
func (h TPMHandle) KnownName() *TPM2BName {
	switch (byte)(h >> 24) {
	case 0x00, 0x02, 0x03, 0x40:
		result := make([]byte, 4)
		binary.BigEndian.PutUint32(result, h.HandleValue())
		return &TPM2BName{Buffer: result}
	default:
		return nil
	}
}

// TPMAAlgorithm represents a TPMA_ALGORITHM.
// See definition in Part 2: Structures, section 8.2.
type TPMAAlgorithm struct {
	bitfield32
	marshalByReflection
	// SET (1): an asymmetric algorithm with public and private portions
	// CLEAR (0): not an asymmetric algorithm
	Asymmetric bool `gotpm:"bit=0"`
	// SET (1): a symmetric block cipher
	// CLEAR (0): not a symmetric block cipher
	Symmetric bool `gotpm:"bit=1"`
	// SET (1): a hash algorithm
	// CLEAR (0): not a hash algorithm
	Hash bool `gotpm:"bit=2"`
	// SET (1): an algorithm that may be used as an object type
	// CLEAR (0): an algorithm that is not used as an object type
	Object bool `gotpm:"bit=3"`
	// SET (1): a signing algorithm. The setting of asymmetric,
	// symmetric, and hash will indicate the type of signing algorithm.
	// CLEAR (0): not a signing algorithm
	Signing bool `gotpm:"bit=8"`
	// SET (1): an encryption/decryption algorithm. The setting of
	// asymmetric, symmetric, and hash will indicate the type of
	// encryption/decryption algorithm.
	// CLEAR (0): not an encryption/decryption algorithm
	Encrypting bool `gotpm:"bit=9"`
	// SET (1): a method such as a key derivative function (KDF)
	// CLEAR (0): not a method
	Method bool `gotpm:"bit=10"`
}

// TPMAObject represents a TPMA_OBJECT.
// See definition in Part 2: Structures, section 8.3.2.
type TPMAObject struct {
	bitfield32
	marshalByReflection
	// SET (1): The hierarchy of the object, as indicated by its
	// Qualified Name, may not change.
	// CLEAR (0): The hierarchy of the object may change as a result
	// of this object or an ancestor key being duplicated for use in
	// another hierarchy.
	FixedTPM bool `gotpm:"bit=1"`
	// SET (1): Previously saved contexts of this object may not be
	// loaded after Startup(CLEAR).
	// CLEAR (0): Saved contexts of this object may be used after a
	// Shutdown(STATE) and subsequent Startup().
	STClear bool `gotpm:"bit=2"`
	// SET (1): The parent of the object may not change.
	// CLEAR (0): The parent of the object may change as the result of
	// a TPM2_Duplicate() of the object.
	FixedParent bool `gotpm:"bit=4"`
	// SET (1): Indicates that, when the object was created with
	// TPM2_Create() or TPM2_CreatePrimary(), the TPM generated all of
	// the sensitive data other than the authValue.
	// CLEAR (0): A portion of the sensitive data, other than the
	// authValue, was provided by the caller.
	SensitiveDataOrigin bool `gotpm:"bit=5"`
	// SET (1): Approval of USER role actions with this object may be
	// with an HMAC session or with a password using the authValue of
	// the object or a policy session.
	// CLEAR (0): Approval of USER role actions with this object may
	// only be done with a policy session.
	UserWithAuth bool `gotpm:"bit=6"`
	// SET (1): Approval of ADMIN role actions with this object may
	// only be done with a policy session.
	// CLEAR (0): Approval of ADMIN role actions with this object may
	// be with an HMAC session or with a password using the authValue
	// of the object or a policy session.
	AdminWithPolicy bool `gotpm:"bit=7"`
	// SET (1): The object is not subject to dictionary attack
	// protections.
	// CLEAR (0): The object is subject to dictionary attack
	// protections.
	NoDA bool `gotpm:"bit=10"`
	// SET (1): If the object is duplicated, then symmetricAlg shall
	// not be TPM_ALG_NULL and newParentHandle shall not be
	// TPM_RH_NULL.
	// CLEAR (0): The object may be duplicated without an inner
	// wrapper on the private portion of the object and the new parent
	// may be TPM_RH_NULL.
	EncryptedDuplication bool `gotpm:"bit=11"`
	// SET (1): Key usage is restricted to manipulate structures of
	// known format; the parent of this key shall have restricted SET.
	// CLEAR (0): Key usage is not restricted to use on special
	// formats.
	Restricted bool `gotpm:"bit=16"`
	// SET (1): The private portion of the key may be used to decrypt.
	// CLEAR (0): The private portion of the key may not be used to
	// decrypt.
	Decrypt bool `gotpm:"bit=17"`
	// SET (1): For a symmetric cipher object, the private portion of
	// the key may be used to encrypt. For other objects, the private
	// portion of the key may be used to sign.
	// CLEAR (0): The private portion of the key may not be used to
	// sign or encrypt.
	SignEncrypt bool `gotpm:"bit=18"`
	// SET (1): An asymmetric key that may not be used to sign with
	// TPM2_Sign() CLEAR (0): A key that may be used with TPM2_Sign()
	// if sign is SET
	// NOTE: This attribute only has significance if sign is SET.
	X509Sign bool `gotpm:"bit=19"`
}

// TPMASession represents a TPMA_SESSION.
// See definition in Part 2: Structures, section 8.4.
type TPMASession struct {
	bitfield8
	marshalByReflection
	// SET (1): In a command, this setting indicates that the session
	// is to remain active after successful completion of the command.
	// In a response, it indicates that the session is still active.
	// If SET in the command, this attribute shall be SET in the response.
	// CLEAR (0): In a command, this setting indicates that the TPM should
	// close the session and flush any related context when the command
	// completes successfully. In a response, it indicates that the
	// session is closed and the context is no longer active.
	// This attribute has no meaning for a password authorization and the
	// TPM will allow any setting of the attribute in the command and SET
	// the attribute in the response.
	ContinueSession bool `gotpm:"bit=0"`
	// SET (1): In a command, this setting indicates that the command
	// should only be executed if the session is exclusive at the start of
	// the command. In a response, it indicates that the session is
	// exclusive. This setting is only allowed if the audit attribute is
	// SET (TPM_RC_ATTRIBUTES).
	// CLEAR (0): In a command, indicates that the session need not be
	// exclusive at the start of the command. In a response, indicates that
	// the session is not exclusive.
	AuditExclusive bool `gotpm:"bit=1"`
	// SET (1): In a command, this setting indicates that the audit digest
	// of the session should be initialized and the exclusive status of the
	// session SET. This setting is only allowed if the audit attribute is
	// SET (TPM_RC_ATTRIBUTES).
	// CLEAR (0): In a command, indicates that the audit digest should not
	// be initialized. This bit is always CLEAR in a response.
	AuditReset bool `gotpm:"bit=2"`
	// SET (1): In a command, this setting indicates that the first
	// parameter in the command is symmetrically encrypted using the
	// parameter encryption scheme described in TPM 2.0 Part 1. The TPM will
	// decrypt the parameter after performing any HMAC computations and
	// before unmarshaling the parameter. In a response, the attribute is
	// copied from the request but has no effect on the response.
	// CLEAR (0): Session not used for encryption.
	// For a password authorization, this attribute will be CLEAR in both the
	// command and response.
	Decrypt bool `gotpm:"bit=5"`
	// SET (1): In a command, this setting indicates that the TPM should use
	// this session to encrypt the first parameter in the response. In a
	// response, it indicates that the attribute was set in the command and
	// that the TPM used the session to encrypt the first parameter in the
	// response using the parameter encryption scheme described in TPM 2.0
	// Part 1.
	// CLEAR (0): Session not used for encryption.
	// For a password authorization, this attribute will be CLEAR in both the
	// command and response.
	Encrypt bool `gotpm:"bit=6"`
	// SET (1): In a command or response, this setting indicates that the
	// session is for audit and that auditExclusive and auditReset have
	// meaning. This session may also be used for authorization, encryption,
	// or decryption. The encrypted and encrypt fields may be SET or CLEAR.
	// CLEAR (0): Session is not used for audit.
	// If SET in the command, then this attribute will be SET in the response.
	Audit bool `gotpm:"bit=7"`
}

// TPMALocality represents a TPMA_LOCALITY.
// See definition in Part 2: Structures, section 8.5.
type TPMALocality struct {
	bitfield8
	marshalByReflection
	TPMLocZero  bool `gotpm:"bit=0"`
	TPMLocOne   bool `gotpm:"bit=1"`
	TPMLocTwo   bool `gotpm:"bit=2"`
	TPMLocThree bool `gotpm:"bit=3"`
	TPMLocFour  bool `gotpm:"bit=4"`
	// If any of these bits is set, an extended locality is indicated
	Extended uint8 `gotpm:"bit=7:5"`
}

// TPMACC represents a TPMA_CC.
// See definition in Part 2: Structures, section 8.9.
type TPMACC struct {
	bitfield32
	marshalByReflection
	// indicates the command being selected
	CommandIndex uint16 `gotpm:"bit=15:0"`
	// SET (1): indicates that the command may write to NV
	// CLEAR (0): indicates that the command does not write to NV
	NV bool `gotpm:"bit=22"`
	// SET (1): This command could flush any number of loaded contexts.
	// CLEAR (0): no additional changes other than indicated by the flushed attribute
	Extensive bool `gotpm:"bit=23"`
	// SET (1): The context associated with any transient handle in the command will be flushed when this command completes.
	// CLEAR (0): No context is flushed as a side effect of this command.
	Flushed bool `gotpm:"bit=24"`
	// indicates the number of the handles in the handle area for this command
	CHandles uint8 `gotpm:"bit=27:25"`
	// SET (1): indicates the presence of the handle area in the response
	RHandle bool `gotpm:"bit=28"`
	// SET (1): indicates that the command is vendor-specific
	// CLEAR (0): indicates that the command is defined in a version of this specification
	V bool `gotpm:"bit=29"`
}

// TPMAACT represents a TPMA_ACT.
// See definition in Part 2: Structures, section 8.12.
type TPMAACT struct {
	bitfield32
	marshalByReflection
	// SET (1): The ACT has signaled
	// CLEAR (0): The ACT has not signaled
	Signaled bool `gotpm:"bit=0"`
	// SET (1): The ACT signaled bit is preserved over a power cycle
	// CLEAR (0): The ACT signaled bit is not preserved over a power cycle
	PreserveSignaled bool `gotpm:"bit=1"`
}

// TPMIYesNo represents a TPMI_YES_NO.
// See definition in Part 2: Structures, section 9.2.
// Use native bool for TPMI_YES_NO; encoding/binary already treats this as 8 bits wide.
type TPMIYesNo = bool

// TPMIDHObject represents a TPMI_DH_OBJECT.
// See definition in Part 2: Structures, section 9.3.
type TPMIDHObject = TPMHandle

// TPMIDHEntity represents a TPMI_DH_ENTITY.
// See definition in Part 2: Structures, section 9.6.
type TPMIDHEntity = TPMHandle

// TPMISHAuthSession represents a TPMI_SH_AUTH_SESSION.
// See definition in Part 2: Structures, section 9.8.
type TPMISHAuthSession = TPMHandle

// TPMISHHMAC represents a TPMI_SH_HMAC.
// See definition in Part 2: Structures, section 9.9.
type TPMISHHMAC = TPMHandle

// TPMISHPolicy represents a TPMI_SH_POLICY.
// See definition in Part 2: Structures, section 9.10.
type TPMISHPolicy = TPMHandle

// TPMIDHContext represents a TPMI_DH_CONTEXT.
// See definition in Part 2: Structures, section 9.11.
type TPMIDHContext = TPMHandle

// TPMIDHSaved represents a TPMI_DH_SAVED.
// See definition in Part 2: Structures, section 9.12.
type TPMIDHSaved = TPMHandle

// TPMIRHHierarchy represents a TPMI_RH_HIERARCHY.
// See definition in Part 2: Structures, section 9.13.
type TPMIRHHierarchy = TPMHandle

// TPMIRHEnables represents a TPMI_RH_ENABLES.
// See definition in Part 2: Structures, section 9.14.
type TPMIRHEnables = TPMHandle

// TPMIRHHierarchyAuth represents a TPMI_RH_HIERARCHY_AUTH.
// See definition in Part 2: Structures, section 9.15.
type TPMIRHHierarchyAuth = TPMHandle

// TPMIRHHierarchyPolicy represents a TPMI_RH_HIERARCHY_POLICY.
// See definition in Part 2: Structures, section 9.16.
type TPMIRHHierarchyPolicy = TPMHandle

// TPMIRHPlatform represents a TPMI_RH_PLATFORM.
// See definition in Part 2: Structures, section 9.17.
type TPMIRHPlatform = TPMHandle

// TPMIRHOwner represents a TPMI_RH_OWNER.
// See definition in Part 2: Structures, section 9.18.
type TPMIRHOwner = TPMHandle

// TPMIRHEndorsement represents a TPMI_RH_ENDORSEMENT.
// See definition in Part 2: Structures, section 9.19.
type TPMIRHEndorsement = TPMHandle

// TPMIRHProvision represents a TPMI_RH_PROVISION.
// See definition in Part 2: Structures, section 9.20.
type TPMIRHProvision = TPMHandle

// TPMIRHClear represents a TPMI_RH_CLEAR.
// See definition in Part 2: Structures, section 9.21.
type TPMIRHClear = TPMHandle

// TPMIRHNVAuth represents a TPMI_RH_NV_AUTH.
// See definition in Part 2: Structures, section 9.22.
type TPMIRHNVAuth = TPMHandle

// TPMIRHLockout represents a TPMI_RH_LOCKOUT.
// See definition in Part 2: Structures, section 9.23.
type TPMIRHLockout = TPMHandle

// TPMIRHNVIndex represents a TPMI_RH_NV_INDEX.
// See definition in Part 2: Structures, section 9.24.
type TPMIRHNVIndex = TPMHandle

// TPMIRHAC represents a TPMI_RH_AC.
// See definition in Part 2: Structures, section 9.25.
type TPMIRHAC = TPMHandle

// TPMIRHACT represents a TPMI_RH_ACT.
// See definition in Part 2: Structures, section 9.26.
type TPMIRHACT = TPMHandle

// TPMIAlgHash represents a TPMI_ALG_HASH.
// See definition in Part 2: Structures, section 9.27.
type TPMIAlgHash = TPMAlgID

// Hash returns the crypto.Hash associated with a TPMIAlgHash.
func (a TPMIAlgHash) Hash() (crypto.Hash, error) {
	switch TPMAlgID(a) {
	case TPMAlgSHA1:
		return crypto.SHA1, nil
	case TPMAlgSHA256:
		return crypto.SHA256, nil
	case TPMAlgSHA384:
		return crypto.SHA384, nil
	case TPMAlgSHA512:
		return crypto.SHA512, nil
	}
	return crypto.SHA256, fmt.Errorf("unsupported hash algorithm: %v", a)
}

// TPMIAlgSym represents a TPMI_ALG_SYM.
// See definition in Part 2: Structures, section 9.29.
type TPMIAlgSym = TPMAlgID

// TPMIAlgSymObject represents a TPMI_ALG_SYM_OBJECT.
// See definition in Part 2: Structures, section 9.30.
type TPMIAlgSymObject = TPMAlgID

// TPMIAlgSymMode represents a TPMI_ALG_SYM_MODE.
// See definition in Part 2: Structures, section 9.31.
type TPMIAlgSymMode = TPMAlgID

// TPMIAlgKDF represents a TPMI_ALG_KDF.
// See definition in Part 2: Structures, section 9.32.
type TPMIAlgKDF = TPMAlgID

// TPMIAlgSigScheme represents a TPMI_ALG_SIG_SCHEME.
// See definition in Part 2: Structures, section 9.33.
type TPMIAlgSigScheme = TPMAlgID

// TPMISTCommandTag represents a TPMI_ST_COMMAND_TAG.
// See definition in Part 2: Structures, section 9.35.
type TPMISTCommandTag = TPMST

// TPMSEmpty represents a TPMS_EMPTY.
// See definition in Part 2: Structures, section 10.1.
type TPMSEmpty struct {
	marshalByReflection
}

// TPMTHA represents a TPMT_HA.
// See definition in Part 2: Structures, section 10.3.2.
type TPMTHA struct {
	marshalByReflection
	// selector of the hash contained in the digest that implies the size of the digest
	HashAlg TPMIAlgHash `gotpm:"nullable"`
	// the digest data
	// NOTE: For convenience, this is not implemented as a union.
	Digest []byte
}

// TPM2BDigest represents a TPM2B_DIGEST.
// See definition in Part 2: Structures, section 10.4.2.
type TPM2BDigest TPM2BData

// TPM2BData represents a TPM2B_DATA.
// See definition in Part 2: Structures, section 10.4.3.
type TPM2BData struct {
	marshalByReflection
	// size in octets of the buffer field; may be 0
	Buffer []byte `gotpm:"sized"`
}

// TPM2BNonce represents a TPM2B_NONCE.
// See definition in Part 2: Structures, section 10.4.4.
type TPM2BNonce TPM2BDigest

// TPM2BEvent represents a TPM2B_EVENT.
// See definition in Part 2: Structures, section 10.4.7.
type TPM2BEvent TPM2BData

// TPM2BTimeout represents a TPM2B_TIMEOUT.
// See definition in Part 2: Structures, section 10.4.10.
type TPM2BTimeout TPM2BData

// TPM2BAuth represents a TPM2B_AUTH.
// See definition in Part 2: Structures, section 10.4.5.
type TPM2BAuth TPM2BDigest

// TPM2BOperand represents a TPM2B_Operand.
// See definition in Part 2: Structures, section 10.4.6.
type TPM2BOperand TPM2BDigest

// TPM2BMaxBuffer represents a TPM2B_MAX_BUFFER.
// See definition in Part 2: Structures, section 10.4.8.
type TPM2BMaxBuffer TPM2BData

// TPM2BMaxNVBuffer represents a TPM2B_MAX_NV_BUFFER.
// See definition in Part 2: Structures, section 10.4.9.
type TPM2BMaxNVBuffer TPM2BData

// TPM2BName represents a TPM2B_NAME.
// See definition in Part 2: Structures, section 10.5.3.
// NOTE: This structure does not contain a TPMUName, because that union
// is not tagged with a selector. Instead, TPM2B_Name is flattened and
// all TPMDirect helpers that deal with names will deal with them as so.
type TPM2BName TPM2BData

// TPMSPCRSelection represents a TPMS_PCR_SELECTION.
// See definition in Part 2: Structures, section 10.6.2.
type TPMSPCRSelection struct {
	marshalByReflection
	Hash      TPMIAlgHash
	PCRSelect []byte `gotpm:"sized8"`
}

// TPMTTKCreation represents a TPMT_TK_CREATION.
// See definition in Part 2: Structures, section 10.7.3.
type TPMTTKCreation struct {
	marshalByReflection
	// ticket structure tag
	Tag TPMST
	// the hierarchy containing name
	Hierarchy TPMIRHHierarchy
	// This shall be the HMAC produced using a proof value of hierarchy.
	Digest TPM2BDigest
}

// TPMTTKVerified represents a TPMT_TK_Verified.
// See definition in Part 2: Structures, section 10.7.4.
type TPMTTKVerified struct {
	marshalByReflection
	// ticket structure tag
	Tag TPMST
	// the hierarchy containing keyName
	Hierarchy TPMIRHHierarchy
	// This shall be the HMAC produced using a proof value of hierarchy.
	Digest TPM2BDigest
}

// TPMTTKAuth represents a TPMT_TK_AUTH.
// See definition in Part 2: Structures, section 10.7.5.
type TPMTTKAuth struct {
	marshalByReflection
	// ticket structure tag
	Tag TPMST
	// the hierarchy of the object used to produce the ticket
	Hierarchy TPMIRHHierarchy `gotpm:"nullable"`
	// This shall be the HMAC produced using a proof value of hierarchy.
	Digest TPM2BDigest
}

// TPMTTKHashCheck represents a TPMT_TK_HASHCHECK.
// See definition in Part 2: Structures, section 10.7.6.
type TPMTTKHashCheck struct {
	marshalByReflection
	// ticket structure tag
	Tag TPMST
	// the hierarchy
	Hierarchy TPMIRHHierarchy `gotpm:"nullable"`
	// This shall be the HMAC produced using a proof value of hierarchy.
	Digest TPM2BDigest
}

// TPMSAlgProperty represents a TPMS_ALG_PROPERTY.
// See definition in Part 2: Structures, section 10.8.1.
type TPMSAlgProperty struct {
	marshalByReflection
	// an algorithm identifier
	Alg TPMAlgID
	// the attributes of the algorithm
	AlgProperties TPMAAlgorithm
}

// TPMSTaggedProperty represents a TPMS_TAGGED_PROPERTY.
// See definition in Part 2: Structures, section 10.8.2.
type TPMSTaggedProperty struct {
	marshalByReflection
	// a property identifier
	Property TPMPT
	// the value of the property
	Value uint32
}

// TPMSTaggedPCRSelect represents a TPMS_TAGGED_PCR_SELECT.
// See definition in Part 2: Structures, section 10.8.3.
type TPMSTaggedPCRSelect struct {
	marshalByReflection
	// the property identifier
	Tag TPMPTPCR
	// the bit map of PCR with the identified property
	PCRSelect []byte `gotpm:"sized8"`
}

// TPMSTaggedPolicy represents a TPMS_TAGGED_POLICY.
// See definition in Part 2: Structures, section 10.8.4.
type TPMSTaggedPolicy struct {
	marshalByReflection
	// a permanent handle
	Handle TPMHandle
	// the policy algorithm and hash
	PolicyHash TPMTHA
}

// TPMSACTData represents a TPMS_ACT_DATA.
// See definition in Part 2: Structures, section 10.8.5.
type TPMSACTData struct {
	marshalByReflection
	// a permanent handle
	Handle TPMHandle
	// the current timeout of the ACT
	Timeout uint32
	// the state of the ACT
	Attributes TPMAACT
}

// TPMLCC represents a TPML_CC.
// See definition in Part 2: Structures, section 10.9.1.
type TPMLCC struct {
	marshalByReflection
	CommandCodes []TPMCC `gotpm:"list"`
}

// TPMLCCA represents a TPML_CCA.
// See definition in Part 2: Structures, section 10.9.2.
type TPMLCCA struct {
	marshalByReflection
	CommandAttributes []TPMACC `gotpm:"list"`
}

// TPMLAlg represents a TPMLALG.
// See definition in Part 2: Structures, section 10.9.3.
type TPMLAlg struct {
	marshalByReflection
	Algorithms []TPMAlgID `gotpm:"list"`
}

// TPMLHandle represents a TPML_HANDLE.
// See definition in Part 2: Structures, section 10.9.4.
type TPMLHandle struct {
	marshalByReflection
	Handle []TPMHandle `gotpm:"list"`
}

// TPMLDigest represents a TPML_DIGEST.
// See definition in Part 2: Structures, section 10.9.5.
type TPMLDigest struct {
	marshalByReflection
	// a list of digests
	Digests []TPM2BDigest `gotpm:"list"`
}

// TPMLDigestValues represents a TPML_DIGEST_VALUES.
// See definition in Part 2: Structures, section 10.9.6.
type TPMLDigestValues struct {
	marshalByReflection
	// a list of tagged digests
	Digests []TPMTHA `gotpm:"list"`
}

// TPMLPCRSelection represents a TPML_PCR_SELECTION.
// See definition in Part 2: Structures, section 10.9.7.
type TPMLPCRSelection struct {
	marshalByReflection
	PCRSelections []TPMSPCRSelection `gotpm:"list"`
}

// TPMLAlgProperty represents a TPML_ALG_PROPERTY.
// See definition in Part 2: Structures, section 10.9.8.
type TPMLAlgProperty struct {
	marshalByReflection
	AlgProperties []TPMSAlgProperty `gotpm:"list"`
}

// TPMLTaggedTPMProperty represents a TPML_TAGGED_TPM_PROPERTY.
// See definition in Part 2: Structures, section 10.9.9.
type TPMLTaggedTPMProperty struct {
	marshalByReflection
	TPMProperty []TPMSTaggedProperty `gotpm:"list"`
}

// TPMLTaggedPCRProperty represents a TPML_TAGGED_PCR_PROPERTY.
// See definition in Part 2: Structures, section 10.9.10.
type TPMLTaggedPCRProperty struct {
	marshalByReflection
	PCRProperty []TPMSTaggedPCRSelect `gotpm:"list"`
}

// TPMLECCCurve represents a TPML_ECC_CURVE.
// See definition in Part 2: Structures, section 10.9.11.
type TPMLECCCurve struct {
	marshalByReflection
	ECCCurves []TPMECCCurve `gotpm:"list"`
}

// TPMLTaggedPolicy represents a TPML_TAGGED_POLICY.
// See definition in Part 2: Structures, section 10.9.12.
type TPMLTaggedPolicy struct {
	marshalByReflection
	Policies []TPMSTaggedPolicy `gotpm:"list"`
}

// TPMLACTData represents a TPML_ACT_DATA.
// See definition in Part 2: Structures, section 10.9.13.
type TPMLACTData struct {
	marshalByReflection
	ACTData []TPMSACTData `gotpm:"list"`
}

type tpmuCapabilities struct {
	selector TPMCap
	contents Marshallable
}

type capabilitiesContents interface {
	Marshallable
	*TPMLAlgProperty | *TPMLHandle | *TPMLCCA | *TPMLCC | *TPMLPCRSelection | *TPMLTaggedTPMProperty |
		*TPMLTaggedPCRProperty | *TPMLECCCurve | *TPMLTaggedPolicy | *TPMLACTData
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuCapabilities) create(hint int64) (reflect.Value, error) {
	switch TPMCap(hint) {
	case TPMCapAlgs:
		contents := TPMLAlgProperty{}
		u.contents = &contents
		u.selector = TPMCap(hint)
		return reflect.ValueOf(&contents), nil
	case TPMCapHandles:
		contents := TPMLHandle{}
		u.contents = &contents
		u.selector = TPMCap(hint)
		return reflect.ValueOf(&contents), nil
	case TPMCapCommands:
		contents := TPMLCCA{}
		u.contents = &contents
		u.selector = TPMCap(hint)
		return reflect.ValueOf(&contents), nil
	case TPMCapPPCommands, TPMCapAuditCommands:
		contents := TPMLCC{}
		u.contents = &contents
		u.selector = TPMCap(hint)
		return reflect.ValueOf(&contents), nil
	case TPMCapPCRs:
		contents := TPMLPCRSelection{}
		u.contents = &contents
		u.selector = TPMCap(hint)
		return reflect.ValueOf(&contents), nil
	case TPMCapTPMProperties:
		contents := TPMLTaggedTPMProperty{}
		u.contents = &contents
		u.selector = TPMCap(hint)
		return reflect.ValueOf(&contents), nil
	case TPMCapPCRProperties:
		contents := TPMLTaggedPCRProperty{}
		u.contents = &contents
		u.selector = TPMCap(hint)
		return reflect.ValueOf(&contents), nil
	case TPMCapECCCurves:
		contents := TPMLECCCurve{}
		u.contents = &contents
		u.selector = TPMCap(hint)
		return reflect.ValueOf(&contents), nil
	case TPMCapAuthPolicies:
		contents := TPMLTaggedPolicy{}
		u.contents = &contents
		u.selector = TPMCap(hint)
		return reflect.ValueOf(&contents), nil
	case TPMCapACT:
		contents := TPMLACTData{}
		u.contents = &contents
		u.selector = TPMCap(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuCapabilities) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMCap(hint) {
	case TPMCapAlgs:
		contents := TPMLAlgProperty{}
		if u.contents != nil {
			contents = *u.contents.(*TPMLAlgProperty)
		}
		return reflect.ValueOf(&contents), nil
	case TPMCapHandles:
		contents := TPMLHandle{}
		if u.contents != nil {
			contents = *u.contents.(*TPMLHandle)
		}
		return reflect.ValueOf(&contents), nil
	case TPMCapCommands:
		contents := TPMLCCA{}
		if u.contents != nil {
			contents = *u.contents.(*TPMLCCA)
		}
		return reflect.ValueOf(&contents), nil
	case TPMCapPPCommands, TPMCapAuditCommands:
		contents := TPMLCC{}
		if u.contents != nil {
			contents = *u.contents.(*TPMLCC)
		}
		return reflect.ValueOf(&contents), nil
	case TPMCapPCRs:
		contents := TPMLPCRSelection{}
		if u.contents != nil {
			contents = *u.contents.(*TPMLPCRSelection)
		}
		return reflect.ValueOf(&contents), nil
	case TPMCapTPMProperties:
		contents := TPMLTaggedTPMProperty{}
		if u.contents != nil {
			contents = *u.contents.(*TPMLTaggedTPMProperty)
		}
		return reflect.ValueOf(&contents), nil
	case TPMCapPCRProperties:
		contents := TPMLTaggedPCRProperty{}
		if u.contents != nil {
			contents = *u.contents.(*TPMLTaggedPCRProperty)
		}
		return reflect.ValueOf(&contents), nil
	case TPMCapECCCurves:
		contents := TPMLECCCurve{}
		if u.contents != nil {
			contents = *u.contents.(*TPMLECCCurve)
		}
		return reflect.ValueOf(&contents), nil
	case TPMCapAuthPolicies:
		contents := TPMLTaggedPolicy{}
		if u.contents != nil {
			contents = *u.contents.(*TPMLTaggedPolicy)
		}
		return reflect.ValueOf(&contents), nil
	case TPMCapACT:
		contents := TPMLACTData{}
		if u.contents != nil {
			contents = *u.contents.(*TPMLACTData)
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUCapabilities represents a TPMU_CAPABILITIES.
// See definition in Part 2: Structures, section 10.10.1.
func TPMUCapabilities[C capabilitiesContents](selector TPMCap, contents C) tpmuCapabilities {
	return tpmuCapabilities{
		selector: selector,
		contents: contents,
	}
}

// Algorithms returns the 'algorithms' member of the union.
func (u *tpmuCapabilities) Algorithms() maybe[TPMLAlgProperty] {
	if u.selector == TPMCapAlgs {
		return asMaybe(u.contents.(*TPMLAlgProperty))
	}
	return maybeNot[TPMLAlgProperty](fmt.Errorf("did not contain algorithms (selector value was %v)", u.selector))
}

// Handles returns the 'handles' member of the union.
func (u *tpmuCapabilities) Handles() maybe[TPMLHandle] {
	if u.selector == TPMCapHandles {
		return asMaybe(u.contents.(*TPMLHandle))
	}
	return maybeNot[TPMLHandle](fmt.Errorf("did not contain handles (selector value was %v)", u.selector))
}

// Command returns the 'command' member of the union.
func (u *tpmuCapabilities) Command() maybe[TPMLCCA] {
	if u.selector == TPMCapAlgs {
		return asMaybe(u.contents.(*TPMLCCA))
	}
	return maybeNot[TPMLCCA](fmt.Errorf("did not contain command (selector value was %v)", u.selector))
}

// PPCommands returns the 'ppCommands' member of the union.
func (u *tpmuCapabilities) PPCommands() maybe[TPMLCC] {
	if u.selector == TPMCapPPCommands {
		return asMaybe(u.contents.(*TPMLCC))
	}
	return maybeNot[TPMLCC](fmt.Errorf("did not contain ppCommands (selector value was %v)", u.selector))
}

// AuditCommands returns the 'auditCommands' member of the union.
func (u *tpmuCapabilities) AuditCommands() maybe[TPMLCC] {
	if u.selector == TPMCapAuditCommands {
		return asMaybe(u.contents.(*TPMLCC))
	}
	return maybeNot[TPMLCC](fmt.Errorf("did not contain auditCommands (selector value was %v)", u.selector))
}

// AssignedPCR returns the 'assignedPCR' member of the union.
func (u *tpmuCapabilities) AssignedPCR() maybe[TPMLPCRSelection] {
	if u.selector == TPMCapPCRs {
		return asMaybe(u.contents.(*TPMLPCRSelection))
	}
	return maybeNot[TPMLPCRSelection](fmt.Errorf("did not contain assignedPCR (selector value was %v)", u.selector))
}

// TPMProperties returns the 'tpmProperties' member of the union.
func (u *tpmuCapabilities) TPMProperties() maybe[TPMLTaggedTPMProperty] {
	if u.selector == TPMCapTPMProperties {
		return asMaybe(u.contents.(*TPMLTaggedTPMProperty))
	}
	return maybeNot[TPMLTaggedTPMProperty](fmt.Errorf("did not contain tpmProperties (selector value was %v)", u.selector))
}

// PCRProperties returns the 'pcrProperties' member of the union.
func (u *tpmuCapabilities) PCRProperties() maybe[TPMLTaggedPCRProperty] {
	if u.selector == TPMCapPCRProperties {
		return asMaybe(u.contents.(*TPMLTaggedPCRProperty))
	}
	return maybeNot[TPMLTaggedPCRProperty](fmt.Errorf("did not contain pcrProperties (selector value was %v)", u.selector))
}

// ECCCurves returns the 'eccCurves' member of the union.
func (u *tpmuCapabilities) ECCCurves() maybe[TPMLECCCurve] {
	if u.selector == TPMCapECCCurves {
		return asMaybe(u.contents.(*TPMLECCCurve))
	}
	return maybeNot[TPMLECCCurve](fmt.Errorf("did not contain eccCurves (selector value was %v)", u.selector))
}

// AuthPolicies returns the 'authPolicies' member of the union.
func (u *tpmuCapabilities) AuthPolicies() maybe[TPMLTaggedPolicy] {
	if u.selector == TPMCapAuthPolicies {
		return asMaybe(u.contents.(*TPMLTaggedPolicy))
	}
	return maybeNot[TPMLTaggedPolicy](fmt.Errorf("did not contain authPolicies (selector value was %v)", u.selector))
}

// ACTData returns the 'actData' member of the union.
func (u *tpmuCapabilities) ACTData() maybe[TPMLACTData] {
	if u.selector == TPMCapAuthPolicies {
		return asMaybe(u.contents.(*TPMLACTData))
	}
	return maybeNot[TPMLACTData](fmt.Errorf("did not contain actData (selector value was %v)", u.selector))
}

// TPMSCapabilityData represents a TPMS_CAPABILITY_DATA.
// See definition in Part 2: Structures, section 10.10.2.
type TPMSCapabilityData struct {
	marshalByReflection
	// the capability
	Capability TPMCap
	// the capability data
	Data tpmuCapabilities `gotpm:"tag=Capability"`
}

// TPMSClockInfo represents a TPMS_CLOCK_INFO.
// See definition in Part 2: Structures, section 10.11.1.
type TPMSClockInfo struct {
	marshalByReflection
	// time value in milliseconds that advances while the TPM is powered
	Clock uint64
	// number of occurrences of TPM Reset since the last TPM2_Clear()
	ResetCount uint32
	// number of times that TPM2_Shutdown() or _TPM_Hash_Start have
	// occurred since the last TPM Reset or TPM2_Clear().
	RestartCount uint32
	// no value of Clock greater than the current value of Clock has been
	// previously reported by the TPM. Set to YES on TPM2_Clear().
	Safe TPMIYesNo
}

// TPMSTimeInfo represents a TPMS_TIMEzINFO.
// See definition in Part 2: Structures, section 10.11.6.
type TPMSTimeInfo struct {
	marshalByReflection
	// time in milliseconds since the TIme circuit was last reset
	Time uint64
	// a structure containing the clock information
	ClockInfo TPMSClockInfo
}

// TPMSTimeAttestInfo represents a TPMS_TIME_ATTEST_INFO.
// See definition in Part 2: Structures, section 10.12.2.
type TPMSTimeAttestInfo struct {
	marshalByReflection
	// the Time, Clock, resetCount, restartCount, and Safe indicator
	Time TPMSTimeInfo
	// a TPM vendor-specific value indicating the version number of the firmware
	FirmwareVersion uint64
}

// TPMSCertifyInfo represents a TPMS_CERTIFY_INFO.
// See definition in Part 2: Structures, section 10.12.3.
type TPMSCertifyInfo struct {
	marshalByReflection
	// Name of the certified object
	Name TPM2BName
	// Qualified Name of the certified object
	QualifiedName TPM2BName
}

// TPMSQuoteInfo represents a TPMS_QUOTE_INFO.
// See definition in Part 2: Structures, section 10.12.4.
type TPMSQuoteInfo struct {
	marshalByReflection
	// information on algID, PCR selected and digest
	PCRSelect TPMLPCRSelection
	// digest of the selected PCR using the hash of the signing key
	PCRDigest TPM2BDigest
}

// TPMSCommandAuditInfo represents a TPMS_COMMAND_AUDIT_INFO.
// See definition in Part 2: Structures, section 10.12.5.
type TPMSCommandAuditInfo struct {
	marshalByReflection
	// the monotonic audit counter
	AuditCounter uint64
	// hash algorithm used for the command audit
	DigestAlg TPMAlgID
	// the current value of the audit digest
	AuditDigest TPM2BDigest
	// digest of the command codes being audited using digestAlg
	CommandDigest TPM2BDigest
}

// TPMSSessionAuditInfo represents a TPMS_SESSION_AUDIT_INFO.
// See definition in Part 2: Structures, section 10.12.6.
type TPMSSessionAuditInfo struct {
	marshalByReflection
	// current exclusive status of the session
	ExclusiveSession TPMIYesNo
	// the current value of the session audit digest
	SessionDigest TPM2BDigest
}

// TPMSCreationInfo represents a TPMS_CREATION_INFO.
// See definition in Part 2: Structures, section 10.12.7.
type TPMSCreationInfo struct {
	marshalByReflection
	// Name of the object
	ObjectName TPM2BName
	// creationHash
	CreationHash TPM2BDigest
}

// TPMSNVCertifyInfo represents a TPMS_NV_CERTIFY_INFO.
// See definition in Part 2: Structures, section 10.12.8.
type TPMSNVCertifyInfo struct {
	marshalByReflection
	// Name of the NV Index
	IndexName TPM2BName
	// the offset parameter of TPM2_NV_Certify()
	Offset uint16
	// contents of the NV Index
	NVContents TPM2BData
}

// TPMSNVDigestCertifyInfo represents a TPMS_NV_DIGEST_CERTIFY_INFO.
// See definition in Part 2: Structures, section 10.12.9.
type TPMSNVDigestCertifyInfo struct {
	marshalByReflection
	// Name of the NV Index
	IndexName TPM2BName
	// hash of the contents of the index
	NVDigest TPM2BDigest
}

// TPMISTAttest represents a TPMI_ST_ATTEST.
// See definition in Part 2: Structures, section 10.12.10.
type TPMISTAttest = TPMST

type tpmuAttest struct {
	selector TPMST
	contents Marshallable
}

type attestContents interface {
	Marshallable
	*TPMSNVCertifyInfo | *TPMSCommandAuditInfo | *TPMSSessionAuditInfo | *TPMSCertifyInfo |
		*TPMSQuoteInfo | *TPMSTimeAttestInfo | *TPMSCreationInfo | *TPMSNVDigestCertifyInfo
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuAttest) create(hint int64) (reflect.Value, error) {
	switch TPMST(hint) {
	case TPMSTAttestNV:
		contents := TPMSNVCertifyInfo{}
		u.contents = &contents
		u.selector = TPMST(hint)
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestCommandAudit:
		contents := TPMSCommandAuditInfo{}
		u.contents = &contents
		u.selector = TPMST(hint)
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestSessionAudit:
		contents := TPMSSessionAuditInfo{}
		u.contents = &contents
		u.selector = TPMST(hint)
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestCertify:
		contents := TPMSCertifyInfo{}
		u.contents = &contents
		u.selector = TPMST(hint)
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestQuote:
		contents := TPMSQuoteInfo{}
		u.contents = &contents
		u.selector = TPMST(hint)
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestTime:
		contents := TPMSTimeAttestInfo{}
		u.contents = &contents
		u.selector = TPMST(hint)
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestCreation:
		contents := TPMSCreationInfo{}
		u.contents = &contents
		u.selector = TPMST(hint)
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestNVDigest:
		contents := TPMSNVDigestCertifyInfo{}
		u.contents = &contents
		u.selector = TPMST(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuAttest) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMST(hint) {
	case TPMSTAttestNV:
		contents := TPMSNVCertifyInfo{}
		if u.contents != nil {
			contents = *u.contents.(*TPMSNVCertifyInfo)
		}
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestCommandAudit:
		contents := TPMSCommandAuditInfo{}
		if u.contents != nil {
			contents = *u.contents.(*TPMSCommandAuditInfo)
		}
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestSessionAudit:
		contents := TPMSSessionAuditInfo{}
		if u.contents != nil {
			contents = *u.contents.(*TPMSSessionAuditInfo)
		}
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestCertify:
		contents := TPMSCertifyInfo{}
		if u.contents != nil {
			contents = *u.contents.(*TPMSCertifyInfo)
		}
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestQuote:
		contents := TPMSQuoteInfo{}
		if u.contents != nil {
			contents = *u.contents.(*TPMSQuoteInfo)
		}
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestTime:
		contents := TPMSTimeAttestInfo{}
		if u.contents != nil {
			contents = *u.contents.(*TPMSTimeAttestInfo)
		}
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestCreation:
		contents := TPMSCreationInfo{}
		if u.contents != nil {
			contents = *u.contents.(*TPMSCreationInfo)
		}
		return reflect.ValueOf(&contents), nil
	case TPMSTAttestNVDigest:
		contents := TPMSNVDigestCertifyInfo{}
		if u.contents != nil {
			contents = *u.contents.(*TPMSNVDigestCertifyInfo)
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUAttest represents a TPMU_ATTEST.
// See definition in Part 2: Structures, section 10.12.11.
func TPMUAttest[C attestContents](selector TPMST, contents C) tpmuAttest {
	return tpmuAttest{
		selector: selector,
		contents: contents,
	}
}

// Certify returns the 'certify' member of the union.
func (u *tpmuAttest) Certify() maybe[TPMSCertifyInfo] {
	if u.selector == TPMSTAttestCertify {
		return asMaybe(u.contents.(*TPMSCertifyInfo))
	}
	return maybeNot[TPMSCertifyInfo](fmt.Errorf("did not contain certify (selector value was %v)", u.selector))
}

// Creation returns the 'creation' member of the union.
func (u *tpmuAttest) Creation() maybe[TPMSCreationInfo] {
	if u.selector == TPMSTAttestCreation {
		return asMaybe(u.contents.(*TPMSCreationInfo))
	}
	return maybeNot[TPMSCreationInfo](fmt.Errorf("did not contain creation (selector value was %v)", u.selector))
}

// Quote returns the 'quote' member of the union.
func (u *tpmuAttest) Quote() maybe[TPMSQuoteInfo] {
	if u.selector == TPMSTAttestQuote {
		return asMaybe(u.contents.(*TPMSQuoteInfo))
	}
	return maybeNot[TPMSQuoteInfo](fmt.Errorf("did not contain quote (selector value was %v)", u.selector))
}

// CommandAudit returns the 'commandAudit' member of the union.
func (u *tpmuAttest) CommandAudit() maybe[TPMSCommandAuditInfo] {
	if u.selector == TPMSTAttestCommandAudit {
		return asMaybe(u.contents.(*TPMSCommandAuditInfo))
	}
	return maybeNot[TPMSCommandAuditInfo](fmt.Errorf("did not contain commandAudit (selector value was %v)", u.selector))
}

// SessionAudit returns the 'sessionAudit' member of the union.
func (u *tpmuAttest) SessionAudit() maybe[TPMSSessionAuditInfo] {
	if u.selector == TPMSTAttestSessionAudit {
		return asMaybe(u.contents.(*TPMSSessionAuditInfo))
	}
	return maybeNot[TPMSSessionAuditInfo](fmt.Errorf("did not contain sessionAudit (selector value was %v)", u.selector))
}

// Time returns the 'time' member of the union.
func (u *tpmuAttest) Time() maybe[TPMSTimeAttestInfo] {
	if u.selector == TPMSTAttestTime {
		return asMaybe(u.contents.(*TPMSTimeAttestInfo))
	}
	return maybeNot[TPMSTimeAttestInfo](fmt.Errorf("did not contain time (selector value was %v)", u.selector))
}

// NV returns the 'nv' member of the union.
func (u *tpmuAttest) NV() maybe[TPMSNVCertifyInfo] {
	if u.selector == TPMSTAttestNV {
		return asMaybe(u.contents.(*TPMSNVCertifyInfo))
	}
	return maybeNot[TPMSNVCertifyInfo](fmt.Errorf("did not contain nv (selector value was %v)", u.selector))
}

// NVDigest returns the 'nvDigest' member of the union.
func (u *tpmuAttest) NVDigest() maybe[TPMSNVDigestCertifyInfo] {
	if u.selector == TPMSTAttestNVDigest {
		return asMaybe(u.contents.(*TPMSNVDigestCertifyInfo))
	}
	return maybeNot[TPMSNVDigestCertifyInfo](fmt.Errorf("did not contain nvDigest (selector value was %v)", u.selector))
}

// TPMSAttest represents a TPMS_ATTEST.
// See definition in Part 2: Structures, section 10.12.12.
type TPMSAttest struct {
	marshalByReflection
	// the indication that this structure was created by a TPM (always TPM_GENERATED_VALUE)
	Magic TPMGenerated `gotpm:"check"`
	// type of the attestation structure
	Type TPMISTAttest
	// Qualified Name of the signing key
	QualifiedSigner TPM2BName
	// external information supplied by caller
	ExtraData TPM2BData
	// Clock, resetCount, restartCount, and Safe
	ClockInfo TPMSClockInfo
	// TPM-vendor-specific value identifying the version number of the firmware
	FirmwareVersion uint64
	// the type-specific attestation information
	Attested tpmuAttest `gotpm:"tag=Type"`
}

type tpm2bAttest = tpm2b[TPMSAttest]

// TPM2BAttest represents a TPM2B_ATTEST.
// See definition in Part 2: Structures, section 10.12.13.
// Note that in the spec, this is just a 2B_DATA with enough room for an S_ATTEST.
// For ergonomics, we pretend that TPM2B_Attest wraps a TPMS_Attest just like other 2Bs.
func TPM2BAttest[C bytesOr[TPMSAttest]](contents C) tpm2bAttest {
	return tpm2bHelper[TPMSAttest](contents)
}

// TPMSAuthCommand represents a TPMS_AUTH_COMMAND.
// See definition in Part 2: Structures, section 10.13.2.
type TPMSAuthCommand struct {
	marshalByReflection
	Handle        TPMISHAuthSession
	Nonce         TPM2BNonce
	Attributes    TPMASession
	Authorization TPM2BData
}

// TPMSAuthResponse represents a TPMS_AUTH_RESPONSE.
// See definition in Part 2: Structures, section 10.13.3.
type TPMSAuthResponse struct {
	marshalByReflection
	Nonce         TPM2BNonce
	Attributes    TPMASession
	Authorization TPM2BData
}

type tpmuSymKeyBits struct {
	selector TPMAlgID
	contents Marshallable
}

type symKeyBitsContents interface {
	TPMKeyBits | TPMAlgID
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuSymKeyBits) create(hint int64) (reflect.Value, error) {
	switch TPMAlgID(hint) {
	case TPMAlgAES:
		var contents boxed[TPMKeyBits]
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgXOR:
		var contents boxed[TPMAlgID]
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuSymKeyBits) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMAlgID(hint) {
	case TPMAlgAES:
		var contents boxed[TPMKeyBits]
		if u.contents != nil {
			contents = *u.contents.(*boxed[TPMKeyBits])
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgXOR:
		var contents boxed[TPMAlgID]
		if u.contents != nil {
			contents = *u.contents.(*boxed[TPMAlgID])
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUSymKeyBits represents a TPMU_SYM_KEY_BITS.
// See definition in Part 2: Structures, section 11.1.3.
func TPMUSymKeyBits[C symKeyBitsContents](selector TPMAlgID, contents C) tpmuSymKeyBits {
	boxed := box(&contents)
	return tpmuSymKeyBits{
		selector: selector,
		contents: &boxed,
	}
}

// AES returns the 'aes' member of the union.
func (u *tpmuSymKeyBits) AES() maybe[TPMKeyBits] {
	if u.selector == TPMAlgAES {
		value := u.contents.(*boxed[TPMKeyBits]).unbox()
		return asMaybe(value)
	}
	return maybeNot[TPMKeyBits](fmt.Errorf("did not contain aes (selector value was %v)", u.selector))
}

// XOR returns the 'xor' member of the union.
func (u *tpmuSymKeyBits) XOR() maybe[TPMAlgID] {
	if u.selector == TPMAlgXOR {
		value := u.contents.(*boxed[TPMAlgID]).unbox()
		return asMaybe(value)
	}
	return maybeNot[TPMAlgID](fmt.Errorf("did not contain xor (selector value was %v)", u.selector))
}

type tpmuSymMode struct {
	selector TPMAlgID
	contents Marshallable
}

type symModeContents interface {
	TPMIAlgSymMode | TPMSEmpty
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuSymMode) create(hint int64) (reflect.Value, error) {
	switch TPMAlgID(hint) {
	case TPMAlgAES:
		var contents boxed[TPMAlgID]
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgXOR:
		var contents boxed[TPMSEmpty]
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuSymMode) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMAlgID(hint) {
	case TPMAlgAES:
		var contents boxed[TPMAlgID]
		if u.contents != nil {
			contents = *u.contents.(*boxed[TPMAlgID])
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgXOR:
		var contents boxed[TPMSEmpty]
		if u.contents != nil {
			contents = *u.contents.(*boxed[TPMSEmpty])
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUSymMode represents a TPMU_SYM_MODE.
// See definition in Part 2: Structures, section 11.1.4.
func TPMUSymMode[C symModeContents](selector TPMAlgID, contents C) tpmuSymMode {
	boxed := box(&contents)
	return tpmuSymMode{
		selector: selector,
		contents: &boxed,
	}
}

// AES returns the 'aes' member of the union.
func (u *tpmuSymMode) AES() maybe[TPMIAlgSymMode] {
	if u.selector == TPMAlgAES {
		value := u.contents.(*boxed[TPMIAlgSymMode]).unbox()
		return asMaybe(value)
	}
	return maybeNot[TPMIAlgSymMode](fmt.Errorf("did not contain aes (selector value was %v)", u.selector))
}

type tpmuSymDetails struct {
	selector TPMAlgID
	contents Marshallable
}

type symDetailsContents interface {
	TPMSEmpty
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuSymDetails) create(hint int64) (reflect.Value, error) {
	switch TPMAlgID(hint) {
	case TPMAlgAES:
		var contents boxed[TPMSEmpty]
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgXOR:
		var contents boxed[TPMSEmpty]
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuSymDetails) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMAlgID(hint) {
	case TPMAlgAES, TPMAlgXOR:
		var contents boxed[TPMSEmpty]
		if u.contents != nil {
			contents = *u.contents.(*boxed[TPMSEmpty])
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUSymDetails represents a TPMU_SYM_DETAILS.
// See definition in Part 2: Structures, section 11.1.5.
func TPMUSymDetails[C symDetailsContents](selector TPMAlgID, contents C) tpmuSymMode {
	boxed := box(&contents)
	return tpmuSymMode{
		selector: selector,
		contents: &boxed,
	}
}

// TPMTSymDef represents a TPMT_SYM_DEF.
// See definition in Part 2: Structures, section 11.1.6.
type TPMTSymDef struct {
	marshalByReflection
	// indicates a symmetric algorithm
	Algorithm TPMIAlgSym `gotpm:"nullable"`
	// the key size
	KeyBits tpmuSymKeyBits `gotpm:"tag=Algorithm"`
	// the mode for the key
	Mode tpmuSymMode `gotpm:"tag=Algorithm"`
	// contains the additional algorithm details
	Details tpmuSymDetails `gotpm:"tag=Algorithm"`
}

// TPMTSymDefObject represents a TPMT_SYM_DEF_OBJECT.
// See definition in Part 2: Structures, section 11.1.7.
type TPMTSymDefObject struct {
	marshalByReflection
	// selects a symmetric block cipher
	// When used in the parameter area of a parent object, this shall
	// be a supported block cipher and not TPM_ALG_NULL
	Algorithm TPMIAlgSymObject `gotpm:"nullable"`
	// the key size
	KeyBits tpmuSymKeyBits `gotpm:"tag=Algorithm"`
	// default mode
	// When used in the parameter area of a parent object, this shall
	// be TPM_ALG_CFB.
	Mode tpmuSymMode `gotpm:"tag=Algorithm"`
	// contains the additional algorithm details, if any
	Details tpmuSymDetails `gotpm:"tag=Algorithm"`
}

// TPM2BSymKey represents a TPM2B_SYM_KEY.
// See definition in Part 2: Structures, section 11.1.8.
type TPM2BSymKey TPM2BData

// TPMSSymCipherParms represents a TPMS_SYMCIPHER_PARMS.
// See definition in Part 2: Structures, section 11.1.9.
type TPMSSymCipherParms struct {
	marshalByReflection
	// a symmetric block cipher
	Sym TPMTSymDefObject
}

// TPM2BLabel represents a TPM2B_LABEL.
// See definition in Part 2: Structures, section 11.1.10.
type TPM2BLabel TPM2BData

// TPMSDerive represents a TPMS_DERIVE.
// See definition in Part 2: Structures, section 11.1.11.
type TPMSDerive struct {
	marshalByReflection
	Label   TPM2BLabel
	Context TPM2BLabel
}

type tpm2bDerive = tpm2b[TPMSDerive]

// TPM2BDerive represents a TPM2B_DERIVE.
// See definition in Part 2: Structures, section 11.1.12.
func TPM2BDerive[C bytesOr[TPMSDerive]](contents C) tpm2bDerive {
	return tpm2bHelper[TPMSDerive](contents)
}

type tpmuSensitiveCreate struct {
	contents Marshallable
}

type sensitiveCreateContents interface {
	Marshallable
	*tpm2bDerive | *TPM2BSensitiveData
}

// marshal implements the Marshallable interface.
func (u *tpmuSensitiveCreate) marshal(buf *bytes.Buffer) {
	if u.contents != nil {
		buf.Write(Marshal(u.contents))
	} else {
		// If this is a zero-valued structure, marshal a default TPM2BSensitiveData.
		var defaultValue TPM2BSensitiveData
		buf.Write(Marshal(&defaultValue))
	}
}

// TPMUSensitiveCreate represents a TPMU_SENSITIVE_CREATE.
// See definition in Part 2: Structures, section 11.1.13.
func TPMUSensitiveCreate[C sensitiveCreateContents](contents C) tpmuSensitiveCreate {
	return tpmuSensitiveCreate{contents: contents}
}

// TPM2BSensitiveData represents a TPM2B_SENSITIVE_DATA.
// See definition in Part 2: Structures, section 11.1.14.
type TPM2BSensitiveData TPM2BData

// TPMSSensitiveCreate represents a TPMS_SENSITIVE_CREATE.
// See definition in Part 2: Structures, section 11.1.15.
type TPMSSensitiveCreate struct {
	marshalByReflection
	// the USER auth secret value.
	UserAuth TPM2BAuth
	// data to be sealed, a key, or derivation values.
	Data tpmuSensitiveCreate
}

// This is a structure instead of an alias to tpm2b[TPMSSensitiveCreate],
// see the implementation of marshal below.
type tpm2bSensitiveCreate struct {
	contents *tpm2b[TPMSSensitiveCreate]
}

// TPM2BSensitiveCreate represents a TPM2B_SENSITIVE_CREATE.
// See definition in Part 2: Structures, section 11.1.16.
func TPM2BSensitiveCreate[C bytesOr[TPMSSensitiveCreate]](contents C) tpm2bSensitiveCreate {
	data := tpm2bHelper[TPMSSensitiveCreate](contents)
	return tpm2bSensitiveCreate{
		contents: &data,
	}
}

// Quirk: When this structure is omitted, we need to marshal
// something better than the default [0x00, 0x00] (an empty 2B).
// This is because this actually needs to contain a small
// structure containing some empty values.
func (c *tpm2bSensitiveCreate) marshal(buf *bytes.Buffer) {
	if c.contents != nil {
		buf.Write(Marshal(c.contents))
	} else {
		// If no value was provided (i.e., this is a zero-valued structure),
		// provide an 2B containing a zero-valued TPMS_SensitiveCreate.
		defaultValue := TPM2BSensitiveCreate(&TPMSSensitiveCreate{
			Data: TPMUSensitiveCreate(&TPM2BSensitiveData{}),
		})
		defaultValue.marshal(buf)
	}
}

// TPMSSchemeHash represents a TPMS_SCHEME_HASH.
// See definition in Part 2: Structures, section 11.1.17.
type TPMSSchemeHash struct {
	marshalByReflection
	// the hash algorithm used to digest the message
	HashAlg TPMIAlgHash
}

// TPMSSchemeECDAA represents a TPMS_SCHEME_ECDAA.
// See definition in Part 2: Structures, section 11.1.18.
type TPMSSchemeECDAA struct {
	marshalByReflection
	// the hash algorithm used to digest the message
	HashAlg TPMIAlgHash
	// the counter value that is used between TPM2_Commit()
	// and the sign operation
	Count uint16
}

// TPMIAlgKeyedHashScheme represents a TPMI_ALG_KEYEDHASH_SCHEME.
// See definition in Part 2: Structures, section 11.1.19.
type TPMIAlgKeyedHashScheme = TPMAlgID

// TPMSSchemeHMAC represents a TPMS_SCHEME_HMAC.
// See definition in Part 2: Structures, section 11.1.20.
type TPMSSchemeHMAC TPMSSchemeHash

// TPMSSchemeXOR represents a TPMS_SCHEME_XOR.
// See definition in Part 2: Structures, section 11.1.21.
type TPMSSchemeXOR struct {
	marshalByReflection
	// the hash algorithm used to digest the message
	HashAlg TPMIAlgHash
	// the key derivation function
	KDF TPMIAlgKDF
}

type tpmuSchemeKeyedHash struct {
	selector TPMAlgID
	contents Marshallable
}

type schemeKeyedHashContents interface {
	Marshallable
	*TPMSSchemeHMAC | *TPMSSchemeXOR
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuSchemeKeyedHash) create(hint int64) (reflect.Value, error) {
	switch TPMAlgID(hint) {
	case TPMAlgHMAC:
		var contents TPMSSchemeHMAC
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgXOR:
		var contents TPMSSchemeXOR
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuSchemeKeyedHash) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMAlgID(hint) {
	case TPMAlgHMAC:
		var contents TPMSSchemeHMAC
		if u.contents != nil {
			contents = *u.contents.(*TPMSSchemeHMAC)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgXOR:
		var contents TPMSSchemeXOR
		if u.contents != nil {
			contents = *u.contents.(*TPMSSchemeXOR)
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUSchemeKeyedHash represents a TPMU_SCHEME_KEYEDHASH.
// See definition in Part 2: Structures, section 11.1.22.
func TPMUSchemeKeyedHash[C schemeKeyedHashContents](selector TPMAlgID, contents C) tpmuSchemeKeyedHash {
	return tpmuSchemeKeyedHash{
		selector: selector,
		contents: contents,
	}
}

// HMAC returns the 'hmac' member of the union.
func (u *tpmuSchemeKeyedHash) HMAC() maybe[TPMSSchemeHMAC] {
	if u.selector == TPMAlgHMAC {
		value := u.contents.(*TPMSSchemeHMAC)
		return asMaybe(value)
	}
	return maybeNot[TPMSSchemeHMAC](fmt.Errorf("did not contain hmac (selector value was %v)", u.selector))
}

// XOR returns the 'xor' member of the union.
func (u *tpmuSchemeKeyedHash) XOR() maybe[TPMSSchemeXOR] {
	if u.selector == TPMAlgXOR {
		value := u.contents.(*TPMSSchemeXOR)
		return asMaybe(value)
	}
	return maybeNot[TPMSSchemeXOR](fmt.Errorf("did not contain xor (selector value was %v)", u.selector))
}

// TPMTKeyedHashScheme represents a TPMT_KEYEDHASH_SCHEME.
// See definition in Part 2: Structures, section 11.1.23.
type TPMTKeyedHashScheme struct {
	marshalByReflection
	Scheme  TPMIAlgKeyedHashScheme `gotpm:"nullable"`
	Details tpmuSchemeKeyedHash    `gotpm:"tag=Scheme"`
}

// TPMSSigSchemeRSASSA represents a TPMS_SIG_SCHEME_RSASSA.
// See definition in Part 2: Structures, section 11.2.1.2.
type TPMSSigSchemeRSASSA TPMSSchemeHash

// TPMSSigSchemeRSAPSS represents a TPMS_SIG_SCHEME_RSAPSS.
// See definition in Part 2: Structures, section 11.2.1.2.
type TPMSSigSchemeRSAPSS TPMSSchemeHash

// TPMSSigSchemeECDSA represents a TPMS_SIG_SCHEME_ECDSA.
// See definition in Part 2: Structures, section 11.2.1.3.
type TPMSSigSchemeECDSA TPMSSchemeHash

type tpmuSigScheme struct {
	selector TPMAlgID
	contents Marshallable
}

type sigSchemeContents interface {
	Marshallable
	*TPMSSchemeHMAC | *TPMSSchemeHash | *TPMSSchemeECDAA
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuSigScheme) create(hint int64) (reflect.Value, error) {
	switch TPMAlgID(hint) {
	case TPMAlgHMAC:
		var contents TPMSSchemeHMAC
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgRSASSA, TPMAlgRSAPSS, TPMAlgECDSA:
		var contents TPMSSchemeHash
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgECDAA:
		var contents TPMSSchemeECDAA
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuSigScheme) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMAlgID(hint) {
	case TPMAlgHMAC:
		var contents TPMSSchemeHMAC
		if u.contents != nil {
			contents = *u.contents.(*TPMSSchemeHMAC)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgRSASSA, TPMAlgRSAPSS, TPMAlgECDSA:
		var contents TPMSSchemeHash
		if u.contents != nil {
			contents = *u.contents.(*TPMSSchemeHash)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgECDAA:
		var contents TPMSSchemeECDAA
		if u.contents != nil {
			contents = *u.contents.(*TPMSSchemeECDAA)
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUSigScheme represents a TPMU_SIG_SCHEME.
// See definition in Part 2: Structures, section 11.2.1.4.
func TPMUSigScheme[C sigSchemeContents](selector TPMAlgID, contents C) tpmuSigScheme {
	return tpmuSigScheme{
		selector: selector,
		contents: contents,
	}
}

// HMAC returns the 'hmac' member of the union.
func (u *tpmuSigScheme) HMAC() maybe[TPMSSchemeHMAC] {
	if u.selector == TPMAlgHMAC {
		return asMaybe(u.contents.(*TPMSSchemeHMAC))
	}
	return maybeNot[TPMSSchemeHMAC](fmt.Errorf("did not contain hmac (selector value was %v)", u.selector))
}

// RSASSA returns the 'rsassa' member of the union.
func (u *tpmuSigScheme) RSASSA() maybe[TPMSSchemeHash] {
	if u.selector == TPMAlgRSASSA {
		return asMaybe(u.contents.(*TPMSSchemeHash))
	}
	return maybeNot[TPMSSchemeHash](fmt.Errorf("did not contain rsassa (selector value was %v)", u.selector))
}

// RSAPSS returns the 'rsapss' member of the union.
func (u *tpmuSigScheme) RSAPSS() maybe[TPMSSchemeHash] {
	if u.selector == TPMAlgRSAPSS {
		return asMaybe(u.contents.(*TPMSSchemeHash))
	}
	return maybeNot[TPMSSchemeHash](fmt.Errorf("did not contain rsapss (selector value was %v)", u.selector))
}

// ECDSA returns the 'ecdsa' member of the union.
func (u *tpmuSigScheme) ECDSA() maybe[TPMSSchemeHash] {
	if u.selector == TPMAlgECDSA {
		return asMaybe(u.contents.(*TPMSSchemeHash))
	}
	return maybeNot[TPMSSchemeHash](fmt.Errorf("did not contain ecdsa (selector value was %v)", u.selector))
}

// ECDAA returns the 'ecdaa' member of the union.
func (u *tpmuSigScheme) ECDAA() maybe[TPMSSchemeECDAA] {
	if u.selector == TPMAlgECDAA {
		return asMaybe(u.contents.(*TPMSSchemeECDAA))
	}
	return maybeNot[TPMSSchemeECDAA](fmt.Errorf("did not contain ecdaa (selector value was %v)", u.selector))
}

// TPMTSigScheme represents a TPMT_SIG_SCHEME.
// See definition in Part 2: Structures, section 11.2.1.5.
type TPMTSigScheme struct {
	marshalByReflection
	Scheme  TPMIAlgSigScheme `gotpm:"nullable"`
	Details tpmuSigScheme    `gotpm:"tag=Scheme"`
}

// TPMSEncSchemeRSAES represents a TPMS_ENC_SCHEME_RSAES.
// See definition in Part 2: Structures, section 11.2.2.2.
type TPMSEncSchemeRSAES TPMSEmpty

// TPMSEncSchemeOAEP represents a TPMS_ENC_SCHEME_OAEP.
// See definition in Part 2: Structures, section 11.2.2.2.
type TPMSEncSchemeOAEP TPMSSchemeHash

// TPMSKeySchemeECDH represents a TPMS_KEY_SCHEME_ECDH.
// See definition in Part 2: Structures, section 11.2.2.3.
type TPMSKeySchemeECDH TPMSSchemeHash

// TPMSKDFSchemeMGF1 represents a TPMS_KDF_SCHEME_MGF1.
// See definition in Part 2: Structures, section 11.2.3.1.
type TPMSKDFSchemeMGF1 TPMSSchemeHash

// TPMSKDFSchemeECDH represents a TPMS_KDF_SCHEME_ECDH.
// See definition in Part 2: Structures, section 11.2.3.1.
type TPMSKDFSchemeECDH TPMSSchemeHash

// TPMSKDFSchemeKDF1SP80056A represents a TPMS_KDF_SCHEME_KDF1SP80056A.
// See definition in Part 2: Structures, section 11.2.3.1.
type TPMSKDFSchemeKDF1SP80056A TPMSSchemeHash

// TPMSKDFSchemeKDF2 represents a TPMS_KDF_SCHEME_KDF2.
// See definition in Part 2: Structures, section 11.2.3.1.
type TPMSKDFSchemeKDF2 TPMSSchemeHash

// TPMSKDFSchemeKDF1SP800108 represents a TPMS_KDF_SCHEME_KDF1SP800108.
// See definition in Part 2: Structures, section 11.2.3.1.
type TPMSKDFSchemeKDF1SP800108 TPMSSchemeHash

type tpmuKDFScheme struct {
	selector TPMAlgID
	contents Marshallable
}

type kdfSchemeContents interface {
	Marshallable
	*TPMSKDFSchemeMGF1 | *TPMSKDFSchemeECDH | *TPMSKDFSchemeKDF1SP80056A |
		*TPMSKDFSchemeKDF2 | *TPMSKDFSchemeKDF1SP800108
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuKDFScheme) create(hint int64) (reflect.Value, error) {
	switch TPMAlgID(hint) {
	case TPMAlgMGF1:
		var contents TPMSKDFSchemeMGF1
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgECDH:
		var contents TPMSKDFSchemeECDH
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgKDF1SP80056A:
		var contents TPMSKDFSchemeKDF1SP80056A
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgKDF2:
		var contents TPMSKDFSchemeKDF2
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgKDF1SP800108:
		var contents TPMSKDFSchemeKDF1SP800108
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuKDFScheme) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMAlgID(hint) {
	case TPMAlgMGF1:
		var contents TPMSKDFSchemeMGF1
		if u.contents != nil {
			contents = *u.contents.(*TPMSKDFSchemeMGF1)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgECDH:
		var contents TPMSKDFSchemeECDH
		if u.contents != nil {
			contents = *u.contents.(*TPMSKDFSchemeECDH)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgKDF1SP80056A:
		var contents TPMSKDFSchemeKDF1SP80056A
		if u.contents != nil {
			contents = *u.contents.(*TPMSKDFSchemeKDF1SP80056A)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgKDF2:
		var contents TPMSKDFSchemeKDF2
		if u.contents != nil {
			contents = *u.contents.(*TPMSKDFSchemeKDF2)
		}
		return reflect.ValueOf(&contents), nil

	case TPMAlgKDF1SP800108:
		var contents TPMSKDFSchemeKDF1SP800108
		if u.contents != nil {
			contents = *u.contents.(*TPMSKDFSchemeKDF1SP800108)
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUKDFScheme represents a TPMU_KDF_SCHEME.
// See definition in Part 2: Structures, section 11.2.3.2.
func TPMUKDFScheme[C kdfSchemeContents](selector TPMAlgID, contents C) tpmuKDFScheme {
	return tpmuKDFScheme{
		selector: selector,
		contents: contents,
	}
}

// MGF1 returns the 'mgf1' member of the union.
func (u *tpmuKDFScheme) MGF1() maybe[TPMSKDFSchemeMGF1] {
	if u.selector == TPMAlgMGF1 {
		return asMaybe(u.contents.(*TPMSKDFSchemeMGF1))
	}
	return maybeNot[TPMSKDFSchemeMGF1](fmt.Errorf("did not contain mgf1 (selector value was %v)", u.selector))
}

// MGF1 returns the 'ecdh' member of the union.
func (u *tpmuKDFScheme) ECDH() maybe[TPMSKDFSchemeECDH] {
	if u.selector == TPMAlgECDH {
		return asMaybe(u.contents.(*TPMSKDFSchemeECDH))
	}
	return maybeNot[TPMSKDFSchemeECDH](fmt.Errorf("did not contain ecdh (selector value was %v)", u.selector))
}

// KDF1SP80056A returns the 'kdf1sp80056a' member of the union.
func (u *tpmuKDFScheme) KDF1SP80056A() maybe[TPMSKDFSchemeKDF1SP80056A] {
	if u.selector == TPMAlgMGF1 {
		return asMaybe(u.contents.(*TPMSKDFSchemeKDF1SP80056A))
	}
	return maybeNot[TPMSKDFSchemeKDF1SP80056A](fmt.Errorf("did not contain kdf1sp80056a (selector value was %v)", u.selector))
}

// KDF2 returns the 'kdf2' member of the union.
func (u *tpmuKDFScheme) KDF2() maybe[TPMSKDFSchemeKDF2] {
	if u.selector == TPMAlgMGF1 {
		return asMaybe(u.contents.(*TPMSKDFSchemeKDF2))
	}
	return maybeNot[TPMSKDFSchemeKDF2](fmt.Errorf("did not contain mgf1 (selector value was %v)", u.selector))
}

// KDF1SP800108 returns the 'kdf1sp800108' member of the union.
func (u *tpmuKDFScheme) KDF1SP800108() maybe[TPMSKDFSchemeKDF1SP800108] {
	if u.selector == TPMAlgMGF1 {
		return asMaybe(u.contents.(*TPMSKDFSchemeKDF1SP800108))
	}
	return maybeNot[TPMSKDFSchemeKDF1SP800108](fmt.Errorf("did not contain kdf1sp800108 (selector value was %v)", u.selector))
}

// TPMTKDFScheme represents a TPMT_KDF_SCHEME.
// See definition in Part 2: Structures, section 11.2.3.3.
type TPMTKDFScheme struct {
	marshalByReflection
	// scheme selector
	Scheme TPMIAlgKDF `gotpm:"nullable"`
	// scheme parameters
	Details tpmuKDFScheme `gotpm:"tag=Scheme"`
}

type tpmuAsymScheme struct {
	selector TPMAlgID
	contents Marshallable
}

type asymSchemeContents interface {
	Marshallable
	*TPMSSigSchemeRSASSA | *TPMSEncSchemeRSAES | *TPMSSigSchemeRSAPSS | *TPMSEncSchemeOAEP |
		*TPMSSigSchemeECDSA | *TPMSKeySchemeECDH | *TPMSSchemeECDAA
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuAsymScheme) create(hint int64) (reflect.Value, error) {
	switch TPMAlgID(hint) {
	case TPMAlgRSASSA:
		var contents TPMSSigSchemeRSASSA
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgRSAES:
		var contents TPMSEncSchemeRSAES
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgRSAPSS:
		var contents TPMSSigSchemeRSAPSS
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgOAEP:
		var contents TPMSEncSchemeOAEP
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgECDSA:
		var contents TPMSSigSchemeECDSA
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgECDH:
		var contents TPMSKeySchemeECDH
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgECDAA:
		var contents TPMSSchemeECDAA
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuAsymScheme) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMAlgID(hint) {
	case TPMAlgRSASSA:
		var contents TPMSSigSchemeRSASSA
		if u.contents != nil {
			contents = *u.contents.(*TPMSSigSchemeRSASSA)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgRSAES:
		var contents TPMSEncSchemeRSAES
		if u.contents != nil {
			contents = *u.contents.(*TPMSEncSchemeRSAES)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgRSAPSS:
		var contents TPMSSigSchemeRSAPSS
		if u.contents != nil {
			contents = *u.contents.(*TPMSSigSchemeRSAPSS)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgOAEP:
		var contents TPMSEncSchemeOAEP
		if u.contents != nil {
			contents = *u.contents.(*TPMSEncSchemeOAEP)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgECDSA:
		var contents TPMSSigSchemeECDSA
		if u.contents != nil {
			contents = *u.contents.(*TPMSSigSchemeECDSA)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgECDH:
		var contents TPMSKeySchemeECDH
		if u.contents != nil {
			contents = *u.contents.(*TPMSKeySchemeECDH)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgECDAA:
		var contents TPMSSchemeECDAA
		if u.contents != nil {
			contents = *u.contents.(*TPMSSchemeECDAA)
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUAsymScheme represents a TPMU_ASYM_SCHEME.
// See definition in Part 2: Structures, section 11.2.3.5.
func TPMUAsymScheme[C asymSchemeContents](selector TPMAlgID, contents C) tpmuAsymScheme {
	return tpmuAsymScheme{
		selector: selector,
		contents: contents,
	}
}

// RSASSA returns the 'rsassa' member of the union.
func (u *tpmuAsymScheme) RSASSA() maybe[TPMSSigSchemeRSASSA] {
	if u.selector == TPMAlgRSASSA {
		return asMaybe(u.contents.(*TPMSSigSchemeRSASSA))
	}
	return maybeNot[TPMSSigSchemeRSASSA](fmt.Errorf("did not contain rsassa (selector value was %v)", u.selector))
}

// RSAES returns the 'rsaes' member of the union.
func (u *tpmuAsymScheme) RSAES() maybe[TPMSEncSchemeRSAES] {
	if u.selector == TPMAlgRSAES {
		return asMaybe(u.contents.(*TPMSEncSchemeRSAES))
	}
	return maybeNot[TPMSEncSchemeRSAES](fmt.Errorf("did not contain rsaes (selector value was %v)", u.selector))
}

// RSAPSS returns the 'rsapss' member of the union.
func (u *tpmuAsymScheme) RSAPSS() maybe[TPMSSigSchemeRSAPSS] {
	if u.selector == TPMAlgRSAPSS {
		return asMaybe(u.contents.(*TPMSSigSchemeRSAPSS))
	}
	return maybeNot[TPMSSigSchemeRSAPSS](fmt.Errorf("did not contain rsapss (selector value was %v)", u.selector))
}

// OAEP returns the 'oaep' member of the union.
func (u *tpmuAsymScheme) OAEP() maybe[TPMSEncSchemeOAEP] {
	if u.selector == TPMAlgOAEP {
		return asMaybe(u.contents.(*TPMSEncSchemeOAEP))
	}
	return maybeNot[TPMSEncSchemeOAEP](fmt.Errorf("did not contain oaep (selector value was %v)", u.selector))
}

// ECDSA returns the 'ecdsa' member of the union.
func (u *tpmuAsymScheme) ECDSA() maybe[TPMSSigSchemeECDSA] {
	if u.selector == TPMAlgECDSA {
		return asMaybe(u.contents.(*TPMSSigSchemeECDSA))
	}
	return maybeNot[TPMSSigSchemeECDSA](fmt.Errorf("did not contain rsassa (selector value was %v)", u.selector))
}

// ECDH returns the 'ecdh' member of the union.
func (u *tpmuAsymScheme) ECDH() maybe[TPMSKeySchemeECDH] {
	if u.selector == TPMAlgRSASSA {
		return asMaybe(u.contents.(*TPMSKeySchemeECDH))
	}
	return maybeNot[TPMSKeySchemeECDH](fmt.Errorf("did not contain ecdh (selector value was %v)", u.selector))
}

// ECDAA returns the 'ecdaa' member of the union.
func (u *tpmuAsymScheme) ECDAA() maybe[TPMSSchemeECDAA] {
	if u.selector == TPMAlgECDAA {
		return asMaybe(u.contents.(*TPMSSchemeECDAA))
	}
	return maybeNot[TPMSSchemeECDAA](fmt.Errorf("did not contain rsassa (selector value was %v)", u.selector))
}

// TPMIAlgRSAScheme represents a TPMI_ALG_RSA_SCHEME.
// See definition in Part 2: Structures, section 11.2.4.1.
type TPMIAlgRSAScheme = TPMAlgID

// TPMTRSAScheme represents a TPMT_RSA_SCHEME.
// See definition in Part 2: Structures, section 11.2.4.2.
type TPMTRSAScheme struct {
	marshalByReflection
	// scheme selector
	Scheme TPMIAlgRSAScheme `gotpm:"nullable"`
	// scheme parameters
	Details tpmuAsymScheme `gotpm:"tag=Scheme"`
}

// TPM2BPublicKeyRSA represents a TPM2B_PUBLIC_KEY_RSA.
// See definition in Part 2: Structures, section 11.2.4.5.
type TPM2BPublicKeyRSA TPM2BData

// TPMIRSAKeyBits represents a TPMI_RSA_KEY_BITS.
// See definition in Part 2: Structures, section 11.2.4.6.
type TPMIRSAKeyBits = TPMKeyBits

// TPM2BPrivateKeyRSA representsa a TPM2B_PRIVATE_KEY_RSA.
// See definition in Part 2: Structures, section 11.2.4.7.
type TPM2BPrivateKeyRSA TPM2BData

// TPM2BECCParameter represents a TPM2B_ECC_PARAMETER.
// See definition in Part 2: Structures, section 11.2.5.1.
type TPM2BECCParameter TPM2BData

// TPMSECCPoint represents a TPMS_ECC_POINT.
// See definition in Part 2: Structures, section 11.2.5.2.
type TPMSECCPoint struct {
	marshalByReflection
	// X coordinate
	X TPM2BECCParameter
	// Y coordinate
	Y TPM2BECCParameter
}

type tpm2bECCPoint = tpm2b[TPMSECCPoint]

// TPM2BECCPoint represents a TPM2B_ECC_POINT.
// See definition in Part 2: Structures, section 11.2.5.3.
func TPM2BECCPoint[C bytesOr[TPMSECCPoint]](contents C) tpm2bECCPoint {
	return tpm2bHelper[TPMSECCPoint](contents)
}

// TPMIAlgECCScheme represents a TPMI_ALG_ECC_SCHEME.
// See definition in Part 2: Structures, section 11.2.5.4.
type TPMIAlgECCScheme = TPMAlgID

// TPMIECCCurve represents a TPMI_ECC_CURVE.
// See definition in Part 2: Structures, section 11.2.5.5.
type TPMIECCCurve = TPMECCCurve

// TPMTECCScheme represents a TPMT_ECC_SCHEME.
// See definition in Part 2: Structures, section 11.2.5.6.
type TPMTECCScheme struct {
	marshalByReflection
	// scheme selector
	Scheme TPMIAlgECCScheme `gotpm:"nullable"`
	// scheme parameters
	Details tpmuAsymScheme `gotpm:"tag=Scheme"`
}

// TPMSSignatureRSA represents a TPMS_SIGNATURE_RSA.
// See definition in Part 2: Structures, section 11.3.1.
type TPMSSignatureRSA struct {
	marshalByReflection
	// the hash algorithm used to digest the message
	Hash TPMIAlgHash
	// The signature is the size of a public key.
	Sig TPM2BPublicKeyRSA
}

// TPMSSignatureECC represents a TPMS_SIGNATURE_ECC.
// See definition in Part 2: Structures, section 11.3.2.
type TPMSSignatureECC struct {
	marshalByReflection
	// the hash algorithm used in the signature process
	Hash       TPMIAlgHash
	SignatureR TPM2BECCParameter
	SignatureS TPM2BECCParameter
}

type tpmuSignature struct {
	selector TPMAlgID
	contents Marshallable
}

type signatureContents interface {
	Marshallable
	*TPMTHA | *TPMSSignatureRSA | *TPMSSignatureECC
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuSignature) create(hint int64) (reflect.Value, error) {
	switch TPMAlgID(hint) {
	case TPMAlgHMAC:
		var contents TPMTHA
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgRSASSA, TPMAlgRSAPSS:
		var contents TPMSSignatureRSA
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgECDSA, TPMAlgECDAA:
		var contents TPMSSignatureECC
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuSignature) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMAlgID(hint) {
	case TPMAlgHMAC:
		var contents TPMTHA
		if u.contents != nil {
			contents = *u.contents.(*TPMTHA)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgRSASSA, TPMAlgRSAPSS:
		var contents TPMSSignatureRSA
		if u.contents != nil {
			contents = *u.contents.(*TPMSSignatureRSA)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgECDSA, TPMAlgECDAA:
		var contents TPMSSignatureECC
		if u.contents != nil {
			contents = *u.contents.(*TPMSSignatureECC)
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUSignature represents a TPMU_SIGNATURE.
// See definition in Part 2: Structures, section 11.3.3.
func TPMUSignature[C signatureContents](selector TPMAlgID, contents C) tpmuSignature {
	return tpmuSignature{
		selector: selector,
		contents: contents,
	}
}

// HMAC returns the 'hmac' member of the union.
func (u *tpmuSignature) HMAC() maybe[TPMTHA] {
	if u.selector == TPMAlgHMAC {
		return asMaybe(u.contents.(*TPMTHA))
	}
	return maybeNot[TPMTHA](fmt.Errorf("did not contain hmac (selector value was %v)", u.selector))
}

// RSASSA returns the 'rsassa' member of the union.
func (u *tpmuSignature) RSASSA() maybe[TPMSSignatureRSA] {
	if u.selector == TPMAlgRSASSA {
		return asMaybe(u.contents.(*TPMSSignatureRSA))
	}
	return maybeNot[TPMSSignatureRSA](fmt.Errorf("did not contain rsassa (selector value was %v)", u.selector))
}

// RSAPSS returns the 'rsapss' member of the union.
func (u *tpmuSignature) RSAPSS() maybe[TPMSSignatureRSA] {
	if u.selector == TPMAlgRSAPSS {
		return asMaybe(u.contents.(*TPMSSignatureRSA))
	}
	return maybeNot[TPMSSignatureRSA](fmt.Errorf("did not contain rsapss (selector value was %v)", u.selector))
}

// ECDSA returns the 'ecdsa' member of the union.
func (u *tpmuSignature) ECDSA() maybe[TPMSSignatureECC] {
	if u.selector == TPMAlgECDSA {
		return asMaybe(u.contents.(*TPMSSignatureECC))
	}
	return maybeNot[TPMSSignatureECC](fmt.Errorf("did not contain ecdsa (selector value was %v)", u.selector))
}

// ECDAA returns the 'ecdaa' member of the union.
func (u *tpmuSignature) ECDAA() maybe[TPMSSignatureECC] {
	if u.selector == TPMAlgRSASSA {
		return asMaybe(u.contents.(*TPMSSignatureECC))
	}
	return maybeNot[TPMSSignatureECC](fmt.Errorf("did not contain ecdaa (selector value was %v)", u.selector))
}

// TPMTSignature represents a TPMT_SIGNATURE.
// See definition in Part 2: Structures, section 11.3.4.
type TPMTSignature struct {
	marshalByReflection
	// selector of the algorithm used to construct the signature
	SigAlg TPMIAlgSigScheme `gotpm:"nullable"`
	// This shall be the actual signature information.
	Signature tpmuSignature `gotpm:"tag=SigAlg"`
}

// TPM2BEncryptedSecret represents a TPM2B_ENCRYPTED_SECRET.
// See definition in Part 2: Structures, section 11.4.33.
type TPM2BEncryptedSecret TPM2BData

// TPMIAlgPublic represents a TPMI_ALG_PUBLIC.
// See definition in Part 2: Structures, section 12.2.2.
type TPMIAlgPublic = TPMAlgID

type tpmuPublicID struct {
	selector TPMAlgID
	contents Marshallable
}

type publicIDContents interface {
	Marshallable
	*TPM2BDigest | *TPM2BPublicKeyRSA | *TPMSECCPoint
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuPublicID) create(hint int64) (reflect.Value, error) {
	switch TPMAlgID(hint) {
	case TPMAlgKeyedHash:
		var contents TPM2BDigest
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgSymCipher:
		var contents TPM2BDigest
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgRSA:
		var contents TPM2BPublicKeyRSA
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgECC:
		var contents TPMSECCPoint
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuPublicID) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMAlgID(hint) {
	case TPMAlgKeyedHash:
		var contents TPM2BDigest
		if u.contents != nil {
			contents = *u.contents.(*TPM2BDigest)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgSymCipher:
		var contents TPM2BDigest
		if u.contents != nil {
			contents = *u.contents.(*TPM2BDigest)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgRSA:
		var contents TPM2BPublicKeyRSA
		if u.contents != nil {
			contents = *u.contents.(*TPM2BPublicKeyRSA)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgECC:
		var contents TPMSECCPoint
		if u.contents != nil {
			contents = *u.contents.(*TPMSECCPoint)
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUPublicID represents a TPMU_PUBLIC_ID.
// See definition in Part 2: Structures, section 12.2.3.2.
func TPMUPublicID[C publicIDContents](selector TPMAlgID, contents C) tpmuPublicID {
	return tpmuPublicID{
		selector: selector,
		contents: contents,
	}
}

// KeyedHash returns the 'keyedHash' member of the union.
func (u *tpmuPublicID) KeyedHash() maybe[TPM2BDigest] {
	if u.selector == TPMAlgKeyedHash {
		return asMaybe(u.contents.(*TPM2BDigest))
	}
	return maybeNot[TPM2BDigest](fmt.Errorf("did not contain keyedHash (selector value was %v)", u.selector))
}

// SymCipher returns the 'symCipher' member of the union.
func (u *tpmuPublicID) SymCipher() maybe[TPM2BDigest] {
	if u.selector == TPMAlgSymCipher {
		return asMaybe(u.contents.(*TPM2BDigest))
	}
	return maybeNot[TPM2BDigest](fmt.Errorf("did not contain symCipher (selector value was %v)", u.selector))
}

// RSA returns the 'rsa' member of the union.
func (u *tpmuPublicID) RSA() maybe[TPM2BPublicKeyRSA] {
	if u.selector == TPMAlgRSA {
		return asMaybe(u.contents.(*TPM2BPublicKeyRSA))
	}
	return maybeNot[TPM2BPublicKeyRSA](fmt.Errorf("did not contain rsa (selector value was %v)", u.selector))
}

// ECC returns the 'ecc' member of the union.
func (u *tpmuPublicID) ECC() maybe[TPMSECCPoint] {
	if u.selector == TPMAlgECC {
		return asMaybe(u.contents.(*TPMSECCPoint))
	}
	return maybeNot[TPMSECCPoint](fmt.Errorf("did not contain ecc (selector value was %v)", u.selector))
}

// TPMSKeyedHashParms represents a TPMS_KEYEDHASH_PARMS.
// See definition in Part 2: Structures, section 12.2.3.3.
type TPMSKeyedHashParms struct {
	marshalByReflection
	// Indicates the signing method used for a keyedHash signing
	// object. This field also determines the size of the data field
	// for a data object created with TPM2_Create() or
	// TPM2_CreatePrimary().
	Scheme TPMTKeyedHashScheme
}

// TPMSRSAParms represents a TPMS_RSA_PARMS.
// See definition in Part 2: Structures, section 12.2.3.5.
type TPMSRSAParms struct {
	marshalByReflection
	// for a restricted decryption key, shall be set to a supported
	// symmetric algorithm, key size, and mode.
	// if the key is not a restricted decryption key, this field shall
	// be set to TPM_ALG_NULL.
	Symmetric TPMTSymDefObject
	// scheme.scheme shall be:
	// for an unrestricted signing key, either TPM_ALG_RSAPSS
	// TPM_ALG_RSASSA or TPM_ALG_NULL
	// for a restricted signing key, either TPM_ALG_RSAPSS or
	// TPM_ALG_RSASSA
	// for an unrestricted decryption key, TPM_ALG_RSAES, TPM_ALG_OAEP,
	// or TPM_ALG_NULL unless the object also has the sign attribute
	// for a restricted decryption key, TPM_ALG_NULL
	Scheme TPMTRSAScheme
	// number of bits in the public modulus
	KeyBits TPMIRSAKeyBits
	// the public exponent
	// A prime number greater than 2.
	Exponent uint32
}

// TPMSECCParms represents a TPMS_ECC_PARMS.
// See definition in Part 2: Structures, section 12.2.3.6.
type TPMSECCParms struct {
	marshalByReflection
	// for a restricted decryption key, shall be set to a supported
	// symmetric algorithm, key size. and mode.
	// if the key is not a restricted decryption key, this field shall
	// be set to TPM_ALG_NULL.
	Symmetric TPMTSymDefObject
	// If the sign attribute of the key is SET, then this shall be a
	// valid signing scheme.
	Scheme TPMTECCScheme
	// ECC curve ID
	CurveID TPMIECCCurve
	// an optional key derivation scheme for generating a symmetric key
	// from a Z value
	// If the kdf parameter associated with curveID is not TPM_ALG_NULL
	// then this is required to be NULL.
	KDF TPMTKDFScheme
}

type tpmuPublicParms struct {
	selector TPMAlgID
	contents Marshallable
}

type publicParmsContents interface {
	Marshallable
	*TPMSKeyedHashParms | *TPMSSymCipherParms | *TPMSRSAParms |
		*TPMSECCParms
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuPublicParms) create(hint int64) (reflect.Value, error) {
	switch TPMAlgID(hint) {
	case TPMAlgKeyedHash:
		var contents TPMSKeyedHashParms
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgSymCipher:
		var contents TPMSSymCipherParms
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgRSA:
		var contents TPMSRSAParms
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgECC:
		var contents TPMSECCParms
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuPublicParms) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMAlgID(hint) {
	case TPMAlgKeyedHash:
		var contents TPMSKeyedHashParms
		if u.contents != nil {
			contents = *u.contents.(*TPMSKeyedHashParms)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgSymCipher:
		var contents TPMSSymCipherParms
		if u.contents != nil {
			contents = *u.contents.(*TPMSSymCipherParms)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgRSA:
		var contents TPMSRSAParms
		if u.contents != nil {
			contents = *u.contents.(*TPMSRSAParms)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgECC:
		var contents TPMSECCParms
		if u.contents != nil {
			contents = *u.contents.(*TPMSECCParms)
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUPublicParms represents a TPMU_PUBLIC_PARMS.
// See definition in Part 2: Structures, section 12.2.3.7.
func TPMUPublicParms[C publicParmsContents](selector TPMAlgID, contents C) tpmuPublicParms {
	return tpmuPublicParms{
		selector: selector,
		contents: contents,
	}
}

// KeyedHashDetail returns the 'keyedHashDetail' member of the union.
func (u *tpmuPublicParms) KeyedHashDetail() maybe[TPMSKeyedHashParms] {
	if u.selector == TPMAlgKeyedHash {
		return asMaybe(u.contents.(*TPMSKeyedHashParms))
	}
	return maybeNot[TPMSKeyedHashParms](fmt.Errorf("did not contain keyedHashDetail (selector value was %v)", u.selector))
}

// SymDetail returns the 'symDetail' member of the union.
func (u *tpmuPublicParms) SymDetail() maybe[TPMSSymCipherParms] {
	if u.selector == TPMAlgSymCipher {
		return asMaybe(u.contents.(*TPMSSymCipherParms))
	}
	return maybeNot[TPMSSymCipherParms](fmt.Errorf("did not contain symDetail (selector value was %v)", u.selector))
}

// RSADetail returns the 'rsaDetail' member of the union.
func (u *tpmuPublicParms) RSADetail() maybe[TPMSRSAParms] {
	if u.selector == TPMAlgRSA {
		return asMaybe(u.contents.(*TPMSRSAParms))
	}
	return maybeNot[TPMSRSAParms](fmt.Errorf("did not contain rsaDetail (selector value was %v)", u.selector))
}

// ECCDetail returns the 'eccDetail' member of the union.
func (u *tpmuPublicParms) ECCDetail() maybe[TPMSECCParms] {
	if u.selector == TPMAlgECC {
		return asMaybe(u.contents.(*TPMSECCParms))
	}
	return maybeNot[TPMSECCParms](fmt.Errorf("did not contain eccDetail (selector value was %v)", u.selector))
}

// TPMTPublic represents a TPMT_PUBLIC.
// See definition in Part 2: Structures, section 12.2.4.
type TPMTPublic struct {
	marshalByReflection
	// “algorithm” associated with this object
	Type TPMIAlgPublic
	// algorithm used for computing the Name of the object
	NameAlg TPMIAlgHash
	// attributes that, along with type, determine the manipulations
	// of this object
	ObjectAttributes TPMAObject
	// optional policy for using this key
	// The policy is computed using the nameAlg of the object.
	AuthPolicy TPM2BDigest
	// the algorithm or structure details
	Parameters tpmuPublicParms `gotpm:"tag=Type"`
	// the unique identifier of the structure
	// For an asymmetric key, this would be the public key.
	Unique tpmuPublicID `gotpm:"tag=Type"`
}

// TPMTTemplate represents a TPMT_TEMPLATE. It is not defined in the spec.
// It represents the alternate form of TPMT_PUBLIC for TPM2B_TEMPLATE as
// described in Part 2: Structures, 12.2.6.
type TPMTTemplate struct {
	marshalByReflection
	// “algorithm” associated with this object
	Type TPMIAlgPublic
	// algorithm used for computing the Name of the object
	NameAlg TPMIAlgHash
	// attributes that, along with type, determine the manipulations
	// of this object
	ObjectAttributes TPMAObject
	// optional policy for using this key
	// The policy is computed using the nameAlg of the object.
	AuthPolicy TPM2BDigest
	// the algorithm or structure details
	Parameters tpmuPublicParms `gotpm:"tag=Type"`
	// the derivation parameters
	Unique TPMSDerive
}

type tpm2bPublic = tpm2b[TPMTPublic]

// TPM2BPublic represents a TPM2B_PUBLIC.
// See definition in Part 2: Structures, section 12.2.5.
func TPM2BPublic[C bytesOr[TPMTPublic]](contents C) tpm2bPublic {
	return tpm2bHelper[TPMTPublic](contents)
}

type tpmuTemplate struct {
	contents Marshallable
}

// marshal implements the Marshallable interface.
func (u *tpmuTemplate) marshal(buf *bytes.Buffer) {
	buf.Write(Marshal(u.contents))
}

type templateContents interface {
	Marshallable
	*TPMTPublic | *TPMTTemplate
}

// TPMUTemplate represents the possible contents of a TPM2B_Template. It is not
// defined or named in the spec, which instead describes how its contents may
// differ in the case of CreateLoaded with a derivation parent.
func TPMUTemplate[C templateContents](contents C) *tpmuTemplate {
	return &tpmuTemplate{contents: contents}
}

type tpm2bTemplate = tpm2b[tpmuTemplate]

// TPM2BTemplate represents a TPM2B_TEMPLATE.
// See definition in Part 2: Structures, section 12.2.6.
func TPM2BTemplate[C bytesOr[tpmuTemplate]](contents C) tpm2bTemplate {
	return tpm2bHelper[tpmuTemplate](contents)
}

type tpmuSensitiveComposite struct {
	selector TPMAlgID
	contents Marshallable
}

type sensitiveCompositeContents interface {
	Marshallable
	*TPM2BPrivateKeyRSA | *TPM2BECCParameter | *TPM2BSensitiveData | *TPM2BSymKey
}

// create implements the unmarshallableWithHint interface.
func (u *tpmuSensitiveComposite) create(hint int64) (reflect.Value, error) {
	switch TPMAlgID(hint) {
	case TPMAlgRSA:
		var contents TPM2BPrivateKeyRSA
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgECC:
		var contents TPM2BECCParameter
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgKeyedHash:
		var contents TPM2BSensitiveData
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	case TPMAlgSymCipher:
		var contents TPM2BSymKey
		u.contents = &contents
		u.selector = TPMAlgID(hint)
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// get implements the unmarshallableWithHint interface.
func (u *tpmuSensitiveComposite) get(hint int64) (reflect.Value, error) {
	if u.selector != 0 && hint != int64(u.selector) {
		return reflect.ValueOf(nil), fmt.Errorf("incorrect union tag %v, is %v", hint, u.selector)
	}
	switch TPMAlgID(hint) {
	case TPMAlgRSA:
		var contents TPM2BPrivateKeyRSA
		if u.contents != nil {
			contents = *u.contents.(*TPM2BPrivateKeyRSA)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgECC:
		var contents TPM2BECCParameter
		if u.contents != nil {
			contents = *u.contents.(*TPM2BECCParameter)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgKeyedHash:
		var contents TPM2BSensitiveData
		if u.contents != nil {
			contents = *u.contents.(*TPM2BSensitiveData)
		}
		return reflect.ValueOf(&contents), nil
	case TPMAlgSymCipher:
		var contents TPM2BSymKey
		if u.contents != nil {
			contents = *u.contents.(*TPM2BSymKey)
		}
		return reflect.ValueOf(&contents), nil
	}
	return reflect.ValueOf(nil), fmt.Errorf("no union member for tag %v", hint)
}

// TPMUSensitiveComposite represents a TPMU_KDF_SCHEME.
// See definition in Part 2: Structures, section 11.2.3.2.
func TPMUSensitiveComposite[C sensitiveCompositeContents](selector TPMAlgID, contents C) tpmuSensitiveComposite {
	return tpmuSensitiveComposite{
		selector: selector,
		contents: contents,
	}
}

// RSA returns the 'rsa' member of the union.
func (u *tpmuKDFScheme) RSA() maybe[TPM2BPrivateKeyRSA] {
	if u.selector == TPMAlgRSA {
		return asMaybe(u.contents.(*TPM2BPrivateKeyRSA))
	}
	return maybeNot[TPM2BPrivateKeyRSA](fmt.Errorf("did not contain rsa (selector value was %v)", u.selector))
}

// ECC returns the 'ecc' member of the union.
func (u *tpmuKDFScheme) ECC() maybe[TPM2BECCParameter] {
	if u.selector == TPMAlgECC {
		return asMaybe(u.contents.(*TPM2BECCParameter))
	}
	return maybeNot[TPM2BECCParameter](fmt.Errorf("did not contain ecc (selector value was %v)", u.selector))
}

// Bits returns the 'bits' member of the union.
func (u *tpmuKDFScheme) Bits() maybe[TPM2BSensitiveData] {
	if u.selector == TPMAlgKeyedHash {
		return asMaybe(u.contents.(*TPM2BSensitiveData))
	}
	return maybeNot[TPM2BSensitiveData](fmt.Errorf("did not contain bits (selector value was %v)", u.selector))
}

// Sym returns the 'sym' member of the union.
func (u *tpmuKDFScheme) Sym() maybe[TPM2BSymKey] {
	if u.selector == TPMAlgSymCipher {
		return asMaybe(u.contents.(*TPM2BSymKey))
	}
	return maybeNot[TPM2BSymKey](fmt.Errorf("did not contain sym (selector value was %v)", u.selector))
}

// // tpmuSensitiveComposite represents a TPMU_SENSITIVE_COMPOSITE.
// // See definition in Part 2: Structures, section 12.3.2.3.
// type tpmuSensitiveComposite struct {
// 	marshalByReflection
// 	// a prime factor of the public key
// 	RSA *TPM2BPrivateKeyRSA `gotpm:"selector=0x0001"` // TPM_ALG_RSA
// 	// the integer private key
// 	ECC *TPM2BECCParameter `gotpm:"selector=0x0023"` // TPM_ALG_ECC
// 	// the private data
// 	Bits *TPM2BSensitiveData `gotpm:"selector=0x0008"` // TPM_ALG_KEYEDHASH
// 	// the symmetric key
// 	Sym *TPM2BSymKey `gotpm:"selector=0x0025"` // TPM_ALG_SYMCIPHER
// }

// TPMTSensitive represents a TPMT_SENSITIVE.
// See definition in Part 2: Structures, section 12.3.2.4.
type TPMTSensitive struct {
	marshalByReflection
	// identifier for the sensitive area
	SensitiveType TPMIAlgPublic
	// user authorization data
	AuthValue TPM2BAuth
	// for a parent object, the optional protection seed; for other objects,
	// the obfuscation value
	SeedValue TPM2BDigest
	// the type-specific private data
	Sensitive tpmuSensitiveComposite `gotpm:"tag=SensitiveType"`
}

type tpm2bSensitive = tpm2b[TPMTSensitive]

// TPM2BSensitive represents a TPM2B_SENSITIVE.
// See definition in Part 2: Structures, section 12.3.3.
func TPM2BSensitive[C bytesOr[TPMTSensitive]](contents C) tpm2bSensitive {
	return tpm2bHelper[TPMTSensitive](contents)
}

// TPM2BPrivate represents a TPM2B_PRIVATE.
// See definition in Part 2: Structures, section 12.3.7.
type TPM2BPrivate TPM2BData

// TPMSCreationData represents a TPMS_CREATION_DATA.
// See definition in Part 2: Structures, section 15.1.
type TPMSCreationData struct {
	marshalByReflection
	// list indicating the PCR included in pcrDigest
	PCRSelect TPMLPCRSelection
	// digest of the selected PCR using nameAlg of the object for which
	// this structure is being created
	PCRDigest TPM2BDigest
	// the locality at which the object was created
	Locality TPMALocality
	// nameAlg of the parent
	ParentNameAlg TPMAlgID
	// Name of the parent at time of creation
	ParentName TPM2BName
	// Qualified Name of the parent at the time of creation
	ParentQualifiedName TPM2BName
	// association with additional information added by the key
	OutsideInfo TPM2BData
}

// TPM2BIDObject represents a TPM2B_ID_OBJECT.
// See definition in Part 2: Structures, section 12.4.3.
type TPM2BIDObject TPM2BData

// TPMNT represents a TPM_NT.
// See definition in Part 2: Structures, section 13.4.
type TPMNT uint8

// TPMANV represents a TPMA_NV.
// See definition in Part 2: Structures, section 13.4.
type TPMANV struct {
	bitfield32
	marshalByReflection
	// SET (1): The Index data can be written if Platform Authorization is
	// provided.
	// CLEAR (0): Writing of the Index data cannot be authorized with
	// Platform Authorization.
	PPWrite bool `gotpm:"bit=0"`
	// SET (1): The Index data can be written if Owner Authorization is
	// provided.
	// CLEAR (0): Writing of the Index data cannot be authorized with Owner
	// Authorization.
	OwnerWrite bool `gotpm:"bit=1"`
	// SET (1): Authorizations to change the Index contents that require
	// USER role may be provided with an HMAC session or password.
	// CLEAR (0): Authorizations to change the Index contents that require
	// USER role may not be provided with an HMAC session or password.
	AuthWrite bool `gotpm:"bit=2"`
	// SET (1): Authorizations to change the Index contents that require
	// USER role may be provided with a policy session.
	// CLEAR (0): Authorizations to change the Index contents that require
	// USER role may not be provided with a policy session.
	PolicyWrite bool `gotpm:"bit=3"`
	// The type of the index.
	NT TPMNT `gotpm:"bit=7:4"`
	// SET (1): Index may not be deleted unless the authPolicy is satisfied
	// using TPM2_NV_UndefineSpaceSpecial().
	// CLEAR (0): Index may be deleted with proper platform or owner
	// authorization using TPM2_NV_UndefineSpace().
	PolicyDelete bool `gotpm:"bit=10"`
	// SET (1): Index cannot be written.
	// CLEAR (0): Index can be written.
	WriteLocked bool `gotpm:"bit=11"`
	// SET (1): A partial write of the Index data is not allowed. The write
	// size shall match the defined space size.
	// CLEAR (0): Partial writes are allowed. This setting is required if
	// the .dataSize of the Index is larger than NV_MAX_BUFFER_SIZE for the
	// implementation.
	WriteAll bool `gotpm:"bit=12"`
	// SET (1): TPM2_NV_WriteLock() may be used to prevent further writes
	// to this location.
	// CLEAR (0): TPM2_NV_WriteLock() does not block subsequent writes if
	// TPMA_NV_WRITE_STCLEAR is also CLEAR.
	WriteDefine bool `gotpm:"bit=13"`
	// SET (1): TPM2_NV_WriteLock() may be used to prevent further writes
	// to this location until the next TPM Reset or TPM Restart.
	// CLEAR (0): TPM2_NV_WriteLock() does not block subsequent writes if
	// TPMA_NV_WRITEDEFINE is also CLEAR.
	WriteSTClear bool `gotpm:"bit=14"`
	// SET (1): If TPM2_NV_GlobalWriteLock() is successful,
	// TPMA_NV_WRITELOCKED is set.
	// CLEAR (0): TPM2_NV_GlobalWriteLock() has no effect on the writing of
	// the data at this Index.
	GlobalLock bool `gotpm:"bit=15"`
	// SET (1): The Index data can be read if Platform Authorization is
	// provided.
	// CLEAR (0): Reading of the Index data cannot be authorized with
	// Platform Authorization.
	PPRead bool `gotpm:"bit=16"`
	// SET (1): The Index data can be read if Owner Authorization is
	// provided.
	// CLEAR (0): Reading of the Index data cannot be authorized with Owner
	// Authorization.
	OwnerRead bool `gotpm:"bit=17"`
	// SET (1): The Index data may be read if the authValue is provided.
	// CLEAR (0): Reading of the Index data cannot be authorized with the
	// Index authValue.
	AuthRead bool `gotpm:"bit=18"`
	// SET (1): The Index data may be read if the authPolicy is satisfied.
	// CLEAR (0): Reading of the Index data cannot be authorized with the
	// Index authPolicy.
	PolicyRead bool `gotpm:"bit=19"`
	// SET (1): Authorization failures of the Index do not affect the DA
	// logic and authorization of the Index is not blocked when the TPM is
	// in Lockout mode.
	// CLEAR (0): Authorization failures of the Index will increment the
	// authorization failure counter and authorizations of this Index are
	// not allowed when the TPM is in Lockout mode.
	NoDA bool `gotpm:"bit=25"`
	// SET (1): NV Index state is only required to be saved when the TPM
	// performs an orderly shutdown (TPM2_Shutdown()).
	// CLEAR (0): NV Index state is required to be persistent after the
	// command to update the Index completes successfully (that is, the NV
	// update is synchronous with the update command).
	Orderly bool `gotpm:"bit=26"`
	// SET (1): TPMA_NV_WRITTEN for the Index is CLEAR by TPM Reset or TPM
	// Restart.
	// CLEAR (0): TPMA_NV_WRITTEN is not changed by TPM Restart.
	ClearSTClear bool `gotpm:"bit=27"`
	// SET (1): Reads of the Index are blocked until the next TPM Reset or
	// TPM Restart.
	// CLEAR (0): Reads of the Index are allowed if proper authorization is
	// provided.
	ReadLocked bool `gotpm:"bit=28"`
	// SET (1): Index has been written.
	// CLEAR (0): Index has not been written.
	Written bool `gotpm:"bit=29"`
	// SET (1): This Index may be undefined with Platform Authorization
	// but not with Owner Authorization.
	// CLEAR (0): This Index may be undefined using Owner Authorization but
	// not with Platform Authorization.
	PlatformCreate bool `gotpm:"bit=30"`
	// SET (1): TPM2_NV_ReadLock() may be used to SET TPMA_NV_READLOCKED
	// for this Index.
	// CLEAR (0): TPM2_NV_ReadLock() has no effect on this Index.
	ReadSTClear bool `gotpm:"bit=31"`
}

// TPMSNVPublic represents a TPMS_NV_PUBLIC.
// See definition in Part 2: Structures, section 13.5.
type TPMSNVPublic struct {
	marshalByReflection
	// the handle of the data area
	NVIndex TPMIRHNVIndex
	// hash algorithm used to compute the name of the Index and used for
	// the authPolicy. For an extend index, the hash algorithm used for the
	// extend.
	NameAlg TPMIAlgHash
	// the Index attributes
	Attributes TPMANV
	// optional access policy for the Index
	AuthPolicy TPM2BDigest
	// the size of the data area
	DataSize uint16
}

type tpm2bNVPublic = tpm2b[TPMSNVPublic]

// TPM2BNVPublic represents a TPM2B_NV_PUBLIC.
// See definition in Part 2: Structures, section 13.6.
func TPM2BNVPublic[C bytesOr[TPMSNVPublic]](contents C) tpm2bNVPublic {
	return tpm2bHelper[TPMSNVPublic](contents)
}

// TPM2BContextSensitive represents a TPM2B_CONTEXT_SENSITIVE
// See definition in Part 2: Structures, section 14.2.
type TPM2BContextSensitive TPM2BData

// TPMSContextData represents a TPMS_CONTEXT_DATA
// See definition in Part 2: Structures, section 14.3.
type TPMSContextData struct {
	marshalByReflection
	// the integrity value
	Integrity TPM2BDigest
	// the sensitive area
	Encrypted TPM2BContextSensitive
}

// TPM2BContextData represents a TPM2B_CONTEXT_DATA
// See definition in Part 2: Structures, section 14.4.
// Represented here as a flat buffer because how a TPM chooses
// to represent its context data is implementation-dependent.
type TPM2BContextData TPM2BData

// TPMSContext represents a TPMS_CONTEXT
// See definition in Part 2: Structures, section 14.5.
type TPMSContext struct {
	marshalByReflection
	// the sequence number of the context
	Sequence uint64
	// a handle indicating if the context is a session, object, or sequence object
	SavedHandle TPMIDHSaved
	// the hierarchy of the context
	Hierarchy TPMIRHHierarchy
	// the context data and integrity HMAC
	ContextBlob TPM2BContextData
}

type tpm2bCreationData = tpm2b[TPMSCreationData]

// TPM2BCreationData represents a TPM2B_CREATION_DATA.
// See definition in Part 2: Structures, section 15.2.
func TPM2BCreationData[C bytesOr[TPMSCreationData]](contents C) tpm2bCreationData {
	return tpm2bHelper[TPMSCreationData](contents)
}

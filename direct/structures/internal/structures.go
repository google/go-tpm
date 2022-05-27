// package internal defines all the TPM 2.0 structures together to avoid import cycles
package internal

import (
	"crypto"
	"crypto/elliptic"
	"encoding/binary"

	// Register the relevant hash implementations.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
)

// TPMCmdHeader is the header structure in front of any TPM command.
// It is described in Part 1, Architecture.
type TPMCmdHeader struct {
	Tag         TPMISTCommandTag
	Length      uint32
	CommandCode TPMCC
}

// TPMRspHeader is the header structure in front of any TPM response.
// It is described in Part 1, Architecture.
type TPMRspHeader struct {
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

// TODO: Provide a placeholder interface here so we can explicitly enumerate
// these for compile-time protection.

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
type TPMSEmpty = struct{}

// TPMTHA represents a TPMT_HA.
// See definition in Part 2: Structures, section 10.3.2.
type TPMTHA struct {
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
	Hash      TPMIAlgHash
	PCRSelect []byte `gotpm:"sized8"`
}

// TPMTTKCreation represents a TPMT_TK_CREATION.
// See definition in Part 2: Structures, section 10.7.3.
type TPMTTKCreation struct {
	// ticket structure tag
	Tag TPMST
	// the hierarchy containing name
	Hierarchy TPMIRHHierarchy
	// This shall be the HMAC produced using a proof value of hierarchy.
	Digest TPM2BDigest
}

// TPMTTVerified represents a TPMT_TK_Verified.
// See definition in Part 2: Structures, section 10.7.4.
type TPMTTKVerified struct {
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
	// ticket structure tag
	Tag TPMST
	// the hierarchy
	Hierarchy TPMIRHHierarchy
	// This shall be the HMAC produced using a proof value of hierarchy.
	Digest TPM2BDigest
}

// TPMSAlgProperty represents a TPMS_ALG_PROPERTY.
// See definition in Part 2: Structures, section 10.8.1.
type TPMSAlgProperty struct {
	// an algorithm identifier
	Alg TPMAlgID
	// the attributes of the algorithm
	AlgProperties TPMAAlgorithm
}

// TPMSTaggedProperty represents a TPMS_TAGGED_PROPERTY.
// See definition in Part 2: Structures, section 10.8.2.
type TPMSTaggedProperty struct {
	// a property identifier
	Property TPMPT
	// the value of the property
	Value uint32
}

// TPMSTaggedPCRSelect represents a TPMS_TAGGED_PCR_SELECT.
// See definition in Part 2: Structures, section 10.8.3.
type TPMSTaggedPCRSelect struct {
	// the property identifier
	Tag TPMPTPCR
	// the bit map of PCR with the identified property
	PCRSelect []byte `gotpm:"sized8"`
}

// TPMSTaggedPolicy represents a TPMS_TAGGED_POLICY.
// See definition in Part 2: Structures, section 10.8.4.
type TPMSTaggedPolicy struct {
	// a permanent handle
	Handle TPMHandle
	// the policy algorithm and hash
	PolicyHash TPMTHA
}

// TPMSACTData represents a TPMS_ACT_DATA.
// See definition in Part 2: Structures, section 10.8.5.
type TPMSACTData struct {
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
	CommandCodes []TPMCC `gotpm:"list"`
}

// TPMLCCA represents a TPML_CCA.
// See definition in Part 2: Structures, section 10.9.2.
type TPMLCCA struct {
	CommandAttributes []TPMACC `gotpm:"list"`
}

// TPMLAlg represents a TPMLALG.
// See definition in Part 2: Structures, section 10.9.3.
type TPMLAlg struct {
	Algorithms []TPMAlgID `gotpm:"list"`
}

// TPMLHandle represents a TPML_HANDLE.
// See definition in Part 2: Structures, section 10.9.4.
type TPMLHandle struct {
	Handle []TPMHandle `gotpm:"list"`
}

// TPMLDigest represents a TPML_DIGEST.
// See definition in Part 2: Structures, section 10.9.5.
type TPMLDigest struct {
	// a list of digests
	Digests []TPM2BDigest `gotpm:"list"`
}

// TPMLDigestValues represents a TPML_DIGEST_VALUES.
// See definition in Part 2: Structures, section 10.9.6.
type TPMLDigestValues struct {
	// a list of tagged digests
	Digests []TPMTHA `gotpm:"list"`
}

// TPMLPCRSelection represents a TPML_PCR_SELECTION.
// See definition in Part 2: Structures, section 10.9.7.
type TPMLPCRSelection struct {
	PCRSelections []TPMSPCRSelection `gotpm:"list"`
}

// TPMLAlgProperty represents a TPML_ALG_PROPERTY.
// See definition in Part 2: Structures, section 10.9.8.
type TPMLAlgProperty struct {
	AlgProperties []TPMSAlgProperty `gotpm:"list"`
}

// TPMLTaggedTPMProperty represents a TPML_TAGGED_TPM_PROPERTY.
// See definition in Part 2: Structures, section 10.9.9.
type TPMLTaggedTPMProperty struct {
	TPMProperty []TPMSTaggedProperty `gotpm:"list"`
}

// TPMLTaggedPCRProperty represents a TPML_TAGGED_PCR_PROPERTY.
// See definition in Part 2: Structures, section 10.9.10.
type TPMLTaggedPCRProperty struct {
	PCRProperty []TPMSTaggedPCRSelect `gotpm:"list"`
}

// TPMLECCCurve represents a TPML_ECC_CURVE.
// See definition in Part 2: Structures, section 10.9.11.
type TPMLECCCurve struct {
	ECCCurves []TPMECCCurve `gotpm:"list"`
}

// TPMLTaggedPolicy represents a TPML_TAGGED_POLICY.
// See definition in Part 2: Structures, section 10.9.12.
type TPMLTaggedPolicy struct {
	Policies []TPMSTaggedPolicy `gotpm:"list"`
}

// TPMLACTData represents a TPML_ACT_DATA.
// See definition in Part 2: Structures, section 10.9.13.
type TPMLACTData struct {
	ACTData []TPMSACTData `gotpm:"list"`
}

// TPMUCapabilities represents a TPMU_CAPABILITIES.
// See definition in Part 2: Structures, section 10.10.1.
type TPMUCapabilities struct {
	Algorithms    *TPMLAlgProperty       `gotpm:"selector=0x00000000"` // TPM_CAP_ALGS
	Handles       *TPMLHandle            `gotpm:"selector=0x00000001"` // TPM_CAP_HANDLES
	Command       *TPMLCCA               `gotpm:"selector=0x00000002"` // TPM_CAP_COMMANDS
	PPCommands    *TPMLCC                `gotpm:"selector=0x00000003"` // TPM_CAP_PP_COMMANDS
	AuditCommands *TPMLCC                `gotpm:"selector=0x00000004"` // TPM_CAP_AUDIT_COMMANDS
	AssignedPCR   *TPMLPCRSelection      `gotpm:"selector=0x00000005"` // TPM_CAP_PCRS
	TPMProperties *TPMLTaggedTPMProperty `gotpm:"selector=0x00000006"` // TPM_CAP_TPM_PROPERTIES
	PCRProperties *TPMLTaggedPCRProperty `gotpm:"selector=0x00000007"` // TPM_CAP_PCR_PROPERTIES
	ECCCurves     *TPMLECCCurve          `gotpm:"selector=0x00000008"` // TPM_CAP_ECC_CURVES
	AuthPolicies  *TPMLTaggedPolicy      `gotpm:"selector=0x00000009"` // TPM_CAP_AUTH_POLICIES
	ACTData       *TPMLACTData           `gotpm:"selector=0x0000000A"` // TPM_CAP_ACT
}

// TPMSCapabilityData represents a TPMS_CAPABILITY_DATA.
// See definition in Part 2: Structures, section 10.10.2.
type TPMSCapabilityData struct {
	// the capability
	Capability TPMCap
	// the capability data
	Data TPMUCapabilities `gotpm:"tag=Capability"`
}

// TPMSClockInfo represents a TPMS_CLOCK_INFO.
// See definition in Part 2: Structures, section 10.11.1.
type TPMSClockInfo struct {
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
	// time in milliseconds since the TIme circuit was last reset
	Time uint64
	// a structure containing the clock information
	ClockInfo TPMSClockInfo
}

// TPMSTimeAttestInfo represents a TPMS_TIME_ATTEST_INFO.
// See definition in Part 2: Structures, section 10.12.2.
type TPMSTimeAttestInfo struct {
	// the Time, Clock, resetCount, restartCount, and Safe indicator
	Time TPMSTimeInfo
	// a TPM vendor-specific value indicating the version number of the firmware
	FirmwareVersion uint64
}

// TPMSCertifyInfo represents a TPMS_CERTIFY_INFO.
// See definition in Part 2: Structures, section 10.12.3.
type TPMSCertifyInfo struct {
	// Name of the certified object
	Name TPM2BName
	// Qualified Name of the certified object
	QualifiedName TPM2BName
}

// TPMSQuoteInfo represents a TPMS_QUOTE_INFO.
// See definition in Part 2: Structures, section 10.12.4.
type TPMSQuoteInfo struct {
	// information on algID, PCR selected and digest
	PCRSelect TPMLPCRSelection
	// digest of the selected PCR using the hash of the signing key
	PCRDigest TPM2BDigest
}

// TPMSCommandAuditInfo represents a TPMS_COMMAND_AUDIT_INFO.
// See definition in Part 2: Structures, section 10.12.5.
type TPMSCommandAuditInfo struct {
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
	// current exclusive status of the session
	ExclusiveSession TPMIYesNo
	// the current value of the session audit digest
	SessionDigest TPM2BDigest
}

// TPMSCreationInfo represents a TPMS_CREATION_INFO.
// See definition in Part 2: Structures, section 10.12.7.
type TPMSCreationInfo struct {
	// Name of the object
	ObjectName TPM2BName
	// creationHash
	CreationHash TPM2BDigest
}

// TPMSNVCertifyInfo represents a TPMS_NV_CERTIFY_INFO.
// See definition in Part 2: Structures, section 10.12.8.
type TPMSNVCertifyInfo struct {
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
	// Name of the NV Index
	IndexName TPM2BName
	// hash of the contents of the index
	NVDigest TPM2BDigest
}

// TPMISTAttest represents a TPMI_ST_ATTEST.
// See definition in Part 2: Structures, section 10.12.10.
type TPMISTAttest = TPMST

// TPMUAttest represents a TPMU_ATTEST.
// See definition in Part 2: Structures, section 10.12.11.
type TPMUAttest struct {
	NV           *TPMSNVCertifyInfo       `gotpm:"selector=0x8014"` // TPM_ST_ATTEST_NV
	CommandAudit *TPMSCommandAuditInfo    `gotpm:"selector=0x8015"` // TPM_ST_ATTEST_COMMAND_AUDIT
	SessionAudit *TPMSSessionAuditInfo    `gotpm:"selector=0x8016"` // TPM_ST_ATTEST_SESSION_AUDIT
	Certify      *TPMSCertifyInfo         `gotpm:"selector=0x8017"` // TPM_ST_ATTEST_CERTIFY
	Quote        *TPMSQuoteInfo           `gotpm:"selector=0x8018"` // TPM_ST_ATTEST_QUOTE
	Time         *TPMSTimeAttestInfo      `gotpm:"selector=0x8019"` // TPM_ST_ATTEST_TIME
	Creation     *TPMSCreationInfo        `gotpm:"selector=0x801A"` // TPM_ST_ATTEST_CREATION
	NVDigest     *TPMSNVDigestCertifyInfo `gotpm:"selector=0x801C"` // TPM_ST_ATTEST_NV_DIGEST
}

// TPMSAttest represents a TPMS_ATTEST.
// See definition in Part 2: Structures, section 10.12.12.
type TPMSAttest struct {
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
	Attested TPMUAttest `gotpm:"tag=Type"`
}

// TPM2BAttest represents a TPM2B_ATTEST.
// See definition in Part 2: Structures, section 10.12.13.
// Note that in the spec, this is just a 2B_DATA with enough room for an S_ATTEST.
// For ergonomics, pretend that TPM2B_Attest wraps a TPMS_Attest just like other 2Bs.
type TPM2BAttest struct {
	// the signed structure
	AttestationData TPMSAttest `gotpm:"sized"`
}

// TPMSAuthCommand represents a TPMS_AUTH_COMMAND.
// See definition in Part 2: Structures, section 10.13.2.
type TPMSAuthCommand struct {
	Handle        TPMISHAuthSession
	Nonce         TPM2BNonce
	Attributes    TPMASession
	Authorization TPM2BData
}

// TPMSAuthResponse represents a TPMS_AUTH_RESPONSE.
// See definition in Part 2: Structures, section 10.13.3.
type TPMSAuthResponse struct {
	Nonce         TPM2BNonce
	Attributes    TPMASession
	Authorization TPM2BData
}

// TPMUSymKeyBits represents a TPMU_SYM_KEY_BITS.
// See definition in Part 2: Structures, section 11.1.3.
type TPMUSymKeyBits struct {
	// TODO: The rest of the symmetric algorithms get their own entry
	// in this union.
	AES *TPMKeyBits  `gotpm:"selector=0x0006"` // TPM_ALG_AES
	XOR *TPMIAlgHash `gotpm:"selector=0x000A"` // TPM_ALG_XOR
}

// TPMUSymMode represents a TPMU_SYM_MODE.
// See definition in Part 2: Structures, section 11.1.4.
type TPMUSymMode struct {
	// TODO: The rest of the symmetric algorithms get their own entry
	// in this union.
	AES *TPMIAlgSymMode `gotpm:"selector=0x0006"` // TPM_ALG_AES
	XOR *struct{}       `gotpm:"selector=0x000A"` // TPM_ALG_XOR
}

// TPMUSymDetails represents a TPMU_SYM_DETAILS.
// See definition in Part 2: Structures, section 11.1.5.
type TPMUSymDetails struct {
	// TODO: The rest of the symmetric algorithms get their own entry
	// in this union.
	AES *struct{} `gotpm:"selector=0x0006"` // TPM_ALG_AES
	XOR *struct{} `gotpm:"selector=0x000A"` // TPM_ALG_XOR
}

// TPMTSymDef represents a TPMT_SYM_DEF.
// See definition in Part 2: Structures, section 11.1.6.
type TPMTSymDef struct {
	// indicates a symmetric algorithm
	Algorithm TPMIAlgSym `gotpm:"nullable"`
	// the key size
	KeyBits TPMUSymKeyBits `gotpm:"tag=Algorithm"`
	// the mode for the key
	Mode TPMUSymMode `gotpm:"tag=Algorithm"`
	// contains the additional algorithm details
	Details TPMUSymDetails `gotpm:"tag=Algorithm"`
}

// TPMTSymDefObject represents a TPMT_SYM_DEF_OBJECT.
// See definition in Part 2: Structures, section 11.1.7.
type TPMTSymDefObject struct {
	// selects a symmetric block cipher
	// When used in the parameter area of a parent object, this shall
	// be a supported block cipher and not TPM_ALG_NULL
	Algorithm TPMIAlgSymObject `gotpm:"nullable"`
	// the key size
	KeyBits TPMUSymKeyBits `gotpm:"tag=Algorithm"`
	// default mode
	// When used in the parameter area of a parent object, this shall
	// be TPM_ALG_CFB.
	Mode TPMUSymMode `gotpm:"tag=Algorithm"`
	// contains the additional algorithm details, if any
	Details TPMUSymDetails `gotpm:"tag=Algorithm"`
}

// TPM2BSymKey represents a TPM2B_SYM_KEY.
// See definition in Part 2: Structures, section 11.1.8.
type TPM2BSymKey TPM2BData

// TPMSSymCipherParms represents a TPMS_SYMCIPHER_PARMS.
// See definition in Part 2: Structures, section 11.1.9.
type TPMSSymCipherParms struct {
	// a symmetric block cipher
	Sym TPMTSymDefObject
}

// TPM2BLabel represents a TPM2B_LABEL.
// See definition in Part 2: Structures, section 11.1.10.
type TPM2BLabel TPM2BData

// TPMSDerive represents a TPMS_DERIVE.
// See definition in Part 2: Structures, section 11.1.11.
type TPMSDerive struct {
	Label   TPM2BLabel
	Context TPM2BLabel
}

// TPM2BDerive represents a TPM2B_DERIVE.
// See definition in Part 2: Structures, section 11.1.12.
type TPM2BDerive struct {
	Buffer TPMSDerive `gotpm:"sized"`
}

// TPMUSensitiveCreate represents a TPMU_SENSITIVE_CREATE.
// See definition in Part 2: Structures, section 11.1.13.
// Since the TPM cannot return this type, it can be an interface.
type TPMUSensitiveCreate interface {
	tpmusensitivecreate()
}

func (TPM2BSensitiveData) tpmusensitivecreate() {}
func (TPM2BDerive) tpmusensitivecreate()        {}

// TPM2BSensitiveData represents a TPM2B_SENSITIVE_DATA.
// See definition in Part 2: Structures, section 11.1.14.
type TPM2BSensitiveData TPM2BData

// TPMSSensitiveCreate represents a TPMS_SENSITIVE_CREATE.
// See definition in Part 2: Structures, section 11.1.15.
type TPMSSensitiveCreate struct {
	// the USER auth secret value.
	UserAuth TPM2BAuth
	// data to be sealed, a key, or derivation values.
	Data TPMUSensitiveCreate
}

// TPM2BSensitiveCreate represents a TPM2B_SENSITIVE_CREATE.
// See definition in Part 2: Structures, section 11.1.16.
type TPM2BSensitiveCreate struct {
	// data to be sealed or a symmetric key value.
	Sensitive TPMSSensitiveCreate `gotpm:"sized"`
}

// TPMSSchemeHash represents a TPMS_SCHEME_HASH.
// See definition in Part 2: Structures, section 11.1.17.
type TPMSSchemeHash struct {
	// the hash algorithm used to digest the message
	HashAlg TPMIAlgHash
}

// TPMIAlgKeyedHashScheme represents a TPMI_ALG_KEYEDHASH_SCHEME.
// See definition in Part 2: Structures, section 11.1.10.
type TPMIAlgKeyedHashScheme = TPMAlgID

// TPMSSchemeHMAC represents a TPMS_SCHEME_HMAC.
// See definition in Part 2: Structures, section 11.1.20.
type TPMSSchemeHMAC TPMSSchemeHash

// TPMSSchemeXOR represents a TPMS_SCHEME_XOR.
// See definition in Part 2: Structures, section 11.1.21.
type TPMSSchemeXOR struct {
	// the hash algorithm used to digest the message
	HashAlg TPMIAlgHash
	// the key derivation function
	KDF TPMIAlgKDF
}

// TPMUSchemeKeyedHash represents a TPMU_SCHEME_KEYEDHASH.
// See definition in Part 2: Structures, section 11.1.22.
type TPMUSchemeKeyedHash struct {
	HMAC *TPMSSchemeHMAC `gotpm:"selector=0x0005"` // TPM_ALG_HMAC
	XOR  *TPMSSchemeXOR  `gotpm:"selector=0x000A"` // TPM_ALG_XOR
}

// TPMTKeyedHashScheme represents a TPMT_KEYEDHASH_SCHEME.
// See definition in Part 2: Structures, section 11.1.23.
type TPMTKeyedHashScheme struct {
	Scheme  TPMIAlgKeyedHashScheme `gotpm:"nullable"`
	Details TPMUSchemeKeyedHash    `gotpm:"tag=Scheme"`
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

// TPMUSigScheme represents a TPMU_SIG_SCHEME.
// See definition in Part 2: Structures, section 11.2.1.4.
type TPMUSigScheme struct {
	HMAC   *TPMSSchemeHMAC `gotpm:"selector=0x0005"` // TPM_ALG_HMAC
	RSASSA *TPMSSchemeHash `gotpm:"selector=0x0014"` // TPM_ALG_RSASSA
	RSAPSS *TPMSSchemeHash `gotpm:"selector=0x0016"` // TPM_ALG_RSAPSS
	ECDSA  *TPMSSchemeHash `gotpm:"selector=0x0018"` // TPM_ALG_ECDSA
}

// TPMTSigScheme represents a TPMT_SIG_SCHEME.
// See definition in Part 2: Structures, section 11.2.1.5.
type TPMTSigScheme struct {
	Scheme  TPMIAlgSigScheme `gotpm:"nullable"`
	Details TPMUSigScheme    `gotpm:"tag=Scheme"`
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

// TPMUKDFScheme represents a TPMU_KDF_SCHEME.
// See definition in Part 2: Structures, section 11.2.3.2.
type TPMUKDFScheme struct {
	MGF1         *TPMSKDFSchemeMGF1         `gotpm:"selector=0x0007"` // TPM_ALG_MGF1
	ECDH         *TPMSKDFSchemeECDH         `gotpm:"selector=0x0019"` // TPM_ALG_ECDH
	KDF1SP80056A *TPMSKDFSchemeKDF1SP80056A `gotpm:"selector=0x0020"` // TPM_ALG_KDF1_SP800_56A
	KDF2         *TPMSKDFSchemeKDF2         `gotpm:"selector=0x0021"` // TPM_ALG_KDF2
	KDF1SP800108 *TPMSKDFSchemeKDF1SP800108 `gotpm:"selector=0x0022"` // TPM_ALG_KDF1_SP800_108
}

// TPMTKDFScheme represents a TPMT_KDF_SCHEME.
// See definition in Part 2: Structures, section 11.2.3.3.
type TPMTKDFScheme struct {
	// scheme selector
	Scheme TPMIAlgKDF `gotpm:"nullable"`
	// scheme parameters
	Details TPMUKDFScheme `gotpm:"tag=Scheme"`
}

// TPMUAsymScheme represents a TPMU_ASYM_SCHEME.
// See definition in Part 2: Structures, section 11.2.3.5.
type TPMUAsymScheme struct {
	// TODO every asym scheme gets an entry in this union.
	RSASSA *TPMSSigSchemeRSASSA `gotpm:"selector=0x0014"` // TPM_ALG_RSASSA
	RSAES  *TPMSEncSchemeRSAES  `gotpm:"selector=0x0015"` // TPM_ALG_RSAES
	RSAPSS *TPMSSigSchemeRSAPSS `gotpm:"selector=0x0016"` // TPM_ALG_RSAPSS
	OAEP   *TPMSEncSchemeOAEP   `gotpm:"selector=0x0017"` // TPM_ALG_OAEP
	ECDSA  *TPMSSigSchemeECDSA  `gotpm:"selector=0x0018"` // TPM_ALG_ECDSA
	ECDH   *TPMSKeySchemeECDH   `gotpm:"selector=0x0019"` // TPM_ALG_ECDH
}

// TPMIAlgRSAScheme represents a TPMI_ALG_RSA_SCHEME.
// See definition in Part 2: Structures, section 11.2.4.1.
type TPMIAlgRSAScheme = TPMAlgID

// TPMTRSAScheme represents a TPMT_RSA_SCHEME.
// See definition in Part 2: Structures, section 11.2.4.2.
type TPMTRSAScheme struct {
	// scheme selector
	Scheme TPMIAlgRSAScheme `gotpm:"nullable"`
	// scheme parameters
	Details TPMUAsymScheme `gotpm:"tag=Scheme"`
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
	// X coordinate
	X TPM2BECCParameter
	// Y coordinate
	Y TPM2BECCParameter
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
	// scheme selector
	Scheme TPMIAlgECCScheme `gotpm:"nullable"`
	// scheme parameters
	Details TPMUAsymScheme `gotpm:"tag=Scheme"`
}

// TPMSSignatureRSA represents a TPMS_SIGNATURE_RSA.
// See definition in Part 2: Structures, section 11.3.1.
type TPMSSignatureRSA struct {
	// the hash algorithm used to digest the message
	Hash TPMIAlgHash
	// The signature is the size of a public key.
	Sig TPM2BPublicKeyRSA
}

// TPMSSignatureECC represents a TPMS_SIGNATURE_ECC.
// See definition in Part 2: Structures, section 11.3.2.
type TPMSSignatureECC struct {
	// the hash algorithm used in the signature process
	Hash       TPMIAlgHash
	SignatureR TPM2BECCParameter
	SignatureS TPM2BECCParameter
}

// TPMUSignature represents a TPMU_SIGNATURE.
// See definition in Part 2: Structures, section 11.3.3.
type TPMUSignature struct {
	HMAC   *TPMTHA           `gotpm:"selector=0x0005"` // TPM_ALG_HMAC
	RSASSA *TPMSSignatureRSA `gotpm:"selector=0x0014"` // TPM_ALG_RSASSA
	RSAPSS *TPMSSignatureRSA `gotpm:"selector=0x0016"` // TPM_ALG_RSAPSS
	ECDSA  *TPMSSignatureECC `gotpm:"selector=0x0018"` // TPM_ALG_ECDSA
}

// TPMTSignature represents a TPMT_SIGNATURE.
// See definition in Part 2: Structures, section 11.3.4.
type TPMTSignature struct {
	// selector of the algorithm used to construct the signature
	SigAlg TPMIAlgSigScheme `gotpm:"nullable"`
	// This shall be the actual signature information.
	Signature TPMUSignature `gotpm:"tag=SigAlg"`
}

// TPM2BEncryptedSecret represents a TPM2B_ENCRYPTED_SECRET.
// See definition in Part 2: Structures, section 11.4.33.
type TPM2BEncryptedSecret TPM2BData

// TPMIAlgPublic represents a TPMI_ALG_PUBLIC.
// See definition in Part 2: Structures, section 12.2.2.
type TPMIAlgPublic = TPMAlgID

// TPMUPublicID represents a TPMU_PUBLIC_ID.
// See definition in Part 2: Structures, section 12.2.3.2.
type TPMUPublicID struct {
	KeyedHash *TPM2BDigest       `gotpm:"selector=0x0008"` // TPM_ALG_KEYEDHASH
	Sym       *TPM2BDigest       `gotpm:"selector=0x0025"` // TPM_ALG_SYMCIPHER
	RSA       *TPM2BPublicKeyRSA `gotpm:"selector=0x0001"` // TPM_ALG_RSA
	ECC       *TPMSECCPoint      `gotpm:"selector=0x0023"` // TPM_ALG_ECC
}

// TPMSKeyedHashParms represents a TPMS_KEYEDHASH_PARMS.
// See definition in Part 2: Structures, section 12.2.3.3.
type TPMSKeyedHashParms struct {
	// Indicates the signing method used for a keyedHash signing
	// object. This field also determines the size of the data field
	// for a data object created with TPM2_Create() or
	// TPM2_CreatePrimary().
	Scheme TPMTKeyedHashScheme
}

// TPMSRSAParms represents a TPMS_RSA_PARMS.
// See definition in Part 2: Structures, section 12.2.3.5.
type TPMSRSAParms struct {
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

// TPMUPublicParms represents a TPMU_PUBLIC_PARMS.
// See definition in Part 2: Structures, section 12.2.3.7.
type TPMUPublicParms struct {
	// sign | decrypt | neither
	KeyedHashDetail *TPMSKeyedHashParms `gotpm:"selector=0x0008"` // TPM_ALG_KEYEDHASH
	// sign | decrypt | neither
	SymCipherDetail *TPMSSymCipherParms `gotpm:"selector=0x0025"` // TPM_ALG_SYMCIPHER
	// decrypt + sign
	RSADetail *TPMSRSAParms `gotpm:"selector=0x0001"` // TPM_ALG_RSA
	// decrypt + sign
	ECCDetail *TPMSECCParms `gotpm:"selector=0x0023"` // TPM_ALG_ECC
}

// TPMTPublic represents a TPMT_PUBLIC.
// See definition in Part 2: Structures, section 12.2.4.
type TPMTPublic struct {
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
	Parameters TPMUPublicParms `gotpm:"tag=Type"`
	// the unique identifier of the structure
	// For an asymmetric key, this would be the public key.
	Unique TPMUPublicID `gotpm:"tag=Type"`
}

// TPMTTemplate represents a TPMT_TEMPLATE. It is not defined in the spec.
// It represents the alternate form of TPMT_PUBLIC for TPM2B_TEMPLATE as
// described in Part 2: Structures, 12.2.6.
type TPMTTemplate struct {
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
	Parameters TPMUPublicParms `gotpm:"tag=Type"`
	// the derivation parameters
	Unique TPMSDerive
}

// TPM2BPublic represents a TPM2B_PUBLIC.
// See definition in Part 2: Structures, section 12.2.5.
type TPM2BPublic struct {
	// the public area
	PublicArea TPMTPublic `gotpm:"sized"`
}

// TPM2BTemplate represents a TPM2B_TEMPLATE.
// See definition in Part 2: Structures, section 12.2.6.
type TPM2BTemplate struct {
	Template TPMUTemplate `gotpm:"sized"`
}

// TPMUTemplate represents the possible contents of a TPM2B_Template. It is not
// defined or named in the spec, which instead describes how its contents may
// differ in the case of CreateLoaded with a derivation parent.
// Since the TPM cannot return this type, it can be an interface.
type TPMUTemplate interface {
	tpmutemplate()
	defaultMarshalling() []byte
}

func (TPMTPublic) tpmutemplate()                {}
func (TPMTPublic) defaultMarshalling() []byte   { return nil }
func (TPMTTemplate) tpmutemplate()              {}
func (TPMTTemplate) defaultMarshalling() []byte { return nil }

// TPMUSensitiveComposite represents a TPMU_SENSITIVE_COMPOSITE.
// See definition in Part 2: Structures, section 12.3.2.3.
type TPMUSensitiveComposite struct {
	// a prime factor of the public key
	RSA *TPM2BPrivateKeyRSA `gotpm:"selector=0x0001"` // TPM_ALG_RSA
	// the integer private key
	ECC *TPM2BECCParameter `gotpm:"selector=0x0023"` // TPM_ALG_ECC
	// the private data
	Bits *TPM2BSensitiveData `gotpm:"selector=0x0008"` // TPM_ALG_KEYEDHASH
	// the symmetric key
	Sym *TPM2BSymKey `gotpm:"selector=0x0025"` // TPM_ALG_SYMCIPHER
}

// TPMTSensitive represents a TPMT_SENSITIVE.
// See definition in Part 2: Structures, section 12.3.2.4.
type TPMTSensitive struct {
	// identifier for the sensitive area
	SensitiveType TPMIAlgPublic
	// user authorization data
	AuthValue TPM2BAuth
	// for a parent object, the optional protection seed; for other objects,
	// the obfuscation value
	SeedValue TPM2BDigest
	// the type-specific private data
	Sensitive TPMUSensitiveComposite `gotpm:"tag=SensitiveType"`
}

// TPM2BSensitive represents a TPM2B_SENSITIVE.
// See definition in Part 2: Structures, section 12.3.3.
type TPM2BSensitive struct {
	// an unencrypted sensitive area
	SensitiveArea TPMTSensitive `gotpm:"sized"`
}

// TPM2BPrivate represents a TPM2B_PRIVATE.
// See definition in Part 2: Structures, section 12.3.7.
type TPM2BPrivate TPM2BData

// TPMSCreationData represents a TPMS_CREATION_DATA.
// See definition in Part 2: Structures, section 15.1.
type TPMSCreationData struct {
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

// TPMNT represents a TPM_NT.
// See definition in Part 2: Structures, section 13.4.
type TPMNT uint8

// TPMANV represents a TPMA_NV.
// See definition in Part 2: Structures, section 13.4.
type TPMANV struct {
	bitfield32
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

// TPM2BNVPublic represents a TPM2B_NV_PUBLIC.
// See definition in Part 2: Structures, section 13.6.
type TPM2BNVPublic struct {
	NVPublic TPMSNVPublic `gotpm:"sized"`
}

// TPM2BCreationData represents a TPM2B_CREATION_DATA.
// See definition in Part 2: Structures, section 15.2.
type TPM2BCreationData struct {
	CreationData TPMSCreationData `gotpm:"sized"`
}

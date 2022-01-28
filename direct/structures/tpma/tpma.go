// package tpma contains the TPM 2.0 structures prefixed by "TPMA_"
package tpma

import "fmt"

// Algorithm represents a TPMA_ALGORITHM.
// See definition in Part 2: Structures, section 8.2.
type Algorithm struct {
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
	Object    bool  `gotpm:"bit=3"`
	Reserved1 uint8 `gotpm:"bit=7:4"`
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
	Method    bool   `gotpm:"bit=10"`
	Reserved2 uint32 `gotpm:"bit=31:11"`
}

// Object represents a TPMA_OBJECT.
// See definition in Part 2: Structures, section 8.3.2.
type Object struct {
	// shall be zero
	Reserved1 uint8 `gotpm:"bit=0"`
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
	// shall be zero
	Reserved2 uint8 `gotpm:"bit=3"`
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
	// shall be zero
	Reserved3 uint8 `gotpm:"bit=9:8"`
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
	// shall be zero
	Reserved4 uint8 `gotpm:"bit=15:12"`
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
	// shall be zero
	Reserved5 uint16 `gotpm:"bit=31:20"`
}

// Session represents a TPMA_SESSION.
// See definition in Part 2: Structures, section 8.4.
type Session struct {
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
	// shall be CLEAR
	Reserved1 bool `gotpm:"bit=3"`
	// shall be CLEAR
	Reserved2 bool `gotpm:"bit=4"`
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

// Locality represents a TPMA_LOCALITY.
// See definition in Part 2: Structures, section 8.5.
type Locality struct {
	TPMLocZero  bool `gotpm:"bit=0"`
	TPMLocOne   bool `gotpm:"bit=1"`
	TPMLocTwo   bool `gotpm:"bit=2"`
	TPMLocThree bool `gotpm:"bit=3"`
	TPMLocFour  bool `gotpm:"bit=4"`
	// If any of these bits is set, an extended locality is indicated
	Extended uint8 `gotpm:"bit=7:5"`
}

// CC represents a TPMA_CC.
// See definition in Part 2: Structures, section 8.9.
type CC struct {
	// indicates the command being selected
	CommandIndex uint16 `gotpm:"bit=15:0"`
	// shall be zero
	Reserved1 uint16 `gotpm:"bit=21:16"`
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
	// allocated for software; shall be zero
	Reserved2 uint8 `gotpm:"bit=31:30"`
}

// ACT represents a TPMA_ACT.
// See definition in Part 2: Structures, section 8.12.
type ACT struct {
	// SET (1): The ACT has signaled
	// CLEAR (0): The ACT has not signaled
	Signaled bool `gotpm:"bit=0"`
	// SET (1): The ACT signaled bit is preserved over a power cycle
	// CLEAR (0): The ACT signaled bit is not preserved over a power cycle
	PreserveSignaled bool `gotpm:"bit=1"`
	// shall be zero
	Reserved uint32 `gotpm:"bit=31:2"`
}


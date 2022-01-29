// package tpm2 contains TPM 2.0 commands
package tpm2

import (
	"encoding/binary"

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpm2b"
	"github.com/google/go-tpm/direct/structures/tpmi"
	"github.com/google/go-tpm/direct/structures/tpml"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
)

// AuthHandle is a convenience type to wrap an authorized handle.
type AuthHandle struct {
	// The handle that is authorized.
	// If zero, treated as TPM_RH_NULL.
	Handle tpmi.DHObject `gotpm:"nullable"`
	// The Name of the object expected at the given handle value.
	// If Name contains a nil buffer, the effective Name will be
	// the big-endian UINT32 representation of Handle, as in
	// Part 1, section 16 "Names" for PCRs, sessions, and
	// permanent values.
	Name tpm2b.Name `gotpm:"skip"`
	// The session used to authorize the object.
	// If the 'UserWithAuth' attribute is not set on the object,
	// must be a Policy session.
	// For ADMIN-role commands, if 'AdminWithPolicy' is set on
	// the object, must be a Policy session.
	// For DUP-role commands, must be a Policy session that
	// sets the policy command code to TPM_CC_DUPLICATE.
	// If nil, the effective Session will be a password session
	// with NULL authorization.
	Auth Session `gotpm:"skip"`
}

// effectiveHandle returns the effective handle value.
// Returns TPM_RH_NULL if unset.
func (a *AuthHandle) effectiveHandle() tpmi.DHObject {
	if a.Handle != 0 {
		return a.Handle
	}
	return tpm.RHNull
}

// effectiveName returns the effective Name.
// Returns the handle value as a name if unset.
func (a *AuthHandle) effectiveName() tpm2b.Name {
	if len(a.Name.Buffer) > 0 {
		return a.Name
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(a.effectiveHandle()))
	return tpm2b.Name{buf}
}

// effectiveAuth returns the effective auth session.
// Returns a NULL password session if unset.
func (a *AuthHandle) effectiveAuth() Session {
	if a.Auth == nil {
		return PasswordAuth(nil)
	}
	return a.Auth
}

// Command is a placeholder interface for TPM command structures so that they
// can be easily distinguished from other types of structures.
type Command interface {
	// The TPM command code associated with this command.
	Command() tpm.CC
}

// Response is a placeholder interface for TPM response structures so that they
// can be easily distinguished from other types of structures.
// All implementations of this interface are pointers to structures, for
// settability.
// See https://go.dev/blog/laws-of-reflection
type Response interface {
	// The TPM command code associated with this response.
	Response() tpm.CC
}

// StartAuthSessionCommand is the input to TPM2_StartAuthSession.
// See definition in Part 3, Commands, section 11.1
type StartAuthSessionCommand struct {
	// handle of a loaded decrypt key used to encrypt salt
	// may be TPM_RH_NULL
	TPMKey tpmi.DHObject `gotpm:"handle,nullable"`
	// entity providing the authValue
	// may be TPM_RH_NULL
	Bind tpmi.DHEntity `gotpm:"handle,nullable"`
	// initial nonceCaller, sets nonceTPM size for the session
	// shall be at least 16 octets
	NonceCaller tpm2b.Nonce
	// value encrypted according to the type of tpmKey
	// If tpmKey is TPM_RH_NULL, this shall be the Empty Buffer.
	EncryptedSalt tpm2b.EncryptedSecret
	// indicates the type of the session; simple HMAC or policy (including
	// a trial policy)
	SessionType tpm.SE
	// the algorithm and key size for parameter encryption
	// may select TPM_ALG_NULL
	Symmetric tpmt.SymDef
	// hash algorithm to use for the session
	// Shall be a hash algorithm supported by the TPM and not TPM_ALG_NULL
	AuthHash tpmi.AlgHash
}

// Command implements the Command interface.
func (*StartAuthSessionCommand) Command() tpm.CC { return tpm.CCStartAuthSession }

// StartAuthSessionResponse is the response from TPM2_StartAuthSession.
type StartAuthSessionResponse struct {
	// handle for the newly created session
	SessionHandle tpmi.SHAuthSession `gotpm:"handle"`
	// the initial nonce from the TPM, used in the computation of the sessionKey
	NonceTPM tpm2b.Nonce
}

// Response implements the Response interface.
func (*StartAuthSessionResponse) Response() tpm.CC { return tpm.CCStartAuthSession }

// CreateCommand is the input to TPM2_Create.
// See definition in Part 3, Commands, section 12.1
type CreateCommand struct {
	// handle of parent for new object
	ParentHandle AuthHandle `gotpm:"handle,auth"`
	// the sensitive data
	InSensitive tpm2b.SensitiveCreate
	// the public template
	InPublic tpm2b.Public
	// data that will be included in the creation data for this
	// object to provide permanent, verifiable linkage between this
	// object and some object owner data
	OutsideInfo tpm2b.Data
	// PCR that will be used in creation data
	CreationPCR tpml.PCRSelection
}

// Command implements the Command interface.
func (*CreateCommand) Command() tpm.CC { return tpm.CCCreate }

// CreateResponse is the response from TPM2_Create.
type CreateResponse struct {
	// the private portion of the object
	OutPrivate tpm2b.Private
	// the public portion of the created object
	OutPublic tpm2b.Public
	// contains a tpms._CREATION_DATA
	CreationData tpm2b.CreationData
	// digest of creationData using nameAlg of outPublic
	CreationHash tpm2b.Digest
	// ticket used by TPM2_CertifyCreation() to validate that the
	// creation data was produced by the TPM
	CreationTicket tpmt.TKCreation
}

// Response implements the Response interface.
func (*CreateResponse) Response() tpm.CC { return tpm.CCCreate }

// LoadCommand is the input to TPM2_Load.
// See definition in Part 3, Commands, section 12.2
type LoadCommand struct {
	// handle of parent for new object
	ParentHandle AuthHandle `gotpm:"handle,auth"`
	// the private portion of the object
	InPrivate tpm2b.Private
	// the public portion of the object
	InPublic tpm2b.Public
}

// Command implements the Command interface.
func (*LoadCommand) Command() tpm.CC { return tpm.CCLoad }

// LoadResponse is the response from TPM2_Load.
type LoadResponse struct {
	// handle of type TPM_HT_TRANSIENT for loaded object
	ObjectHandle tpm.Handle `gotpm:"handle"`
	// Name of the loaded object
	Name tpm2b.Name
}

// Response implements the Response interface.
func (*LoadResponse) Response() tpm.CC { return tpm.CCLoad }

// UnsealCommand is the input to TPM2_Unseal.
// See definition in Part 3, Commands, section 12.7
type UnsealCommand struct {
	ItemHandle AuthHandle `gotpm:"handle,auth"`
}

// Command implements the Command interface.
func (*UnsealCommand) Command() tpm.CC { return tpm.CCUnseal }

// UnsealResponse is the response from TPM2_Unseal.
type UnsealResponse struct {
	OutData tpm2b.SensitiveData
}

// Response implements the Response interface.
func (*UnsealResponse) Response() tpm.CC { return tpm.CCUnseal }

// QuoteCommand is the input to TPM2_Quote.
// See definition in Part 3, Commands, section 18.4
type QuoteCommand struct {
	// handle of key that will perform signature
	SignHandle AuthHandle `gotpm:"handle,auth"`
	// data supplied by the caller
	QualifyingData tpm2b.Data
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme tpmt.SigScheme
	// PCR set to quote
	PCRSelect tpml.PCRSelection
}

// Command implements the Command interface.
func (*QuoteCommand) Command() tpm.CC { return tpm.CCQuote }

// QuoteResponse is the response from TPM2_Quote.
type QuoteResponse struct {
	// the quoted information
	Quoted tpm2b.Attest
	// the signature over quoted
	Signature tpmt.Signature
}

// Response implements the Response interface.
func (*QuoteResponse) Response() tpm.CC { return tpm.CCQuote }

// GetSessionAuditDigestCommand is the input to TPM2_GetSessionAuditDigest.
// See definition in Part 3, Commands, section 18.5
type GetSessionAuditDigestCommand struct {
	// handle of the privacy administrator (TPM_RH_ENDORSEMENT)
	PrivacyAdminHandle AuthHandle `gotpm:"handle,auth"`
	// handle of the signing key
	SignHandle AuthHandle `gotpm:"handle,auth"`
	// handle of the audit session
	SessionHandle tpmi.SHHMAC `gotpm:"handle"`
	// user-provided qualifying data – may be zero-length
	QualifyingData tpm2b.Data
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme tpmt.SigScheme
}

// Command implements the Command interface.
func (*GetSessionAuditDigestCommand) Command() tpm.CC { return tpm.CCGetSessionAuditDigest }

// GetSessionAuditDigestResponse is the response from
// TPM2_GetSessionAuditDigest.
type GetSessionAuditDigestResponse struct {
	// the audit information that was signed
	AuditInfo tpm2b.Attest
	// the signature over auditInfo
	Signature tpmt.Signature
}

// Response implements the Response interface.
func (*GetSessionAuditDigestResponse) Response() tpm.CC { return tpm.CCGetSessionAuditDigest }

// PCRExtendCommand is the input to TPM2_PCR_Extend.
// See definition in Part 3, Commands, section 22.2
type PCRExtendCommand struct {
	// handle of the PCR
	PCRHandle AuthHandle `gotpm:"handle,auth"`
	// list of tagged digest values to be extended
	Digests tpml.DigestValues
}

// Command implements the Command interface.
func (*PCRExtendCommand) Command() tpm.CC { return tpm.CCPCRExtend }

// PCRExtendResponse is the response from TPM2_PCR_Extend.
type PCRExtendResponse struct {
}

// Response implements the Response interface.
func (*PCRExtendResponse) Response() tpm.CC { return tpm.CCPCRExtend }

// PCREventCommand is the input to TPM2_PCR_Event.
// See definition in Part 3, Commands, section 22.3
type PCREventCommand struct {
	// Handle of the PCR
	PCRHandle AuthHandle `gotpm:"handle,auth"`
	// Event data in sized buffer
	EventData tpm2b.Event
}

// Command implements the Command interface.
func (*PCREventCommand) Command() tpm.CC { return tpm.CCPCREvent }

// PCREventResponse is the response from TPM2_PCR_Event.
type PCREventResponse struct {
}

// Response implements the Response interface.
func (*PCREventResponse) Response() tpm.CC { return tpm.CCPCREvent }

// PCRReadCommand is the input to TPM2_PCR_Read.
// See definition in Part 3, Commands, section 22.4
type PCRReadCommand struct {
	// The selection of PCR to read
	PCRSelectionIn tpml.PCRSelection
}

// Command implements the Command interface.
func (*PCRReadCommand) Command() tpm.CC { return tpm.CCPCRRead }

// PCRReadResponse is the response from TPM2_PCR_Read.
type PCRReadResponse struct {
	// the current value of the PCR update counter
	PCRUpdateCounter uint32
	// the PCR in the returned list
	PCRSelectionOut tpml.PCRSelection
	// the contents of the PCR indicated in pcrSelectOut-> pcrSelection[] as tagged digests
	PCRValues tpml.Digest
}

// Response implements the Response interface.
func (*PCRReadResponse) Response() tpm.CC { return tpm.CCPCRRead }

// PolicySecretCommand is the input to TPM2_PolicySecret.
// See definition in Part 3, Commands, section 23.4
type PolicySecretCommand struct {
	// handle for an entity providing the authorization
	AuthHandle AuthHandle `gotpm:"handle,auth"`
	// handle for the policy session being extended
	PolicySession tpmi.SHPolicy `gotpm:"handle"`
	// the policy nonce for the session
	NonceTPM tpm2b.Nonce
	// digest of the command parameters to which this authorization is limited
	CPHashA tpm2b.Digest
	// a reference to a policy relating to the authorization – may be the Empty Buffer
	PolicyRef tpm2b.Nonce
	// time when authorization will expire, measured in seconds from the time
	// that nonceTPM was generated
	Expiration int32
}

// Command implements the Command interface.
func (*PolicySecretCommand) Command() tpm.CC { return tpm.CCPolicySecret }

// PolicySecretResponse is the response from TPM2_PolicySecret.
type PolicySecretResponse struct {
	// implementation-specific time value used to indicate to the TPM when the ticket expires
	Timeout tpm2b.Timeout
	// produced if the command succeeds and expiration in the command was non-zero
	PolicyTicket tpmt.TKAuth
}

// Response implements the Response interface.
func (*PolicySecretResponse) Response() tpm.CC { return tpm.CCPolicySecret }

// CreatePrimaryCommand is the input to TPM2_CreatePrimary.
// See definition in Part 3, Commands, section 24.1
type CreatePrimaryCommand struct {
	// TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP},
	// or TPM_RH_NULL
	PrimaryHandle AuthHandle `gotpm:"handle,auth"`
	// the sensitive data
	InSensitive tpm2b.SensitiveCreate
	// the public template
	InPublic tpm2b.Public
	// data that will be included in the creation data for this
	// object to provide permanent, verifiable linkage between this
	// object and some object owner data
	OutsideInfo tpm2b.Data
	// PCR that will be used in creation data
	CreationPCR tpml.PCRSelection
}

// Command implements the Command interface.
func (*CreatePrimaryCommand) Command() tpm.CC { return tpm.CCCreatePrimary }

// CreatePrimaryResponse is the response from TPM2_CreatePrimary.
type CreatePrimaryResponse struct {
	// handle of type TPM_HT_TRANSIENT for created Primary Object
	ObjectHandle tpm.Handle `gotpm:"handle"`
	// the public portion of the created object
	OutPublic tpm2b.Public
	// contains a tpms._CREATION_DATA
	CreationData tpm2b.CreationData
	// digest of creationData using nameAlg of outPublic
	CreationHash tpm2b.Digest
	// ticket used by TPM2_CertifyCreation() to validate that the
	// creation data was produced by the TPM
	CreationTicket tpmt.TKCreation
	// the name of the created object
	Name tpm2b.Name
}

// Response implements the Response interface.
func (*CreatePrimaryResponse) Response() tpm.CC { return tpm.CCCreatePrimary }

// FlushContextCommand is the input to TPM2_FlushContext.
// See definition in Part 3, Commands, section 28.4
type FlushContextCommand struct {
	// the handle of the item to flush
	FlushHandle tpmi.DHContext
}

// Command implements the Command interface.
func (*FlushContextCommand) Command() tpm.CC { return tpm.CCFlushContext }

// FlushContextResponse is the response from TPM2_FlushContext.
type FlushContextResponse struct {
}

// Response implements the Response interface.
func (*FlushContextResponse) Response() tpm.CC { return tpm.CCFlushContext }

// GetCapabilityCommand is the input to TPM2_GetCapability.
// See definition in Part 3, Commands, section 30.2
type GetCapabilityCommand struct {
	// group selection; determines the format of the response
	Capability tpm.Cap
	// further definition of information
	Property uint32
	// number of properties of the indicated type to return
	PropertyCount uint32
}

// Command implements the Command interface.
func (*GetCapabilityCommand) Command() tpm.CC { return tpm.CCGetCapability }

// GetCapabilityResponse is the response from TPM2_GetCapability.
type GetCapabilityResponse struct {
	// flag to indicate if there are more values of this type
	MoreData tpmi.YesNo
	// the capability data
	CapabilityData tpms.CapabilityData
}

// Response implements the Response interface.
func (*GetCapabilityResponse) Response() tpm.CC { return tpm.CCGetCapability }

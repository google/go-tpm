package direct

import "encoding/binary"

// AuthHandle is a convenience type to wrap an authorized handle.
type AuthHandle struct {
	// The handle that is authorized.
	// If zero, treated as TPM_RH_NULL.
	Handle TPMIDHObject `gotpm:"nullable"`
	// The Name of the object expected at the given handle value.
	// If Name contains a nil buffer, the effective Name will be
	// the big-endian UINT32 representation of Handle, as in
	// Part 1, section 16 "Names" for PCRs, sessions, and
	// permanent values.
	Name TPM2BName `gotpm:"skip"`
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
func (a *AuthHandle) effectiveHandle() TPMIDHObject {
	if a.Handle != 0 {
		return a.Handle
	}
	return TPMRHNull
}

// effectiveName returns the effective Name.
// Returns the handle value as a name if unset.
func (a *AuthHandle) effectiveName() TPM2BName {
	if len(a.Name.Buffer) > 0 {
		return a.Name
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(a.effectiveHandle()))
	return TPM2BName{buf}
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
	Command() TPMCC
}

// Response is a placeholder interface for TPM response structures so that they
// can be easily distinguished from other types of structures.
// All implementations of this interface are pointers to structures, for
// settability.
// See https://go.dev/blog/laws-of-reflection
type Response interface {
	// The TPM command code associated with this response.
	Response() TPMCC
}

// StartAuthSessionCommand is the input to TPM2_StartAuthSession.
// See definition in Part 3, Commands, section 11.1
type StartAuthSessionCommand struct {
	// handle of a loaded decrypt key used to encrypt salt
	// may be TPM_RH_NULL
	TPMKey TPMIDHObject `gotpm:"handle,nullable"`
	// entity providing the authValue
	// may be TPM_RH_NULL
	Bind TPMIDHEntity `gotpm:"handle,nullable"`
	// initial nonceCaller, sets nonceTPM size for the session
	// shall be at least 16 octets
	NonceCaller TPM2BNonce
	// value encrypted according to the type of tpmKey
	// If tpmKey is TPM_RH_NULL, this shall be the Empty Buffer.
	EncryptedSalt TPM2BEncryptedSecret
	// indicates the type of the session; simple HMAC or policy (including
	// a trial policy)
	SessionType TPMSE
	// the algorithm and key size for parameter encryption
	// may select TPM_ALG_NULL
	Symmetric TPMTSymDef
	// hash algorithm to use for the session
	// Shall be a hash algorithm supported by the TPM and not TPM_ALG_NULL
	AuthHash TPMIAlgHash
}

func (*StartAuthSessionCommand) Command() TPMCC { return TPMCCStartAuthSession }

// StartAuthSessionResponse is the response from TPM2_StartAuthSession.
type StartAuthSessionResponse struct {
	// handle for the newly created session
	SessionHandle TPMISHAuthSession `gotpm:"handle"`
	// the initial nonce from the TPM, used in the computation of the sessionKey
	NonceTPM TPM2BNonce
}

func (*StartAuthSessionResponse) Response() TPMCC { return TPMCCStartAuthSession }

// CreateCommand is the input to TPM2_Create.
// See definition in Part 3, Commands, section 12.1
type CreateCommand struct {
	// handle of parent for new object
	ParentHandle AuthHandle `gotpm:"handle,auth"`
	// the sensitive data
	InSensitive TPM2BSensitiveCreate
	// the public template
	InPublic TPM2BPublic
	// data that will be included in the creation data for this
	// object to provide permanent, verifiable linkage between this
	// object and some object owner data
	OutsideInfo TPM2BData
	// PCR that will be used in creation data
	CreationPCR TPMLPCRSelection
}

func (*CreateCommand) Command() TPMCC { return TPMCCCreate }

// CreateResponse is the response from TPM2_Create.
type CreateResponse struct {
	// the private portion of the object
	OutPrivate TPM2BPrivate
	// the public portion of the created object
	OutPublic TPM2BPublic
	// contains a TPMS_CREATION_DATA
	CreationData TPM2BCreationData
	// digest of creationData using nameAlg of outPublic
	CreationHash TPM2BDigest
	// ticket used by TPM2_CertifyCreation() to validate that the
	// creation data was produced by the TPM
	CreationTicket TPMTTKCreation
}

func (*CreateResponse) Response() TPMCC { return TPMCCCreate }

// LoadCommand is the input to TPM2_Load.
// See definition in Part 3, Commands, section 12.2
type LoadCommand struct {
	// handle of parent for new object
	ParentHandle AuthHandle `gotpm:"handle,auth"`
	// the private portion of the object
	InPrivate TPM2BPrivate
	// the public portion of the object
	InPublic TPM2BPublic
}

func (*LoadCommand) Command() TPMCC { return TPMCCLoad }

// LoadResponse is the response from TPM2_Load.
type LoadResponse struct {
	// handle of type TPM_HT_TRANSIENT for loaded object
	ObjectHandle TPMHandle `gotpm:"handle"`
	// Name of the loaded object
	Name TPM2BName
}

func (*LoadResponse) Response() TPMCC { return TPMCCLoad }

// UnsealCommand is the input to TPM2_Unseal.
// See definition in Part 3, Commands, section 12.7
type UnsealCommand struct {
	ItemHandle AuthHandle `gotpm:"handle,auth"`
}

func (*UnsealCommand) Command() TPMCC { return TPMCCUnseal }

// UnsealResponse is the response from TPM2_Unseal.
type UnsealResponse struct {
	OutData TPM2BSensitiveData
}

func (*UnsealResponse) Response() TPMCC { return TPMCCUnseal }

// QuoteCommand is the input to TPM2_Quote.
// See definition in Part 3, Commands, section 18.4
type QuoteCommand struct {
	// handle of key that will perform signature
	SignHandle AuthHandle `gotpm:"handle,auth"`
	// data supplied by the caller
	QualifyingData TPM2BData
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme TPMTSigScheme
	// PCR set to quote
	PCRSelect TPMLPCRSelection
}

func (*QuoteCommand) Command() TPMCC { return TPMCCQuote }

// QuoteResponse is the response from TPM2_Quote.
type QuoteResponse struct {
	// the quoted information
	Quoted TPM2BAttest
	// the signature over quoted
	Signature TPMTSignature
}

func (*QuoteResponse) Response() TPMCC { return TPMCCQuote }

// GetSessionAuditDigestCommand is the input to TPM2_GetSessionAuditDigest.
// See definition in Part 3, Commands, section 18.5
type GetSessionAuditDigestCommand struct {
	// handle of the privacy administrator (TPM_RH_ENDORSEMENT)
	PrivacyAdminHandle AuthHandle `gotpm:"handle,auth"`
	// handle of the signing key
	SignHandle AuthHandle `gotpm:"handle,auth"`
	// handle of the audit session
	SessionHandle TPMISHHMAC `gotpm:"handle"`
	// user-provided qualifying data – may be zero-length
	QualifyingData TPM2BData
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme TPMTSigScheme
}

func (*GetSessionAuditDigestCommand) Command() TPMCC { return TPMCCGetSessionAuditDigest }

// GetSessionAuditDigestResponse is the response from
// TPM2_GetSessionAuditDigest.
type GetSessionAuditDigestResponse struct {
	// the audit information that was signed
	AuditInfo TPM2BAttest
	// the signature over auditInfo
	Signature TPMTSignature
}

func (*GetSessionAuditDigestResponse) Response() TPMCC { return TPMCCGetSessionAuditDigest }

// PCRExtendCommand is the input to TPM2_PCR_Extend.
// See definition in Part 3, Commands, section 22.2
type PCRExtendCommand struct {
	// handle of the PCR
	PCRHandle AuthHandle `gotpm:"handle,auth"`
	// list of tagged digest values to be extended
	Digests TPMLDigestValues
}

func (*PCRExtendCommand) Command() TPMCC { return TPMCCPCRExtend }

// PCRExtendResponse is the response from TPM2_PCR_Extend.
type PCRExtendResponse struct {
}

func (*PCRExtendResponse) Response() TPMCC { return TPMCCPCRExtend }

// PCREventCommand is the input to TPM2_PCR_Event.
// See definition in Part 3, Commands, section 22.3
type PCREventCommand struct {
	// Handle of the PCR
	PCRHandle AuthHandle `gotpm:"handle,auth"`
	// Event data in sized buffer
	EventData TPM2BEvent
}

func (*PCREventCommand) Command() TPMCC { return TPMCCPCREvent }

// PCREventResponse is the response from TPM2_PCR_Event.
type PCREventResponse struct {
}

func (*PCREventResponse) Response() TPMCC { return TPMCCPCREvent }

// PCRReadCommand is the input to TPM2_PCR_Read.
// See definition in Part 3, Commands, section 22.4
type PCRReadCommand struct {
	// The selection of PCR to read
	PCRSelectionIn TPMLPCRSelection
}

func (*PCRReadCommand) Command() TPMCC { return TPMCCPCRRead }

// PCRReadResponse is the response from TPM2_PCR_Read.
type PCRReadResponse struct {
	// the current value of the PCR update counter
	PCRUpdateCounter uint32
	// the PCR in the returned list
	PCRSelectionOut TPMLPCRSelection
	// the contents of the PCR indicated in pcrSelectOut-> pcrSelection[] as tagged digests
	PCRValues TPMLDigest
}

func (*PCRReadResponse) Response() TPMCC { return TPMCCPCRRead }

// PolicySecret is the input to TPM2_PolicySecret.
// See definition in Part 3, Commands, section 23.4
type PolicySecretCommand struct {
	// handle for an entity providing the authorization
	AuthHandle AuthHandle `gotpm:"handle,auth"`
	// handle for the policy session being extended
	PolicySession TPMISHPolicy `gotpm:"handle"`
	// the policy nonce for the session
	NonceTPM TPM2BNonce
	// digest of the command parameters to which this authorization is limited
	CPHashA TPM2BDigest
	// a reference to a policy relating to the authorization – may be the Empty Buffer
	PolicyRef TPM2BNonce
	// time when authorization will expire, measured in seconds from the time
	// that nonceTPM was generated
	Expiration int32
}

func (*PolicySecretCommand) Command() TPMCC { return TPMCCPolicySecret }

// PolicySecretResponse is the response from TPM2_PolicySecret.
type PolicySecretResponse struct {
	// implementation-specific time value used to indicate to the TPM when the ticket expires
	Timeout TPM2BTimeout
	// produced if the command succeeds and expiration in the command was non-zero
	PolicyTicket TPMTTKAuth
}

func (*PolicySecretResponse) Response() TPMCC { return TPMCCPolicySecret }

// CreatePrimaryCommand is the input to TPM2_CreatePrimary.
// See definition in Part 3, Commands, section 24.1
type CreatePrimaryCommand struct {
	// TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP},
	// or TPM_RH_NULL
	PrimaryHandle AuthHandle `gotpm:"handle,auth"`
	// the sensitive data
	InSensitive TPM2BSensitiveCreate
	// the public template
	InPublic TPM2BPublic
	// data that will be included in the creation data for this
	// object to provide permanent, verifiable linkage between this
	// object and some object owner data
	OutsideInfo TPM2BData
	// PCR that will be used in creation data
	CreationPCR TPMLPCRSelection
}

func (*CreatePrimaryCommand) Command() TPMCC { return TPMCCCreatePrimary }

// CreatePrimaryResponse is the response from TPM2_CreatePrimary.
type CreatePrimaryResponse struct {
	// handle of type TPM_HT_TRANSIENT for created Primary Object
	ObjectHandle TPMHandle `gotpm:"handle"`
	// the public portion of the created object
	OutPublic TPM2BPublic
	// contains a TPMS_CREATION_DATA
	CreationData TPM2BCreationData
	// digest of creationData using nameAlg of outPublic
	CreationHash TPM2BDigest
	// ticket used by TPM2_CertifyCreation() to validate that the
	// creation data was produced by the TPM
	CreationTicket TPMTTKCreation
	// the name of the created object
	Name TPM2BName
}

func (*CreatePrimaryResponse) Response() TPMCC { return TPMCCCreatePrimary }

// FlushContextCommand is the input to TPM2_FlushContext.
// See definition in Part 3, Commands, section 28.4
type FlushContextCommand struct {
	// the handle of the item to flush
	FlushHandle TPMIDHContext
}

func (*FlushContextCommand) Command() TPMCC { return TPMCCFlushContext }

// FlushContextResponse is the response from TPM2_FlushContext.
type FlushContextResponse struct {
}

func (*FlushContextResponse) Response() TPMCC { return TPMCCFlushContext }

// GetCapabilityCommand is the input to TPM2_GetCapability.
// See definition in Part 3, Commands, section 30.2
type GetCapabilityCommand struct {
	// group selection; determines the format of the response
	Capability TPMCap
	// further definition of information
	Property uint32
	// number of properties of the indicated type to return
	PropertyCount uint32
}

func (*GetCapabilityCommand) Command() TPMCC { return TPMCCGetCapability }

// GetCapabilityResponse is the response from TPM2_GetCapability.
type GetCapabilityResponse struct {
	// flag to indicate if there are more values of this type
	MoreData TPMIYesNo
	// the capability data
	CapabilityData TPMSCapabilityData
}

func (*GetCapabilityResponse) Response() TPMCC { return TPMCCGetCapability }

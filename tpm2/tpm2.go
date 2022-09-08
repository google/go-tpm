// Package tpm2 contains TPM 2.0 commands and structures.
package tpm2

import (
	"bytes"
	"encoding/binary"

	"github.com/google/go-tpm/tpm2/transport"
)

// handle represents a TPM handle as comprehended in Part 3: Commands.
// In the context of TPM commands, handles are special parameters for which
// there is a known associated name.
// This is not an exported interface, because the reflection logic has special
// behavior for AuthHandle, due to the fact that referencing Session from this
// interface would break the ability to make TPMHandle implement it.
type handle interface {
	// HandleValue is the numeric concrete handle value in the TPM.
	HandleValue() uint32
	// KnownName is the TPM Name of the associated entity. See Part 1, section 16.
	KnownName() *TPM2BName
}

// NamedHandle represents an associated pairing of TPM handle and known Name.
type NamedHandle struct {
	Handle TPMHandle
	Name   TPM2BName
}

// HandleValue implements the handle interface.
func (h NamedHandle) HandleValue() uint32 {
	return h.Handle.HandleValue()
}

// KnownName implements the handle interface.
func (h NamedHandle) KnownName() *TPM2BName {
	return &h.Name
}

// AuthHandle allows the caller to add an authorization session onto a handle.
type AuthHandle struct {
	Handle TPMHandle
	Name   TPM2BName
	Auth   Session
}

// HandleValue implements the handle interface.
func (h AuthHandle) HandleValue() uint32 {
	return h.Handle.HandleValue()
}

// KnownName implements the handle interface.
// If Name is not provided (i.e., only Auth), then rely on the underlying
// TPMHandle.
func (h AuthHandle) KnownName() *TPM2BName {
	if len(h.Name.Buffer) != 0 {
		return &h.Name
	}
	return h.Handle.KnownName()
}

// Command is a placeholder interface for TPM command structures so that they
// can be easily distinguished from other types of structures.
// TODO: once go-tpm requires Go 1.18, parameterize this type for compile-time
// command/response matching.
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

// PolicyCommand is a TPM command that can be part of a TPM policy.
type PolicyCommand interface {
	// Update updates the given policy hash according to the command
	// parameters.
	Update(policy *PolicyCalculator) error
}

// Shutdown_ is the input to TPM2_Shutdown.
// See definition in Part 3, Commands, section 9.4.
// TODO: Rename this to Startup after adapter.go is deleted.
type Shutdown_ struct {
	// TPM_SU_CLEAR or TPM_SU_STATE
	ShutdownType TPMSU
}

// Command implements the Command interface.
func (*Shutdown_) Command() TPMCC { return TPMCCShutdown }

// Execute executes the command and returns the response.
func (cmd *Shutdown_) Execute(t transport.TPM, s ...Session) error {
	var rsp ShutdownResponse
	return execute(t, cmd, &rsp, s...)
}

// ShutdownResponse is the response from TPM2_Shutdown.
type ShutdownResponse struct{}

// Response implements the Response interface.
func (*ShutdownResponse) Response() TPMCC { return TPMCCShutdown }

// Startup_ is the input to TPM2_Startup.
// See definition in Part 3, Commands, section 9.3.
// TODO: Rename this to Startup after adapter.go is deleted.
type Startup_ struct {
	// TPM_SU_CLEAR or TPM_SU_STATE
	StartupType TPMSU
}

// Command implements the Command interface.
func (*Startup_) Command() TPMCC { return TPMCCStartup }

// Execute executes the command and returns the response.
func (cmd *Startup_) Execute(t transport.TPM, s ...Session) error {
	var rsp StartupResponse
	return execute(t, cmd, &rsp, s...)
}

// StartupResponse is the response from TPM2_Startup.
type StartupResponse struct{}

// Response implements the Response interface.
func (*StartupResponse) Response() TPMCC { return TPMCCStartup }

// StartAuthSession is the input to TPM2_StartAuthSession.
// See definition in Part 3, Commands, section 11.1
type StartAuthSession struct {
	// handle of a loaded decrypt key used to encrypt salt
	// may be TPM_RH_NULL
	TPMKey handle `gotpm:"handle,nullable"`
	// entity providing the authValue
	// may be TPM_RH_NULL
	Bind handle `gotpm:"handle,nullable"`
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
	// may select transport.TPM_ALG_NULL
	Symmetric TPMTSymDef
	// hash algorithm to use for the session
	// Shall be a hash algorithm supported by the TPM and not transport.TPM_ALG_NULL
	AuthHash TPMIAlgHash
}

// Command implements the Command interface.
func (*StartAuthSession) Command() TPMCC { return TPMCCStartAuthSession }

// Execute executes the command and returns the response.
func (cmd *StartAuthSession) Execute(t transport.TPM, s ...Session) (*StartAuthSessionResponse, error) {
	var rsp StartAuthSessionResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// StartAuthSessionResponse is the response from TPM2_StartAuthSession.
type StartAuthSessionResponse struct {
	// handle for the newly created session
	SessionHandle TPMISHAuthSession `gotpm:"handle"`
	// the initial nonce from the TPM, used in the computation of the sessionKey
	NonceTPM TPM2BNonce
}

// Response implements the Response interface.
func (*StartAuthSessionResponse) Response() TPMCC { return TPMCCStartAuthSession }

// Create is the input to TPM2_Create.
// See definition in Part 3, Commands, section 12.1
type Create struct {
	// handle of parent for new object
	ParentHandle handle `gotpm:"handle,auth"`
	// the sensitive data
	InSensitive tpm2bSensitiveCreate
	// the public template
	InPublic tpm2bPublic
	// data that will be included in the creation data for this
	// object to provide permanent, verifiable linkage between this
	// object and some object owner data
	OutsideInfo TPM2BData
	// PCR that will be used in creation data
	CreationPCR TPMLPCRSelection
}

// Command implements the Command interface.
func (*Create) Command() TPMCC { return TPMCCCreate }

// Execute executes the command and returns the response.
func (cmd *Create) Execute(t transport.TPM, s ...Session) (*CreateResponse, error) {
	var rsp CreateResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// CreateResponse is the response from TPM2_Create.
type CreateResponse struct {
	// the private portion of the object
	OutPrivate TPM2BPrivate
	// the public portion of the created object
	OutPublic tpm2bPublic
	// contains a TPMS_CREATION_DATA
	CreationData tpm2bCreationData
	// digest of creationData using nameAlg of outPublic
	CreationHash TPM2BDigest
	// ticket used by TPM2_CertifyCreation() to validate that the
	// creation data was produced by the TPM.
	CreationTicket TPMTTKCreation
}

// Response implements the Response interface.
func (*CreateResponse) Response() TPMCC { return TPMCCCreate }

// Load is the input to TPM2_Load.
// See definition in Part 3, Commands, section 12.2
type Load struct {
	// handle of parent for new object
	ParentHandle handle `gotpm:"handle,auth"`
	// the private portion of the object
	InPrivate TPM2BPrivate
	// the public portion of the object
	InPublic tpm2bPublic
}

// Command implements the Command interface.
func (*Load) Command() TPMCC { return TPMCCLoad }

// Execute executes the command and returns the response.
func (cmd *Load) Execute(t transport.TPM, s ...Session) (*LoadResponse, error) {
	var rsp LoadResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// LoadResponse is the response from TPM2_Load.
type LoadResponse struct {
	// handle of type TPM_HT_TRANSIENT for loaded object
	ObjectHandle TPMHandle `gotpm:"handle"`
	// Name of the loaded object
	Name TPM2BName
}

// Response implements the Response interface.
func (*LoadResponse) Response() TPMCC { return TPMCCLoad }

// LoadExternal is the input to TPM2_LoadExternal.
// See definition in Part 3, Commands, section 12.3
type LoadExternal struct {
	// the sensitive portion of the object (optional)
	InPrivate tpm2bSensitive `gotpm:"optional"`
	// the public portion of the object
	InPublic tpm2bPublic
	// hierarchy with which the object area is associated
	Hierarchy TPMIRHHierarchy `gotpm:"nullable"`
}

// Command implements the Command interface.
func (*LoadExternal) Command() TPMCC { return TPMCCLoadExternal }

// Execute executes the command and returns the response.
func (cmd *LoadExternal) Execute(t transport.TPM, s ...Session) (*LoadExternalResponse, error) {
	var rsp LoadExternalResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// LoadExternalResponse is the response from TPM2_LoadExternal.
type LoadExternalResponse struct {
	// handle of type TPM_HT_TRANSIENT for loaded object
	ObjectHandle TPMHandle `gotpm:"handle"`
	// Name of the loaded object
	Name TPM2BName
}

// Response implements the Response interface.
func (*LoadExternalResponse) Response() TPMCC { return TPMCCLoadExternal }

// ReadPublic is the input to TPM2_ReadPublic.
// See definition in Part 3, Commands, section 12.4
type ReadPublic struct {
	// TPM handle of an object
	ObjectHandle TPMIDHObject `gotpm:"handle"`
}

// Command implements the Command interface.
func (*ReadPublic) Command() TPMCC { return TPMCCReadPublic }

// Execute executes the command and returns the response.
func (cmd *ReadPublic) Execute(t transport.TPM, s ...Session) (*ReadPublicResponse, error) {
	var rsp ReadPublicResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// ReadPublicResponse is the response from TPM2_ReadPublic.
type ReadPublicResponse struct {
	// structure containing the public area of an object
	OutPublic tpm2bPublic
	// name of object
	Name TPM2BName
	// the Qualified Name of the object
	QualifiedName TPM2BName
}

// Response implements the Response interface.
func (*ReadPublicResponse) Response() TPMCC { return TPMCCReadPublic }

// ActivateCredential is the input to TPM2_ActivateCredential.
// See definition in Part 3, Commands, section 12.5.
type ActivateCredential struct {
	// handle of the object associated with certificate in credentialBlob
	ActivateHandle handle `gotpm:"handle,auth"`
	// loaded key used to decrypt the TPMS_SENSITIVE in credentialBlob
	KeyHandle handle `gotpm:"handle,auth"`
	// the credential
	CredentialBlob TPM2BIDObject
	// keyHandle algorithm-dependent encrypted seed that protects credentialBlob
	Secret TPM2BEncryptedSecret
}

// Command implements the Command interface.
func (*ActivateCredential) Command() TPMCC { return TPMCCActivateCredential }

// Execute executes the command and returns the response.
func (cmd *ActivateCredential) Execute(t transport.TPM, s ...Session) (*ActivateCredentialResponse, error) {
	var rsp ActivateCredentialResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// ActivateCredentialResponse is the response from TPM2_ActivateCredential.
type ActivateCredentialResponse struct {
	// the decrypted certificate information
	CertInfo TPM2BDigest
}

// Response implements the Response interface.
func (*ActivateCredentialResponse) Response() TPMCC { return TPMCCActivateCredential }

// MakeCredential is the input to TPM2_MakeCredential.
// See definition in Part 3, Commands, section 12.6.
type MakeCredential struct {
	// loaded public area, used to encrypt the sensitive area containing the credential key
	Handle TPMIDHObject `gotpm:"handle"`
	// the credential information
	Credential TPM2BDigest
	// Name of the object to which the credential applies
	ObjectNamae TPM2BName
}

// Command implements the Command interface.
func (*MakeCredential) Command() TPMCC { return TPMCCMakeCredential }

// Execute executes the command and returns the response.
func (cmd *MakeCredential) Execute(t transport.TPM, s ...Session) (*MakeCredentialResponse, error) {
	var rsp MakeCredentialResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// MakeCredentialResponse is the response from TPM2_MakeCredential.
type MakeCredentialResponse struct {
	// the credential
	CredentialBlob TPM2BIDObject
	// handle algorithm-dependent data that wraps the key that encrypts credentialBlob
	Secret TPM2BEncryptedSecret
}

// Response implements the Response interface.
func (*MakeCredentialResponse) Response() TPMCC { return TPMCCMakeCredential }

// Unseal is the input to TPM2_Unseal.
// See definition in Part 3, Commands, section 12.7
type Unseal struct {
	ItemHandle handle `gotpm:"handle,auth"`
}

// Command implements the Command interface.
func (*Unseal) Command() TPMCC { return TPMCCUnseal }

// Execute executes the command and returns the response.
func (cmd *Unseal) Execute(t transport.TPM, s ...Session) (*UnsealResponse, error) {
	var rsp UnsealResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// UnsealResponse is the response from TPM2_Unseal.
type UnsealResponse struct {
	OutData TPM2BSensitiveData
}

// Response implements the Response interface.
func (*UnsealResponse) Response() TPMCC { return TPMCCUnseal }

// CreateLoaded is the input to TPM2_CreateLoaded.
// See definition in Part 3, Commands, section 12.9
type CreateLoaded struct {
	// Handle of a transient storage key, a persistent storage key,
	// TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL
	ParentHandle handle `gotpm:"handle,auth,nullable"`
	// the sensitive data, see TPM 2.0 Part 1 Sensitive Values
	InSensitive tpm2bSensitiveCreate
	// the public template
	InPublic tpm2bTemplate
}

// Command implements the Command interface.
func (*CreateLoaded) Command() TPMCC { return TPMCCCreateLoaded }

// Execute executes the command and returns the response.
func (cmd *CreateLoaded) Execute(t transport.TPM, s ...Session) (*CreateLoadedResponse, error) {
	var rsp CreateLoadedResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// CreateLoadedResponse is the response from TPM2_CreateLoaded.
type CreateLoadedResponse struct {
	// handle of type TPM_HT_TRANSIENT for loaded object
	ObjectHandle TPMHandle `gotpm:"handle"`
	// the sensitive area of the object (optional)
	OutPrivate TPM2BPrivate `gotpm:"optional"`
	// the public portion of the created object
	OutPublic tpm2bPublic
	// the name of the created object
	Name TPM2BName
}

// Response implements the Response interface.
func (*CreateLoadedResponse) Response() TPMCC { return TPMCCCreateLoaded }

// ECDHZGen is the input to TPM2_ECDHZGen.
// See definition in Part 3, Commands, section 14.5
type ECDHZGen struct {
	// handle of a loaded ECC key
	KeyHandle handle `gotpm:"handle,auth"`
	// a public key
	InPoint tpm2bECCPoint
}

// Command implements the Command interface.
func (*ECDHZGen) Command() TPMCC { return TPMCCECDHZGen }

// Execute executes the command and returns the response.
func (cmd *ECDHZGen) Execute(t transport.TPM, s ...Session) (*ECDHZGenResponse, error) {
	var rsp ECDHZGenResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// ECDHZGenResponse is the response from TPM2_ECDHZGen.
type ECDHZGenResponse struct {
	// X and Y coordinates of the product of the multiplication
	OutPoint tpm2bECCPoint
}

// Response implements the Response interface.
func (*ECDHZGenResponse) Response() TPMCC { return TPMCCECDHZGen }

// Hash is the input to TPM2_Hash.
// See definition in Part 3, Commands, section 15.4
type Hash struct {
	//data to be hashed
	Data TPM2BMaxBuffer
	// algorithm for the hash being computed - shall not be TPM_ALH_NULL
	HashAlg TPMIAlgHash
	// hierarchy to use for the ticket (TPM_RH_NULL_allowed)
	Hierarchy TPMIRHHierarchy `gotpm:"nullable"`
}

// Command implements the Command interface.
func (*Hash) Command() TPMCC { return TPMCCHash }

// Execute executes the command and returns the response.
func (cmd *Hash) Execute(t transport.TPM, s ...Session) (*HashResponse, error) {
	var rsp HashResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// HashResponse is the response from TPM2_Hash.
type HashResponse struct {
	// results
	OutHash TPM2BDigest
	// ticket indicating that the sequence of octets used to
	// compute outDigest did not start with TPM_GENERATED_VALUE
	Validation TPMTTKHashCheck
}

// Response implements the Response interface.
func (*HashResponse) Response() TPMCC { return TPMCCHash }

// GetRandom is the input to TPM2_GetRandom.
// See definition in Part 3, Commands, section 16.1
type GetRandom struct {
	// number of octets to return
	BytesRequested uint16
}

// Command implements the Command interface.
func (*GetRandom) Command() TPMCC { return TPMCCGetRandom }

// Execute executes the command and returns the response.
func (cmd *GetRandom) Execute(t transport.TPM, s ...Session) (*GetRandomResponse, error) {
	var rsp GetRandomResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// GetRandomResponse is the response from TPM2_GetRandom.
type GetRandomResponse struct {
	// the random octets
	RandomBytes TPM2BDigest
}

// Response implements the Response interface.
func (*GetRandomResponse) Response() TPMCC { return TPMCCGetRandom }

// HashSequenceStart is the input to TPM2_HashSequenceStart.
// See definition in Part 3, Commands, section 17.3
type HashSequenceStart struct {
	// authorization value for subsequent use of the sequence
	Auth TPM2BAuth
	// the hash algorithm to use for the hash sequence
	// An Event Sequence starts if this is TPM_ALG_NULL.
	HashAlg TPMIAlgHash
}

// Command implements the Command interface.
func (*HashSequenceStart) Command() TPMCC { return TPMCCHashSequenceStart }

// Execute executes the command and returns the response.
func (cmd *HashSequenceStart) Execute(t transport.TPM, s ...Session) (*HashSequenceStartResponse, error) {
	var rsp HashSequenceStartResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// HashSequenceStartResponse is the response from TPM2_StartHashSequence.
type HashSequenceStartResponse struct {
	// a handle to reference the sequence
	SequenceHandle TPMIDHObject
}

// Response implements the Response interface.
func (*HashSequenceStartResponse) Response() TPMCC { return TPMCCHashSequenceStart }

// SequenceUpdate is the input to TPM2_SequenceUpdate.
// See definition in Part 3, Commands, section 17.4
type SequenceUpdate struct {
	// handle for the sequence object
	SequenceHandle handle `gotpm:"handle,auth"`
	// data to be added to hash
	Buffer TPM2BMaxBuffer
}

// Command implements the Command interface.
func (*SequenceUpdate) Command() TPMCC { return TPMCCSequenceUpdate }

// Execute executes the command and returns the response.
func (cmd *SequenceUpdate) Execute(t transport.TPM, s ...Session) (*SequenceUpdateResponse, error) {
	var rsp SequenceUpdateResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// SequenceUpdateResponse is the response from TPM2_SequenceUpdate.
type SequenceUpdateResponse struct{}

// Response implements the Response interface.
func (*SequenceUpdateResponse) Response() TPMCC { return TPMCCSequenceUpdate }

// SequenceComplete is the input to TPM2_SequenceComplete.
// See definition in Part 3, Commands, section 17.5
type SequenceComplete struct {
	// authorization for the sequence
	SequenceHandle handle `gotpm:"handle,auth"`
	// data to be added to the hash/HMAC
	Buffer TPM2BMaxBuffer
	// hierarchy of the ticket for a hash
	Hierarchy TPMIRHHierarchy `gotpm:"nullable"`
}

// Command implements the Command interface.
func (*SequenceComplete) Command() TPMCC { return TPMCCSequenceComplete }

// Execute executes the command and returns the response.
func (cmd *SequenceComplete) Execute(t transport.TPM, s ...Session) (*SequenceCompleteResponse, error) {
	var rsp SequenceCompleteResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// SequenceCompleteResponse is the response from TPM2_SequenceComplete.
type SequenceCompleteResponse struct {
	// the returned HMAC or digest in a sized buffer
	Result TPM2BDigest
	// 	ticket indicating that the sequence of octets used to
	// compute outDigest did not start with TPM_GENERATED_VALUE
	Validation TPMTTKHashCheck
}

// Response implements the Response interface.
func (*SequenceCompleteResponse) Response() TPMCC { return TPMCCSequenceComplete }

// Certify is the input to TPM2_Certify.
// See definition in Part 3, Commands, section 18.2.
type Certify struct {
	// handle of the object to be certified
	ObjectHandle handle `gotpm:"handle,auth"`
	// handle of the key used to sign the attestation structure
	SignHandle handle `gotpm:"handle,auth"`
	// user provided qualifying data
	QualifyingData TPM2BData
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme TPMTSigScheme
}

// Command implements the Command interface.
func (*Certify) Command() TPMCC { return TPMCCCertify }

// Execute executes the command and returns the response.
func (cmd *Certify) Execute(t transport.TPM, s ...Session) (*CertifyResponse, error) {
	var rsp CertifyResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// CertifyResponse is the response from TPM2_Certify.
type CertifyResponse struct {
	// the structure that was signed
	CertifyInfo tpm2bAttest
	// the asymmetric signature over certifyInfo using the key referenced by signHandle
	Signature TPMTSignature
}

// Response implements the Response interface.
func (*CertifyResponse) Response() TPMCC { return TPMCCCertify }

// CertifyCreation is the input to TPM2_CertifyCreation.
// See definition in Part 3, Commands, section 18.3.
type CertifyCreation struct {
	// handle of the key that will sign the attestation block
	SignHandle handle `gotpm:"handle,auth"`
	// the object associated with the creation data
	ObjectHandle handle `gotpm:"handle"`
	// user-provided qualifying data
	QualifyingData TPM2BData
	// hash of the creation data produced by TPM2_Create() or TPM2_CreatePrimary()
	CreationHash TPM2BDigest
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme TPMTSigScheme
	// ticket produced by TPM2_Create() or TPM2_CreatePrimary()
	CreationTicket TPMTTKCreation
}

// Command implements the Command interface.
func (*CertifyCreation) Command() TPMCC { return TPMCCCertifyCreation }

// Execute executes the command and returns the response.
func (cmd *CertifyCreation) Execute(t transport.TPM, s ...Session) (*CertifyCreationResponse, error) {
	var rsp CertifyCreationResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// CertifyCreationResponse is the response from TPM2_CertifyCreation.
type CertifyCreationResponse struct {
	// the structure that was signed
	CertifyInfo tpm2bAttest
	// the signature over certifyInfo
	Signature TPMTSignature
}

// Response implements the Response interface.
func (*CertifyCreationResponse) Response() TPMCC { return TPMCCCertifyCreation }

// Quote is the input to TPM2_Quote.
// See definition in Part 3, Commands, section 18.4
type Quote struct {
	// handle of key that will perform signature
	SignHandle handle `gotpm:"handle,auth"`
	// data supplied by the caller
	QualifyingData TPM2BData
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme TPMTSigScheme
	// PCR set to quote
	PCRSelect TPMLPCRSelection
}

// Command implements the Command interface.
func (*Quote) Command() TPMCC { return TPMCCQuote }

// Execute executes the command and returns the response.
func (cmd *Quote) Execute(t transport.TPM, s ...Session) (*QuoteResponse, error) {
	var rsp QuoteResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// QuoteResponse is the response from TPM2_Quote.
type QuoteResponse struct {
	// the quoted information
	Quoted tpm2bAttest
	// the signature over quoted
	Signature TPMTSignature
}

// Response implements the Response interface.
func (*QuoteResponse) Response() TPMCC { return TPMCCQuote }

// GetSessionAuditDigest is the input to TPM2_GetSessionAuditDigest.
// See definition in Part 3, Commands, section 18.5
type GetSessionAuditDigest struct {
	// handle of the privacy administrator (TPM_RH_ENDORSEMENT)
	PrivacyAdminHandle handle `gotpm:"handle,auth"`
	// handle of the signing key
	SignHandle handle `gotpm:"handle,auth"`
	// handle of the audit session
	SessionHandle handle `gotpm:"handle"`
	// user-provided qualifying data – may be zero-length
	QualifyingData TPM2BData
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme TPMTSigScheme
}

// Command implements the Command interface.
func (*GetSessionAuditDigest) Command() TPMCC { return TPMCCGetSessionAuditDigest }

// Execute executes the command and returns the response.
func (cmd *GetSessionAuditDigest) Execute(t transport.TPM, s ...Session) (*GetSessionAuditDigestResponse, error) {
	var rsp GetSessionAuditDigestResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// GetSessionAuditDigestResponse is the response from
// TPM2_GetSessionAuditDigest.
type GetSessionAuditDigestResponse struct {
	// the audit information that was signed
	AuditInfo tpm2bAttest
	// the signature over auditInfo
	Signature TPMTSignature
}

// Response implements the Response interface.
func (*GetSessionAuditDigestResponse) Response() TPMCC { return TPMCCGetSessionAuditDigest }

// Commit is the input to TPM2_Commit.
// See definition in Part 3, Commands, section 19.2.
type Commit struct {
	// handle of the key that will be used in the signing operation
	SignHandle handle `gotpm:"handle,auth"`
	// a point (M) on the curve used by signHandle
	P1 tpm2bECCPoint
	// octet array used to derive x-coordinate of a base point
	S2 TPM2BSensitiveData
	// y coordinate of the point associated with s2
	Y2 TPM2BECCParameter
}

// Command implements the Command interface.
func (*Commit) Command() TPMCC { return TPMCCCommit }

// Execute executes the command and returns the response.
func (cmd *Commit) Execute(t transport.TPM, s ...Session) (*CommitResponse, error) {
	var rsp CommitResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}

	return &rsp, nil
}

// CommitResponse is the response from TPM2_Commit.
type CommitResponse struct {
	// ECC point K ≔ [ds](x2, y2)
	K tpm2bECCPoint
	// ECC point L ≔ [r](x2, y2)
	L tpm2bECCPoint
	// ECC point E ≔ [r]P1
	E tpm2bECCPoint
	// least-significant 16 bits of commitCount
	Counter uint16
}

// Response implements the Response interface.
func (*CommitResponse) Response() TPMCC { return TPMCCCommit }

// VerifySignature is the input to TPM2_VerifySignature.
// See definition in Part 3, Commands, section 20.1
type VerifySignature struct {
	// handle of public key that will be used in the validation
	KeyHandle handle `gotpm:"handle"`
	// digest of the signed message
	Digest TPM2BDigest
	// signature to be tested
	Signature TPMTSignature
}

// Command implements the Command interface.
func (*VerifySignature) Command() TPMCC { return TPMCCVerifySignature }

// Execute executes the command and returns the response.
func (cmd *VerifySignature) Execute(t transport.TPM, s ...Session) (*VerifySignatureResponse, error) {
	var rsp VerifySignatureResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// VerifySignatureResponse is the response from TPM2_VerifySignature.
type VerifySignatureResponse struct {
	Validation TPMTTKVerified
}

// Response implements the Response interface.
func (*VerifySignatureResponse) Response() TPMCC { return TPMCCVerifySignature }

// Sign is the input to TPM2_Sign.
// See definition in Part 3, Commands, section 20.2.
type Sign struct {
	// Handle of key that will perform signing
	KeyHandle handle `gotpm:"handle,auth"`
	// digest to be signed
	Digest TPM2BDigest
	// signing scheme to use if the scheme for keyHandle is TPM_ALG_NULL
	InScheme TPMTSigScheme `gotpm:"nullable"`
	// proof that digest was created by the TPM.
	// If keyHandle is not a restricted signing key, then this
	// may be a NULL Ticket with tag = TPM_ST_CHECKHASH.
	Validation TPMTTKHashCheck
}

// Command implements the Command interface.
func (*Sign) Command() TPMCC { return TPMCCSign }

// Execute executes the command and returns the response.
func (cmd *Sign) Execute(t transport.TPM, s ...Session) (*SignResponse, error) {
	var rsp SignResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// SignResponse is the response from TPM2_Sign.
type SignResponse struct {
	// the signature
	Signature TPMTSignature
}

// Response implements the Response interface.
func (*SignResponse) Response() TPMCC { return TPMCCSign }

// PCRExtend is the input to TPM2_PCR_Extend.
// See definition in Part 3, Commands, section 22.2
type PCRExtend struct {
	// handle of the PCR
	PCRHandle handle `gotpm:"handle,auth"`
	// list of tagged digest values to be extended
	Digests TPMLDigestValues
}

// Command implements the Command interface.
func (*PCRExtend) Command() TPMCC { return TPMCCPCRExtend }

// Execute executes the command and returns the response.
func (cmd *PCRExtend) Execute(t transport.TPM, s ...Session) error {
	var rsp PCRExtendResponse
	return execute(t, cmd, &rsp, s...)
}

// PCRExtendResponse is the response from TPM2_PCR_Extend.
type PCRExtendResponse struct{}

// Response implements the Response interface.
func (*PCRExtendResponse) Response() TPMCC { return TPMCCPCRExtend }

// PCREvent is the input to TPM2_PCR_Event.
// See definition in Part 3, Commands, section 22.3
type PCREvent struct {
	// Handle of the PCR
	PCRHandle handle `gotpm:"handle,auth"`
	// Event data in sized buffer
	EventData TPM2BEvent
}

// Command implements the Command interface.
func (*PCREvent) Command() TPMCC { return TPMCCPCREvent }

// Execute executes the command and returns the response.
func (cmd *PCREvent) Execute(t transport.TPM, s ...Session) error {
	var rsp PCREventResponse
	return execute(t, cmd, &rsp, s...)
}

// PCREventResponse is the response from TPM2_PCR_Event.
type PCREventResponse struct{}

// Response implements the Response interface.
func (*PCREventResponse) Response() TPMCC { return TPMCCPCREvent }

// PCRRead is the input to TPM2_PCR_Read.
// See definition in Part 3, Commands, section 22.4
type PCRRead struct {
	// The selection of PCR to read
	PCRSelectionIn TPMLPCRSelection
}

// Command implements the Command interface.
func (*PCRRead) Command() TPMCC { return TPMCCPCRRead }

// Execute executes the command and returns the response.
func (cmd *PCRRead) Execute(t transport.TPM, s ...Session) (*PCRReadResponse, error) {
	var rsp PCRReadResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// PCRReadResponse is the response from TPM2_PCR_Read.
type PCRReadResponse struct {
	// the current value of the PCR update counter
	PCRUpdateCounter uint32
	// the PCR in the returned list
	PCRSelectionOut TPMLPCRSelection
	// the contents of the PCR indicated in pcrSelectOut-> pcrSelection[] as tagged digests
	PCRValues TPMLDigest
}

// Response implements the Response interface.
func (*PCRReadResponse) Response() TPMCC { return TPMCCPCRRead }

// PCRReset is the input to TPM2_PCRReset.
// See definition in Part 3, Commands, section 22.8.
type PCRReset struct {
	// the PCR to reset
	PCRHandle handle `gotpm:"handle,auth"`
}

// Command implements the Command interface.
func (*PCRReset) Command() TPMCC { return TPMCCPCRReset }

// Execute executes the command and returns the response.
func (cmd *PCRReset) Execute(t transport.TPM, s ...Session) (*PCRResetResponse, error) {
	var rsp PCRResetResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// PCRResetResponse is the response from TPM2_PCRReset.
type PCRResetResponse struct{}

// Response implements the Response interface.
func (*PCRResetResponse) Response() TPMCC { return TPMCCPCRReset }

// PolicySigned is the input to TPM2_PolicySigned.
// See definition in Part 3, Commands, section 23.3.
type PolicySigned struct {
	// handle for an entity providing the authorization
	AuthObject handle `gotpm:"handle"`
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// the policy nonce for the session
	NonceTPM TPM2BNonce
	// digest of the command parameters to which this authorization is limited
	CPHashA TPM2BDigest
	// a reference to a policy relating to the authorization – may be the Empty Buffer
	PolicyRef TPM2BNonce
	// time when authorization will expire, measured in seconds from the time
	// that nonceTPM was generated
	Expiration int32
	// signed authorization (not optional)
	Auth TPMTSignature
}

// Command implements the Command interface.
func (*PolicySigned) Command() TPMCC { return TPMCCPolicySigned }

// Execute executes the command and returns the response.
func (cmd *PolicySigned) Execute(t transport.TPM, s ...Session) (*PolicySignedResponse, error) {
	var rsp PolicySignedResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// policyUpdate implements the PolicyUpdate helper for the several TPM policy
// commands as described in Part 3, 23.2.3.
func policyUpdate(policy *PolicyCalculator, cc TPMCC, arg2, arg3 []byte) error {
	if err := policy.Update(cc, arg2); err != nil {
		return err
	}
	return policy.Update(arg3)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicySigned) Update(policy *PolicyCalculator) error {
	return policyUpdate(policy, TPMCCPolicySigned, cmd.AuthObject.KnownName().Buffer, cmd.PolicyRef.Buffer)
}

// PolicySignedResponse is the response from TPM2_PolicySigned.
type PolicySignedResponse struct {
	// implementation-specific time value used to indicate to the TPM when the ticket expires
	Timeout TPM2BTimeout
	// produced if the command succeeds and expiration in the command was non-zero
	PolicyTicket TPMTTKAuth
}

// Response implements the Response interface.
func (*PolicySignedResponse) Response() TPMCC { return TPMCCPolicySigned }

// PolicySecret is the input to TPM2_PolicySecret.
// See definition in Part 3, Commands, section 23.4.
type PolicySecret struct {
	// handle for an entity providing the authorization
	AuthHandle handle `gotpm:"handle,auth"`
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
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

// Command implements the Command interface.
func (*PolicySecret) Command() TPMCC { return TPMCCPolicySecret }

// Execute executes the command and returns the response.
func (cmd *PolicySecret) Execute(t transport.TPM, s ...Session) (*PolicySecretResponse, error) {
	var rsp PolicySecretResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// Update implements the PolicyCommand interface.
func (cmd *PolicySecret) Update(policy *PolicyCalculator) {
	policyUpdate(policy, TPMCCPolicySecret, cmd.AuthHandle.KnownName().Buffer, cmd.PolicyRef.Buffer)
}

// PolicySecretResponse is the response from TPM2_PolicySecret.
type PolicySecretResponse struct {
	// implementation-specific time value used to indicate to the TPM when the ticket expires
	Timeout TPM2BTimeout
	// produced if the command succeeds and expiration in the command was non-zero
	PolicyTicket TPMTTKAuth
}

// Response implements the Response interface.
func (*PolicySecretResponse) Response() TPMCC { return TPMCCPolicySecret }

// PolicyOr is the input to TPM2_PolicyOR.
// See definition in Part 3, Commands, section 23.6.
type PolicyOr struct {
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// the list of hashes to check for a match
	PHashList TPMLDigest
}

// Command implements the Command interface.
func (*PolicyOr) Command() TPMCC { return TPMCCPolicyOR }

// Execute executes the command and returns the response.
func (cmd *PolicyOr) Execute(t transport.TPM, s ...Session) error {
	var rsp PolicyOrResponse
	return execute(t, cmd, &rsp, s...)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyOr) Update(policy *PolicyCalculator) error {
	policy.Reset()
	var digests bytes.Buffer
	for _, digest := range cmd.PHashList.Digests {
		digests.Write(digest.Buffer)
	}
	return policy.Update(TPMCCPolicyOR, digests.Bytes())
}

// PolicyOrResponse is the response from TPM2_PolicyOr.
type PolicyOrResponse struct{}

// Response implements the Response interface.
func (*PolicyOrResponse) Response() TPMCC { return TPMCCPolicyOR }

// PolicyPCR is the input to TPM2_PolicyPCR.
// See definition in Part 3, Commands, section 23.7.
type PolicyPCR struct {
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// expected digest value of the selected PCR using the
	// hash algorithm of the session; may be zero length
	PcrDigest TPM2BDigest
	// the PCR to include in the check digest
	Pcrs TPMLPCRSelection
}

// Command implements the Command interface.
func (*PolicyPCR) Command() TPMCC { return TPMCCPolicyPCR }

// Execute executes the command and returns the response.
func (cmd *PolicyPCR) Execute(t transport.TPM, s ...Session) error {
	var rsp PolicyPCRResponse
	return execute(t, cmd, &rsp, s...)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyPCR) Update(policy *PolicyCalculator) error {
	return policy.Update(TPMCCPolicyPCR, cmd.Pcrs, cmd.PcrDigest.Buffer)
}

// PolicyPCRResponse is the response from TPM2_PolicyPCR.
type PolicyPCRResponse struct{}

// Response implements the Response interface.
func (*PolicyPCRResponse) Response() TPMCC { return TPMCCPolicyPCR }

// PolicyNV is the input to TPM2_PolicyNV.
// See definition in Part 3, Commands, section 23.9.
type PolicyNV struct {
	// handle indicating the source of the authorization value
	AuthHandle handle `gotpm:"handle,auth"`
	// the NV Index of the area to read
	NVIndex handle `gotpm:"handle"`
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// the second operand
	OperandB TPM2BOperand
	// the octet offset in the NV Index for the start of operand A
	Offset uint16
	// the comparison to make
	Operation TPMEO
}

// Command implements the Command interface.
func (*PolicyNV) Command() TPMCC { return TPMCCPolicyNV }

// Execute executes the command and returns the response.
func (cmd *PolicyNV) Execute(t transport.TPM, s ...Session) error {
	var rsp PolicyNVResponse
	return execute(t, cmd, &rsp, s...)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyNV) Update(policy *PolicyCalculator) error {
	alg, err := policy.alg.Hash()
	if err != nil {
		return err
	}
	h := alg.New()
	h.Write(cmd.OperandB.Buffer)
	binary.Write(h, binary.BigEndian, cmd.Offset)
	binary.Write(h, binary.BigEndian, cmd.Operation)
	args := h.Sum(nil)
	return policy.Update(TPMCCPolicyNV, args, cmd.NVIndex.KnownName().Buffer)
}

// PolicyNVResponse is the response from TPM2_PolicyPCR.
type PolicyNVResponse struct{}

// Response implements the Response interface.
func (*PolicyNVResponse) Response() TPMCC { return TPMCCPolicyNV }

// PolicyCommandCode is the input to TPM2_PolicyCommandCode.
// See definition in Part 3, Commands, section 23.11.
type PolicyCommandCode struct {
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// the allowed commandCode
	Code TPMCC
}

// Command implements the Command interface.
func (*PolicyCommandCode) Command() TPMCC { return TPMCCPolicyCommandCode }

// Execute executes the command and returns the response.
func (cmd *PolicyCommandCode) Execute(t transport.TPM, s ...Session) error {
	var rsp PolicyCommandCodeResponse
	return execute(t, cmd, &rsp, s...)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyCommandCode) Update(policy *PolicyCalculator) error {
	return policy.Update(TPMCCPolicyCommandCode, cmd.Code)
}

// PolicyCommandCodeResponse is the response from TPM2_PolicyCommandCode.
type PolicyCommandCodeResponse struct{}

// Response implements the Response interface.
func (*PolicyCommandCodeResponse) Response() TPMCC { return TPMCCPolicyCommandCode }

// PolicyCPHash is the input to TPM2_PolicyCpHash.
// See definition in Part 3, Commands, section 23.13.
type PolicyCPHash struct {
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// the cpHash added to the policy
	CPHashA TPM2BDigest
}

// Command implements the Command interface.
func (*PolicyCPHash) Command() TPMCC { return TPMCCPolicyCpHash }

// Execute executes the command and returns the response.
func (cmd *PolicyCPHash) Execute(t transport.TPM, s ...Session) error {
	var rsp PolicyCPHashResponse
	return execute(t, cmd, &rsp, s...)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyCPHash) Update(policy *PolicyCalculator) error {
	return policy.Update(TPMCCPolicyCpHash, cmd.CPHashA.Buffer)
}

// PolicyCPHashResponse is the response from TPM2_PolicyCpHash.
type PolicyCPHashResponse struct{}

// Response implements the Response interface.
func (*PolicyCPHashResponse) Response() TPMCC { return TPMCCPolicyCpHash }

// PolicyAuthorize is the input to TPM2_PolicySigned.
// See definition in Part 3, Commands, section 23.16.
type PolicyAuthorize struct {
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// digest of the policy being approved
	ApprovedPolicy TPM2BDigest
	// a policy qualifier
	PolicyRef TPM2BDigest
	// Name of a key that can sign a policy addition
	KeySign TPM2BName
	// ticket validating that approvedPolicy and policyRef were signed by keySign
	CheckTicket TPMTTKVerified
}

// Command implements the Command interface.
func (*PolicyAuthorize) Command() TPMCC { return TPMCCPolicyAuthorize }

// Execute executes the command and returns the response.
func (cmd *PolicyAuthorize) Execute(t transport.TPM, s ...Session) error {
	var rsp PolicyAuthorizeResponse
	return execute(t, cmd, &rsp, s...)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyAuthorize) Update(policy *PolicyCalculator) error {
	return policyUpdate(policy, TPMCCPolicyAuthorize, cmd.KeySign.Buffer, cmd.PolicyRef.Buffer)
}

// PolicyAuthorizeResponse is the response from TPM2_PolicyAuthorize.
type PolicyAuthorizeResponse struct{}

// Response implements the Response interface.
func (*PolicyAuthorizeResponse) Response() TPMCC { return TPMCCPolicyAuthorize }

// PolicyGetDigest is the input to TPM2_PolicyGetDigest.
// See definition in Part 3, Commands, section 23.19.
type PolicyGetDigest struct {
	// handle for the policy session
	PolicySession handle `gotpm:"handle"`
}

// Command implements the Command interface.
func (*PolicyGetDigest) Command() TPMCC { return TPMCCPolicyGetDigest }

// Execute executes the command and returns the response.
func (cmd *PolicyGetDigest) Execute(t transport.TPM, s ...Session) (*PolicyGetDigestResponse, error) {
	var rsp PolicyGetDigestResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// PolicyGetDigestResponse is the response from TPM2_PolicyGetDigest.
type PolicyGetDigestResponse struct {
	// the current value of the policySession→policyDigest
	PolicyDigest TPM2BDigest
}

// Response implements the Response interface.
func (*PolicyGetDigestResponse) Response() TPMCC { return TPMCCPolicyGetDigest }

// PolicyNVWritten is the input to TPM2_PolicyNvWritten.
// See definition in Part 3, Commands, section 23.20.
type PolicyNVWritten struct {
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// YES if NV Index is required to have been written
	// NO if NV Index is required not to have been written
	WrittenSet TPMIYesNo
}

// Command implements the Command interface.
func (*PolicyNVWritten) Command() TPMCC { return TPMCCPolicyNvWritten }

// Execute executes the command and returns the response.
func (cmd *PolicyNVWritten) Execute(t transport.TPM, s ...Session) (*PolicyNVWrittenResponse, error) {
	var rsp PolicyNVWrittenResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyNVWritten) Update(policy *PolicyCalculator) error {
	return policy.Update(TPMCCPolicyNvWritten, cmd.WrittenSet)
}

// PolicyNVWrittenResponse is the response from TPM2_PolicyNvWritten.
type PolicyNVWrittenResponse struct {
}

// Response implements the Response interface.
func (*PolicyNVWrittenResponse) Response() TPMCC { return TPMCCPolicyNvWritten }

// PolicyAuthorizeNV is the input to TPM2_PolicyAuthorizeNV.
// See definition in Part 3, Commands, section 23.22.
type PolicyAuthorizeNV struct {
	// handle indicating the source of the authorization value
	AuthHandle handle `gotpm:"handle,auth"`
	// the NV Index of the area to read
	NVIndex handle `gotpm:"handle"`
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
}

// Command implements the Command interface.
func (*PolicyAuthorizeNV) Command() TPMCC { return TPMCCPolicyAuthorizeNV }

// Execute executes the command and returns the response.
func (cmd *PolicyAuthorizeNV) Execute(t transport.TPM, s ...Session) error {
	var rsp PolicyAuthorizeNVResponse
	return execute(t, cmd, &rsp, s...)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyAuthorizeNV) Update(policy *PolicyCalculator) error {
	policy.Reset()
	return policy.Update(TPMCCPolicyAuthorizeNV, cmd.NVIndex.KnownName().Buffer)
}

// PolicyAuthorizeNVResponse is the response from TPM2_PolicyAuthorizeNV.
type PolicyAuthorizeNVResponse struct{}

// Response implements the Response interface.
func (*PolicyAuthorizeNVResponse) Response() TPMCC { return TPMCCPolicyAuthorizeNV }

// CreatePrimary is the input to TPM2_CreatePrimary.
// See definition in Part 3, Commands, section 24.1
type CreatePrimary struct {
	// TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP},
	// or TPM_RH_NULL
	PrimaryHandle handle `gotpm:"handle,auth"`
	// the sensitive data
	InSensitive tpm2bSensitiveCreate
	// the public template
	InPublic tpm2bPublic
	// data that will be included in the creation data for this
	// object to provide permanent, verifiable linkage between this
	// object and some object owner data
	OutsideInfo TPM2BData
	// PCR that will be used in creation data
	CreationPCR TPMLPCRSelection
}

// Command implements the Command interface.
func (*CreatePrimary) Command() TPMCC { return TPMCCCreatePrimary }

// Execute executes the command and returns the response.
func (cmd *CreatePrimary) Execute(t transport.TPM, s ...Session) (*CreatePrimaryResponse, error) {
	var rsp CreatePrimaryResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// CreatePrimaryResponse is the response from TPM2_CreatePrimary.
type CreatePrimaryResponse struct {
	// handle of type TPM_HT_TRANSIENT for created Primary Object
	ObjectHandle TPMHandle `gotpm:"handle"`
	// the public portion of the created object
	OutPublic tpm2bPublic
	// contains a TPMS_CREATION_DATA
	CreationData tpm2bCreationData
	// digest of creationData using nameAlg of outPublic
	CreationHash TPM2BDigest
	// ticket used by TPM2_CertifyCreation() to validate that the
	// creation data was produced by the TPM.
	CreationTicket TPMTTKCreation
	// the name of the created object
	Name TPM2BName
}

// Response implements the Response interface.
func (*CreatePrimaryResponse) Response() TPMCC { return TPMCCCreatePrimary }

// Clear is the input to TPM2_Clear.
// See definition in Part 3, Commands, section 24.6
type Clear struct {
	// TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP}
	AuthHandle handle `gotpm:"handle,auth"`
}

// Command implements the Command interface.
func (*Clear) Command() TPMCC { return TPMCCClear }

// Execute executes the command and returns the response.
func (cmd *Clear) Execute(t transport.TPM, s ...Session) error {
	var rsp ClearResponse
	return execute(t, cmd, &rsp, s...)
}

// ClearResponse is the response from TPM2_Clear.
type ClearResponse struct{}

// Response implements the Response interface.
func (*ClearResponse) Response() TPMCC { return TPMCCClear }

// ContextSave is the input to TPM2_ContextSave.
// See definition in Part 3, Commands, section 28.2
type ContextSave struct {
	// handle of the resource to save
	SaveHandle TPMIDHContext
}

// Command implements the Command interface.
func (*ContextSave) Command() TPMCC { return TPMCCContextSave }

// Execute executes the command and returns the response.
func (cmd *ContextSave) Execute(t transport.TPM, s ...Session) (*ContextSaveResponse, error) {
	var rsp ContextSaveResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// ContextSaveResponse is the response from TPM2_ContextSave.
type ContextSaveResponse struct {
	Context TPMSContext
}

// Response implements the Response interface.
func (*ContextSaveResponse) Response() TPMCC { return TPMCCContextSave }

// ContextLoad is the input to TPM2_ContextLoad.
// See definition in Part 3, Commands, section 28.3
type ContextLoad struct {
	// the context blob
	Context TPMSContext
}

// Command implements the Command interface.
func (*ContextLoad) Command() TPMCC { return TPMCCContextLoad }

// Execute executes the command and returns the response.
func (cmd *ContextLoad) Execute(t transport.TPM, s ...Session) (*ContextLoadResponse, error) {
	var rsp ContextLoadResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// ContextLoadResponse is the response from TPM2_ContextLoad.
type ContextLoadResponse struct {
	// the handle assigned to the resource after it has been successfully loaded
	LoadedHandle TPMIDHContext
}

// Response implements the Response interface.
func (*ContextLoadResponse) Response() TPMCC { return TPMCCContextLoad }

// FlushContext is the input to TPM2_FlushContext.
// See definition in Part 3, Commands, section 28.4
type FlushContext struct {
	// the handle of the item to flush
	FlushHandle handle `gotpm:"handle"`
}

// Command implements the Command interface.
func (*FlushContext) Command() TPMCC { return TPMCCFlushContext }

// Execute executes the command and returns the response.
func (cmd *FlushContext) Execute(t transport.TPM, s ...Session) error {
	var rsp FlushContextResponse
	return execute(t, cmd, &rsp, s...)
}

// FlushContextResponse is the response from TPM2_FlushContext.
type FlushContextResponse struct{}

// Response implements the Response interface.
func (*FlushContextResponse) Response() TPMCC { return TPMCCFlushContext }

// GetCapability is the input to TPM2_GetCapability.
// See definition in Part 3, Commands, section 30.2
type GetCapability struct {
	// group selection; determines the format of the response
	Capability TPMCap
	// further definition of information
	Property uint32
	// number of properties of the indicated type to return
	PropertyCount uint32
}

// Command implements the Command interface.
func (*GetCapability) Command() TPMCC { return TPMCCGetCapability }

// Execute executes the command and returns the response.
func (cmd *GetCapability) Execute(t transport.TPM, s ...Session) (*GetCapabilityResponse, error) {
	var rsp GetCapabilityResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// GetCapabilityResponse is the response from TPM2_GetCapability.
type GetCapabilityResponse struct {
	// flag to indicate if there are more values of this type
	MoreData TPMIYesNo
	// the capability data
	CapabilityData TPMSCapabilityData
}

// Response implements the Response interface.
func (*GetCapabilityResponse) Response() TPMCC { return TPMCCGetCapability }

// NVDefineSpace is the input to TPM2_NV_DefineSpace.
// See definition in Part 3, Commands, section 31.3.
type NVDefineSpace struct {
	// TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
	AuthHandle handle `gotpm:"handle,auth"`
	// the authorization value
	Auth TPM2BAuth
	// the public parameters of the NV area
	PublicInfo tpm2bNVPublic
}

// Command implements the Command interface.
func (*NVDefineSpace) Command() TPMCC { return TPMCCNVDefineSpace }

// Execute executes the command and returns the response.
func (cmd *NVDefineSpace) Execute(t transport.TPM, s ...Session) error {
	var rsp NVDefineSpaceResponse
	return execute(t, cmd, &rsp, s...)
}

// NVDefineSpaceResponse is the response from TPM2_NV_DefineSpace.
type NVDefineSpaceResponse struct{}

// Response implements the Response interface.
func (*NVDefineSpaceResponse) Response() TPMCC { return TPMCCNVDefineSpace }

// NVUndefineSpace is the input to TPM2_NV_UndefineSpace.
// See definition in Part 3, Commands, section 31.4.
type NVUndefineSpace struct {
	// TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
	AuthHandle handle `gotpm:"handle,auth"`
	// the NV Index to remove from NV space
	NVIndex handle `gotpm:"handle"`
}

// Command implements the Command interface.
func (*NVUndefineSpace) Command() TPMCC { return TPMCCNVUndefineSpace }

// Execute executes the command and returns the response.
func (cmd *NVUndefineSpace) Execute(t transport.TPM, s ...Session) error {
	var rsp NVUndefineSpaceResponse
	return execute(t, cmd, &rsp, s...)
}

// NVUndefineSpaceResponse is the response from TPM2_NV_UndefineSpace.
type NVUndefineSpaceResponse struct{}

// Response implements the Response interface.
func (*NVUndefineSpaceResponse) Response() TPMCC { return TPMCCNVUndefineSpace }

// NVUndefineSpaceSpecial is the input to TPM2_NV_UndefineSpaceSpecial.
// See definition in Part 3, Commands, section 31.5.
type NVUndefineSpaceSpecial struct {
	// Index to be deleted
	NVIndex handle `gotpm:"handle,auth"`
	// TPM_RH_PLATFORM+{PP}
	Platform handle `gotpm:"handle,auth"`
}

// Command implements the Command interface.
func (*NVUndefineSpaceSpecial) Command() TPMCC { return TPMCCNVUndefineSpaceSpecial }

// Execute executes the command and returns the response.
func (cmd *NVUndefineSpaceSpecial) Execute(t transport.TPM, s ...Session) error {
	var rsp NVUndefineSpaceSpecialResponse
	return execute(t, cmd, &rsp, s...)
}

// NVUndefineSpaceSpecialResponse is the response from TPM2_NV_UndefineSpaceSpecial.
type NVUndefineSpaceSpecialResponse struct{}

// Response implements the Response interface.
func (*NVUndefineSpaceSpecialResponse) Response() TPMCC { return TPMCCNVUndefineSpaceSpecial }

// NVReadPublic is the input to TPM2_NV_ReadPublic.
// See definition in Part 3, Commands, section 31.6.
type NVReadPublic struct {
	// the NV index
	NVIndex handle `gotpm:"handle"`
}

// Command implements the Command interface.
func (*NVReadPublic) Command() TPMCC { return TPMCCNVReadPublic }

// Execute executes the command and returns the response.
func (cmd *NVReadPublic) Execute(t transport.TPM, s ...Session) (*NVReadPublicResponse, error) {
	var rsp NVReadPublicResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// NVReadPublicResponse is the response from TPM2_NV_ReadPublic.
type NVReadPublicResponse struct {
	NVPublic tpm2bNVPublic
	NVName   TPM2BName
}

// Response implements the Response interface.
func (*NVReadPublicResponse) Response() TPMCC { return TPMCCNVReadPublic }

// NVWrite is the input to TPM2_NV_Write.
// See definition in Part 3, Commands, section 31.7.
type NVWrite struct {
	// handle indicating the source of the authorization value
	AuthHandle handle `gotpm:"handle,auth"`
	// the NV index of the area to write
	NVIndex handle `gotpm:"handle"`
	// the data to write
	Data TPM2BMaxNVBuffer
	// the octet offset into the NV Area
	Offset uint16
}

// Command implements the Command interface.
func (*NVWrite) Command() TPMCC { return TPMCCNVWrite }

// Execute executes the command and returns the response.
func (cmd *NVWrite) Execute(t transport.TPM, s ...Session) error {
	var rsp NVWriteResponse
	return execute(t, cmd, &rsp, s...)
}

// NVWriteResponse is the response from TPM2_NV_Write.
type NVWriteResponse struct{}

// Response implements the Response interface.
func (*NVWriteResponse) Response() TPMCC { return TPMCCNVWrite }

// NVIncrement is the input to TPM2_NV_Increment.
// See definition in Part 3, Commands, section 31.8.
type NVIncrement struct {
	// handle indicating the source of the authorization value
	AuthHandle handle `gotpm:"handle,auth"`
	// the NV index of the area to write
	NVIndex handle `gotpm:"handle"`
}

// Command implements the Command interface.
func (*NVIncrement) Command() TPMCC { return TPMCCNVIncrement }

// Execute executes the command and returns the response.
func (cmd *NVIncrement) Execute(t transport.TPM, s ...Session) error {
	var rsp NVIncrementResponse
	return execute(t, cmd, &rsp, s...)
}

// NVIncrementResponse is the response from TPM2_NV_Increment.
type NVIncrementResponse struct{}

// Response implements the Response interface.
func (*NVIncrementResponse) Response() TPMCC { return TPMCCNVIncrement }

// NVWriteLock is the input to TPM2_NV_WriteLock.
// See definition in Part 3, Commands, section 31.11.
type NVWriteLock struct {
	// handle indicating the source of the authorization value
	AuthHandle handle `gotpm:"handle,auth"`
	// the NV index of the area to lock
	NVIndex handle `gotpm:"handle"`
}

// Command implements the Command interface.
func (*NVWriteLock) Command() TPMCC { return TPMCCNVWriteLock }

// Execute executes the command and returns the response.
func (cmd *NVWriteLock) Execute(t transport.TPM, s ...Session) error {
	var rsp NVWriteLockResponse
	return execute(t, cmd, &rsp, s...)
}

// NVWriteLockResponse is the response from TPM2_NV_WriteLock.
type NVWriteLockResponse struct{}

// Response implements the Response interface.
func (*NVWriteLockResponse) Response() TPMCC { return TPMCCNVWriteLock }

// NVRead is the input to TPM2_NV_Read.
// See definition in Part 3, Commands, section 31.13.
type NVRead struct {
	// handle indicating the source of the authorization value
	AuthHandle handle `gotpm:"handle,auth"`
	// the NV index to read
	NVIndex handle `gotpm:"handle"`
	// number of octets to read
	Size uint16
	// octet offset into the NV area
	Offset uint16
}

// Command implements the Command interface.
func (*NVRead) Command() TPMCC { return TPMCCNVRead }

// Execute executes the command and returns the response.
func (cmd *NVRead) Execute(t transport.TPM, s ...Session) (*NVReadResponse, error) {
	var rsp NVReadResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// NVReadResponse is the response from TPM2_NV_Read.
type NVReadResponse struct {
	// the data read
	Data TPM2BMaxNVBuffer
}

// Response implements the Response interface.
func (*NVReadResponse) Response() TPMCC { return TPMCCNVRead }

// NVCertify is the input to TPM2_NV_Certify.
// See definition in Part 3, Commands, section 31.16.
type NVCertify struct {
	// handle of the key used to sign the attestation structure
	SignHandle handle `gotpm:"handle,auth"`
	// handle indicating the source of the authorization value
	AuthHandle handle `gotpm:"handle,auth"`
	// Index for the area to be certified
	NVIndex handle `gotpm:"handle"`
	// user-provided qualifying data
	QualifyingData TPM2BData
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme TPMTSigScheme `gotpm:"nullable"`
	// number of octets to certify
	Size uint16
	// octet offset into the NV area
	Offset uint16
}

// Command implements the Command interface.
func (*NVCertify) Command() TPMCC { return TPMCCNVCertify }

// Execute executes the command and returns the response.
func (cmd *NVCertify) Execute(t transport.TPM, s ...Session) (*NVCertifyResponse, error) {
	var rsp NVCertifyResponse
	if err := execute(t, cmd, &rsp, s...); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// NVCertifyResponse is the response from TPM2_NV_Read.
type NVCertifyResponse struct {
	// the structure that was signed
	CertifyInfo tpm2bAttest
	// the asymmetric signature over certifyInfo using the key referenced by signHandle
	Signature TPMTSignature
}

// Response implements the Response interface.
func (*NVCertifyResponse) Response() TPMCC { return TPMCCNVCertify }

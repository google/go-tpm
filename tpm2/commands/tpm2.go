// Package tpm2 contains TPM 2.0 commands
package tpm2

import (
	"bytes"

	"github.com/google/go-tpm/tpm2/structures/tpm"
	"github.com/google/go-tpm/tpm2/structures/tpm2b"
	"github.com/google/go-tpm/tpm2/structures/tpmi"
	"github.com/google/go-tpm/tpm2/structures/tpml"
	"github.com/google/go-tpm/tpm2/structures/tpms"
	"github.com/google/go-tpm/tpm2/structures/tpmt"
	"github.com/google/go-tpm/tpm2/transport"
)

// handle represents a TPM handle as comprehended in Part 3: Commands.
// In the context of TPM commands, handles are special parameters for which
// there is a known associated name.
// This is not an exported interface, because the reflection logic has special
// behavior for AuthHandle, due to the fact that referencing Session from this
// interface would break the ability to make tpm.Handle implement it.
type handle interface {
	// HandleValue is the numeric concrete handle value in the TPM.
	HandleValue() uint32
	// KnownName is the TPM Name of the associated entity. See Part 1, section 16.
	KnownName() *tpm2b.Name
}

// NamedHandle represents an associated pairing of TPM handle and known Name.
type NamedHandle struct {
	tpm.Handle
	Name tpm2b.Name
}

// KnownName implements the handle interface, shadowing the default
// behavior of the embedded tpm.Handle.
func (h NamedHandle) KnownName() *tpm2b.Name {
	return &h.Name
}

// AuthHandle allows the caller to add an authorization session onto a handle.
type AuthHandle struct {
	tpm.Handle
	Name tpm2b.Name
	Auth Session
}

// KnownName implements the handle interface, shadowing the default
// behavior of the embedded tpm.Handle if needed.
// If Name is not provided (i.e., only Auth), then rely on the underlying
// tpm.Handle.
func (h AuthHandle) KnownName() *tpm2b.Name {
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

// PolicyCommand is a TPM command that can be part of a TPM policy.
type PolicyCommand interface {
	// Update updates the given policy hash according to the command
	// parameters.
	Update(policy *PolicyCalculator) error
}

// Shutdown is the input to TPM2_Shutdown.
// See definition in Part 3, Commands, section 9.4.
type Shutdown struct {
	// TPM_SU_CLEAR or TPM_SU_STATE
	ShutdownType tpm.SU
}

// Command implements the Command interface.
func (*Shutdown) Command() tpm.CC { return tpm.CCShutdown }

// Execute executes the command and returns the response.
func (cmd *Shutdown) Execute(t transport.TPM, s ...Session) error {
	var rsp ShutdownResponse
	return execute(t, cmd, &rsp, s...)
}

// ShutdownResponse is the response from TPM2_Shutdown.
type ShutdownResponse struct{}

// Response implements the Response interface.
func (*ShutdownResponse) Response() tpm.CC { return tpm.CCShutdown }

// Startup is the input to TPM2_Startup.
// See definition in Part 3, Commands, section 9.3.
type Startup struct {
	// TPM_SU_CLEAR or TPM_SU_STATE
	StartupType tpm.SU
}

// Command implements the Command interface.
func (*Startup) Command() tpm.CC { return tpm.CCStartup }

// Execute executes the command and returns the response.
func (cmd *Startup) Execute(t transport.TPM, s ...Session) error {
	var rsp StartupResponse
	return execute(t, cmd, &rsp, s...)
}

// StartupResponse is the response from TPM2_Startup.
type StartupResponse struct{}

// Response implements the Response interface.
func (*StartupResponse) Response() tpm.CC { return tpm.CCStartup }

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
	NonceCaller tpm2b.Nonce
	// value encrypted according to the type of tpmKey
	// If tpmKey is TPM_RH_NULL, this shall be the Empty Buffer.
	EncryptedSalt tpm2b.EncryptedSecret
	// indicates the type of the session; simple HMAC or policy (including
	// a trial policy)
	SessionType tpm.SE
	// the algorithm and key size for parameter encryption
	// may select transport.TPM_ALG_NULL
	Symmetric tpmt.SymDef
	// hash algorithm to use for the session
	// Shall be a hash algorithm supported by the TPM and not transport.TPM_ALG_NULL
	AuthHash tpmi.AlgHash
}

// Command implements the Command interface.
func (*StartAuthSession) Command() tpm.CC { return tpm.CCStartAuthSession }

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
	SessionHandle tpmi.SHAuthSession `gotpm:"handle"`
	// the initial nonce from the TPM, used in the computation of the sessionKey
	NonceTPM tpm2b.Nonce
}

// Response implements the Response interface.
func (*StartAuthSessionResponse) Response() tpm.CC { return tpm.CCStartAuthSession }

// Create is the input to TPM2_Create.
// See definition in Part 3, Commands, section 12.1
type Create struct {
	// handle of parent for new object
	ParentHandle handle `gotpm:"handle,auth"`
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
func (*Create) Command() tpm.CC { return tpm.CCCreate }

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

// Load is the input to TPM2_Load.
// See definition in Part 3, Commands, section 12.2
type Load struct {
	// handle of parent for new object
	ParentHandle handle `gotpm:"handle,auth"`
	// the private portion of the object
	InPrivate tpm2b.Private
	// the public portion of the object
	InPublic tpm2b.Public
}

// Command implements the Command interface.
func (*Load) Command() tpm.CC { return tpm.CCLoad }

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
	ObjectHandle tpm.Handle `gotpm:"handle"`
	// Name of the loaded object
	Name tpm2b.Name
}

// Response implements the Response interface.
func (*LoadResponse) Response() tpm.CC { return tpm.CCLoad }

// LoadExternal is the input to TPM2_LoadExternal.
// See definition in Part 3, Commands, section 12.3
type LoadExternal struct {
	// the sensitive portion of the object (optional)
	InPrivate *tpm2b.Sensitive `gotpm:"optional"`
	// the public portion of the object
	InPublic tpm2b.Public
	// hierarchy with which the object area is associated
	Hierarchy tpmi.RHHierarchy `gotpm:"nullable"`
}

// Command implements the Command interface.
func (*LoadExternal) Command() tpm.CC { return tpm.CCLoadExternal }

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
	ObjectHandle tpm.Handle `gotpm:"handle"`
	// Name of the loaded object
	Name tpm2b.Name
}

// Response implements the Response interface.
func (*LoadExternalResponse) Response() tpm.CC { return tpm.CCLoadExternal }

// ReadPublic is the input to TPM2_ReadPublic.
// See definition in Part 3, Commands, section 12.4
type ReadPublic struct {
	// TPM handle of an object, Auth Index: None
	ObjectHandle tpmi.DHObject `gotpm:"handle"`
}

// Command implements the Command interface.
func (*ReadPublic) Command() tpm.CC { return tpm.CCReadPublic }

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
	OutPublic tpm2b.Public
	// name of object
	Name tpm2b.Name
	// the Qualified Name of the object
	QualifiedName tpm2b.Name
}

// Response implements the Response interface.
func (*ReadPublicResponse) Response() tpm.CC { return tpm.CCReadPublic }

// Unseal is the input to TPM2_Unseal.
// See definition in Part 3, Commands, section 12.7
type Unseal struct {
	ItemHandle handle `gotpm:"handle,auth"`
}

// Command implements the Command interface.
func (*Unseal) Command() tpm.CC { return tpm.CCUnseal }

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
	OutData tpm2b.SensitiveData
}

// Response implements the Response interface.
func (*UnsealResponse) Response() tpm.CC { return tpm.CCUnseal }

// CreateLoaded is the input to TPM2_CreateLoaded.
// See definition in Part 3, Commands, section 12.9
type CreateLoaded struct {
	// Handle of a transient storage key, a persistent storage key,
	// TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL
	ParentHandle handle `gotpm:"handle,auth,nullable"`
	// the sensitive data, see TPM 2.0 Part 1 Sensitive Values
	InSensitive tpm2b.SensitiveCreate
	// the public template
	InPublic tpm2b.Template
}

// Command implements the Command interface.
func (*CreateLoaded) Command() tpm.CC { return tpm.CCCreateLoaded }

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
	ObjectHandle tpm.Handle `gotpm:"handle"`
	// the sensitive area of the object (optional)
	OutPrivate tpm2b.Private `gotpm:"optional"`
	// the public portion of the created object
	OutPublic tpm2b.Public
	// the name of the created object
	Name tpm2b.Name
}

// Response implements the Response interface.
func (*CreateLoadedResponse) Response() tpm.CC { return tpm.CCCreateLoaded }

// Hash is the input to TPM2_Hash.
// See definition in Part 3, Commands, section 15.4
type Hash struct {
	//data to be hashed
	Data tpm2b.MaxBuffer
	// algorithm for the hash being computed - shall not be TPM_ALH_NULL
	HashAlg tpmi.AlgHash
	// hierarchy to use for the ticket (TPM_RH_NULL_allowed)
	Hierarchy tpmi.RHHierarchy `gotpm:"nullable"`
}

// Command implements the Command interface.
func (*Hash) Command() tpm.CC { return tpm.CCHash }

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
	OutHash tpm2b.Digest
	// ticket indicating that the sequence of octets used to
	// compute outDigest did not start with TPM_GENERATED_VALUE
	Validation tpmt.TKHashCheck
}

// Response implements the Response interface.
func (*HashResponse) Response() tpm.CC { return tpm.CCHash }

// GetRandom is the input to TPM2_GetRandom.
// See definition in Part 3, Commands, section 16.1
type GetRandom struct {
	// number of octets to return
	BytesRequested uint16
}

// Command implements the Command interface.
func (*GetRandom) Command() tpm.CC { return tpm.CCGetRandom }

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
	RandomBytes tpm2b.Digest
}

// Response implements the Response interface.
func (*GetRandomResponse) Response() tpm.CC { return tpm.CCGetRandom }

// HashSequenceStart is the input to TPM2_HashSequenceStart.
// See definition in Part 3, Commands, section 17.3
type HashSequenceStart struct {
	// authorization value for subsequent use of the sequence
	Auth tpm2b.Auth
	// the hash algorithm to use for the hash sequence
	// An Event Sequence starts if this is TPM_ALG_NULL.
	HashAlg tpmi.AlgHash
}

// Command implements the Command interface.
func (*HashSequenceStart) Command() tpm.CC { return tpm.CCHashSequenceStart }

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
	SequenceHandle tpmi.DHObject
}

// Response implements the Response interface.
func (*HashSequenceStartResponse) Response() tpm.CC { return tpm.CCHashSequenceStart }

// SequenceUpdate is the input to TPM2_SequenceUpdate.
// See definition in Part 3, Commands, section 17.4
type SequenceUpdate struct {
	// handle for the sequence object Auth Index: 1 Auth Role: USER
	SequenceHandle handle `gotpm:"handle,auth"`
	// data to be added to hash
	Buffer tpm2b.MaxBuffer
}

// Command implements the Command interface.
func (*SequenceUpdate) Command() tpm.CC { return tpm.CCSequenceUpdate }

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
func (*SequenceUpdateResponse) Response() tpm.CC { return tpm.CCSequenceUpdate }

// SequenceComplete is the input to TPM2_SequenceComplete.
// See definition in Part 3, Commands, section 17.5
type SequenceComplete struct {
	// authorization for the sequence, Auth Index: 1, Auth Role: USER
	SequenceHandle handle `gotpm:"handle,auth"`
	// data to be added to the hash/HMAC
	Buffer tpm2b.MaxBuffer
	// hierarchy of the ticket for a hash
	Hierarchy tpmi.RHHierarchy `gotpm:"nullable"`
}

// Command implements the Command interface.
func (*SequenceComplete) Command() tpm.CC { return tpm.CCSequenceComplete }

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
	Result tpm2b.Digest
	// 	ticket indicating that the sequence of octets used to
	// compute outDigest did not start with TPM_GENERATED_VALUE
	Validation tpmt.TKHashCheck
}

// Response implements the Response interface.
func (*SequenceCompleteResponse) Response() tpm.CC { return tpm.CCSequenceComplete }

// Certify is the input to TPM2_Certify.
// See definition in Part 3, Commands, section 18.2.
type Certify struct {
	// handle of the object to be certified, Auth Index: 1, Auth Role: ADMIN
	ObjectHandle handle `gotpm:"handle,auth"`
	// handle of the key used to sign the attestation structure, Auth Index: 2, Auth Role: USER
	SignHandle handle `gotpm:"handle,auth"`
	// user provided qualifying data
	QualifyingData tpm2b.Data
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme tpmt.SigScheme
}

// Command implements the Command interface.
func (*Certify) Command() tpm.CC { return tpm.CCCertify }

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
	CertifyInfo tpm2b.Attest
	// the asymmetric signature over certifyInfo using the key referenced by signHandle
	Signature tpmt.Signature
}

// Response implements the Response interface.
func (*CertifyResponse) Response() tpm.CC { return tpm.CCCertify }

// CertifyCreation is the input to TPM2_CertifyCreation.
// See definition in Part 3, Commands, section 18.3.
type CertifyCreation struct {
	// handle of the key that will sign the attestation block
	SignHandle handle `gotpm:"handle,auth"`
	// the object associated with the creation data
	ObjectHandle handle `gotpm:"handle"`
	// user-provided qualifying data
	QualifyingData tpm2b.Data
	// hash of the creation data produced by TPM2_Create() or TPM2_CreatePrimary()
	CreationHash tpm2b.Digest
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme tpmt.SigScheme
	// ticket produced by TPM2_Create() or TPM2_CreatePrimary()
	CreationTicket tpmt.TKCreation
}

// Command implements the Command interface.
func (*CertifyCreation) Command() tpm.CC { return tpm.CCCertifyCreation }

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
	CertifyInfo tpm2b.Attest
	// the signature over certifyInfo
	Signature tpmt.Signature
}

// Response implements the Response interface.
func (*CertifyCreationResponse) Response() tpm.CC { return tpm.CCCertifyCreation }

// Quote is the input to TPM2_Quote.
// See definition in Part 3, Commands, section 18.4
type Quote struct {
	// handle of key that will perform signature
	SignHandle handle `gotpm:"handle,auth"`
	// data supplied by the caller
	QualifyingData tpm2b.Data
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme tpmt.SigScheme
	// PCR set to quote
	PCRSelect tpml.PCRSelection
}

// Command implements the Command interface.
func (*Quote) Command() tpm.CC { return tpm.CCQuote }

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
	Quoted tpm2b.Attest
	// the signature over quoted
	Signature tpmt.Signature
}

// Response implements the Response interface.
func (*QuoteResponse) Response() tpm.CC { return tpm.CCQuote }

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
	QualifyingData tpm2b.Data
	// signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
	InScheme tpmt.SigScheme
}

// Command implements the Command interface.
func (*GetSessionAuditDigest) Command() tpm.CC { return tpm.CCGetSessionAuditDigest }

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
	AuditInfo tpm2b.Attest
	// the signature over auditInfo
	Signature tpmt.Signature
}

// Response implements the Response interface.
func (*GetSessionAuditDigestResponse) Response() tpm.CC { return tpm.CCGetSessionAuditDigest }

// Commit is the input to TPM2_Commit.
// See definition in Part 3, Commands, section 19.2.
type Commit struct {
	// handle of the key that will be used in the signing operation
	SignHandle handle `gotpm:"handle,auth"`
	// a point (M) on the curve used by signHandle
	P1 tpm2b.ECCPoint
	// octet array used to derive x-coordinate of a base point
	S2 tpm2b.SensitiveData
	// y coordinate of the point associated with s2
	Y2 tpm2b.ECCParameter
}

// Command implements the Command interface.
func (*Commit) Command() tpm.CC { return tpm.CCCommit }

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
	K tpm2b.ECCPoint
	// ECC point L ≔ [r](x2, y2)
	L tpm2b.ECCPoint
	// ECC point E ≔ [r]P1
	E tpm2b.ECCPoint
	// least-significant 16 bits of commitCount
	Counter uint16
}

// Response implements the Response interface.
func (*CommitResponse) Response() tpm.CC { return tpm.CCCommit }

// VerifySignature is the input to TPM2_VerifySignature.
// See definition in Part 3, Commands, section 20.1
type VerifySignature struct {
	// handle of public key that will be used in the validation
	KeyHandle handle `gotpm:"handle"`
	// digest of the signed message
	Digest tpm2b.Digest
	// signature to be tested
	Signature tpmt.Signature
}

// Command implements the Command interface.
func (*VerifySignature) Command() tpm.CC { return tpm.CCVerifySignature }

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
	Validation tpmt.TKVerified
}

// Response implements the Response interface.
func (*VerifySignatureResponse) Response() tpm.CC { return tpm.CCVerifySignature }

// Sign is the input to TPM2_Sign.
// See definition in Part 3, Commands, section 20.2.
type Sign struct {
	// Handle of key that will perform signing, Auth Index: 1, Auth Role: USER
	KeyHandle handle `gotpm:"handle,auth"`
	// digest to be signed
	Digest tpm2b.Digest
	// signing scheme to use if the scheme for keyHandle is TPM_ALG_NULL
	InScheme tpmt.SigScheme
	// proof that digest was created by the TPM
	// If keyHandle is not a restricted signing key, then this
	// may be a NULL Ticket with tag = TPM_ST_CHECKHASH.
	Validation tpmt.TKHashCheck
}

// Command implements the Command interface.
func (*Sign) Command() tpm.CC { return tpm.CCSign }

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
	Signature tpmt.Signature
}

// Response implements the Response interface.
func (*SignResponse) Response() tpm.CC { return tpm.CCSign }

// PCRExtend is the input to TPM2_PCR_Extend.
// See definition in Part 3, Commands, section 22.2
type PCRExtend struct {
	// handle of the PCR
	PCRHandle handle `gotpm:"handle,auth"`
	// list of tagged digest values to be extended
	Digests tpml.DigestValues
}

// Command implements the Command interface.
func (*PCRExtend) Command() tpm.CC { return tpm.CCPCRExtend }

// Execute executes the command and returns the response.
func (cmd *PCRExtend) Execute(t transport.TPM, s ...Session) error {
	var rsp PCRExtendResponse
	return execute(t, cmd, &rsp, s...)
}

// PCRExtendResponse is the response from TPM2_PCR_Extend.
type PCRExtendResponse struct{}

// Response implements the Response interface.
func (*PCRExtendResponse) Response() tpm.CC { return tpm.CCPCRExtend }

// PCREvent is the input to TPM2_PCR_Event.
// See definition in Part 3, Commands, section 22.3
type PCREvent struct {
	// Handle of the PCR
	PCRHandle handle `gotpm:"handle,auth"`
	// Event data in sized buffer
	EventData tpm2b.Event
}

// Command implements the Command interface.
func (*PCREvent) Command() tpm.CC { return tpm.CCPCREvent }

// Execute executes the command and returns the response.
func (cmd *PCREvent) Execute(t transport.TPM, s ...Session) error {
	var rsp PCREventResponse
	return execute(t, cmd, &rsp, s...)
}

// PCREventResponse is the response from TPM2_PCR_Event.
type PCREventResponse struct{}

// Response implements the Response interface.
func (*PCREventResponse) Response() tpm.CC { return tpm.CCPCREvent }

// PCRRead is the input to TPM2_PCR_Read.
// See definition in Part 3, Commands, section 22.4
type PCRRead struct {
	// The selection of PCR to read
	PCRSelectionIn tpml.PCRSelection
}

// Command implements the Command interface.
func (*PCRRead) Command() tpm.CC { return tpm.CCPCRRead }

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
	PCRSelectionOut tpml.PCRSelection
	// the contents of the PCR indicated in pcrSelectOut-> pcrSelection[] as tagged digests
	PCRValues tpml.Digest
}

// Response implements the Response interface.
func (*PCRReadResponse) Response() tpm.CC { return tpm.CCPCRRead }

// PCRReset is the input to TPM2_PCRReset.
// See definition in Part 3, Commands, section 22.8.
type PCRReset struct {
	// the PCR to reset
	PCRHandle handle `gotpm:"handle,auth"`
}

// Command implements the Command interface.
func (*PCRReset) Command() tpm.CC { return tpm.CCPCRReset }

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
func (*PCRResetResponse) Response() tpm.CC { return tpm.CCPCRReset }

// PolicySigned is the input to TPM2_PolicySigned.
// See definition in Part 3, Commands, section 23.3.
type PolicySigned struct {
	// handle for an entity providing the authorization
	AuthObject handle `gotpm:"handle"`
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// the policy nonce for the session
	NonceTPM tpm2b.Nonce
	// digest of the command parameters to which this authorization is limited
	CPHashA tpm2b.Digest
	// a reference to a policy relating to the authorization – may be the Empty Buffer
	PolicyRef tpm2b.Nonce
	// time when authorization will expire, measured in seconds from the time
	// that nonceTPM was generated
	Expiration int32
	// signed authorization (not optional)
	Auth tpmt.Signature
}

// Command implements the Command interface.
func (*PolicySigned) Command() tpm.CC { return tpm.CCPolicySigned }

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
func policyUpdate(policy *PolicyCalculator, cc tpm.CC, arg2, arg3 []byte) error {
	if err := policy.Update(cc, arg2); err != nil {
		return err
	}
	return policy.Update(arg3)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicySigned) Update(policy *PolicyCalculator) error {
	return policyUpdate(policy, tpm.CCPolicySigned, cmd.AuthObject.KnownName().Buffer, cmd.PolicyRef.Buffer)
}

// PolicySignedResponse is the response from TPM2_PolicySigned.
type PolicySignedResponse struct {
	// implementation-specific time value used to indicate to the TPM when the ticket expires
	Timeout tpm2b.Timeout
	// produced if the command succeeds and expiration in the command was non-zero
	PolicyTicket tpmt.TKAuth
}

// Response implements the Response interface.
func (*PolicySignedResponse) Response() tpm.CC { return tpm.CCPolicySigned }

// PolicySecret is the input to TPM2_PolicySecret.
// See definition in Part 3, Commands, section 23.4.
type PolicySecret struct {
	// handle for an entity providing the authorization
	AuthHandle handle `gotpm:"handle,auth"`
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
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
func (*PolicySecret) Command() tpm.CC { return tpm.CCPolicySecret }

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
	policyUpdate(policy, tpm.CCPolicySecret, cmd.AuthHandle.KnownName().Buffer, cmd.PolicyRef.Buffer)
}

// PolicySecretResponse is the response from TPM2_PolicySecret.
type PolicySecretResponse struct {
	// implementation-specific time value used to indicate to the TPM when the ticket expires
	Timeout tpm2b.Timeout
	// produced if the command succeeds and expiration in the command was non-zero
	PolicyTicket tpmt.TKAuth
}

// Response implements the Response interface.
func (*PolicySecretResponse) Response() tpm.CC { return tpm.CCPolicySecret }

// PolicyOr is the input to TPM2_PolicyOR.
// See definition in Part 3, Commands, section 23.6.
type PolicyOr struct {
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// the list of hashes to check for a match
	PHashList tpml.Digest
}

// Command implements the Command interface.
func (*PolicyOr) Command() tpm.CC { return tpm.CCPolicyOR }

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
	return policy.Update(tpm.CCPolicyOR, digests.Bytes())
}

// PolicyOrResponse is the response from TPM2_PolicyOr.
type PolicyOrResponse struct{}

// Response implements the Response interface.
func (*PolicyOrResponse) Response() tpm.CC { return tpm.CCPolicyOR }

// PolicyPCR is the input to TPM2_PolicyPCR.
// See definition in Part 3, Commands, section 23.7.
type PolicyPCR struct {
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// expected digest value of the selected PCR using the
	// hash algorithm of the session; may be zero length
	PcrDigest tpm2b.Digest
	// the PCR to include in the check digest
	Pcrs tpml.PCRSelection
}

// Command implements the Command interface.
func (*PolicyPCR) Command() tpm.CC { return tpm.CCPolicyPCR }

// Execute executes the command and returns the response.
func (cmd *PolicyPCR) Execute(t transport.TPM, s ...Session) error {
	var rsp PolicyPCRResponse
	return execute(t, cmd, &rsp, s...)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyPCR) Update(policy *PolicyCalculator) error {
	return policy.Update(tpm.CCPolicyPCR, cmd.Pcrs, cmd.PcrDigest.Buffer)
}

// PolicyPCRResponse is the response from TPM2_PolicyPCR.
type PolicyPCRResponse struct{}

// Response implements the Response interface.
func (*PolicyPCRResponse) Response() tpm.CC { return tpm.CCPolicyPCR }

// PolicyCommandCode is the input to TPM2_PolicyCommandCode.
// See definition in Part 3, Commands, section 23.11.
type PolicyCommandCode struct {
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// the allowed commandCode
	Code tpm.CC
}

// Command implements the Command interface.
func (*PolicyCommandCode) Command() tpm.CC { return tpm.CCPolicyCommandCode }

// Execute executes the command and returns the response.
func (cmd *PolicyCommandCode) Execute(t transport.TPM, s ...Session) error {
	var rsp PolicyCommandCodeResponse
	return execute(t, cmd, &rsp, s...)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyCommandCode) Update(policy *PolicyCalculator) error {
	return policy.Update(tpm.CCPolicyCommandCode, cmd.Code)
}

// PolicyCommandCodeResponse is the response from TPM2_PolicyCommandCode.
type PolicyCommandCodeResponse struct{}

// Response implements the Response interface.
func (*PolicyCommandCodeResponse) Response() tpm.CC { return tpm.CCPolicyCommandCode }

// PolicyCPHash is the input to TPM2_PolicyCpHash.
// See definition in Part 3, Commands, section 23.13.
type PolicyCPHash struct {
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// the cpHash added to the policy
	CPHashA tpm2b.Digest
}

// Command implements the Command interface.
func (*PolicyCPHash) Command() tpm.CC { return tpm.CCPolicyCpHash }

// Execute executes the command and returns the response.
func (cmd *PolicyCPHash) Execute(t transport.TPM, s ...Session) error {
	var rsp PolicyCPHashResponse
	return execute(t, cmd, &rsp, s...)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyCPHash) Update(policy *PolicyCalculator) error {
	return policy.Update(tpm.CCPolicyCpHash, cmd.CPHashA.Buffer)
}

// PolicyCPHashResponse is the response from TPM2_PolicyCpHash.
type PolicyCPHashResponse struct{}

// Response implements the Response interface.
func (*PolicyCPHashResponse) Response() tpm.CC { return tpm.CCPolicyCpHash }

// PolicyAuthorize is the input to TPM2_PolicySigned.
// See definition in Part 3, Commands, section 23.16.
type PolicyAuthorize struct {
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// digest of the policy being approved
	ApprovedPolicy tpm2b.Digest
	// a policy qualifier
	PolicyRef tpm2b.Digest
	// Name of a key that can sign a policy addition
	KeySign tpm2b.Name
	// ticket validating that approvedPolicy and policyRef were signed by keySign
	CheckTicket tpmt.TKVerified
}

// Command implements the Command interface.
func (*PolicyAuthorize) Command() tpm.CC { return tpm.CCPolicyAuthorize }

// Execute executes the command and returns the response.
func (cmd *PolicyAuthorize) Execute(t transport.TPM, s ...Session) error {
	var rsp PolicyAuthorizeResponse
	return execute(t, cmd, &rsp, s...)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyAuthorize) Update(policy *PolicyCalculator) error {
	return policyUpdate(policy, tpm.CCPolicyAuthorize, cmd.KeySign.Buffer, cmd.PolicyRef.Buffer)
}

// PolicyAuthorizeResponse is the response from TPM2_PolicyAuthorize.
type PolicyAuthorizeResponse struct{}

// Response implements the Response interface.
func (*PolicyAuthorizeResponse) Response() tpm.CC { return tpm.CCPolicyAuthorize }

// PolicyGetDigest is the input to TPM2_PolicyGetDigest.
// See definition in Part 3, Commands, section 23.19.
type PolicyGetDigest struct {
	// handle for the policy session
	PolicySession handle `gotpm:"handle"`
}

// Command implements the Command interface.
func (*PolicyGetDigest) Command() tpm.CC { return tpm.CCPolicyGetDigest }

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
	PolicyDigest tpm2b.Digest
}

// Response implements the Response interface.
func (*PolicyGetDigestResponse) Response() tpm.CC { return tpm.CCPolicyGetDigest }

// PolicyNVWritten is the input to TPM2_PolicyNvWritten.
// See definition in Part 3, Commands, section 23.20.
type PolicyNVWritten struct {
	// handle for the policy session being extended
	PolicySession handle `gotpm:"handle"`
	// YES if NV Index is required to have been written
	// NO if NV Index is required not to have been written
	WrittenSet tpmi.YesNo
}

// Command implements the Command interface.
func (*PolicyNVWritten) Command() tpm.CC { return tpm.CCPolicyNvWritten }

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
	return policy.Update(tpm.CCPolicyNvWritten, cmd.WrittenSet)
}

// PolicyNVWrittenResponse is the response from TPM2_PolicyNvWritten.
type PolicyNVWrittenResponse struct {
}

// Response implements the Response interface.
func (*PolicyNVWrittenResponse) Response() tpm.CC { return tpm.CCPolicyNvWritten }

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
func (*PolicyAuthorizeNV) Command() tpm.CC { return tpm.CCPolicyAuthorizeNV }

// Execute executes the command and returns the response.
func (cmd *PolicyAuthorizeNV) Execute(t transport.TPM, s ...Session) error {
	var rsp PolicyAuthorizeNVResponse
	return execute(t, cmd, &rsp, s...)
}

// Update implements the PolicyCommand interface.
func (cmd *PolicyAuthorizeNV) Update(policy *PolicyCalculator) error {
	policy.Reset()
	return policy.Update(tpm.CCPolicyAuthorizeNV, cmd.NVIndex.KnownName().Buffer)
}

// PolicyAuthorizeNVResponse is the response from TPM2_PolicyAuthorizeNV.
type PolicyAuthorizeNVResponse struct{}

// Response implements the Response interface.
func (*PolicyAuthorizeNVResponse) Response() tpm.CC { return tpm.CCPolicyAuthorizeNV }

// CreatePrimary is the input to TPM2_CreatePrimary.
// See definition in Part 3, Commands, section 24.1
type CreatePrimary struct {
	// TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP},
	// or TPM_RH_NULL
	PrimaryHandle handle `gotpm:"handle,auth"`
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
func (*CreatePrimary) Command() tpm.CC { return tpm.CCCreatePrimary }

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

// ContextSave is the input to TPM2_ContextSave.
// See definition in Part 3, Commands, section 28.2
type ContextSave struct {
	// handle of the resource to save Auth Index: None
	SaveHandle tpmi.DHContext
}

// Command implements the Command interface.
func (*ContextSave) Command() tpm.CC { return tpm.CCContextSave }

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
	Context tpms.Context
}

// Response implements the Response interface.
func (*ContextSaveResponse) Response() tpm.CC { return tpm.CCContextSave }

// ContextLoad is the input to TPM2_ContextLoad.
// See definition in Part 3, Commands, section 28.3
type ContextLoad struct {
	// the context blob
	Context tpms.Context
}

// Command implements the Command interface.
func (*ContextLoad) Command() tpm.CC { return tpm.CCContextLoad }

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
	LoadedHandle tpmi.DHContext
}

// Response implements the Response interface.
func (*ContextLoadResponse) Response() tpm.CC { return tpm.CCContextLoad }

// FlushContext is the input to TPM2_FlushContext.
// See definition in Part 3, Commands, section 28.4
type FlushContext struct {
	// the handle of the item to flush
	FlushHandle handle `gotpm:"handle"`
}

// Command implements the Command interface.
func (*FlushContext) Command() tpm.CC { return tpm.CCFlushContext }

// Execute executes the command and returns the response.
func (cmd *FlushContext) Execute(t transport.TPM, s ...Session) error {
	var rsp FlushContextResponse
	return execute(t, cmd, &rsp, s...)
}

// FlushContextResponse is the response from TPM2_FlushContext.
type FlushContextResponse struct{}

// Response implements the Response interface.
func (*FlushContextResponse) Response() tpm.CC { return tpm.CCFlushContext }

// GetCapability is the input to TPM2_GetCapability.
// See definition in Part 3, Commands, section 30.2
type GetCapability struct {
	// group selection; determines the format of the response
	Capability tpm.Cap
	// further definition of information
	Property uint32
	// number of properties of the indicated type to return
	PropertyCount uint32
}

// Command implements the Command interface.
func (*GetCapability) Command() tpm.CC { return tpm.CCGetCapability }

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
	MoreData tpmi.YesNo
	// the capability data
	CapabilityData tpms.CapabilityData
}

// Response implements the Response interface.
func (*GetCapabilityResponse) Response() tpm.CC { return tpm.CCGetCapability }

// NVDefineSpace is the input to TPM2_NV_DefineSpace.
// See definition in Part 3, Commands, section 31.3.
type NVDefineSpace struct {
	// TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
	AuthHandle handle `gotpm:"handle,auth"`
	// the authorization value
	Auth tpm2b.Auth
	// the public parameters of the NV area
	PublicInfo tpm2b.NVPublic
}

// Command implements the Command interface.
func (*NVDefineSpace) Command() tpm.CC { return tpm.CCNVDefineSpace }

// Execute executes the command and returns the response.
func (cmd *NVDefineSpace) Execute(t transport.TPM, s ...Session) error {
	var rsp NVDefineSpaceResponse
	return execute(t, cmd, &rsp, s...)
}

// NVDefineSpaceResponse is the response from TPM2_NV_DefineSpace.
type NVDefineSpaceResponse struct{}

// Response implements the Response interface.
func (*NVDefineSpaceResponse) Response() tpm.CC { return tpm.CCNVDefineSpace }

// NVUndefineSpace is the input to TPM2_NV_UndefineSpace.
// See definition in Part 3, Commands, section 31.4.
type NVUndefineSpace struct {
	// TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
	AuthHandle handle `gotpm:"handle,auth"`
	// the NV Index to remove from NV space
	NVIndex handle `gotpm:"handle"`
}

// Command implements the Command interface.
func (*NVUndefineSpace) Command() tpm.CC { return tpm.CCNVUndefineSpace }

// Execute executes the command and returns the response.
func (cmd *NVUndefineSpace) Execute(t transport.TPM, s ...Session) error {
	var rsp NVUndefineSpaceResponse
	return execute(t, cmd, &rsp, s...)
}

// NVUndefineSpaceResponse is the response from TPM2_NV_UndefineSpace.
type NVUndefineSpaceResponse struct{}

// Response implements the Response interface.
func (*NVUndefineSpaceResponse) Response() tpm.CC { return tpm.CCNVUndefineSpace }

// NVUndefineSpaceSpecial is the input to TPM2_NV_UndefineSpaceSpecial.
// See definition in Part 3, Commands, section 31.5.
type NVUndefineSpaceSpecial struct {
	// Index to be deleted
	NVIndex handle `gotpm:"handle,auth"`
	// TPM_RH_PLATFORM+{PP}
	Platform handle `gotpm:"handle,auth"`
}

// Command implements the Command interface.
func (*NVUndefineSpaceSpecial) Command() tpm.CC { return tpm.CCNVUndefineSpaceSpecial }

// Execute executes the command and returns the response.
func (cmd *NVUndefineSpaceSpecial) Execute(t transport.TPM, s ...Session) error {
	var rsp NVUndefineSpaceSpecialResponse
	return execute(t, cmd, &rsp, s...)
}

// NVUndefineSpaceSpecialResponse is the response from TPM2_NV_UndefineSpaceSpecial.
type NVUndefineSpaceSpecialResponse struct{}

// Response implements the Response interface.
func (*NVUndefineSpaceSpecialResponse) Response() tpm.CC { return tpm.CCNVUndefineSpaceSpecial }

// NVReadPublic is the input to TPM2_NV_ReadPublic.
// See definition in Part 3, Commands, section 31.6.
type NVReadPublic struct {
	// the NV index
	NVIndex handle `gotpm:"handle"`
}

// Command implements the Command interface.
func (*NVReadPublic) Command() tpm.CC { return tpm.CCNVReadPublic }

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
	NVPublic tpm2b.NVPublic
	NVName   tpm2b.Name
}

// Response implements the Response interface.
func (*NVReadPublicResponse) Response() tpm.CC { return tpm.CCNVReadPublic }

// NVWrite is the input to TPM2_NV_Write.
// See definition in Part 3, Commands, section 31.7.
type NVWrite struct {
	// handle indicating the source of the authorization value
	AuthHandle handle `gotpm:"handle,auth"`
	// the NV index of the area to write
	NVIndex handle `gotpm:"handle"`
	// the data to write
	Data tpm2b.MaxNVBuffer
	// the octet offset into the NV Area
	Offset uint16
}

// Command implements the Command interface.
func (*NVWrite) Command() tpm.CC { return tpm.CCNVWrite }

// Execute executes the command and returns the response.
func (cmd *NVWrite) Execute(t transport.TPM, s ...Session) error {
	var rsp NVWriteResponse
	return execute(t, cmd, &rsp, s...)
}

// NVWriteResponse is the response from TPM2_NV_Write.
type NVWriteResponse struct{}

// Response implements the Response interface.
func (*NVWriteResponse) Response() tpm.CC { return tpm.CCNVWrite }

// NVWriteLock is the input to TPM2_NV_WriteLock.
// See definition in Part 3, Commands, section 31.11.
type NVWriteLock struct {
	// handle indicating the source of the authorization value
	AuthHandle handle `gotpm:"handle,auth"`
	// the NV index of the area to lock
	NVIndex handle `gotpm:"handle"`
}

// Command implements the Command interface.
func (*NVWriteLock) Command() tpm.CC { return tpm.CCNVWriteLock }

// Execute executes the command and returns the response.
func (cmd *NVWriteLock) Execute(t transport.TPM, s ...Session) error {
	var rsp NVWriteLockResponse
	return execute(t, cmd, &rsp, s...)
}

// NVWriteLockResponse is the response from TPM2_NV_WriteLock.
type NVWriteLockResponse struct{}

// Response implements the Response interface.
func (*NVWriteLockResponse) Response() tpm.CC { return tpm.CCNVWriteLock }

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
func (*NVRead) Command() tpm.CC { return tpm.CCNVRead }

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
	Data tpm2b.MaxNVBuffer
}

// Response implements the Response interface.
func (*NVReadResponse) Response() tpm.CC { return tpm.CCNVRead }

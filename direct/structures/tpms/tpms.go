// package tpms contains the TPM 2.0 structures prefixed by "TPMS_"
package tpms

import "fmt"

// Empty represents a TPMS_EMPTY.
// See definition in Part 2: Structures, section 10.1.
type Empty = struct{}

// PCRSelection represents a TPMS_PCR_SELECTION.
// See definition in Part 2: Structures, section 10.6.2.
type PCRSelection struct {
	Hash      tpmi.AlgHash
	PCRSelect []byte `gotpm:"sized8"`
}

// AlgProperty represents a TPMS_ALG_PROPERTY.
// See definition in Part 2: Structures, section 10.8.1.
type AlgProperty struct {
	// an algorithm identifier
	Alg tpm.AlgID
	// the attributes of the algorithm
	AlgProperties tpma.Algorithm
}

// TaggedProperty represents a TPMS_TAGGED_PROPERTY.
// See definition in Part 2: Structures, section 10.8.2.
type TaggedProperty struct {
	// a property identifier
	Property tpm.PT
	// the value of the property
	Value uint32
}

// TaggedPCRSelect represents a TPMS_TAGGED_PCR_SELECT.
// See definition in Part 2: Structures, section 10.8.3.
type TaggedPCRSelect struct {
	// the property identifier
	Tag tpm.PTPCR
	// the bit map of PCR with the identified property
	PCRSelect []byte `gotpm:"sized8"`
}

// TaggedPolicy represents a TPMS_TAGGED_POLICY.
// See definition in Part 2: Structures, section 10.8.4.
type TaggedPolicy struct {
	// a permanent handle
	Handle tpm.Handle
	// the policy algorithm and hash
	PolicyHash tpmt.HA
}

// ACTData represents a TPMS_ACT_DATA.
// See definition in Part 2: Structures, section 10.8.5.
type ACTData struct {
	// a permanent handle
	Handle tpm.Handle
	// the current timeout of the ACT
	Timeout uint32
	// the state of the ACT
	Attributes tpma.ACT
}

// CapabilityData represents a TPMS_CAPABILITY_DATA.
// See definition in Part 2: Structures, section 10.10.2.
type CapabilityData struct {
	// the capability
	Capability tpm.Cap
	// the capability data
	Data tpmu.Capabilities `gotpm:"tag=Capability"`
}

// ClockInfo represents a TPMS_CLOCK_INFO.
// See definition in Part 2: Structures, section 10.11.1.
type ClockInfo struct {
	// time value in milliseconds that advances while the TPM is powered
	Clock uint64
	// number of occurrences of TPM Reset since the last TPM2_Clear()
	ResetCount uint32
	// number of times that TPM2_Shutdown() or _TPM_Hash_Start have
	// occurred since the last TPM Reset or TPM2_Clear().
	RestartCount uint32
	// no value of Clock greater than the current value of Clock has been
	// previously reported by the TPM. Set to YES on TPM2_Clear().
	Safe tpmi.YesNo
}

// TimeInfo represents a TPMS_TIMEzINFO.
// See definition in Part 2: Structures, section 10.11.6.
type TimeInfo struct {
	// time in milliseconds since the TIme circuit was last reset
	Time uint64
	// a structure containing the clock information
	ClockInfo tpms.ClockInfo
}

// TimeAttestInfo represents a TPMS_TIME_ATTEST_INFO.
// See definition in Part 2: Structures, section 10.12.2.
type TimeAttestInfo struct {
	// the Time, Clock, resetCount, restartCount, and Safe indicator
	Time tpms.TimeInfo
	// a TPM vendor-specific value indicating the version number of the firmware
	FirmwareVersion uint64
}

// CertifyInfo represents a TPMS_CERTIFY_INFO.
// See definition in Part 2: Structures, section 10.12.3.
type CertifyInfo struct {
	// Name of the certified object
	Name tpm2b.Name
	// Qualified Name of the certified object
	QualifiedName tpm2b.Name
}

// QuoteInfo represents a TPMS_QUOTE_INFO.
// See definition in Part 2: Structures, section 10.12.4.
type QuoteInfo struct {
	// information on algID, PCR selected and digest
	PCRSelect tpml.PCRSelection
	// digest of the selected PCR using the hash of the signing key
	PCRDigest tpm2b.Digest
}

// CommandAuditInfo represents a TPMS_COMMAND_AUDIT_INFO.
// See definition in Part 2: Structures, section 10.12.5.
type CommandAuditInfo struct {
	// the monotonic audit counter
	AuditCounter uint64
	// hash algorithm used for the command audit
	DigestAlg tpm.AlgID
	// the current value of the audit digest
	AuditDigest tpm2b.Digest
	// digest of the command codes being audited using digestAlg
	CommandDigest tpm2b.Digest
}

// SessionAuditInfo represents a TPMS_SESSION_AUDIT_INFO.
// See definition in Part 2: Structures, section 10.12.6.
type SessionAuditInfo struct {
	// current exclusive status of the session
	ExclusiveSession tpmi.YesNo
	// the current value of the session audit digest
	SessionDigest tpm2b.Digest
}

// CreationInfo represents a TPMS_CREATION_INFO.
// See definition in Part 2: Structures, section 10.12.7.
type CreationInfo struct {
	// Name of the object
	ObjectName tpm2b.Name
	// creationHash
	CreationHash tpm2b.Digest
}

// NVCertifyInfo represents a TPMS_NV_CERTIFY_INFO.
// See definition in Part 2: Structures, section 10.12.8.
type NVCertifyInfo struct {
	// Name of the NV Index
	IndexName tpm2b.Name
	// the offset parameter of TPM2_NV_Certify()
	Offset uint16
	// contents of the NV Index
	NVContents tpm2b.Data
}

// NVDigestCertifyInfo represents a TPMS_NV_DIGEST_CERTIFY_INFO.
// See definition in Part 2: Structures, section 10.12.9.
type NVDigestCertifyInfo struct {
	// Name of the NV Index
	IndexName tpm2b.Name
	// hash of the contents of the index
	NVDigest tpm2b.Digest
}

// Attest represents a TPMS_ATTEST.
// See definition in Part 2: Structures, section 10.12.12.
type Attest struct {
	// the indication that this structure was created by a TPM (always TPM_GENERATED_VALUE)
	Magic tpm.Generated `gotpm:"check"`
	// type of the attestation structure
	Type tpmi.STAttest
	// Qualified Name of the signing key
	QualifiedSigner tpm2b.Name
	// external information supplied by caller
	ExtraData tpm2b.Data
	// Clock, resetCount, restartCount, and Safe
	ClockInfo tpms.ClockInfo
	// TPM-vendor-specific value identifying the version number of the firmware
	FirmwareVersion uint64
	// the type-specific attestation information
	Attested tpmu.Attest `gotpm:"tag=Type"`
}

// AuthCommand represents a TPMS_AUTH_COMMAND.
// See definition in Part 2: Structures, section 10.13.2.
type AuthCommand struct {
	Handle        tpmi.SHAuthSession
	Nonce         tpm2b.Nonce
	Attributes    tpma.Session
	Authorization tpm2b.Data
}

// AuthResponse represents a TPMS_AUTH_RESPONSE.
// See definition in Part 2: Structures, section 10.13.3.
type AuthResponse struct {
	Nonce         tpm2b.Nonce
	Attributes    tpma.Session
	Authorization tpm2b.Data
}

// SymCipherParms represents a TPMS_SYMCIPHER_PARMS.
// See definition in Part 2: Structures, section 11.1.9.
type SymCipherParms struct {
	// a symmetric block cipher
	Sym tpmt.SymDefObject
}

// SensitiveCreate represents a TPMS_SENSITIVE_CREATE.
// See definition in Part 2: Structures, section 11.1.15.
type SensitiveCreate struct {
	// the USER auth secret value.
	UserAuth tpm2b.Auth
	// data to be sealed, a key, or derivation values.
	Data tpm2b.Data
}

// SchemeHash represents a TPMS_SCHEME_HASH.
// See definition in Part 2: Structures, section 11.1.17.
type SchemeHash struct {
	// the hash algorithm used to digest the message
	HashAlg tpmi.AlgHash
}

// SchemeHMAC represents a TPMS_SCHEME_HMAC.
// See definition in Part 2: Structures, section 11.1.20.
type SchemeHMAC tpms.SchemeHash

// SchemeXOR represents a TPMS_SCHEME_XOR.
// See definition in Part 2: Structures, section 11.1.21.
type SchemeXOR struct {
	// the hash algorithm used to digest the message
	HashAlg tpmi.AlgHash
	// the key derivation function
	KDF tpmi.AlgKDF
}

// SigSchemeRSASSA represents a TPMS_SIG_SCHEME_RSASSA.
// See definition in Part 2: Structures, section 11.2.1.2.
type SigSchemeRSASSA tpms.SchemeHash

// SigSchemeRSAPSS represents a TPMS_SIG_SCHEME_RSAPSS.
// See definition in Part 2: Structures, section 11.2.1.2.
type SigSchemeRSAPSS tpms.SchemeHash

// SigSchemeECDSA represents a TPMS_SIG_SCHEME_ECDSA.
// See definition in Part 2: Structures, section 11.2.1.3.
type SigSchemeECDSA tpms.SchemeHash

// EncSchemeRSAES represents a TPMS_ENC_SCHEME_RSAES.
// See definition in Part 2: Structures, section 11.2.2.2.
type EncSchemeRSAES tpms.Empty

// EncSchemeOAEP represents a TPMS_ENC_SCHEME_OAEP.
// See definition in Part 2: Structures, section 11.2.2.2.
type EncSchemeOAEP tpms.SchemeHash

// KeySchemeECDH represents a TPMS_KEY_SCHEME_ECDH.
// See definition in Part 2: Structures, section 11.2.2.3.
type KeySchemeECDH tpms.SchemeHash

// KDFSchemeMGF1 represents a TPMS_KDF_SCHEME_MGF1.
// See definition in Part 2: Structures, section 11.2.3.1.
type KDFSchemeMGF1 tpms.SchemeHash

// KDFSchemeECDH represents a TPMS_KDF_SCHEME_ECDH.
// See definition in Part 2: Structures, section 11.2.3.1.
type KDFSchemeECDH tpms.SchemeHash

// KDFSchemeKDF1SP80056A represents a TPMS_KDF_SCHEME_KDF1SP80056A.
// See definition in Part 2: Structures, section 11.2.3.1.
type KDFSchemeKDF1SP80056A tpms.SchemeHash

// KDFSchemeKDF2 represents a TPMS_KDF_SCHEME_KDF2.
// See definition in Part 2: Structures, section 11.2.3.1.
type KDFSchemeKDF2 tpms.SchemeHash

// KDFSchemeKDF1SP800108 represents a TPMS_KDF_SCHEME_KDF1SP800108.
// See definition in Part 2: Structures, section 11.2.3.1.
type KDFSchemeKDF1SP800108 tpms.SchemeHash

// ECCPoint represents a TPMS_ECC_POINT.
// See definition in Part 2: Structures, section 11.2.5.2.
type ECCPoint struct {
	// X coordinate
	X tpm2b.ECCParameter
	// Y coordinate
	Y tpm2b.ECCParameter
}

// SignatureRSA represents a TPMS_SIGNATURE_RSA.
// See definition in Part 2: Structures, section 11.3.1.
type SignatureRSA struct {
	// the hash algorithm used to digest the message
	Hash tpmi.AlgHash
	// The signature is the size of a public key.
	Sig tpm2b.PublicKeyRSA
}

// SignatureECC represents a TPMS_SIGNATURE_ECC.
// See definition in Part 2: Structures, section 11.3.2.
type SignatureECC struct {
	// the hash algorithm used in the signature process
	Hash       tpmi.AlgHash
	SignatureR tpm2b.ECCParameter
	SignatureS tpm2b.ECCParameter
}

// KeyedHashParms represents a TPMS_KEYED_HASH_PARMS.
// See definition in Part 2: Structures, section 12.2.3.3.
type KeyedHashParms struct {
	// Indicates the signing method used for a keyedHash signing
	// object. This field also determines the size of the data field
	// for a data object created with TPM2_Create() or
	// TPM2_CreatePrimary().
	Scheme tpmt.KeyedHashScheme
}

// RSAParms represents a TPMS_RSA_PARMS.
// See definition in Part 2: Structures, section 12.2.3.5.
type RSAParms struct {
	// for a restricted decryption key, shall be set to a supported
	// symmetric algorithm, key size, and mode.
	// if the key is not a restricted decryption key, this field shall
	// be set to TPM_ALG_NULL.
	Symmetric tpmt.SymDefObject
	// scheme.scheme shall be:
	// for an unrestricted signing key, either TPM_ALG_RSAPSS
	// TPM_ALG_RSASSA or TPM_ALG_NULL
	// for a restricted signing key, either TPM_ALG_RSAPSS or
	// TPM_ALG_RSASSA
	// for an unrestricted decryption key, TPM_ALG_RSAES, TPM_ALG_OAEP,
	// or TPM_ALG_NULL unless the object also has the sign attribute
	// for a restricted decryption key, TPM_ALG_NULL
	Scheme tpmt.RSAScheme
	// number of bits in the public modulus
	KeyBits tpmi.RSAKeyBits
	// the public exponent
	// A prime number greater than 2.
	Exponent uint32
}

// ECCParms represents a TPMS_ECC_PARMS.
// See definition in Part 2: Structures, section 12.2.3.6.
type ECCParms struct {
	// for a restricted decryption key, shall be set to a supported
	// symmetric algorithm, key size. and mode.
	// if the key is not a restricted decryption key, this field shall
	// be set to TPM_ALG_NULL.
	Symmetric tpmt.SymDefObject
	// If the sign attribute of the key is SET, then this shall be a
	// valid signing scheme.
	Scheme tpmt.ECCScheme
	// ECC curve ID
	CurveID tpmi.ECCCurve
	// an optional key derivation scheme for generating a symmetric key
	// from a Z value
	// If the kdf parameter associated with curveID is not TPM_ALG_NULL
	// then this is required to be NULL.
	KDF tpmt.KDFScheme
}

// CreationData represents a TPMS_CREATION_DATA.
// See definition in Part 2: Structures, section 15.1.
type CreationData struct {
	// list indicating the PCR included in pcrDigest
	PCRSelect tpml.PCRSelection
	// digest of the selected PCR using nameAlg of the object for which
	// this structure is being created
	PCRDigest tpm2b.Digest
	// the locality at which the object was created
	Locality tpma.Locality
	// nameAlg of the parent
	ParentNameAlg tpm.AlgID
	// Name of the parent at time of creation
	ParentName tpm2b.Name
	// Qualified Name of the parent at the time of creation
	ParentQualifiedName tpm2b.Name
	// association with additional information added by the key
	OutsideInfo tpm2b.Data
}


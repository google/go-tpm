// package tpms contains the TPM 2.0 structures prefixed by "TPMS_"
package tpms

import "github.com/google/go-tpm/direct/structures/internal"

// Empty represents a TPMS_EMPTY.
// See definition in Part 2: Structures, section 10.1.
type Empty = internal.TPMSEmpty

// PCRSelection represents a TPMS_PCR_SELECTION.
// See definition in Part 2: Structures, section 10.6.2.
type PCRSelection = internal.TPMSPCRSelection

// AlgProperty represents a TPMS_ALG_PROPERTY.
// See definition in Part 2: Structures, section 10.8.1.
type AlgProperty = internal.TPMSAlgProperty

// TaggedProperty represents a TPMS_TAGGED_PROPERTY.
// See definition in Part 2: Structures, section 10.8.2.
type TaggedProperty = internal.TPMSTaggedProperty

// TaggedPCRSelect represents a TPMS_TAGGED_PCR_SELECT.
// See definition in Part 2: Structures, section 10.8.3.
type TaggedPCRSelect = internal.TPMSTaggedPCRSelect

// TaggedPolicy represents a TPMS_TAGGED_POLICY.
// See definition in Part 2: Structures, section 10.8.4.
type TaggedPolicy = internal.TPMSTaggedPolicy

// ACTData represents a TPMS_ACT_DATA.
// See definition in Part 2: Structures, section 10.8.5.
type ACTData = internal.TPMSACTData

// CapabilityData represents a TPMS_CAPABILITY_DATA.
// See definition in Part 2: Structures, section 10.10.2.
type CapabilityData = internal.TPMSCapabilityData

// ClockInfo represents a TPMS_CLOCK_INFO.
// See definition in Part 2: Structures, section 10.11.1.
type ClockInfo = internal.TPMSClockInfo

// TimeInfo represents a TPMS_TIMEzINFO.
// See definition in Part 2: Structures, section 10.11.6.
type TimeInfo = internal.TPMSTimeInfo

// TimeAttestInfo represents a TPMS_TIME_ATTEST_INFO.
// See definition in Part 2: Structures, section 10.12.2.
type TimeAttestInfo = internal.TPMSTimeAttestInfo

// CertifyInfo represents a TPMS_CERTIFY_INFO.
// See definition in Part 2: Structures, section 10.12.3.
type CertifyInfo = internal.TPMSCertifyInfo

// QuoteInfo represents a TPMS_QUOTE_INFO.
// See definition in Part 2: Structures, section 10.12.4.
type QuoteInfo = internal.TPMSQuoteInfo

// CommandAuditInfo represents a TPMS_COMMAND_AUDIT_INFO.
// See definition in Part 2: Structures, section 10.12.5.
type CommandAuditInfo = internal.TPMSCommandAuditInfo

// SessionAuditInfo represents a TPMS_SESSION_AUDIT_INFO.
// See definition in Part 2: Structures, section 10.12.6.
type SessionAuditInfo = internal.TPMSSessionAuditInfo

// CreationInfo represents a TPMS_CREATION_INFO.
// See definition in Part 2: Structures, section 10.12.7.
type CreationInfo = internal.TPMSCreationInfo

// NVCertifyInfo represents a TPMS_NV_CERTIFY_INFO.
// See definition in Part 2: Structures, section 10.12.8.
type NVCertifyInfo = internal.TPMSNVCertifyInfo

// NVDigestCertifyInfo represents a TPMS_NV_DIGEST_CERTIFY_INFO.
// See definition in Part 2: Structures, section 10.12.9.
type NVDigestCertifyInfo = internal.TPMSNVDigestCertifyInfo

// Attest represents a TPMS_ATTEST.
// See definition in Part 2: Structures, section 10.12.12.
type Attest = internal.TPMSAttest

// AuthCommand represents a TPMS_AUTH_COMMAND.
// See definition in Part 2: Structures, section 10.13.2.
type AuthCommand = internal.TPMSAuthCommand

// AuthResponse represents a TPMS_AUTH_RESPONSE.
// See definition in Part 2: Structures, section 10.13.3.
type AuthResponse = internal.TPMSAuthResponse

// SymCipherParms represents a TPMS_SYMCIPHER_PARMS.
// See definition in Part 2: Structures, section 11.1.9.
type SymCipherParms = internal.TPMSSymCipherParms

// SensitiveCreate represents a TPMS_SENSITIVE_CREATE.
// See definition in Part 2: Structures, section 11.1.15.
type SensitiveCreate = internal.TPMSSensitiveCreate

// SchemeHash represents a TPMS_SCHEME_HASH.
// See definition in Part 2: Structures, section 11.1.17.
type SchemeHash = internal.TPMSSchemeHash

// SchemeHMAC represents a TPMS_SCHEME_HMAC.
// See definition in Part 2: Structures, section 11.1.20.
type SchemeHMAC = internal.TPMSSchemeHMAC

// SchemeXOR represents a TPMS_SCHEME_XOR.
// See definition in Part 2: Structures, section 11.1.21.
type SchemeXOR = internal.TPMSSchemeXOR

// SigSchemeRSASSA represents a TPMS_SIG_SCHEME_RSASSA.
// See definition in Part 2: Structures, section 11.2.1.2.
type SigSchemeRSASSA = internal.TPMSSigSchemeRSASSA

// SigSchemeRSAPSS represents a TPMS_SIG_SCHEME_RSAPSS.
// See definition in Part 2: Structures, section 11.2.1.2.
type SigSchemeRSAPSS = internal.TPMSSigSchemeRSAPSS

// SigSchemeECDSA represents a TPMS_SIG_SCHEME_ECDSA.
// See definition in Part 2: Structures, section 11.2.1.3.
type SigSchemeECDSA = internal.TPMSSigSchemeECDSA

// EncSchemeRSAES represents a TPMS_ENC_SCHEME_RSAES.
// See definition in Part 2: Structures, section 11.2.2.2.
type EncSchemeRSAES = internal.TPMSEncSchemeRSAES

// EncSchemeOAEP represents a TPMS_ENC_SCHEME_OAEP.
// See definition in Part 2: Structures, section 11.2.2.2.
type EncSchemeOAEP = internal.TPMSEncSchemeOAEP

// KeySchemeECDH represents a TPMS_KEY_SCHEME_ECDH.
// See definition in Part 2: Structures, section 11.2.2.3.
type KeySchemeECDH = internal.TPMSKeySchemeECDH

// KDFSchemeMGF1 represents a TPMS_KDF_SCHEME_MGF1.
// See definition in Part 2: Structures, section 11.2.3.1.
type KDFSchemeMGF1 = internal.TPMSKDFSchemeMGF1

// KDFSchemeECDH represents a TPMS_KDF_SCHEME_ECDH.
// See definition in Part 2: Structures, section 11.2.3.1.
type KDFSchemeECDH = internal.TPMSKDFSchemeECDH

// KDFSchemeKDF1SP80056A represents a TPMS_KDF_SCHEME_KDF1SP80056A.
// See definition in Part 2: Structures, section 11.2.3.1.
type KDFSchemeKDF1SP80056A = internal.TPMSKDFSchemeKDF1SP80056A

// KDFSchemeKDF2 represents a TPMS_KDF_SCHEME_KDF2.
// See definition in Part 2: Structures, section 11.2.3.1.
type KDFSchemeKDF2 = internal.TPMSKDFSchemeKDF2

// KDFSchemeKDF1SP800108 represents a TPMS_KDF_SCHEME_KDF1SP800108.
// See definition in Part 2: Structures, section 11.2.3.1.
type KDFSchemeKDF1SP800108 = internal.TPMSKDFSchemeKDF1SP800108

// ECCPoint represents a TPMS_ECC_POINT.
// See definition in Part 2: Structures, section 11.2.5.2.
type ECCPoint = internal.TPMSECCPoint

// SignatureRSA represents a TPMS_SIGNATURE_RSA.
// See definition in Part 2: Structures, section 11.3.1.
type SignatureRSA = internal.TPMSSignatureRSA

// SignatureECC represents a TPMS_SIGNATURE_ECC.
// See definition in Part 2: Structures, section 11.3.2.
type SignatureECC = internal.TPMSSignatureECC

// KeyedHashParms represents a TPMS_KEYED_HASH_PARMS.
// See definition in Part 2: Structures, section 12.2.3.3.
type KeyedHashParms = internal.TPMSKeyedHashParms

// RSAParms represents a TPMS_RSA_PARMS.
// See definition in Part 2: Structures, section 12.2.3.5.
type RSAParms = internal.TPMSRSAParms

// ECCParms represents a TPMS_ECC_PARMS.
// See definition in Part 2: Structures, section 12.2.3.6.
type ECCParms = internal.TPMSECCParms

// CreationData represents a TPMS_CREATION_DATA.
// See definition in Part 2: Structures, section 15.1.
type CreationData = internal.TPMSCreationData

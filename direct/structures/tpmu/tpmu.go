// package tpmu contains TPM 2.0 structures prefixed with "TPMU_"
package tpmu

import "fmt"

// HA represents a TPMU_HA.
// See definition in Part 2: Structures, section 10.3.1.
type HA struct {
	SHA1     *[20]byte `gotpm:"selector=0x0004"` // TPM_ALG_SHA1
	SHA256   *[32]byte `gotpm:"selector=0x000B"` // TPM_ALG_SHA256
	SHA384   *[48]byte `gotpm:"selector=0x000C"` // TPM_ALG_SHA384
	SHA512   *[64]byte `gotpm:"selector=0x000D"` // TPM_ALG_SHA512
	SHA3x256 *[32]byte `gotpm:"selector=0x0027"` // TPM_ALG_SHA3_256
	SHA3x384 *[48]byte `gotpm:"selector=0x0028"` // TPM_ALG_SHA3_384
	SHA3x512 *[64]byte `gotpm:"selector=0x0029"` // TPM_ALG_SHA3_512
}

// Capabilities represents a TPMU_CAPABILITIES.
// See definition in Part 2: Structures, section 10.10.1.
type Capabilities struct {
	Algorithms    *tpml.AlgProperty       `gotpm:"selector=0x00000000"` // TPM_CAP_ALGS
	Handles       *tpml.Handle            `gotpm:"selector=0x00000001"` // TPM_CAP_HANDLES
	Command       *tpml.CCA               `gotpm:"selector=0x00000002"` // TPM_CAP_COMMANDS
	PPCommands    *tpml.CC                `gotpm:"selector=0x00000003"` // TPM_CAP_PP_COMMANDS
	AuditCommands *tpml.CC                `gotpm:"selector=0x00000004"` // TPM_CAP_AUDIT_COMMANDS
	AssignedPCR   *tpml.PCRSelection      `gotpm:"selector=0x00000005"` // TPM_CAP_PCRS
	TPMProperties *tpml.TaggedTPMProperty `gotpm:"selector=0x00000006"` // TPM_CAP_TPM_PROPERTIES
	PCRProperties *tpml.TaggedPCRProperty `gotpm:"selector=0x00000007"` // TPM_CAP_PCR_PROPERTIES
	ECCCurves     *tpml.ECCCurve          `gotpm:"selector=0x00000008"` // TPM_CAP_ECC_CURVES
	AuthPolicies  *tpml.TaggedPolicy      `gotpm:"selector=0x00000009"` // TPM_CAP_AUTH_POLICIES
	ACTData       *tpml.ACTData           `gotpm:"selector=0x0000000A"` // TPM_CAP_ACT
}

// Attest represents a TPMU_ATTEST.
// See definition in Part 2: Structures, section 10.12.11.
type Attest struct {
	NV           *tpms.NVCertifyInfo       `gotpm:"selector=0x8014"` // TPM_ST_ATTEST_NV
	CommandAudit *tpms.CommandAuditInfo    `gotpm:"selector=0x8015"` // TPM_ST_ATTEST_COMMAND_AUDIT
	SessionAudit *tmps.SessionAuditInfo    `gotpm:"selector=0x8016"` // TPM_ST_ATTEST_SESSION_AUDIT
	Certify      *tpms.CertifyInfo         `gotpm:"selector=0x8017"` // TPM_ST_ATTEST_CERTIFY
	Quote        *tpms.QuoteInfo           `gotpm:"selector=0x8018"` // TPM_ST_ATTEST_QUOTE
	Time         *tpms.TimeAttestInfo      `gotpm:"selector=0x8019"` // TPM_ST_ATTEST_TIME
	Creation     *tpms.CreationInfo        `gotpm:"selector=0x801A"` // TPM_ST_ATTEST_CREATION
	NVDigest     *tpms.NVDigestCertifyInfo `gotpm:"selector=0x801C"` // TPM_ST_ATTEST_NV_DIGEST
}

// SymKeyBits represents a TPMU_SYM_KEY_BITS.
// See definition in Part 2: Structures, section 11.1.3.
type SymKeyBits struct {
	// TODO: The rest of the symmetric algorithms get their own entry
	// in this union.
	AES *tpm.KeyBits  `gotpm:"selector=0x0006"` // TPM_ALG_AES
	XOR *tpmi.AlgHash `gotpm:"selector=0x000A"` // TPM_ALG_XOR
}

// SymMode represents a TPMU_SYM_MODE.
// See definition in Part 2: Structures, section 11.1.4.
type SymMode struct {
	// TODO: The rest of the symmetric algorithms get their own entry
	// in this union.
	AES *tpmi.AlgSymMode `gotpm:"selector=0x0006"` // TPM_ALG_AES
	XOR *struct{}       `gotpm:"selector=0x000A"` // TPM_ALG_XOR
}

// SymDetails represents a TPMU_SYM_DETAILS.
// See definition in Part 2: Structures, section 11.1.5.
type SymDetails struct {
	// TODO: The rest of the symmetric algorithms get their own entry
	// in this union.
	AES *struct{} `gotpm:"selector=0x0006"` // TPM_ALG_AES
	XOR *struct{} `gotpm:"selector=0x000A"` // TPM_ALG_XOR
}

// SchemeKeyedHash represents a TPMU_SCHEME_KEYEDHASH.
// See definition in Part 2: Structures, section 11.1.22.
type SchemeKeyedHash struct {
	HMAC *tpms.SchemeHMAC `gotpm:"selector=0x0005"` // TPM_ALG_HMAC
	XOR  *tpms.SchemeXOR  `gotpm:"selector=0x000A"` // TPM_ALG_XOR
}

// SigScheme represents a TPMU_SIG_SCHEME.
// See definition in Part 2: Structures, section 11.2.1.4.
type SigScheme struct {
	HMAC   *tpms.SchemeHMAC `gotpm:"selector=0x0005"` // TPM_ALG_HMAC
	RSASSA *tpms.SchemeHash `gotpm:"selector=0x0014"` // TPM_ALG_RSASSA
	RSAPSS *tpms.SchemeHash `gotpm:"selector=0x0016"` // TPM_ALG_RSAPSS
	ECDSA  *tpms.SchemeHash `gotpm:"selector=0x0018"` // TPM_ALG_ECDSA
}

// KDFScheme represents a TPMU_KDF_SCHEME.
// See definition in Part 2: Structures, section 11.2.3.2.
type KDFScheme struct {
	MGF1         *tpms.KDFSchemeMGF1         `gotpm:"selector=0x0007"` // TPM_ALG_MGF1
	ECDH         *tpms.KDFSchemeECDH         `gotpm:"selector=0x0019"` // TPM_ALG_ECDH
	KDF1SP80056A *tpms.KDFSchemeKDF1SP80056A `gotpm:"selector=0x0020"` // TPM_ALG_KDF1_SP800_56A
	KDF2         *tpms.KDFSchemeKDF2         `gotpm:"selector=0x0021"` // TPM_ALG_KDF2
	KDF1SP800108 *tpms.KDFSchemeKDF1SP800108 `gotpm:"selector=0x0022"` // TPM_ALG_KDF1_SP800_108
}

// AsymScheme represents a TPMU_ASYM_SCHEME.
// See definition in Part 2: Structures, section 11.2.3.5.
type AsymScheme struct {
	// TODO every asym scheme gets an entry in this union.
	RSASSA *tpms.SigSchemeRSASSA `gotpm:"selector=0x0014"` // TPM_ALG_RSASSA
	RSAES  *tpms.EncSchemeRSAES  `gotpm:"selector=0x0015"` // TPM_ALG_RSAES
	RSAPSS *tpms.SigSchemeRSAPSS `gotpm:"selector=0x0016"` // TPM_ALG_RSAPSS
	OAEP   *tpms.EncSchemeOAEP   `gotpm:"selector=0x0017"` // TPM_ALG_OAEP
	ECDSA  *tpms.SigSchemeECDSA  `gotpm:"selector=0x0018"` // TPM_ALG_ECDSA
	ECDH   *tpms.KeySchemeECDH   `gotpm:"selector=0x0019"` // TPM_ALG_ECDH
}

// Signature represents a TPMU_SIGNATURE.
// See definition in Part 2: Structures, section 11.3.3.
type Signature struct {
	HMAC   *tpmt.HA           `gotpm:"selector=0x0005"` // TPM_ALG_HMAC
	RSASSA *tpms.SignatureRSA `gotpm:"selector=0x0014"` // TPM_ALG_RSASSA
	RSAPSS *tpms.SignatureRSA `gotpm:"selector=0x0016"` // TPM_ALG_RSAPSS
	ECDSA  *tpms.SignatureECC `gotpm:"selector=0x0018"` // TPM_ALG_ECDSA
}

// PublicID represents a TPMU_PUBLIC_ID.
// See definition in Part 2: Structures, section 12.2.3.2.
type PublicID struct {
	KeyedHash *tpm2b.Digest       `gotpm:"selector=0x0008"` // TPM_ALG_KEYEDHASH
	Sym       *tpm2b.Digest       `gotpm:"selector=0x0025"` // TPM_ALG_SYMCIPHER
	RSA       *tpm2b.PublicKeyRSA `gotpm:"selector=0x0001"` // TPM_ALG_RSA
	ECC       *tpms.ECCPoint      `gotpm:"selector=0x0023"` // TPM_ALG_ECC
}

// PublicParms represents a TPMU_PUBLIC_PARMS.
// See definition in Part 2: Structures, section 12.2.3.7.
type PublicParms struct {
	// sign | decrypt | neither
	KeyedHashDetail *tpms.KeyedHashParms `gotpm:"selector=0x0008"` // TPM_ALG_KEYEDHASH
	// sign | decrypt | neither
	SymCipherDetail *tpms.SymCipherParms `gotpm:"selector=0x0025"` // TPM_ALG_SYMCIPHER
	// decrypt + sign
	RSADetail *tpms.RSAParms `gotpm:"selector=0x0001"` // TPM_ALG_RSA
	// decrypt + sign
	ECCDetail *tpms.ECCParms `gotpm:"selector=0x0023"` // TPM_ALG_ECC
}


// package tpmi contains the TPM 2.0 structures prefixed by "TPMI_"
package tpmi

import (
	"crypto"
	"fmt"

	"github.com/google/go-tpm/direct/structures/tpm"
)

// YesNo represents a TPMI_YES_NO.
// See definition in Part 2: Structures, section 9.2.
// Use native bool for TPMI_YES_NO; encoding/binary already treats this as 8 bits wide.
type YesNo = bool

// DHObject represents a TPMI_DH_OBJECT.
// See definition in Part 2: Structures, section 9.3.
type DHObject = tpm.Handle

// DHEntity represents a TPMI_DH_ENTITY.
// See definition in Part 2: Structures, section 9.6.
type DHEntity = tpm.Handle

// SHAuthSession represents a TPMI_SH_AUTH_SESSION.
// See definition in Part 2: Structures, section 9.8.
type SHAuthSession = tpm.Handle

// SHHMAC represents a TPMI_SH_HMAC.
// See definition in Part 2: Structures, section 9.9.
type SHHMAC = tpm.Handle

// SHPolicy represents a TPMI_SH_POLICY.
// See definition in Part 2: Structures, section 9.10.
type SHPolicy = tpm.Handle

// DHContext represents a TPMI_DH_CONTEXT.
// See definition in Part 2: Structures, section 9.11.
type DHContext = tpm.Handle

// RHHierarchy represents a TPMI_RH_HIERARCHY.
// See definition in Part 2: Structures, section 9.13.
type RHHierarchy = tpm.Handle

// AlgHash represents a TPMI_ALG_HASH.
// See definition in Part 2: Structures, section 9.27.
type AlgHash = tpm.AlgID

// Hash returns the crypto.Hash associated with a tpmi.AlgHash.
func (a AlgHash) Hash() crypto.Hash {
	switch tpm.AlgID(a) {
	case tpm.AlgSHA1:
		return crypto.SHA1
	case tpm.AlgSHA256:
		return crypto.SHA256
	case tpm.AlgSHA384:
		return crypto.SHA384
	case tpm.AlgSHA512:
		return crypto.SHA512
	}
	panic(fmt.Sprintf("unsupported hash algorithm: %v", a))
}

// TODO: Provide a placeholder interface here so we can explicitly enumerate
// these for compile-time protection.

// AlgSym represents a TPMI_ALG_SYM.
// See definition in Part 2: Structures, section 9.29.
type AlgSym = tpm.AlgID

// AlgSymObject represents a TPMI_ALG_SYM_OBJECT.
// See definition in Part 2: Structures, section 9.30.
type AlgSymObject = tpm.AlgID

// AlgSymMode represents a TPMI_ALG_SYM_MODE.
// See definition in Part 2: Structures, section 9.31.
type AlgSymMode = tpm.AlgID

// AlgKDF represents a TPMI_ALG_KDF.
// See definition in Part 2: Structures, section 9.32.
type AlgKDF = tpm.AlgID

// AlgSigScheme represents a TPMI_ALG_SIG_SCHEME.
// See definition in Part 2: Structures, section 9.33.
type AlgSigScheme = tpm.AlgID

// STCommandTag represents a TPMI_ST_COMMAND_TAG.
// See definition in Part 2: Structures, section 9.35.
type STCommandTag = tpm.ST

// STAttest represents a TPMI_ST_ATTEST.
// See definition in Part 2: Structures, section 10.12.10.
type STAttest = tpm.ST

// AlgKeyedHashScheme represents a TPMI_ALG_KEYEDHASH_SCHEME.
// See definition in Part 2: Structures, section 11.1.10.
type AlgKeyedHashScheme = tpm.AlgID

// AlgRSAScheme represents a TPMI_ALG_RSA_SCHEME.
// See definition in Part 2: Structures, section 11.2.4.1.
type AlgRSAScheme = tpm.AlgID

// RSAKeyBits represents a TPMI_RSA_KEY_BITS.
// See definition in Part 2: Structures, section 11.2.4.6.
type RSAKeyBits = tpm.KeyBits

// AlgECCScheme represents a TPMI_ALG_ECC_SCHEME.
// See definition in Part 2: Structures, section 11.2.5.4.
type AlgECCScheme = tpm.AlgID

// ECCCurve represents a TPMI_ECC_CURVE.
// See definition in Part 2: Structures, section 11.2.5.5.
type ECCCurve = tpm.ECCCurve

// AlgPublic represents a TPMI_ALG_PUBLIC.
// See definition in Part 2: Structures, section 12.2.2.
type AlgPublic = tpm.AlgID

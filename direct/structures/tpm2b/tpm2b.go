// package tpm2b contains the TPM 2.0 structures prefixed with "TPM2B_"
package tpm2b

import (
	"github.com/google/go-tpm/direct/structures/internal"
)

// Digest represents a TPM2B_DIGEST.
// See definition in Part 2: Structures, section 10.4.2.
type Digest = internal.TPM2BDigest

// Data represents a TPM2B_DATA.
// See definition in Part 2: Structures, section 10.4.3.
type Data = internal.TPM2BData

// Nonce represents a TPM2B_NONCE.
// See definition in Part 2: Structures, section 10.4.4.
type Nonce = internal.TPM2BNonce

// Event represents a TPM2B_EVENT.
// See definition in Part 2: Structures, section 10.4.7.
type Event = internal.TPM2BEvent

// Timeout represents a TPM2B_TIMEOUT.
// See definition in Part 2: Structures, section 10.4.10.
type Timeout = internal.TPM2BTimeout

// Auth represents a TPM2B_AUTH.
// See definition in Part 2: Structures, section 10.4.5.
type Auth = internal.TPM2BAuth

// Name represents a TPM2B_NAME.
// See definition in Part 2: Structures, section 10.5.3.
// NOTE: This structure does not contain a TPMUName, because that union
// is not tagged with a selector. Instead, TPM2B_Name is flattened and
// all TPMDirect helpers that deal with names will deal with them as so.
type Name = internal.TPM2BName

// Attest represents a TPM2B_ATTEST.
// See definition in Part 2: Structures, section 10.12.13.
// Note that in the spec, this is just a 2B_DATA with enough room for an S_ATTEST.
// For ergonomics, pretend that TPM2B_Attest wraps a TPMS_Attest just like other 2Bs.
type Attest = internal.TPM2BAttest

// SensitiveData represents a TPM2B_SENSITIVE_DATA.
// See definition in Part 2: Structures, section 11.1.14.
type SensitiveData = internal.TPM2BSensitiveData

// SensitiveCreate represents a TPM2B_SENSITIVE_CREATE.
// See definition in Part 2: Structures, section 11.1.16.
type SensitiveCreate = internal.TPM2BSensitiveCreate

// PublicKeyRSA represents a TPM2B_PUBLIC_KEY_RSA.
// See definition in Part 2: Structures, section 11.2.4.5.
type PublicKeyRSA = internal.TPM2BPublicKeyRSA

// ECCParameter represents a TPM2B_ECC_PARAMETER.
// See definition in Part 2: Structures, section 11.2.5.1.
type ECCParameter = internal.TPM2BECCParameter

// EncryptedSecret represents a TPM2B_ENCRYPTED_SECRET.
// See definition in Part 2: Structures, section 11.4.33.
type EncryptedSecret = internal.TPM2BEncryptedSecret

// Public represents a TPM2B_PUBLIC.
// See definition in Part 2: Structures, section 12.2.5.
type Public = internal.TPM2BPublic

// Private represents a TPM2B_PRIVATE.
// See definition in Part 2: Structures, section 12.3.7.
type Private = internal.TPM2BPrivate

// CreationData represents a TPM2B_CREATION_DATA.
// See definition in Part 2: Structures, section 15.2.
type CreationData = internal.TPM2BCreationData

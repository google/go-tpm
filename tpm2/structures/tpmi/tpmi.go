// Package tpmi contains the TPM 2.0 structures prefixed by "TPMI_"
package tpmi

import (
	"github.com/google/go-tpm/tpm2/structures/internal"
)

// YesNo represents a TPMI_YES_NO.
// See definition in Part 2: Structures, section 9.2.
// Use native bool for TPMI_YES_NO; encoding/binary already treats this as 8 bits wide.
type YesNo = internal.TPMIYesNo

// DHObject represents a TPMI_DH_OBJECT.
// See definition in Part 2: Structures, section 9.3.
type DHObject = internal.TPMIDHObject

// DHEntity represents a TPMI_DH_ENTITY.
// See definition in Part 2: Structures, section 9.6.
type DHEntity = internal.TPMIDHEntity

// SHAuthSession represents a TPMI_SH_AUTH_SESSION.
// See definition in Part 2: Structures, section 9.8.
type SHAuthSession = internal.TPMISHAuthSession

// SHHMAC represents a TPMI_SH_HMAC.
// See definition in Part 2: Structures, section 9.9.
type SHHMAC = internal.TPMISHHMAC

// SHPolicy represents a TPMI_SH_POLICY.
// See definition in Part 2: Structures, section 9.10.
type SHPolicy = internal.TPMISHPolicy

// DHContext represents a TPMI_DH_CONTEXT.
// See definition in Part 2: Structures, section 9.11.
type DHContext = internal.TPMIDHContext

// RHHierarchy represents a TPMI_RH_HIERARCHY.
// See definition in Part 2: Structures, section 9.13.
type RHHierarchy = internal.TPMIRHHierarchy

// RHEnables represents a TPMI_RH_ENABLES.
// See definition in Part 2: Structures, section 9.14.
type RHEnables = internal.TPMIRHEnables

// RHHierarchyAuth represents a TPMI_RH_HIERARCHY_AUTH.
// See definition in Part 2: Structures, section 9.15.
type RHHierarchyAuth = internal.TPMIRHHierarchyAuth

// RHHierarchyPolicy represents a TPMI_RH_HIERARCHY_POLICY.
// See definition in Part 2: Structures, section 9.16.
type RHHierarchyPolicy = internal.TPMIRHHierarchyPolicy

// RHPlatform represents a TPMI_RH_PLATFORM.
// See definition in Part 2: Structures, section 9.17.
type RHPlatform = internal.TPMIRHPlatform

// RHOwner represents a TPMI_RH_OWNER.
// See definition in Part 2: Structures, section 9.18.
type RHOwner = internal.TPMIRHOwner

// RHEndorsement represents a TPMI_RH_ENDORSEMENT.
// See definition in Part 2: Structures, section 9.19.
type RHEndorsement = internal.TPMIRHEndorsement

// RHProvision represents a TPMI_RH_PROVISION.
// See definition in Part 2: Structures, section 9.20.
type RHProvision = internal.TPMIRHProvision

// RHClear represents a TPMI_RH_CLEAR.
// See definition in Part 2: Structures, section 9.21.
type RHClear = internal.TPMIRHClear

// RHNVAuth represents a TPMI_RH_NV_AUTH.
// See definition in Part 2: Structures, section 9.22.
type RHNVAuth = internal.TPMIRHNVAuth

// RHLockout represents a TPMI_RH_LOCKOUT.
// See definition in Part 2: Structures, section 9.23.
type RHLockout = internal.TPMIRHLockout

// RHNVIndex represents a TPMI_RH_NV_INDEX.
// See definition in Part 2: Structures, section 9.24.
type RHNVIndex = internal.TPMIRHNVIndex

// RHAC represents a TPMI_RH_AC.
// See definition in Part 2: Structures, section 9.25.
type RHAC = internal.TPMIRHAC

// RHACT represents a TPMI_RH_ACT.
// See definition in Part 2: Structures, section 9.26.
type RHACT = internal.TPMIRHACT

// AlgHash represents a TPMI_ALG_HASH.
// See definition in Part 2: Structures, section 9.27.
type AlgHash = internal.TPMIAlgHash

// AlgSym represents a TPMI_ALG_SYM.
// See definition in Part 2: Structures, section 9.29.
type AlgSym = internal.TPMIAlgSym

// AlgSymObject represents a TPMI_ALG_SYM_OBJECT.
// See definition in Part 2: Structures, section 9.30.
type AlgSymObject = internal.TPMIAlgSymObject

// AlgSymMode represents a TPMI_ALG_SYM_MODE.
// See definition in Part 2: Structures, section 9.31.
type AlgSymMode = internal.TPMIAlgSymMode

// AlgKDF represents a TPMI_ALG_KDF.
// See definition in Part 2: Structures, section 9.32.
type AlgKDF = internal.TPMIAlgKDF

// AlgSigScheme represents a TPMI_ALG_SIG_SCHEME.
// See definition in Part 2: Structures, section 9.33.
type AlgSigScheme = internal.TPMIAlgSigScheme

// STCommandTag represents a TPMI_ST_COMMAND_TAG.
// See definition in Part 2: Structures, section 9.35.
type STCommandTag = internal.TPMISTCommandTag

// STAttest represents a TPMI_ST_ATTEST.
// See definition in Part 2: Structures, section 10.12.10.
type STAttest = internal.TPMISTAttest

// AlgKeyedHashScheme represents a TPMI_ALG_KEYEDHASH_SCHEME.
// See definition in Part 2: Structures, section 11.1.10.
type AlgKeyedHashScheme = internal.TPMIAlgKeyedHashScheme

// AlgRSAScheme represents a TPMI_ALG_RSA_SCHEME.
// See definition in Part 2: Structures, section 11.2.4.1.
type AlgRSAScheme = internal.TPMIAlgRSAScheme

// RSAKeyBits represents a TPMI_RSA_KEY_BITS.
// See definition in Part 2: Structures, section 11.2.4.6.
type RSAKeyBits = internal.TPMIRSAKeyBits

// AlgECCScheme represents a TPMI_ALG_ECC_SCHEME.
// See definition in Part 2: Structures, section 11.2.5.4.
type AlgECCScheme = internal.TPMIAlgECCScheme

// ECCCurve represents a TPMI_ECC_CURVE.
// See definition in Part 2: Structures, section 11.2.5.5.
type ECCCurve = internal.TPMIECCCurve

// AlgPublic represents a TPMI_ALG_PUBLIC.
// See definition in Part 2: Structures, section 12.2.2.
type AlgPublic = internal.TPMIAlgPublic

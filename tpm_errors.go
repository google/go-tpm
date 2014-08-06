// Copyright (c) 2014, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tpm

import (
	"strconv"
)

// A tpmError is an error value from the TPM.
type tpmError uint32

// Error produces a string for the given TPM Error code
func (o tpmError) Error() string {
	if s, ok := tpmErrMsgs[o]; ok {
		return "tpm: " + s
	}

	return "tpm: unknown error code " + strconv.Itoa(int(o))
}

// These are the TPM error codes from the spec.
const (
	_                    = iota
	ErrAuthFail tpmError = iota
	ErrBadIndex
	ErrBadParameter
	ErrAuditFailure
	ErrClearDisabled
	ErrDeactivated
	ErrDisabled
	ErrDisabledCmd
	ErrFail
	ErrBadOrdinal
	ErrInstallDisabled
	ErrInvalidKeyHandle
	ErrKeyNotFound
	ErrInappropriateEnc
	ErrMigrateFail
	ErrInvalidPCRInfo
	ErrNoSpace
	ErrNoSRK
	ErrNotSealedBlob
	ErrOwnerSet
	ErrResources
	ErrShortRandom
	ErrSize
	ErrWrongPCRVal
	ErrBadParamSize
	ErrSHAThread
	ErrSHAError
	ErrFailedSelfTest
	ErrAuth2Fail
	ErrBadTag
	ErrIOError
	ErrEncryptError
	ErrDecryptError
	ErrInvalidAuthHandle
	ErrNoEndorsement
	ErrInvalidKeyUsage
	ErrWrongEntityType
	ErrInvalidPostInit
	ErrInappropriateSig
	ErrBadKeyProperty
	ErrBadMigration
	ErrBadScheme
	ErrBadDatasize
	ErrBadMode
	ErrBadPresence
	ErrBadVersion
	ErrNoWrapTransport
	ErrAuditFailUnsuccessful
	ErrAuditFailSuccessful
	ErrNotResetable
	ErrNotLocal
	ErrBadType
	ErrInvalidResource
	ErrNotFIPS
	ErrInvalidFamily
	ErrNoNVPermission
	ErrRequiresSign
	ErrKeyNotSupported
	ErrAuthConflict
	ErrAreaLocked
	ErrBadLocality
	ErrReadOnly
	ErrPerNoWrite
	ErrFamilyCount
	ErrWriteLocked
	ErrBadAttributes
	ErrInvalidStructure
	ErrKeyOwnerControl
	ErrBadCounter
	ErrNotFullWrite
	ErrContextGap
	ErrMaxNVWrites
	ErrNoOperator
	ErrResourceMissing
	ErrDelegateLock
	ErrDelegateFamliy
	ErrDelegateAdmin
	ErrTransportNotExclusive
	ErrOwnerControl
	ErrDAAResources
	ErrDAAInputData0
	ErrDAAInputData1
	ErrDAAIssuerSettings
	ErrDAASettings
	ErrDAAState
	ErrDAAIssuerVailidity
	ErrDAAWrongW
	ErrBadHandle
	ErrBadDelegate
	ErrBadContext
	ErrTooManyContexts
	ErrMATicketSignature
	ErrMADestination
	ErrMASource
	ErrMAAuthority
)

// Extra messages the TPM might return.
const ErrDefendLockRunning tpmError = 2051

// tpmErrMsgs maps tpmError codes to their associated error strings.
var tpmErrMsgs = map[tpmError]string{
	ErrAuthFail:              "authentication failed",
	ErrBadIndex:              "the index to a PCR, DIR or other register is incorrect",
	ErrBadParameter:          "one or more parameter is bad",
	ErrAuditFailure:          "an operation completed successfully but the auditing of that operation failed",
	ErrClearDisabled:         "the clear disable flag is set and all clear operations now require physical access",
	ErrDeactivated:           "the TPM is deactivated",
	ErrDisabled:              "the TPM is disabled",
	ErrDisabledCmd:           "the target command has been disabled",
	ErrFail:                  "the operation failed",
	ErrBadOrdinal:            "the ordinal was unknown or inconsistent",
	ErrInstallDisabled:       "the ability to install an owner is disabled",
	ErrInvalidKeyHandle:      "the key handle can not be interpreted",
	ErrKeyNotFound:           "the key handle points to an invalid key",
	ErrInappropriateEnc:      "unacceptable encryption scheme",
	ErrMigrateFail:           "migration authorization failed",
	ErrInvalidPCRInfo:        "PCR information could not be interpreted",
	ErrNoSpace:               "no room to load key",
	ErrNoSRK:                 "there is no SRK set",
	ErrNotSealedBlob:         "an encrypted blob is invalid or was not created by this TPM",
	ErrOwnerSet:              "there is already an Owner",
	ErrResources:             "the TPM has insufficient internal resources to perform the requested action",
	ErrShortRandom:           "a random string was too short",
	ErrSize:                  "the TPM does not have the space to perform the operation",
	ErrWrongPCRVal:           "the named PCR value does not match the current PCR value",
	ErrBadParamSize:          "the paramSize argument to the command has the incorrect value",
	ErrSHAThread:             "there is no existing SHA-1 thread",
	ErrSHAError:              "the calculation is unable to proceed because the existing SHA-1 thread has already encountered an error",
	ErrFailedSelfTest:        "self-test has failed and the TPM has shutdown",
	ErrAuth2Fail:             "the authorization for the second key in a 2 key function failed authorization",
	ErrBadTag:                "the tag value sent to for a command is invalid",
	ErrIOError:               "an IO error occurred transmitting information to the TPM",
	ErrEncryptError:          "the encryption process had a problem",
	ErrDecryptError:          "the decryption process had a problem",
	ErrInvalidAuthHandle:     "an invalid handle was used",
	ErrNoEndorsement:         "the TPM does not have an EK installed",
	ErrInvalidKeyUsage:       "the usage of a key is not allowed",
	ErrWrongEntityType:       "the submitted entity type is not allowed",
	ErrInvalidPostInit:       "the command was received in the wrong sequence relative to Init and a subsequent Startup",
	ErrInappropriateSig:      "signed data cannot include additional DER information",
	ErrBadKeyProperty:        "the key properties in KEY_PARAMs are not supported by this TPM",
	ErrBadMigration:          "the migration properties of this key are incorrect",
	ErrBadScheme:             "the signature or encryption scheme for this key is incorrect or not permitted in this situation",
	ErrBadDatasize:           "the size of the data (or blob) parameter is bad or inconsistent with the referenced key",
	ErrBadMode:               "a mode parameter is bad, such as capArea or subCapArea for GetCapability, physicalPresence parameter for PhysicalPresence, or migrationType for CreateMigrationBlob",
	ErrBadPresence:           "either the physicalPresence or physicalPresenceLock bits have the wrong value",
	ErrBadVersion:            "the TPM cannot perform this version of the capability",
	ErrNoWrapTransport:       "the TPM does not allow for wrapped transport sessions",
	ErrAuditFailUnsuccessful: "TPM audit construction failed and the underlying command was returning a failure code also",
	ErrAuditFailSuccessful:   "TPM audit construction failed and the underlying command was returning success",
	ErrNotResetable:          "attempt to reset a PCR register that does not have the resettable attribute",
	ErrNotLocal:              "attempt to reset a PCR register that requires locality and locality modifier not part of command transport",
	ErrBadType:               "make identity blob not properly typed",
	ErrInvalidResource:       "when saving context identified resource type does not match actual resource",
	ErrNotFIPS:               "the TPM is attempting to execute a command only available when in FIPS mode",
	ErrInvalidFamily:         "the command is attempting to use an invalid family ID",
	ErrNoNVPermission:        "the permission to manipulate the NV storage is not available",
	ErrRequiresSign:          "the operation requires a signed command",
	ErrKeyNotSupported:       "wrong operation to load an NV key",
	ErrAuthConflict:          "NV_LoadKey blob requires both owner and blob authorization",
	ErrAreaLocked:            "the NV area is locked and not writeable",
	ErrBadLocality:           "the locality is incorrect for the attempted operation",
	ErrReadOnly:              "the NV area is read only and can't be written to",
	ErrPerNoWrite:            "there is no protection on the write to the NV area",
	ErrFamilyCount:           "the family count value does not match",
	ErrWriteLocked:           "the NV area has already been written to",
	ErrBadAttributes:         "the NV area attributes conflict",
	ErrInvalidStructure:      "the structure tag and version are invalid or inconsistent",
	ErrKeyOwnerControl:       "the key is under control of the TPM Owner and can only be evicted by the TPM Owner",
	ErrBadCounter:            "the counter handle is incorrect",
	ErrNotFullWrite:          "the write is not a complete write of the area",
	ErrContextGap:            "the gap between saved context counts is too large",
	ErrMaxNVWrites:           "the maximum number of NV writes without an owner has been exceeded",
	ErrNoOperator:            "no operator AuthData value is set",
	ErrResourceMissing:       "the resource pointed to by context is not loaded",
	ErrDelegateLock:          "the delegate administration is locked",
	ErrDelegateFamliy:        "attempt to manage a family other than the delegated family",
	ErrDelegateAdmin:         "delegation table management not enabled",
	ErrTransportNotExclusive: "there was a command executed outside of an exclusive transport session",
	ErrOwnerControl:          "attempt to context save a owner evict controlled key",
	ErrDAAResources:          "the DAA command has no resources available to execute the command",
	ErrDAAInputData0:         "the consistency check on DAA parameter inputData0 has failed",
	ErrDAAInputData1:         "the consistency check on DAA parameter inputData1 has failed",
	ErrDAAIssuerSettings:     "the consistency check on DAA_issuerSettings has failed",
	ErrDAASettings:           "the consistency check on DAA_tpmSpecific has failed",
	ErrDAAState:              "the atomic process indicated by the submitted DAA command is not the expected process",
	ErrDAAIssuerVailidity:    "the issuer's validity check has detected an inconsistency",
	ErrDAAWrongW:             "the consistency check on w has failed",
	ErrBadHandle:             "the handle is incorrect",
	ErrBadDelegate:           "delegation is not correct",
	ErrBadContext:            "the context blob is invalid",
	ErrTooManyContexts:       "too many contexts held by the TPM",
	ErrMATicketSignature:     "migration authority signature validation failure",
	ErrMADestination:         "migration destination not authenticated",
	ErrMASource:              "migration source incorrect",
	ErrMAAuthority:           "incorrect migration authority",
	ErrDefendLockRunning:     "the TPM is defending against dictionary attacks and is in some time-out period",
}

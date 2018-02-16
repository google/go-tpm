// Copyright (c) 2018, Google Inc. All rights reserved.
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

package tpm2

import "github.com/google/go-tpm/tpmutil"

func init() {
	tpmutil.UseTPM20LengthPrefixSize()
}

// Algorithm represents a TPM_ALG_ID value.
type Algorithm uint16

// Supported Algorithms.
const (
	AlgRSA       Algorithm = 0x0001
	AlgSHA1      Algorithm = 0x0004
	AlgAES       Algorithm = 0x0006
	AlgKeyedHash Algorithm = 0x0008
	AlgSHA256    Algorithm = 0x000B
	AlgSHA384    Algorithm = 0x000C
	AlgSHA512    Algorithm = 0x000D
	AlgNull      Algorithm = 0x0010
	AlgRSASSA    Algorithm = 0x0014
	AlgRSAES     Algorithm = 0x0015
	AlgRSAPSS    Algorithm = 0x0016
	AlgOAEP      Algorithm = 0x0017
	AlgECDSA     Algorithm = 0x0018
	AlgECDH      Algorithm = 0x0019
	AlgECDAA     Algorithm = 0x001A
	AlgECC       Algorithm = 0x0023
	AlgCTR       Algorithm = 0x0040
	AlgOFB       Algorithm = 0x0041
	AlgCBC       Algorithm = 0x0042
	AlgCFB       Algorithm = 0x0043
	AlgECB       Algorithm = 0x0044
)

// SessionType defines the type of session created in StartAuthSession.
type SessionType uint8

// Supported session types.
const (
	SessionHMAC   SessionType = 0x00
	SessionPolicy SessionType = 0x01
	SessionTrial  SessionType = 0x03
)

// KeyProp is a bitmask used in Attributes field of key templates. Individual
// flags should be OR-ed to form a full mask.
type KeyProp uint32

// Key properties.
const (
	FlagFixedTPM            KeyProp = 0x00000002
	FlagFixedParent         KeyProp = 0x00000010
	FlagSensitiveDataOrigin KeyProp = 0x00000020
	FlagUserWithAuth        KeyProp = 0x00000040
	FlagAdminWithPolicy     KeyProp = 0x00000080
	FlagRestricted          KeyProp = 0x00010000
	FlagDecrypt             KeyProp = 0x00020000
	FlagSign                KeyProp = 0x00040000

	FlagSealDefault   = FlagFixedTPM | FlagFixedParent
	FlagSignerDefault = FlagSign | FlagRestricted | FlagFixedTPM |
		FlagFixedParent | FlagSensitiveDataOrigin | FlagUserWithAuth
	FlagStorageDefault = FlagDecrypt | FlagRestricted | FlagFixedTPM |
		FlagFixedParent | FlagSensitiveDataOrigin | FlagUserWithAuth
)

// Reserved Handles.
const (
	HandleOwner tpmutil.Handle = 0x40000001 + iota
	HandleRevoke
	HandleTransport
	HandleOperator
	HandleAdmin
	HandleEK
	HandleNull
	HandleUnassigned
	HandlePasswordSession
	HandleLockout
	HandleEndorsement
	HandlePlatform
)

// Capability identifies some TPM property or state type.
type Capability uint32

// TPM Capabilies.
const (
	CapabilityAlgs Capability = iota
	CapabilityHandles
	CapabilityCommands
	CapabilityPPCommands
	CapabilityAuditCommands
	CapabilityPCRs
	CapabilityTPMProperties
	CapabilityPCRProperties
	CapabilityECCCurves
	CapabilityAuthPolicies
)

const (
	tagNull       tpmutil.Tag = 0x8000
	tagNoSessions tpmutil.Tag = 0x8001
	tagSessions   tpmutil.Tag = 0x8002
	tagHashcheck  tpmutil.Tag = 0x8024
)

// StartupType instructs the TPM on how to handle its state during Shutdown or
// Startup.
type StartupType uint16

// Startup types
const (
	StartupClear StartupType = iota
	StartupState
)

// Supported TPM operations.
const (
	cmdEvictControl       tpmutil.Command = 0x00000120
	cmdUndefineSpace      tpmutil.Command = 0x00000122
	cmdClockSet           tpmutil.Command = 0x00000128
	cmdDefineSpace        tpmutil.Command = 0x0000012A
	cmdPCRAllocate        tpmutil.Command = 0x0000012B
	cmdCreatePrimary      tpmutil.Command = 0x00000131
	cmdIncrementNVCounter tpmutil.Command = 0x00000134
	cmdWriteNV            tpmutil.Command = 0x00000137
	cmdPCREvent           tpmutil.Command = 0x0000013C
	cmdStartup            tpmutil.Command = 0x00000144
	cmdShutdown           tpmutil.Command = 0x00000145
	cmdStirRandom         tpmutil.Command = 0x00000146
	cmdActivateCredential tpmutil.Command = 0x00000147
	cmdCertify            tpmutil.Command = 0x00000148
	cmdReadNV             tpmutil.Command = 0x0000014E
	cmdCreate             tpmutil.Command = 0x00000153
	cmdLoad               tpmutil.Command = 0x00000157
	cmdQuote              tpmutil.Command = 0x00000158
	cmdUnseal             tpmutil.Command = 0x0000015E
	cmdContextLoad        tpmutil.Command = 0x00000161
	cmdContextSave        tpmutil.Command = 0x00000162
	cmdFlushContext       tpmutil.Command = 0x00000165
	cmdLoadExternal       tpmutil.Command = 0x00000167
	cmdMakeCredential     tpmutil.Command = 0x00000168
	cmdReadPublicNV       tpmutil.Command = 0x00000169
	cmdReadPublic         tpmutil.Command = 0x00000173
	cmdStartAuthSession   tpmutil.Command = 0x00000176
	cmdGetCapability      tpmutil.Command = 0x0000017A
	cmdGetRandom          tpmutil.Command = 0x0000017B
	cmdHash               tpmutil.Command = 0x0000017D
	cmdPCRRead            tpmutil.Command = 0x0000017E
	cmdPolicyPCR          tpmutil.Command = 0x0000017F
	cmdReadClock          tpmutil.Command = 0x00000181
	cmdPCRExtend          tpmutil.Command = 0x00000182
	cmdPolicyGetDigest    tpmutil.Command = 0x00000189
	cmdPolicyPassword     tpmutil.Command = 0x0000018C
)

// Regular TPM 2.0 devices use 24-bit mask (3 bytes) for PCR selection.
const sizeOfPCRSelect = 3

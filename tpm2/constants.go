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

package tpm2

const maxTPMResponse = 4096

// Algorithm represents a TPM_ALG_ID value.
type Algorithm uint16

// Supported Algorithms.
const (
	TPM_ALG_RSA       Algorithm = 0x0001
	TPM_ALG_SHA1      Algorithm = 0x0004
	TPM_ALG_AES       Algorithm = 0x0006
	TPM_ALG_SHA256    Algorithm = 0x000B
	TPM_ALG_SHA384    Algorithm = 0x000C
	TPM_ALG_SHA512    Algorithm = 0x000D
	TPM_ALG_NULL      Algorithm = 0x0010
	TPM_ALG_RSASSA    Algorithm = 0x0014
	TPM_ALG_RSAES     Algorithm = 0x0015
	TPM_ALG_RSAPSS    Algorithm = 0x0016
	TPM_ALG_OAEP      Algorithm = 0x0017
	TPM_ALG_ECDSA     Algorithm = 0x0018
	TPM_ALG_ECDH      Algorithm = 0x0019
	TPM_ALG_ECDAA     Algorithm = 0x001A
	TPM_ALG_ECC       Algorithm = 0x0023
	TPM_ALG_CTR       Algorithm = 0x0040
	TPM_ALG_OFB       Algorithm = 0x0041
	TPM_ALG_CBC       Algorithm = 0x0042
	TPM_ALG_CFB       Algorithm = 0x0043
	TPM_ALG_ECB       Algorithm = 0x0044
	TPM_ALG_LAST      Algorithm = 0x0044
	TPM_ALG_KEYEDHASH Algorithm = 0x0008
)

// SessionType defines the type of session created in StartAuthSession.
type SessionType uint8

// Supported session types.
const (
	TPM_SE_HMAC   SessionType = 0x00
	TPM_SE_POLICY SessionType = 0x01
	TPM_SE_TRIAL  SessionType = 0x03
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

// A Handle is an identifier for TPM objects.
type Handle uint32

// Reserved Handles.
const (
	TPM_RH_OWNER       Handle = 0x40000001
	TPM_RH_REVOKE      Handle = 0x40000002
	TPM_RH_TRANSPORT   Handle = 0x40000003
	TPM_RH_OPERATOR    Handle = 0x40000004
	TPM_RH_ADMIN       Handle = 0x40000005
	TPM_RH_EK          Handle = 0x40000006
	TPM_RH_NULL        Handle = 0x40000007
	TPM_RH_UNASSIGNED  Handle = 0x40000008
	TPM_RH_LOCKOUT     Handle = 0x4000000A
	TPM_RH_ENDORSEMENT Handle = 0x4000000B
	TPM_RH_PLATFORM    Handle = 0x4000000C
	TPM_RS_PW          Handle = 0x40000009
)

// Capability identifies some TPM property or state type.
type Capability uint32

// TPM Capabilies.
const (
	TPM_CAP_ALGS           Capability = 0x00000000
	TPM_CAP_HANDLES        Capability = 0x00000001
	TPM_CAP_COMMANDS       Capability = 0x00000002
	TPM_CAP_PP_COMMANDS    Capability = 0x00000003
	TPM_CAP_AUDIT_COMMANDS Capability = 0x00000004
	TPM_CAP_PCRS           Capability = 0x00000005
	TPM_CAP_TPM_PROPERTIES Capability = 0x00000006
	TPM_CAP_PCR_PROPERTIES Capability = 0x00000007
	TPM_CAP_ECC_CURVES     Capability = 0x00000008
	TPM_CAP_AUTH_POLICIES  Capability = 0x00000009
)

type structureTag uint16

const (
	tagNull       structureTag = 0x8000
	tagNoSessions structureTag = 0x8001
	tagSessions   structureTag = 0x8002
	tagHashcheck  structureTag = 0x8024
)

// StartupType instructs the TPM on how to handle its state during Shutdown or
// Startup.
type StartupType uint16

// Startup types
const (
	TPM_SU_CLEAR StartupType = 0x0000
	TPM_SU_STATE StartupType = 0x0001
)

type command uint32

// Supported TPM operations.
const (
	cmdEvictControl       command = 0x00000120
	cmdClockSet           command = 0x00000128
	cmdPCRAllocate        command = 0x0000012B
	cmdCreatePrimary      command = 0x00000131
	cmdCreate             command = 0x00000153
	cmdStirRandom         command = 0x00000146
	cmdActivateCredential command = 0x00000147
	cmdCertify            command = 0x00000148
	cmdLoad               command = 0x00000157
	cmdQuote              command = 0x00000158
	cmdUnseal             command = 0x0000015E
	cmdContextLoad        command = 0x00000161
	cmdContextSave        command = 0x00000162
	cmdFlushContext       command = 0x00000165
	cmdLoadExternal       command = 0x00000167
	cmdMakeCredential     command = 0x00000168
	cmdReadPublic         command = 0x00000173
	cmdStartAuthSession   command = 0x00000176
	cmdGetCapability      command = 0x0000017A
	cmdGetRandom          command = 0x0000017B
	cmdPCRRead            command = 0x0000017E
	cmdPolicyPCR          command = 0x0000017F
	cmdReadClock          command = 0x00000181
	cmdPCRExtend          command = 0x00000182
	cmdPolicyGetDigest    command = 0x00000189
	cmdPolicyPassword     command = 0x0000018C
	cmdPCREvent           command = 0x0000013C
	cmdDefineSpace        command = 0x0000012A
	cmdUndefineSpace      command = 0x00000122
	cmdReadPublicNv       command = 0x00000169
	cmdReadNv             command = 0x0000014E
	cmdWriteNv            command = 0x00000137
	cmdIncrementNvCounter command = 0x00000134
	cmdHash               command = 0x0000017D
	cmdStartup            command = 0x00000144
	cmdShutdown           command = 0x00000145
)

type responseCode uint32

const (
	rcSuccess responseCode = 0x000
)

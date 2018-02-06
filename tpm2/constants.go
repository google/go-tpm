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

// TPM generated
const (
	TPM_GENERATED_VALUE uint32 = 0xff544347
)

// Supported Algorithms.
const (
	TPM_ALG_RSA       uint16 = 0x0001
	TPM_ALG_SHA1      uint16 = 0x0004
	TPM_ALG_AES       uint16 = 0x0006
	TPM_ALG_SHA256    uint16 = 0x000B
	TPM_ALG_SHA384    uint16 = 0x000C
	TPM_ALG_SHA512    uint16 = 0x000D
	TPM_ALG_NULL      uint16 = 0x0010
	TPM_ALG_RSASSA    uint16 = 0x0014
	TPM_ALG_RSAES     uint16 = 0x0015
	TPM_ALG_RSAPSS    uint16 = 0x0016
	TPM_ALG_OAEP      uint16 = 0x0017
	TPM_ALG_ECDSA     uint16 = 0x0018
	TPM_ALG_ECDH      uint16 = 0x0019
	TPM_ALG_ECDAA     uint16 = 0x001A
	TPM_ALG_ECC       uint16 = 0x0023
	TPM_ALG_CTR       uint16 = 0x0040
	TPM_ALG_OFB       uint16 = 0x0041
	TPM_ALG_CBC       uint16 = 0x0042
	TPM_ALG_CFB       uint16 = 0x0043
	TPM_ALG_ECB       uint16 = 0x0044
	TPM_ALG_LAST      uint16 = 0x0044
	TPM_ALG_KEYEDHASH uint16 = 0x0008
)

// Policy
const (
	TPM_SE_POLICY uint8 = 0x01
)

// Key properties
const (
	FlagFixedTPM            uint32 = 0x00000002
	FlagFixedParent         uint32 = 0x00000010
	FlagSensitiveDataOrigin uint32 = 0x00000020
	FlagUserWithAuth        uint32 = 0x00000040
	FlagAdminWithPolicy     uint32 = 0x00000080
	FlagRestricted          uint32 = 0x00010000
	FlagDecrypt             uint32 = 0x00020000
	FlagSign                uint32 = 0x00040000

	FlagSealDefault   uint32 = FlagFixedTPM | FlagFixedParent
	FlagSignerDefault uint32 = FlagSign | FlagRestricted | FlagFixedTPM |
		FlagFixedParent | FlagSensitiveDataOrigin | FlagUserWithAuth
	FlagStorageDefault uint32 = FlagDecrypt | FlagRestricted | FlagFixedTPM |
		FlagFixedParent | FlagSensitiveDataOrigin | FlagUserWithAuth
)

// Reserved Handles and Properties
const (
	TPM_RH_OWNER       uint32 = 0x40000001
	TPM_RH_REVOKE      uint32 = 0x40000002
	TPM_RH_TRANSPORT   uint32 = 0x40000003
	TPM_RH_OPERATOR    uint32 = 0x40000004
	TPM_RH_ADMIN       uint32 = 0x40000005
	TPM_RH_EK          uint32 = 0x40000006
	TPM_RH_NULL        uint32 = 0x40000007
	TPM_RH_UNASSIGNED  uint32 = 0x40000008
	TPM_RH_LOCKOUT     uint32 = 0x4000000A
	TPM_RH_ENDORSEMENT uint32 = 0x4000000B
	TPM_RH_PLATFORM    uint32 = 0x4000000C

	TPM_RS_PW uint32 = 0x40000009

	TPM_CAP_TPM_PROPERTIES uint32 = 0x00000006
	TPM_CAP_HANDLES        uint32 = 0x00000001

	NV_PLATFORMCREATE uint32 = 0x40000000
	NV_AUTHWRITE      uint32 = 0x00000004
	NV_AUTHREAD       uint32 = 0x00040000
	NV_COUNTER        uint32 = 0x00000010
	NV_EXTEND         uint32 = 0x00000040
	NV_POLICY_DELETE  uint32 = 0x00000400
	NV_WRITTEN        uint32 = 0x20000000

	TPM_HT_NV_INDEX uint32 = 1
)

// Command tags
const (
	tagNoSessions uint16 = 0x8001
	tagSessions   uint16 = 0x8002
)

// Startup types
const (
	TPM_SU_CLEAR uint16 = 0x0000
	TPM_SU_STATE uint16 = 0x0001
)

// Structure Tags
const (
	TPM_ST_HASHCHECK uint16 = 0x8024
)

// Supported TPM operations.
const (
	cmdEvictControl       uint32 = 0x00000120
	cmdClockSet           uint32 = 0x00000128
	cmdPCRAllocate        uint32 = 0x0000012B
	cmdCreatePrimary      uint32 = 0x00000131
	cmdCreate             uint32 = 0x00000153
	cmdStirRandom         uint32 = 0x00000146
	cmdActivateCredential uint32 = 0x00000147
	cmdCertify            uint32 = 0x00000148
	cmdLoad               uint32 = 0x00000157
	cmdQuote              uint32 = 0x00000158
	cmdUnseal             uint32 = 0x0000015E
	cmdContextLoad        uint32 = 0x00000161
	cmdContextSave        uint32 = 0x00000162
	cmdFlushContext       uint32 = 0x00000165
	cmdLoadExternal       uint32 = 0x00000167
	cmdMakeCredential     uint32 = 0x00000168
	cmdReadPublic         uint32 = 0x00000173
	cmdStartAuthSession   uint32 = 0x00000176
	cmdGetCapability      uint32 = 0x0000017A
	cmdGetRandom          uint32 = 0x0000017B
	cmdPCR_Read           uint32 = 0x0000017E
	cmdPolicyPCR          uint32 = 0x0000017F
	cmdReadClock          uint32 = 0x00000181
	cmdPCR_Extend         uint32 = 0x00000182
	cmdPolicyGetDigest    uint32 = 0x00000189
	cmdPolicyPassword     uint32 = 0x0000018C
	cmdPCREvent           uint32 = 0x0000013C
	cmdDefineSpace        uint32 = 0x0000012A
	cmdUndefineSpace      uint32 = 0x00000122
	cmdReadPublicNv       uint32 = 0x00000169
	cmdReadNv             uint32 = 0x0000014E
	cmdWriteNv            uint32 = 0x00000137
	cmdIncrementNvCounter uint32 = 0x00000134
	cmdHash               uint32 = 0x0000017D
	cmdStartup            uint32 = 0x00000144
	cmdShutdown           uint32 = 0x00000145
)

type responseCode uint32

const (
	rcSuccess responseCode = 0x000
)

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

// TPM generated
const(
	OrdTPM_GENERATED_VALUE uint32 = 0xff544347
)

// Supported Algorithms.
const(
	AlgTPM_ALG_RSA      uint16 = 0x0001
	AlgTPM_ALG_SHA1     uint16 = 0x0004
	AlgTPM_ALG_AES      uint16 = 0x0006
	AlgTPM_ALG_SHA256   uint16 = 0x000B
	AlgTPM_ALG_SHA384   uint16 = 0x000C
	AlgTPM_ALG_SHA512   uint16 = 0x000D
	AlgTPM_ALG_NULL     uint16 = 0x0010
	AlgTPM_ALG_RSASSA   uint16 = 0x0014
	AlgTPM_ALG_RSAES    uint16 = 0x0015
	AlgTPM_ALG_RSAPSS   uint16 = 0x0016
	AlgTPM_ALG_OAEP     uint16 = 0x0017
	AlgTPM_ALG_ECDSA    uint16 = 0x0018
	AlgTPM_ALG_ECDH     uint16 = 0x0019
	AlgTPM_ALG_ECDAA    uint16 = 0x001A
	AlgTPM_ALG_ECC      uint16 = 0x0023
	AlgTPM_ALG_CTR      uint16 = 0x0040
	AlgTPM_ALG_OFB      uint16 = 0x0041
	AlgTPM_ALG_CBC      uint16 = 0x0042
	AlgTPM_ALG_CFB      uint16 = 0x0043
	AlgTPM_ALG_ECB      uint16 = 0x0044
	AlgTPM_ALG_LAST     uint16 = 0x0044
	AlgTPM_ALG_KEYEDHASH uint16 = 0x0008
)

// Policy
const(
	OrdTPM_SE_POLICY  uint8 = 0x01
)

// Properties
const(
	FlagFixedTPM	           uint32 = 0x00000002
	FlagFixedParent            uint32 = 0x00000010
	FlagSensitiveDataOrigin    uint32 = 0x00000020
	FlagUserWithAuth           uint32 = 0x00000040
	FlagAdminWithPolicy        uint32 = 0x00000080

	FlagRestricted             uint32 = 0x00010000
	FlagDecrypt                uint32 = 0x00020000
	FlagSign                   uint32 = 0x00040000

	FlagSealDefault		   uint32 = FlagFixedTPM | FlagFixedParent
	FlagSignerDefault	   uint32 = FlagSign | FlagRestricted | FlagFixedTPM |
					FlagFixedParent | FlagSensitiveDataOrigin | FlagUserWithAuth
	FlagStorageDefault	   uint32 = FlagDecrypt | FlagRestricted | FlagFixedTPM |
					FlagFixedParent | FlagSensitiveDataOrigin | FlagUserWithAuth
)

// Reserved Handles and Properties
const(
	OrdTPM_RH_OWNER            uint32 = 0x40000001
	OrdTPM_RH_REVOKE           uint32 = 0x40000002
	OrdTPM_RH_TRANSPORT        uint32 = 0x40000003
	OrdTPM_RH_OPERATOR         uint32 = 0x40000004
	OrdTPM_RH_ADMIN            uint32 = 0x40000005
	OrdTPM_RH_EK               uint32 = 0x40000006
	OrdTPM_RH_NULL             uint32 = 0x40000007
	OrdTPM_RH_UNASSIGNED       uint32 = 0x40000008
	OrdTPM_RS_PW               uint32 = 0x40000009
	OrdTPM_RH_LOCKOUT          uint32 = 0x4000000A
	OrdTPM_RH_ENDORSEMENT      uint32 = 0x4000000B
	OrdTPM_RH_PLATFORM         uint32 = 0x4000000C
	OrdTPM_CAP_TPM_PROPERTIES  uint32 = 0x00000006
	OrdTPM_CAP_HANDLES         uint32 = 0x00000001
	OrdNV_PLATFORMCREATE	   uint32 = 0x40000000
	OrdNV_AUTHWRITE		   uint32 = 0x00000004
	OrdNV_AUTHREAD		   uint32 = 0x00040000
	OrdNV_COUNTER		   uint32 = 0x00000010
	OrdHR_SHIFT		   uint32 = 24
	OrdTPM_HT_NV_INDEX	   uint32 = 1
	OrdNV_EXTEND		   uint32 = 0x00000040
	OrdNV_POLICY_DELETE	   uint32 = 0x00000400
	OrdNV_WRITTEN		   uint32 = 0x20000000
)

// Tags
const(
	tagNO_SESSIONS uint16 = 0x8001
	tagSESSIONS    uint16 = 0x8002
)

// magic number
const(
	ordTpmMagic		   uint32 = 0xff544347
)

// Supported TPM operations.
const (
	cmdEvictControl            uint32 = 0x00000120
	cmdClockSet                uint32 = 0x00000128
	cmdPCR_Allocate            uint32 = 0x0000012B
	cmdCreatePrimary           uint32 = 0x00000131
	cmdCreate                  uint32 = 0x00000153
	cmdStirRandom              uint32 = 0x00000146
	cmdActivateCredential      uint32 = 0x00000147
	cmdCertify                 uint32 = 0x00000148
	cmdLoad                    uint32 = 0x00000157
	cmdQuote                   uint32 = 0x00000158
	cmdUnseal                  uint32 = 0x0000015E
	cmdContextLoad             uint32 = 0x00000161
	cmdContextSave             uint32 = 0x00000162
	cmdFlushContext            uint32 = 0x00000165
	cmdLoadExternal            uint32 = 0x00000167
	cmdMakeCredential          uint32 = 0x00000168
	cmdReadPublic              uint32 = 0x00000173
	cmdStartAuthSession        uint32 = 0x00000176
	cmdGetCapability           uint32 = 0x0000017A
	cmdGetRandom               uint32 = 0x0000017B
	cmdPCR_Read                uint32 = 0x0000017E
	cmdPolicyPCR               uint32 = 0x0000017F
	cmdReadClock               uint32 = 0x00000181
	cmdPCR_Extend              uint32 = 0x00000182
	cmdPolicyGetDigest         uint32 = 0x00000189
	cmdPolicyPassword          uint32 = 0x0000018C
	cmdPcrEvent                uint32 = 0x0000013C
	cmdDefineSpace		   uint32 = 0x0000012A
	cmdUndefineSpace	   uint32 = 0x00000122
	cmdReadNv		   uint32 = 0x0000014E
	cmdWriteNv		   uint32 = 0x00000137
	cmdIncrementNvCounter	   uint32 = 0x00000134
)

const maxTPMResponse = 4096


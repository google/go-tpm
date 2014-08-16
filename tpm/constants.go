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

// Supported TPM commands.
const (
	tagPCRInfoLong     uint16 = 0x06
	tagRQUCommand      uint16 = 0x00C1
	tagRQUAuth1Command uint16 = 0x00C2
	tagRQUAuth2Command uint16 = 0x00C3
	tagRSPCommand      uint16 = 0x00C4
	tagRSPAuth1Command uint16 = 0x00C5
	tagRSPAuth2Command uint16 = 0x00C6
)

// Supported TPM operations.
const (
	ordOIAP          uint32 = 0x0000000A
	ordOSAP          uint32 = 0x0000000B
	ordPCRRead       uint32 = 0x00000015
	ordQuote         uint32 = 0x00000016
	ordSeal          uint32 = 0x00000017
	ordUnseal        uint32 = 0x00000018
	ordGetPubKey     uint32 = 0x00000021
	ordQuote2        uint32 = 0x0000003E
	ordLoadKey2      uint32 = 0x00000041
	ordGetRandom     uint32 = 0x00000046
	ordFlushSpecific uint32 = 0x000000BA
)

// Entity types
const (
	etKeyHandle uint16 = 0x0001
	etSRK       uint16 = 0x0004
	etKey       uint16 = 0x0005
)

// Resource types
const (
	rtKey   uint32 = 0x00000001
	rtAuth  uint32 = 0x00000002
	rtHash  uint32 = 0x00000003
	rtTrans uint32 = 0x00000004
)

// Entity values.
const (
	khSRK Handle = 0x40000000
)

// Algorithm ID values.
const (
	_ uint32 = iota
	algRSA
	_ // was DES
	_ // was 3DES in EDE mode
	algSHA
	algHMAC
	algAES128
	algMGF1
	algAES192
	algAES256
	algXOR
)

// Encryption schemes. The values esNone and the two that contain the string
// "RSA" are only valid under algRSA. The other two are symmetric encryption
// schemes.
const (
	_ uint16 = iota
	esNone
	esRSAEsPKCSv15
	esRSAEsOAEPSHA1MGF1
	esSymCTR
	esSymOFB
)

// Signature schemes. These are only valid under algRSA.
const (
	_ uint16 = iota
	ssNone
	ssRSASaPKCS1v15_SHA1
	ssRSASaPKCS1v15_DER
	ssRSASaPKCS1v15_INFO
)

// maxTPMResponse is the largest possible response from the TPM. We need to know
// this because we don't always know the length of the TPM response, and
// /dev/tpm insists on giving it all back in a single value rather than
// returning a header and a body in separate responses.
const maxTPMResponse = 4096

// fixedQuote is the fixed constant string used in quoteInfo.
var fixedQuote = [4]byte{byte('Q'), byte('U'), byte('O'), byte('T')}

// quoteVersion is the fixed version string for quoteInfo.
const quoteVersion uint32 = 0x01010000

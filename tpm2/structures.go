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

// A Handle is a 32-bit unsigned integer.
type Handle uint32

// A commandHeader is the header for a TPM command.
type commandHeader struct {
	Tag  cmdTag
	Size uint32
	Cmd  command
}

// A responseHeader is a header for TPM responses.
type responseHeader struct {
	Tag  cmdTag
	Size uint32
	Res  command
}

type RSAParams struct {
	EncAlg     Algorithm
	HashAlg    Algorithm
	Attributes keyProp
	AuthPolicy []byte
	SymAlg     Algorithm
	SymSize    uint16
	Mode       Algorithm
	Scheme     Algorithm
	SchemeHash Algorithm
	ModSize    uint16
	Exp        uint32
	Modulus    []byte
}

type KeyedHashParams struct {
	TypeAlg    Algorithm
	HashAlg    Algorithm
	Attributes uint32
	AuthPolicy []byte
	SymAlg     Algorithm
	SymSize    uint16
	Mode       Algorithm
	Scheme     Algorithm
	Unique     []byte
}

type NVPublic struct {
	NVIndex    Handle
	NameAlg    Algorithm
	Attributes uint32
	AuthPolicy []byte
	DataSize   uint16
}

type TPMTPublic struct {
	Type       uint16
	NameAlg    Algorithm
	Attributes uint32
	Digest     []byte
	Parameters TPMS_RSAParams
	Unique     []byte
}

type TPMS_RSAParams struct {
	Symmetric TPMT_RSAScheme
	Scheme    Algorithm
	KeyBits   uint16
	Exponent  uint32
}

type TPMT_RSAScheme struct {
	Alg     Algorithm
	KeyBits uint16
	Mode    Algorithm
}

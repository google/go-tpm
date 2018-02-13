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

// RSAParams is a template for an RSA key.
type RSAParams struct {
	EncAlg     Algorithm
	HashAlg    Algorithm
	Attributes KeyProp
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

// KeyedHashParams contains parameters of a keyed hash object.
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

// NVPublic contains the public area of an NV index.
type NVPublic struct {
	NVIndex    tpmutil.Handle
	NameAlg    Algorithm
	Attributes uint32
	AuthPolicy []byte
	DataSize   uint16
}

type tpmtPublic struct {
	Type       uint16
	NameAlg    Algorithm
	Attributes uint32
	Digest     []byte
	Parameters tpmsRSAParams
	Unique     []byte
}

type tpmsRSAParams struct {
	Symmetric tpmtRSAScheme
	Scheme    Algorithm
	KeyBits   uint16
	Exponent  uint32
}

type tpmtRSAScheme struct {
	Alg     Algorithm
	KeyBits uint16
	Mode    Algorithm
}

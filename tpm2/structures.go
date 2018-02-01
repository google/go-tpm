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

import (
	"fmt"
)

// A Handle is a 32-bit unsigned integer.
type Handle uint32

// A commandHeader is the header for a TPM command.
type commandHeader struct {
	Tag  uint16
	Size uint32
	Cmd  uint32
}

// String returns a string version of a commandHeader
func (ch commandHeader) String() string {
	return fmt.Sprintf("commandHeader{Tag: %x, Size: %x, Cmd: %x}", ch.Tag, ch.Size, ch.Cmd)
}

// A responseHeader is a header for TPM responses.
type responseHeader struct {
	Tag  uint16
	Size uint32
	Res  uint32
}

type RSAParams struct {
	EncAlg     uint16
	HashAlg    uint16
	Attributes uint32
	AuthPolicy []byte
	SymAlg     uint16
	SymSize    uint16
	Mode       uint16
	Scheme     uint16
	SchemeHash uint16
	ModSize    uint16
	Exp        uint32
	Modulus    []byte
}

type KeyedHashParams struct {
	TypeAlg    uint16
	HashAlg    uint16
	Attributes uint32
	AuthPolicy []byte
	SymAlg     uint16
	SymSize    uint16
	Mode       uint16
	Scheme     uint16
	Unique     []byte
}

type AttestParams struct {
	MagicNumber     uint32
	AttestType      uint16
	Name            []byte
	Data            []byte
	Clock           uint64
	ResetCount      uint32
	RestartCount    uint32
	Safe            byte
	FirmwareVersion uint64
	PCRSelect       []byte
	PCRDigest       []byte
}

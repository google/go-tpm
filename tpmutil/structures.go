// Copyright (c) 2018, Google LLC All rights reserved.
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

package tpmutil

import (
	"encoding/binary"
	"io"
)

// RawBytes is for Pack and RunCommand arguments that are already encoded.
// Compared to []byte, RawBytes will not be prepended with slice length during
// encoding.
type RawBytes []byte

// U16Bytes is a byte slice with a 16-bit header
type U16Bytes []byte

// TPMMarshal packs U16Bytes
func (b *U16Bytes) TPMMarshal(out io.Writer) error {
	size := uint16(len([]byte(*b)))
	if err := binary.Write(out, binary.BigEndian, size); err != nil {
		return err
	}
	if err := binary.Write(out, binary.BigEndian, []byte(*b)); err != nil {
		return err
	}
	return nil
}

// TPMUnmarshal unpacks a U16Bytes
func (b *U16Bytes) TPMUnmarshal(in io.Reader) error {
	var tmpSize uint16
	if err := binary.Read(in, binary.BigEndian, &tmpSize); err != nil {
		return err
	}
	size := int(tmpSize)
	if len([]byte(*b)) >= size {
		*b = (*b)[:size]
	} else {
		*b = append(*b, make([]byte, size-len(*b))...)
	}

	if err := binary.Read(in, binary.BigEndian, b); err != nil {
		return err
	}
	return nil
}

// U32Bytes is a byte slice with a 32-bit header
type U32Bytes []byte

// TPMMarshal packs U32Bytes
func (b *U32Bytes) TPMMarshal(out io.Writer) error {
	size := uint32(len([]byte(*b)))
	if err := binary.Write(out, binary.BigEndian, size); err != nil {
		return err
	}
	if err := binary.Write(out, binary.BigEndian, []byte(*b)); err != nil {
		return err
	}
	return nil
}

// TPMUnmarshal unpacks a U32Bytes
func (b *U32Bytes) TPMUnmarshal(in io.Reader) error {
	var tmpSize uint32
	if err := binary.Read(in, binary.BigEndian, &tmpSize); err != nil {
		return err
	}
	size := int(tmpSize)
	if len([]byte(*b)) >= size {
		*b = (*b)[:size]
	} else {
		*b = append(*b, make([]byte, size-len(*b))...)
	}

	if err := binary.Read(in, binary.BigEndian, b); err != nil {
		return err
	}
	return nil
}

// Tag is a command tag.
type Tag uint16

// Command is an identifier of a TPM command.
type Command uint32

// A commandHeader is the header for a TPM command.
type commandHeader struct {
	Tag  Tag
	Size uint32
	Cmd  Command
}

// ResponseCode is a response code returned by TPM.
type ResponseCode uint32

// RCSuccess is response code for successful command. Identical for TPM 1.2 and
// 2.0.
const RCSuccess ResponseCode = 0x000

// A responseHeader is a header for TPM responses.
type responseHeader struct {
	Tag  Tag
	Size uint32
	Res  ResponseCode
}

// A Handle is a reference to a TPM object.
type Handle uint32

// TODO(jsonp): Refactor use of *[]Handle to its own type, so special-case
// logic can be moved out of unpackValue() & instead the new type can
// implement SelfMarshaler.

// SelfMarshaler allows custom types to override default encoding/decoding
// behavior in Pack, Unpack and UnpackBuf.
type SelfMarshaler interface {
	TPMMarshal(out io.Writer) error
	TPMUnmarshal(in io.Reader) error
}

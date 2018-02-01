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
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
)

// Make commandHeader
func MakeCommandHeader(tag uint16, size uint32, command uint32) (commandHeader, error) {
	var cmdHdr commandHeader
	cmdHdr.Tag = tag
	cmdHdr.Size = size + 10
	cmdHdr.Cmd = command
	return cmdHdr, nil
}

// Decode response
func DecodeCommandResponse(in []byte) (uint16, uint32, TpmError, error) {
	var tag uint16 
        var size uint32
        var status uint32

        out :=  []interface{}{&tag, &size, &status}
        err := unpack(in, out)
        if err != nil {
                return 0, 0, 0, errors.New("Can't decode response")
        }

	return tag, size, TpmError(status), nil
}

// packedSize computes the size of a sequence of types that can be passed to
// binary.Read or binary.Write.
func packedSize(elts []interface{}) int {
	var size int
	for _, e := range elts {
		v := reflect.ValueOf(e)
		switch v.Kind() {
		case reflect.Ptr:
			s := packedSize([]interface{}{reflect.Indirect(v).Interface()})
			if s < 0 {
				return s
			}

			size += s
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				s := packedSize([]interface{}{v.Field(i).Interface()})
				if s < 0 {
					return s
				}

				size += s
			}
		case reflect.Slice:
			b, ok := e.([]byte)
			if !ok {
				return -1
			}

			size += 2 + len(b)
		default:
			s := binary.Size(e)
			if s < 0 {
				return s
			}

			size += s
		}
	}

	return size
}

// packWithBytes takes a command and byte slice and packs them into a single
// nil is error
func packWithBytes(ch commandHeader, args []byte) ([]byte) {
	hdrSize := binary.Size(ch)
	bodySize := len(args)
	if bodySize < 0 {
		return nil
	}
	ch.Size = uint32(hdrSize + bodySize)
	cmdHdr, _ := pack([]interface{}{ch})
	cmd := append(cmdHdr, args...)
	return cmd
}

// packWithHeader takes a header and a sequence of elements that are either of
// fixed length or slices of fixed-length types and packs them into a single
// byte array using binary.Write. It updates the CommandHeader to have the right
// length.
func packWithHeader(ch commandHeader, cmd []interface{}) ([]byte, error) {
	hdrSize := binary.Size(ch)
	bodySize := packedSize(cmd)
	if bodySize < 0 {
		return nil, errors.New("couldn't compute packed size for message body")
	}
	ch.Size = uint32(hdrSize + bodySize)
	in := []interface{}{ch}
	in = append(in, cmd...)
	return pack(in)
}

// pack encodes a set of elements into a single byte array, using
// encoding/binary. This means that all the elements must be encodeable
// according to the rules of encoding/binary. It has one difference from
// encoding/binary: it encodes byte slices with a prepended uint16 length, to
// match how the TPM encodes variable-length arrays.
func pack(elts []interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := packType(buf, elts); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// packType recursively packs types the same way that encoding/binary does under
// binary.BigEndian, but with one difference: it packs a byte slice as a uint16
// size followed by the bytes. The function unpackType performs the inverse
// operation of unpacking slices stored in this manner and using encoding/binary
// for everything else.
func packType(buf io.Writer, elts []interface{}) error {
	for _, e := range elts {
		v := reflect.ValueOf(e)
		switch v.Kind() {
		case reflect.Ptr:
			if err := packType(buf, []interface{}{reflect.Indirect(v).Interface()}); err != nil {
				return err
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if err := packType(buf, []interface{}{v.Field(i).Interface()}); err != nil {
					return err
				}
			}
		case reflect.Slice:
			b, ok := e.([]byte)
			if !ok {
				return errors.New("can't pack slices of non-byte values")
			}

			if err := binary.Write(buf, binary.BigEndian, uint16(len(b))); err != nil {
				return err
			}

			if err := binary.Write(buf, binary.BigEndian, b); err != nil {
				return err
			}
		default:
			if err := binary.Write(buf, binary.BigEndian, e); err != nil {
				return err
			}
		}

	}

	return nil
}

// unpack performs the inverse operation from pack.
func unpack(b []byte, elts []interface{}) error {
	buf := bytes.NewBuffer(b)
	return unpackType(buf, elts)
}

// resizeBytes changes the size of the byte slice according to the second param.
func resizeBytes(b *[]byte, size uint32) {
	// Append to the slice if it's too small and shrink it if it's too large.
	l := len(*b)
	ss := int(size)
	if l > ss {
		*b = (*b)[:ss]
	} else if l < ss {
		*b = append(*b, make([]byte, ss-l)...)
	}
}

// unpackType recursively unpacks types from a reader just as encoding/binary
// does under binary.BigEndian, but with one difference: it unpacks a byte slice
// by first reading a uint16, then reading that many bytes. It assumes that
// incoming values are pointers to values so that, e.g., underlying slices can
// be resized as needed.
func unpackType(buf io.Reader, elts []interface{}) error {
	for _, e := range elts {
		v := reflect.ValueOf(e)
		k := v.Kind()
		if k != reflect.Ptr {
			return errors.New("all values passed to unpack must be pointers")
		}

		if v.IsNil() {
			return errors.New("can't fill a nil pointer")
		}

		iv := reflect.Indirect(v)
		switch iv.Kind() {
		case reflect.Struct:
			// Decompose the struct and copy over the values.
			for i := 0; i < iv.NumField(); i++ {
				if err := unpackType(buf, []interface{}{iv.Field(i).Addr().Interface()}); err != nil {
					return err
				}
			}
		case reflect.Slice:
			// Read a uint16 and resize the byte array as needed
			var size uint16
			if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
				return err
			}

			// A zero size is used by the TPM to signal that certain elements
			// are not present.
			if size == 0 {
				continue
			}

			b, ok := e.(*[]byte)
			if !ok {
				return errors.New("can't fill pointers to slices of non-byte values")
			}

			resizeBytes(b, uint32(size))
			if err := binary.Read(buf, binary.BigEndian, e); err != nil {
				return err
			}
		default:
			if err := binary.Read(buf, binary.BigEndian, e); err != nil {
				return err
			}
		}

	}

	return nil
}

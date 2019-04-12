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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
)

// Encoding implements encoding logic for different versions of the TPM
// specification.
type Encoding struct {
	// lengthPrefixSize is the size in bytes of length prefix for byte slices.
	//
	// In TPM 1.2 this is 4 bytes.
	// In TPM 2.0 this is 2 bytes.
	lengthPrefixSize int
}

var (
	// Encoding1_2 implements TPM 1.2 encoding.
	Encoding1_2 = &Encoding{
		lengthPrefixSize: tpm12PrefixSize,
	}
	// Encoding2_0 implements TPM 2.0 encoding.
	Encoding2_0 = &Encoding{
		lengthPrefixSize: tpm20PrefixSize,
	}

	defaultEncoding *Encoding
)

const (
	tpm12PrefixSize = 4
	tpm20PrefixSize = 2
)

// UseTPM12Encoding makes the package level Pack/Unpack functions use
// TPM 1.2 encoding for byte arrays.
func UseTPM12Encoding() {
	defaultEncoding = Encoding1_2
}

// UseTPM20Encoding makes the package level Pack/Unpack functions use
// TPM 2.0 encoding for byte arrays.
func UseTPM20Encoding() {
	defaultEncoding = Encoding2_0
}

// packedSize computes the size of a sequence of types that can be passed to
// binary.Read or binary.Write.
func (enc *Encoding) packedSize(elts ...interface{}) (int, error) {
	var size int
	for _, e := range elts {
		marshaler, ok := e.(SelfMarshaler)
		if ok {
			size += marshaler.TPMPackedSize()
			continue
		}
		v := reflect.ValueOf(e)
		switch v.Kind() {
		case reflect.Ptr:
			s, err := enc.packedSize(reflect.Indirect(v).Interface())
			if err != nil {
				return 0, err
			}

			size += s
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				s, err := enc.packedSize(v.Field(i).Interface())
				if err != nil {
					return 0, err
				}

				size += s
			}
		case reflect.Slice:
			switch s := e.(type) {
			case []byte:
				size += enc.lengthPrefixSize + len(s)
			case RawBytes:
				size += len(s)
			default:
				return 0, fmt.Errorf("encoding of %T is not supported, only []byte and RawBytes slices are", e)
			}
		default:
			s := binary.Size(e)
			if s < 0 {
				return 0, fmt.Errorf("can't calculate size of type %T", e)
			}

			size += s
		}
	}

	return size, nil
}

// packWithHeader takes a header and a sequence of elements that are either of
// fixed length or slices of fixed-length types and packs them into a single
// byte array using binary.Write. It updates the CommandHeader to have the right
// length.
func (enc *Encoding) packWithHeader(ch commandHeader, cmd ...interface{}) ([]byte, error) {
	hdrSize := binary.Size(ch)
	bodySize, err := enc.packedSize(cmd...)
	if err != nil {
		return nil, fmt.Errorf("couldn't compute packed size for message body: %v", err)
	}
	ch.Size = uint32(hdrSize + bodySize)
	in := []interface{}{ch}
	in = append(in, cmd...)
	return enc.Pack(in...)
}

// Pack encodes a set of elements using the package's default encoding.
//
// Callers must call UseTPM12Encoding() or UseTPM20Encoding() before calling
// this method.
func Pack(elts ...interface{}) ([]byte, error) {
	if defaultEncoding == nil {
		return nil, errors.New("default encoding not initialized")
	}
	return defaultEncoding.Pack(elts...)
}

// Pack encodes a set of elements into a single byte array, using
// encoding/binary. This means that all the elements must be encodeable
// according to the rules of encoding/binary.
//
// It has one difference from encoding/binary: it encodes byte slices with a
// prepended length, to match how the TPM encodes variable-length arrays. If
// you wish to add a byte slice without length prefix, use RawBytes.
func (enc *Encoding) Pack(elts ...interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := enc.packType(buf, elts...); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// packType recursively packs types the same way that encoding/binary does
// under binary.BigEndian, but with one difference: it packs a byte slice as a
// lengthPrefixSize size followed by the bytes. The function unpackType
// performs the inverse operation of unpacking slices stored in this manner and
// using encoding/binary for everything else.
func (enc *Encoding) packType(buf io.Writer, elts ...interface{}) error {
	for _, e := range elts {
		marshaler, ok := e.(SelfMarshaler)
		if ok {
			if err := marshaler.TPMMarshal(buf); err != nil {
				return err
			}
			continue
		}
		v := reflect.ValueOf(e)
		switch v.Kind() {
		case reflect.Ptr:
			if err := enc.packType(buf, reflect.Indirect(v).Interface()); err != nil {
				return err
			}
		case reflect.Struct:
			// TODO(awly): Currently packType cannot handle non-struct fields that implement SelfMarshaler
			for i := 0; i < v.NumField(); i++ {
				if err := enc.packType(buf, v.Field(i).Interface()); err != nil {
					return err
				}
			}
		case reflect.Slice:
			switch s := e.(type) {
			case []byte:
				switch enc.lengthPrefixSize {
				case tpm20PrefixSize:
					if err := binary.Write(buf, binary.BigEndian, uint16(len(s))); err != nil {
						return err
					}
				case tpm12PrefixSize:
					if err := binary.Write(buf, binary.BigEndian, uint32(len(s))); err != nil {
						return err
					}
				default:
					return fmt.Errorf("lengthPrefixSize is %d, must be either 2 or 4", enc.lengthPrefixSize)
				}
				if err := binary.Write(buf, binary.BigEndian, s); err != nil {
					return err
				}
			case RawBytes:
				if err := binary.Write(buf, binary.BigEndian, s); err != nil {
					return err
				}
			default:
				return fmt.Errorf("only []byte and RawBytes slices are supported, got %T", e)
			}
		default:
			if err := binary.Write(buf, binary.BigEndian, e); err != nil {
				return err
			}
		}

	}

	return nil
}

// Unpack is a convenience wrapper around UnpackBuf using the package's default
// encoding.
//
// Callers must call UseTPM12Encoding() or UseTPM20Encoding() before calling
// this method.
func Unpack(b []byte, elts ...interface{}) (int, error) {
	if defaultEncoding == nil {
		return 0, errors.New("default encoding not initialized")
	}
	return defaultEncoding.Unpack(b, elts...)
}

// Unpack is a convenience wrapper around UnpackBuf. Unpack returns the number
// of bytes read from b to fill elts and error, if any.
func (enc *Encoding) Unpack(b []byte, elts ...interface{}) (int, error) {
	buf := bytes.NewBuffer(b)
	err := enc.UnpackBuf(buf, elts...)
	read := len(b) - buf.Len()
	return read, err
}

// UnpackBuf recursively unpacks types from a reader using the package's default
// encoding.
//
// Callers must call UseTPM12Encoding() or UseTPM20Encoding() before calling
// this method.
func UnpackBuf(buf io.Reader, elts ...interface{}) error {
	if defaultEncoding == nil {
		return errors.New("default encoding not initialized")
	}
	return defaultEncoding.UnpackBuf(buf, elts...)
}

// UnpackBuf recursively unpacks types from a reader just as encoding/binary
// does under binary.BigEndian, but with one difference: it unpacks a byte
// slice by first reading an integer with lengthPrefixSize bytes, then reading
// that many bytes. It assumes that incoming values are pointers to values so
// that, e.g., underlying slices can be resized as needed.
func (enc *Encoding) UnpackBuf(buf io.Reader, elts ...interface{}) error {
	for _, e := range elts {
		v := reflect.ValueOf(e)
		k := v.Kind()
		if k != reflect.Ptr {
			return fmt.Errorf("all values passed to Unpack must be pointers, got %v", k)
		}

		if v.IsNil() {
			return errors.New("can't fill a nil pointer")
		}

		marshaler, ok := e.(SelfMarshaler)
		if ok {
			if err := marshaler.TPMUnmarshal(buf); err != nil {
				return err
			}
			continue
		}
		iv := reflect.Indirect(v)
		switch iv.Kind() {
		case reflect.Struct:
			// Decompose the struct and copy over the values.
			for i := 0; i < iv.NumField(); i++ {
				if err := enc.UnpackBuf(buf, iv.Field(i).Addr().Interface()); err != nil {
					return err
				}
			}
		case reflect.Slice:
			var size int
			_, isHandles := e.(*[]Handle)

			switch {
			// []Handle always uses 2-byte length, even with TPM 1.2.
			case isHandles:
				var tmpSize uint16
				if err := binary.Read(buf, binary.BigEndian, &tmpSize); err != nil {
					return err
				}
				size = int(tmpSize)
			// TPM 2.0
			case enc.lengthPrefixSize == tpm20PrefixSize:
				var tmpSize uint16
				if err := binary.Read(buf, binary.BigEndian, &tmpSize); err != nil {
					return err
				}
				size = int(tmpSize)
			// TPM 1.2
			case enc.lengthPrefixSize == tpm12PrefixSize:
				var tmpSize uint32
				if err := binary.Read(buf, binary.BigEndian, &tmpSize); err != nil {
					return err
				}
				size = int(tmpSize)
			default:
				return fmt.Errorf("lengthPrefixSize is %d, must be either 2 or 4", enc.lengthPrefixSize)
			}

			// A zero size is used by the TPM to signal that certain elements
			// are not present.
			if size == 0 {
				continue
			}

			// Make len(e) match size exactly.
			switch b := e.(type) {
			case *[]byte:
				if len(*b) >= size {
					*b = (*b)[:size]
				} else {
					*b = append(*b, make([]byte, size-len(*b))...)
				}
			case *[]Handle:
				if len(*b) >= size {
					*b = (*b)[:size]
				} else {
					*b = append(*b, make([]Handle, size-len(*b))...)
				}
			default:
				return fmt.Errorf("can't fill pointer to %T, only []byte or []Handle slices", e)
			}

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

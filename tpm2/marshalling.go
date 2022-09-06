package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
)

var notImplError = errors.New("not implemented")

// Marshallable represents any TPM type that can be marshalled.
type Marshallable interface {
	// marshal will serialize the given value, appending onto the given buffer.
	// Returns an error if the value is not marshallable.
	marshal(buf *bytes.Buffer) error
}

// Unmarshallable represents any TPM type that can be marshalled or unmarshalled.
type Unmarshallable interface {
	Marshallable
	// marshal will deserialize the given value from the given buffer.
	// Returns an error if there was an unmarshalling error or if there was not
	// enough data in the buffer.
	unmarshal(buf *bytes.Buffer) error
}

// Marshal will serialize the given values, returning them as a byte slice.
func Marshal[T Marshallable](v T) []byte {
	var buf bytes.Buffer
	if err := marshal(&buf, reflect.ValueOf(v)); err != nil {
		panic(fmt.Sprintf("unexpected error marshalling %v: %v", reflect.TypeOf(v).Name(), err))
	}
	return buf.Bytes()
}

// Returns an error if the buffer does not contain enough data to satisfy the
// types, or if the types are not unmarshallable.
func Unmarshal[T any, P interface {
	// *T must satisfy Marshallable
	*T
	Unmarshallable
}](data []byte) (*T, error) {
	buf := bytes.NewBuffer(data)
	var t T
	value := reflect.New(reflect.TypeOf(t))
	if err := unmarshal(buf, value.Elem()); err != nil {
		return nil, err
	}
	return value.Interface().(*T), nil
}

// marshallableByReflection is a placeholder interface, to hint to the unmarshalling
// library that it is supposed to use reflection.
type marshallableByReflection interface {
	reflectionSafe()
}

// marshalByReflection is embedded into any type that can be marshalled by reflection,
// needing no custom logic.
type marshalByReflection struct{}

func (_ marshalByReflection) reflectionSafe() {}

// Placeholder: because this type implements the defaultMarshallable interface,
// the reflection library knows not to call this.
func (_ *marshalByReflection) marshal(_ *bytes.Buffer) error { return notImplError }

// Placeholder: because this type implements the defaultMarshallable interface,
// the reflection library knows not to call this.
func (_ *marshalByReflection) unmarshal(_ *bytes.Buffer) error { return notImplError }

// tpm2b is a helper type for a field that can be provided either by structure or by byte-array.
// When deserialized (e.g., from a TPM response), both contents and Buffer are populated.
// When serialized, if contents is non-nil, the value of contents is used.
//   Else, the value of Buffer is used.
type tpm2b[T any] struct {
	contents *T
	buffer   []byte
}

type bytesOr[T any] interface{ *T | []byte }

// tpm2bHelper is a helper function that can convert either a structure or a byte buffer into
// the proper TPM2B_ sub-type.
func tpm2bHelper[T any, C bytesOr[T]](contents C) *tpm2b[T] {
	if typed, ok := any(contents).(*T); ok {
		return &tpm2b[T]{contents: typed}
	}
	return &tpm2b[T]{buffer: any(contents).([]byte)}
}

// marshal implements the marshallable interface.
func (value *tpm2b[T]) marshal(buf *bytes.Buffer) error {
	if value.contents != nil {
		var temp bytes.Buffer
		if err := marshal(&temp, reflect.ValueOf(value.contents)); err != nil {
			return err
		}
		binary.Write(buf, binary.BigEndian, uint16(temp.Len()))
		io.Copy(buf, &temp)
		return nil
	}
	binary.Write(buf, binary.BigEndian, uint16(len(value.buffer)))
	buf.Write(value.buffer)
	return nil
}

// unmarshal implements the marshallable interface.
func (value *tpm2b[T]) unmarshal(buf *bytes.Buffer) error {
	var size uint16
	binary.Read(buf, binary.BigEndian, &size)
	value.buffer = make([]byte, size)
	n, err := buf.Read(value.buffer)
	if err != nil {
		return err
	}
	if n != int(size) {
		return fmt.Errorf("ran out of data attempting to read %v bytes from the bufferm which only had %v", size, n)
	}
	rdr := bytes.NewBuffer(value.buffer)
	value.contents = new(T)
	return unmarshal(rdr, reflect.ValueOf(value.contents))
}

// CheckUnwrap returns the structured contents of the tpm2b.
// Never returns an error if the tpm2b's underlying value is an actual structure.
// May return an error if the underlying value was a byte array, and there were errors parsing it.
func (value *tpm2b[T]) CheckUnwrap() (*T, error) {
	if value.contents != nil {
		return value.contents, nil
	}
	if value.buffer == nil {
		return nil, fmt.Errorf("TPMB had no contents or buffer")
	}
	var result T
	if err := unmarshal(bytes.NewBuffer(value.buffer), reflect.ValueOf(&result).Elem()); err != nil {
		return nil, err
	}
	return &result, nil
}

// Unwrap returns the structured contents of the tpm2b.
// Never panics if the tpm2b's underlying value is an actual structure.
// Panics if the underlying value was a byte array, and there were errors parsing it.
// To unmarshal a byte array-backed TPM2B safely, use CheckUnmarshal.
func (value *tpm2b[T]) Unwrap() *T {
	result, err := value.CheckUnwrap()
	if err != nil {
		panic(fmt.Sprintf("could not unwrap %v: %v", reflect.TypeOf(result).Elem(), err))
	}
	return result
}

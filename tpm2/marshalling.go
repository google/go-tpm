package tpm2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
)

// marshallable represents any TPM type that has its own custom logic for marshalling.
type marshallable interface {
	// marshal will serialize the given value, appending onto the given buffer.
	// Returns an error if the value is not marshallable.
	marshal(buf *bytes.Buffer) error
}

// unmarshallable represents any TPM type that has its own custom logic for unmarshalling.
type unmarshallable interface {
	// unmarshal will deserialize the given value from the given buffer.
	// Returns an error if the buffer does not contain enough data to satisfy the type.
	unmarshal(buf *bytes.Buffer) error
}

// tpm2b is a helper type for a field that can be provided either by structure or by byte-array.
// When deserialized (e.g., from a TPM response), both Contents and Buffer are populated.
// When serialized, if Contents is non-nil, the value of Contents is used.
//   Else, the value of Buffer is used.
type tpm2b[T any] struct {
	Contents *T
	Buffer   []byte
}

type bytesOr[T any] interface{ *T | []byte }

// tpm2bHelper is a helper function that can convert either a structure or a byte buffer into
// the proper TPM2B_ sub-type.
func tpm2bHelper[T any, C bytesOr[T]](contents C) tpm2b[T] {
	if typed, ok := any(contents).(*T); ok {
		return tpm2b[T]{Contents: typed}
	}
	return tpm2b[T]{Buffer: any(contents).([]byte)}
}

// marshal implements the marshallable interface.
func (value tpm2b[T]) marshal(buf *bytes.Buffer) error {
	if value.Contents != nil {
		var temp bytes.Buffer
		if err := marshal(&temp, reflect.ValueOf(*value.Contents)); err != nil {
			return err
		}
		binary.Write(buf, binary.BigEndian, uint16(temp.Len()))
		io.Copy(buf, &temp)
		return nil
	}
	binary.Write(buf, binary.BigEndian, uint16(len(value.Buffer)))
	buf.Write(value.Buffer)
	return nil
}

// unmarshal implements the unmarshallable interface.
func (value *tpm2b[T]) unmarshal(buf *bytes.Buffer) error {
	var size uint16
	binary.Read(buf, binary.BigEndian, &size)
	value.Buffer = make([]byte, size)
	n, err := buf.Read(value.Buffer)
	if err != nil {
		return err
	}
	if n != int(size) {
		return fmt.Errorf("ran out of data attempting to read %v bytes from the bufferm which only had %v", size, n)
	}
	rdr := bytes.NewBuffer(value.Buffer)
	value.Contents = new(T)
	return unmarshal(rdr, reflect.ValueOf(value.Contents).Elem())
}

// CheckUnwrap returns the structured contents of the tpm2b.
// Never returns an error if the tpm2b's underlying value is an actual structure.
// May return an error if the underlying value was a byte array, and there were errors parsing it.
func (value *tpm2b[T]) CheckUnwrap() (*T, error) {
	if value.Contents != nil {
		return value.Contents, nil
	}
	if value.Buffer == nil {
		return nil, fmt.Errorf("TPMB had no contents or buffer")
	}
	var result T
	if err := unmarshal(bytes.NewBuffer(value.Buffer), reflect.ValueOf(&result).Elem()); err != nil {
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

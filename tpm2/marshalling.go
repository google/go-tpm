package tpm2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
)

// maybe represents some type that came out of an unmarshalling process.
// We may have the value, or we may have an error.
type maybe[T any] struct {
	err   error
	value *T
}

// OK returns true if the maybe contains contents instead of an error.
func (m maybe[_]) OK() bool {
	return m.err == nil
}

// Unwrap unwraps the result of an unmarshalling operation.
// Panics if the data was not unmarshalled.
func (m maybe[T]) Unwrap() *T {
	if m.err != nil {
		panic(fmt.Sprintf("could not unwrap: %v", m.err))
	}
	return m.value
}

// CheckUnwrap unwraps the result of an unmarshalling operation.
func (m maybe[T]) CheckUnwrap() (*T, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.value, nil
}

// asMaybe returns a maybe enclosing the given contents.
func asMaybe[T any](t *T) maybe[T] {
	return maybe[T]{
		value: t,
	}
}

// maybeNot returns a maybe with the given error.
func maybeNot[T any](err error) maybe[T] {
	return maybe[T]{
		err: err,
	}
}

// Marshallable represents any TPM type that can be marshalled.
type Marshallable interface {
	// marshal will serialize the given value, appending onto the given buffer.
	// Returns an error if the value is not marshallable.
	marshal(buf *bytes.Buffer)
}

// Unmarshallable represents any TPM type that can be marshalled or unmarshalled.
type Unmarshallable interface {
	Marshallable
	// marshal will deserialize the given value from the given buffer.
	// Returns an error if there was an unmarshalling error or if there was not
	// enough data in the buffer.
	unmarshal(buf *bytes.Buffer) error
}

// UnmarshallableWithHint represents any TPM type that can be marshalled or unmarshalled,
// but that requires a selector ("hint") value when unmarshalling. Most TPMU_ are
// an example of this.
type UnmarshallableWithHint interface {
	// create will instantiate and return the corresponding union member.
	create(hint int64) (reflect.Value, error)
	// get will return the corresponding union member by copy. If the union is
	// uninitialized, it will initialize a new zero-valued one.
	get(hint int64) (reflect.Value, error)
}

// Marshal will serialize the given values, returning them as a byte slice.
func Marshal[T Marshallable](v T) []byte {
	var buf bytes.Buffer
	if err := marshal(&buf, reflect.ValueOf(v)); err != nil {
		panic(fmt.Sprintf("unexpected error marshalling %v: %v", reflect.TypeOf(v).Name(), err))
	}
	return buf.Bytes()
}

// Unmarshal unmarshals the given type from the byte array.
// Returns an error if the buffer does not contain enough data to satisfy the
// types, or if the types are not unmarshallable.
func Unmarshal[T any, P interface {
	// *T must satisfy Marshallable
	*T
	Unmarshallable
}](data []byte) maybe[T] {
	buf := bytes.NewBuffer(data)
	var t T
	value := reflect.New(reflect.TypeOf(t))
	if err := unmarshal(buf, value.Elem()); err != nil {
		return maybe[T]{
			err: err,
		}
	}
	return maybe[T]{
		value: value.Interface().(*T),
	}
}

// marshallableByReflection is a placeholder interface, to hint to the unmarshalling
// library that it is supposed to use reflection.
type marshallableByReflection interface {
	reflectionSafe()
}

// marshalByReflection is embedded into any type that can be marshalled by reflection,
// needing no custom logic.
type marshalByReflection struct{}

func (marshalByReflection) reflectionSafe() {}

// These placeholders are required because a type constraint cannot union another interface
// that contains methods.
// Otherwise, marshalByReflection would not implement Unmarshallable, and the Marshal/Unmarshal
// functions would accept interface{ Marshallable | marshallableByReflection } instead.

// Placeholder: because this type implements the defaultMarshallable interface,
// the reflection library knows not to call this.
func (*marshalByReflection) marshal(_ *bytes.Buffer) {
	panic("not implemented")
}

// Placeholder: because this type implements the defaultMarshallable interface,
// the reflection library knows not to call this.
func (*marshalByReflection) unmarshal(_ *bytes.Buffer) error {
	panic("not implemented")
}

// tpm2b is a helper type for a field that can be provided either by structure or by byte-array.
// When deserialized (e.g., from a TPM response), both contents and Buffer are populated.
// When serialized, if contents is non-nil, the value of contents is used.
//
//	Else, the value of Buffer is used.
type tpm2b[T any] struct {
	contents *T
	buffer   []byte
}

type bytesOr[T any] interface{ *T | []byte }

// tpm2bHelper is a helper function that can convert either a structure or a byte buffer into
// the proper TPM2B_ sub-type.
func tpm2bHelper[T any, C bytesOr[T]](contents C) tpm2b[T] {
	if typed, ok := any(contents).(*T); ok {
		return tpm2b[T]{contents: typed}
	}
	return tpm2b[T]{buffer: any(contents).([]byte)}
}

// marshal implements the Marshallable interface.
func (value *tpm2b[T]) marshal(buf *bytes.Buffer) {
	if value.contents != nil {
		var temp bytes.Buffer
		marshal(&temp, reflect.ValueOf(value.contents))
		binary.Write(buf, binary.BigEndian, uint16(temp.Len()))
		io.Copy(buf, &temp)
	} else {
		binary.Write(buf, binary.BigEndian, uint16(len(value.buffer)))
		buf.Write(value.buffer)
	}
}

// unmarshal implements the Marshallable interface.
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

// Contents returns the structured contents of the tpm2b.
func (value *tpm2b[T]) Contents() maybe[T] {
	if value.contents != nil {
		return asMaybe(value.contents)
	}
	if value.buffer == nil {
		return maybeNot[T](fmt.Errorf("TPMB had no contents or buffer"))
	}
	var result T
	if err := unmarshal(bytes.NewBuffer(value.buffer), reflect.ValueOf(&result).Elem()); err != nil {
		return maybeNot[T](err)
	}
	return asMaybe(&result)
}

// boxed is a helper type for corner cases such as unions, where all members must be structs.
type boxed[T any] struct {
	Contents *T
}

// box will put a value into a box.
func box[T any](contents *T) boxed[T] {
	return boxed[T]{
		Contents: contents,
	}
}

// unbox will take a value out of a box.
func (b *boxed[T]) unbox() *T {
	return b.Contents
}

// marshal implements the Marshallable interface.
func (b *boxed[T]) marshal(buf *bytes.Buffer) {
	if b.Contents == nil {
		var contents T
		marshal(buf, reflect.ValueOf(&contents))
	} else {
		marshal(buf, reflect.ValueOf(b.Contents))
	}
}

// unmarshal implements the Unmarshallable interface.
func (b *boxed[T]) unmarshal(buf *bytes.Buffer) error {
	b.Contents = new(T)
	return unmarshal(buf, reflect.ValueOf(b.Contents))
}

package tpm2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
)

// Marshallable represents any TPM type that can be marshalled.
type Marshallable interface {
	// marshal will serialize the given value, appending onto the given buffer.
	// Returns an error if the value is not marshallable.
	marshal(buf *bytes.Buffer)
}

// marshallableWithHint represents any TPM type that can be marshalled,
// but that requires a selector ("hint") value when marshalling. Most TPMU_ are
// an example of this.
type marshallableWithHint interface {
	// get will return the corresponding union member by copy. If the union is
	// uninitialized, it will initialize a new zero-valued one.
	get(hint int64) (reflect.Value, error)
}

// CommandPreimage represents a structured preimage of cpHash for a TPM command.
// This structure is marshaled to bytes using [Marshal] for storage/transmission
// and can be converted to the raw cpHash preimage format for hashing.
//
// Format when marshaled:
//   - CommandCode: 4 bytes (TPMCC)
//   - Names: sized list of TPM2BName
//   - Parameters: sized buffer
//
// See definition in Part 1: Architecture, section 16.7.
type CommandPreimage struct {
	marshalByReflection
	// CommandCode is the TPM command code
	CommandCode TPMCC
	// Names are the names of the handles referenced by the command
	Names []TPM2BName `gotpm:"list"`
	// Parameters are the marshaled command parameters
	Parameters TPM2BData
}

// ToCPHashPreimage converts the CommandPreimage to the raw buffer format
// used to compute cpHash according to TPM 2.0 spec.
func (cp *CommandPreimage) ToCPHashPreimage() []byte {
	var buf bytes.Buffer

	// Write command code (4 bytes, big endian)
	binary.Write(&buf, binary.BigEndian, cp.CommandCode)

	// Write names (raw buffers without size prefix)
	for _, name := range cp.Names {
		buf.Write(name.Buffer)
	}

	// Write parameters
	buf.Write(cp.Parameters.Buffer)

	return buf.Bytes()
}

// Unmarshallable represents any TPM type that can be marshalled or unmarshalled.
type Unmarshallable interface {
	Marshallable
	// marshal will deserialize the given value from the given buffer.
	// Returns an error if there was an unmarshalling error or if there was not
	// enough data in the buffer.
	unmarshal(buf *bytes.Buffer) error
}

// unmarshallableWithHint represents any TPM type that can be marshalled or unmarshalled,
// but that requires a selector ("hint") value when unmarshalling. Most TPMU_ are
// an example of this.
type unmarshallableWithHint interface {
	marshallableWithHint
	// create will instantiate and return the corresponding union member.
	create(hint int64) (reflect.Value, error)
}

// Marshal will serialize the given values, returning them as a byte slice.
func Marshal(v Marshallable) []byte {
	var buf bytes.Buffer
	if err := marshal(&buf, reflect.ValueOf(v)); err != nil {
		panic(fmt.Sprintf("unexpected error marshalling %v: %v", reflect.TypeOf(v).Name(), err))
	}
	return buf.Bytes()
}

// Unmarshal unmarshals the given type from the byte array.
// Returns an error if the buffer does not contain enough data to satisfy the
// types, or if the types are not unmarshallable.
func Unmarshal[T Marshallable, P interface {
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

func (marshalByReflection) reflectionSafe() {}

// These placeholders are required because a type constraint cannot union another interface
// that contains methods.
// Otherwise, marshalByReflection would not implement Unmarshallable, and the Marshal/Unmarshal
// functions would accept interface{ Marshallable | marshallableByReflection } instead.

// Placeholder: because this type implements the defaultMarshallable interface,
// the reflection library knows not to call this.
func (marshalByReflection) marshal(_ *bytes.Buffer) {
	panic("not implemented")
}

// Placeholder: because this type implements the defaultMarshallable interface,
// the reflection library knows not to call this.
func (*marshalByReflection) unmarshal(_ *bytes.Buffer) error {
	panic("not implemented")
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

// toCommandPreimage convert a Command to a CommandPreimage structure from a command.
func toCommandPreimage[C Command[R, *R], R any](cmd C) (*CommandPreimage, error) {
	cc := cmd.Command()

	names, err := cmdNames(cmd)
	if err != nil {
		return nil, err
	}

	params, err := cmdParameters(cmd, nil)
	if err != nil {
		return nil, err
	}

	return &CommandPreimage{
		CommandCode: cc,
		Names:       names,
		Parameters: TPM2BData{
			Buffer: params,
		},
	}, nil
}

// MarshalCommand marshals a TPM command into a serialized CommandPreimage.
// The returned bytes contain a marshaled CommandPreimage structure that includes:
//   - CommandCode (4 bytes)
//   - Names (sized list)
//   - Parameters (sized buffer)
//
// This can be stored, transmitted, or later unmarshaled.
//
// To compute cpHash use [CommandPreimage.ToCPHashPreimage].
func MarshalCommand[C Command[R, *R], R any](cmd C) ([]byte, error) {
	preimage, err := toCommandPreimage(cmd)
	if err != nil {
		return nil, err
	}
	return Marshal(preimage), nil
}

// unmarshalCommandPreimage unmarshals serialized data into CommandPreimage components.
// Returns the command code, names, and parameters.
func unmarshalCommandPreimage(data []byte) (TPMCC, []TPM2BName, []byte, error) {
	if data == nil {
		return 0, nil, nil, fmt.Errorf("data cannot be nil")
	}

	preimage, err := Unmarshal[CommandPreimage](data)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("unmarshalling CommandPreimage: %w", err)
	}

	return preimage.CommandCode, preimage.Names, preimage.Parameters.Buffer, nil
}

// UnmarshalCommand unmarshals a serialized [CommandPreimage] back into a TPM command.
// The data should be the output from [MarshalCommand].
//
// Note: command produced from this function is not meant to be executed directly on a TPM,
// instead it is expected to be used for purposes such as auditing or inspection.
func UnmarshalCommand[C Command[R, *R], R any](data []byte) (C, error) {
	var cmd C

	cc, names, params, err := unmarshalCommandPreimage(data)
	if err != nil {
		return cmd, err
	}

	if cc != cmd.Command() {
		return cmd, fmt.Errorf("command code mismatch: expected %v, got %v", cmd.Command(), cc)
	}

	{
		n, err := cmdNames(cmd)
		if err != nil {
			return cmd, err
		}

		expectedNames := len(names)
		if len(n) != expectedNames {
			return cmd, fmt.Errorf("name count mismatch: command expects %d names, got %d", expectedNames, len(n))
		}
	}

	// Populate the command's handle fields from the names
	if err := populateHandlesFromNames(&cmd, names); err != nil {
		return cmd, fmt.Errorf("populating handles: %w", err)
	}

	// Now unmarshal the parameters using the helper
	buf := bytes.NewBuffer(params)
	if err := unmarshalCmdParameters(buf, &cmd, nil); err != nil {
		return cmd, err
	}
	return cmd, nil
}

// MarshalResponse marshals a TPM response.
func MarshalResponse[R any](rsp *R) ([]byte, error) {
	return marshalRspParameters(rsp, nil)
}

// UnmarshalResponse unmarshals a TPM response.
//
// Note: the result from this function is expected to be used for purposes such as auditing or inspection.
func UnmarshalResponse[R any](data []byte) (*R, error) {
	var rsp R
	if data == nil {
		return nil, fmt.Errorf("data cannot be nil")
	}
	if err := rspParameters(data, nil, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

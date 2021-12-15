package direct

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func marshalUnmarshal(t *testing.T, v interface{}, want []byte) {
	t.Helper()
	var buf bytes.Buffer
	marshal(&buf, reflect.ValueOf(v))
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("want %x got %x", want, buf.Bytes())
	}
	got := reflect.New(reflect.TypeOf(v))
	err := unmarshal(&buf, got.Elem())
	if err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if !cmp.Equal(v, got.Elem().Interface()) {
		t.Errorf("want %#v, got %#v\n%v", v, got.Elem().Interface(), cmp.Diff(v, got.Elem().Interface()))
	}
}

func TestMarshalNumeric(t *testing.T) {
	vals := map[interface{}][]byte{
		false:              []byte{0},
		byte(1):            []byte{1},
		int8(2):            []byte{2},
		uint8(3):           []byte{3},
		int16(260):         []byte{1, 4},
		uint16(261):        []byte{1, 5},
		int32(65542):       []byte{0, 1, 0, 6},
		uint32(65543):      []byte{0, 1, 0, 7},
		int64(4294967304):  []byte{0, 0, 0, 1, 0, 0, 0, 8},
		uint64(4294967305): []byte{0, 0, 0, 1, 0, 0, 0, 9},
	}
	for v, want := range vals {
		t.Run(fmt.Sprintf("%v-%v", reflect.TypeOf(v), v), func(t *testing.T) {
			marshalUnmarshal(t, v, want)
		})
	}
}

func TestMarshalArray(t *testing.T) {
	vals := []struct {
		Data          interface{}
		Serialization []byte
	}{
		{[4]int8{1, 2, 3, 4}, []byte{1, 2, 3, 4}},
		{[3]uint16{5, 6, 7}, []byte{0, 5, 0, 6, 0, 7}},
	}
	for _, val := range vals {
		v, want := val.Data, val.Serialization
		t.Run(fmt.Sprintf("%v-%v", reflect.TypeOf(v), v), func(t *testing.T) {
			marshalUnmarshal(t, v, want)
		})
	}
}

func TestMarshalSlice(t *testing.T) {
	// Slices in reflect/gotpm must be tagged marshalled/unmarshalled as
	// part of a struct with the 'list' tag
	type sliceWrapper struct {
		Elems []uint32 `gotpm:"list"`
	}
	vals := []struct {
		Name          string
		Data          sliceWrapper
		Serialization []byte
	}{
		{"3", sliceWrapper{[]uint32{1, 2, 3}}, []byte{0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3}},
		{"1", sliceWrapper{[]uint32{4}}, []byte{0, 0, 0, 1, 0, 0, 0, 4}},
		{"empty", sliceWrapper{[]uint32{}}, []byte{0, 0, 0, 0}},
	}
	for _, val := range vals {
		v, want := val.Data, val.Serialization
		t.Run(val.Name, func(t *testing.T) {
			marshalUnmarshal(t, v, want)
		})
	}
}

func TestMarshalBitfield(t *testing.T) {
	type bitfield8 struct {
		Bit0 uint8 `gotpm:"bit=0"`
		Bit1 uint8 `gotpm:"bit=1"`
		Bit2 uint8 `gotpm:"bit=2"`
		Bit3 uint8 `gotpm:"bit=3"`
		Bit4 uint8 `gotpm:"bit=4"`
		Bit5 uint8 `gotpm:"bit=5"`
		Bit6 uint8 `gotpm:"bit=6"`
		Bit7 uint8 `gotpm:"bit=7"`
	}
	type bitfield32 struct {
		Reserved1       uint16 `gotpm:"bit=5:0"`
		Bit6            uint8  `gotpm:"bit=6"`
		Reserved2       uint8  `gotpm:"bit=12:7"`
		Bit13           bool   `gotpm:"bit=13"`
		Bits14Through18 uint8  `gotpm:"bit=18:14"`
		Bit19           byte   `gotpm:"bit=19"`
		Reserved3       uint16 `gotpm:"bit=30:20"`
		Bit31           uint32 `gotpm:"bit=31"`
	}
	t.Run("8bit", func(t *testing.T) {
		v := bitfield8{
			Bit0: 0,
			Bit1: 1,
			Bit2: 0,
			Bit3: 1,
			Bit4: 1,
			Bit5: 0,
			Bit6: 0,
			Bit7: 1,
		}
		want := []byte{0x9a}
		marshalUnmarshal(t, v, want)
	})
	t.Run("32bit", func(t *testing.T) {
		v := bitfield32{
			Bit6:            1,
			Bit13:           false,
			Bits14Through18: 29,
			Bit19:           1,
			Bit31:           1,
		}
		want := []byte{0x80, 0x0f, 0x40, 0x40}
		marshalUnmarshal(t, v, want)
	})
}

func TestMarshalUnion(t *testing.T) {
	type valStruct struct {
		First  bool
		Second int32
	}
	type unionValue struct {
		Val8      *uint8     `gotpm:"selector=8"`
		Val64     *uint64    `gotpm:"selector=0x00000040"`
		ValStruct *valStruct `gotpm:"selector=5"` // 5 for '5truct'
	}
	type unionEnvelope struct {
		Type       uint8
		OtherThing uint32
		Value      unionValue `gotpm:"tag=Type"`
	}
	eight := uint8(8)
	sixtyFour := uint64(64)
	cases := []struct {
		Name          string
		Data          unionEnvelope
		Serialization []byte
	}{
		{
			Name: "8",
			Data: unionEnvelope{
				Type:       8,
				OtherThing: 0xabcd1234,
				Value: unionValue{
					Val8: &eight,
				},
			},
			Serialization: []byte{
				0x08, 0xab, 0xcd, 0x12, 0x34, 0x08,
			},
		},
		{
			Name: "64",
			Data: unionEnvelope{
				Type:       64,
				OtherThing: 0xffffffff,
				Value: unionValue{
					Val64: &sixtyFour,
				},
			},
			Serialization: []byte{
				0x40, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
			},
		},
		{
			Name: "Struct",
			Data: unionEnvelope{
				Type:       5,
				OtherThing: 0x11111111,
				Value: unionValue{
					ValStruct: &valStruct{
						First:  true,
						Second: 65537,
					},
				},
			},
			Serialization: []byte{
				0x05, 0x11, 0x11, 0x11, 0x11, 0x01, 0x00, 0x01, 0x00, 0x01,
			},
		},
	}

	for _, c := range cases {
		v, want := c.Data, c.Serialization
		t.Run(c.Name, func(t *testing.T) {
			marshalUnmarshal(t, v, want)
		})
	}
}

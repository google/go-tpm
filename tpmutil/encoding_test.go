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

package tpmutil

import (
	"bytes"
	"io"
	"io/ioutil"
	"reflect"
	"testing"
)

func init() {
	UseTPM12LengthPrefixSize()
}

type invalidPacked struct {
	A []int
	B uint32
}

func testEncodingInvalidSlices(t *testing.T, f func(io.Writer, interface{}) error) {
	d := ioutil.Discard

	// The packedSize function doesn't handle slices to anything other than bytes.
	var invalid []int
	if err := f(d, invalid); err == nil {
		t.Fatal("The packing function incorrectly succeeds for a slice of integers")
	}
	if err := f(d, &invalid); err == nil {
		t.Fatal("The packing function incorrectly succeeds for a pointer to a slice of integers")
	}

	invalid2 := invalidPacked{
		A: make([]int, 10),
		B: 137,
	}
	if err := f(d, invalid2); err == nil {
		t.Fatal("The packing function incorrectly succeeds for a struct that contains an integer slice")
	}
	if err := f(d, &invalid2); err == nil {
		t.Fatal("The packing function incorrectly succeeds for a pointer to a struct that contains an integer slice")
	}

	if err := f(d, d); err == nil {
		t.Fatal("The packing function incorrectly succeeds for a non-packable value")
	}
}

func TestEncodingPackedSizeInvalid(t *testing.T) {
	f := func(w io.Writer, i interface{}) error {
		_, err := packedSize(i)
		return err
	}

	testEncodingInvalidSlices(t, f)
}

func TestEncodingPackTypeInvalid(t *testing.T) {
	f := func(w io.Writer, i interface{}) error {
		return packType(w, i)
	}

	testEncodingInvalidSlices(t, f)
}

type simplePacked struct {
	A uint32
	B uint32
}

type nestedPacked struct {
	SP simplePacked
	C  uint32
}

type nestedSlice struct {
	A uint32
	S []byte
}

func TestEncodingPackedSize(t *testing.T) {
	buf := make([]byte, 10)
	tests := []struct {
		in   interface{}
		want int
	}{
		{uint32(3), 4},
		{buf, 14},
		{&buf, 14},
		{simplePacked{137, 138}, 8},
		{nestedPacked{simplePacked{137, 138}, 139}, 12},
		{nestedSlice{137, buf}, 18},
		{[]byte(nil), 4},
	}
	for _, tt := range tests {
		if s, err := packedSize(tt.in); err != nil || s != tt.want {
			t.Errorf("packedSize(%#v): %d, want %d", tt.in, s, tt.want)
		}
	}
}

func TestEncodingPackType(t *testing.T) {
	if err := packType(ioutil.Discard, uint32(3)); err != nil {
		t.Fatal("packType failed for a uint32")
	}

	b := make([]byte, 10)
	if err := packType(ioutil.Discard, b); err != nil {
		t.Fatal("packType failed for a byte slice")
	}
	if err := packType(ioutil.Discard, &b); err != nil {
		t.Fatal("packType failed for a pointer to a byte slice")
	}

	sp := simplePacked{137, 138}
	if err := packType(ioutil.Discard, sp); err != nil {
		t.Fatal("packType failed for a simple struct")
	}

	np := nestedPacked{sp, 139}
	if err := packType(ioutil.Discard, np); err != nil {
		t.Fatal("packType failed for a nested struct")
	}

	ns := nestedSlice{137, b}
	if err := packType(ioutil.Discard, ns); err != nil {
		t.Fatal("packType failed for a struct that contains a slice")
	}

	// Pack an empty array.
	var empty []byte
	if err := packType(ioutil.Discard, empty); err != nil {
		t.Fatal("packType failed for an empty byte slice")
	}

	// Pack into a writer that doesn't have enough space.
	// The value l has enough space for a uint32 length, but not any bytes.
	l := &limitedDiscard{4}
	bb := []byte{1}
	if err := packType(l, bb); err == nil {
		t.Fatal("packType incorrectly packed into an array that didn't have enough space")
	}

	// The value l2 doesn't even have enough space to pack a uint32.
	l2 := &limitedDiscard{3}
	if err := packType(l2, empty); err == nil {
		t.Fatal("packType incorrectly packed an empty array size into an array that didn't have enough space")
	}
}

// limitedDiscard is an implementation of io.Writer that accepts a given number
// of bytes before returning errors.
type limitedDiscard struct {
	remaining int
}

// Write writes p to the limitedDiscard instance.
func (l *limitedDiscard) Write(p []byte) (n int, err error) {
	n = len(p)
	if n > l.remaining {
		n = l.remaining
		err = io.EOF
	}

	l.remaining -= n
	return
}

func TestEncodingCommandHeaderInvalidBody(t *testing.T) {
	var invalid []int
	ch := commandHeader{1, 0, 2}
	_, err := packWithHeader(ch, invalid)
	if err == nil {
		t.Fatal("packWithHeader incorrectly packed a body that with an invalid int slice member")
	}
}

func TestEncodingInvalidPack(t *testing.T) {
	var invalid []int
	ch := commandHeader{1, 0, 2}
	_, err := packWithHeader(ch, invalid)
	if err == nil {
		t.Fatal("packWithHeader incorrectly packed a body that with an invalid int slice member")
	}

	_, err = Pack(invalid)
	if err == nil {
		t.Fatal("pack incorrectly packed a slice of int")
	}
}

func TestEncodingCommandHeaderEncoding(t *testing.T) {
	ch := commandHeader{1, 0, 2}
	var c uint32 = 137
	in := c

	b, err := packWithHeader(ch, in)
	if err != nil {
		t.Fatal("Couldn't pack the bytes:", err)
	}

	var hdr commandHeader
	var size uint32
	if err := Unpack(b, &hdr, &size); err != nil {
		t.Fatal("Couldn't unpack the packed bytes")
	}

	if size != 137 {
		t.Fatal("Got the wrong size back")
	}
}

func TestEncodingInvalidUnpack(t *testing.T) {
	var i *uint32
	i = nil
	// The value ui is a serialization of uint32(0).
	ui := []byte{0, 0, 0, 0}
	uiBuf := bytes.NewBuffer(ui)
	if err := unpackType(uiBuf, i); err == nil {
		t.Fatal("unpackType incorrectly deserialized into a nil pointer")
	}

	var ii uint32
	if err := unpackType(uiBuf, ii); err == nil {
		t.Fatal("unpackType incorrectly deserialized into a non pointer")
	}

	var b []byte
	var empty []byte
	emptyBuf := bytes.NewBuffer(empty)
	if err := unpackType(emptyBuf, &b); err == nil {
		t.Fatal("unpackType incorrectly deserialized an empty byte array into a byte slice")
	}

	// Try to deserialize a byte array that has a length but not enough bytes.
	// The slice ui represents uint32(1), which is the length of an empty byte array.
	ui2 := []byte{0, 0, 0, 1}
	uiBuf2 := bytes.NewBuffer(ui2)
	if err := unpackType(uiBuf2, &b); err == nil {
		t.Fatal("unpackType incorrectly deserialized a byte array that didn't have enough bytes available")
	}

	var iii []int
	ui3 := []byte{0, 0, 0, 1}
	uiBuf3 := bytes.NewBuffer(ui3)
	if err := unpackType(uiBuf3, &iii); err == nil {
		t.Fatal("unpackType incorrectly deserialized into a slice of ints (only byte slices are supported)")
	}

}

func TestEncodingUnpack(t *testing.T) {
	// Deserialize the empty byte array.
	var b []byte
	// The slice ui represents uint32(0), which is the length of an empty byte array.
	ui := []byte{0, 0, 0, 0}
	uiBuf := bytes.NewBuffer(ui)
	if err := unpackType(uiBuf, &b); err != nil {
		t.Fatal("unpackType failed to unpack the empty byte array")
	}

	// A byte slice of length 1 with a single entry: b[0] == 137
	ui2 := []byte{0, 0, 0, 1, 137}
	uiBuf2 := bytes.NewBuffer(ui2)
	if err := unpackType(uiBuf2, &b); err != nil {
		t.Fatal("unpackType failed to unpack a byte array with a single value in it")
	}

	if !bytes.Equal(b, []byte{137}) {
		t.Fatal("unpackType unpacked a small byte array incorrectly")
	}

	sp := simplePacked{137, 138}
	bsp, err := Pack(sp)
	if err != nil {
		t.Fatal("Couldn't pack a simple struct:", err)
	}
	var sp2 simplePacked
	if err := Unpack(bsp, &sp2); err != nil {
		t.Fatal("Couldn't unpack a simple struct:", err)
	}

	if sp.A != sp2.A || sp.B != sp2.B {
		t.Fatal("Unpacked simple struct didn't match the original")
	}

	// Try unpacking a version that's missing a byte at the end.
	if err := Unpack(bsp[:len(bsp)-1], &sp2); err == nil {
		t.Fatal("unpack incorrectly unpacked from a byte array that didn't have enough values")
	}

	np := nestedPacked{sp, 139}
	bnp, err := Pack(np)
	if err != nil {
		t.Fatal("Couldn't pack a nested struct")
	}
	var np2 nestedPacked
	if err := Unpack(bnp, &np2); err != nil {
		t.Fatal("Couldn't unpack a nested struct:", err)
	}
	if np.SP.A != np2.SP.A || np.SP.B != np2.SP.B || np.C != np2.C {
		t.Fatal("Unpacked nested struct didn't match the original")
	}

	ns := nestedSlice{137, b}
	bns, err := Pack(ns)
	if err != nil {
		t.Fatal("Couldn't pack a struct with a nested byte slice:", err)
	}
	var ns2 nestedSlice
	if err := Unpack(bns, &ns2); err != nil {
		t.Fatal("Couldn't unpacked a struct with a nested slice:", err)
	}
	if ns.A != ns2.A || !bytes.Equal(ns.S, ns2.S) {
		t.Fatal("Unpacked struct with nested slice didn't match the original")
	}

	var hs []Handle
	if err := Unpack([]byte{0, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, &hs); err != nil {
		t.Fatal("Couldn't unpack a list of Handles:", err)
	}
	if want := []Handle{0x01020304, 0x05060708, 0x090a0b0c}; !reflect.DeepEqual(want, hs) {
		t.Fatalf("Unpacking []Handle: got %v, want %v", hs, want)
	}
}

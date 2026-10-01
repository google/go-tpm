package tpm2

import (
	"bytes"
	"testing"
)

func TestHMACKeyFromAuthValue(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want []byte
	}{
		{"empty", nil, nil},
		{"no zeros", []byte{1, 2, 3}, []byte{1, 2, 3}},
		{"trailing zeros", []byte{1, 2, 3, 0, 0}, []byte{1, 2, 3}},
		{"all zeros", []byte{0, 0, 0}, nil},
		{"interior zero kept", []byte{1, 0, 2}, []byte{1, 0, 2}},
		{"interior and trailing", []byte{1, 0, 2, 0}, []byte{1, 0, 2}},
		{"leading zero kept", []byte{0, 1}, []byte{0, 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hmacKeyFromAuthValue(c.in)
			if !bytes.Equal(got, c.want) {
				t.Errorf("hmacKeyFromAuthValue(%x) = %x, want %x", c.in, got, c.want)
			}
		})
	}
}

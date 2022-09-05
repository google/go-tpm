package tpm2

import (
	"bytes"
	"testing"
)

func TestMarshal2B(t *testing.T) {
	// Define some TPMT_Public
	pub := TPMTPublic{
		Type:    TPMAlgKeyedHash,
		NameAlg: TPMAlgSHA256,
		ObjectAttributes: TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
			NoDA:         true,
		},
	}

	// Get the wire-format version
	pubBytes, err := Marshal(pub)
	if err != nil {
		t.Fatalf("could not Marshal: %v", err)
	}

	// Create two versions of the same 2B:
	// one instantiated by the actual TPMTPublic
	// one instantiated by the contents
	var boxed1 TPM2BPublic
	var boxed2 TPM2BPublic
	boxed1 = NewTPM2BPublic(&pub)
	boxed2 = NewTPM2BPublic(pubBytes)

	boxed1Bytes, err := Marshal(boxed1)
	if err != nil {
		t.Fatalf("could not Marshal: %v", err)
	}
	boxed2Bytes, err := Marshal(boxed2)
	if err != nil {
		t.Fatalf("could not Marshal: %v", err)
	}

	if !bytes.Equal(boxed1Bytes, boxed2Bytes) {
		t.Errorf("got %x want %x", boxed2Bytes, boxed1Bytes)
	}

	// Make a nonsense 2B_Public, demonstrating that the library doesn't have to understand the serialization
	boxed1 = NewTPM2BPublic([]byte{0xff})
}

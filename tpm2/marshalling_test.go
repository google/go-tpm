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
	pubBytes := Marshal(&pub)

	// Create two versions of the same 2B:
	// one instantiated by the actual TPMTPublic
	// one instantiated by the contents
	var boxed1 TPM2BPublic
	var boxed2 TPM2BPublic
	boxed1 = *NewTPM2BPublic(&pub)
	boxed2 = *NewTPM2BPublic(pubBytes)

	boxed1Bytes := Marshal(&boxed1)
	boxed2Bytes := Marshal(&boxed2)

	if !bytes.Equal(boxed1Bytes, boxed2Bytes) {
		t.Errorf("got %x want %x", boxed2Bytes, boxed1Bytes)
	}

	boxed3, err := Unmarshal[TPM2BPublic](boxed1Bytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPM2BPublic: %v", err)
	}

	boxed3Bytes := Marshal(boxed3)
	if !bytes.Equal(boxed1Bytes, boxed3Bytes) {
		t.Errorf("got %x want %x", boxed3Bytes, boxed1Bytes)
	}

	// Make a nonsense 2B_Public, demonstrating that the library doesn't have to understand the serialization
	boxed1 = *NewTPM2BPublic([]byte{0xff})
}

func TestMarshalT(t *testing.T) {
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
	pubBytes := Marshal(&pub)

	pub2, err := Unmarshal[TPMTPublic](pubBytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPMTPublic: %v", err)
	}

	// Some default fields might have been populated in the round-trip. Get the wire-format again and compare.
	pub2Bytes := Marshal(pub2)

	if !bytes.Equal(pubBytes, pub2Bytes) {
		t.Errorf("want %x\ngot %x", pubBytes, pub2Bytes)
	}
}

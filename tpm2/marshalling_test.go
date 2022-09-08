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
	boxed1 = NewTPM2BPublic(&pub)
	boxed2 = NewTPM2BPublic(pubBytes)

	boxed1Bytes := Marshal(&boxed1)
	boxed2Bytes := Marshal(&boxed2)

	if !bytes.Equal(boxed1Bytes, boxed2Bytes) {
		t.Errorf("got %x want %x", boxed2Bytes, boxed1Bytes)
	}

	z := Unmarshal[TPM2BPublic](boxed1Bytes)
	t.Logf("%v", z.value)

	boxed3, err := z.CheckUnwrap()
	if err != nil {
		t.Fatalf("could not unmarshal TPM2BPublic: %v", err)
	}
	t.Logf("%v", boxed3)

	boxed3Bytes := Marshal(boxed3)
	if !bytes.Equal(boxed1Bytes, boxed3Bytes) {
		t.Errorf("got %x want %x", boxed3Bytes, boxed1Bytes)
	}

	// Make a nonsense 2B_Public, demonstrating that the library doesn't have to understand the serialization
	boxed1 = NewTPM2BPublic([]byte{0xff})
}

func TestMarshalT(t *testing.T) {
	// Define some TPMT_Public
	pub := TPMTPublic{
		Type:    TPMAlgECC,
		NameAlg: TPMAlgSHA256,
		ObjectAttributes: TPMAObject{
			SignEncrypt: true,
		},
		Parameters: TPMUPublicParms{
			ECCDetail: &TPMSECCParms{
				CurveID: TPMECCNistP256,
			},
		},
		Unique: TPMUPublicID(
			// This happens to be a P256 EKpub from the simulator
			TPMAlgECC,
			&TPMSECCPoint{
				X: TPM2BECCParameter{},
				Y: TPM2BECCParameter{},
			},
		),
	}

	// Marshal each component of the parameters
	symBytes := Marshal(&pub.Parameters.ECCDetail.Symmetric)
	t.Logf("Symmetric: %x\n", symBytes)
	sym, err := Unmarshal[TPMTSymDefObject](symBytes).CheckUnwrap()
	if err != nil {
		t.Fatalf("could not unmarshal TPMTSymDefObject: %v", err)
	}
	symBytes2 := Marshal(sym)
	if !bytes.Equal(symBytes, symBytes2) {
		t.Errorf("want %x\ngot %x", symBytes, symBytes2)
	}
	schemeBytes := Marshal(&pub.Parameters.ECCDetail.Scheme)
	t.Logf("Scheme: %x\n", symBytes)
	scheme, err := Unmarshal[TPMTECCScheme](schemeBytes).CheckUnwrap()
	if err != nil {
		t.Fatalf("could not unmarshal TPMTECCScheme: %v", err)
	}
	schemeBytes2 := Marshal(scheme)
	if !bytes.Equal(schemeBytes, schemeBytes2) {
		t.Errorf("want %x\ngot %x", schemeBytes, schemeBytes2)
	}
	kdfBytes := Marshal(&pub.Parameters.ECCDetail.KDF)
	t.Logf("KDF: %x\n", kdfBytes)
	kdf, err := Unmarshal[TPMTKDFScheme](kdfBytes).CheckUnwrap()
	if err != nil {
		t.Fatalf("could not unmarshal TPMTKDFScheme: %v", err)
	}
	kdfBytes2 := Marshal(kdf)
	if !bytes.Equal(kdfBytes, kdfBytes2) {
		t.Errorf("want %x\ngot %x", kdfBytes, kdfBytes2)
	}

	// Marshal the parameters
	parmsBytes := Marshal(pub.Parameters.ECCDetail)
	t.Logf("Parms: %x\n", parmsBytes)
	parms, err := Unmarshal[TPMSECCParms](parmsBytes).CheckUnwrap()
	if err != nil {
		t.Fatalf("could not unmarshal TPMSECCParms: %v", err)
	}
	parmsBytes2 := Marshal(parms)
	if !bytes.Equal(parmsBytes, parmsBytes2) {
		t.Errorf("want %x\ngot %x", parmsBytes, parmsBytes2)
	}

	// Marshal the unique area
	uniqueBytes := Marshal(pub.Unique.ECC().Unwrap())
	t.Logf("Unique: %x\n", uniqueBytes)
	unique, err := Unmarshal[TPMSECCPoint](uniqueBytes).CheckUnwrap()
	if err != nil {
		t.Fatalf("could not unmarshal TPMSECCPoint: %v", err)
	}
	uniqueBytes2 := Marshal(unique)
	if !bytes.Equal(uniqueBytes, uniqueBytes2) {
		t.Errorf("want %x\ngot %x", uniqueBytes, uniqueBytes2)
	}

	// Get the wire-format version of the whole thing
	pubBytes := Marshal(&pub)

	pub2, err := Unmarshal[TPMTPublic](pubBytes).CheckUnwrap()
	if err != nil {
		t.Fatalf("could not unmarshal TPMTPublic: %v", err)
	}

	// Some default fields might have been populated in the round-trip. Get the wire-format again and compare.
	pub2Bytes := Marshal(pub2)

	if !bytes.Equal(pubBytes, pub2Bytes) {
		t.Errorf("want %x\ngot %x", pubBytes, pub2Bytes)
	}
}

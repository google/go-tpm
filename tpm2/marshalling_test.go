package tpm2_test

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestMarshal2B(t *testing.T) {
	// Define some TPMT_Public
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
			NoDA:         true,
		},
	}

	// Get the wire-format version
	pubBytes := tpm2.Marshal(pub)

	// Create two versions of the same 2B:
	// one instantiated by the actual TPMTPublic
	// one instantiated by the contents
	var boxed1 tpm2.TPM2BPublic
	var boxed2 tpm2.TPM2BPublic
	boxed1 = tpm2.New2B(pub)
	boxed2 = tpm2.BytesAs2B[tpm2.TPMTPublic](pubBytes)

	boxed1Bytes := tpm2.Marshal(boxed1)
	boxed2Bytes := tpm2.Marshal(boxed2)

	if !bytes.Equal(boxed1Bytes, boxed2Bytes) {
		t.Errorf("got %x want %x", boxed2Bytes, boxed1Bytes)
	}

	z, err := tpm2.Unmarshal[tpm2.TPM2BPublic](boxed1Bytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPM2BPublic: %v", err)
	}
	t.Logf("%v", z)

	boxed3Bytes := tpm2.Marshal(z)
	if !bytes.Equal(boxed1Bytes, boxed3Bytes) {
		t.Errorf("got %x want %x", boxed3Bytes, boxed1Bytes)
	}

	// Make a nonsense 2B_Public, demonstrating that the library doesn't have to understand the serialization
	tpm2.BytesAs2B[tpm2.TPMTPublic]([]byte{0xff})
}

func unwrap[T any](f func() (*T, error)) *T {
	t, err := f()
	if err != nil {
		panic(err.Error())
	}
	return t
}

func TestMarshalT(t *testing.T) {
	// Define some TPMT_Public
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			// This happens to be a P256 EKpub from the simulator
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{},
				Y: tpm2.TPM2BECCParameter{},
			},
		),
	}

	// Marshal each component of the parameters
	symBytes := tpm2.Marshal(&unwrap(pub.Parameters.ECCDetail).Symmetric)
	t.Logf("Symmetric: %x\n", symBytes)
	sym, err := tpm2.Unmarshal[tpm2.TPMTSymDefObject](symBytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPMTSymDefObject: %v", err)
	}
	symBytes2 := tpm2.Marshal(sym)
	if !bytes.Equal(symBytes, symBytes2) {
		t.Errorf("want %x\ngot %x", symBytes, symBytes2)
	}
	schemeBytes := tpm2.Marshal(&unwrap(pub.Parameters.ECCDetail).Scheme)
	t.Logf("Scheme: %x\n", symBytes)
	scheme, err := tpm2.Unmarshal[tpm2.TPMTECCScheme](schemeBytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPMTECCScheme: %v", err)
	}
	schemeBytes2 := tpm2.Marshal(scheme)
	if !bytes.Equal(schemeBytes, schemeBytes2) {
		t.Errorf("want %x\ngot %x", schemeBytes, schemeBytes2)
	}
	kdfBytes := tpm2.Marshal(&unwrap(pub.Parameters.ECCDetail).KDF)
	t.Logf("KDF: %x\n", kdfBytes)
	kdf, err := tpm2.Unmarshal[tpm2.TPMTKDFScheme](kdfBytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPMTKDFScheme: %v", err)
	}
	kdfBytes2 := tpm2.Marshal(kdf)
	if !bytes.Equal(kdfBytes, kdfBytes2) {
		t.Errorf("want %x\ngot %x", kdfBytes, kdfBytes2)
	}

	// Marshal the parameters
	parmsBytes := tpm2.Marshal(unwrap(pub.Parameters.ECCDetail))
	t.Logf("Parms: %x\n", parmsBytes)
	parms, err := tpm2.Unmarshal[tpm2.TPMSECCParms](parmsBytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPMSECCParms: %v", err)
	}
	parmsBytes2 := tpm2.Marshal(parms)
	if !bytes.Equal(parmsBytes, parmsBytes2) {
		t.Errorf("want %x\ngot %x", parmsBytes, parmsBytes2)
	}

	// Marshal the unique area
	uniqueBytes := tpm2.Marshal(unwrap(pub.Unique.ECC))
	t.Logf("Unique: %x\n", uniqueBytes)
	unique, err := tpm2.Unmarshal[tpm2.TPMSECCPoint](uniqueBytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPMSECCPoint: %v", err)
	}
	uniqueBytes2 := tpm2.Marshal(unique)
	if !bytes.Equal(uniqueBytes, uniqueBytes2) {
		t.Errorf("want %x\ngot %x", uniqueBytes, uniqueBytes2)
	}

	// Get the wire-format version of the whole thing
	pubBytes := tpm2.Marshal(&pub)

	pub2, err := tpm2.Unmarshal[tpm2.TPMTPublic](pubBytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPMTPublic: %v", err)
	}

	// Some default fields might have been populated in the round-trip. Get the wire-format again and compare.
	pub2Bytes := tpm2.Marshal(pub2)

	if !bytes.Equal(pubBytes, pub2Bytes) {
		t.Errorf("want %x\ngot %x", pubBytes, pub2Bytes)
	}
}

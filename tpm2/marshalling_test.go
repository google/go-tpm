package tpm2

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
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
	pubBytes := Marshal(pub)

	// Create two versions of the same 2B:
	// one instantiated by the actual TPMTPublic
	// one instantiated by the contents
	var boxed1 TPM2BPublic
	var boxed2 TPM2BPublic
	boxed1 = New2B(pub)
	boxed2 = BytesAs2B[TPMTPublic](pubBytes)

	boxed1Bytes := Marshal(boxed1)
	boxed2Bytes := Marshal(boxed2)

	if !bytes.Equal(boxed1Bytes, boxed2Bytes) {
		t.Errorf("got %x want %x", boxed2Bytes, boxed1Bytes)
	}

	z, err := Unmarshal[TPM2BPublic](boxed1Bytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPM2BPublic: %v", err)
	}
	t.Logf("%v", z)

	boxed3Bytes := Marshal(z)
	if !bytes.Equal(boxed1Bytes, boxed3Bytes) {
		t.Errorf("got %x want %x", boxed3Bytes, boxed1Bytes)
	}

	// Make a nonsense 2B_Public, demonstrating that the library doesn't have to understand the serialization
	BytesAs2B[TPMTPublic]([]byte{0xff})
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
	pub := TPMTPublic{
		Type:    TPMAlgECC,
		NameAlg: TPMAlgSHA256,
		ObjectAttributes: TPMAObject{
			SignEncrypt: true,
		},
		Parameters: NewTPMUPublicParms(
			TPMAlgECC,
			&TPMSECCParms{
				CurveID: TPMECCNistP256,
			},
		),
		Unique: NewTPMUPublicID(
			// This happens to be a P256 EKpub from the simulator
			TPMAlgECC,
			&TPMSECCPoint{
				X: TPM2BECCParameter{},
				Y: TPM2BECCParameter{},
			},
		),
	}

	// Marshal each component of the parameters
	symBytes := Marshal(&unwrap(pub.Parameters.ECCDetail).Symmetric)
	t.Logf("Symmetric: %x\n", symBytes)
	sym, err := Unmarshal[TPMTSymDefObject](symBytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPMTSymDefObject: %v", err)
	}
	symBytes2 := Marshal(sym)
	if !bytes.Equal(symBytes, symBytes2) {
		t.Errorf("want %x\ngot %x", symBytes, symBytes2)
	}
	schemeBytes := Marshal(&unwrap(pub.Parameters.ECCDetail).Scheme)
	t.Logf("Scheme: %x\n", symBytes)
	scheme, err := Unmarshal[TPMTECCScheme](schemeBytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPMTECCScheme: %v", err)
	}
	schemeBytes2 := Marshal(scheme)
	if !bytes.Equal(schemeBytes, schemeBytes2) {
		t.Errorf("want %x\ngot %x", schemeBytes, schemeBytes2)
	}
	kdfBytes := Marshal(&unwrap(pub.Parameters.ECCDetail).KDF)
	t.Logf("KDF: %x\n", kdfBytes)
	kdf, err := Unmarshal[TPMTKDFScheme](kdfBytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPMTKDFScheme: %v", err)
	}
	kdfBytes2 := Marshal(kdf)
	if !bytes.Equal(kdfBytes, kdfBytes2) {
		t.Errorf("want %x\ngot %x", kdfBytes, kdfBytes2)
	}

	// Marshal the parameters
	parmsBytes := Marshal(unwrap(pub.Parameters.ECCDetail))
	t.Logf("Parms: %x\n", parmsBytes)
	parms, err := Unmarshal[TPMSECCParms](parmsBytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPMSECCParms: %v", err)
	}
	parmsBytes2 := Marshal(parms)
	if !bytes.Equal(parmsBytes, parmsBytes2) {
		t.Errorf("want %x\ngot %x", parmsBytes, parmsBytes2)
	}

	// Marshal the unique area
	uniqueBytes := Marshal(unwrap(pub.Unique.ECC))
	t.Logf("Unique: %x\n", uniqueBytes)
	unique, err := Unmarshal[TPMSECCPoint](uniqueBytes)
	if err != nil {
		t.Fatalf("could not unmarshal TPMSECCPoint: %v", err)
	}
	uniqueBytes2 := Marshal(unique)
	if !bytes.Equal(uniqueBytes, uniqueBytes2) {
		t.Errorf("want %x\ngot %x", uniqueBytes, uniqueBytes2)
	}

	// Get the wire-format version of the whole thing
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

func TestMarshalCommandResponse(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	getCmd := GetCapability{
		Capability:    TPMCapTPMProperties,
		Property:      uint32(TPMPTFamilyIndicator),
		PropertyCount: 1,
	}
	capabilityRsp, err := getCmd.Execute(thetpm)
	if err != nil {
		t.Fatalf("executing GetCapability: %v", err)
	}

	cmdParamsBytes, err := MarshalCommand(getCmd)
	if err != nil {
		t.Fatalf("MarshalCommand failed: %v", err)
	}

	unmarshalCmd, err := UnmarshalCommand[GetCapability](cmdParamsBytes)
	if err != nil {
		t.Fatalf("UnmarshalCommand failed: %v", err)
	}

	if !reflect.DeepEqual(getCmd, unmarshalCmd) {
		t.Errorf("Commands do not match \nwant: %+v\ngot: %+v", getCmd, unmarshalCmd)
	}

	respParamsBytes, err := MarshalResponse(getCmd, capabilityRsp)
	if err != nil {
		t.Fatalf("MarshalResponse failed: %v", err)
	}

	unmarshalRsp, err := UnmarshalResponse[GetCapabilityResponse](respParamsBytes)
	if err != nil {
		t.Fatalf("UnmarshalResponse failed: %v", err)
	}
	if !reflect.DeepEqual(capabilityRsp, unmarshalRsp) {
		t.Errorf("Responses do not match \nwant: %+v\ngot: %+v", capabilityRsp, unmarshalRsp)
	}
}

func TestUnmarshalTPMTHAList(t *testing.T) {
	sha1Digest := bytes.Repeat([]byte{0x11}, 20)
	sha256Digest := bytes.Repeat([]byte{0x22}, 32)

	// TPML_DIGEST_VALUES with a SHA-1 and a SHA-256 digest, encoded by hand
	// (Part 2, sections 10.3.2 and 10.9.7).
	digestValues := []byte{0x00, 0x00, 0x00, 0x02}
	digestValues = append(digestValues, 0x00, 0x04)
	digestValues = append(digestValues, sha1Digest...)
	digestValues = append(digestValues, 0x00, 0x0b)
	digestValues = append(digestValues, sha256Digest...)

	dv, err := Unmarshal[TPMLDigestValues](digestValues)
	if err != nil {
		t.Fatalf("could not unmarshal TPMLDigestValues: %v", err)
	}
	want := TPMLDigestValues{
		Digests: []TPMTHA{
			{HashAlg: TPMAlgSHA1, Digest: sha1Digest},
			{HashAlg: TPMAlgSHA256, Digest: sha256Digest},
		},
	}
	if !reflect.DeepEqual(*dv, want) {
		t.Errorf("Unmarshal(TPMLDigestValues) = %+v, want %+v", *dv, want)
	}
	if got := Marshal(dv); !bytes.Equal(got, digestValues) {
		t.Errorf("Marshal(TPMLDigestValues) = %x, want %x", got, digestValues)
	}

	// TPML_TAGGED_POLICY whose first entry has no policy (TPM_ALG_NULL),
	// encoded by hand (Part 2, sections 10.8.4 and 10.9.13).
	taggedPolicies := []byte{0x00, 0x00, 0x00, 0x02}
	taggedPolicies = append(taggedPolicies, 0x40, 0x00, 0x00, 0x01, 0x00, 0x10)
	taggedPolicies = append(taggedPolicies, 0x40, 0x00, 0x00, 0x0b, 0x00, 0x0b)
	taggedPolicies = append(taggedPolicies, sha256Digest...)

	tp, err := Unmarshal[TPMLTaggedPolicy](taggedPolicies)
	if err != nil {
		t.Fatalf("could not unmarshal TPMLTaggedPolicy: %v", err)
	}
	if len(tp.Policies) != 2 {
		t.Fatalf("got %d policies, want 2", len(tp.Policies))
	}
	if got := tp.Policies[0]; got.Handle != TPMRHOwner || got.PolicyHash.HashAlg != TPMAlgNull || len(got.PolicyHash.Digest) != 0 {
		t.Errorf("policy 0 = %+v, want owner with TPM_ALG_NULL and no digest", got)
	}
	if got := tp.Policies[1]; got.Handle != TPMRHEndorsement || got.PolicyHash.HashAlg != TPMAlgSHA256 || !bytes.Equal(got.PolicyHash.Digest, sha256Digest) {
		t.Errorf("policy 1 = %+v, want endorsement with SHA-256 digest %x", got, sha256Digest)
	}
	if got := Marshal(tp); !bytes.Equal(got, taggedPolicies) {
		t.Errorf("Marshal(TPMLTaggedPolicy) = %x, want %x", got, taggedPolicies)
	}

	// A truncated digest must be an error.
	if _, err := Unmarshal[TPMLDigestValues](digestValues[:len(digestValues)-1]); err == nil {
		t.Error("Unmarshal(TPMLDigestValues) of truncated data succeeded, want error")
	}
}

func TestGetCapabilityAuthPolicies(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	rsp, err := GetCapability{
		Capability:    TPMCapAuthPolicies,
		Property:      uint32(TPMRHOwner),
		PropertyCount: 8,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("GetCapability(TPM_CAP_AUTH_POLICIES) failed: %v", err)
	}
	policies, err := rsp.CapabilityData.Data.AuthPolicies()
	if err != nil {
		t.Fatalf("AuthPolicies failed: %v", err)
	}
	if len(policies.Policies) < 2 {
		t.Fatalf("got %d policies, want at least 2", len(policies.Policies))
	}
	for _, p := range policies.Policies {
		wantSize := 0
		if p.PolicyHash.HashAlg != TPMAlgNull {
			h, err := p.PolicyHash.HashAlg.Hash()
			if err != nil {
				t.Fatalf("policy for handle %x: %v", p.Handle, err)
			}
			wantSize = h.Size()
		}
		if len(p.PolicyHash.Digest) != wantSize {
			t.Errorf("policy for handle %x has a %d-byte digest, want %d bytes", p.Handle, len(p.PolicyHash.Digest), wantSize)
		}
	}
}

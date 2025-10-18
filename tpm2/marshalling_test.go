package tpm2

import (
	"bytes"
	"encoding/binary"
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

	respParamsBytes, err := MarshalResponse(capabilityRsp)
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

func TestCommandPreimage(t *testing.T) {
	tests := []struct {
		name        string
		marshalFunc func(t *testing.T) ([]byte, error)
		nameCount   int
	}{
		{
			name: "no handle",
			marshalFunc: func(_ *testing.T) ([]byte, error) {
				return MarshalCommand(GetCapability{
					Capability:    TPMCapTPMProperties,
					Property:      uint32(TPMPTFamilyIndicator),
					PropertyCount: 1,
				})
			},
			nameCount: 0,
		},
		{
			name: "one handle",
			marshalFunc: func(_ *testing.T) ([]byte, error) {
				return MarshalCommand(CreatePrimary{
					PrimaryHandle: TPMRHOwner,
					InPublic:      New2B(ECCSRKTemplate),
				})
			},
			nameCount: 1,
		},
		{
			name: "two handles",
			marshalFunc: func(_ *testing.T) ([]byte, error) {
				thetpm, err := simulator.OpenSimulator()
				if err != nil {
					t.Fatalf("could not connect to TPM simulator: %v", err)
				}
				defer thetpm.Close()

				public := New2B(TPMTPublic{
					Type:    TPMAlgRSA,
					NameAlg: TPMAlgSHA256,
					ObjectAttributes: TPMAObject{
						SignEncrypt:         true,
						Restricted:          true,
						FixedTPM:            true,
						FixedParent:         true,
						SensitiveDataOrigin: true,
						UserWithAuth:        true,
						NoDA:                true,
					},
					Parameters: NewTPMUPublicParms(
						TPMAlgRSA,
						&TPMSRSAParms{
							Scheme: TPMTRSAScheme{
								Scheme: TPMAlgRSASSA,
								Details: NewTPMUAsymScheme(
									TPMAlgRSASSA,
									&TPMSSigSchemeRSASSA{
										HashAlg: TPMAlgSHA256,
									},
								),
							},
							KeyBits: 2048,
						},
					),
				})

				createPrimary := CreatePrimary{
					PrimaryHandle: TPMRHEndorsement,
					InPublic:      public,
				}
				rspCP, err := createPrimary.Execute(thetpm)
				if err != nil {
					t.Fatalf("Failed to create primary: %v", err)
				}
				flushContext := FlushContext{FlushHandle: rspCP.ObjectHandle}
				defer flushContext.Execute(thetpm)

				inScheme := TPMTSigScheme{
					Scheme: TPMAlgRSASSA,
					Details: NewTPMUSigScheme(
						TPMAlgRSASSA,
						&TPMSSchemeHash{
							HashAlg: TPMAlgSHA256,
						},
					),
				}

				return MarshalCommand(CertifyCreation{
					SignHandle: AuthHandle{
						Handle: rspCP.ObjectHandle,
						Name:   rspCP.Name,
						Auth:   PasswordAuth(nil),
					},
					ObjectHandle: NamedHandle{
						Handle: rspCP.ObjectHandle,
						Name:   rspCP.Name,
					},
					CreationHash:   rspCP.CreationHash,
					InScheme:       inScheme,
					CreationTicket: rspCP.CreationTicket,
				})
			},
			nameCount: 2,
		},
		{
			name: "three handles",
			marshalFunc: func(t *testing.T) ([]byte, error) {
				thetpm, err := simulator.OpenSimulator()
				if err != nil {
					return nil, err
				}
				defer thetpm.Close()

				createAKCmd := CreatePrimary{
					PrimaryHandle: TPMRHOwner,
					InPublic: New2B(TPMTPublic{
						Type:    TPMAlgECC,
						NameAlg: TPMAlgSHA256,
						ObjectAttributes: TPMAObject{
							FixedTPM:             true,
							STClear:              false,
							FixedParent:          true,
							SensitiveDataOrigin:  true,
							UserWithAuth:         true,
							AdminWithPolicy:      false,
							NoDA:                 true,
							EncryptedDuplication: false,
							Restricted:           true,
							Decrypt:              false,
							SignEncrypt:          true,
						},
						Parameters: NewTPMUPublicParms(
							TPMAlgECC,
							&TPMSECCParms{
								Scheme: TPMTECCScheme{
									Scheme: TPMAlgECDSA,
									Details: NewTPMUAsymScheme(
										TPMAlgECDSA,
										&TPMSSigSchemeECDSA{
											HashAlg: TPMAlgSHA256,
										},
									),
								},
								CurveID: TPMECCNistP256,
							},
						),
					}),
				}
				createAKRsp, err := createAKCmd.Execute(thetpm)
				if err != nil {
					return nil, err
				}
				defer FlushContext{FlushHandle: createAKRsp.ObjectHandle}.Execute(thetpm)

				sess, cleanup, err := HMACSession(thetpm, TPMAlgSHA256, 16, Audit())
				if err != nil {
					return nil, err
				}
				defer cleanup()

				return MarshalCommand(GetSessionAuditDigest{
					PrivacyAdminHandle: TPMRHEndorsement,
					SignHandle: NamedHandle{
						Handle: createAKRsp.ObjectHandle,
						Name:   createAKRsp.Name,
					},
					SessionHandle: sess.Handle(),
				})
			},
			nameCount: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmdBytes, err := tt.marshalFunc(t)
			if err != nil {
				t.Fatalf("MarshalCommand failed: %v", err)
			}
			_, names, _, err := unmarshalCommandPreimage(cmdBytes)
			if err != nil {
				t.Fatalf("unmarshalCommandPreimage failed: %v", err)
			}
			if len(names) != tt.nameCount {
				t.Errorf("name count mismatch: want %d, got %d", tt.nameCount, len(names))
			}
		})
	}
}
func TestCommandPreimageToCPHash(t *testing.T) {
	getCmd := GetCapability{
		Capability:    TPMCapTPMProperties,
		Property:      uint32(TPMPTFamilyIndicator),
		PropertyCount: 1,
	}

	cmdBytes, err := MarshalCommand(getCmd)
	if err != nil {
		t.Fatalf("MarshalCommand failed: %v", err)
	}

	cc, names, params, err := unmarshalCommandPreimage(cmdBytes)
	if err != nil {
		t.Fatalf("unmarshalCommandPreimage failed: %v", err)
	}

	preimage := &CommandPreimage{
		CommandCode: cc,
		Names:       names,
		Parameters: TPM2BData{
			Buffer: params,
		},
	}

	cpHashPreimage := preimage.ToCPHashPreimage()

	if len(cpHashPreimage) < 4 {
		t.Fatalf("cpHash preimage too short: %d bytes", len(cpHashPreimage))
	}

	var ccFromPreimage TPMCC
	buf := bytes.NewReader(cpHashPreimage[:4])
	if err := binary.Read(buf, binary.BigEndian, &ccFromPreimage); err != nil {
		t.Fatalf("reading command code from preimage: %v", err)
	}

	if ccFromPreimage != TPMCCGetCapability {
		t.Errorf("command code mismatch: want %v, got %v", TPMCCGetCapability, ccFromPreimage)
	}
}
